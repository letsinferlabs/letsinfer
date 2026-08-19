import Foundation

actor WatchdogDataSource: SiteDataSource {
    static let defaultPort = 9_768

    private let client: any WatchdogTelemetryClient
    private let inventorySource: (any SiteDataSource)?
    private var inventory: [SavedSite.ID: SiteSnapshot] = [:]
    private var inventoryTasks: [SavedSite.ID: Task<Void, Never>] = [:]
    private var inventoryRetryAfter: [SavedSite.ID: Date] = [:]
    private var previousSamples: [SavedSite.ID: WatchdogTelemetrySample] = [:]

    init(
        client: any WatchdogTelemetryClient = WatchdogTLSClient(),
        inventorySource: (any SiteDataSource)? = nil
    ) {
        self.client = client
        self.inventorySource = inventorySource
    }

    func fetchSnapshot(for site: SavedSite) async throws -> SiteSnapshot {
        let installationID = try installationID(for: site)
        let sample = try await client.latest(
            host: site.host, port: port(for: site), installationID: installationID
        )
        scheduleInventoryIfNeeded(for: site)
        return mapAndRemember(sample, to: site)
    }

    func fetchHistory(for site: SavedSite, since: Date) async throws -> [SiteSnapshot] {
        let installationID = try installationID(for: site)
        let samples = try await client.history(
            host: site.host,
            port: port(for: site),
            installationID: installationID,
            since: since
        )
        let cachedInventory = inventory[site.id]
        var previous: WatchdogTelemetrySample?
        let snapshots = samples.map { sample in
            defer { previous = sample }
            return Self.map(
                sample,
                to: site,
                inventory: cachedInventory,
                previous: previous
            )
        }
        if let latest = samples.max(by: { $0.unixMilliseconds < $1.unixMilliseconds }),
           previousSamples[site.id].map({ $0.unixMilliseconds <= latest.unixMilliseconds }) ?? true {
            previousSamples[site.id] = latest
        }
        return snapshots
    }

    func updates(for site: SavedSite) async -> AsyncThrowingStream<SiteSnapshot, Error>? {
        guard let installationID = site.installationID else { return nil }
        let events = await client.subscribe(
            host: site.host,
            port: port(for: site),
            installationID: installationID,
            historySeconds: 30 * 60
        )
        return AsyncThrowingStream { continuation in
            let task = Task { [weak self] in
                var status: SiteStatus?
                do {
                    for try await event in events {
                        guard let self else { return }
                        switch event {
                        case .status(let value):
                            status = value
                        case .sample(let sample):
                            let snapshot = await self.snapshot(
                                sample,
                                for: site,
                                status: status
                            )
                            continuation.yield(snapshot)
                        case .unavailable:
                            if let fallback = await self.fallbackSnapshot(for: site) {
                                continuation.yield(fallback)
                            }
                        }
                    }
                    continuation.finish()
                } catch {
                    continuation.finish(throwing: error)
                }
            }
            continuation.onTermination = { @Sendable _ in task.cancel() }
        }
    }

    private func fallbackSnapshot(for site: SavedSite) async -> SiteSnapshot? {
        guard let inventorySource else { return nil }
        return try? await inventorySource.fetchSnapshot(for: site)
    }

    private func installationID(for site: SavedSite) throws -> String {
        guard let value = site.installationID else {
            throw WatchdogClientError.credentialsUnavailable
        }
        return value
    }

    private func snapshot(
        _ sample: WatchdogTelemetrySample,
        for site: SavedSite,
        status: SiteStatus?
    ) -> SiteSnapshot {
        scheduleInventoryIfNeeded(for: site)
        return mapAndRemember(sample, to: site, status: status)
    }

    private func mapAndRemember(
        _ sample: WatchdogTelemetrySample,
        to site: SavedSite,
        status: SiteStatus? = nil
    ) -> SiteSnapshot {
        let previous = previousSamples[site.id]
        let snapshot = Self.map(
            sample,
            to: site,
            inventory: inventory[site.id],
            status: status,
            previous: previous
        )
        if previous.map({ $0.unixMilliseconds <= sample.unixMilliseconds }) ?? true {
            previousSamples[site.id] = sample
        }
        return snapshot
    }

    static func map(
        _ sample: WatchdogTelemetrySample,
        to site: SavedSite,
        inventory: SiteSnapshot? = nil,
        status: SiteStatus? = nil,
        previous: WatchdogTelemetrySample? = nil
    ) -> SiteSnapshot {
        let base = inventory?.metrics
        let cpuUnits = sample.cpuCorePercent.enumerated().map { index, value in
            UtilizationUnit(
                id: "cpu\(index)",
                name: "Core \(index)",
                utilizationPercent: percent(value)
            )
        }
        let gpuNames = ["SM", "Memory", "Encoder", "Decoder", "JPEG", "OFA"]
        let gpuUnits = sample.gpuEnginePercent.enumerated().map { index, value in
            UtilizationUnit(
                id: "gpu-engine-\(index)",
                name: index < gpuNames.count ? gpuNames[index] : "Engine \(index + 1)",
                utilizationPercent: percent(value)
            )
        }

        let gpuAvailable = sample.flags & 0b10 != 0
        let gpuUtilization = percent(sample.gpuPercent)
        let gpuMemory = percent(sample.gpuMemoryPercent)
        let gpuTemperature = temperature(sample.gpuTemperatureDeciCelsius)
        let gpu = gpuAvailable || gpuUtilization != nil || gpuTemperature != nil
            ? GPUMetrics(
                utilizationPercent: gpuUtilization,
                temperatureCelsius: gpuTemperature,
                powerWatts: Double(sample.powerDeciwatts) / 10,
                powerLimitWatts: base?.gpu?.powerLimitWatts,
                smClockMHz: clock(sample.gpuClockMHz) ?? base?.gpu?.smClockMHz,
                maxSMClockMHz: base?.gpu?.maxSMClockMHz,
                isThrottled: sample.flags & 0b100 != 0,
                memoryUtilizationPercent: gpuMemory,
                graphicsClockMHz: clock(sample.gpuClockMHz) ?? base?.gpu?.graphicsClockMHz,
                memoryClockMHz: clock(sample.vramClockMHz) ?? base?.gpu?.memoryClockMHz,
                performanceState: base?.gpu?.performanceState,
                computeMode: base?.gpu?.computeMode,
                displayActive: base?.gpu?.displayActive,
                pcieGeneration: base?.gpu?.pcieGeneration,
                pcieWidth: base?.gpu?.pcieWidth,
                units: gpuUnits
            )
            : nil

        let memoryTotal = bytesFromMiB(sample.memoryTotalMiB, zeroIsUnknown: true)
        let memoryUsed = bytesFromMiB(sample.memoryUsedMiB, zeroIsUnknown: false)
        let diskTotal = bytesFromMiB(sample.diskTotalMiB, zeroIsUnknown: true)
        let diskUsed = bytesFromMiB(sample.diskUsedMiB, zeroIsUnknown: false)

        let liveStatus = status ?? inventory?.letsinfer
        let llm: [LLMMetrics]
        if sample.flags & 0b1000 != 0 {
            llm = [
                LLMMetrics(
                    id: "letsinfer-gateway",
                    backend: liveStatus?.engine,
                    model: liveStatus?.model,
                    generationTokensPerSecond: decodeRate(sample, previous: previous),
                    aggregateTokensPerSecond: outputRate(sample, previous: previous),
                    prefillTokensPerSecond: prefillRate(sample, previous: previous),
                    runningRequests: Int(sample.activeRequests),
                    waitingRequests: Int(sample.queuedRequests),
                    kvCacheUtilization: nil
                )
            ]
        } else {
            llm = base?.llm ?? []
        }

        return SiteSnapshot(
            siteID: site.id,
            source: .watchdog,
            sampledAt: sample.unixMilliseconds == 0
                ? Date()
                : Date(timeIntervalSince1970: Double(sample.unixMilliseconds) / 1_000),
            availability: .online,
            uptimeSeconds: inventory?.uptimeSeconds,
            identity: inventory?.identity,
            system: inventory?.system,
            metrics: MemberMetrics(
                gpu: gpu,
                cpu: CPUMetrics(
                    utilizationPercent: percent(sample.cpuPercent),
                    temperatureCelsius: temperature(sample.systemTemperatureDeciCelsius),
                    averageFrequencyMHz: clock(sample.cpuClockMHz) ?? base?.cpu?.averageFrequencyMHz,
                    loadAverage1Minute: Double(sample.load1Centi) / 100,
                    loadAverage5Minutes: base?.cpu?.loadAverage5Minutes,
                    loadAverage15Minutes: base?.cpu?.loadAverage15Minutes,
                    pressureAverage10Seconds: base?.cpu?.pressureAverage10Seconds,
                    units: cpuUnits
                ),
                memory: MemoryMetrics(
                    usedBytes: memoryUsed,
                    totalBytes: memoryTotal,
                    availableBytes: subtract(memoryTotal, memoryUsed),
                    utilizationPercent: percent(sample.memoryPercent),
                    cachedBytes: base?.memory?.cachedBytes,
                    swapUsedBytes: base?.memory?.swapUsedBytes,
                    swapTotalBytes: base?.memory?.swapTotalBytes,
                    pressureAverage10Seconds: base?.memory?.pressureAverage10Seconds,
                    clockMHz: clock(sample.systemRAMClockMHz) ?? base?.memory?.clockMHz
                ),
                storage: StorageMetrics(
                    usedBytes: diskUsed,
                    totalBytes: diskTotal,
                    availableBytes: subtract(diskTotal, diskUsed),
                    utilizationPercent: percent(sample.diskPercent),
                    temperatureCelsius: temperature(sample.nvmeTemperatureDeciCelsius),
                    readBytesPerSecond: Double(sample.diskReadKiBPerSecond) * 1_024,
                    writeBytesPerSecond: Double(sample.diskWriteKiBPerSecond) * 1_024,
                    pressureAverage10Seconds: base?.storage?.pressureAverage10Seconds
                ),
                network: NetworkMetrics(
                    receiveBytesPerSecond: Double(sample.networkReceiveKiBPerSecond) * 1_024,
                    transmitBytesPerSecond: Double(sample.networkTransmitKiBPerSecond) * 1_024,
                    receivedPackets: base?.network?.receivedPackets,
                    transmittedPackets: base?.network?.transmittedPackets,
                    receiveErrors: base?.network?.receiveErrors,
                    transmitErrors: base?.network?.transmitErrors,
                    receiveDrops: base?.network?.receiveDrops,
                    transmitDrops: base?.network?.transmitDrops
                ),
                llm: llm
            ),
            letsinfer: liveStatus
        )
    }

    private func scheduleInventoryIfNeeded(for site: SavedSite) {
        guard inventory[site.id] == nil, inventoryTasks[site.id] == nil else { return }
        guard inventoryRetryAfter[site.id, default: .distantPast] <= Date() else { return }
        guard let inventorySource else { return }

        inventoryTasks[site.id] = Task { [weak self] in
            let snapshot = try? await inventorySource.fetchSnapshot(for: site)
            await self?.finishInventory(snapshot, for: site.id)
        }
    }

    private func finishInventory(_ snapshot: SiteSnapshot?, for id: SavedSite.ID) {
        inventoryTasks[id] = nil
        if let snapshot {
            inventory[id] = snapshot
            inventoryRetryAfter[id] = nil
        } else {
            inventoryRetryAfter[id] = Date().addingTimeInterval(5 * 60)
        }
    }

    private func port(for site: SavedSite) -> Int {
        if case .watchdog(let port) = site.dataSource { return port }
        return Self.defaultPort
    }

    private static func percent(_ value: UInt32) -> Double? {
        value <= 100 ? Double(value) : nil
    }

    private static func temperature(_ value: Int32) -> Double? {
        value == .min ? nil : Double(value) / 10
    }

    private static func bytesFromMiB(_ value: UInt32, zeroIsUnknown: Bool) -> Double? {
        if zeroIsUnknown, value == 0 { return nil }
        return Double(value) * 1_024 * 1_024
    }

    private static func clock(_ value: UInt32) -> Double? {
        value == .max ? nil : Double(value)
    }

    private static func subtract(_ total: Double?, _ used: Double?) -> Double? {
        guard let total, let used else { return nil }
        return max(0, total - used)
    }

    private static func counterDelta(_ current: UInt64, _ previous: UInt64) -> UInt64 {
        current >= previous ? current - previous : current
    }

    private static func decodeRate(
        _ sample: WatchdogTelemetrySample,
        previous: WatchdogTelemetrySample?
    ) -> Double? {
        guard let previous,
              sample.unixMilliseconds > previous.unixMilliseconds else {
            return nil
        }
        let output = counterDelta(sample.outputTokens, previous.outputTokens)
        let milliseconds = counterDelta(
            sample.decodeMilliseconds, previous.decodeMilliseconds
        )
        if counterDelta(sample.exactTokenRequests, previous.exactTokenRequests) > 0,
           output > 0, milliseconds > 0 {
            return Double(output) * 1_000 / Double(milliseconds)
        }
        return outputRate(sample, previous: previous)
    }

    private static func outputRate(
        _ sample: WatchdogTelemetrySample,
        previous: WatchdogTelemetrySample?
    ) -> Double? {
        guard let previous,
              sample.unixMilliseconds > previous.unixMilliseconds else {
            return nil
        }
        let output = counterDelta(sample.outputTokens, previous.outputTokens)
        guard output > 0 else { return nil }
        return Double(output) * 1_000
            / Double(sample.unixMilliseconds - previous.unixMilliseconds)
    }

    private static func prefillRate(
        _ sample: WatchdogTelemetrySample,
        previous: WatchdogTelemetrySample?
    ) -> Double? {
        guard let previous,
              sample.unixMilliseconds > previous.unixMilliseconds else {
            return nil
        }
        let input = counterDelta(sample.inputTokens, previous.inputTokens)
        let cached = counterDelta(sample.cachedTokens, previous.cachedTokens)
        let milliseconds = counterDelta(sample.ttftMilliseconds, previous.ttftMilliseconds)
        guard input >= cached, input > cached else { return nil }
        if counterDelta(sample.exactTokenRequests, previous.exactTokenRequests) > 0,
           milliseconds > 0 {
            return Double(input - cached) * 1_000 / Double(milliseconds)
        }
        return Double(input - cached) * 1_000
            / Double(sample.unixMilliseconds - previous.unixMilliseconds)
    }
}
