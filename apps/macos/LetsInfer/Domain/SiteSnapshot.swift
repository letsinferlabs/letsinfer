import Foundation

enum SiteDataSourceKind: String, Codable, Sendable {
    case controller
    case ssh
    case watchdog
}

enum MemberAvailability: String, Codable, Sendable {
    case online
    case offline
    case degraded
}

struct SiteSnapshot: Equatable, Sendable {
    let siteID: SavedSite.ID
    let source: SiteDataSourceKind
    let sampledAt: Date
    let availability: MemberAvailability
    let uptimeSeconds: TimeInterval?
    let identity: MemberIdentity?
    let system: MemberSystemInfo?
    let metrics: MemberMetrics
    let letsinfer: SiteStatus?

    init(
        siteID: SavedSite.ID,
        source: SiteDataSourceKind,
        sampledAt: Date,
        availability: MemberAvailability,
        uptimeSeconds: TimeInterval?,
        identity: MemberIdentity?,
        system: MemberSystemInfo? = nil,
        metrics: MemberMetrics,
        letsinfer: SiteStatus? = nil
    ) {
        self.siteID = siteID
        self.source = source
        self.sampledAt = sampledAt
        self.availability = availability
        self.uptimeSeconds = uptimeSeconds
        self.identity = identity
        self.system = system
        self.metrics = metrics
        self.letsinfer = letsinfer
    }
}

struct SiteStatus: Equatable, Sendable {
    let installationID: String
    let release: String
    let model: String
    let engine: String
    let runtimeName: String?
    let runtimeVersion: String?
    let manifestSHA256: String
    let cacheProvider: String
    let cachePersistent: Bool
    let inferencePort: Int
    let maxConnections: Int
    let maxActiveRequests: Int
    let maxContextTokens: Int
    let serviceState: String
    let engineState: String
    let protectionPhase: String
    let protectionArmed: Bool
    let tripLatched: Bool
    let containerName: String?
}

struct MemberIdentity: Equatable, Sendable {
    let vendor: String?
    let product: String?
    let architecture: String?
    let gpuName: String?

    var isGB10: Bool? {
        guard let gpuName, !gpuName.isEmpty else { return nil }
        return gpuName.localizedCaseInsensitiveContains("GB10")
    }

    var manufacturerName: String? {
        guard let vendor else { return nil }
        let value = vendor.lowercased()
        if value.contains("asustek") || value == "asus" { return "ASUS" }
        if value.contains("nvidia") { return "NVIDIA" }
        if value.contains("acer") { return "Acer" }
        if value.contains("dell") { return "Dell" }
        if value.contains("gigabyte") { return "GIGABYTE" }
        if value.contains("hewlett") || value == "hp" || value.hasPrefix("hp ") { return "HP" }
        if value.contains("lenovo") { return "Lenovo" }
        if value.contains("micro-star") || value == "msi" { return "MSI" }
        return vendor
    }

    var displayName: String? {
        let values = [manufacturerName, product]
            .compactMap { $0 }
            .filter { !$0.isEmpty }
        return values.joined(separator: " ").nilIfEmpty
    }
}

struct MemberSystemInfo: Equatable, Sendable {
    let hostname: String?
    let operatingSystem: String?
    let kernelVersion: String?
    let productVersion: String?
    let serialNumber: String?
    let serialSource: String?
    let systemUUID: String?
    let machineIDHash: String?
    let dmiSerialRequiresPrivilege: Bool
    let boardVendor: String?
    let boardName: String?
    let boardVersion: String?
    let boardSerial: String?
    let chassisVendor: String?
    let chassisType: String?
    let chassisSerial: String?
    let biosVendor: String?
    let biosVersion: String?
    let biosDate: String?
    let cpuModel: String?
    let cpuCoreCount: Int?
    let gpuUUID: String?
    let nvidiaDriverVersion: String?
    let dgxName: String?
    let dgxSoftwareVersion: String?
    let dgxBaseBuildVersion: String?
    let dgxBuildDate: String?
    let dgxCommitID: String?
    let dgxPlatform: String?
    let dgxUpdateDate: String?
    let nvmeModel: String?
    let nvmeSerial: String?
    let nvmeFirmware: String?
    let networkAddresses: [NetworkAddress]
    let defaultNetworkInterface: String?
    let processCount: Int?
    let activeUsers: [String]
    let loginSessionCount: Int?
    let lastLogin: String?
    let firmwareUpdateCount: Int?
    let containers: [ContainerInfo]
}

struct NetworkAddress: Decodable, Equatable, Identifiable, Sendable {
    var id: String { "\(interface)-\(family)-\(address)" }
    let interface: String
    let family: String
    let address: String
}

struct ContainerInfo: Decodable, Equatable, Identifiable, Sendable {
    var id: String { name }
    let name: String
    let image: String?
    let status: String?
}

struct MemberMetrics: Equatable, Sendable {
    var gpu: GPUMetrics?
    var cpu: CPUMetrics?
    var memory: MemoryMetrics?
    var storage: StorageMetrics?
    var network: NetworkMetrics?
    var llm: [LLMMetrics]

    init(
        gpu: GPUMetrics? = nil,
        cpu: CPUMetrics? = nil,
        memory: MemoryMetrics? = nil,
        storage: StorageMetrics? = nil,
        network: NetworkMetrics? = nil,
        llm: [LLMMetrics] = []
    ) {
        self.gpu = gpu
        self.cpu = cpu
        self.memory = memory
        self.storage = storage
        self.network = network
        self.llm = llm
    }

    static let empty = MemberMetrics()
}

struct UtilizationUnit: Equatable, Identifiable, Sendable {
    let id: String
    let name: String
    let utilizationPercent: Double?
}

struct GPUMetrics: Equatable, Sendable {
    let utilizationPercent: Double?
    let memoryUtilizationPercent: Double?
    let temperatureCelsius: Double?
    let powerWatts: Double?
    let powerLimitWatts: Double?
    let graphicsClockMHz: Double?
    let smClockMHz: Double?
    let memoryClockMHz: Double?
    let maxSMClockMHz: Double?
    let performanceState: String?
    let computeMode: String?
    let displayActive: Bool?
    let pcieGeneration: Int?
    let pcieWidth: Int?
    let isThrottled: Bool?
    let units: [UtilizationUnit]

    init(
        utilizationPercent: Double?,
        temperatureCelsius: Double?,
        powerWatts: Double?,
        powerLimitWatts: Double?,
        smClockMHz: Double?,
        maxSMClockMHz: Double?,
        isThrottled: Bool?,
        memoryUtilizationPercent: Double? = nil,
        graphicsClockMHz: Double? = nil,
        memoryClockMHz: Double? = nil,
        performanceState: String? = nil,
        computeMode: String? = nil,
        displayActive: Bool? = nil,
        pcieGeneration: Int? = nil,
        pcieWidth: Int? = nil,
        units: [UtilizationUnit] = []
    ) {
        self.utilizationPercent = utilizationPercent
        self.memoryUtilizationPercent = memoryUtilizationPercent
        self.temperatureCelsius = temperatureCelsius
        self.powerWatts = powerWatts
        self.powerLimitWatts = powerLimitWatts
        self.graphicsClockMHz = graphicsClockMHz
        self.smClockMHz = smClockMHz
        self.memoryClockMHz = memoryClockMHz
        self.maxSMClockMHz = maxSMClockMHz
        self.performanceState = performanceState
        self.computeMode = computeMode
        self.displayActive = displayActive
        self.pcieGeneration = pcieGeneration
        self.pcieWidth = pcieWidth
        self.isThrottled = isThrottled
        self.units = units
    }
}

struct CPUMetrics: Equatable, Sendable {
    let utilizationPercent: Double?
    let temperatureCelsius: Double?
    let averageFrequencyMHz: Double?
    let loadAverage1Minute: Double?
    let loadAverage5Minutes: Double?
    let loadAverage15Minutes: Double?
    let pressureAverage10Seconds: Double?
    let units: [UtilizationUnit]

    init(
        utilizationPercent: Double?,
        temperatureCelsius: Double?,
        averageFrequencyMHz: Double? = nil,
        loadAverage1Minute: Double? = nil,
        loadAverage5Minutes: Double? = nil,
        loadAverage15Minutes: Double? = nil,
        pressureAverage10Seconds: Double? = nil,
        units: [UtilizationUnit] = []
    ) {
        self.utilizationPercent = utilizationPercent
        self.temperatureCelsius = temperatureCelsius
        self.averageFrequencyMHz = averageFrequencyMHz
        self.loadAverage1Minute = loadAverage1Minute
        self.loadAverage5Minutes = loadAverage5Minutes
        self.loadAverage15Minutes = loadAverage15Minutes
        self.pressureAverage10Seconds = pressureAverage10Seconds
        self.units = units
    }
}

struct MemoryMetrics: Equatable, Sendable {
    let usedBytes: Double?
    let totalBytes: Double?
    let availableBytes: Double?
    let utilizationPercent: Double?
    let cachedBytes: Double?
    let swapUsedBytes: Double?
    let swapTotalBytes: Double?
    let pressureAverage10Seconds: Double?
    let clockMHz: Double?

    init(
        usedBytes: Double?,
        totalBytes: Double?,
        availableBytes: Double?,
        utilizationPercent: Double?,
        cachedBytes: Double? = nil,
        swapUsedBytes: Double? = nil,
        swapTotalBytes: Double? = nil,
        pressureAverage10Seconds: Double? = nil,
        clockMHz: Double? = nil
    ) {
        self.usedBytes = usedBytes
        self.totalBytes = totalBytes
        self.availableBytes = availableBytes
        self.utilizationPercent = utilizationPercent
        self.cachedBytes = cachedBytes
        self.swapUsedBytes = swapUsedBytes
        self.swapTotalBytes = swapTotalBytes
        self.pressureAverage10Seconds = pressureAverage10Seconds
        self.clockMHz = clockMHz
    }
}

struct StorageMetrics: Equatable, Sendable {
    let usedBytes: Double?
    let totalBytes: Double?
    let availableBytes: Double?
    let utilizationPercent: Double?
    let temperatureCelsius: Double?
    let readBytesPerSecond: Double?
    let writeBytesPerSecond: Double?
    let pressureAverage10Seconds: Double?

    init(
        usedBytes: Double?,
        totalBytes: Double?,
        availableBytes: Double?,
        utilizationPercent: Double?,
        temperatureCelsius: Double?,
        readBytesPerSecond: Double? = nil,
        writeBytesPerSecond: Double? = nil,
        pressureAverage10Seconds: Double? = nil
    ) {
        self.usedBytes = usedBytes
        self.totalBytes = totalBytes
        self.availableBytes = availableBytes
        self.utilizationPercent = utilizationPercent
        self.temperatureCelsius = temperatureCelsius
        self.readBytesPerSecond = readBytesPerSecond
        self.writeBytesPerSecond = writeBytesPerSecond
        self.pressureAverage10Seconds = pressureAverage10Seconds
    }
}

struct NetworkMetrics: Equatable, Sendable {
    let receiveBytesPerSecond: Double?
    let transmitBytesPerSecond: Double?
    let receivedPackets: Double?
    let transmittedPackets: Double?
    let receiveErrors: Double?
    let transmitErrors: Double?
    let receiveDrops: Double?
    let transmitDrops: Double?

    init(
        receiveBytesPerSecond: Double?,
        transmitBytesPerSecond: Double?,
        receivedPackets: Double? = nil,
        transmittedPackets: Double? = nil,
        receiveErrors: Double? = nil,
        transmitErrors: Double? = nil,
        receiveDrops: Double? = nil,
        transmitDrops: Double? = nil
    ) {
        self.receiveBytesPerSecond = receiveBytesPerSecond
        self.transmitBytesPerSecond = transmitBytesPerSecond
        self.receivedPackets = receivedPackets
        self.transmittedPackets = transmittedPackets
        self.receiveErrors = receiveErrors
        self.transmitErrors = transmitErrors
        self.receiveDrops = receiveDrops
        self.transmitDrops = transmitDrops
    }
}

struct LLMMetrics: Equatable, Sendable, Identifiable {
    let id: String
    let backend: String?
    let model: String?
    let generationTokensPerSecond: Double?
    let aggregateTokensPerSecond: Double?
    let prefillTokensPerSecond: Double?
    let runningRequests: Int?
    let waitingRequests: Int?
    let kvCacheUtilization: Double?

    init(
        id: String,
        backend: String?,
        model: String?,
        generationTokensPerSecond: Double?,
        aggregateTokensPerSecond: Double? = nil,
        prefillTokensPerSecond: Double?,
        runningRequests: Int?,
        waitingRequests: Int?,
        kvCacheUtilization: Double?
    ) {
        self.id = id
        self.backend = backend
        self.model = model
        self.generationTokensPerSecond = generationTokensPerSecond
        self.aggregateTokensPerSecond = aggregateTokensPerSecond
        self.prefillTokensPerSecond = prefillTokensPerSecond
        self.runningRequests = runningRequests
        self.waitingRequests = waitingRequests
        self.kvCacheUtilization = kvCacheUtilization
    }
}

private extension String {
    var nilIfEmpty: String? { isEmpty ? nil : self }
}

extension SiteSnapshot {
    static func controllerFacts(
        siteID: SavedSite.ID,
        facts: SiteMemberFacts
    ) -> SiteSnapshot? {
        guard facts.inventory != nil else { return nil }
        return SiteSnapshot(
            siteID: siteID,
            source: .controller,
            sampledAt: Date(timeIntervalSince1970: TimeInterval(facts.observedAtUnix)),
            availability: facts.memberAvailability,
            uptimeSeconds: facts.inventory?.uptimeSeconds.map { TimeInterval($0) },
            identity: nil,
            metrics: .empty
        ).enriched(with: facts)
    }

    func enriched(with facts: SiteMemberFacts) -> SiteSnapshot {
        guard let inventory = facts.inventory else { return self }
        let architecture = facts.platform.split(separator: "/", maxSplits: 1)
            .last.map(String.init)
        let mergedIdentity = MemberIdentity(
            vendor: inventory.productVendor ?? identity?.vendor,
            product: inventory.productName ?? identity?.product,
            architecture: architecture ?? identity?.architecture,
            gpuName: inventory.gpuName ?? identity?.gpuName
        )
        let previous = system
        let mergedSystem = MemberSystemInfo(
            hostname: inventory.hostname ?? previous?.hostname,
            operatingSystem: inventory.operatingSystem ?? previous?.operatingSystem,
            kernelVersion: inventory.kernelVersion ?? previous?.kernelVersion,
            productVersion: inventory.productVersion ?? previous?.productVersion,
            serialNumber: inventory.serialNumber ?? previous?.serialNumber,
            serialSource: inventory.serialSource ?? previous?.serialSource,
            systemUUID: inventory.systemUUID ?? previous?.systemUUID,
            machineIDHash: inventory.machineIDSHA256 ?? previous?.machineIDHash,
            dmiSerialRequiresPrivilege: inventory.dmiSerialRequiresPrivilege,
            boardVendor: inventory.boardVendor ?? previous?.boardVendor,
            boardName: inventory.boardName ?? previous?.boardName,
            boardVersion: inventory.boardVersion ?? previous?.boardVersion,
            boardSerial: inventory.boardSerial ?? previous?.boardSerial,
            chassisVendor: inventory.chassisVendor ?? previous?.chassisVendor,
            chassisType: inventory.chassisType ?? previous?.chassisType,
            chassisSerial: inventory.chassisSerial ?? previous?.chassisSerial,
            biosVendor: inventory.biosVendor ?? previous?.biosVendor,
            biosVersion: inventory.biosVersion ?? previous?.biosVersion,
            biosDate: inventory.biosDate ?? previous?.biosDate,
            cpuModel: inventory.cpuModel ?? previous?.cpuModel,
            cpuCoreCount: inventory.cpuCoreCount ?? previous?.cpuCoreCount,
            gpuUUID: inventory.gpuUUID ?? previous?.gpuUUID,
            nvidiaDriverVersion: inventory.nvidiaDriverVersion ?? previous?.nvidiaDriverVersion,
            dgxName: inventory.dgxName ?? previous?.dgxName,
            dgxSoftwareVersion: inventory.dgxSoftwareVersion ?? previous?.dgxSoftwareVersion,
            dgxBaseBuildVersion: inventory.dgxBaseBuildVersion ?? previous?.dgxBaseBuildVersion,
            dgxBuildDate: inventory.dgxBuildDate ?? previous?.dgxBuildDate,
            dgxCommitID: inventory.dgxCommitID ?? previous?.dgxCommitID,
            dgxPlatform: inventory.dgxPlatform ?? previous?.dgxPlatform,
            dgxUpdateDate: inventory.dgxUpdateDate ?? previous?.dgxUpdateDate,
            nvmeModel: inventory.nvmeModel ?? previous?.nvmeModel,
            nvmeSerial: inventory.nvmeSerial ?? previous?.nvmeSerial,
            nvmeFirmware: inventory.nvmeFirmware ?? previous?.nvmeFirmware,
            networkAddresses: inventory.networkAddresses,
            defaultNetworkInterface: inventory.defaultNetworkInterface
                ?? previous?.defaultNetworkInterface,
            processCount: inventory.processCount ?? previous?.processCount,
            activeUsers: inventory.activeUsers,
            loginSessionCount: inventory.loginSessionCount ?? previous?.loginSessionCount,
            lastLogin: inventory.lastLogin ?? previous?.lastLogin,
            firmwareUpdateCount: inventory.firmwareUpdateCount
                ?? previous?.firmwareUpdateCount,
            containers: inventory.containers
        )
        return SiteSnapshot(
            siteID: siteID,
            source: source,
            sampledAt: sampledAt,
            availability: facts.memberAvailability,
            uptimeSeconds: inventory.uptimeSeconds.map { TimeInterval($0) } ?? uptimeSeconds,
            identity: mergedIdentity,
            system: mergedSystem,
            metrics: metrics,
            letsinfer: letsinfer
        )
    }

    func enriched(with placement: SitePlacementRecord) -> SiteSnapshot {
        guard let current = letsinfer,
              let runtime = PlacementRuntimeIdentity(placement.runtime) else {
            return self
        }
        let capacity = placement.capacity
        let maxActive = capacity?.maxActiveRequests
            ?? placement.endpoints.map(\.maxActiveRequests).compactMap { $0 }.reduce(0, +)
        let maxContext = capacity?.maxContextTokens
            ?? placement.endpoints.map(\.maxContextTokens).compactMap { $0 }.max()
        let resolvedContext = maxContext.flatMap { $0 > 0 ? $0 : nil }
            ?? current.maxContextTokens
        let maxConnections = capacity?.maxConnections ?? max(maxActive, current.maxConnections)
        let status = SiteStatus(
            installationID: current.installationID,
            release: runtime.version ?? current.release,
            model: placement.model,
            engine: runtime.engine,
            runtimeName: runtime.name,
            runtimeVersion: runtime.version,
            manifestSHA256: current.manifestSHA256,
            cacheProvider: current.cacheProvider,
            cachePersistent: current.cachePersistent,
            inferencePort: current.inferencePort,
            maxConnections: maxConnections > 0 ? maxConnections : current.maxConnections,
            maxActiveRequests: maxActive > 0 ? maxActive : current.maxActiveRequests,
            maxContextTokens: resolvedContext,
            serviceState: current.serviceState,
            engineState: placement.state,
            protectionPhase: current.protectionPhase,
            protectionArmed: current.protectionArmed,
            tripLatched: current.tripLatched,
            containerName: current.containerName
        )
        var mergedMetrics = metrics
        mergedMetrics.llm = metrics.llm.map { value in
            LLMMetrics(
                id: value.id,
                backend: runtime.engine,
                model: placement.model,
                generationTokensPerSecond: value.generationTokensPerSecond,
                aggregateTokensPerSecond: value.aggregateTokensPerSecond,
                prefillTokensPerSecond: value.prefillTokensPerSecond,
                runningRequests: value.runningRequests,
                waitingRequests: value.waitingRequests,
                kvCacheUtilization: value.kvCacheUtilization
            )
        }
        return SiteSnapshot(
            siteID: siteID,
            source: source,
            sampledAt: sampledAt,
            availability: availability,
            uptimeSeconds: uptimeSeconds,
            identity: identity,
            system: system,
            metrics: mergedMetrics,
            letsinfer: status
        )
    }

    func enriched(with inference: SiteInferenceAggregate) -> SiteSnapshot {
        var mergedMetrics = metrics
        let previous = metrics.llm.first
        mergedMetrics.llm = [
            LLMMetrics(
                id: previous?.id ?? "letsinfer-gateway",
                backend: previous?.backend ?? letsinfer?.engine,
                model: previous?.model ?? letsinfer?.model,
                generationTokensPerSecond: inference.rates.decodeTokensPerSecond,
                aggregateTokensPerSecond: inference.rates.aggregateTokensPerSecond
                    ?? inference.rates.outputTokensPerSecond,
                prefillTokensPerSecond: inference.rates.prefillTokensPerSecond,
                runningRequests: Int(inference.activeRequests),
                waitingRequests: Int(inference.queuedRequests),
                kvCacheUtilization: previous?.kvCacheUtilization
            )
        ]
        return SiteSnapshot(
            siteID: siteID,
            source: source,
            sampledAt: sampledAt,
            availability: availability,
            uptimeSeconds: uptimeSeconds,
            identity: identity,
            system: system,
            metrics: mergedMetrics,
            letsinfer: letsinfer
        )
    }

    func enrichedIfFresh(with telemetry: SiteTelemetrySnapshot) -> SiteSnapshot {
        guard telemetry.isAtLeastAsFresh(as: sampledAt) else { return self }
        return enriched(with: telemetry.aggregate)
    }
}

private struct PlacementRuntimeIdentity {
    let engine: String
    let name: String
    let version: String?

    init?(_ value: String) {
        let identity = value.components(separatedBy: "@sha256:").first ?? value
        let parts = identity.split(separator: "/", omittingEmptySubsequences: false)
        guard parts.count == 3, !parts[1].isEmpty else { return nil }
        let targetAndVersion = parts[2].split(
            separator: "@", maxSplits: 1, omittingEmptySubsequences: false
        )
        guard let target = targetAndVersion.first, !target.isEmpty else { return nil }
        engine = String(parts[1])
        name = parts[0...1].map(String.init).joined(separator: "/")
            + "/" + String(target)
        if targetAndVersion.count == 2, !targetAndVersion[1].isEmpty {
            version = String(targetAndVersion[1])
        } else {
            version = nil
        }
    }
}

private extension SiteMemberFacts {
    var memberAvailability: MemberAvailability {
        switch health.state {
        case "healthy": .online
        case "degraded": .degraded
        default: .offline
        }
    }
}
