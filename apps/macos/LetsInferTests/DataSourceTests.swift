import Foundation
import Testing
@testable import LetsInfer

struct DataSourceTests {
    @Test
    func automaticRouterPrefersWatchdogAndFallsBackToSSH() async throws {
        let site = SavedSite(
            name: "Desk Spark",
            host: "site.local",
            username: "developer",
            authentication: .sshConfig
        )
        let preferred = RoutingSiteDataSource(
            ssh: StubDataSource(source: .ssh),
            watchdog: StubDataSource(source: .watchdog)
        )
        let fallback = RoutingSiteDataSource(
            ssh: StubDataSource(source: .ssh),
            watchdog: FailingDataSource()
        )

        #expect(try await preferred.fetchSnapshot(for: site).source == .watchdog)
        #expect(try await fallback.fetchSnapshot(for: site).source == .ssh)
    }

    @Test
    func pairedRouterNeverFallsBackToSSH() async {
        let site = SavedSite(
            name: "Home",
            host: "home.local",
            username: "unused",
            authentication: .sshConfig,
            installationID: String(repeating: "a", count: 64)
        )
        let router = RoutingSiteDataSource(
            ssh: StubDataSource(source: .ssh),
            watchdog: FailingDataSource()
        )
        do {
            _ = try await router.fetchSnapshot(for: site)
            Issue.record("A paired node must not use the SSH fallback")
        } catch let error as WatchdogClientError {
            guard case .connectionClosed = error else {
                Issue.record("Expected the Watchdog failure to be preserved")
                return
            }
        } catch {
            Issue.record("Expected the Watchdog failure to be preserved")
        }
    }

    @Test
    func sshAdapterNormalizesProbeAndCalculatesRates() async throws {
        let transport = SequencedSSHTransport(outputs: [
            Self.sshFixture(timestamp: 100, cpuTotal: 1_000, cpuIdle: 400, rx: 10_000, tx: 20_000),
            Self.sshFixture(timestamp: 102, cpuTotal: 1_200, cpuIdle: 450, rx: 12_000, tx: 21_000)
        ])
        let source = SSHSiteDataSource(transport: transport)
        let site = SavedSite(
            name: "Desk Spark",
            host: "site.local",
            username: "developer",
            authentication: .sshConfig
        )

        _ = try await source.fetchSnapshot(for: site)
        let snapshot = try await source.fetchSnapshot(for: site)

        #expect(snapshot.identity?.isGB10 == true)
        #expect(snapshot.identity?.manufacturerName == "ASUS")
        #expect(snapshot.system?.productVersion == "5.36_GX10DGX")
        #expect(snapshot.system?.serialNumber == "DGX123")
        #expect(snapshot.system?.dgxSoftwareVersion == "7.5.0")
        #expect(snapshot.system?.firmwareUpdateCount == 3)
        #expect(snapshot.system?.networkAddresses.first?.interface == "eth0")
        #expect(snapshot.system?.cpuCoreCount == 20)
        #expect(snapshot.system?.containers.first?.name == "inference")
        #expect(snapshot.metrics.cpu?.utilizationPercent == 75)
        #expect(snapshot.metrics.cpu?.units.count == 2)
        #expect(snapshot.metrics.cpu?.units.first?.name == "Core 0")
        #expect(snapshot.metrics.cpu?.units.first?.utilizationPercent == 75)
        #expect(snapshot.metrics.gpu?.units.count == 6)
        #expect(snapshot.metrics.gpu?.units.first?.name == "SM")
        #expect(snapshot.metrics.gpu?.units.first?.utilizationPercent == 80)
        #expect(snapshot.metrics.network?.receiveBytesPerSecond == 1_000)
        #expect(snapshot.metrics.network?.transmitBytesPerSecond == 500)
        #expect(snapshot.metrics.memory?.totalBytes == Double(128_000 * 1_024))
        #expect(snapshot.metrics.storage?.temperatureCelsius == 42)
        #expect(snapshot.metrics.storage?.readBytesPerSecond == 1_000)
    }

    @Test
    func watchdogCodecAndMappingAreBoundedAndNormalized() throws {
        #expect(WatchdogProtobuf.getLatest(requestID: 2) == Data([0x08, 0x02, 0x52, 0x00]))

        var gpu = Data()
        Self.writeUInt(field: 1, value: 96, to: &gpu)
        Self.writeUInt(field: 2, value: 91, to: &gpu)
        Self.writeMessage(field: 3, body: Data([96, 42, 1, 2, 3, 4]), to: &gpu)
        Self.writeUInt(field: 4, value: Self.zigZag(680), to: &gpu)
        Self.writeUInt(field: 5, value: 766, to: &gpu)
        Self.writeUInt(field: 6, value: 1_500, to: &gpu)
        Self.writeUInt(field: 7, value: 2_400, to: &gpu)

        var telemetry = Data()
        Self.writeUInt(field: 1, value: 42, to: &telemetry)
        Self.writeUInt(field: 2, value: 1_700_000_000_000, to: &telemetry)
        Self.writeUInt(field: 4, value: 0b1110, to: &telemetry)
        Self.writeUInt(field: 5, value: 10, to: &telemetry)
        Self.writeMessage(field: 6, body: Data([10, 20, 30]), to: &telemetry)
        Self.writeUInt(field: 7, value: 91, to: &telemetry)
        Self.writeUInt(field: 8, value: 55, to: &telemetry)
        Self.writeMessage(field: 9, body: gpu, to: &telemetry)
        Self.writeUInt(field: 10, value: Self.zigZag(740), to: &telemetry)
        Self.writeUInt(field: 11, value: Self.zigZag(560), to: &telemetry)
        Self.writeUInt(field: 12, value: 54, to: &telemetry)
        Self.writeUInt(field: 13, value: 116_480, to: &telemetry)
        Self.writeUInt(field: 14, value: 128_000, to: &telemetry)
        Self.writeUInt(field: 15, value: 506_000, to: &telemetry)
        Self.writeUInt(field: 16, value: 915_000, to: &telemetry)
        Self.writeUInt(field: 17, value: 100, to: &telemetry)
        Self.writeUInt(field: 18, value: 50, to: &telemetry)
        Self.writeUInt(field: 19, value: 8, to: &telemetry)
        Self.writeUInt(field: 20, value: 4, to: &telemetry)
        Self.writeUInt(field: 23, value: 3_800, to: &telemetry)
        Self.writeUInt(field: 24, value: 4_267, to: &telemetry)
        Self.writeUInt(field: 25, value: 2, to: &telemetry)
        Self.writeUInt(field: 26, value: 1, to: &telemetry)
        Self.writeUInt(field: 27, value: 5, to: &telemetry)
        Self.writeUInt(field: 28, value: 4, to: &telemetry)
        Self.writeUInt(field: 29, value: 3, to: &telemetry)
        Self.writeUInt(field: 30, value: 1, to: &telemetry)
        Self.writeUInt(field: 31, value: 2, to: &telemetry)
        Self.writeUInt(field: 32, value: 1, to: &telemetry)
        Self.writeUInt(field: 33, value: 1_000, to: &telemetry)
        Self.writeUInt(field: 34, value: 200, to: &telemetry)
        Self.writeUInt(field: 35, value: 200, to: &telemetry)
        Self.writeUInt(field: 36, value: 50, to: &telemetry)
        Self.writeUInt(field: 37, value: 400, to: &telemetry)
        Self.writeUInt(field: 38, value: 1_000, to: &telemetry)
        Self.writeUInt(field: 39, value: 1, to: &telemetry)
        Self.writeUInt(field: 40, value: 1, to: &telemetry)
        Self.writeUInt(field: 41, value: 3, to: &telemetry)
        Self.writeUInt(field: 42, value: 4, to: &telemetry)

        var envelope = Data()
        Self.writeUInt(field: 1, value: 7, to: &envelope)
        Self.writeMessage(field: 10, body: telemetry, to: &envelope)
        let response = try WatchdogProtobuf.decodeServerEnvelope(envelope)
        guard case .latest(7, let sample) = response else {
            Issue.record("Expected latest watchdog sample")
            return
        }

        let site = SavedSite(
            name: "Desk Spark",
            host: "site.local",
            username: "developer",
            authentication: .sshConfig
        )
        var previous = sample
        previous.unixMilliseconds -= 1_000
        previous.requestsReceived = 0
        previous.requestsAdmitted = 0
        previous.requestsCompleted = 0
        previous.requestsFailed = 0
        previous.requestsRetried = 0
        previous.inputTokens = 0
        previous.outputTokens = 0
        previous.cachedTokens = 0
        previous.queueMilliseconds = 0
        previous.ttftMilliseconds = 0
        previous.decodeMilliseconds = 0
        previous.exactTokenRequests = 0
        previous.prefixCacheHits = 0
        let snapshot = WatchdogDataSource.map(sample, to: site, previous: previous)
        #expect(snapshot.source == .watchdog)
        #expect(snapshot.metrics.gpu?.utilizationPercent == 96)
        #expect(snapshot.metrics.gpu?.temperatureCelsius == 68)
        #expect(snapshot.metrics.gpu?.powerWatts == 76.6)
        #expect(snapshot.metrics.gpu?.graphicsClockMHz == 1_500)
        #expect(snapshot.metrics.gpu?.memoryClockMHz == 2_400)
        #expect(snapshot.metrics.gpu?.units.count == 6)
        #expect(snapshot.metrics.cpu?.units.count == 3)
        #expect(snapshot.metrics.cpu?.temperatureCelsius == 74)
        #expect(snapshot.metrics.cpu?.averageFrequencyMHz == 3_800)
        #expect(snapshot.metrics.memory?.utilizationPercent == 91)
        #expect(snapshot.metrics.memory?.clockMHz == 4_267)
        #expect(snapshot.metrics.storage?.utilizationPercent == 55)
        #expect(snapshot.metrics.storage?.temperatureCelsius == 56)
        #expect(snapshot.metrics.network?.receiveBytesPerSecond == 102_400)
        #expect(sample.activeRequests == 2)
        #expect(sample.requestsRetried == 1)
        #expect(sample.requestsCancelled == 2)
        #expect(sample.prefixCacheHits == 1)
        #expect(sample.usageRecordsDropped == 3)
        #expect(sample.usageWriteErrors == 4)
        #expect(snapshot.metrics.llm.first?.runningRequests == 2)
        #expect(snapshot.metrics.llm.first?.waitingRequests == 1)
        #expect(snapshot.metrics.llm.first?.generationTokensPerSecond == 200)
        #expect(snapshot.metrics.llm.first?.aggregateTokensPerSecond == 200)
        #expect(snapshot.metrics.llm.first?.prefillTokensPerSecond == 2_000)

        var livePrevious = sample
        livePrevious.unixMilliseconds -= 1_000
        livePrevious.inputTokens -= 40
        livePrevious.outputTokens -= 12
        livePrevious.cachedTokens -= 10
        let live = WatchdogDataSource.map(
            sample, to: site, previous: livePrevious
        )
        #expect(live.metrics.llm.first?.generationTokensPerSecond == 12)
        #expect(live.metrics.llm.first?.aggregateTokensPerSecond == 12)
        #expect(live.metrics.llm.first?.prefillTokensPerSecond == 30)
    }

    @Test
    func watchdogV3CapabilitiesAndSiteStatusAreTyped() throws {
        #expect(WatchdogTLSClient.supportedProtocolVersion == 3)
        #expect(WatchdogProtobuf.getCapabilities(requestID: 7) == Data([0x08, 0x07, 0x6a, 0x00]))
        #expect(WatchdogProtobuf.getSiteStatus(requestID: 8) == Data([0x08, 0x08, 0x7a, 0x00]))

        var capabilities = Data()
        Self.writeUInt(field: 1, value: 3, to: &capabilities)
        Self.writeUInt(field: 2, value: 1_000, to: &capabilities)
        Self.writeUInt(field: 3, value: 10_000, to: &capabilities)
        Self.writeUInt(field: 4, value: 256, to: &capabilities)
        Self.writeUInt(field: 5, value: 1, to: &capabilities)
        Self.writeUInt(field: 6, value: 1, to: &capabilities)
        Self.writeUInt(field: 7, value: 1, to: &capabilities)
        var capabilitiesEnvelope = Data()
        Self.writeUInt(field: 1, value: 7, to: &capabilitiesEnvelope)
        Self.writeMessage(field: 14, body: capabilities, to: &capabilitiesEnvelope)

        guard case .capabilities(7, let decodedCapabilities) = try WatchdogProtobuf
            .decodeServerEnvelope(capabilitiesEnvelope) else {
            Issue.record("Expected Watchdog v3 capabilities")
            return
        }
        #expect(decodedCapabilities.protocolVersion == 3)
        #expect(decodedCapabilities.mutualTLSRequired)
        #expect(decodedCapabilities.physicalGPUCount == 1)

        var status = Data()
        Self.writeString(field: 1, value: "0.11.0-rc.3", to: &status)
        Self.writeString(field: 2, value: "fixture-model", to: &status)
        Self.writeString(field: 3, value: "dwarfstar", to: &status)
        Self.writeString(field: 4, value: "fixture-runtime", to: &status)
        Self.writeString(field: 5, value: "0.11.0-rc.3", to: &status)
        Self.writeString(field: 6, value: String(repeating: "a", count: 64), to: &status)
        Self.writeString(field: 7, value: "letsinfer-prefix", to: &status)
        Self.writeUInt(field: 8, value: 1, to: &status)
        Self.writeUInt(field: 9, value: 8_000, to: &status)
        Self.writeUInt(field: 10, value: 64, to: &status)
        Self.writeUInt(field: 11, value: 60, to: &status)
        Self.writeUInt(field: 12, value: 557_056, to: &status)
        Self.writeString(field: 13, value: "running", to: &status)
        Self.writeString(field: 14, value: "running", to: &status)
        Self.writeString(field: 15, value: "armed", to: &status)
        Self.writeUInt(field: 16, value: 1, to: &status)
        Self.writeString(field: 18, value: "letsinfer-dwarfstar", to: &status)
        Self.writeString(field: 19, value: String(repeating: "b", count: 64), to: &status)
        var statusEnvelope = Data()
        Self.writeUInt(field: 1, value: 8, to: &statusEnvelope)
        Self.writeMessage(field: 18, body: status, to: &statusEnvelope)

        guard case .letsinferStatus(8, let decodedStatus) = try WatchdogProtobuf
            .decodeServerEnvelope(statusEnvelope) else {
            Issue.record("Expected typed Let's Infer status")
            return
        }
        #expect(decodedStatus.release == "0.11.0-rc.3")
        #expect(decodedStatus.installationID == String(repeating: "b", count: 64))
        #expect(decodedStatus.engine == "dwarfstar")
        #expect(decodedStatus.protectionArmed)
        #expect(decodedStatus.maxActiveRequests == 60)
        #expect(decodedStatus.containerName == "letsinfer-dwarfstar")
    }

    @Test
    func watchdogOperationTimeoutIsBoundedAndCancelsTransport() async {
        let cancellation = CancellationProbe()
        let gate = WatchdogOperationGate<Int>(cancelConnection: { cancellation.record() })
        let started = ContinuousClock.now
        do {
            let _: Int = try await withCheckedThrowingContinuation { continuation in
                gate.install(continuation)
                gate.scheduleTimeout(after: 0.02, operation: "receive telemetry")
            }
            Issue.record("Expected Watchdog operation timeout")
        } catch let error as WatchdogClientError {
            guard case .timeout("receive telemetry") = error else {
                Issue.record("Expected the named timeout")
                return
            }
        } catch {
            Issue.record("Expected WatchdogClientError.timeout")
        }
        #expect(ContinuousClock.now - started < .seconds(1))
        #expect(cancellation.count == 1)
        gate.finish(.success(1))
        #expect(cancellation.count == 1)
    }

    @Test
    func controllerPairingChallengeAndVerificationMatchLetsInfer() {
        let installation = String(repeating: "1", count: 64)
        let session = String(repeating: "2", count: 32)
        let nonce = String(repeating: "3", count: 64)
        let controller = String(repeating: "4", count: 32)
        let publicKey = String(repeating: "5", count: 64)
        let challenge = ControllerPairingClient.challenge(
            installationID: installation,
            sessionID: session,
            nonce: nonce,
            controllerID: controller,
            name: "Desk Mac",
            publicKeySHA256: publicKey
        )
        #expect(String(decoding: challenge, as: UTF8.self) == """
        letsinfer-controller-pair-v1
        \(installation)
        \(session)
        \(nonce)
        \(controller)
        Desk Mac
        \(publicKey)

        """)
        #expect(ControllerPairingClient.confirmationCode(
            installationID: installation,
            sessionID: session,
            nonce: nonce,
            controllerID: controller,
            publicKeySHA256: publicKey
        ) == "833267")
    }

    @Test
    @MainActor
    func bonjourDiscoveryAcceptsOnlyCompleteMainIdentity() {
        let siteID = String(repeating: "a", count: 32)
        let memberID = String(repeating: "b", count: 32)
        let certificate = String(repeating: "c", count: 64)
        let publicKey = String(repeating: "d", count: 64)
        let fields = [
            "protocol": "1",
            "control": "letsinfer-node-control-v1",
            "role": "main",
            "state": "adoptable",
            "node": siteID,
            "machine": memberID,
            "tls": certificate,
            "key": publicKey,
            "inference": "http",
            "inference_port": "8000",
            "direct": "connectx"
        ]

        let site = BonjourDiscovery.validatedSite(
            fallbackID: "fallback",
            name: "Let's Infer — Home",
            host: "home.local.",
            port: 9_770,
            text: fields
        )
        #expect(site?.id == siteID)
        #expect(site?.displayName == "Home")
        #expect(site?.host == "home.local")
        #expect(site?.controlPort == 9_770)
        #expect(site?.coordinatorID == memberID)
        #expect(site?.inferenceEndpoint == "http://home.local:8000/v1")
        #expect(site?.directConnectX == true)
        #expect(site?.adoptable == true)

        var member = fields
        member["role"] = "child"
        #expect(BonjourDiscovery.validatedSite(
            fallbackID: "fallback",
            name: "Child",
            host: "child.local",
            port: 9_770,
            text: member
        ) == nil)

        var incomplete = fields
        incomplete.removeValue(forKey: "tls")
        #expect(BonjourDiscovery.validatedSite(
            fallbackID: "fallback",
            name: "Incomplete",
            host: "incomplete.local",
            port: 9_770,
            text: incomplete
        ) == nil)

        var invalidInference = fields
        invalidInference["inference"] = "https"
        #expect(BonjourDiscovery.validatedSite(
            fallbackID: "fallback",
            name: "Invalid inference",
            host: "invalid.local",
            port: 9_770,
            text: invalidInference
        ) == nil)
    }

    private static func writeUInt(field: Int, value: UInt64, to output: inout Data) {
        writeVarint(UInt64(field << 3), to: &output)
        writeVarint(value, to: &output)
    }

    private static func writeMessage(field: Int, body: Data, to output: inout Data) {
        writeVarint(UInt64(field << 3 | 2), to: &output)
        writeVarint(UInt64(body.count), to: &output)
        output.append(body)
    }

    private static func writeString(field: Int, value: String, to output: inout Data) {
        writeMessage(field: field, body: Data(value.utf8), to: &output)
    }

    private static func writeVarint(_ input: UInt64, to output: inout Data) {
        var value = input
        while value >= 0x80 {
            output.append(UInt8(truncatingIfNeeded: value) | 0x80)
            value >>= 7
        }
        output.append(UInt8(value))
    }

    private static func zigZag(_ value: Int32) -> UInt64 {
        UInt64((UInt32(bitPattern: value) << 1) ^ UInt32(bitPattern: value >> 31))
    }

    private static func sshFixture(
        timestamp: Int,
        cpuTotal: Int,
        cpuIdle: Int,
        rx: Int,
        tx: Int
    ) -> String {
        """
        timestamp\t\(timestamp)
        architecture\taarch64
        hostname\tspark-abcd
        operating_system\tUbuntu 24.04.4 LTS
        kernel\t6.17.0-1026-nvidia
        vendor\tASUSTeK COMPUTER INC.
        product\tGX10
        product_version\t5.36_GX10DGX
        product_serial\t
        product_uuid\t
        dgx_name\tNVIDIA DGX Spark
        dgx_serial\tDGX123
        dgx_ota_version\t7.5.0
        dgx_ota_date\tWed Jul 22 14:40:26 EDT 2026
        dgx_build_version\t7.2.3
        dgx_build_date\t2025-09-10-13-50-03
        dgx_commit_id\t833b4a7
        dgx_platform\tGX10
        dmi_serial_access\trestricted
        machine_id_hash\tabc123
        board_vendor\tASUSTeK COMPUTER INC.
        board_name\tGX10
        board_version\t
        board_serial\t
        chassis_vendor\tASUSTeK COMPUTER INC.
        chassis_type\t17
        chassis_serial\t
        bios_vendor\tAMI
        bios_version\t0104
        bios_date\t03/26/2026
        cpu_model\tCortex-X925 / Cortex-A725
        cpu_count\t20
        cpu_frequency_khz\t3000000
        uptime\t123.5
        load_average\t1.0 2.0 3.0
        mem_total_kb\t128000
        mem_available_kb\t64000
        mem_cached_kb\t32000
        swap_total_kb\t1000
        swap_free_kb\t500
        psi_cpu\tsome avg10=0.10 avg60=0.20 avg300=0.30 total=1
        psi_memory\tsome avg10=0.20 avg60=0.30 avg300=0.40 total=2
        psi_io\tsome avg10=0.30 avg60=0.40 avg300=0.50 total=3
        cpu_total\t\(cpuTotal)
        cpu_idle\t\(cpuIdle)
        cpu_cores\tcpu0|\(cpuTotal / 2)|\(cpuIdle / 2);;cpu1|\(cpuTotal / 2)|\(cpuIdle / 2)
        cpu_temp_millic\t51000
        nvme_temp_millic\t42000
        root_disk_kb\t1000000 100000 900000
        disk_read_bytes\t\(timestamp * 1000)
        disk_write_bytes\t\(timestamp * 500)
        net_rx\t\(rx)
        net_tx\t\(tx)
        net_rx_packets\t100
        net_tx_packets\t200
        net_rx_errors\t0
        net_tx_errors\t0
        net_rx_drops\t0
        net_tx_drops\t0
        network_addresses\teth0|inet|192.0.2.2/24;;tailscale0|inet|100.64.0.2/32
        default_interface\teth0
        process_count\t354
        active_users\tdeveloper
        login_sessions\t1
        last_login\tdeveloper pts/0 192.0.2.1
        firmware_update_count\t3
        nvme_model\tTest SSD
        nvme_serial\tSSD123
        nvme_firmware\t1.0
        containers\tinference|test/image|Up 10 minutes
        gpu\tNVIDIA GB10, GPU-test, 580.159.03, 61, 80, 0, 95, [N/A], 1500, 1500, [N/A], 2000, P0, Default, Disabled, 1, 1, Not Active, Not Active, Not Active, Not Active
        gpu_engines\t80|42|1|2|3|4
        """
    }
}

private final class CancellationProbe: @unchecked Sendable {
    private let lock = NSLock()
    private var value = 0

    var count: Int {
        lock.lock()
        defer { lock.unlock() }
        return value
    }

    func record() {
        lock.lock()
        value += 1
        lock.unlock()
    }
}

private struct StubDataSource: SiteDataSource {
    let source: SiteDataSourceKind

    func fetchSnapshot(for site: SavedSite) async throws -> SiteSnapshot {
        SiteSnapshot(
            siteID: site.id,
            source: source,
            sampledAt: Date(),
            availability: .online,
            uptimeSeconds: nil,
            identity: nil,
            metrics: .empty
        )
    }
}

private struct FailingDataSource: SiteDataSource {
    func fetchSnapshot(for site: SavedSite) async throws -> SiteSnapshot {
        throw WatchdogClientError.connectionClosed
    }
}

private actor SequencedSSHTransport: SSHTransport {
    private var outputs: [String]

    init(outputs: [String]) {
        self.outputs = outputs
    }

    func run(_ command: String, on site: SavedSite) async throws -> String {
        guard !outputs.isEmpty else {
            throw SSHTransportError.commandFailed("No fixture output")
        }
        return outputs.removeFirst()
    }
}
