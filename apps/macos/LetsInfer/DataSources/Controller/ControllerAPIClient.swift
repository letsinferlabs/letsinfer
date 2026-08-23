import Foundation
import Security

private let controllerProtocol = "letsinfer-controller-control-v1"
private let maximumControllerResponseBytes = 1_048_576

struct ControllerPrincipal: Decodable, Equatable, Sendable {
    let id: String
    let role: String
}

struct LogicalSiteIdentity: Decodable, Equatable, Sendable {
    let siteID: String
    let memberID: String
    let displayName: String
    let role: String
    let coordinatorID: String
    let coordinatorAddress: String
    let memberPublicKeySHA256: String

    enum CodingKeys: String, CodingKey {
        case siteID = "node_id"
        case memberID = "machine_id"
        case displayName = "display_name"
        case role
        case coordinatorID = "main_id"
        case coordinatorAddress = "main_address"
        case memberPublicKeySHA256 = "machine_public_key_sha256"
    }
}

struct SiteMemberHealthFacts: Decodable, Equatable, Sendable {
    let state: String
    let memoryPressure: Bool
    let protectionTrip: Bool
    let maxTemperatureCelsius: Double

    enum CodingKeys: String, CodingKey {
        case state
        case memoryPressure = "memory_pressure"
        case protectionTrip = "protection_trip"
        case maxTemperatureCelsius = "max_temperature_c"
    }
}

struct SiteMemberInventory: Decodable, Equatable, Sendable {
    let hostname: String?
    let operatingSystem: String?
    let kernelVersion: String?
    let productVendor: String?
    let productName: String?
    let productVersion: String?
    let serialNumber: String?
    let serialSource: String?
    let systemUUID: String?
    let machineIDSHA256: String?
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
    let gpuName: String?
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
    let uptimeSeconds: Int?
    let processCount: Int?
    let activeUsers: [String]
    let loginSessionCount: Int?
    let lastLogin: String?
    let firmwareUpdateCount: Int?
    let containers: [ContainerInfo]

    enum CodingKeys: String, CodingKey {
        case hostname
        case operatingSystem = "operating_system"
        case kernelVersion = "kernel_version"
        case productVendor = "product_vendor"
        case productName = "product_name"
        case productVersion = "product_version"
        case serialNumber = "serial_number"
        case serialSource = "serial_source"
        case systemUUID = "system_uuid"
        case machineIDSHA256 = "machine_id_sha256"
        case dmiSerialRequiresPrivilege = "dmi_serial_requires_privilege"
        case boardVendor = "board_vendor"
        case boardName = "board_name"
        case boardVersion = "board_version"
        case boardSerial = "board_serial"
        case chassisVendor = "chassis_vendor"
        case chassisType = "chassis_type"
        case chassisSerial = "chassis_serial"
        case biosVendor = "bios_vendor"
        case biosVersion = "bios_version"
        case biosDate = "bios_date"
        case cpuModel = "cpu_model"
        case cpuCoreCount = "cpu_core_count"
        case gpuName = "gpu_name"
        case gpuUUID = "gpu_uuid"
        case nvidiaDriverVersion = "nvidia_driver_version"
        case dgxName = "dgx_name"
        case dgxSoftwareVersion = "dgx_software_version"
        case dgxBaseBuildVersion = "dgx_base_build_version"
        case dgxBuildDate = "dgx_build_date"
        case dgxCommitID = "dgx_commit_id"
        case dgxPlatform = "dgx_platform"
        case dgxUpdateDate = "dgx_update_date"
        case nvmeModel = "nvme_model"
        case nvmeSerial = "nvme_serial"
        case nvmeFirmware = "nvme_firmware"
        case networkAddresses = "network_addresses"
        case defaultNetworkInterface = "default_network_interface"
        case uptimeSeconds = "uptime_seconds"
        case processCount = "process_count"
        case activeUsers = "active_users"
        case loginSessionCount = "login_session_count"
        case lastLogin = "last_login"
        case firmwareUpdateCount = "firmware_update_count"
        case containers
    }
}

struct SiteMemberFacts: Decodable, Equatable, Sendable {
    let schemaVersion: Int
    let memberID: String
    let observedAtUnix: Int
    let platform: String
    let health: SiteMemberHealthFacts
    let inventory: SiteMemberInventory?

    enum CodingKeys: String, CodingKey {
        case schemaVersion = "schema_version"
        case memberID = "member_id"
        case observedAtUnix = "observed_at_unix"
        case platform, health, inventory
    }
}

struct SiteMemberRecord: Decodable, Equatable, Identifiable, Sendable {
    var id: String { memberID }
    let memberID: String
    let displayName: String
    let role: String
    let address: String
    let state: String
    let certificateSHA256: String
    let facts: SiteMemberFacts?
    let factsSHA256: String?
    let joinedAtUnix: Int
    let updatedAtUnix: Int

    enum CodingKeys: String, CodingKey {
        case memberID = "member_id"
        case displayName = "display_name"
        case role, address, state
        case certificateSHA256 = "certificate_sha256"
        case facts
        case factsSHA256 = "facts_sha256"
        case joinedAtUnix = "joined_at_unix"
        case updatedAtUnix = "updated_at_unix"
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        memberID = try container.decode(String.self, forKey: .memberID)
        displayName = try container.decode(String.self, forKey: .displayName)
        role = try container.decode(String.self, forKey: .role)
        address = try container.decode(String.self, forKey: .address)
        state = try container.decode(String.self, forKey: .state)
        certificateSHA256 = try container.decode(String.self, forKey: .certificateSHA256)
        facts = try container.decodeIfPresent(SiteMemberFacts.self, forKey: .facts)
        factsSHA256 = try container.decodeIfPresent(String.self, forKey: .factsSHA256)
        joinedAtUnix = try container.decode(Int.self, forKey: .joinedAtUnix)
        updatedAtUnix = try container.decode(Int.self, forKey: .updatedAtUnix)
    }
}

struct SitePlacementRecord: Decodable, Equatable, Identifiable, Sendable {
    var id: String { placementID }
    let groupID: String
    let placementID: String
    let model: String
    let runtime: String
    let target: String
    let strategy: String
    let state: String
    let members: [String]
    let endpoints: [SitePlacementEndpoint]
    let capacity: SitePlacementCapacity?
    let release: SiteRuntimeRelease?
    let endpointOwner: String?
    let resourceAssignments: [SiteResourceAssignment]
    let taskStates: [SiteTaskState]
    let connections: [SiteGroupConnection]
    let deviceAllocations: [SiteDeviceAllocation]
    let telemetry: SiteGroupTelemetry?
    let updatedAtUnix: Int

    enum CodingKeys: String, CodingKey {
        case groupID = "group_id"
        case placementID = "placement_id"
        case model, runtime, target, strategy, state, members, endpoints, capacity
        case release
        case endpointOwner = "endpoint_owner"
        case resourceAssignments = "resource_assignments"
        case taskStates = "task_states"
        case connections
        case deviceAllocations = "device_allocations"
        case telemetry
        case updatedAtUnix = "updated_at_unix"
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        placementID = try container.decode(String.self, forKey: .placementID)
        groupID = try container.decodeIfPresent(String.self, forKey: .groupID)
            ?? placementID
        model = try container.decode(String.self, forKey: .model)
        runtime = try container.decode(String.self, forKey: .runtime)
        target = try container.decode(String.self, forKey: .target)
        strategy = try container.decode(String.self, forKey: .strategy)
        state = try container.decode(String.self, forKey: .state)
        members = try container.decode([String].self, forKey: .members)
        endpoints = try container.decodeIfPresent(
            [SitePlacementEndpoint].self, forKey: .endpoints
        ) ?? []
        capacity = try container.decodeIfPresent(
            SitePlacementCapacity.self, forKey: .capacity
        )
        release = try container.decodeIfPresent(
            SiteRuntimeRelease.self, forKey: .release
        )
        endpointOwner = try container.decodeIfPresent(
            String.self, forKey: .endpointOwner
        )
        resourceAssignments = try container.decodeIfPresent(
            [SiteResourceAssignment].self, forKey: .resourceAssignments
        ) ?? []
        taskStates = try container.decodeIfPresent(
            [SiteTaskState].self, forKey: .taskStates
        ) ?? []
        connections = try container.decodeIfPresent(
            [SiteGroupConnection].self, forKey: .connections
        ) ?? []
        deviceAllocations = try container.decodeIfPresent(
            [SiteDeviceAllocation].self, forKey: .deviceAllocations
        ) ?? []
        telemetry = try container.decodeIfPresent(
            SiteGroupTelemetry.self, forKey: .telemetry
        )
        updatedAtUnix = try container.decodeIfPresent(
            Int.self, forKey: .updatedAtUnix
        ) ?? 0
    }
}

struct SiteResourceAssignment: Decodable, Equatable, Sendable {
    let nodeID: String
    let address: String
    let taskID: String
    let portBase: Int
    let portCount: Int
    let deviceUUIDs: [String]

    enum CodingKeys: String, CodingKey {
        case nodeID = "node_id"
        case address
        case taskID = "task_id"
        case portBase = "port_base"
        case portCount = "port_count"
        case deviceUUIDs = "device_uuids"
    }
}

struct SiteTaskState: Decodable, Equatable, Sendable {
    let nodeID: String
    let taskID: String
    let state: String
    let error: String?

    enum CodingKeys: String, CodingKey {
        case nodeID = "node_id"
        case taskID = "task_id"
        case state, error
    }
}

struct SiteGroupConnection: Decodable, Equatable, Sendable {
    let nodes: [String]
    let kind: String
    let speedMbps: Int
    let mtu: Int
    let rdma: Bool

    enum CodingKeys: String, CodingKey {
        case nodes, kind, mtu, rdma
        case speedMbps = "speed_mbps"
    }
}

struct SiteRuntimeRelease: Decodable, Equatable, Sendable {
    let candidateID: String
    let version: String
    let qualification: String
    let authors: [String]

    enum CodingKeys: String, CodingKey {
        case candidateID = "candidate_id"
        case version, qualification, authors
    }
}

struct SiteDeviceAllocation: Decodable, Equatable, Sendable {
    let machineID: String
    let deviceUUID: String
    let state: String

    enum CodingKeys: String, CodingKey {
        case machineID = "machine_id"
        case deviceUUID = "device_uuid"
        case state
    }
}

struct SiteGroupTelemetry: Decodable, Equatable, Sendable {
    let activeRequests: Int
    let maxActiveRequests: Int

    enum CodingKeys: String, CodingKey {
        case activeRequests = "active_requests"
        case maxActiveRequests = "max_active_requests"
    }
}

struct SitePlacementEndpoint: Decodable, Equatable, Sendable {
    let memberID: String
    let maxActiveRequests: Int?
    let maxContextTokens: Int?

    enum CodingKeys: String, CodingKey {
        case memberID = "member_id"
        case maxActiveRequests = "max_active_requests"
        case maxContextTokens = "max_context_tokens"
    }
}

struct SitePlacementCapacity: Decodable, Equatable, Sendable {
    let maxConnections: Int?
    let maxActiveRequests: Int?
    let maxContextTokens: Int?

    enum CodingKeys: String, CodingKey {
        case maxConnections = "max_connections"
        case maxActiveRequests = "max_active_requests"
        case maxContextTokens = "max_context_tokens"
    }
}

struct SiteTopologyRecord: Decodable, Equatable, Sendable {
    let valid: Bool
    let topologySHA256: String?
    let error: String?

    enum CodingKeys: String, CodingKey {
        case valid
        case topologySHA256 = "topology_sha256"
        case error
    }
}

struct SiteExposureRecord: Decodable, Equatable, Sendable {
    let provider: String
    let publicURL: String
    let state: String
    let inferenceTarget: String
    let configurationSHA256: String
    let updatedAtUnix: Int

    enum CodingKeys: String, CodingKey {
        case provider, state
        case publicURL = "public_url"
        case inferenceTarget = "inference_target"
        case configurationSHA256 = "configuration_sha256"
        case updatedAtUnix = "updated_at_unix"
    }
}

struct SiteTopologyPlanRecord: Decodable, Equatable, Identifiable, Sendable {
    var id: String { planID }
    let planID: String
    let model: String
    let proposedSHA256: String
    let state: String
    let createdAtUnix: Int

    enum CodingKeys: String, CodingKey {
        case planID = "plan_id"
        case model, state
        case proposedSHA256 = "proposed_sha256"
        case createdAtUnix = "created_at_unix"
    }
}

struct ControllerSiteDocument: Decodable, Equatable, Sendable {
    let schemaVersion: Int
    let identity: LogicalSiteIdentity
    let members: [SiteMemberRecord]
    let topology: SiteTopologyRecord
    let services: [ControllerModelService]
    let pendingTopologyPlans: [SiteTopologyPlanRecord]
    let exposure: SiteExposureRecord

    enum CodingKeys: String, CodingKey {
        case schemaVersion = "schema_version"
        case identity, topology, services, exposure
        case members = "machines"
        case pendingTopologyPlans = "pending_topology_plans"
    }

    var activeMemberCount: Int {
        members.count { $0.state == "active" }
    }

    var placements: [SitePlacementRecord] {
        services.flatMap(\.groups)
    }

    var currentPlacements: [SitePlacementRecord] {
        var selected: [String: (record: SitePlacementRecord, priority: (Int, Int, String))] = [:]
        var modelOrder: [String] = []
        for placement in placements {
            if selected[placement.model] == nil {
                modelOrder.append(placement.model)
            }
            let candidate = (
                placement.updatedAtUnix,
                Self.placementPriority(placement.state),
                placement.placementID
            )
            if let current = selected[placement.model],
               !Self.isNewer(candidate, than: current.priority) {
                continue
            }
            selected[placement.model] = (placement, candidate)
        }
        return modelOrder.compactMap { selected[$0]?.record }
    }

    private static func placementPriority(_ state: String) -> Int {
        switch state {
        case "failed": 0
        case "stopped": 1
        case "draining": 2
        case "starting": 3
        case "running": 4
        default: -1
        }
    }

    private static func isNewer(
        _ candidate: (Int, Int, String),
        than current: (Int, Int, String)
    ) -> Bool {
        if candidate.0 != current.0 { return candidate.0 > current.0 }
        if candidate.1 != current.1 { return candidate.1 > current.1 }
        return candidate.2 > current.2
    }
}

struct ControllerModelService: Decodable, Equatable, Identifiable, Sendable {
    var id: String { serviceID }
    let serviceID: String
    let model: String
    let desiredState: String
    let groups: [SitePlacementRecord]
    let telemetry: SiteServiceTelemetry

    enum CodingKeys: String, CodingKey {
        case serviceID = "service_id"
        case model, groups, telemetry
        case desiredState = "desired_state"
    }
}

struct SiteServiceTelemetry: Decodable, Equatable, Sendable {
    let activeRequests: Int
    let queuedRequests: Int
    let available: Bool

    enum CodingKeys: String, CodingKey {
        case activeRequests = "active_requests"
        case queuedRequests = "queued_requests"
        case available
    }
}

struct ControllerSiteEnvelope: Decodable, Equatable, Sendable {
    let protocolName: String
    let controller: ControllerPrincipal
    let site: ControllerSiteDocument

    enum CodingKeys: String, CodingKey {
        case protocolName = "protocol"
        case controller
        case site = "node"
    }
}

struct SiteInferenceAggregate: Decodable, Equatable, Sendable {
    let activeRequests: UInt64
    let queuedRequests: UInt64
    let requestsReceived: UInt64
    let requestsAdmitted: UInt64
    let requestsCompleted: UInt64
    let requestsFailed: UInt64
    let requestsCancelled: UInt64
    let requestsRetried: UInt64
    let inputTokens: UInt64
    let outputTokens: UInt64
    let cachedTokens: UInt64
    let queueMilliseconds: UInt64
    let ttftMilliseconds: UInt64
    let decodeMilliseconds: UInt64
    let exactTokenRequests: UInt64
    let prefixCacheHits: UInt64
    let usageRecordsDropped: UInt64
    let usageWriteErrors: UInt64
    let rates: SiteInferenceRates

    enum CodingKeys: String, CodingKey {
        case activeRequests = "active_requests"
        case queuedRequests = "queued_requests"
        case requestsReceived = "requests_received"
        case requestsAdmitted = "requests_admitted"
        case requestsCompleted = "requests_completed"
        case requestsFailed = "requests_failed"
        case requestsCancelled = "requests_cancelled"
        case requestsRetried = "requests_retried"
        case inputTokens = "input_tokens"
        case outputTokens = "output_tokens"
        case cachedTokens = "cached_tokens"
        case queueMilliseconds = "queue_milliseconds"
        case ttftMilliseconds = "ttft_milliseconds"
        case decodeMilliseconds = "decode_milliseconds"
        case exactTokenRequests = "exact_token_requests"
        case prefixCacheHits = "prefix_cache_hits"
        case usageRecordsDropped = "usage_records_dropped"
        case usageWriteErrors = "usage_write_errors"
        case rates
    }
}

struct SiteInferenceLogicalCounters: Decodable, Equatable, Sendable {
    let requestsReceived: UInt64
    let requestsAdmitted: UInt64
    let requestsCompleted: UInt64
    let requestsFailed: UInt64
    let requestsCancelled: UInt64
    let requestsRetried: UInt64
    let inputTokens: UInt64
    let outputTokens: UInt64
    let cachedTokens: UInt64
    let queueMilliseconds: UInt64
    let ttftMilliseconds: UInt64
    let decodeMilliseconds: UInt64
    let exactTokenRequests: UInt64
    let prefixCacheHits: UInt64
    let usageRecordsDropped: UInt64
    let usageWriteErrors: UInt64

    enum CodingKeys: String, CodingKey {
        case requestsReceived = "requests_received"
        case requestsAdmitted = "requests_admitted"
        case requestsCompleted = "requests_completed"
        case requestsFailed = "requests_failed"
        case requestsCancelled = "requests_cancelled"
        case requestsRetried = "requests_retried"
        case inputTokens = "input_tokens"
        case outputTokens = "output_tokens"
        case cachedTokens = "cached_tokens"
        case queueMilliseconds = "queue_milliseconds"
        case ttftMilliseconds = "ttft_milliseconds"
        case decodeMilliseconds = "decode_milliseconds"
        case exactTokenRequests = "exact_token_requests"
        case prefixCacheHits = "prefix_cache_hits"
        case usageRecordsDropped = "usage_records_dropped"
        case usageWriteErrors = "usage_write_errors"
    }
}

struct SiteInferenceRates: Decodable, Equatable, Sendable {
    let requestsPerSecond: Double?
    let failuresPerSecond: Double?
    let cancellationsPerSecond: Double?
    let retriesPerSecond: Double?
    let inputTokensPerSecond: Double?
    let outputTokensPerSecond: Double?
    let aggregateTokensPerSecond: Double?
    let cachedTokensPerSecond: Double?
    let prefillTokensPerSecond: Double?
    let decodeTokensPerSecond: Double?
    let averageQueueMilliseconds: Double?
    let averageTTFTMilliseconds: Double?
    let averageDecodeMilliseconds: Double?
    let prefixCacheHitRatio: Double?
    let exactTokenRatio: Double?

    enum CodingKeys: String, CodingKey {
        case requestsPerSecond = "requests_per_second"
        case failuresPerSecond = "failures_per_second"
        case cancellationsPerSecond = "cancellations_per_second"
        case retriesPerSecond = "retries_per_second"
        case inputTokensPerSecond = "input_tokens_per_second"
        case outputTokensPerSecond = "output_tokens_per_second"
        case aggregateTokensPerSecond = "aggregate_tokens_per_second"
        case cachedTokensPerSecond = "cached_tokens_per_second"
        case prefillTokensPerSecond = "prefill_tokens_per_second"
        case decodeTokensPerSecond = "decode_tokens_per_second"
        case averageQueueMilliseconds = "average_queue_milliseconds"
        case averageTTFTMilliseconds = "average_ttft_milliseconds"
        case averageDecodeMilliseconds = "average_decode_milliseconds"
        case prefixCacheHitRatio = "prefix_cache_hit_ratio"
        case exactTokenRatio = "exact_token_ratio"
    }
}

struct SiteMemberSystemTelemetry: Decodable, Equatable, Sendable {
    let cpuCorePercent: [Int]
    let cpuPercent: Int
    let gpuPercent: Int
    let memoryPercent: Int
    let diskPercent: Int
    let gpuMemoryPercent: Int
    let gpuEnginePercent: [Int]
    let systemTemperatureDeciCelsius: Int
    let gpuTemperatureDeciCelsius: Int
    let nvmeTemperatureDeciCelsius: Int
    let powerDeciWatts: Int
    let loadOneMinuteCenti: Int
    let memoryUsedMiB: Int
    let memoryTotalMiB: Int
    let diskUsedMiB: Int
    let diskTotalMiB: Int
    let networkReceiveKiBPerSecond: Int
    let networkTransmitKiBPerSecond: Int
    let diskReadKiBPerSecond: Int
    let diskWriteKiBPerSecond: Int
    let cpuClockMHz: Int
    let gpuClockMHz: Int
    let vramClockMHz: Int
    let systemRAMClockMHz: Int

    enum CodingKeys: String, CodingKey {
        case cpuCorePercent = "cpu_core_percent"
        case cpuPercent = "cpu_percent"
        case gpuPercent = "gpu_percent"
        case memoryPercent = "memory_percent"
        case diskPercent = "disk_percent"
        case gpuMemoryPercent = "gpu_memory_percent"
        case gpuEnginePercent = "gpu_engine_percent"
        case systemTemperatureDeciCelsius = "system_temp_deci_c"
        case gpuTemperatureDeciCelsius = "gpu_temp_deci_c"
        case nvmeTemperatureDeciCelsius = "nvme_temp_deci_c"
        case powerDeciWatts = "power_deci_w"
        case loadOneMinuteCenti = "load1_centi"
        case memoryUsedMiB = "memory_used_mib"
        case memoryTotalMiB = "memory_total_mib"
        case diskUsedMiB = "disk_used_mib"
        case diskTotalMiB = "disk_total_mib"
        case networkReceiveKiBPerSecond = "network_rx_kib_s"
        case networkTransmitKiBPerSecond = "network_tx_kib_s"
        case diskReadKiBPerSecond = "disk_read_kib_s"
        case diskWriteKiBPerSecond = "disk_write_kib_s"
        case cpuClockMHz = "cpu_clock_mhz"
        case gpuClockMHz = "gpu_clock_mhz"
        case vramClockMHz = "vram_clock_mhz"
        case systemRAMClockMHz = "system_ram_clock_mhz"
    }
}

struct SiteMemberInferenceTelemetry: Decodable, Equatable, Sendable {
    let gatewayAvailable: Bool
    let activeRequests: UInt64
    let queuedRequests: UInt64
    let counters: SiteInferenceLogicalCounters

    enum CodingKeys: String, CodingKey {
        case gatewayAvailable = "gateway_available"
        case activeRequests = "active_requests"
        case queuedRequests = "queued_requests"
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        gatewayAvailable = try container.decode(Bool.self, forKey: .gatewayAvailable)
        activeRequests = try container.decode(UInt64.self, forKey: .activeRequests)
        queuedRequests = try container.decode(UInt64.self, forKey: .queuedRequests)
        counters = try SiteInferenceLogicalCounters(from: decoder)
    }
}

struct SiteMemberWorkloadTelemetry: Decodable, Equatable, Sendable {
    let type: Int
    let id: UInt64
    let gpuAvailable: Bool
    let throttled: Bool

    enum CodingKeys: String, CodingKey {
        case type, id
        case gpuAvailable = "gpu_available"
        case throttled
    }
}

struct SiteMemberTelemetrySample: Decodable, Equatable, Sendable {
    let schemaVersion: Int
    let memberID: String
    let sequence: UInt64
    let unixMilliseconds: UInt64
    let monotonicMilliseconds: UInt64
    let system: SiteMemberSystemTelemetry
    let inference: SiteMemberInferenceTelemetry
    let workload: SiteMemberWorkloadTelemetry

    enum CodingKeys: String, CodingKey {
        case schemaVersion = "schema_version"
        case memberID = "member_id"
        case sequence
        case unixMilliseconds = "unix_ms"
        case monotonicMilliseconds = "monotonic_ms"
        case system, inference, workload
    }
}

struct SiteMemberTelemetry: Decodable, Equatable, Identifiable, Sendable {
    var id: String { sample.memberID }
    let sample: SiteMemberTelemetrySample
    let stale: Bool
    let logicalCounters: SiteInferenceLogicalCounters
    let rates: SiteInferenceRates

    enum CodingKeys: String, CodingKey {
        case sample, stale, rates
        case logicalCounters = "logical_counters"
    }
}

struct SiteTelemetrySnapshot: Decodable, Equatable, Sendable {
    let schemaVersion: Int
    let unixMilliseconds: UInt64
    let members: [SiteMemberTelemetry]
    let aggregate: SiteInferenceAggregate

    enum CodingKeys: String, CodingKey {
        case schemaVersion = "schema_version"
        case unixMilliseconds = "unix_ms"
        case members, aggregate
    }
}

extension SiteTelemetrySnapshot {
    func isAtLeastAsFresh(as date: Date) -> Bool {
        guard let newest = members.map(\.sample.unixMilliseconds).max() else {
            return false
        }
        return newest >= UInt64(max(0, date.timeIntervalSince1970 * 1_000))
    }
}

struct ControllerTelemetryEnvelope: Decodable, Equatable, Sendable {
    let protocolName: String
    let controller: ControllerPrincipal
    let telemetry: SiteTelemetrySnapshot

    enum CodingKeys: String, CodingKey {
        case protocolName = "protocol"
        case controller, telemetry
    }
}

enum ControllerSiteAction: String, Sendable {
    case start
    case stop
    case restart
    case recover
    case install
    case topologyPlan = "topology-plan"
    case expose
    case unexpose
}

struct ControllerActionRecord: Decodable, Equatable, Sendable {
    let operationID: String
    let action: String
    let state: String
    let result: ControllerActionResult?
    let error: String?

    enum CodingKeys: String, CodingKey {
        case operationID = "operation_id"
        case action, state, result, error
    }
}

struct ControllerActionResult: Decodable, Equatable, Sendable {
    let resource: String
    let identifier: String
    let state: String
    let model: String?
}

struct ControllerActionEnvelope: Decodable, Equatable, Sendable {
    let protocolName: String
    let controller: ControllerPrincipal
    let action: ControllerActionRecord

    enum CodingKeys: String, CodingKey {
        case protocolName = "protocol"
        case controller, action
    }
}

struct SiteMovePlan: Decodable, Equatable, Sendable {
    let sourceSiteID: String
    let sourceMemberID: String
    let destinationEffect: String
    let memberCount: Int
    let controllerCount: Int
    let apiKeyCount: Int
    let placementCount: Int
    let activePlacements: [SiteMovePlacement]
    let blockingReasons: [String]
    let preservedData: [String]
    let resetState: [String]

    enum CodingKeys: String, CodingKey {
        case sourceSiteID = "source_site_id"
        case sourceMemberID = "source_member_id"
        case destinationEffect = "destination_effect"
        case memberCount = "member_count"
        case controllerCount = "controller_count"
        case apiKeyCount = "api_key_count"
        case placementCount = "placement_count"
        case activePlacements = "active_placements"
        case blockingReasons = "blocking_reasons"
        case preservedData = "preserved_data"
        case resetState = "reset_state"
    }
}

struct SiteMovePlacement: Decodable, Equatable, Identifiable, Sendable {
    var id: String { placementID }
    let placementID: String
    let model: String
    let runtime: String
    let target: String
    let strategy: String
    let state: String

    enum CodingKeys: String, CodingKey {
        case placementID = "placement_id"
        case model, runtime, target, strategy, state
    }
}

struct SiteMovePlanResult: Decodable, Equatable, Sendable {
    let plan: SiteMovePlan
}

struct MemberInvite: Decodable, Equatable, Sendable {
    let inviteID: String
    let mode: String
    let code: String?
    let expiresAtUnix: Int
    let endpoint: String
    let coordinatorCertificateSHA256: String

    enum CodingKeys: String, CodingKey {
        case inviteID = "invite_id"
        case mode, code, endpoint
        case expiresAtUnix = "expires_at_unix"
        case coordinatorCertificateSHA256 = "main_certificate_sha256"
    }
}

struct MemberInviteResult: Decodable, Equatable, Sendable {
    let invite: MemberInvite
}

struct AdoptedMember: Decodable, Equatable, Sendable {
    let protocolName: String
    let state: String
    let sourceSiteID: String
    let destinationSiteID: String
    let memberID: String
    let moveID: String

    enum CodingKeys: String, CodingKey {
        case protocolName = "protocol"
        case state
        case sourceSiteID = "source_site_id"
        case destinationSiteID = "destination_site_id"
        case memberID = "member_id"
        case moveID = "move_id"
    }
}

struct AdoptedMemberResult: Decodable, Equatable, Sendable {
    let adoption: AdoptedMember
}

struct MemberApproval: Decodable, Equatable, Sendable {
    let memberID: String
    let state: String

    enum CodingKeys: String, CodingKey {
        case memberID = "member_id"
        case state
    }
}

struct MemberApprovalResult: Decodable, Equatable, Sendable {
    let membership: MemberApproval
}

struct ControllerAPIKeyRecord: Decodable, Equatable, Identifiable, Sendable {
    var id: String { keyID }
    let keyID: String
    let name: String
    let models: [String]
    let expiresAtUnix: Int?
    let revokedAtUnix: Int?
    let requestsPerMinute: Int?
    let tokensPerMinute: Int?
    let concurrencyLimit: Int?
    let contextLimit: Int?
    let tenant: String?
    let application: String?
    let createdAtUnix: Int
    let rotatedFrom: String?

    enum CodingKeys: String, CodingKey {
        case keyID = "key_id"
        case name, models, tenant, application
        case expiresAtUnix = "expires_at_unix"
        case revokedAtUnix = "revoked_at_unix"
        case requestsPerMinute = "requests_per_minute"
        case tokensPerMinute = "tokens_per_minute"
        case concurrencyLimit = "concurrency_limit"
        case contextLimit = "context_limit"
        case createdAtUnix = "created_at_unix"
        case rotatedFrom = "rotated_from"
    }
}

struct ControllerAPIKeyListResult: Decodable, Equatable, Sendable {
    let keys: [ControllerAPIKeyRecord]
}

struct ControllerAPIKeyResult: Decodable, Equatable, Sendable {
    let key: ControllerAPIKeyRecord
}

struct ControllerAPIKeySecretResult: Decodable, Equatable, Sendable {
    let key: ControllerAPIKeyRecord
    let token: String
}

struct ControllerAPIKeyPolicy: Equatable, Sendable {
    var models: [String] = []
    var expiresAtUnix: Int?
    var requestsPerMinute: Int?
    var tokensPerMinute: Int?
    var concurrencyLimit: Int?
    var contextLimit: Int?
    var tenant: String?
    var application: String?

    fileprivate var jsonObject: [String: Any] {
        [
            "models": models,
            "expires_at_unix": expiresAtUnix.map { $0 as Any } ?? NSNull(),
            "requests_per_minute": requestsPerMinute.map { $0 as Any } ?? NSNull(),
            "tokens_per_minute": tokensPerMinute.map { $0 as Any } ?? NSNull(),
            "concurrency_limit": concurrencyLimit.map { $0 as Any } ?? NSNull(),
            "context_limit": contextLimit.map { $0 as Any } ?? NSNull(),
            "tenant": tenant.map { $0 as Any } ?? NSNull(),
            "application": application.map { $0 as Any } ?? NSNull(),
        ]
    }
}

struct PreparedSiteMove: Decodable, Equatable, Sendable {
    let moveID: String
    let sourceSiteID: String
    let destinationSiteID: String
    let memberID: String
    let membershipState: String
    let comparisonCode: String?
    let expiresAtUnix: Int
    let plan: SiteMovePlan

    enum CodingKeys: String, CodingKey {
        case moveID = "move_id"
        case sourceSiteID = "source_site_id"
        case destinationSiteID = "destination_site_id"
        case memberID = "member_id"
        case membershipState = "membership_state"
        case comparisonCode = "comparison_code"
        case expiresAtUnix = "expires_at_unix"
        case plan
    }
}

struct PreparedSiteMoveResult: Decodable, Equatable, Sendable {
    let move: PreparedSiteMove
}

struct CommittedSiteMove: Decodable, Equatable, Sendable {
    let moveID: String
    let sourceSiteID: String
    let destinationSiteID: String
    let memberID: String
    let state: String

    enum CodingKeys: String, CodingKey {
        case moveID = "move_id"
        case sourceSiteID = "source_site_id"
        case destinationSiteID = "destination_site_id"
        case memberID = "member_id"
        case state
    }
}

struct CommittedSiteMoveResult: Decodable, Equatable, Sendable {
    let move: CommittedSiteMove
}

struct CancelledSiteMove: Decodable, Equatable, Sendable {
    let moveID: String
    let state: String

    enum CodingKeys: String, CodingKey {
        case moveID = "move_id"
        case state
    }
}

struct CancelledSiteMoveResult: Decodable, Equatable, Sendable {
    let move: CancelledSiteMove
}

struct ControllerAdministrationEnvelope<Result: Decodable & Equatable & Sendable>:
    Decodable, Equatable, Sendable
{
    let protocolName: String
    let controller: ControllerPrincipal
    let result: Result

    enum CodingKeys: String, CodingKey {
        case protocolName = "protocol"
        case controller, result
    }
}

protocol ControllerSiteAPI: Sendable {
    func site(for savedSite: SavedSite) async throws -> ControllerSiteEnvelope
    func telemetry(for savedSite: SavedSite) async throws -> ControllerTelemetryEnvelope
    func siteAction(
        _ action: ControllerSiteAction,
        model: String?,
        engine: String?,
        for savedSite: SavedSite
    ) async throws -> ControllerActionEnvelope
    func siteActionStatus(
        operationID: String,
        for savedSite: SavedSite
    ) async throws -> ControllerActionEnvelope
    func apiKeys(for savedSite: SavedSite) async throws
        -> ControllerAdministrationEnvelope<ControllerAPIKeyListResult>
    func createAPIKey(
        name: String,
        policy: ControllerAPIKeyPolicy,
        for savedSite: SavedSite
    ) async throws -> ControllerAdministrationEnvelope<ControllerAPIKeySecretResult>
    func rotateAPIKey(
        key: String,
        for savedSite: SavedSite
    ) async throws -> ControllerAdministrationEnvelope<ControllerAPIKeySecretResult>
    func revokeAPIKey(
        key: String,
        for savedSite: SavedSite
    ) async throws -> ControllerAdministrationEnvelope<ControllerAPIKeyResult>
    func updateAPIKeyPolicy(
        key: String,
        policy: ControllerAPIKeyPolicy,
        for savedSite: SavedSite
    ) async throws -> ControllerAdministrationEnvelope<ControllerAPIKeyResult>
    func removeMember(
        memberID: String,
        for savedSite: SavedSite
    ) async throws -> ControllerAdministrationEnvelope<MemberApprovalResult>
    func drainMember(
        memberID: String,
        for savedSite: SavedSite
    ) async throws -> ControllerAdministrationEnvelope<MemberApprovalResult>
    func resumeMember(
        memberID: String,
        for savedSite: SavedSite
    ) async throws -> ControllerAdministrationEnvelope<MemberApprovalResult>
    func siteMovePlan(for savedSite: SavedSite) async throws
        -> ControllerAdministrationEnvelope<SiteMovePlanResult>
    func createMemberInvite(
        mode: String,
        candidatePublicKeySHA256: String?,
        candidateEndpoint: String?,
        directInterface: String?,
        for savedSite: SavedSite
    ) async throws -> ControllerAdministrationEnvelope<MemberInviteResult>
    func adoptMember(
        sourceEndpoint: String,
        sourceSiteID: String,
        sourceMemberID: String,
        sourcePublicKeySHA256: String,
        sourceCertificateSHA256: String,
        for savedSite: SavedSite
    ) async throws -> ControllerAdministrationEnvelope<AdoptedMemberResult>
    func approveMember(
        memberID: String,
        comparisonCode: String,
        for savedSite: SavedSite
    ) async throws -> ControllerAdministrationEnvelope<MemberApprovalResult>
    func prepareSiteMove(
        sourceSiteID: String,
        invite: MemberInvite,
        memberName: String,
        memberAddress: String,
        for savedSite: SavedSite
    ) async throws -> ControllerAdministrationEnvelope<PreparedSiteMoveResult>
    func commitSiteMove(
        moveID: String,
        for savedSite: SavedSite
    ) async throws -> ControllerAdministrationEnvelope<CommittedSiteMoveResult>
    func cancelSiteMove(
        moveID: String,
        for savedSite: SavedSite
    ) async throws -> ControllerAdministrationEnvelope<CancelledSiteMoveResult>
    func cancelPreparedMember(
        memberID: String,
        for savedSite: SavedSite
    ) async throws -> ControllerAdministrationEnvelope<MemberApprovalResult>
}

extension ControllerSiteAPI {
    func siteAction(
        _ action: ControllerSiteAction,
        model: String?,
        engine: String?,
        for savedSite: SavedSite
    ) async throws -> ControllerActionEnvelope {
        throw ControllerAPIError.unavailable
    }

    func siteActionStatus(
        operationID: String,
        for savedSite: SavedSite
    ) async throws -> ControllerActionEnvelope {
        throw ControllerAPIError.unavailable
    }

    func apiKeys(for savedSite: SavedSite) async throws
        -> ControllerAdministrationEnvelope<ControllerAPIKeyListResult> {
        throw ControllerAPIError.unavailable
    }

    func createAPIKey(
        name: String,
        policy: ControllerAPIKeyPolicy,
        for savedSite: SavedSite
    ) async throws -> ControllerAdministrationEnvelope<ControllerAPIKeySecretResult> {
        throw ControllerAPIError.unavailable
    }

    func rotateAPIKey(
        key: String,
        for savedSite: SavedSite
    ) async throws -> ControllerAdministrationEnvelope<ControllerAPIKeySecretResult> {
        throw ControllerAPIError.unavailable
    }

    func revokeAPIKey(
        key: String,
        for savedSite: SavedSite
    ) async throws -> ControllerAdministrationEnvelope<ControllerAPIKeyResult> {
        throw ControllerAPIError.unavailable
    }

    func updateAPIKeyPolicy(
        key: String,
        policy: ControllerAPIKeyPolicy,
        for savedSite: SavedSite
    ) async throws -> ControllerAdministrationEnvelope<ControllerAPIKeyResult> {
        throw ControllerAPIError.unavailable
    }

    func removeMember(
        memberID: String,
        for savedSite: SavedSite
    ) async throws -> ControllerAdministrationEnvelope<MemberApprovalResult> {
        throw ControllerAPIError.unavailable
    }

    func drainMember(
        memberID: String,
        for savedSite: SavedSite
    ) async throws -> ControllerAdministrationEnvelope<MemberApprovalResult> {
        throw ControllerAPIError.unavailable
    }

    func resumeMember(
        memberID: String,
        for savedSite: SavedSite
    ) async throws -> ControllerAdministrationEnvelope<MemberApprovalResult> {
        throw ControllerAPIError.unavailable
    }

    func siteMovePlan(for savedSite: SavedSite) async throws
        -> ControllerAdministrationEnvelope<SiteMovePlanResult> {
        throw ControllerAPIError.unavailable
    }

    func createMemberInvite(
        mode: String,
        candidatePublicKeySHA256: String?,
        candidateEndpoint: String?,
        directInterface: String?,
        for savedSite: SavedSite
    ) async throws -> ControllerAdministrationEnvelope<MemberInviteResult> {
        throw ControllerAPIError.unavailable
    }

    func adoptMember(
        sourceEndpoint: String,
        sourceSiteID: String,
        sourceMemberID: String,
        sourcePublicKeySHA256: String,
        sourceCertificateSHA256: String,
        for savedSite: SavedSite
    ) async throws -> ControllerAdministrationEnvelope<AdoptedMemberResult> {
        throw ControllerAPIError.unavailable
    }

    func approveMember(
        memberID: String,
        comparisonCode: String,
        for savedSite: SavedSite
    ) async throws -> ControllerAdministrationEnvelope<MemberApprovalResult> {
        throw ControllerAPIError.unavailable
    }

    func prepareSiteMove(
        sourceSiteID: String,
        invite: MemberInvite,
        memberName: String,
        memberAddress: String,
        for savedSite: SavedSite
    ) async throws -> ControllerAdministrationEnvelope<PreparedSiteMoveResult> {
        throw ControllerAPIError.unavailable
    }

    func commitSiteMove(
        moveID: String,
        for savedSite: SavedSite
    ) async throws -> ControllerAdministrationEnvelope<CommittedSiteMoveResult> {
        throw ControllerAPIError.unavailable
    }

    func cancelSiteMove(
        moveID: String,
        for savedSite: SavedSite
    ) async throws -> ControllerAdministrationEnvelope<CancelledSiteMoveResult> {
        throw ControllerAPIError.unavailable
    }

    func cancelPreparedMember(
        memberID: String,
        for savedSite: SavedSite
    ) async throws -> ControllerAdministrationEnvelope<MemberApprovalResult> {
        throw ControllerAPIError.unavailable
    }
}

enum ControllerAPIError: LocalizedError {
    case unavailable
    case invalidPort
    case invalidResponse
    case rejected(String)

    var errorDescription: String? {
        switch self {
        case .unavailable: "The private Let's Infer controller API is unavailable."
        case .invalidPort: "The private Let's Infer controller port is invalid."
        case .invalidResponse: "The private Let's Infer controller response is invalid."
        case .rejected(let reason): reason
        }
    }
}

private final class ControllerSessionDelegate: NSObject, URLSessionDelegate, @unchecked Sendable {
    private let credential: WatchdogTLSCredentials

    init(credential: WatchdogTLSCredentials) {
        self.credential = credential
    }

    func urlSession(
        _ session: URLSession,
        didReceive challenge: URLAuthenticationChallenge,
        completionHandler: @escaping @Sendable (URLSession.AuthChallengeDisposition, URLCredential?) -> Void
    ) {
        switch challenge.protectionSpace.authenticationMethod {
        case NSURLAuthenticationMethodClientCertificate:
            completionHandler(
                .useCredential,
                URLCredential(
                    identity: credential.identity,
                    certificates: credential.certificateChain,
                    persistence: .none
                )
            )
        case NSURLAuthenticationMethodServerTrust:
            guard let trust = challenge.protectionSpace.serverTrust,
                  let chain = SecTrustCopyCertificateChain(trust) as? [SecCertificate],
                  let leaf = chain.first,
                  SecCertificateCopyData(leaf) as Data
                    == SecCertificateCopyData(credential.serverCertificate) as Data else {
                completionHandler(.cancelAuthenticationChallenge, nil)
                return
            }
            SecTrustSetPolicies(trust, SecPolicyCreateBasicX509())
            SecTrustSetAnchorCertificates(trust, [credential.rootCertificate] as CFArray)
            SecTrustSetAnchorCertificatesOnly(trust, true)
            var error: CFError?
            guard SecTrustEvaluateWithError(trust, &error) else {
                completionHandler(.cancelAuthenticationChallenge, nil)
                return
            }
            completionHandler(.useCredential, URLCredential(trust: trust))
        default:
            completionHandler(.cancelAuthenticationChallenge, nil)
        }
    }
}

actor ControllerAPIClient: ControllerSiteAPI {
    private let credentials: ControllerCredentialStore

    init(credentials: ControllerCredentialStore = .shared) {
        self.credentials = credentials
    }

    func site(for savedSite: SavedSite) async throws -> ControllerSiteEnvelope {
        try await request(savedSite, path: "/control/v1/node")
    }

    func telemetry(for savedSite: SavedSite) async throws -> ControllerTelemetryEnvelope {
        try await request(savedSite, path: "/control/v1/telemetry?history=0")
    }

    func siteAction(
        _ action: ControllerSiteAction,
        model: String?,
        engine: String?,
        for savedSite: SavedSite
    ) async throws -> ControllerActionEnvelope {
        let payload: [String: Any]
        switch action {
        case .start, .stop, .restart, .recover:
            guard let model, engine == nil else {
                throw ControllerAPIError.invalidResponse
            }
            payload = ["model": model]
        case .install, .topologyPlan:
            guard let model else { throw ControllerAPIError.invalidResponse }
            payload = [
                "model": model,
                "engine": engine.map { $0 as Any } ?? NSNull(),
            ]
        case .expose, .unexpose:
            guard model == nil, engine == nil else {
                throw ControllerAPIError.invalidResponse
            }
            payload = [:]
        }
        let body = try JSONSerialization.data(withJSONObject: payload)
        return try await request(
            savedSite,
            path: "/control/v1/actions/\(action.rawValue)",
            method: "POST",
            body: body,
            acceptedStatus: 202
        )
    }

    func siteActionStatus(
        operationID: String,
        for savedSite: SavedSite
    ) async throws -> ControllerActionEnvelope {
        try await request(
            savedSite,
            path: "/control/v1/actions/\(operationID)"
        )
    }

    func apiKeys(for savedSite: SavedSite) async throws
        -> ControllerAdministrationEnvelope<ControllerAPIKeyListResult> {
        try await administrationRequest(savedSite, path: "/control/v1/keys")
    }

    func createAPIKey(
        name: String,
        policy: ControllerAPIKeyPolicy,
        for savedSite: SavedSite
    ) async throws -> ControllerAdministrationEnvelope<ControllerAPIKeySecretResult> {
        var payload = policy.jsonObject
        payload["name"] = name
        return try await administrationRequest(
            savedSite,
            path: "/control/v1/keys/create",
            method: "POST",
            body: try JSONSerialization.data(withJSONObject: payload)
        )
    }

    func rotateAPIKey(
        key: String,
        for savedSite: SavedSite
    ) async throws -> ControllerAdministrationEnvelope<ControllerAPIKeySecretResult> {
        try await keyRequest(
            savedSite, path: "/control/v1/keys/rotate", key: key
        )
    }

    func revokeAPIKey(
        key: String,
        for savedSite: SavedSite
    ) async throws -> ControllerAdministrationEnvelope<ControllerAPIKeyResult> {
        try await keyRequest(
            savedSite, path: "/control/v1/keys/revoke", key: key
        )
    }

    func updateAPIKeyPolicy(
        key: String,
        policy: ControllerAPIKeyPolicy,
        for savedSite: SavedSite
    ) async throws -> ControllerAdministrationEnvelope<ControllerAPIKeyResult> {
        var payload = policy.jsonObject
        payload["key"] = key
        return try await administrationRequest(
            savedSite,
            path: "/control/v1/keys/policy",
            method: "POST",
            body: try JSONSerialization.data(withJSONObject: payload)
        )
    }

    func removeMember(
        memberID: String,
        for savedSite: SavedSite
    ) async throws -> ControllerAdministrationEnvelope<MemberApprovalResult> {
        let body = try JSONSerialization.data(
            withJSONObject: ["member_id": memberID]
        )
        return try await administrationRequest(
            savedSite,
            path: "/control/v1/children/remove",
            method: "POST",
            body: body
        )
    }

    func drainMember(
        memberID: String,
        for savedSite: SavedSite
    ) async throws -> ControllerAdministrationEnvelope<MemberApprovalResult> {
        try await memberRoutingRequest(
            memberID: memberID,
            path: "/control/v1/children/drain",
            for: savedSite
        )
    }

    func resumeMember(
        memberID: String,
        for savedSite: SavedSite
    ) async throws -> ControllerAdministrationEnvelope<MemberApprovalResult> {
        try await memberRoutingRequest(
            memberID: memberID,
            path: "/control/v1/children/resume",
            for: savedSite
        )
    }

    private func memberRoutingRequest(
        memberID: String,
        path: String,
        for savedSite: SavedSite
    ) async throws -> ControllerAdministrationEnvelope<MemberApprovalResult> {
        let body = try JSONSerialization.data(
            withJSONObject: ["member_id": memberID]
        )
        return try await administrationRequest(
            savedSite,
            path: path,
            method: "POST",
            body: body
        )
    }

    private func keyRequest<Result: Decodable & Equatable & Sendable>(
        _ savedSite: SavedSite,
        path: String,
        key: String
    ) async throws -> ControllerAdministrationEnvelope<Result> {
        let body = try JSONSerialization.data(withJSONObject: ["key": key])
        return try await administrationRequest(
            savedSite, path: path, method: "POST", body: body
        )
    }

    func siteMovePlan(for savedSite: SavedSite) async throws
        -> ControllerAdministrationEnvelope<SiteMovePlanResult> {
        try await administrationRequest(
            savedSite, path: "/control/v1/node-move/plan"
        )
    }

    func createMemberInvite(
        mode: String,
        candidatePublicKeySHA256: String?,
        candidateEndpoint: String?,
        directInterface: String?,
        for savedSite: SavedSite
    ) async throws -> ControllerAdministrationEnvelope<MemberInviteResult> {
        let body = try JSONSerialization.data(withJSONObject: [
            "mode": mode,
            "expires_in": 180,
            "candidate_public_key_sha256": candidatePublicKeySHA256.map { $0 as Any } ?? NSNull(),
            "candidate_endpoint": candidateEndpoint.map { $0 as Any } ?? NSNull(),
            "direct_interface": directInterface.map { $0 as Any } ?? NSNull(),
        ])
        return try await administrationRequest(
            savedSite,
            path: "/control/v1/children/invite",
            method: "POST",
            body: body
        )
    }

    func adoptMember(
        sourceEndpoint: String,
        sourceSiteID: String,
        sourceMemberID: String,
        sourcePublicKeySHA256: String,
        sourceCertificateSHA256: String,
        for savedSite: SavedSite
    ) async throws -> ControllerAdministrationEnvelope<AdoptedMemberResult> {
        let body = try JSONSerialization.data(withJSONObject: [
            "source_endpoint": sourceEndpoint,
            "source_site_id": sourceSiteID,
            "source_member_id": sourceMemberID,
            "source_public_key_sha256": sourcePublicKeySHA256,
            "source_certificate_sha256": sourceCertificateSHA256,
        ])
        return try await administrationRequest(
            savedSite,
            path: "/control/v1/children/adopt",
            method: "POST",
            body: body
        )
    }

    func approveMember(
        memberID: String,
        comparisonCode: String,
        for savedSite: SavedSite
    ) async throws -> ControllerAdministrationEnvelope<MemberApprovalResult> {
        let body = try JSONSerialization.data(withJSONObject: [
            "member_id": memberID,
            "comparison_code": comparisonCode,
        ])
        return try await administrationRequest(
            savedSite,
            path: "/control/v1/children/approve",
            method: "POST",
            body: body
        )
    }

    func prepareSiteMove(
        sourceSiteID: String,
        invite: MemberInvite,
        memberName: String,
        memberAddress: String,
        for savedSite: SavedSite
    ) async throws -> ControllerAdministrationEnvelope<PreparedSiteMoveResult> {
        let body = try JSONSerialization.data(withJSONObject: [
            "source_site_id": sourceSiteID,
            "endpoint": invite.endpoint,
            "invite_id": invite.inviteID,
            "code": invite.code.map { $0 as Any } ?? NSNull(),
            "main_certificate_sha256": invite.coordinatorCertificateSHA256,
            "member_name": memberName,
            "member_address": memberAddress,
        ])
        return try await administrationRequest(
            savedSite,
            path: "/control/v1/node-move/prepare",
            method: "POST",
            body: body
        )
    }

    func commitSiteMove(
        moveID: String,
        for savedSite: SavedSite
    ) async throws -> ControllerAdministrationEnvelope<CommittedSiteMoveResult> {
        let body = try JSONSerialization.data(withJSONObject: ["move_id": moveID])
        return try await administrationRequest(
            savedSite,
            path: "/control/v1/node-move/commit",
            method: "POST",
            body: body
        )
    }

    func cancelSiteMove(
        moveID: String,
        for savedSite: SavedSite
    ) async throws -> ControllerAdministrationEnvelope<CancelledSiteMoveResult> {
        let body = try JSONSerialization.data(withJSONObject: ["move_id": moveID])
        return try await administrationRequest(
            savedSite,
            path: "/control/v1/node-move/cancel",
            method: "POST",
            body: body
        )
    }

    func cancelPreparedMember(
        memberID: String,
        for savedSite: SavedSite
    ) async throws -> ControllerAdministrationEnvelope<MemberApprovalResult> {
        let body = try JSONSerialization.data(withJSONObject: ["member_id": memberID])
        return try await administrationRequest(
            savedSite,
            path: "/control/v1/children/cancel",
            method: "POST",
            body: body
        )
    }

    private func administrationRequest<Result: Decodable & Equatable & Sendable>(
        _ savedSite: SavedSite,
        path: String,
        method: String = "GET",
        body: Data? = nil
    ) async throws -> ControllerAdministrationEnvelope<Result> {
        let value: ControllerAdministrationEnvelope<Result> = try await request(
            savedSite,
            path: path,
            method: method,
            body: body,
            requestTimeout: 60,
            resourceTimeout: 90
        )
        guard value.protocolName == controllerProtocol,
              value.controller.role == "administrator" else {
            throw ControllerAPIError.invalidResponse
        }
        return value
    }

    private func request<Response: Decodable>(
        _ savedSite: SavedSite,
        path: String,
        method: String = "GET",
        body: Data? = nil,
        acceptedStatus: Int = 200,
        requestTimeout: TimeInterval = 8,
        resourceTimeout: TimeInterval = 10
    ) async throws -> Response {
        guard let installationID = savedSite.installationID,
              let controlPort = savedSite.controlPort,
              (1...65_535).contains(controlPort) else {
            throw ControllerAPIError.invalidPort
        }
        let credential = try credentials.credentials(installationID: installationID)
        var components = URLComponents()
        components.scheme = "https"
        components.host = savedSite.host
        components.port = controlPort
        let split = path.split(separator: "?", maxSplits: 1, omittingEmptySubsequences: false)
        components.path = String(split[0])
        components.percentEncodedQuery = split.count == 2 ? String(split[1]) : nil
        guard let url = components.url else { throw ControllerAPIError.invalidResponse }
        let delegate = ControllerSessionDelegate(credential: credential)
        let configuration = URLSessionConfiguration.ephemeral
        configuration.timeoutIntervalForRequest = requestTimeout
        configuration.timeoutIntervalForResource = resourceTimeout
        let session = URLSession(
            configuration: configuration, delegate: delegate, delegateQueue: nil
        )
        defer { session.finishTasksAndInvalidate() }
        var request = URLRequest(url: url)
        request.httpMethod = method
        request.httpBody = body
        request.cachePolicy = .reloadIgnoringLocalAndRemoteCacheData
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        if body != nil {
            request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        }
        let (data, rawResponse) = try await session.data(for: request)
        guard data.count <= maximumControllerResponseBytes,
              let response = rawResponse as? HTTPURLResponse else {
            throw ControllerAPIError.invalidResponse
        }
        guard response.statusCode == acceptedStatus else {
            let reason = (try? JSONSerialization.jsonObject(with: data) as? [String: String])?["error"]
            throw ControllerAPIError.rejected(reason ?? "The controller request was rejected.")
        }
        let value = try JSONDecoder().decode(Response.self, from: data)
        if let site = value as? ControllerSiteEnvelope,
           site.protocolName != controllerProtocol || site.site.schemaVersion != 2 {
            throw ControllerAPIError.invalidResponse
        }
        if let telemetry = value as? ControllerTelemetryEnvelope,
           telemetry.protocolName != controllerProtocol || telemetry.telemetry.schemaVersion != 2 {
            throw ControllerAPIError.invalidResponse
        }
        if let action = value as? ControllerActionEnvelope,
           action.protocolName != controllerProtocol
            || !["accepted", "succeeded", "failed"].contains(action.action.state)
            || action.action.operationID.count != 32
            || (action.action.state == "succeeded" && action.action.result == nil)
            || (action.action.state == "failed" && action.action.error == nil) {
            throw ControllerAPIError.invalidResponse
        }
        return value
    }
}
