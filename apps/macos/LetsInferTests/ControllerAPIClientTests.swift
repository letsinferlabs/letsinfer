import Foundation
import Testing
@testable import LetsInfer

struct ControllerAPIClientTests {
    @Test
    func malformedSignedMemberFactsFailClosed() {
        let memberData = Data("""
        {
          "member_id":"33333333333333333333333333333333",
          "display_name":"Desk",
          "role":"coordinator",
          "address":"home.local",
          "state":"active",
          "certificate_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
          "facts":{"schema_version":"invalid"},
          "facts_sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
          "joined_at_unix":1700000000,
          "updated_at_unix":1700000001
        }
        """.utf8)

        #expect(throws: DecodingError.self) {
            try JSONDecoder().decode(SiteMemberRecord.self, from: memberData)
        }
    }

    @Test
    func siteAndAggregateTelemetryContractsDecodeStrictIdentities() throws {
        let siteData = Data("""
        {
          "protocol":"letsinfer-controller-control-v1",
          "controller":{"id":"11111111111111111111111111111111","role":"viewer"},
          "site":{
            "schema_version":1,
            "identity":{
              "site_id":"22222222222222222222222222222222",
              "member_id":"33333333333333333333333333333333",
              "display_name":"Home",
              "role":"coordinator",
              "coordinator_id":"33333333333333333333333333333333",
              "coordinator_address":"home.local",
              "member_public_key_sha256":"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
            },
            "members":[{
              "member_id":"33333333333333333333333333333333",
              "display_name":"Desk",
              "role":"coordinator",
              "address":"home.local",
              "state":"active",
              "certificate_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
              "facts":{
                "schema_version":1,
                "member_id":"33333333333333333333333333333333",
                "observed_at_unix":1700000001,
                "platform":"linux/arm64",
                "health":{
                  "state":"healthy",
                  "memory_pressure":false,
                  "protection_trip":false,
                  "max_temperature_c":61
                },
                "inventory":{
                  "hostname":"homeai",
                  "operating_system":"Ubuntu 24.04",
                  "kernel_version":"6.11.0",
                  "product_vendor":"NVIDIA",
                  "product_name":"DGX Spark",
                  "product_version":"1",
                  "serial_number":"SPARK123",
                  "serial_source":"dmi",
                  "system_uuid":"aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
                  "machine_id_sha256":"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
                  "dmi_serial_requires_privilege":false,
                  "board_vendor":"NVIDIA",
                  "board_name":"GB10",
                  "board_version":"1",
                  "board_serial":"BOARD123",
                  "chassis_vendor":"NVIDIA",
                  "chassis_type":"17",
                  "chassis_serial":"CHASSIS123",
                  "bios_vendor":"NVIDIA",
                  "bios_version":"1.0",
                  "bios_date":"2026-01-01",
                  "cpu_model":"Arm v9",
                  "cpu_core_count":20,
                  "gpu_name":"NVIDIA GB10",
                  "gpu_uuid":"GPU-11111111-2222-3333-4444-555555555555",
                  "nvidia_driver_version":"580.65",
                  "dgx_name":"DGX OS",
                  "dgx_software_version":"7.5.0",
                  "dgx_base_build_version":"base-1",
                  "dgx_build_date":"2026-01-02",
                  "dgx_commit_id":"abcdef",
                  "dgx_platform":"spark",
                  "dgx_update_date":"2026-01-03",
                  "nvme_model":"NVMe Test",
                  "nvme_serial":"NVME123",
                  "nvme_firmware":"1.2",
                  "network_addresses":[{"interface":"eth0","family":"inet","address":"192.168.1.66"}],
                  "default_network_interface":"eth0",
                  "uptime_seconds":3600,
                  "process_count":200,
                  "active_users":["homeai"],
                  "login_session_count":1,
                  "last_login":"homeai pts/0",
                  "firmware_update_count":0,
                  "containers":[{"name":"letsinfer-dwarfstar","image":"sha256:abc","status":"running"}]
                }
              },
              "facts_sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
              "joined_at_unix":1700000000,
              "updated_at_unix":1700000001
            }],
            "topology":{"valid":true,"topology_sha256":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"},
            "placements":[{
              "placement_id":"44444444444444444444444444444444",
              "model":"qwen3.8-27b",
              "runtime":"qwen3.8-27b/sglang/dgx-spark@0.1.0-rc.2@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
              "target":"dgx-spark",
              "strategy":"single",
              "state":"running",
              "members":["33333333333333333333333333333333"],
              "endpoints":[{
                "member_id":"33333333333333333333333333333333",
                "max_active_requests":10,
                "max_context_tokens":1000000
              }],
              "capacity":{
                "max_connections":128,
                "max_active_requests":10,
                "max_context_tokens":1000000
              },
              "updated_at_unix":1700000010
            },{
              "placement_id":"55555555555555555555555555555555",
              "model":"qwen3.8-27b",
              "runtime":"qwen3.8-27b/sglang/dgx-spark@0.1.0-rc.1",
              "target":"fixture-target",
              "strategy":"single",
              "state":"stopped",
              "members":["33333333333333333333333333333333"],
              "updated_at_unix":1700000002
            }],
            "pending_topology_plans":[],
            "exposure":{
              "provider":"tailscale-funnel",
              "public_url":"",
              "state":"disabled",
              "inference_target":"http://127.0.0.1:8000",
              "configuration_sha256":"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
              "updated_at_unix":1700000002
            }
          }
        }
        """.utf8)
        let site = try JSONDecoder().decode(ControllerSiteEnvelope.self, from: siteData)
        #expect(site.site.identity.displayName == "Home")
        #expect(site.site.members.first?.role == "coordinator")
        #expect(site.site.placements.first?.strategy == "single")
        #expect(site.site.currentPlacements.count == 1)
        #expect(site.site.currentPlacements.first?.state == "running")
        #expect(site.site.currentPlacements.first?.capacity?.maxActiveRequests == 10)
        #expect(site.site.activeMemberCount == 1)
        #expect(site.site.exposure.state == "disabled")
        #expect(site.site.members.first?.facts?.inventory?.hostname == "homeai")
        let siteID = UUID()
        let facts = try #require(site.site.members.first?.facts)
        let snapshot = try #require(
            SiteSnapshot.controllerFacts(
                siteID: siteID,
                facts: facts
            )
        )
        #expect(snapshot.siteID == siteID)
        #expect(snapshot.source == .controller)
        #expect(snapshot.identity?.displayName == "NVIDIA DGX Spark")
        #expect(snapshot.identity?.architecture == "arm64")
        #expect(snapshot.system?.hostname == "homeai")
        #expect(snapshot.system?.cpuCoreCount == 20)
        #expect(snapshot.system?.networkAddresses.first?.address == "192.168.1.66")
        #expect(snapshot.system?.containers.first?.name == "letsinfer-dwarfstar")
        #expect(snapshot.uptimeSeconds == 3_600)

        let staleRuntimeSnapshot = SiteSnapshot(
            siteID: siteID,
            source: .watchdog,
            sampledAt: Date(),
            availability: .online,
            uptimeSeconds: 3_600,
            identity: nil,
            metrics: MemberMetrics(llm: [
                LLMMetrics(
                    id: "letsinfer-gateway",
                    backend: "core",
                    model: "site",
                    generationTokensPerSecond: nil,
                    prefillTokensPerSecond: nil,
                    runningRequests: 0,
                    waitingRequests: 0,
                    kvCacheUtilization: nil
                )
            ]),
            letsinfer: SiteStatus(
                installationID: "installation",
                release: "0.11.0-rc.14",
                model: "site",
                engine: "core",
                runtimeName: "site",
                runtimeVersion: "1",
                manifestSHA256: String(repeating: "a", count: 64),
                cacheProvider: "none",
                cachePersistent: false,
                inferencePort: 8000,
                maxConnections: 1,
                maxActiveRequests: 1,
                maxContextTokens: 1,
                serviceState: "active",
                engineState: "running",
                protectionPhase: "armed",
                protectionArmed: true,
                tripLatched: false,
                containerName: nil
            )
        )
        let placement = try #require(site.site.currentPlacements.first)
        let activeRuntimeSnapshot = staleRuntimeSnapshot.enriched(with: placement)
        #expect(activeRuntimeSnapshot.letsinfer?.model == "qwen3.8-27b")
        #expect(activeRuntimeSnapshot.letsinfer?.engine == "sglang")
        #expect(activeRuntimeSnapshot.letsinfer?.runtimeVersion == "0.1.0-rc.2")
        #expect(activeRuntimeSnapshot.letsinfer?.maxActiveRequests == 10)
        #expect(activeRuntimeSnapshot.letsinfer?.maxConnections == 128)
        #expect(activeRuntimeSnapshot.letsinfer?.maxContextTokens == 1_000_000)
        #expect(activeRuntimeSnapshot.metrics.llm.first?.model == "qwen3.8-27b")

        let telemetryData = Data("""
        {
          "protocol":"letsinfer-controller-control-v1",
          "controller":{"id":"11111111111111111111111111111111","role":"viewer"},
          "telemetry":{
            "schema_version":2,
            "unix_ms":1700000000000,
            "members":[{
              "sample":{
                "schema_version":2,
                "member_id":"33333333333333333333333333333333",
                "sequence":42,
                "unix_ms":1700000000000,
                "monotonic_ms":12000,
                "system":{
                  "cpu_core_percent":[10,20],
                  "cpu_percent":15,
                  "gpu_percent":80,
                  "memory_percent":70,
                  "disk_percent":25,
                  "gpu_memory_percent":60,
                  "gpu_engine_percent":[80,70],
                  "system_temp_deci_c":520,
                  "gpu_temp_deci_c":610,
                  "nvme_temp_deci_c":430,
                  "power_deci_w":900,
                  "load1_centi":125,
                  "memory_used_mib":64000,
                  "memory_total_mib":128000,
                  "disk_used_mib":200000,
                  "disk_total_mib":1000000,
                  "network_rx_kib_s":100,
                  "network_tx_kib_s":50,
                  "disk_read_kib_s":20,
                  "disk_write_kib_s":10,
                  "cpu_clock_mhz":3200,
                  "gpu_clock_mhz":1200,
                  "vram_clock_mhz":1600,
                  "system_ram_clock_mhz":4266
                },
                "inference":{
                  "gateway_available":true,
                  "active_requests":2,
                  "queued_requests":1,
                  "requests_received":10,
                  "requests_admitted":9,
                  "requests_completed":8,
                  "requests_failed":1,
                  "requests_cancelled":0,
                  "requests_retried":1,
                  "input_tokens":32000,
                  "output_tokens":1024,
                  "cached_tokens":12000,
                  "queue_milliseconds":120,
                  "ttft_milliseconds":800,
                  "decode_milliseconds":4000,
                  "exact_token_requests":8,
                  "prefix_cache_hits":3,
                  "usage_records_dropped":0,
                  "usage_write_errors":0
                },
                "workload":{"type":2,"id":7,"gpu_available":true,"throttled":false}
              },
              "stale":false,
              "logical_counters":{
                "requests_received":10,
                "requests_admitted":9,
                "requests_completed":8,
                "requests_failed":1,
                "requests_cancelled":0,
                "requests_retried":1,
                "input_tokens":32000,
                "output_tokens":1024,
                "cached_tokens":12000,
                "queue_milliseconds":120,
                "ttft_milliseconds":800,
                "decode_milliseconds":4000,
                "exact_token_requests":8,
                "prefix_cache_hits":3,
                "usage_records_dropped":0,
                "usage_write_errors":0
              },
              "rates":{
                "requests_per_second":2.0,
                "failures_per_second":0.0,
                "cancellations_per_second":0.0,
                "retries_per_second":0.25,
                "input_tokens_per_second":6400.0,
                "output_tokens_per_second":200.0,
                "aggregate_tokens_per_second":200.0,
                "cached_tokens_per_second":2400.0,
                "prefill_tokens_per_second":25000.0,
                "decode_tokens_per_second":256.0,
                "average_queue_milliseconds":15.0,
                "average_ttft_milliseconds":100.0,
                "average_decode_milliseconds":500.0,
                "prefix_cache_hit_ratio":0.375,
                "exact_token_ratio":1.0
              }
            }],
            "aggregate":{
              "active_requests":2,
              "queued_requests":1,
              "requests_received":10,
              "requests_admitted":9,
              "requests_completed":8,
              "requests_failed":1,
              "requests_cancelled":0,
              "requests_retried":1,
              "input_tokens":32000,
              "output_tokens":1024,
              "cached_tokens":12000,
              "queue_milliseconds":120,
              "ttft_milliseconds":800,
              "decode_milliseconds":4000,
              "exact_token_requests":8,
              "prefix_cache_hits":3,
              "usage_records_dropped":0,
              "usage_write_errors":0,
              "rates":{
                "requests_per_second":2.0,
                "failures_per_second":0.0,
                "cancellations_per_second":0.0,
                "retries_per_second":0.25,
                "input_tokens_per_second":6400.0,
                "output_tokens_per_second":200.0,
                "aggregate_tokens_per_second":201.0,
                "cached_tokens_per_second":2400.0,
                "prefill_tokens_per_second":25000.0,
                "decode_tokens_per_second":256.0,
                "average_queue_milliseconds":15.0,
                "average_ttft_milliseconds":100.0,
                "average_decode_milliseconds":500.0,
                "prefix_cache_hit_ratio":0.375,
                "exact_token_ratio":1.0
              }
            }
          },
          "history":[]
        }
        """.utf8)
        let telemetry = try JSONDecoder().decode(
            ControllerTelemetryEnvelope.self, from: telemetryData
        )
        #expect(telemetry.telemetry.aggregate.activeRequests == 2)
        #expect(telemetry.telemetry.aggregate.outputTokens == 1024)
        #expect(telemetry.telemetry.aggregate.requestsAdmitted == 9)
        #expect(telemetry.telemetry.aggregate.rates.decodeTokensPerSecond == 256)
        #expect(telemetry.telemetry.members.first?.sample.system.gpuPercent == 80)
        #expect(telemetry.telemetry.members.first?.sample.inference.activeRequests == 2)
        #expect(telemetry.telemetry.members.first?.sample.inference.counters.outputTokens == 1024)
        #expect(telemetry.telemetry.members.first?.sample.workload.throttled == false)
        #expect(telemetry.telemetry.members.first?.rates.outputTokensPerSecond == 200)
        #expect(telemetry.telemetry.isAtLeastAsFresh(
            as: Date(timeIntervalSince1970: 1_700_000_000)
        ))
        #expect(!telemetry.telemetry.isAtLeastAsFresh(
            as: Date(timeIntervalSince1970: 1_700_000_001)
        ))
        let newerDirectSnapshot = activeRuntimeSnapshot.enriched(
            with: telemetry.telemetry.aggregate
        )
        let preservedLiveSnapshot = newerDirectSnapshot.enrichedIfFresh(
            with: telemetry.telemetry
        )
        #expect(preservedLiveSnapshot.metrics.llm.first?.runningRequests == 2)
        let liveSnapshot = activeRuntimeSnapshot.enriched(
            with: telemetry.telemetry.aggregate
        )
        #expect(liveSnapshot.metrics.llm.first?.aggregateTokensPerSecond == 201)
        #expect(liveSnapshot.metrics.llm.first?.generationTokensPerSecond == 256)
        #expect(liveSnapshot.metrics.llm.first?.prefillTokensPerSecond == 25_000)
        #expect(liveSnapshot.metrics.llm.first?.runningRequests == 2)
        #expect(liveSnapshot.metrics.llm.first?.waitingRequests == 1)

        let actionData = Data("""
        {
          "protocol":"letsinfer-controller-control-v1",
          "controller":{"id":"11111111111111111111111111111111","role":"operator"},
          "action":{
            "operation_id":"44444444444444444444444444444444",
            "action":"restart",
            "state":"succeeded",
            "result":{
              "resource":"placement",
              "identifier":"placement-1",
              "model":"fixture-model",
              "state":"running"
            }
          }
        }
        """.utf8)
        let action = try JSONDecoder().decode(
            ControllerActionEnvelope.self, from: actionData
        )
        #expect(action.action.state == "succeeded")
        #expect(action.action.result?.identifier == "placement-1")
        #expect(action.action.result?.resource == "placement")
    }

    @Test
    func administratorAPIKeySecretDecodesWithoutPersistenceFields() throws {
        let data = Data("""
        {
          "protocol":"letsinfer-controller-control-v1",
          "controller":{"id":"11111111111111111111111111111111","role":"administrator"},
          "result":{
            "key":{
              "key_id":"0123456789abcdef",
              "name":"mac-app",
              "models":["fixture-model"],
              "expires_at_unix":null,
              "revoked_at_unix":null,
              "requests_per_minute":60,
              "tokens_per_minute":10000,
              "concurrency_limit":4,
              "context_limit":65536,
              "tenant":"home",
              "application":"mac",
              "created_at_unix":1700000000,
              "rotated_from":null
            },
            "token":"li_0123456789abcdef_secret"
          }
        }
        """.utf8)
        let envelope = try JSONDecoder().decode(
            ControllerAdministrationEnvelope<ControllerAPIKeySecretResult>.self,
            from: data
        )
        #expect(envelope.result.key.models == ["fixture-model"])
        #expect(envelope.result.key.concurrencyLimit == 4)
        #expect(envelope.result.token.hasPrefix("li_"))
    }

    @Test
    func administratorMovePlanDecodesAffectedState() throws {
        let data = Data("""
        {
          "protocol":"letsinfer-controller-control-v1",
          "controller":{"id":"11111111111111111111111111111111","role":"administrator"},
          "result":{"plan":{
            "source_site_id":"22222222222222222222222222222222",
            "source_member_id":"33333333333333333333333333333333",
            "destination_effect":"replace-local-site-membership",
            "member_count":1,
            "controller_count":2,
            "api_key_count":3,
            "placement_count":0,
            "active_placements":[],
            "blocking_reasons":[],
            "preserved_data":["model artifacts"],
            "reset_state":["source controller and API credentials"]
          }}
        }
        """.utf8)
        let envelope = try JSONDecoder().decode(
            ControllerAdministrationEnvelope<SiteMovePlanResult>.self,
            from: data
        )
        #expect(envelope.controller.role == "administrator")
        #expect(envelope.result.plan.apiKeyCount == 3)
        #expect(envelope.result.plan.blockingReasons.isEmpty)
    }

    @Test
    func freshConnectXAdoptionDecodesCommittedPhysicalIdentity() throws {
        let data = Data("""
        {
          "protocol":"letsinfer-controller-control-v1",
          "controller":{"id":"11111111111111111111111111111111","role":"administrator"},
          "result":{"adoption":{
            "protocol":"letsinfer-site-adoption-v1",
            "state":"committed",
            "source_site_id":"22222222222222222222222222222222",
            "destination_site_id":"33333333333333333333333333333333",
            "member_id":"44444444444444444444444444444444",
            "move_id":"55555555555555555555555555555555"
          }}
        }
        """.utf8)
        let envelope = try JSONDecoder().decode(
            ControllerAdministrationEnvelope<AdoptedMemberResult>.self,
            from: data
        )
        #expect(envelope.result.adoption.state == "committed")
        #expect(envelope.result.adoption.memberID == "44444444444444444444444444444444")
    }
}
