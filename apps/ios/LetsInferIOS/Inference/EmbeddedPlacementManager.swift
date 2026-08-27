import CryptoKit
import Foundation

@MainActor
final class EmbeddedPlacementManager {
    static let protocolName = "letsinfer-placement-job-v1"

    struct Record: Codable {
        let placementGroupID: String
        let placementID: String
        let planSHA256: String
        let runtimeDigest: String
        let manifestSHA256: String
        let topologySHA256: String
        let engineCredentialSHA256: String
        let nodeID: String
        let candidateID: String
        let payloadID: String
        let source: String
        let placement: Data
        var state: String
        var lastOperationID: String
        var updatedAtUnix: Int
    }

    private let defaults = UserDefaults.standard
    private let recordKey = "letsinfer.embedded-placement.v2"
    private let inference: InferenceService
    private let identityStore: NodeIdentityStore
    private let accessKeys = EngineAccessKeyStore()

    init(inference: InferenceService, identityStore: NodeIdentityStore) {
        self.inference = inference
        self.identityStore = identityStore
        if let record = record(), record.state != "running" {
            inference.setPlacementEnabled(false)
        }
    }

    var requiredEngineID: String? {
        guard let record = record(), record.state != "removed" else { return nil }
        return record.candidateID == EmbeddedEngineIdentities.mlcCandidate
            ? "mlc-metal"
            : "llamacpp"
    }

    func handle(
        object: [String: Any],
        engineCredential: String?,
        identity: ProvisionalNodeIdentity
    ) throws -> [String: Any] {
        let job = try validate(object, identity: identity)
        if let current = record(), current.lastOperationID == job.operationID {
            return response(
                operationID: job.operationID,
                replayed: true,
                result: try safeResult(
                    record: current,
                    placement: job.placement,
                    address: job.address,
                    identity: identity
                )
            )
        }
        var record = record()
        if job.action == "stage" {
            guard record == nil
                    || record?.state == "removed"
                    || record?.placementGroupID == job.placementGroupID
            else {
                throw NodeError.inference(
                    "A different iOS placement group is already staged"
                )
            }
            let llamaReady = job.candidateID == EmbeddedEngineIdentities.llamaCandidate
                && job.payloadID == EmbeddedEngineIdentities.llamaPayload
                && inference.activeEngineID == "llamacpp"
                && inference.modelLoaded
                && inference.modelStore.manifest.revision
                    == "23749fefcc72300e3a2ad315e1317431b06b590a"
                && inference.modelStore.manifest.sha256
                    == "9465e63a22add5354d9bb4b99e90117043c7124007664907259bd16d043bb031"
            let mlcReady = job.candidateID == EmbeddedEngineIdentities.mlcCandidate
                && job.payloadID == EmbeddedEngineIdentities.mlcPayload
                && inference.activeEngineID == "mlc-metal"
                && inference.modelLoaded
            guard (llamaReady || mlcReady), let engineCredential,
                  SHA256.hash(data: Data(engineCredential.utf8)).hexString
                    == job.engineCredentialSHA256
            else {
                throw NodeError.inference(
                    "The exact embedded Engine and model must be loaded before stage"
                )
            }
            try accessKeys.setPlacementGroupKey(engineCredential)
            record = Record(
                placementGroupID: job.placementGroupID,
                placementID: job.placementID,
                planSHA256: job.planSHA256,
                runtimeDigest: job.runtimeDigest,
                manifestSHA256: job.manifestSHA256,
                topologySHA256: job.topologySHA256,
                engineCredentialSHA256: job.engineCredentialSHA256,
                nodeID: identity.memberID,
                candidateID: job.candidateID,
                payloadID: job.payloadID,
                source: job.source!,
                placement: try JSONSerialization.data(
                    withJSONObject: job.placement,
                    options: [.sortedKeys]
                ),
                state: "staged",
                lastOperationID: job.operationID,
                updatedAtUnix: Int(Date().timeIntervalSince1970)
            )
            inference.setPlacementEnabled(false)
        } else {
            guard var existing = record,
                  existing.placementGroupID == job.placementGroupID,
                  existing.planSHA256 == job.planSHA256,
                  existing.runtimeDigest == job.runtimeDigest,
                  existing.manifestSHA256 == job.manifestSHA256,
                  existing.topologySHA256 == job.topologySHA256,
                  existing.engineCredentialSHA256 == job.engineCredentialSHA256
            else {
                throw NodeError.inference(
                    "iOS placement job differs from staged immutable state"
                )
            }
            switch job.action {
            case "start", "recover":
                let expectedEngine = existing.candidateID
                    == EmbeddedEngineIdentities.mlcCandidate
                    ? "mlc-metal"
                    : "llamacpp"
                guard inference.modelLoaded,
                      inference.activeEngineID == expectedEngine
                else {
                    throw NodeError.inference("The staged embedded Engine is not loaded")
                }
                existing.state = "running"
                inference.setPlacementEnabled(true)
            case "stop":
                existing.state = "stopped"
                inference.setPlacementEnabled(false)
            case "remove":
                existing.state = "removed"
                inference.setPlacementEnabled(false)
                try accessKeys.setPlacementGroupKey(nil)
            default:
                throw NodeError.invalidData("Unsupported iOS Engine action")
            }
            existing.lastOperationID = job.operationID
            existing.updatedAtUnix = Int(Date().timeIntervalSince1970)
            record = existing
        }
        guard let record else {
            throw NodeError.inference("iOS placement-group state is unavailable")
        }
        save(record)
        return response(
            operationID: job.operationID,
            replayed: false,
            result: try safeResult(
                record: record,
                placement: job.placement,
                address: job.address,
                identity: identity
            )
        )
    }

    func status(placementGroupID: String) -> [String: Any] {
        guard let record = record(), record.placementGroupID == placementGroupID else {
            return [
                "protocol": Self.protocolName,
                "placement": NSNull(),
                "protection_trip_latched": false,
            ]
        }
        return [
            "protocol": Self.protocolName,
            "placement": placementObject(record),
            "protection_trip_latched": ProcessInfo.processInfo.thermalState == .critical,
        ]
    }

    private struct Job {
        let operationID: String
        let placementGroupID: String
        let placementID: String
        let action: String
        let planSHA256: String
        let runtimeDigest: String
        let manifestSHA256: String
        let topologySHA256: String
        let engineCredentialSHA256: String
        let source: String?
        let placement: [String: Any]
        let address: String
        let candidateID: String
        let payloadID: String
    }

    private func validate(
        _ value: [String: Any],
        identity: ProvisionalNodeIdentity
    ) throws -> Job {
        let fields: Set<String> = [
            "protocol", "operation_id", "placement_group_id", "placement_id",
            "action", "node_id",
            "plan_sha256", "runtime_digest", "manifest_sha256", "topology_sha256",
            "engine_credential_sha256", "expires_at_unix", "source", "placement",
            "placement_group",
        ]
        guard Set(value.keys) == fields,
              value["protocol"] as? String == Self.protocolName,
              let operationID = value["operation_id"] as? String,
              let placementGroupID = value["placement_group_id"] as? String,
              let placementID = value["placement_id"] as? String,
              let action = value["action"] as? String,
              value["node_id"] as? String == identity.memberID,
              let planSHA = value["plan_sha256"] as? String,
              let runtimeDigest = value["runtime_digest"] as? String,
              let manifestSHA = value["manifest_sha256"] as? String,
              let topologySHA = value["topology_sha256"] as? String,
              let credentialSHA = value["engine_credential_sha256"] as? String,
              let expires = value["expires_at_unix"] as? Int,
              let placement = value["placement"] as? [String: Any],
              let placementGroup = value["placement_group"] as? [String: Any],
              let release = placementGroup["release"] as? [String: Any],
              let distribution = release["engine_distribution"] as? [String: Any],
              let nativeExecution = release["native_execution"] as? [String: Any],
              operationID.isLowercaseHex(count: 32),
              placementGroupID.isLowercaseHex(count: 32),
              placementID.isLowercaseHex(count: 32),
              ["stage", "start", "recover", "stop", "remove"].contains(action),
              [planSHA, runtimeDigest, manifestSHA, topologySHA, credentialSHA]
                .allSatisfy({ $0.isLowercaseHex(count: 64) }),
              expires >= Int(Date().timeIntervalSince1970) - 30,
              expires <= Int(Date().timeIntervalSince1970) + 300,
              placementGroup["placement_group_id"] as? String == placementGroupID,
              placementGroup["runtime_digest"] as? String == runtimeDigest,
              placementGroup["manifest_sha256"] as? String == manifestSHA,
              placementGroup["topology_sha256"] as? String == topologySHA,
              distribution["kind"] as? String == "embedded-application",
              distribution["platform"] as? String == "ios/arm64",
              distribution["bundle_id"] as? String == "ai.letsinfer.ios",
              distribution["signing_policy"] as? String == "deployment-managed",
              let payloadID = distribution["payload_id"] as? String,
              [EmbeddedEngineIdentities.llamaPayload, EmbeddedEngineIdentities.mlcPayload]
                .contains(payloadID),
              let candidateID = release["candidate_id"] as? String,
              [EmbeddedEngineIdentities.llamaCandidate, EmbeddedEngineIdentities.mlcCandidate]
                .contains(candidateID),
              nativeExecution["engine"] is [String: Any],
              placement["placement_id"] as? String == placementID,
              placement["node_id"] as? String == identity.memberID,
              placement["endpoint_owner"] as? Bool == true,
              placement["port_base"] as? Int == Int(NodeProtocol.enginePort),
              placement["port_count"] as? Int == 1,
              placement["launcher"] as? String == "manifest",
              placement["command"] is [String],
              placement["environment"] is [String: String],
              placement["readiness"] is [String: Any],
              placement["device_uuids"] is [String],
              let plannedPlacements = placementGroup["placements"] as? [[String: Any]],
              let plannedPlacement = plannedPlacements.first(where: {
                  $0["placement_id"] as? String == placementID
                    && $0["node_id"] as? String == identity.memberID
              }),
              plannedPlacement["task_id"] as? String
                == placement["task_id"] as? String,
              plannedPlacement["port_base"] as? Int
                == placement["port_base"] as? Int,
              plannedPlacement["port_count"] as? Int
                == placement["port_count"] as? Int,
              plannedPlacement["device_uuids"] as? [String]
                == placement["device_uuids"] as? [String],
              placementGroup["endpoint_placement_id"] as? String == placementID,
              let address = plannedPlacement["address"] as? String,
              !address.isEmpty,
              SHA256.hash(data: try CanonicalJSON.data(placementGroup)).hexString
                == planSHA
        else {
            throw NodeError.invalidData("iOS placement job is invalid")
        }
        let source = value["source"] as? String
        guard (action == "stage" && source?.contains("@sha256:") == true)
                || (action != "stage" && value["source"] is NSNull),
              action != "stage" || release["source"] as? String == source
        else {
            throw NodeError.invalidData("iOS placement-group source is invalid")
        }
        return Job(
            operationID: operationID,
            placementGroupID: placementGroupID,
            placementID: placementID,
            action: action,
            planSHA256: planSHA,
            runtimeDigest: runtimeDigest,
            manifestSHA256: manifestSHA,
            topologySHA256: topologySHA,
            engineCredentialSHA256: credentialSHA,
            source: source,
            placement: placement,
            address: address,
            candidateID: candidateID,
            payloadID: payloadID
        )
    }

    private func safeResult(
        record: Record,
        placement: [String: Any],
        address: String,
        identity: ProvisionalNodeIdentity
    ) throws -> [String: Any] {
        let certificate = try identityStore.activeCertificateDER(identity: identity)
        let host = address.contains(":") ? "[\(address)]" : address
        return [
            "state": record.state,
            "placement_group_id": record.placementGroupID,
            "placement_id": record.placementID,
            "node_id": record.nodeID,
            "task_id": placement["task_id"] as? String ?? "task-0",
            "runtime_digest": record.runtimeDigest,
            "manifest_sha256": record.manifestSHA256,
            "tls_certificate_sha256": SHA256.hash(data: certificate).hexString,
            "tls_certificate_pem": pem(label: "CERTIFICATE", data: certificate),
            "endpoint": "https://\(host):\(NodeProtocol.enginePort)",
        ]
    }

    private func response(
        operationID: String,
        replayed: Bool,
        result: [String: Any]
    ) -> [String: Any] {
        [
            "protocol": Self.protocolName,
            "operation_id": operationID,
            "replayed": replayed,
            "state": "succeeded",
            "result": result,
        ]
    }

    private func placementObject(_ record: Record) -> [String: Any] {
        [
            "placement_group_id": record.placementGroupID,
            "placement_id": record.placementID,
            "plan_sha256": record.planSHA256,
            "runtime_digest": record.runtimeDigest,
            "manifest_sha256": record.manifestSHA256,
            "topology_sha256": record.topologySHA256,
            "engine_credential_sha256": record.engineCredentialSHA256,
            "node_id": record.nodeID,
            "placement": (
                try? JSONSerialization.jsonObject(with: record.placement)
            ) ?? [:],
            "source": record.source,
            "state": record.state,
            "last_operation_id": record.lastOperationID,
            "updated_at_unix": record.updatedAtUnix,
        ]
    }

    private func record() -> Record? {
        guard let data = defaults.data(forKey: recordKey) else { return nil }
        return try? JSONDecoder().decode(Record.self, from: data)
    }

    private func save(_ record: Record) {
        defaults.set(try? JSONEncoder().encode(record), forKey: recordKey)
    }
}
