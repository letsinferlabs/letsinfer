import Foundation
import Metal
import UIKit

enum DeviceFacts {
    static func make(
        memberID: String,
        foreground: Bool,
        version: String = "ios-prototype-0.1.0"
    ) -> [String: Any] {
        let totalBytes = ProcessInfo.processInfo.physicalMemory
        let totalGiB = max(1, Int(totalBytes / 1_073_741_824))
        let availableBytes = os_proc_available_memory()
        let availableGiB = min(totalGiB, Int(availableBytes / 1_073_741_824))
        let storage = storageCapacity()
        let thermal = ProcessInfo.processInfo.thermalState
        let health: String
        switch thermal {
        case .serious, .critical:
            health = "degraded"
        default:
            health = foreground ? "healthy" : "offline"
        }
        let gpuName = MTLCreateSystemDefaultDevice()?.name ?? "Apple GPU"
        return [
            "schema_version": 1,
            "member_id": memberID,
            "observed_at_unix": Int(Date().timeIntervalSince1970),
            "platform": "ios/arm64",
            "accelerator": [
                "vendor": "apple",
                "architecture": "apple-gpu",
                "count": 1,
                "partitioning": "full-device",
                "minimum_memory_gib": totalGiB,
                "devices": ["apple-gpu-\(memberID)"],
            ],
            "memory": [
                "topology": "unified",
                "total_gib": totalGiB,
                "available_gib": max(0, availableGiB),
            ],
            "storage": [
                "total_gib": storage.total,
                "available_gib": storage.available,
                "cache_available_gib": storage.available,
            ],
            "network": [
                "interfaces": [],
                "links": [],
            ],
            "software": [
                "driver": "\(gpuName); iOS \(UIDevice.current.systemVersion)",
                "container_runtime": "native-app",
                "letsinfer_version": version,
            ],
            "health": [
                "state": health,
                "memory_pressure": availableGiB == 0,
                "protection_trip": thermal == .critical,
                "max_temperature_c": -1,
            ],
        ]
    }

    private static func storageCapacity() -> (total: Int, available: Int) {
        let home = URL(fileURLWithPath: NSHomeDirectory())
        let values = try? home.resourceValues(forKeys: [
            .volumeTotalCapacityKey,
            .volumeAvailableCapacityForImportantUsageKey,
        ])
        let total = max(1, (values?.volumeTotalCapacity ?? 1) / 1_073_741_824)
        let available = min(
            total,
            max(0, Int((values?.volumeAvailableCapacityForImportantUsage ?? 0) / 1_073_741_824))
        )
        return (total, available)
    }
}

struct FactsPublisher {
    let identityStore: NodeIdentityStore

    func publish(
        membership: MembershipRecord,
        provisional: ProvisionalNodeIdentity,
        foreground: Bool
    ) async throws {
        guard let baseURL = URL(string: membership.mainEndpoint) else {
            throw NodeError.invalidData("Main node endpoint is invalid")
        }
        let facts = DeviceFacts.make(
            memberID: membership.document.memberID,
            foreground: foreground
        )
        let signature = try identityStore.sign(CanonicalJSON.data(facts))
            .base64EncodedString()
        let client = PinnedHTTPSClient(
            expectedCertificateSHA256: membership.mainCertificateSHA256,
            clientIdentity: try identityStore.activeTLSIdentity(identity: provisional)
        )
        let response = try await client.request(
            method: "POST",
            url: baseURL.appending(path: "node/v1/facts"),
            object: [
                "protocol": NodeProtocol.control,
                "facts": facts,
                "signature": signature,
            ]
        )
        guard response.count == 2,
              response["protocol"] as? String == NodeProtocol.control,
              response["accepted"] as? Bool == true
        else {
            throw NodeError.invalidData("Main node returned an invalid facts acknowledgement")
        }
    }
}
