import XCTest
@testable import Let_s_Infer

final class NodeContractTests: XCTestCase {
    func testCanonicalJSONMatchesCoreOrderingAndNewline() throws {
        let value: [String: Any] = ["z": 3, "a": "hello/world", "middle": true]
        XCTAssertEqual(
            String(decoding: try CanonicalJSON.data(value), as: UTF8.self),
            #"{"a":"hello/world","middle":true,"z":3}"# + "\n"
        )
    }

    func testNodeAddRequestAcceptsCurrentLANContract() throws {
        let now = 1_800_000_000
        let request = try NodeAddRequest.parse([
            "protocol": NodeProtocol.nodeAdd,
            "request_id": String(repeating: "1", count: 32),
            "main_node_id": String(repeating: "2", count: 32),
            "main_name": "Home",
            "main_endpoint": "https://home.local:9770",
            "main_certificate_sha256": String(repeating: "3", count: 64),
            "invite_id": String(repeating: "4", count: 32),
            "membership_code": "12345678",
            "expires_at_unix": now + 180,
        ], now: now)
        XCTAssertEqual(request.mainName, "Home")
        XCTAssertEqual(request.membershipCode, "12345678")
    }

    func testNodeAddRequestRejectsUnknownFields() {
        let now = 1_800_000_000
        XCTAssertThrowsError(try NodeAddRequest.parse([
            "protocol": NodeProtocol.nodeAdd,
            "request_id": String(repeating: "1", count: 32),
            "main_node_id": String(repeating: "2", count: 32),
            "main_name": "Home",
            "main_endpoint": "https://home.local:9770",
            "main_certificate_sha256": String(repeating: "3", count: 64),
            "invite_id": String(repeating: "4", count: 32),
            "membership_code": "12345678",
            "expires_at_unix": now + 180,
            "unexpected": true,
        ], now: now))
    }

    func testPinnedDefaultModelIdentity() {
        let model = NativeModelManifest.qwen3_0_6B
        XCTAssertEqual(model.revision.count, 40)
        XCTAssertEqual(model.sha256.count, 64)
        XCTAssertEqual(model.sizeBytes, 639_446_688)
        XCTAssertEqual(model.sourceURL.scheme, "https")
        XCTAssertEqual(model.id, "qwen3-0.6b")
        XCTAssertEqual(model.contextTokens, 8_192)
    }

    func testEmbeddedEngineAndMLCSnapshotIdentitiesArePinned() {
        XCTAssertTrue(EmbeddedEngineIdentities.llamaPayload.hasPrefix("sha256:"))
        XCTAssertEqual(EmbeddedEngineIdentities.llamaPayload.count, 71)
        XCTAssertTrue(EmbeddedEngineIdentities.mlcPayload.hasPrefix("sha256:"))
        XCTAssertEqual(EmbeddedEngineIdentities.mlcPayload.count, 71)
        XCTAssertEqual(MLCModelStore.revision.count, 40)
        XCTAssertEqual(MLCModelStore.expectedFileCount, 18)
        XCTAssertEqual(MLCModelStore.expectedSnapshotBytes, 351_517_143)
    }
}
