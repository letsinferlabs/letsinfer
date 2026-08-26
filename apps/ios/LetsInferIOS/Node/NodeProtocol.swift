import CryptoKit
import Foundation
import Security

enum NodeProtocol {
    static let control = "letsinfer-node-control-v1"
    static let nodeAdd = "letsinfer-node-add-v1"
    static let maximumBodyBytes = 16 * 1024
    static let controlPort: UInt16 = 9770
    static let enginePort: UInt16 = 18000
}

enum NodeError: LocalizedError, Equatable {
    case invalidData(String)
    case crypto(String)
    case network(String)
    case inference(String)

    var errorDescription: String? {
        switch self {
        case .invalidData(let message), .crypto(let message),
             .network(let message), .inference(let message):
            return message
        }
    }
}

struct NodeAddRequest: Codable, Equatable, Identifiable {
    let protocolName: String
    let requestID: String
    let mainNodeID: String
    let mainName: String
    let mainEndpoint: String
    let mainCertificateSHA256: String
    let inviteID: String
    let membershipCode: String
    let expiresAtUnix: Int

    var id: String { requestID }

    enum CodingKeys: String, CodingKey {
        case protocolName = "protocol"
        case requestID = "request_id"
        case mainNodeID = "main_node_id"
        case mainName = "main_name"
        case mainEndpoint = "main_endpoint"
        case mainCertificateSHA256 = "main_certificate_sha256"
        case inviteID = "invite_id"
        case membershipCode = "membership_code"
        case expiresAtUnix = "expires_at_unix"
    }

    static func parse(_ object: [String: Any], now: Int = Int(Date().timeIntervalSince1970)) throws -> Self {
        let expected = Set(CodingKeys.allCases.map(\.rawValue))
        guard Set(object.keys) == expected else {
            throw NodeError.invalidData("Node-add request schema is invalid")
        }
        let data = try JSONSerialization.data(withJSONObject: object)
        let value = try JSONDecoder().decode(Self.self, from: data)
        guard value.protocolName == NodeProtocol.nodeAdd,
              value.requestID.isLowercaseHex(count: 32),
              value.mainNodeID.isLowercaseHex(count: 32),
              value.inviteID.isLowercaseHex(count: 32),
              value.mainCertificateSHA256.isLowercaseHex(count: 64),
              value.membershipCode.range(of: #"^[0-9]{8}$"#, options: .regularExpression) != nil,
              !value.mainName.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty,
              now < value.expiresAtUnix,
              value.expiresAtUnix <= now + 300,
              let components = URLComponents(string: value.mainEndpoint),
              components.scheme == "https",
              components.host != nil,
              components.user == nil,
              components.password == nil,
              components.query == nil,
              components.fragment == nil,
              components.path.isEmpty || components.path == "/"
        else {
            throw NodeError.invalidData("Node-add request contains invalid values")
        }
        return value
    }
}

extension NodeAddRequest.CodingKeys: CaseIterable {}

struct EnrollmentChallenge {
    let siteID: String
    let inviteID: String
    let nonce: String
    let mode: String
    let expiresAtUnix: Int
    let coordinatorID: String
    let coordinatorAddress: String
    let sitePublicKeySHA256: String
    let coordinatorCertificateSHA256: String

    static func parse(_ object: [String: Any]) throws -> Self {
        let fields: Set<String> = [
            "protocol", "site_id", "invite_id", "nonce", "mode",
            "expires_at_unix", "coordinator_id", "coordinator_address",
            "site_public_key_sha256", "coordinator_certificate_sha256",
        ]
        guard Set(object.keys) == fields,
              object["protocol"] as? String == NodeProtocol.control,
              let siteID = object["site_id"] as? String,
              let inviteID = object["invite_id"] as? String,
              let nonce = object["nonce"] as? String,
              let mode = object["mode"] as? String,
              let expires = object["expires_at_unix"] as? Int,
              let coordinatorID = object["coordinator_id"] as? String,
              let coordinatorAddress = object["coordinator_address"] as? String,
              let siteKey = object["site_public_key_sha256"] as? String,
              let certificate = object["coordinator_certificate_sha256"] as? String,
              siteID.isLowercaseHex(count: 32),
              inviteID.isLowercaseHex(count: 32),
              nonce.isLowercaseHex(count: 64),
              ["lan", "remote", "connectx"].contains(mode),
              expires >= Int(Date().timeIntervalSince1970) - 30,
              coordinatorID.isLowercaseHex(count: 32),
              !coordinatorAddress.isEmpty,
              siteKey.isLowercaseHex(count: 64),
              certificate.isLowercaseHex(count: 64)
        else {
            throw NodeError.invalidData("Membership challenge is invalid")
        }
        return Self(
            siteID: siteID,
            inviteID: inviteID,
            nonce: nonce,
            mode: mode,
            expiresAtUnix: expires,
            coordinatorID: coordinatorID,
            coordinatorAddress: coordinatorAddress,
            sitePublicKeySHA256: siteKey,
            coordinatorCertificateSHA256: certificate
        )
    }
}

struct MembershipDocument: Codable, Equatable {
    let schemaVersion: Int
    let siteID: String
    let memberID: String
    let installationID: String
    let installationCreatedAtUnix: Int
    let displayName: String
    let coordinatorID: String
    let coordinatorAddress: String
    let sitePublicKeySHA256: String
    let memberPublicKeySHA256: String
    let memberCertificateSHA256: String
    let state: String
    let approvalExpiresAtUnix: Int?
    let issuedAtUnix: Int

    enum CodingKeys: String, CodingKey, CaseIterable {
        case schemaVersion = "schema_version"
        case siteID = "site_id"
        case memberID = "member_id"
        case installationID = "installation_id"
        case installationCreatedAtUnix = "installation_created_at_unix"
        case displayName = "display_name"
        case coordinatorID = "coordinator_id"
        case coordinatorAddress = "coordinator_address"
        case sitePublicKeySHA256 = "site_public_key_sha256"
        case memberPublicKeySHA256 = "member_public_key_sha256"
        case memberCertificateSHA256 = "member_certificate_sha256"
        case state
        case approvalExpiresAtUnix = "approval_expires_at_unix"
        case issuedAtUnix = "issued_at_unix"
    }
}

struct MembershipRecord: Codable, Equatable {
    let document: MembershipDocument
    let signatureBase64: String
    let sitePublicKeyPEM: String
    let siteCACertificatePEM: String
    let memberCertificatePEM: String
    let mainEndpoint: String
    let mainCertificateSHA256: String

    static func parse(
        response: [String: Any],
        request: NodeAddRequest,
        provisional: ProvisionalNodeIdentity,
        identityStore: NodeIdentityStore
    ) throws -> Self {
        let fields: Set<String> = [
            "protocol", "document", "signature", "site_public_key",
            "site_ca_certificate", "member_certificate", "comparison_code",
        ]
        guard Set(response.keys) == fields,
              response["protocol"] as? String == NodeProtocol.control,
              response["comparison_code"] is NSNull,
              let documentObject = response["document"] as? [String: Any],
              Set(documentObject.keys) == Set(MembershipDocument.CodingKeys.allCases.map(\.rawValue)),
              let signature = response["signature"] as? String,
              let sitePublicKey = response["site_public_key"] as? String,
              let siteCA = response["site_ca_certificate"] as? String,
              let memberCertificate = response["member_certificate"] as? String
        else {
            throw NodeError.invalidData("Membership response schema is invalid")
        }
        let encodedDocument = try JSONSerialization.data(withJSONObject: documentObject)
        let document = try JSONDecoder().decode(MembershipDocument.self, from: encodedDocument)
        guard document.schemaVersion == 1,
              document.siteID == request.mainNodeID,
              document.memberID == provisional.memberID,
              document.installationID == provisional.installationID,
              document.installationCreatedAtUnix == provisional.createdAtUnix,
              document.coordinatorID.isLowercaseHex(count: 32),
              document.sitePublicKeySHA256.isLowercaseHex(count: 64),
              document.memberPublicKeySHA256 == (try identityStore.publicKeySHA256()),
              document.memberCertificateSHA256.isLowercaseHex(count: 64),
              document.state == "active",
              document.approvalExpiresAtUnix == nil,
              !document.displayName.isEmpty,
              !document.coordinatorAddress.isEmpty
        else {
            throw NodeError.invalidData("Membership document does not describe this device")
        }

        let sitePublicDER = try pemData(sitePublicKey, label: "PUBLIC KEY")
        guard SHA256.hash(data: sitePublicDER).hexString == document.sitePublicKeySHA256,
              let signatureData = Data(base64Encoded: signature),
              verifyP256Signature(
                publicKeySPKI: sitePublicDER,
                message: try CanonicalJSON.data(documentObject),
                signature: signatureData
              )
        else {
            throw NodeError.crypto("Membership authority signature is invalid")
        }

        let memberCertificateObject = try certificate(fromPEM: memberCertificate)
        let memberCertificateDER = SecCertificateCopyData(memberCertificateObject) as Data
        guard SHA256.hash(data: memberCertificateDER).hexString == document.memberCertificateSHA256,
              memberCertificateDER.range(of: Data("urn:letsinfer:member:\(provisional.memberID)".utf8)) != nil,
              let memberCertificateKey = SecCertificateCopyKey(memberCertificateObject),
              let expectedPublicKey = SecKeyCopyPublicKey(try identityStore.privateKey()),
              try externalRepresentation(memberCertificateKey) == externalRepresentation(expectedPublicKey)
        else {
            throw NodeError.crypto("Membership certificate does not match this device")
        }

        let siteCACertificate = try certificate(fromPEM: siteCA)
        guard let siteCAKey = SecCertificateCopyKey(siteCACertificate),
              try externalRepresentation(siteCAKey) == p256RawKey(fromSPKI: sitePublicDER),
              verifyCertificate(memberCertificateObject, anchoredBy: siteCACertificate)
        else {
            throw NodeError.crypto("Membership certificate chain is invalid")
        }
        return Self(
            document: document,
            signatureBase64: signature,
            sitePublicKeyPEM: sitePublicKey,
            siteCACertificatePEM: siteCA,
            memberCertificatePEM: memberCertificate,
            mainEndpoint: request.mainEndpoint,
            mainCertificateSHA256: request.mainCertificateSHA256
        )
    }
}

func p256RawKey(fromSPKI value: Data) throws -> Data {
    let marker = Data([0x03, 0x42, 0x00, 0x04])
    guard let range = value.range(of: marker), value.distance(from: range.lowerBound, to: value.endIndex) == 68 else {
        throw NodeError.crypto("P-256 public key encoding is invalid")
    }
    return value.suffix(65)
}

func verifyP256Signature(publicKeySPKI: Data, message: Data, signature: Data) -> Bool {
    guard let raw = try? p256RawKey(fromSPKI: publicKeySPKI),
          let key = SecKeyCreateWithData(raw as CFData, [
            kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeyClass: kSecAttrKeyClassPublic,
            kSecAttrKeySizeInBits: 256,
          ] as CFDictionary, nil)
    else { return false }
    return SecKeyVerifySignature(
        key,
        .ecdsaSignatureMessageX962SHA256,
        message as CFData,
        signature as CFData,
        nil
    )
}

func verifyCertificate(_ certificate: SecCertificate, anchoredBy root: SecCertificate) -> Bool {
    var trust: SecTrust?
    guard SecTrustCreateWithCertificates(
        certificate,
        SecPolicyCreateBasicX509(),
        &trust
    ) == errSecSuccess, let trust else { return false }
    SecTrustSetAnchorCertificates(trust, [root] as CFArray)
    SecTrustSetAnchorCertificatesOnly(trust, true)
    return SecTrustEvaluateWithError(trust, nil)
}

extension String {
    func isLowercaseHex(count: Int) -> Bool {
        self.count == count && range(of: "^[0-9a-f]{\(count)}$", options: .regularExpression) != nil
    }
}
