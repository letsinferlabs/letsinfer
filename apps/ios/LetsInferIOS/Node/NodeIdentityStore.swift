import CryptoKit
import Foundation
import Security

struct ProvisionalNodeIdentity: Codable, Equatable {
    let nodeID: String
    let memberID: String
    let installationID: String
    let createdAtUnix: Int
}

final class NodeIdentityStore {
    private let defaults: UserDefaults
    private let keyTag = Data("ai.letsinfer.ios.member-signing.v1".utf8)
    private let certificateLabel = "ai.letsinfer.ios.node-tls.v1"
    private let provisionalKey = "letsinfer.provisional-identity.v1"
    private let certificateKey = "letsinfer.provisional-certificate.v1"
    private let membershipKey = "letsinfer.membership.v1"

    init(defaults: UserDefaults = .standard) {
        self.defaults = defaults
    }

    func bootstrap() throws -> ProvisionalNodeIdentity {
        if let data = defaults.data(forKey: provisionalKey),
           let identity = try? JSONDecoder().decode(ProvisionalNodeIdentity.self, from: data) {
            _ = try privateKey()
            _ = try provisionalCertificate(identity: identity)
            return identity
        }
        let identity = ProvisionalNodeIdentity(
            nodeID: randomHex(bytes: 16),
            memberID: randomHex(bytes: 16),
            installationID: randomHex(bytes: 32),
            createdAtUnix: Int(Date().timeIntervalSince1970)
        )
        defaults.set(try JSONEncoder().encode(identity), forKey: provisionalKey)
        _ = try privateKey()
        _ = try provisionalCertificate(identity: identity)
        return identity
    }

    func membership() -> MembershipRecord? {
        guard let data = defaults.data(forKey: membershipKey) else { return nil }
        return try? JSONDecoder().decode(MembershipRecord.self, from: data)
    }

    func save(membership: MembershipRecord) throws {
        let certificate = try certificate(fromPEM: membership.memberCertificatePEM)
        try storeCertificate(certificate)
        defaults.set(try JSONEncoder().encode(membership), forKey: membershipKey)
    }

    func clearMembership() {
        defaults.removeObject(forKey: membershipKey)
    }

    func privateKey() throws -> SecKey {
        let query: [CFString: Any] = [
            kSecClass: kSecClassKey,
            kSecAttrApplicationTag: keyTag,
            kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
            kSecReturnRef: true,
        ]
        var item: CFTypeRef?
        let existing = SecItemCopyMatching(query as CFDictionary, &item)
        if existing == errSecSuccess, let key = item as! SecKey? {
            return key
        }
        guard existing == errSecItemNotFound else {
            throw NodeError.crypto("Could not read the node key (\(existing))")
        }
        var error: Unmanaged<CFError>?
        let attributes: [CFString: Any] = [
            kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits: 256,
            kSecPrivateKeyAttrs: [
                kSecAttrIsPermanent: true,
                kSecAttrApplicationTag: keyTag,
                kSecAttrAccessible: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
            ],
        ]
        guard let key = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
            if let error { throw error.takeRetainedValue() }
            throw NodeError.crypto("Could not create the node key")
        }
        return key
    }

    func publicKeySPKI() throws -> Data {
        let key = try privateKey()
        guard let publicKey = SecKeyCopyPublicKey(key) else {
            throw NodeError.crypto("Node public key is unavailable")
        }
        return DER.p256SubjectPublicKeyInfo(
            rawPublicKey: try externalRepresentation(publicKey)
        )
    }

    func publicKeyPEM() throws -> String {
        pem(label: "PUBLIC KEY", data: try publicKeySPKI())
    }

    func publicKeySHA256() throws -> String {
        SHA256.hash(data: try publicKeySPKI()).hexString
    }

    func sign(_ data: Data) throws -> Data {
        var error: Unmanaged<CFError>?
        guard let signature = SecKeyCreateSignature(
            try privateKey(),
            .ecdsaSignatureMessageX962SHA256,
            data as CFData,
            &error
        ) as Data? else {
            if let error { throw error.takeRetainedValue() }
            throw NodeError.crypto("Could not sign node data")
        }
        return signature
    }

    func activeCertificate(identity: ProvisionalNodeIdentity) throws -> SecCertificate {
        if let membership = membership() {
            return try certificate(fromPEM: membership.memberCertificatePEM)
        }
        return try provisionalCertificate(identity: identity)
    }

    func activeCertificateDER(identity: ProvisionalNodeIdentity) throws -> Data {
        SecCertificateCopyData(try activeCertificate(identity: identity)) as Data
    }

    func activeTLSIdentity(identity: ProvisionalNodeIdentity) throws -> SecIdentity {
        let certificate = try activeCertificate(identity: identity)
        try storeCertificate(certificate)
        guard let result = SecIdentityCreate(nil, certificate, try privateKey()) else {
            throw NodeError.crypto("Could not bind the node certificate to its key")
        }
        return result
    }

    func certificateSHA256(identity: ProvisionalNodeIdentity) throws -> String {
        SHA256.hash(data: try activeCertificateDER(identity: identity)).hexString
    }

    private func provisionalCertificate(
        identity: ProvisionalNodeIdentity
    ) throws -> SecCertificate {
        let certificateData: Data
        if let existing = defaults.data(forKey: certificateKey) {
            certificateData = existing
        } else {
            let privateKey = try privateKey()
            guard let publicKey = SecKeyCopyPublicKey(privateKey) else {
                throw NodeError.crypto("Node public key is unavailable")
            }
            certificateData = try X509CertificateBuilder.selfSigned(
                privateKey: privateKey,
                publicKey: publicKey,
                memberID: identity.memberID
            )
            defaults.set(certificateData, forKey: certificateKey)
        }
        guard let certificate = SecCertificateCreateWithData(
            nil,
            certificateData as CFData
        ) else {
            throw NodeError.crypto("Stored node certificate is invalid")
        }
        try storeCertificate(certificate)
        return certificate
    }

    private func storeCertificate(_ certificate: SecCertificate) throws {
        SecItemDelete([
            kSecClass: kSecClassCertificate,
            kSecAttrLabel: certificateLabel,
        ] as CFDictionary)
        let status = SecItemAdd([
            kSecClass: kSecClassCertificate,
            kSecAttrLabel: certificateLabel,
            kSecValueRef: certificate,
            kSecAttrAccessible: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
        ] as CFDictionary, nil)
        guard status == errSecSuccess || status == errSecDuplicateItem else {
            throw NodeError.crypto("Could not store the node certificate (\(status))")
        }
    }

    private func randomHex(bytes: Int) -> String {
        (try? secureRandom(count: bytes).hexString) ?? UUID().uuidString
            .replacingOccurrences(of: "-", with: "")
            .lowercased()
    }
}

func pem(label: String, data: Data) -> String {
    let body = data.base64EncodedString(options: [.lineLength64Characters, .endLineWithLineFeed])
    return "-----BEGIN \(label)-----\n\(body)\n-----END \(label)-----\n"
}

func pemData(_ value: String, label: String) throws -> Data {
    let body = value
        .replacingOccurrences(of: "-----BEGIN \(label)-----", with: "")
        .replacingOccurrences(of: "-----END \(label)-----", with: "")
        .components(separatedBy: .whitespacesAndNewlines)
        .joined()
    guard let data = Data(base64Encoded: body), !data.isEmpty else {
        throw NodeError.crypto("Invalid \(label.lowercased()) PEM")
    }
    return data
}

func certificate(fromPEM value: String) throws -> SecCertificate {
    let data = try pemData(value, label: "CERTIFICATE")
    guard let certificate = SecCertificateCreateWithData(nil, data as CFData) else {
        throw NodeError.crypto("Invalid certificate")
    }
    return certificate
}

extension Data {
    var hexString: String { map { String(format: "%02x", $0) }.joined() }
}

extension SHA256.Digest {
    var hexString: String { map { String(format: "%02x", $0) }.joined() }
}
