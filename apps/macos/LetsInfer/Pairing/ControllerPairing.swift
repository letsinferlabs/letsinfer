import CryptoKit
import Foundation
import Security

private let controllerPairingProtocol = "letsinfer-controller-pair-v1"
private let controllerPairingPort = 9_769

struct ControllerPairingResult: Equatable, Sendable {
    let installationID: String
    let controllerID: String
    let watchdogPort: Int
    let controlPort: Int
}

protocol ControllerPairing: Sendable {
    func pair(
        host: String,
        setupCode: String,
        name: String,
        onVerificationCode: @escaping @Sendable (String) -> Void
    ) async throws -> ControllerPairingResult
}

enum ControllerPairingError: LocalizedError {
    case invalidCode
    case invalidHost
    case invalidName
    case invalidResponse
    case keyGenerationFailed
    case proofFailed
    case serverIdentityRejected
    case certificateRejected
    case activationFailed(String)
    case keychain(OSStatus)
    case server(String)

    var errorDescription: String? {
        switch self {
        case .invalidCode:
            "Enter the eight-digit code shown by `letsinfer auth controller add`."
        case .invalidHost:
            "Enter a valid Let's Infer hostname or IP address."
        case .invalidName:
            "Enter a controller name between 1 and 64 characters."
        case .invalidResponse:
            "Let's Infer returned an invalid pairing response."
        case .keyGenerationFailed:
            "This Mac could not create its controller key."
        case .proofFailed:
            "This Mac could not prove ownership of its controller key."
        case .serverIdentityRejected:
            "The paired Let's Infer server identity could not be verified."
        case .certificateRejected:
            "The issued Let's Infer controller certificate could not be verified."
        case .activationFailed(let message):
            "Let's Infer issued the controller identity but did not accept it: \(message)"
        case .keychain(let status):
            "The controller identity could not be stored in Keychain (\(status))."
        case .server(let message):
            message
        }
    }
}

private struct PairingHello: Decodable {
    let protocolName: String
    let installationID: String
    let sessionID: String
    let nonce: String
    let watchdogPort: Int
    let controlPort: Int

    enum CodingKeys: String, CodingKey {
        case protocolName = "protocol"
        case installationID = "installation_id"
        case sessionID = "session_id"
        case nonce
        case watchdogPort = "watchdog_port"
        case controlPort = "control_port"
    }
}

private struct PairingEnrollment: Encodable {
    let protocolName: String
    let setupCode: String
    let controllerID: String
    let name: String
    let publicKeySPKI: String
    let proof: String

    enum CodingKeys: String, CodingKey {
        case protocolName = "protocol"
        case setupCode = "setup_code"
        case controllerID = "controller_id"
        case name
        case publicKeySPKI = "public_key_spki"
        case proof
    }
}

private struct PairingResponse: Decodable {
    let protocolName: String
    let status: String
    let installationID: String
    let controllerID: String
    let watchdogPort: Int
    let controlPort: Int
    let certificatePEM: String
    let caPEM: String

    enum CodingKeys: String, CodingKey {
        case protocolName = "protocol"
        case status
        case installationID = "installation_id"
        case controllerID = "controller_id"
        case watchdogPort = "watchdog_port"
        case controlPort = "control_port"
        case certificatePEM = "certificate_pem"
        case caPEM = "ca_pem"
    }
}

private struct PairingErrorResponse: Decodable {
    let error: String
}

private final class PairingTrustDelegate: NSObject, URLSessionDelegate, @unchecked Sendable {
    private let lock = NSLock()
    private var leafData: Data?

    var leafCertificateData: Data? {
        lock.lock()
        defer { lock.unlock() }
        return leafData
    }

    func urlSession(
        _ session: URLSession,
        didReceive challenge: URLAuthenticationChallenge,
        completionHandler: @escaping @Sendable (URLSession.AuthChallengeDisposition, URLCredential?) -> Void
    ) {
        guard
            challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust,
            let trust = challenge.protectionSpace.serverTrust,
            let chain = SecTrustCopyCertificateChain(trust) as? [SecCertificate],
            let leaf = chain.first
        else {
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }
        lock.lock()
        leafData = SecCertificateCopyData(leaf) as Data
        lock.unlock()
        completionHandler(.useCredential, URLCredential(trust: trust))
    }
}

private struct ControllerCredentialMetadata: Codable {
    let installationID: String
    let controllerID: String
    let keyTag: Data
    let certificateLabel: String
    let certificateDER: Data
    let caDER: Data
    let serverCertificateDER: Data
    let alternativeHost: String
    let watchdogPort: Int
    let controlPort: Int
}

struct ControllerPreparedKey: @unchecked Sendable {
    let privateKey: SecKey
    let keyTag: Data
    let publicKeyX963: Data
    let publicKeySPKI: Data
}

final class ControllerCredentialStore: @unchecked Sendable {
    static let shared = ControllerCredentialStore()

    private let controllerService = "ai.letsinfer.macos.controller-id"
    private let credentialService = "ai.letsinfer.macos.controller-credential"

    func controllerID() throws -> String {
        if let data = try genericPassword(service: controllerService, account: "controller"),
           let value = String(data: data, encoding: .ascii),
           Self.lowercaseHex(value, count: 32) {
            return value
        }
        var bytes = [UInt8](repeating: 0, count: 16)
        guard SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes) == errSecSuccess else {
            throw ControllerPairingError.keyGenerationFailed
        }
        let value = bytes.map { String(format: "%02x", $0) }.joined()
        try storeGenericPassword(
            Data(value.utf8), service: controllerService, account: "controller"
        )
        return value
    }

    func prepareKey() throws -> ControllerPreparedKey {
        var tagBytes = [UInt8](repeating: 0, count: 24)
        guard SecRandomCopyBytes(kSecRandomDefault, tagBytes.count, &tagBytes) == errSecSuccess else {
            throw ControllerPairingError.keyGenerationFailed
        }
        let tag = Data("ai.letsinfer.macos.controller-key.".utf8) + Data(tagBytes)
        let privateAttributes: [String: Any] = [
            kSecAttrIsPermanent as String: true,
            kSecAttrIsExtractable as String: false,
            kSecAttrApplicationTag as String: tag,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        ]
        let base: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecPrivateKeyAttrs as String: privateAttributes
        ]
        var error: Unmanaged<CFError>?
        var secure = base
        secure[kSecAttrTokenID as String] = kSecAttrTokenIDSecureEnclave
        let privateKey = SecKeyCreateRandomKey(secure as CFDictionary, &error)
            ?? SecKeyCreateRandomKey(base as CFDictionary, &error)
        guard
            let privateKey,
            let publicKey = SecKeyCopyPublicKey(privateKey),
            let external = SecKeyCopyExternalRepresentation(publicKey, &error) as Data?,
            external.count == 65,
            external.first == 0x04
        else {
            forgetKey(tag: tag)
            throw ControllerPairingError.keyGenerationFailed
        }
        return ControllerPreparedKey(
            privateKey: privateKey,
            keyTag: tag,
            publicKeyX963: external,
            publicKeySPKI: Self.p256SPKI(external)
        )
    }

    func store(
        prepared: ControllerPreparedKey,
        installationID: String,
        controllerID: String,
        certificateDER: Data,
        caDER: Data,
        serverCertificateDER: Data,
        host: String,
        watchdogPort: Int,
        controlPort: Int
    ) throws {
        let previous = try metadata(installationID: installationID)
        guard
            let certificate = SecCertificateCreateWithData(nil, certificateDER as CFData),
            let certificateKey = SecCertificateCopyKey(certificate),
            let external = SecKeyCopyExternalRepresentation(certificateKey, nil) as Data?,
            external == prepared.publicKeyX963
        else {
            forgetKey(tag: prepared.keyTag)
            throw ControllerPairingError.certificateRejected
        }
        let label = "Let's Infer controller \(installationID) \(SHA256.hash(data: certificateDER).hex)"
        let addStatus = SecItemAdd([
            kSecClass as String: kSecClassCertificate,
            kSecValueRef as String: certificate,
            kSecAttrLabel as String: label
        ] as CFDictionary, nil)
        guard addStatus == errSecSuccess || addStatus == errSecDuplicateItem else {
            forgetKey(tag: prepared.keyTag)
            throw ControllerPairingError.keychain(addStatus)
        }
        let value = ControllerCredentialMetadata(
            installationID: installationID,
            controllerID: controllerID,
            keyTag: prepared.keyTag,
            certificateLabel: label,
            certificateDER: certificateDER,
            caDER: caDER,
            serverCertificateDER: serverCertificateDER,
            alternativeHost: host,
            watchdogPort: watchdogPort,
            controlPort: controlPort
        )
        do {
            try storeGenericPassword(
                try JSONEncoder().encode(value),
                service: credentialService,
                account: installationID
            )
        } catch {
            forgetCertificate(label: label)
            forgetKey(tag: prepared.keyTag)
            throw error
        }
        if let previous {
            if previous.certificateLabel != label {
                forgetCertificate(label: previous.certificateLabel)
            }
            if previous.keyTag != prepared.keyTag {
                forgetKey(tag: previous.keyTag)
            }
        }
    }

    func credentials(installationID: String) throws -> WatchdogTLSCredentials {
        guard let value = try metadata(installationID: installationID) else {
            throw WatchdogClientError.credentialsUnavailable
        }
        guard
            let clientCertificate = SecCertificateCreateWithData(
                nil, value.certificateDER as CFData
            ),
            let root = SecCertificateCreateWithData(nil, value.caDER as CFData),
            let serverCertificate = SecCertificateCreateWithData(
                nil, value.serverCertificateDER as CFData
            )
        else {
            throw WatchdogClientError.invalidCertificate
        }
        var identity: SecIdentity?
        guard
            SecIdentityCreateWithCertificate(nil, clientCertificate, &identity) == errSecSuccess,
            let identity
        else {
            throw WatchdogClientError.invalidCredentials
        }
        return WatchdogTLSCredentials(
            identity: identity,
            certificateChain: [clientCertificate, root],
            rootCertificate: root,
            serverCertificate: serverCertificate,
            alternativeHost: value.alternativeHost
        )
    }

    func forget(installationID: String) throws {
        guard let value = try metadata(installationID: installationID) else { return }
        forgetCertificate(label: value.certificateLabel)
        forgetKey(tag: value.keyTag)
        let status = SecItemDelete([
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: credentialService,
            kSecAttrAccount as String: installationID
        ] as CFDictionary)
        if status != errSecSuccess && status != errSecItemNotFound {
            throw ControllerPairingError.keychain(status)
        }
    }

    private func metadata(installationID: String) throws -> ControllerCredentialMetadata? {
        guard let data = try genericPassword(
            service: credentialService, account: installationID
        ) else { return nil }
        do {
            return try JSONDecoder().decode(ControllerCredentialMetadata.self, from: data)
        } catch {
            throw WatchdogClientError.invalidCredentials
        }
    }

    private func genericPassword(service: String, account: String) throws -> Data? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess, let data = result as? Data else {
            throw ControllerPairingError.keychain(status)
        }
        return data
    }

    private func storeGenericPassword(
        _ data: Data, service: String, account: String
    ) throws {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account
        ]
        let update = SecItemUpdate(
            query as CFDictionary,
            [kSecValueData as String: data] as CFDictionary
        )
        if update == errSecSuccess { return }
        guard update == errSecItemNotFound else {
            throw ControllerPairingError.keychain(update)
        }
        var add = query
        add[kSecValueData as String] = data
        add[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        let status = SecItemAdd(add as CFDictionary, nil)
        guard status == errSecSuccess else { throw ControllerPairingError.keychain(status) }
    }

    private func forgetKey(tag: Data) {
        SecItemDelete([
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: tag,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom
        ] as CFDictionary)
    }

    private func forgetCertificate(label: String) {
        SecItemDelete([
            kSecClass as String: kSecClassCertificate,
            kSecAttrLabel as String: label
        ] as CFDictionary)
    }

    private static func p256SPKI(_ x963: Data) -> Data {
        Data([
            0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce,
            0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d,
            0x03, 0x01, 0x07, 0x03, 0x42, 0x00
        ]) + x963
    }

    private static func lowercaseHex(_ value: String, count: Int) -> Bool {
        value.utf8.count == count && value.utf8.allSatisfy {
            ($0 >= 48 && $0 <= 57) || ($0 >= 97 && $0 <= 102)
        }
    }
}

actor ControllerPairingClient: ControllerPairing {
    private let credentials: ControllerCredentialStore

    init(credentials: ControllerCredentialStore = .shared) {
        self.credentials = credentials
    }

    func pair(
        host: String,
        setupCode: String,
        name: String,
        onVerificationCode: @escaping @Sendable (String) -> Void
    ) async throws -> ControllerPairingResult {
        let normalizedHost = host
            .trimmingCharacters(in: .whitespacesAndNewlines)
            .trimmingCharacters(in: CharacterSet(charactersIn: "."))
        guard !normalizedHost.isEmpty else { throw ControllerPairingError.invalidHost }
        let codeScalars = setupCode.unicodeScalars
        guard codeScalars.allSatisfy({ scalar in
            (48...57).contains(scalar.value)
                || scalar == "-"
                || CharacterSet.whitespacesAndNewlines.contains(scalar)
        }) else { throw ControllerPairingError.invalidCode }
        let code = codeScalars
            .filter { (48...57).contains($0.value) }
            .map { String($0) }
            .joined()
        guard code.count == 8 else { throw ControllerPairingError.invalidCode }
        let controllerName = Self.normalizedName(name)
        guard
            !controllerName.isEmpty,
            controllerName.unicodeScalars.count <= 64,
            controllerName.utf8.count <= 128,
            controllerName.unicodeScalars.allSatisfy(Self.isPrintableNameScalar)
        else { throw ControllerPairingError.invalidName }

        let helloRequest = try request(host: normalizedHost, path: "/pair/v1/hello")
        let (helloData, helloCertificate) = try await perform(helloRequest, timeout: 12)
        let hello = try JSONDecoder().decode(PairingHello.self, from: helloData)
        guard
            hello.protocolName == controllerPairingProtocol,
            Self.lowercaseHex(hello.installationID, count: 64),
            Self.lowercaseHex(hello.sessionID, count: 32),
            Self.lowercaseHex(hello.nonce, count: 64),
            (1...65_535).contains(hello.watchdogPort),
            (1...65_535).contains(hello.controlPort)
        else { throw ControllerPairingError.invalidResponse }

        let controllerID = try credentials.controllerID()
        let prepared = try credentials.prepareKey()
        do {
            let publicKeySHA = SHA256.hash(data: prepared.publicKeySPKI).hex
            let challenge = Self.challenge(
                installationID: hello.installationID,
                sessionID: hello.sessionID,
                nonce: hello.nonce,
                controllerID: controllerID,
                name: controllerName,
                publicKeySHA256: publicKeySHA
            )
            var signingError: Unmanaged<CFError>?
            guard let proof = SecKeyCreateSignature(
                prepared.privateKey,
                .ecdsaSignatureMessageX962SHA256,
                challenge as CFData,
                &signingError
            ) as Data? else {
                throw ControllerPairingError.proofFailed
            }
            let verification = Self.confirmationCode(
                installationID: hello.installationID,
                sessionID: hello.sessionID,
                nonce: hello.nonce,
                controllerID: controllerID,
                publicKeySHA256: publicKeySHA
            )
            onVerificationCode("\(verification.prefix(3))-\(verification.suffix(3))")
            let enrollment = PairingEnrollment(
                protocolName: controllerPairingProtocol,
                setupCode: code,
                controllerID: controllerID,
                name: controllerName,
                publicKeySPKI: prepared.publicKeySPKI.base64EncodedString(),
                proof: proof.base64EncodedString()
            )
            var enrollRequest = try request(host: normalizedHost, path: "/pair/v1/enroll")
            enrollRequest.httpMethod = "POST"
            enrollRequest.setValue("application/json", forHTTPHeaderField: "Content-Type")
            enrollRequest.httpBody = try JSONEncoder().encode(enrollment)
            let (responseData, enrollmentCertificate) = try await perform(
                enrollRequest, timeout: 190
            )
            guard helloCertificate == enrollmentCertificate else {
                throw ControllerPairingError.certificateRejected
            }
            let response = try JSONDecoder().decode(PairingResponse.self, from: responseData)
            guard
                response.protocolName == controllerPairingProtocol,
                response.status == "paired",
                response.installationID == hello.installationID,
                response.controllerID == controllerID,
                response.watchdogPort == hello.watchdogPort,
                response.controlPort == hello.controlPort,
                let clientDER = Self.decodePEM(response.certificatePEM),
                let caDER = Self.decodePEM(response.caPEM)
            else { throw ControllerPairingError.invalidResponse }
            try Self.validateBootstrap(leafDER: helloCertificate, caDER: caDER)
            try Self.validateClient(certificateDER: clientDER, caDER: caDER)
            try credentials.store(
                prepared: prepared,
                installationID: hello.installationID,
                controllerID: controllerID,
                certificateDER: clientDER,
                caDER: caDER,
                serverCertificateDER: helloCertificate,
                host: normalizedHost,
                watchdogPort: hello.watchdogPort,
                controlPort: hello.controlPort
            )
            var activationError: Error?
            for attempt in 0..<5 {
                do {
                    _ = try await WatchdogTLSClient().latest(
                        host: normalizedHost,
                        port: hello.watchdogPort,
                        installationID: hello.installationID
                    )
                    activationError = nil
                    break
                } catch {
                    activationError = error
                    if attempt < 4 {
                        try await Task.sleep(for: .milliseconds(400))
                    }
                }
            }
            if let activationError {
                try? credentials.forget(installationID: hello.installationID)
                throw ControllerPairingError.activationFailed(
                    activationError.localizedDescription
                )
            }
            return ControllerPairingResult(
                installationID: hello.installationID,
                controllerID: controllerID,
                watchdogPort: hello.watchdogPort,
                controlPort: hello.controlPort
            )
        } catch {
            credentials.forgetPreparedKey(prepared.keyTag)
            throw error
        }
    }

    private func request(host: String, path: String) throws -> URLRequest {
        var components = URLComponents()
        components.scheme = "https"
        components.host = host
        components.port = controllerPairingPort
        components.path = path
        guard let url = components.url else { throw ControllerPairingError.invalidHost }
        var request = URLRequest(url: url)
        request.cachePolicy = .reloadIgnoringLocalAndRemoteCacheData
        return request
    }

    private func perform(_ request: URLRequest, timeout: TimeInterval) async throws -> (Data, Data) {
        let delegate = PairingTrustDelegate()
        let configuration = URLSessionConfiguration.ephemeral
        configuration.timeoutIntervalForRequest = timeout
        configuration.timeoutIntervalForResource = timeout
        let session = URLSession(configuration: configuration, delegate: delegate, delegateQueue: nil)
        defer { session.finishTasksAndInvalidate() }
        let (data, rawResponse) = try await session.data(for: request)
        guard
            let response = rawResponse as? HTTPURLResponse,
            let leaf = delegate.leafCertificateData
        else { throw ControllerPairingError.invalidResponse }
        guard response.statusCode == 200 else {
            let message = (try? JSONDecoder().decode(PairingErrorResponse.self, from: data).error)
                ?? "Controller pairing failed."
            throw ControllerPairingError.server(message)
        }
        return (data, leaf)
    }

    static func challenge(
        installationID: String,
        sessionID: String,
        nonce: String,
        controllerID: String,
        name: String,
        publicKeySHA256: String
    ) -> Data {
        Data((
            "\(controllerPairingProtocol)\n\(installationID)\n\(sessionID)\n\(nonce)\n" +
            "\(controllerID)\n\(normalizedName(name))\n\(publicKeySHA256)\n"
        ).utf8)
    }

    static func confirmationCode(
        installationID: String,
        sessionID: String,
        nonce: String,
        controllerID: String,
        publicKeySHA256: String
    ) -> String {
        let value = Data((
            "\(controllerPairingProtocol):confirmation\n\(installationID)\n\(sessionID)\n" +
            "\(nonce)\n\(controllerID)\n\(publicKeySHA256)\n"
        ).utf8)
        let digest = SHA256.hash(data: value)
        let prefix = digest.prefix(4).reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
        return String(format: "%06u", prefix % 1_000_000)
    }

    private static func normalizedName(_ value: String) -> String {
        value
            .trimmingCharacters(in: .whitespacesAndNewlines)
            .precomposedStringWithCanonicalMapping
    }

    private static func isPrintableNameScalar(_ scalar: Unicode.Scalar) -> Bool {
        if scalar == " " { return true }
        switch scalar.properties.generalCategory {
        case .control, .format, .surrogate, .privateUse, .unassigned,
             .spaceSeparator, .lineSeparator, .paragraphSeparator:
            return false
        default:
            return true
        }
    }

    private static func decodePEM(_ value: String) -> Data? {
        let base64 = value
            .replacingOccurrences(of: "-----BEGIN CERTIFICATE-----", with: "")
            .replacingOccurrences(of: "-----END CERTIFICATE-----", with: "")
        return Data(base64Encoded: base64, options: .ignoreUnknownCharacters)
    }

    private static func validateBootstrap(leafDER: Data, caDER: Data) throws {
        guard
            let leaf = SecCertificateCreateWithData(nil, leafDER as CFData),
            let root = SecCertificateCreateWithData(nil, caDER as CFData)
        else { throw ControllerPairingError.serverIdentityRejected }
        do {
            // The pairing code and comparison bind this exact leaf to the
            // installation. Use the private installation CA policy here rather
            // than Apple's public-Web-PKI lifetime policy; normal Watchdog
            // connections pin this same leaf byte-for-byte.
            try validateTrust(leaf: leaf, root: root, policy: SecPolicyCreateBasicX509())
        } catch {
            throw ControllerPairingError.serverIdentityRejected
        }
    }

    private static func validateClient(certificateDER: Data, caDER: Data) throws {
        guard
            let leaf = SecCertificateCreateWithData(nil, certificateDER as CFData),
            let root = SecCertificateCreateWithData(nil, caDER as CFData)
        else { throw ControllerPairingError.certificateRejected }
        try validateTrust(leaf: leaf, root: root, policy: SecPolicyCreateBasicX509())
    }

    private static func validateTrust(
        leaf: SecCertificate, root: SecCertificate, policy: SecPolicy
    ) throws {
        var trust: SecTrust?
        guard
            SecTrustCreateWithCertificates(leaf, policy, &trust) == errSecSuccess,
            let trust,
            SecTrustSetAnchorCertificates(trust, [root] as CFArray) == errSecSuccess,
            SecTrustSetAnchorCertificatesOnly(trust, true) == errSecSuccess
        else { throw ControllerPairingError.certificateRejected }
        var error: CFError?
        guard SecTrustEvaluateWithError(trust, &error) else {
            throw ControllerPairingError.certificateRejected
        }
    }

    private static func lowercaseHex(_ value: String, count: Int) -> Bool {
        value.utf8.count == count && value.utf8.allSatisfy {
            ($0 >= 48 && $0 <= 57) || ($0 >= 97 && $0 <= 102)
        }
    }
}

private extension ControllerCredentialStore {
    func forgetPreparedKey(_ tag: Data) {
        SecItemDelete([
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: tag,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom
        ] as CFDictionary)
    }
}

private extension Digest {
    var hex: String { map { String(format: "%02x", $0) }.joined() }
}
