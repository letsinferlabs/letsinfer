import CryptoKit
import Foundation
import Security

final class PinnedHTTPSClient: NSObject, URLSessionDelegate {
    private let expectedCertificateSHA256: String
    private let clientIdentity: SecIdentity?

    init(expectedCertificateSHA256: String, clientIdentity: SecIdentity? = nil) {
        self.expectedCertificateSHA256 = expectedCertificateSHA256
        self.clientIdentity = clientIdentity
    }

    func request(
        method: String,
        url: URL,
        object: [String: Any]? = nil
    ) async throws -> [String: Any] {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.timeoutIntervalForRequest = 15
        configuration.timeoutIntervalForResource = 20
        configuration.waitsForConnectivity = false
        configuration.tlsMinimumSupportedProtocolVersion = .TLSv13
        configuration.tlsMaximumSupportedProtocolVersion = .TLSv13
        let session = URLSession(
            configuration: configuration,
            delegate: self,
            delegateQueue: nil
        )
        defer { session.finishTasksAndInvalidate() }
        var request = URLRequest(url: url)
        request.httpMethod = method
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        if let object {
            request.httpBody = try JSONSerialization.data(
                withJSONObject: object,
                options: [.withoutEscapingSlashes]
            )
            request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        }
        let (data, response) = try await session.data(for: request)
        guard data.count <= NodeProtocol.maximumBodyBytes,
              let http = response as? HTTPURLResponse
        else {
            throw NodeError.network("Node response is invalid")
        }
        let value = try CanonicalJSON.object(from: data)
        guard http.statusCode == 200 else {
            throw NodeError.network(value["error"] as? String ?? "Node request was rejected")
        }
        return value
    }

    func urlSession(
        _ session: URLSession,
        didReceive challenge: URLAuthenticationChallenge,
        completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void
    ) {
        switch challenge.protectionSpace.authenticationMethod {
        case NSURLAuthenticationMethodServerTrust:
            guard let trust = challenge.protectionSpace.serverTrust,
                  let chain = SecTrustCopyCertificateChain(trust) as? [SecCertificate],
                  let leaf = chain.first
            else {
                completionHandler(.cancelAuthenticationChallenge, nil)
                return
            }
            let digest = SHA256.hash(data: SecCertificateCopyData(leaf) as Data).hexString
            guard digest == expectedCertificateSHA256 else {
                completionHandler(.cancelAuthenticationChallenge, nil)
                return
            }
            completionHandler(.useCredential, URLCredential(trust: trust))
        case NSURLAuthenticationMethodClientCertificate:
            guard let clientIdentity else {
                completionHandler(.performDefaultHandling, nil)
                return
            }
            completionHandler(
                .useCredential,
                URLCredential(
                    identity: clientIdentity,
                    certificates: nil,
                    persistence: .forSession
                )
            )
        default:
            completionHandler(.performDefaultHandling, nil)
        }
    }
}
