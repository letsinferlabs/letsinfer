import Foundation
import Network
import Security

struct HTTPRequest {
    let method: String
    let path: String
    let headers: [String: String]
    let body: Data

    var json: [String: Any] {
        get throws {
            guard !body.isEmpty else { return [:] }
            return try CanonicalJSON.object(from: body)
        }
    }
}

struct HTTPResponse {
    let status: Int
    let object: [String: Any]

    static func ok(_ object: [String: Any]) -> Self {
        Self(status: 200, object: object)
    }

    static func forbidden(_ message: String) -> Self {
        Self(status: 403, object: ["error": message])
    }

    static func notFound() -> Self {
        Self(status: 404, object: ["error": "not found"])
    }
}

final class NodeHTTPServer {
    typealias Router = (HTTPRequest, @escaping (HTTPResponse) -> Void) -> Void

    private let queue = DispatchQueue(label: "ai.letsinfer.ios.node-control")
    private let router: Router
    private var listener: NWListener?
    private var connections: [ObjectIdentifier: HTTPConnection] = [:]

    init(router: @escaping Router) {
        self.router = router
    }

    func start(
        identity: SecIdentity,
        port rawPort: UInt16 = NodeProtocol.controlPort,
        serviceName: String? = nil,
        txt: [String: String] = [:],
        trustedClientCA: SecCertificate? = nil,
        requiredClientMemberID: String? = nil,
        stateChanged: @escaping (NWListener.State) -> Void
    ) throws {
        stop()
        let tls = NWProtocolTLS.Options()
        guard let protocolIdentity = sec_identity_create(identity) else {
            throw NodeError.crypto("Could not create the node TLS identity")
        }
        sec_protocol_options_set_local_identity(
            tls.securityProtocolOptions,
            protocolIdentity
        )
        sec_protocol_options_set_min_tls_protocol_version(
            tls.securityProtocolOptions,
            .TLSv13
        )
        sec_protocol_options_set_max_tls_protocol_version(
            tls.securityProtocolOptions,
            .TLSv13
        )
        let requiresClient = trustedClientCA != nil && requiredClientMemberID != nil
        sec_protocol_options_set_peer_authentication_required(
            tls.securityProtocolOptions,
            requiresClient
        )
        if let trustedClientCA, let requiredClientMemberID {
            sec_protocol_options_set_verify_block(
                tls.securityProtocolOptions,
                { _, trust, complete in
                    let unmanagedTrust = sec_trust_copy_ref(trust)
                    let trustRef = unmanagedTrust.takeRetainedValue()
                    SecTrustSetAnchorCertificates(
                        trustRef,
                        [trustedClientCA] as CFArray
                    )
                    SecTrustSetAnchorCertificatesOnly(trustRef, true)
                    guard SecTrustEvaluateWithError(trustRef, nil),
                          let chain = SecTrustCopyCertificateChain(trustRef) as? [SecCertificate],
                          let leaf = chain.first
                    else {
                        complete(false)
                        return
                    }
                    let der = SecCertificateCopyData(leaf) as Data
                    complete(
                        der.range(
                            of: Data("urn:letsinfer:member:\(requiredClientMemberID)".utf8)
                        ) != nil
                    )
                },
                queue
            )
        }

        let parameters = NWParameters(tls: tls, tcp: NWProtocolTCP.Options())
        parameters.includePeerToPeer = true
        parameters.allowLocalEndpointReuse = true
        guard let port = NWEndpoint.Port(rawValue: rawPort) else {
            throw NodeError.network("Node control port is invalid")
        }
        let listener = try NWListener(using: parameters, on: port)
        if let serviceName {
            listener.service = NWListener.Service(
                name: serviceName,
                type: "_letsinfer._tcp",
                domain: "local",
                txtRecord: NWTXTRecord(txt)
            )
        }
        listener.stateUpdateHandler = stateChanged
        listener.newConnectionHandler = { [weak self] connection in
            self?.accept(connection)
        }
        self.listener = listener
        listener.start(queue: queue)
    }

    func stop() {
        listener?.cancel()
        listener = nil
        connections.values.forEach { $0.cancel() }
        connections.removeAll()
    }

    private func accept(_ connection: NWConnection) {
        var handler: HTTPConnection!
        handler = HTTPConnection(
            connection: connection,
            router: router,
            finished: { [weak self] in
                self?.connections.removeValue(forKey: ObjectIdentifier(handler))
            }
        )
        connections[ObjectIdentifier(handler)] = handler
        handler.start(queue: queue)
    }
}

private final class HTTPConnection {
    private let connection: NWConnection
    private let router: NodeHTTPServer.Router
    private let finished: () -> Void
    private var buffer = Data()
    private var complete = false
    private var didFinish = false

    init(
        connection: NWConnection,
        router: @escaping NodeHTTPServer.Router,
        finished: @escaping () -> Void
    ) {
        self.connection = connection
        self.router = router
        self.finished = finished
    }

    func start(queue: DispatchQueue) {
        connection.stateUpdateHandler = { [weak self] state in
            switch state {
            case .ready:
                self?.receive()
            case .failed, .cancelled:
                self?.finish()
            default:
                break
            }
        }
        connection.start(queue: queue)
    }

    func cancel() {
        connection.cancel()
        finish()
    }

    private func receive() {
        connection.receive(
            minimumIncompleteLength: 1,
            maximumLength: NodeProtocol.maximumBodyBytes + 4096
        ) { [weak self] data, _, isComplete, error in
            guard let self, !self.complete else { return }
            if let data { self.buffer.append(data) }
            if self.buffer.count > NodeProtocol.maximumBodyBytes + 4096 {
                self.send(.forbidden("request is too large"))
                return
            }
            do {
                if let request = try self.parseIfComplete() {
                    self.router(request) { [weak self] response in
                        self?.send(response)
                    }
                    return
                }
            } catch {
                self.send(.forbidden(error.localizedDescription))
                return
            }
            if error != nil || isComplete {
                self.finish()
            } else {
                self.receive()
            }
        }
    }

    private func parseIfComplete() throws -> HTTPRequest? {
        guard let headerRange = buffer.range(of: Data("\r\n\r\n".utf8)) else {
            return nil
        }
        let headerData = buffer[..<headerRange.lowerBound]
        guard let headerText = String(data: headerData, encoding: .utf8) else {
            throw NodeError.invalidData("request headers are not UTF-8")
        }
        let lines = headerText.components(separatedBy: "\r\n")
        guard let requestLine = lines.first else {
            throw NodeError.invalidData("request line is missing")
        }
        let requestParts = requestLine.split(separator: " ")
        guard requestParts.count == 3,
              requestParts[2] == "HTTP/1.1",
              ["GET", "POST"].contains(String(requestParts[0]))
        else {
            throw NodeError.invalidData("request line is invalid")
        }
        var headers: [String: String] = [:]
        for line in lines.dropFirst() {
            guard let separator = line.firstIndex(of: ":") else {
                throw NodeError.invalidData("request header is invalid")
            }
            let key = line[..<separator].trimmingCharacters(in: .whitespaces).lowercased()
            let value = line[line.index(after: separator)...].trimmingCharacters(in: .whitespaces)
            guard !key.isEmpty, headers[key] == nil else {
                throw NodeError.invalidData("request headers are ambiguous")
            }
            headers[key] = value
        }
        let contentLength = Int(headers["content-length"] ?? "0") ?? -1
        guard contentLength >= 0, contentLength <= NodeProtocol.maximumBodyBytes else {
            throw NodeError.invalidData("request content length is invalid")
        }
        let bodyStart = headerRange.upperBound
        guard buffer.distance(from: bodyStart, to: buffer.endIndex) >= contentLength else {
            return nil
        }
        let bodyEnd = buffer.index(bodyStart, offsetBy: contentLength)
        return HTTPRequest(
            method: String(requestParts[0]),
            path: String(requestParts[1]),
            headers: headers,
            body: Data(buffer[bodyStart..<bodyEnd])
        )
    }

    private func send(_ response: HTTPResponse) {
        guard !complete else { return }
        complete = true
        let body = (try? JSONSerialization.data(
            withJSONObject: response.object,
            options: [.sortedKeys, .withoutEscapingSlashes]
        )) ?? Data(#"{"error":"response encoding failed"}"#.utf8)
        let reason: String
        switch response.status {
        case 200: reason = "OK"
        case 403: reason = "Forbidden"
        case 404: reason = "Not Found"
        default: reason = "Error"
        }
        var message = Data(
            "HTTP/1.1 \(response.status) \(reason)\r\n".utf8
        )
        message.append(Data("Content-Type: application/json\r\n".utf8))
        message.append(Data("Content-Length: \(body.count)\r\n".utf8))
        message.append(Data("Connection: close\r\n\r\n".utf8))
        message.append(body)
        connection.send(content: message, completion: .contentProcessed { [weak self] _ in
            self?.connection.cancel()
            self?.finish()
        })
    }

    private func finish() {
        guard !didFinish else { return }
        didFinish = true
        complete = true
        finished()
    }
}
