@preconcurrency import Network
import Foundation
import Security

protocol WatchdogTelemetryClient: Sendable {
    func latest(
        host: String, port: Int, installationID: String
    ) async throws -> WatchdogTelemetrySample
    func history(
        host: String, port: Int, installationID: String, since: Date
    ) async throws -> [WatchdogTelemetrySample]
    func subscribe(
        host: String,
        port: Int,
        installationID: String,
        historySeconds: UInt32
    ) async -> AsyncThrowingStream<WatchdogTelemetryEvent, Error>
}

enum WatchdogTelemetryEvent: Equatable, Sendable {
    case sample(WatchdogTelemetrySample)
    case status(SiteStatus)
    case unavailable(String)
}

enum WatchdogClientError: LocalizedError {
    case credentialsUnavailable
    case invalidCredentials
    case invalidCertificate
    case invalidPort
    case connection(String)
    case connectionClosed
    case timeout(String)

    var errorDescription: String? {
        switch self {
        case .credentialsUnavailable:
            "No paired Let's Infer controller identity is available for this node."
        case .invalidCredentials:
            "The paired Let's Infer controller identity could not be loaded."
        case .invalidCertificate:
            "The paired Let's Infer controller CA certificate is invalid."
        case .invalidPort:
            "The watchdog port is invalid."
        case .connection(let message):
            "watchdog connection failed: \(message)"
        case .connectionClosed:
            "watchdog closed the telemetry connection."
        case .timeout(let operation):
            "watchdog timed out while waiting to \(operation)."
        }
    }
}

final class WatchdogTLSCredentials: @unchecked Sendable {
    let identity: SecIdentity
    let certificateChain: [SecCertificate]
    let rootCertificate: SecCertificate
    let serverCertificate: SecCertificate
    let alternativeHost: String?

    init(
        identity: SecIdentity,
        certificateChain: [SecCertificate],
        rootCertificate: SecCertificate,
        serverCertificate: SecCertificate,
        alternativeHost: String?
    ) {
        self.identity = identity
        self.certificateChain = certificateChain
        self.rootCertificate = rootCertificate
        self.serverCertificate = serverCertificate
        self.alternativeHost = alternativeHost
    }
}

actor WatchdogTLSClient: WatchdogTelemetryClient {
    static let supportedProtocolVersion: UInt32 = 3

    private let credentials: ControllerCredentialStore
    private let networkQueue = DispatchQueue(label: "ai.letsinfer.macos.watchdog")
    private let verifyQueue = DispatchQueue(label: "ai.letsinfer.macos.watchdog.verify")

    init() {
        credentials = .shared
    }

    func latest(
        host: String, port: Int, installationID: String
    ) async throws -> WatchdogTelemetrySample {
        let connection = try await connect(
            host: host, port: port, installationID: installationID
        )
        defer { connection.cancel() }
        do {
            try await validateCapabilities(on: connection, requestID: 1)
            let requestID: UInt64 = 2
            try await Self.send(
                try WatchdogProtobuf.framed(WatchdogProtobuf.getLatest(requestID: requestID)),
                on: connection
            )
            let response = try await Self.receiveMessage(on: connection)
            guard response.requestID == requestID else {
                throw WatchdogProtocolError.unexpectedResponse
            }
            switch response {
            case .latest(_, let sample), .live(_, let sample):
                return sample
            case .error(_, let code, let message):
                throw WatchdogProtocolError.server(code: code, message: message)
            default:
                throw WatchdogProtocolError.unexpectedResponse
            }
        } catch {
            connection.cancel()
            throw error
        }
    }

    func history(
        host: String, port: Int, installationID: String, since: Date
    ) async throws -> [WatchdogTelemetrySample] {
        let connection = try await connect(
            host: host, port: port, installationID: installationID
        )
        defer { connection.cancel() }
        do {
            try await validateCapabilities(on: connection, requestID: 1)
            let requestID: UInt64 = 2
            let end = UInt64(max(0, Date().timeIntervalSince1970 * 1_000))
            let start = UInt64(max(0, since.timeIntervalSince1970 * 1_000))
            try await Self.send(
                try WatchdogProtobuf.framed(WatchdogProtobuf.queryHistory(
                    requestID: requestID,
                    startMilliseconds: min(start, end),
                    endMilliseconds: end,
                    resolution: end - min(start, end) > 60 * 60 * 1_000 ? 2 : 1
                )),
                on: connection
            )

            var samples: [WatchdogTelemetrySample] = []
            while true {
                let response = try await Self.receiveMessage(on: connection)
                guard response.requestID == requestID else {
                    throw WatchdogProtocolError.unexpectedResponse
                }
                switch response {
                case .history(_, let batch):
                    samples.append(contentsOf: batch)
                    guard samples.count <= 3_600 else {
                        throw WatchdogProtocolError.frameTooLarge
                    }
                case .historyComplete:
                    return samples
                case .error(_, let code, let message):
                    throw WatchdogProtocolError.server(code: code, message: message)
                default:
                    throw WatchdogProtocolError.unexpectedResponse
                }
            }
        } catch {
            connection.cancel()
            throw error
        }
    }

    func subscribe(
        host: String,
        port: Int,
        installationID: String,
        historySeconds: UInt32
    ) async -> AsyncThrowingStream<WatchdogTelemetryEvent, Error> {
        AsyncThrowingStream { continuation in
            let task = Task { [weak self] in
                guard let self else { return }
                await self.subscriptionLoop(
                    host: host,
                    port: port,
                    installationID: installationID,
                    historySeconds: historySeconds,
                    continuation: continuation
                )
            }
            continuation.onTermination = { @Sendable _ in task.cancel() }
        }
    }

    private func subscriptionLoop(
        host: String,
        port: Int,
        installationID: String,
        historySeconds: UInt32,
        continuation: AsyncThrowingStream<WatchdogTelemetryEvent, Error>.Continuation
    ) async {
        var backoffSeconds = 0.5
        let cursor = WatchdogSubscriptionCursor()
        while !Task.isCancelled {
            let connectedAt = Date()
            do {
                try await runSubscription(
                    host: host,
                    port: port,
                    installationID: installationID,
                    historySeconds: cursor.historySeconds(maximum: historySeconds),
                    cursor: cursor,
                    continuation: continuation
                )
                if Task.isCancelled { break }
                throw WatchdogClientError.connectionClosed
            } catch is CancellationError {
                break
            } catch let error as WatchdogClientError {
                switch error {
                case .credentialsUnavailable, .invalidCredentials, .invalidCertificate, .invalidPort:
                    continuation.finish(throwing: error)
                    return
                case .connection, .connectionClosed, .timeout:
                    continuation.yield(.unavailable(error.localizedDescription))
                    break
                }
            } catch let error as WatchdogProtocolError {
                if case .sequenceGap = error {
                    // Reconnect with retained history to close the gap deterministically.
                    continuation.yield(.unavailable(error.localizedDescription))
                } else {
                    continuation.finish(throwing: error)
                    return
                }
            } catch {
                continuation.finish(throwing: error)
                return
            }

            if Date().timeIntervalSince(connectedAt) >= 10 {
                backoffSeconds = 0.5
            }
            let jitter = Double.random(in: 0...(backoffSeconds * 0.25))
            do {
                try await Task.sleep(for: .seconds(backoffSeconds + jitter))
            } catch {
                break
            }
            backoffSeconds = min(30, backoffSeconds * 2)
        }
        continuation.finish()
    }

    private func runSubscription(
        host: String,
        port: Int,
        installationID: String,
        historySeconds: UInt32,
        cursor: WatchdogSubscriptionCursor,
        continuation: AsyncThrowingStream<WatchdogTelemetryEvent, Error>.Continuation
    ) async throws {
        let connection = try await connect(
            host: host, port: port, installationID: installationID
        )
        defer { connection.cancel() }
        try await validateCapabilities(on: connection, requestID: 1)

        try await Self.send(
            try WatchdogProtobuf.framed(WatchdogProtobuf.getSiteStatus(requestID: 2)),
            on: connection
        )
        let initialStatus = try await Self.receiveMessage(on: connection)
        guard case .letsinferStatus(2, let status) = initialStatus,
              status.installationID == installationID else {
            throw WatchdogProtocolError.unexpectedResponse
        }
        continuation.yield(.status(status))

        let subscriptionID: UInt64 = 3
        try await Self.send(
            try WatchdogProtobuf.framed(WatchdogProtobuf.subscribe(
                requestID: subscriptionID,
                historySeconds: historySeconds
            )),
            on: connection
        )

        var liveSamplesSinceStatus = 0
        var nextRequestID: UInt64 = 4
        var pendingStatusID: UInt64?
        while !Task.isCancelled {
            let message = try await Self.receiveMessage(on: connection)
            switch message {
            case .latest(let requestID, let sample):
                guard requestID == subscriptionID else {
                    throw WatchdogProtocolError.unexpectedResponse
                }
                cursor.beginSession(with: sample)
                continuation.yield(.sample(sample))
                liveSamplesSinceStatus += 1
            case .live(let requestID, let sample):
                guard requestID == subscriptionID else {
                    throw WatchdogProtocolError.unexpectedResponse
                }
                cursor.observe(sample)
                continuation.yield(.sample(sample))
                liveSamplesSinceStatus += 1
            case .history(let requestID, let samples):
                guard requestID == subscriptionID else {
                    throw WatchdogProtocolError.unexpectedResponse
                }
                samples.forEach {
                    cursor.observe($0)
                    continuation.yield(.sample($0))
                }
            case .historyComplete(let requestID, _):
                guard requestID == subscriptionID else {
                    throw WatchdogProtocolError.unexpectedResponse
                }
            case .letsinferStatus(let requestID, let value):
                guard requestID == pendingStatusID,
                      value.installationID == installationID else {
                    throw WatchdogProtocolError.unexpectedResponse
                }
                pendingStatusID = nil
                liveSamplesSinceStatus = 0
                continuation.yield(.status(value))
            case .gap(let requestID, let first, let latest):
                guard requestID == subscriptionID else {
                    throw WatchdogProtocolError.unexpectedResponse
                }
                cursor.noteGap(first: first, latest: latest)
                throw WatchdogProtocolError.sequenceGap(first: first, latest: latest)
            case .error(_, let code, let message):
                throw WatchdogProtocolError.server(code: code, message: message)
            default:
                throw WatchdogProtocolError.unexpectedResponse
            }

            if liveSamplesSinceStatus >= 5, pendingStatusID == nil {
                pendingStatusID = nextRequestID
                nextRequestID &+= 1
                try await Self.send(
                    try WatchdogProtobuf.framed(
                        WatchdogProtobuf.getSiteStatus(requestID: pendingStatusID!)
                    ),
                    on: connection
                )
            }
        }
        throw CancellationError()
    }

    private func validateCapabilities(on connection: NWConnection, requestID: UInt64) async throws {
        try await Self.send(
            try WatchdogProtobuf.framed(WatchdogProtobuf.getCapabilities(requestID: requestID)),
            on: connection
        )
        let response = try await Self.receiveMessage(on: connection)
        guard case .capabilities(requestID, let capabilities) = response else {
            throw WatchdogProtocolError.unexpectedResponse
        }
        guard capabilities.protocolVersion == Self.supportedProtocolVersion else {
            throw WatchdogProtocolError.incompatibleProtocol(capabilities.protocolVersion)
        }
        guard capabilities.mutualTLSRequired else {
            throw WatchdogProtocolError.unexpectedResponse
        }
    }

    private enum ConnectionAttempt: @unchecked Sendable {
        case success(NWConnection)
        case failure(Error)
    }

    private func connect(
        host: String, port: Int, installationID: String
    ) async throws -> NWConnection {
        guard let endpointPort = NWEndpoint.Port(rawValue: UInt16(exactly: port) ?? 0),
              endpointPort.rawValue != 0 else {
            throw WatchdogClientError.invalidPort
        }
        let normalizedHost = host.lowercased().trimmingCharacters(
            in: CharacterSet(charactersIn: ".")
        )
        let credential = try credentials.credentials(installationID: installationID)
        let hosts = [normalizedHost, credential.alternativeHost]
            .compactMap { $0 }
            .reduce(into: [String]()) { values, candidate in
                if !values.contains(candidate) { values.append(candidate) }
            }
        let queue = networkQueue
        let verifier = verifyQueue
        let winner = WatchdogConnectionWinner()

        return try await withThrowingTaskGroup(
            of: ConnectionAttempt.self,
            returning: NWConnection.self
        ) { group in
            for candidate in hosts {
                group.addTask {
                    do {
                        let parameters = try Self.parameters(
                            credential: credential, verifyQueue: verifier
                        )
                        let connection = NWConnection(
                            host: NWEndpoint.Host(candidate),
                            port: endpointPort,
                            using: parameters
                        )
                        do {
                            try await Self.start(connection, queue: queue)
                            if winner.claim() { return .success(connection) }
                            connection.cancel()
                            return .failure(CancellationError())
                        } catch {
                            connection.cancel()
                            return .failure(error)
                        }
                    } catch {
                        return .failure(error)
                    }
                }
            }

            var lastError: Error = WatchdogClientError.connectionClosed
            for try await attempt in group {
                switch attempt {
                case .success(let connection):
                    group.cancelAll()
                    return connection
                case .failure(let error):
                    lastError = error
                }
            }
            throw lastError
        }
    }

    private static func parameters(
        credential: WatchdogTLSCredentials,
        verifyQueue: DispatchQueue
    ) throws -> NWParameters {
        guard let localIdentity = sec_identity_create_with_certificates(
            credential.identity,
            credential.certificateChain as CFArray
        ) else {
            throw WatchdogClientError.invalidCredentials
        }

        let tls = NWProtocolTLS.Options()
        let options = tls.securityProtocolOptions
        sec_protocol_options_set_local_identity(options, localIdentity)
        sec_protocol_options_set_min_tls_protocol_version(options, .TLSv13)
        sec_protocol_options_set_max_tls_protocol_version(options, .TLSv13)

        sec_protocol_options_set_verify_block(options, { _, trustObject, complete in
            let trust = sec_trust_copy_ref(trustObject).takeRetainedValue()
            guard
                let chain = SecTrustCopyCertificateChain(trust) as? [SecCertificate],
                let leaf = chain.first,
                SecCertificateCopyData(leaf) as Data
                    == SecCertificateCopyData(credential.serverCertificate) as Data
            else {
                complete(false)
                return
            }
            let policy = SecPolicyCreateBasicX509()
            let anchors = [credential.rootCertificate] as CFArray
            SecTrustSetPolicies(trust, policy)
            SecTrustSetAnchorCertificates(trust, anchors)
            SecTrustSetAnchorCertificatesOnly(trust, true)
            var error: CFError?
            complete(SecTrustEvaluateWithError(trust, &error))
        }, verifyQueue)

        let tcp = NWProtocolTCP.Options()
        tcp.connectionTimeout = 6
        tcp.enableKeepalive = true
        tcp.keepaliveIdle = 10
        tcp.keepaliveInterval = 5
        tcp.keepaliveCount = 2
        let parameters = NWParameters(tls: tls, tcp: tcp)
        parameters.serviceClass = .background
        return parameters
    }

    private static func start(_ connection: NWConnection, queue: DispatchQueue) async throws {
        let _: Void = try await perform(
            on: connection,
            timeoutSeconds: 8,
            operation: "connect"
        ) { complete in
            connection.stateUpdateHandler = { state in
                switch state {
                case .ready:
                    complete(.success(()))
                case .failed(let error):
                    complete(.failure(WatchdogClientError.connection(error.localizedDescription)))
                case .cancelled:
                    complete(.failure(WatchdogClientError.connectionClosed))
                case .waiting(let error):
                    complete(.failure(WatchdogClientError.connection(error.localizedDescription)))
                default:
                    break
                }
            }
            connection.start(queue: queue)
        }
        connection.stateUpdateHandler = nil
    }

    private static func send(_ data: Data, on connection: NWConnection) async throws {
        let _: Void = try await perform(
            on: connection,
            timeoutSeconds: 5,
            operation: "send a request"
        ) { complete in
            connection.send(content: data, completion: .contentProcessed { error in
                if let error {
                    complete(.failure(WatchdogClientError.connection(error.localizedDescription)))
                } else {
                    complete(.success(()))
                }
            })
        }
    }

    private static func receiveMessage(on connection: NWConnection) async throws -> WatchdogServerMessage {
        let header = try await receiveExactly(4, on: connection)
        let length = try WatchdogProtobuf.frameLength(header)
        return try WatchdogProtobuf.decodeServerEnvelope(
            try await receiveExactly(length, on: connection)
        )
    }

    private static func receiveExactly(_ count: Int, on connection: NWConnection) async throws -> Data {
        var result = Data()
        while result.count < count {
            let remaining = count - result.count
            let chunk: Data = try await perform(
                on: connection,
                timeoutSeconds: 8,
                operation: "receive telemetry"
            ) { complete in
                connection.receive(
                    minimumIncompleteLength: 1,
                    maximumLength: remaining
                ) { data, _, isComplete, error in
                    if let error {
                        complete(.failure(WatchdogClientError.connection(error.localizedDescription)))
                    } else if let data, !data.isEmpty {
                        complete(.success(data))
                    } else if isComplete {
                        complete(.failure(WatchdogClientError.connectionClosed))
                    } else {
                        complete(.failure(WatchdogClientError.connectionClosed))
                    }
                }
            }
            result.append(chunk)
        }
        return result
    }

    private static func perform<Value: Sendable>(
        on connection: NWConnection,
        timeoutSeconds: TimeInterval,
        operation: String,
        start: (@escaping @Sendable (Result<Value, Error>) -> Void) -> Void
    ) async throws -> Value {
        let gate = WatchdogOperationGate<Value>(cancelConnection: { connection.cancel() })
        return try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
                gate.install(continuation)
                gate.scheduleTimeout(after: timeoutSeconds, operation: operation)
                start { result in gate.finish(result) }
            }
        } onCancel: {
            gate.cancel()
        }
    }
}

private final class WatchdogSubscriptionCursor: @unchecked Sendable {
    private let lock = NSLock()
    private var lastSequence: UInt64 = 0
    private var lastUnixMilliseconds: UInt64 = 0

    func historySeconds(maximum: UInt32) -> UInt32 {
        lock.lock()
        defer { lock.unlock() }
        guard lastUnixMilliseconds > 0 else { return maximum }
        let now = UInt64(max(0, Date().timeIntervalSince1970 * 1_000))
        let elapsed = now > lastUnixMilliseconds ? now - lastUnixMilliseconds : 0
        let seconds = min(UInt64(maximum), elapsed / 1_000 + 2)
        return UInt32(max(2, seconds))
    }

    func beginSession(with sample: WatchdogTelemetrySample) {
        lock.lock()
        if sample.sequence < lastSequence && sample.unixMilliseconds >= lastUnixMilliseconds {
            lastSequence = 0
        }
        observeLocked(sample)
        lock.unlock()
    }

    func observe(_ sample: WatchdogTelemetrySample) {
        lock.lock()
        observeLocked(sample)
        lock.unlock()
    }

    func noteGap(first: UInt64, latest: UInt64) {
        lock.lock()
        let missing = latest >= first ? latest - first + 1 : 1
        let rewind = min(lastUnixMilliseconds, (missing + 2) * 1_000)
        lastUnixMilliseconds -= rewind
        lock.unlock()
    }

    private func observeLocked(_ sample: WatchdogTelemetrySample) {
        lastSequence = max(lastSequence, sample.sequence)
        lastUnixMilliseconds = max(lastUnixMilliseconds, sample.unixMilliseconds)
    }
}

private final class WatchdogConnectionWinner: @unchecked Sendable {
    private let lock = NSLock()
    private var selected = false

    func claim() -> Bool {
        lock.lock()
        defer { lock.unlock() }
        guard !selected else { return false }
        selected = true
        return true
    }
}

final class WatchdogOperationGate<Value: Sendable>: @unchecked Sendable {
    private let lock = NSLock()
    private let cancelConnection: @Sendable () -> Void
    private var continuation: CheckedContinuation<Value, Error>?
    private var pendingResult: Result<Value, Error>?
    private var timeout: DispatchWorkItem?
    private var completed = false

    init(cancelConnection: @escaping @Sendable () -> Void) {
        self.cancelConnection = cancelConnection
    }

    func install(_ value: CheckedContinuation<Value, Error>) {
        lock.lock()
        if completed, let result = pendingResult {
            pendingResult = nil
            lock.unlock()
            value.resume(with: result)
        } else {
            continuation = value
            lock.unlock()
        }
    }

    func scheduleTimeout(after seconds: TimeInterval, operation: String) {
        let item = DispatchWorkItem { [weak self] in
            self?.finish(
                .failure(WatchdogClientError.timeout(operation)),
                cancellingConnection: true
            )
        }
        lock.lock()
        if !completed {
            timeout = item
            lock.unlock()
            DispatchQueue.global(qos: .utility).asyncAfter(
                deadline: .now() + seconds,
                execute: item
            )
        } else {
            lock.unlock()
        }
    }

    func finish(_ result: Result<Value, Error>) {
        finish(result, cancellingConnection: false)
    }

    func cancel() {
        finish(.failure(CancellationError()), cancellingConnection: true)
    }

    private func finish(
        _ result: Result<Value, Error>,
        cancellingConnection: Bool
    ) {
        lock.lock()
        guard !completed else {
            lock.unlock()
            return
        }
        completed = true
        let value = continuation
        continuation = nil
        if value == nil { pendingResult = result }
        let timeout = timeout
        self.timeout = nil
        lock.unlock()
        timeout?.cancel()
        if cancellingConnection { cancelConnection() }
        value?.resume(with: result)
    }
}
