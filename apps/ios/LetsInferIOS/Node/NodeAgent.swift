import Combine
import CryptoKit
import Foundation
import Network
import UIKit

@MainActor
final class NodeAgent: ObservableObject {
    enum State: Equatable {
        case stopped
        case starting
        case discoverable
        case joining(String)
        case child(String)
        case offline
        case failed(String)
    }

    @Published private(set) var state: State = .stopped
    @Published private(set) var pendingRequest: NodeAddRequest?
    @Published private(set) var factsLastPublishedAt: Date?
    @Published private(set) var eventLog: [String] = []

    let identityStore: NodeIdentityStore
    let inference: InferenceService
    let inferenceServer: InferenceHTTPServer
    let embeddedPlacements: EmbeddedPlacementManager
    private let engineAccessKeys = EngineAccessKeyStore()

    private var identity: ProvisionalNodeIdentity?
    private var controlServer: NodeHTTPServer?
    private var deniedRequests: [String: Int] = [:]
    private var factsTimer: Timer?
    private var publishTask: Task<Void, Never>?
    private var enabled = false
    private var foreground = true
    private var cancellables: Set<AnyCancellable> = []

    init(
        identityStore: NodeIdentityStore = NodeIdentityStore(),
        inference: InferenceService? = nil
    ) {
        UIDevice.current.isBatteryMonitoringEnabled = true
        self.identityStore = identityStore
        let inference = inference ?? InferenceService()
        self.inference = inference
        self.inferenceServer = InferenceHTTPServer(inference: inference)
        self.embeddedPlacements = EmbeddedPlacementManager(
            inference: inference,
            identityStore: identityStore
        )
        inference.$state
            .sink { [weak self] _ in
                Task { @MainActor in self?.refreshInferenceServer() }
            }
            .store(in: &cancellables)
    }

    var membership: MembershipRecord? { identityStore.membership() }

    var displayName: String {
        let name = UIDevice.current.name.trimmingCharacters(in: .whitespacesAndNewlines)
        return name.isEmpty ? "iPhone" : String(name.prefix(64))
    }

    var memberID: String? {
        membership?.document.memberID ?? identity?.memberID
    }

    var nodeID: String? {
        membership?.document.siteID ?? identity?.nodeID
    }

    var certificateSHA256: String? {
        guard let identity else { return nil }
        return try? identityStore.certificateSHA256(identity: identity)
    }

    var engineAccessKey: String? { try? engineAccessKeys.key() }

    func start() {
        enabled = true
        guard foreground else {
            state = .offline
            return
        }
        do {
            identity = try identityStore.bootstrap()
            state = .starting
            try startControlServer()
            startFactsTimer()
            if embeddedPlacements.requiredEngineID == "mlc-metal" {
                Task { await inference.loadInstalledMLCModel() }
            } else {
                Task { await inference.loadInstalledModel() }
            }
            UIApplication.shared.isIdleTimerDisabled = true
            appendEvent("Node service starting")
        } catch {
            state = .failed(error.localizedDescription)
            appendEvent(error.localizedDescription)
        }
    }

    func stop() {
        enabled = false
        stopServers()
        inference.setForeground(false)
        state = .stopped
        UIApplication.shared.isIdleTimerDisabled = false
        appendEvent("Node stopped")
    }

    func sceneChanged(active: Bool) {
        foreground = active
        inference.setForeground(active)
        if active {
            if enabled { start() }
            return
        }
        guard enabled else { return }
        let taskID = UIApplication.shared.beginBackgroundTask(withName: "letsinfer-offline")
        Task {
            await publishFacts(foreground: false)
            stopServers()
            state = .offline
            UIApplication.shared.isIdleTimerDisabled = false
            if taskID != .invalid { UIApplication.shared.endBackgroundTask(taskID) }
        }
    }

    func acceptPendingRequest() {
        guard let request = pendingRequest,
              let identity,
              request.expiresAtUnix > Int(Date().timeIntervalSince1970)
        else {
            pendingRequest = nil
            return
        }
        state = .joining(request.mainName)
        appendEvent("Joining \(request.mainName)")
        Task {
            do {
                let membership = try await EnrollmentClient(
                    identityStore: identityStore
                ).enroll(
                    request: request,
                    provisional: identity,
                    memberName: displayName,
                    memberAddress: ProcessInfo.processInfo.hostName
                )
                pendingRequest = nil
                try startControlServer()
                state = .child(request.mainName)
                appendEvent("Added to \(request.mainName)")
                await publishFacts(foreground: true)
                _ = membership
            } catch {
                state = .failed(error.localizedDescription)
                appendEvent("Join failed: \(error.localizedDescription)")
            }
        }
    }

    func denyPendingRequest() {
        guard let request = pendingRequest else { return }
        deniedRequests[request.requestID] = request.expiresAtUnix
        pendingRequest = nil
        state = membership.map { .child($0.document.displayName) } ?? .discoverable
        appendEvent("Denied request from \(request.mainName)")
    }

    func retryAfterFailure() {
        if enabled { start() }
    }

    private func startControlServer() throws {
        guard let identity else {
            throw NodeError.invalidData("Node identity is unavailable")
        }
        controlServer?.stop()
        let server = NodeHTTPServer { [weak self] request, complete in
            Task { @MainActor in
                guard let self else {
                    complete(.forbidden("node service is unavailable"))
                    return
                }
                complete(self.route(request))
            }
        }
        controlServer = server
        let membership = membership
        try server.start(
            identity: identityStore.activeTLSIdentity(identity: identity),
            serviceName: "Let's Infer — \(displayName)",
            txt: try advertisement(identity: identity),
            trustedClientCA: try membership.map {
                try certificate(fromPEM: $0.siteCACertificatePEM)
            },
            requiredClientMemberID: membership?.document.coordinatorID,
            stateChanged: { [weak self] listenerState in
                Task { @MainActor in
                    guard let self else { return }
                    switch listenerState {
                    case .ready:
                        if let membership = self.membership {
                            self.state = .child(membership.document.displayName)
                        } else {
                            self.state = .discoverable
                        }
                        self.appendEvent("Discoverable on port \(NodeProtocol.controlPort)")
                    case .failed(let error):
                        self.state = .failed(error.localizedDescription)
                        self.appendEvent("Node listener failed: \(error.localizedDescription)")
                    default:
                        break
                    }
                }
            }
        )
        refreshInferenceServer(force: true)
    }

    private func advertisement(identity: ProvisionalNodeIdentity) throws -> [String: String] {
        let membership = membership
        return [
            "protocol": "1",
            "node": membership?.document.siteID ?? identity.nodeID,
            "machine": identity.memberID,
            "role": membership == nil ? "main" : "child",
            "state": "configured",
            "key": try identityStore.publicKeySHA256(),
            "tls": try identityStore.certificateSHA256(identity: identity),
            "control": NodeProtocol.control,
            "inference": "https",
            "inference_port": String(NodeProtocol.enginePort),
        ]
    }

    private func route(_ request: HTTPRequest) -> HTTPResponse {
        purgeExpiredRequests()
        if request.method == "GET", request.path == "/node/v1/discovery" {
            return discoveryResponse()
        }
        if request.method == "POST", request.path == "/node/v1/add-request" {
            guard request.headers["content-type"]?.split(separator: ";").first == "application/json" else {
                return .forbidden("membership request content type is invalid")
            }
            guard membership == nil else {
                return .forbidden("this iOS device already belongs to a main node")
            }
            do {
                let candidate = try NodeAddRequest.parse(request.json)
                pendingRequest = candidate
                appendEvent("Request from \(candidate.mainName)")
                return .ok([
                    "protocol": NodeProtocol.nodeAdd,
                    "request_id": candidate.requestID,
                    "status": "pending",
                ])
            } catch {
                return .forbidden(error.localizedDescription)
            }
        }
        let prefix = "/node/v1/add-request/"
        if request.method == "GET", request.path.hasPrefix(prefix) {
            let requestID = String(request.path.dropFirst(prefix.count))
            let status: String
            if pendingRequest?.requestID == requestID {
                status = "pending"
            } else if deniedRequests[requestID] != nil {
                status = "denied"
            } else {
                status = "unknown"
            }
            return .ok([
                "protocol": NodeProtocol.nodeAdd,
                "request_id": requestID,
                "status": status,
            ])
        }
        if request.method == "GET", request.path == "/node/v1/facts",
           let membership {
            do {
                let facts = DeviceFacts.make(
                    memberID: membership.document.memberID,
                    foreground: foreground
                )
                return .ok([
                    "protocol": NodeProtocol.control,
                    "facts": facts,
                    "signature": try identityStore.sign(CanonicalJSON.data(facts))
                        .base64EncodedString(),
                ])
            } catch {
                return .forbidden(error.localizedDescription)
            }
        }
        if request.method == "POST", request.path == "/node/v1/placement-job" {
            do {
                guard let identity else {
                    throw NodeError.invalidData("Node identity is unavailable")
                }
                return .ok(try embeddedPlacements.handle(
                    object: request.json,
                    engineCredential: request.headers[
                        "x-letsinfer-engine-credential"
                    ],
                    identity: identity
                ))
            } catch {
                return .forbidden(error.localizedDescription)
            }
        }
        let placementGroupPrefix = "/node/v1/placement-groups/"
        if request.method == "GET", request.path.hasPrefix(placementGroupPrefix) {
            return .ok(embeddedPlacements.status(
                placementGroupID: String(
                    request.path.dropFirst(placementGroupPrefix.count)
                )
            ))
        }
        return .notFound()
    }

    private func discoveryResponse() -> HTTPResponse {
        guard let identity else {
            return .forbidden("node identity is unavailable")
        }
        let membership = membership
        return .ok([
            "protocol": NodeProtocol.control,
            "display_name": displayName,
            "site_id": membership?.document.siteID ?? identity.nodeID,
            "member_id": identity.memberID,
            "role": membership == nil ? "main" : "child",
            "claimed_state": "configured",
            "public_key_sha256": (try? identityStore.publicKeySHA256()) ?? "",
            "certificate_sha256": certificateSHA256 ?? "",
            "direct_connectx": false,
            "adoption_nonce": NSNull(),
            "adoption_expires_at_unix": NSNull(),
        ])
    }

    private func startFactsTimer() {
        factsTimer?.invalidate()
        factsTimer = Timer.scheduledTimer(withTimeInterval: 5, repeats: true) { [weak self] _ in
            Task { @MainActor in await self?.publishFacts(foreground: true) }
        }
        Task { await publishFacts(foreground: true) }
    }

    private func publishFacts(foreground: Bool) async {
        guard let membership, let identity else { return }
        publishTask?.cancel()
        let task = Task {
            do {
                try await FactsPublisher(identityStore: identityStore).publish(
                    membership: membership,
                    provisional: identity,
                    foreground: foreground
                )
                factsLastPublishedAt = Date()
            } catch {
                appendEvent("Facts unavailable: \(error.localizedDescription)")
            }
        }
        publishTask = task
        await task.value
    }

    private func refreshInferenceServer(force: Bool = false) {
        guard enabled, foreground, inference.modelLoaded, let identity else {
            inferenceServer.stop()
            return
        }
        if !force {
            switch inferenceServer.state {
            case .starting, .ready:
                return
            case .stopped, .failed:
                break
            }
        }
        do {
            inferenceServer.start(
                identity: try identityStore.activeTLSIdentity(identity: identity)
            )
        } catch {
            appendEvent("Engine listener failed: \(error.localizedDescription)")
        }
    }

    private func stopServers() {
        factsTimer?.invalidate()
        factsTimer = nil
        publishTask?.cancel()
        publishTask = nil
        controlServer?.stop()
        controlServer = nil
        inferenceServer.stop()
    }

    private func purgeExpiredRequests() {
        let now = Int(Date().timeIntervalSince1970)
        if let pendingRequest, pendingRequest.expiresAtUnix <= now {
            self.pendingRequest = nil
        }
        deniedRequests = deniedRequests.filter { $0.value > now }
    }

    private func appendEvent(_ message: String) {
        let formatter = DateFormatter()
        formatter.dateFormat = "HH:mm:ss"
        eventLog.append("\(formatter.string(from: Date()))  \(message)")
        if eventLog.count > 8 { eventLog.removeFirst(eventLog.count - 8) }
    }
}
