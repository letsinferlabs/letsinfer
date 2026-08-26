import Foundation
import Network
import Security

@MainActor
final class InferenceHTTPServer: ObservableObject {
    enum State: Equatable {
        case stopped
        case starting
        case ready
        case failed(String)
    }

    @Published private(set) var state: State = .stopped
    private let inference: InferenceService
    private let accessKeys = EngineAccessKeyStore()
    private var server: NodeHTTPServer?
    private var activeRequests = 0
    private var completedRequests = 0

    init(inference: InferenceService) {
        self.inference = inference
    }

    func start(identity: SecIdentity) {
        stop()
        state = .starting
        let server = NodeHTTPServer { [weak self] request, complete in
            Task { @MainActor in
                guard let self else {
                    complete(.forbidden("inference service is unavailable"))
                    return
                }
                await self.route(request, complete: complete)
            }
        }
        self.server = server
        do {
            try server.start(
                identity: identity,
                port: NodeProtocol.enginePort,
                stateChanged: { [weak self] listenerState in
                    Task { @MainActor in
                        switch listenerState {
                        case .ready:
                            self?.state = .ready
                        case .failed(let error):
                            self?.state = .failed(error.localizedDescription)
                        case .cancelled:
                            if let current = self?.state {
                                if case .failed = current {} else { self?.state = .stopped }
                            }
                        default:
                            break
                        }
                    }
                }
            )
        } catch {
            state = .failed(error.localizedDescription)
        }
    }

    func stop() {
        server?.stop()
        server = nil
        state = .stopped
    }

    private func route(
        _ request: HTTPRequest,
        complete: @escaping (HTTPResponse) -> Void
    ) async {
        if request.method == "GET", request.path == "/health" {
            complete(HTTPResponse(status: inference.isReady ? 200 : 503, object: [
                "status": inference.isReady ? "ok" : "unavailable",
                "model": inference.servedModelID,
            ]))
            return
        }
        guard accessKeys.authorizes(request.headers["authorization"]) else {
            complete(HTTPResponse(status: 401, object: ["error": "unauthorized"]))
            return
        }
        if request.method == "GET", request.path == "/v1/letsinfer/telemetry" {
            let result = inference.lastResult
            let decodeRate: Any = result != nil
                ? result!.tokensPerSecond as Any
                : NSNull()
            complete(.ok([
                "object": "engine_telemetry",
                "protocol": 2,
                "engine": inference.telemetryEngineID,
                "model": inference.servedModelID,
                "state": inference.isReady ? "ready" : "starting",
                "requests": [
                    "active": activeRequests,
                    "completed": completedRequests,
                    "queued": NSNull(),
                ],
                "tokens": [
                    "decode_per_second": decodeRate,
                    "prefill_per_second": NSNull(),
                ],
                "cache": [
                    "prefix_hit_rate": NSNull(),
                    "kv_used_bytes": NSNull(),
                ],
                "timestamp_unix_ns": Int64(Date().timeIntervalSince1970 * 1_000_000_000),
            ]))
            return
        }
        if request.method == "GET", request.path == "/v1/models" {
            complete(.ok([
                "object": "list",
                "data": [[
                    "id": inference.servedModelID,
                    "object": "model",
                    "owned_by": "letsinfer-ios",
                ]],
            ]))
            return
        }
        if request.method == "POST", request.path == "/v1/letsinfer/token-count" {
            do {
                let value = try request.json
                guard value["model"] as? String == inference.servedModelID else {
                    throw NodeError.invalidData("request model does not match the native runtime")
                }
                let messages = try parseMessages(value)
                let count = try await inference.tokenCount(messages: messages)
                complete(.ok([
                    "object": "token_count",
                    "model": inference.servedModelID,
                    "prompt_tokens": count,
                ]))
            } catch {
                complete(HTTPResponse(status: 400, object: [
                    "error": ["message": error.localizedDescription, "code": "exact_count_failed"],
                ]))
            }
            return
        }
        guard request.method == "POST", request.path == "/v1/chat/completions" else {
            complete(.notFound())
            return
        }
        do {
            let value = try request.json
            guard value["model"] as? String == inference.servedModelID else {
                throw NodeError.invalidData("request model does not match the native runtime")
            }
            let messages = try parseMessages(value)
            guard value["stream"] as? Bool != true else {
                throw NodeError.invalidData("streaming is not implemented in this prototype")
            }
            var options = GenerationOptions()
            if let maximum = value["max_tokens"] as? Int { options.maximumTokens = maximum }
            if let temperature = value["temperature"] as? NSNumber {
                options.temperature = temperature.floatValue
            }
            if let topP = value["top_p"] as? NSNumber {
                options.topP = topP.floatValue
            }
            activeRequests += 1
            defer {
                activeRequests -= 1
                completedRequests += 1
            }
            let result = try await inference.generate(messages: messages, options: options)
            let created = Int(Date().timeIntervalSince1970)
            complete(.ok([
                "id": "chatcmpl-\(UUID().uuidString.replacingOccurrences(of: "-", with: "").lowercased())",
                "object": "chat.completion",
                "created": created,
                "model": inference.servedModelID,
                "choices": [[
                    "index": 0,
                    "message": ["role": "assistant", "content": result.text],
                    "finish_reason": "stop",
                ]],
                "usage": [
                    "prompt_tokens": result.promptTokens,
                    "completion_tokens": result.completionTokens,
                    "total_tokens": result.promptTokens + result.completionTokens,
                ],
                "letsinfer": [
                    "ttft_seconds": result.timeToFirstToken,
                    "decode_tokens_per_second": result.tokensPerSecond,
                ],
            ]))
        } catch {
            complete(.forbidden(error.localizedDescription))
        }
    }

    private func parseMessages(_ value: [String: Any]) throws -> [ChatMessage] {
        guard let rawMessages = value["messages"] as? [[String: Any]],
              !rawMessages.isEmpty,
              rawMessages.count <= 128
        else {
            throw NodeError.invalidData("messages must be a bounded non-empty array")
        }
        return try rawMessages.map { item -> ChatMessage in
            guard Set(item.keys) == ["role", "content"],
                  let role = item["role"] as? String,
                  let content = item["content"] as? String,
                  !content.isEmpty,
                  content.utf8.count <= 64 * 1024
            else {
                throw NodeError.invalidData("chat message is invalid")
            }
            return ChatMessage(role: role, content: content)
        }
    }
}
