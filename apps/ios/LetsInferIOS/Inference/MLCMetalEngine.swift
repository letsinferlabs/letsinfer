import Foundation

#if canImport(MLCSwift)
import MLCSwift

actor MLCMetalEngine {
    private let engine = MLCEngine()
    private var loaded = false

    func load(modelURL: URL, modelLibrary: String) async throws {
        guard modelURL.isFileURL, !modelLibrary.isEmpty else {
            throw NodeError.inference("MLC model identity is invalid")
        }
        await engine.reload(modelPath: modelURL.path, modelLib: modelLibrary)
        loaded = true
    }

    func unload() async {
        await engine.unload()
        loaded = false
    }

    func generate(
        messages: [ChatMessage],
        options: GenerationOptions
    ) async throws -> GenerationResult {
        guard loaded else {
            throw NodeError.inference("MLC Engine is not loaded")
        }
        let input = try messages.map(mlcMessage)
        let started = ContinuousClock.now
        var first: ContinuousClock.Instant?
        var text = ""
        var usage: CompletionUsage?
        let stream = await engine.chat.completions.create(
            messages: input,
            model: "qwen3-0.6b",
            max_tokens: options.maximumTokens,
            seed: Int(options.seed),
            stream: true,
            stream_options: StreamOptions(include_usage: true),
            temperature: options.temperature,
            top_p: options.topP
        )
        for await response in stream {
            if Task.isCancelled { throw CancellationError() }
            for choice in response.choices {
                if let content = choice.delta.content?.asText(), !content.isEmpty {
                    if first == nil { first = .now }
                    text += content
                }
            }
            if let current = response.usage { usage = current }
        }
        guard let usage else {
            throw NodeError.inference("MLC Engine did not return exact usage")
        }
        let finished = ContinuousClock.now
        let firstToken = first ?? finished
        let decodeSeconds = max(
            0.000_001,
            seconds(firstToken.duration(to: finished))
        )
        return GenerationResult(
            text: text,
            promptTokens: usage.prompt_tokens,
            completionTokens: usage.completion_tokens,
            timeToFirstToken: seconds(started.duration(to: firstToken)),
            tokensPerSecond: Double(usage.completion_tokens) / decodeSeconds
        )
    }

    func tokenCount(messages: [ChatMessage]) async throws -> Int {
        guard loaded else {
            throw NodeError.inference("MLC Engine is not loaded")
        }
        let stream = await engine.chat.completions.create(
            messages: try messages.map(mlcMessage),
            model: "qwen3-0.6b",
            max_tokens: 1,
            stream: true,
            stream_options: StreamOptions(include_usage: true),
            temperature: 0
        )
        var count: Int?
        for await response in stream {
            if let usage = response.usage { count = usage.prompt_tokens }
        }
        guard let count, count > 0 else {
            throw NodeError.inference("MLC Engine did not return an exact token count")
        }
        return count
    }

    private func mlcMessage(_ message: ChatMessage) throws -> ChatCompletionMessage {
        guard let role = ChatCompletionRole(rawValue: message.role) else {
            throw NodeError.invalidData("MLC Engine message role is unsupported")
        }
        return ChatCompletionMessage(role: role, content: message.content)
    }

    private func seconds(_ duration: Duration) -> Double {
        let value = duration.components
        return Double(value.seconds) + Double(value.attoseconds) / 1e18
    }
}

#else

actor MLCMetalEngine {
    func load(modelURL: URL, modelLibrary: String) async throws {
        throw NodeError.inference(
            "This build does not contain the pinned MLC Metal libraries"
        )
    }

    func unload() async {}

    func generate(
        messages: [ChatMessage],
        options: GenerationOptions
    ) async throws -> GenerationResult {
        throw NodeError.inference(
            "This build does not contain the pinned MLC Metal libraries"
        )
    }

    func tokenCount(messages: [ChatMessage]) async throws -> Int {
        throw NodeError.inference(
            "This build does not contain the pinned MLC Metal libraries"
        )
    }
}

#endif
