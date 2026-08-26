import Foundation
import llama

struct ChatMessage: Codable, Equatable {
    let role: String
    let content: String
}

struct GenerationOptions: Equatable {
    var maximumTokens = 256
    var temperature: Float = 0.7
    var topP: Float = 0.9
    var seed: UInt32 = UInt32.random(in: 0..<UInt32.max)
}

struct GenerationResult: Equatable {
    let text: String
    let promptTokens: Int
    let completionTokens: Int
    let timeToFirstToken: TimeInterval
    let tokensPerSecond: Double
}

private func clearBatch(_ batch: inout llama_batch) {
    batch.n_tokens = 0
}

private func addToken(
    _ batch: inout llama_batch,
    token: llama_token,
    position: llama_pos,
    logits: Bool
) {
    let index = Int(batch.n_tokens)
    batch.token[index] = token
    batch.pos[index] = position
    batch.n_seq_id[index] = 1
    batch.seq_id[index]![0] = 0
    batch.logits[index] = logits ? 1 : 0
    batch.n_tokens += 1
}

actor LlamaEngine {
    enum State: Equatable {
        case unloaded
        case loaded(description: String)
    }

    private var model: OpaquePointer?
    private var context: OpaquePointer?
    private var vocab: OpaquePointer?
    private var batch: llama_batch?
    private var contextTokens = 0
    private(set) var state: State = .unloaded

    func load(modelURL: URL, contextTokens: Int) throws -> String {
        unload()
        llama_backend_init()
        var modelParameters = llama_model_default_params()
        modelParameters.n_gpu_layers = 999
        guard let model = llama_model_load_from_file(modelURL.path, modelParameters) else {
            llama_backend_free()
            throw NodeError.inference("llama.cpp could not load the GGUF model")
        }
        let threadCount = max(1, min(8, ProcessInfo.processInfo.processorCount - 2))
        var contextParameters = llama_context_default_params()
        contextParameters.n_ctx = UInt32(contextTokens)
        contextParameters.n_batch = UInt32(contextTokens)
        contextParameters.n_ubatch = min(512, UInt32(contextTokens))
        contextParameters.n_threads = Int32(threadCount)
        contextParameters.n_threads_batch = Int32(threadCount)
        guard let context = llama_init_from_model(model, contextParameters) else {
            llama_model_free(model)
            llama_backend_free()
            throw NodeError.inference("llama.cpp could not allocate the model context")
        }
        self.model = model
        self.context = context
        self.vocab = llama_model_get_vocab(model)
        self.batch = llama_batch_init(Int32(contextTokens), 0, 1)
        self.contextTokens = contextTokens
        let description = modelDescription(model)
        state = .loaded(description: description)
        return description
    }

    func unload() {
        if let batch {
            llama_batch_free(batch)
            self.batch = nil
        }
        if let context {
            llama_free(context)
            self.context = nil
        }
        if let model {
            llama_model_free(model)
            self.model = nil
        }
        vocab = nil
        if state != .unloaded { llama_backend_free() }
        state = .unloaded
    }

    func generate(
        messages: [ChatMessage],
        options: GenerationOptions
    ) throws -> GenerationResult {
        guard let model, let context, let vocab, var batch else {
            throw NodeError.inference("No model is loaded")
        }
        guard !messages.isEmpty,
              messages.allSatisfy({ ["system", "user", "assistant"].contains($0.role) && !$0.content.isEmpty }),
              (1...min(2_048, contextTokens)).contains(options.maximumTokens),
              options.temperature >= 0,
              options.temperature <= 2,
              options.topP > 0,
              options.topP <= 1
        else {
            throw NodeError.invalidData("Chat generation options are invalid")
        }
        let prompt = try applyTemplate(model: model, messages: messages)
        let promptTokens = try tokenize(vocab: vocab, text: prompt)
        guard promptTokens.count + options.maximumTokens <= contextTokens else {
            throw NodeError.inference(
                "Prompt and requested output exceed the \(contextTokens)-token context"
            )
        }
        llama_memory_clear(llama_get_memory(context), true)
        clearBatch(&batch)
        for (index, token) in promptTokens.enumerated() {
            addToken(
                &batch,
                token: token,
                position: Int32(index),
                logits: index == promptTokens.count - 1
            )
        }
        let started = ContinuousClock.now
        guard llama_decode(context, batch) == 0 else {
            throw NodeError.inference("Model prompt evaluation failed")
        }

        let samplerParameters = llama_sampler_chain_default_params()
        guard let sampler = llama_sampler_chain_init(samplerParameters) else {
            throw NodeError.inference("Model sampler could not be created")
        }
        defer { llama_sampler_free(sampler) }
        llama_sampler_chain_add(sampler, llama_sampler_init_top_k(40))
        llama_sampler_chain_add(sampler, llama_sampler_init_top_p(options.topP, 1))
        llama_sampler_chain_add(sampler, llama_sampler_init_temp(options.temperature))
        llama_sampler_chain_add(sampler, llama_sampler_init_dist(options.seed))

        var output = Data()
        var completionTokens = 0
        var firstTokenAt: ContinuousClock.Instant?
        var position = promptTokens.count
        while completionTokens < options.maximumTokens {
            if Task.isCancelled {
                throw CancellationError()
            }
            let token = llama_sampler_sample(sampler, context, batch.n_tokens - 1)
            if llama_vocab_is_eog(vocab, token) { break }
            if firstTokenAt == nil { firstTokenAt = .now }
            output.append(contentsOf: tokenPiece(vocab: vocab, token: token))
            completionTokens += 1
            clearBatch(&batch)
            addToken(&batch, token: token, position: Int32(position), logits: true)
            position += 1
            guard llama_decode(context, batch) == 0 else {
                throw NodeError.inference("Model decode failed")
            }
        }
        self.batch = batch
        let finished = ContinuousClock.now
        let first = firstTokenAt ?? finished
        let ttft = durationSeconds(started.duration(to: first))
        let decodeSeconds = max(0.000_001, durationSeconds(first.duration(to: finished)))
        return GenerationResult(
            text: String(decoding: output, as: UTF8.self),
            promptTokens: promptTokens.count,
            completionTokens: completionTokens,
            timeToFirstToken: ttft,
            tokensPerSecond: Double(completionTokens) / decodeSeconds
        )
    }

    func tokenCount(messages: [ChatMessage]) throws -> Int {
        guard let model, let vocab else {
            throw NodeError.inference("No model is loaded")
        }
        guard !messages.isEmpty else {
            throw NodeError.invalidData("messages must be non-empty")
        }
        return try tokenize(
            vocab: vocab,
            text: applyTemplate(model: model, messages: messages)
        ).count
    }

    private func modelDescription(_ model: OpaquePointer) -> String {
        var buffer = [CChar](repeating: 0, count: 512)
        let count = llama_model_desc(model, &buffer, buffer.count)
        guard count > 0 else { return "GGUF model" }
        return String(decoding: buffer.prefix(Int(count)).map(UInt8.init(bitPattern:)), as: UTF8.self)
    }

    private func applyTemplate(
        model: OpaquePointer,
        messages: [ChatMessage]
    ) throws -> String {
        var cMessages: [llama_chat_message] = messages.map { message in
            llama_chat_message(
                role: strdup(message.role),
                content: strdup(message.content)
            )
        }
        defer {
            for message in cMessages {
                free(UnsafeMutableRawPointer(mutating: message.role))
                free(UnsafeMutableRawPointer(mutating: message.content))
            }
        }
        let template = llama_model_chat_template(model, nil)
        var capacity = max(256, messages.reduce(0) { $0 + $1.role.utf8.count + $1.content.utf8.count } * 2)
        while true {
            var buffer = [CChar](repeating: 0, count: capacity)
            let count = llama_chat_apply_template(
                template,
                &cMessages,
                cMessages.count,
                true,
                &buffer,
                Int32(buffer.count)
            )
            guard count >= 0 else {
                throw NodeError.inference("Model chat template could not be applied")
            }
            if count < buffer.count {
                return String(decoding: buffer.prefix(Int(count)).map(UInt8.init(bitPattern:)), as: UTF8.self)
            }
            capacity = Int(count) + 1
        }
    }

    private func tokenize(vocab: OpaquePointer, text: String) throws -> [llama_token] {
        let utf8 = text.utf8.count
        var tokens = [llama_token](repeating: 0, count: utf8 + 4)
        var count = llama_tokenize(
            vocab,
            text,
            Int32(utf8),
            &tokens,
            Int32(tokens.count),
            true,
            true
        )
        if count < 0 {
            tokens = [llama_token](repeating: 0, count: Int(-count))
            count = llama_tokenize(
                vocab,
                text,
                Int32(utf8),
                &tokens,
                Int32(tokens.count),
                true,
                true
            )
        }
        guard count > 0 else {
            throw NodeError.inference("Model tokenizer rejected the prompt")
        }
        return Array(tokens.prefix(Int(count)))
    }

    private func tokenPiece(vocab: OpaquePointer, token: llama_token) -> [UInt8] {
        var buffer = [CChar](repeating: 0, count: 16)
        var count = llama_token_to_piece(
            vocab,
            token,
            &buffer,
            Int32(buffer.count),
            0,
            false
        )
        if count < 0 {
            buffer = [CChar](repeating: 0, count: Int(-count))
            count = llama_token_to_piece(
                vocab,
                token,
                &buffer,
                Int32(buffer.count),
                0,
                false
            )
        }
        guard count > 0 else { return [] }
        return buffer.prefix(Int(count)).map(UInt8.init(bitPattern:))
    }

    private func durationSeconds(_ duration: Duration) -> Double {
        let components = duration.components
        return Double(components.seconds) + Double(components.attoseconds) / 1e18
    }
}
