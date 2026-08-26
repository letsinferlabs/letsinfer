import Foundation
import UIKit

@MainActor
final class InferenceService: ObservableObject {
    enum State: Equatable {
        case noModel
        case loading
        case ready(String)
        case busy
        case paused(String)
        case failed(String)
    }

    @Published private(set) var state: State = .noModel
    @Published private(set) var lastResult: GenerationResult?
    @Published private(set) var modelLoaded = false
    @Published private(set) var activeEngineID = "llamacpp"
    let modelStore: ModelStore
    let mlcModelStore: MLCModelStore
    let engine = LlamaEngine()
    let mlcEngine = MLCMetalEngine()
    private var foreground = true
    private var placementEnabled = true

    init(
        modelStore: ModelStore? = nil,
        mlcModelStore: MLCModelStore? = nil
    ) {
        let modelStore = modelStore ?? ModelStore()
        self.modelStore = modelStore
        self.mlcModelStore = mlcModelStore ?? MLCModelStore()
        if modelStore.modelURL != nil { state = .noModel }
        NotificationCenter.default.addObserver(
            forName: ProcessInfo.thermalStateDidChangeNotification,
            object: nil,
            queue: .main
        ) { [weak self] _ in
            Task { @MainActor in self?.applyAvailability() }
        }
        NotificationCenter.default.addObserver(
            forName: .NSProcessInfoPowerStateDidChange,
            object: nil,
            queue: .main
        ) { [weak self] _ in
            Task { @MainActor in self?.applyAvailability() }
        }
        NotificationCenter.default.addObserver(
            forName: UIDevice.batteryLevelDidChangeNotification,
            object: nil,
            queue: .main
        ) { [weak self] _ in
            Task { @MainActor in self?.applyAvailability() }
        }
    }

    var isReady: Bool {
        if case .ready = state { return true }
        return false
    }

    var servedModelID: String { modelStore.manifest.id }

    var telemetryEngineID: String {
        activeEngineID == "mlc-metal" ? "mlc-metal-ios" : "llama.cpp-ios"
    }

    func downloadAndLoad() async {
        do {
            let url = try await modelStore.download()
            try await load(url: url)
        } catch {
            state = .failed(error.localizedDescription)
        }
    }

    func loadInstalledModel() async {
        do {
            let url = try await modelStore.verifiedModelURL()
            try await load(url: url)
        } catch {
            state = .failed(error.localizedDescription)
        }
    }

    func loadMLCModel(modelURL: URL, modelLibrary: String) async throws {
        state = .loading
        try await mlcEngine.load(modelURL: modelURL, modelLibrary: modelLibrary)
        activeEngineID = "mlc-metal"
        modelLoaded = true
        state = .ready("MLC Metal · Qwen3 0.6B")
        applyAvailability()
    }

    func downloadAndLoadMLC() async {
        do {
            let url = try await mlcModelStore.download()
            try await loadMLCModel(modelURL: url, modelLibrary: "qwen3_0_6b")
        } catch {
            state = .failed(error.localizedDescription)
        }
    }

    func loadInstalledMLCModel() async {
        do {
            let url = try await mlcModelStore.verifiedModelURL()
            try await loadMLCModel(modelURL: url, modelLibrary: "qwen3_0_6b")
        } catch {
            state = .failed(error.localizedDescription)
        }
    }

    func setForeground(_ foreground: Bool) {
        self.foreground = foreground
        applyAvailability()
    }

    func setPlacementEnabled(_ enabled: Bool) {
        placementEnabled = enabled
        applyAvailability()
    }

    func generate(
        messages: [ChatMessage],
        options: GenerationOptions
    ) async throws -> GenerationResult {
        guard foreground else {
            throw NodeError.inference("The iOS node is offline while the app is backgrounded")
        }
        guard placementEnabled else {
            throw NodeError.inference("The model placement is stopped")
        }
        if ProcessInfo.processInfo.isLowPowerModeEnabled || onLowBattery {
            applyAvailability()
            throw NodeError.inference("Inference is paused by power protection")
        }
        switch ProcessInfo.processInfo.thermalState {
        case .serious, .critical:
            applyAvailability()
            throw NodeError.inference("Inference is paused until the device cools")
        default:
            break
        }
        guard isReady else {
            throw NodeError.inference("The model is not ready")
        }
        state = .busy
        do {
            let result = try await (
                activeEngineID == "mlc-metal"
                ? mlcEngine.generate(messages: messages, options: options)
                : engine.generate(messages: messages, options: options)
            )
            lastResult = result
            state = .ready(activeModelDescription)
            return result
        } catch {
            applyAvailability()
            if case .ready = state {} else if case .paused = state {} else {
                state = .failed(error.localizedDescription)
            }
            throw error
        }
    }

    func tokenCount(messages: [ChatMessage]) async throws -> Int {
        guard modelLoaded else {
            throw NodeError.inference("The model is not loaded")
        }
        return try await (
            activeEngineID == "mlc-metal"
            ? mlcEngine.tokenCount(messages: messages)
            : engine.tokenCount(messages: messages)
        )
    }

    private func load(url: URL) async throws {
        state = .loading
        let description = try await engine.load(
            modelURL: url,
            contextTokens: modelStore.manifest.contextTokens
        )
        activeEngineID = "llamacpp"
        modelLoaded = true
        state = .ready(description)
        applyAvailability()
    }

    private func applyAvailability() {
        if !foreground {
            state = .paused("App is not active")
            return
        }
        if !placementEnabled {
            state = .paused("Model placement is stopped")
            return
        }
        if ProcessInfo.processInfo.isLowPowerModeEnabled {
            state = .paused("Low Power Mode is enabled")
            return
        }
        if onLowBattery {
            state = .paused("Connect power to continue")
            return
        }
        switch ProcessInfo.processInfo.thermalState {
        case .serious:
            state = .paused("Device is too warm")
        case .critical:
            state = .paused("Thermal protection is active")
        default:
            if !modelLoaded {
                state = .noModel
            } else if case .paused = state {
                state = .ready(activeModelDescription)
            }
        }
    }

    private var activeModelDescription: String {
        activeEngineID == "mlc-metal"
            ? "MLC Metal · Qwen3 0.6B"
            : modelStore.manifest.displayName
    }

    private var onLowBattery: Bool {
        UIDevice.current.batteryLevel >= 0
            && UIDevice.current.batteryLevel < 0.15
            && UIDevice.current.batteryState == .unplugged
    }
}
