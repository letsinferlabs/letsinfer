import SwiftUI
import UIKit

struct ContentView: View {
    @ObservedObject var agent: NodeAgent

    var body: some View {
        ZStack {
            BrandPalette.canvas.ignoresSafeArea()
            ScrollView {
                VStack(spacing: 18) {
                    topBar
                    hero
                    if let request = agent.pendingRequest {
                        IncomingRequestCard(agent: agent, request: request)
                    }
                    NodeStatusCard(agent: agent)
                    ModelCard(
                        inference: agent.inference,
                        modelStore: agent.inference.modelStore
                    )
                    MLCModelCard(
                        inference: agent.inference,
                        modelStore: agent.inference.mlcModelStore
                    )
                    AddNodeCard(agent: agent)
                    EngineEndpointCard(agent: agent)
                    KioskCard()
                    EventLogCard(events: agent.eventLog)
                }
                .frame(maxWidth: 760)
                .padding(.horizontal, 18)
                .padding(.bottom, 44)
            }
        }
        .preferredColorScheme(nil)
    }

    private var topBar: some View {
        HStack(spacing: 12) {
            BoltMark()
            Text("Let's Infer")
                .font(.system(size: 20, weight: .semibold, design: .rounded))
                .tracking(-0.35)
            Spacer()
            statusCapsule
        }
        .padding(.top, 12)
        .frame(height: 62)
    }

    private var hero: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("Turn this iPhone into one reliable inference node.")
                .font(.system(size: 42, weight: .bold, design: .rounded))
                .tracking(-1.9)
                .lineSpacing(-3)
            Text("Metal inference, certificate-pinned enrollment, and graceful offline state—all inside the app.")
                .font(.system(size: 17, weight: .regular))
                .foregroundStyle(.secondary)
                .lineSpacing(3)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(.vertical, 22)
    }

    private var statusCapsule: some View {
        let presentation = agent.state.presentation
        return HStack(spacing: 7) {
            Circle().fill(presentation.color).frame(width: 8, height: 8)
            Text(presentation.label.uppercased())
                .font(.system(size: 11, weight: .bold, design: .rounded))
                .tracking(0.7)
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 8)
        .background(presentation.color.opacity(0.14))
        .clipShape(Capsule())
    }
}

private struct NodeStatusCard: View {
    @ObservedObject var agent: NodeAgent

    var body: some View {
        ActivityCard {
            VStack(alignment: .leading, spacing: 16) {
                HStack(alignment: .top) {
                    VStack(alignment: .leading, spacing: 4) {
                        Text("NODE")
                            .eyebrow()
                        Text(agent.state.presentation.title)
                            .font(.system(size: 28, weight: .bold, design: .rounded))
                            .tracking(-0.8)
                    }
                    Spacer()
                    Image(systemName: "iphone.gen3.radiowaves.left.and.right")
                        .font(.system(size: 28, weight: .medium))
                        .foregroundStyle(agent.state.presentation.color)
                }
                if let memberID = agent.memberID {
                    IdentityRow(label: "Machine", value: memberID)
                }
                if let nodeID = agent.nodeID {
                    IdentityRow(label: "Node", value: nodeID)
                }
                if let fingerprint = agent.certificateSHA256 {
                    IdentityRow(label: "TLS", value: fingerprint)
                }
                Button {
                    switch agent.state {
                    case .stopped:
                        agent.start()
                    default:
                        agent.stop()
                    }
                } label: {
                    Text(agent.state == .stopped ? "Start node" : "Stop node")
                        .frame(maxWidth: .infinity)
                }
                .buttonStyle(PrimaryButtonStyle(
                    color: agent.state == .stopped ? BrandPalette.blue : BrandPalette.red
                ))
            }
        }
    }
}

private struct IncomingRequestCard: View {
    @ObservedObject var agent: NodeAgent
    let request: NodeAddRequest

    var body: some View {
        ActivityCard {
            VStack(alignment: .leading, spacing: 16) {
                Label("Adoption request", systemImage: "exclamationmark.circle.fill")
                    .font(.system(size: 13, weight: .bold, design: .rounded))
                    .foregroundStyle(BrandPalette.yellow)
                Text(request.mainName)
                    .font(.system(size: 30, weight: .bold, design: .rounded))
                    .tracking(-0.8)
                Text("Accepting replaces this device's standalone node authority and joins it to the selected main. The model stays on this device.")
                    .foregroundStyle(.secondary)
                HStack(spacing: 10) {
                    Button("Deny") { agent.denyPendingRequest() }
                        .buttonStyle(SecondaryButtonStyle())
                    Button("Accept") { agent.acceptPendingRequest() }
                        .buttonStyle(PrimaryButtonStyle(color: BrandPalette.blue))
                }
            }
        }
        .overlay(alignment: .topTrailing) {
            Circle()
                .fill(BrandPalette.yellow)
                .frame(width: 12, height: 12)
                .padding(20)
        }
    }
}

private struct ModelCard: View {
    @ObservedObject var inference: InferenceService
    @ObservedObject var modelStore: ModelStore

    var body: some View {
        ActivityCard {
            VStack(alignment: .leading, spacing: 16) {
                HStack {
                    VStack(alignment: .leading, spacing: 4) {
                        Text("NATIVE MODEL").eyebrow()
                        Text(modelStore.manifest.displayName)
                            .font(.system(size: 28, weight: .bold, design: .rounded))
                            .tracking(-0.8)
                    }
                    Spacer()
                    Text("METAL")
                        .font(.system(size: 11, weight: .bold, design: .rounded))
                        .tracking(0.7)
                        .padding(.horizontal, 10)
                        .padding(.vertical, 7)
                        .background(BrandPalette.purple.opacity(0.15))
                        .foregroundStyle(BrandPalette.purple)
                        .clipShape(Capsule())
                }
                modelState
                if let result = inference.lastResult {
                    HStack(spacing: 12) {
                        metric("DECODE", String(format: "%.1f tok/s", result.tokensPerSecond))
                        metric("TTFT", String(format: "%.2f s", result.timeToFirstToken))
                    }
                }
            }
        }
    }

    @ViewBuilder
    private var modelState: some View {
        switch modelStore.state {
        case .missing:
            Text("Exact Q8_0 GGUF · 610 MiB · pinned revision and SHA-256")
                .foregroundStyle(.secondary)
            Button("Download model") {
                Task { await inference.downloadAndLoad() }
            }
            .buttonStyle(PrimaryButtonStyle(color: BrandPalette.blue))
        case .downloading(let progress):
            ProgressView(value: progress)
                .tint(BrandPalette.blue)
            Text("Downloading \(Int(progress * 100))%")
                .foregroundStyle(.secondary)
        case .verifying:
            ProgressView("Verifying SHA-256…")
        case .ready:
            switch inference.state {
            case .noModel:
                Button("Load model") {
                    Task { await inference.loadInstalledModel() }
                }
                .buttonStyle(PrimaryButtonStyle(color: BrandPalette.blue))
            case .loading:
                ProgressView("Loading into unified memory…")
            case .ready(let description):
                Label(description, systemImage: "checkmark.circle.fill")
                    .foregroundStyle(BrandPalette.green)
            case .busy:
                ProgressView("Generating…")
            case .paused(let reason):
                Label(reason, systemImage: "thermometer.high")
                    .foregroundStyle(BrandPalette.orange)
            case .failed(let reason):
                Label(reason, systemImage: "xmark.circle.fill")
                    .foregroundStyle(BrandPalette.red)
            }
        case .failed(let reason):
            Label(reason, systemImage: "xmark.circle.fill")
                .foregroundStyle(BrandPalette.red)
            Button("Retry download") {
                Task { await inference.downloadAndLoad() }
            }
            .buttonStyle(PrimaryButtonStyle(color: BrandPalette.blue))
        }
    }

    private func metric(_ label: String, _ value: String) -> some View {
        VStack(alignment: .leading, spacing: 3) {
            Text(label).eyebrow()
            Text(value).font(.system(size: 20, weight: .bold, design: .rounded))
        }
        .padding(14)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(BrandPalette.surface)
        .clipShape(RoundedRectangle(cornerRadius: 16, style: .continuous))
    }
}

private struct MLCModelCard: View {
    @ObservedObject var inference: InferenceService
    @ObservedObject var modelStore: MLCModelStore

    var body: some View {
        ActivityCard {
            VStack(alignment: .leading, spacing: 16) {
                HStack {
                    VStack(alignment: .leading, spacing: 4) {
                        Text("MLC MODEL").eyebrow()
                        Text("Qwen3 0.6B · 4-bit")
                            .font(.system(size: 28, weight: .bold, design: .rounded))
                            .tracking(-0.8)
                    }
                    Spacer()
                    Text("METAL")
                        .font(.system(size: 11, weight: .bold, design: .rounded))
                        .tracking(0.7)
                        .padding(.horizontal, 10)
                        .padding(.vertical, 7)
                        .background(BrandPalette.purple.opacity(0.15))
                        .foregroundStyle(BrandPalette.purple)
                        .clipShape(Capsule())
                }
                stateView
                Text("Pinned MLC LLM source and exact model revision. This path is intended for iPhones and iPads where the Apple GPU is the primary accelerator.")
                    .foregroundStyle(.secondary)
            }
        }
    }

    @ViewBuilder
    private var stateView: some View {
        switch modelStore.state {
        case .missing:
            Button("Download MLC model") {
                Task { await inference.downloadAndLoadMLC() }
            }
            .buttonStyle(PrimaryButtonStyle(color: BrandPalette.purple))
        case .downloading(let progress):
            ProgressView(value: progress)
                .tint(BrandPalette.purple)
            Text("Downloading \(Int(progress * 100))%")
                .foregroundStyle(.secondary)
        case .verifying:
            ProgressView("Verifying model files…")
        case .ready:
            if inference.activeEngineID == "mlc-metal", inference.modelLoaded {
                Label("Loaded with MLC Metal", systemImage: "checkmark.circle.fill")
                    .foregroundStyle(BrandPalette.green)
            } else {
                Button("Load MLC model") {
                    Task { await inference.loadInstalledMLCModel() }
                }
                .buttonStyle(PrimaryButtonStyle(color: BrandPalette.purple))
            }
        case .failed(let reason):
            Label(reason, systemImage: "xmark.circle.fill")
                .foregroundStyle(BrandPalette.red)
            Button("Retry MLC download") {
                Task { await inference.downloadAndLoadMLC() }
            }
            .buttonStyle(PrimaryButtonStyle(color: BrandPalette.purple))
        }
    }
}

private struct AddNodeCard: View {
    @ObservedObject var agent: NodeAgent

    var body: some View {
        ActivityCard {
            VStack(alignment: .leading, spacing: 14) {
                Text("ADD TO A MAIN").eyebrow()
                Text("Run this on the main node")
                    .font(.system(size: 22, weight: .bold, design: .rounded))
                HStack {
                    Text("letsinfer node add")
                        .font(.system(.body, design: .monospaced, weight: .semibold))
                    Spacer()
                    Button {
                        UIPasteboard.general.string = "letsinfer node add"
                    } label: {
                        Image(systemName: "doc.on.doc")
                    }
                    .buttonStyle(.plain)
                }
                .padding(16)
                .background(BrandPalette.surface)
                .clipShape(RoundedRectangle(cornerRadius: 15, style: .continuous))
                Text("Select \(agent.displayName), then accept the request here. The node uses the current code-less, certificate-pinned LAN flow.")
                    .foregroundStyle(.secondary)
            }
        }
    }
}

private struct EngineEndpointCard: View {
    @ObservedObject var agent: NodeAgent

    var body: some View {
        ActivityCard {
            VStack(alignment: .leading, spacing: 14) {
                Text("ENGINE API").eyebrow()
                Text("OpenAI-compatible while online")
                    .font(.system(size: 22, weight: .bold, design: .rounded))
                IdentityRow(label: "Port", value: String(NodeProtocol.enginePort))
                if let key = agent.engineAccessKey {
                    HStack {
                        Text(key)
                            .font(.system(size: 11, design: .monospaced))
                            .lineLimit(1)
                            .truncationMode(.middle)
                        Spacer()
                        Button {
                            UIPasteboard.general.string = key
                        } label: {
                            Image(systemName: "doc.on.doc")
                        }
                        .buttonStyle(.plain)
                    }
                    .padding(16)
                    .background(BrandPalette.surface)
                    .clipShape(RoundedRectangle(cornerRadius: 15, style: .continuous))
                }
                Text("HTTPS with a pinned node certificate. Health is public; model discovery and chat completions require this bearer key.")
                    .foregroundStyle(.secondary)
            }
        }
    }
}

private struct KioskCard: View {
    @State private var enabled = UIAccessibility.isGuidedAccessEnabled
    @State private var requesting = false
    @State private var resultMessage: String?

    var body: some View {
        ActivityCard {
            VStack(alignment: .leading, spacing: 14) {
                HStack(alignment: .top, spacing: 14) {
                    Image(systemName: enabled ? "lock.fill" : "lock.open")
                        .font(.system(size: 22, weight: .semibold))
                        .foregroundStyle(enabled ? BrandPalette.green : BrandPalette.orange)
                    VStack(alignment: .leading, spacing: 5) {
                        Text(enabled ? "Kiosk active" : "Enable kiosk mode")
                            .font(.system(size: 18, weight: .bold, design: .rounded))
                        Text("Guided Access works on ordinary devices. Autonomous Single App Mode requires a supervised device and an MDM allowlist.")
                            .foregroundStyle(.secondary)
                    }
                }
                Button(requesting ? "Requesting…" : (enabled ? "Exit autonomous kiosk" : "Enter autonomous kiosk")) {
                    requesting = true
                    UIAccessibility.requestGuidedAccessSession(enabled: !enabled) { success in
                        Task { @MainActor in
                            requesting = false
                            enabled = UIAccessibility.isGuidedAccessEnabled
                            resultMessage = success
                                ? nil
                                : "Autonomous mode was not allowed. Use the side-button Guided Access shortcut or configure this app through MDM."
                        }
                    }
                }
                .disabled(requesting)
                .buttonStyle(SecondaryButtonStyle())
                if let resultMessage {
                    Text(resultMessage)
                        .font(.footnote)
                        .foregroundStyle(BrandPalette.orange)
                }
            }
        }
        .onReceive(NotificationCenter.default.publisher(for: UIAccessibility.guidedAccessStatusDidChangeNotification)) { _ in
            enabled = UIAccessibility.isGuidedAccessEnabled
        }
    }
}

private struct EventLogCard: View {
    let events: [String]

    var body: some View {
        ActivityCard {
            VStack(alignment: .leading, spacing: 10) {
                Text("ACTIVITY").eyebrow()
                if events.isEmpty {
                    Text("No activity yet").foregroundStyle(.secondary)
                } else {
                    ForEach(events.reversed(), id: \.self) { event in
                        Text(event)
                            .font(.system(size: 12, design: .monospaced))
                            .foregroundStyle(.secondary)
                    }
                }
            }
        }
    }
}

private struct IdentityRow: View {
    let label: String
    let value: String

    var body: some View {
        HStack(alignment: .firstTextBaseline) {
            Text(label).foregroundStyle(.secondary)
            Spacer()
            Text(value)
                .font(.system(size: 11, design: .monospaced))
                .lineLimit(1)
                .truncationMode(.middle)
                .textSelection(.enabled)
        }
    }
}

private struct PrimaryButtonStyle: ButtonStyle {
    let color: Color

    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .font(.system(size: 16, weight: .bold, design: .rounded))
            .padding(.horizontal, 18)
            .frame(minHeight: 50)
            .frame(maxWidth: .infinity)
            .background(color.opacity(configuration.isPressed ? 0.72 : 1))
            .foregroundStyle(.white)
            .clipShape(RoundedRectangle(cornerRadius: 15, style: .continuous))
    }
}

private struct SecondaryButtonStyle: ButtonStyle {
    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .font(.system(size: 16, weight: .bold, design: .rounded))
            .padding(.horizontal, 18)
            .frame(minHeight: 50)
            .frame(maxWidth: .infinity)
            .background(BrandPalette.surface.opacity(configuration.isPressed ? 0.7 : 1))
            .clipShape(RoundedRectangle(cornerRadius: 15, style: .continuous))
    }
}

private extension Text {
    func eyebrow() -> some View {
        font(.system(size: 11, weight: .bold, design: .rounded))
            .tracking(0.9)
            .foregroundStyle(.secondary)
    }
}

private extension NodeAgent.State {
    var presentation: (label: String, title: String, color: Color) {
        switch self {
        case .stopped:
            return ("Stopped", "Node is off", .secondary)
        case .starting:
            return ("Starting", "Starting secure services", BrandPalette.yellow)
        case .discoverable:
            return ("Discoverable", "Ready to join a main", BrandPalette.blue)
        case .joining(let main):
            return ("Joining", "Joining \(main)", BrandPalette.yellow)
        case .child(let main):
            return ("Online", "Child of \(main)", BrandPalette.green)
        case .offline:
            return ("Offline", "App is suspended", BrandPalette.orange)
        case .failed(let message):
            return ("Error", message, BrandPalette.red)
        }
    }
}
