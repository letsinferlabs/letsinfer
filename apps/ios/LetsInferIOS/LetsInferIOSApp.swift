import SwiftUI

@main
struct LetsInferIOSApp: App {
    @StateObject private var agent = NodeAgent()
    @Environment(\.scenePhase) private var scenePhase

    var body: some Scene {
        WindowGroup {
            ContentView(agent: agent)
                .onAppear { agent.start() }
        }
        .onChange(of: scenePhase) { _, phase in
            agent.sceneChanged(active: phase == .active)
        }
    }
}
