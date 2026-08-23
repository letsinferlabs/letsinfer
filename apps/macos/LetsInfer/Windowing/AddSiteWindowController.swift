import AppKit
import SwiftUI

@MainActor
final class AddSiteWindowController: NSObject, ObservableObject, NSWindowDelegate {
    private var window: NSWindow?

    func show(store: SiteStore) {
        if let window {
            NSApplication.shared.activate(ignoringOtherApps: true)
            window.makeKeyAndOrderFront(nil)
            return
        }

        let content = AddSiteView { [weak self] in
            self?.window?.close()
        }
        .environmentObject(store)

        let window = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 650, height: 500),
            styleMask: [.titled, .closable],
            backing: .buffered,
            defer: false
        )
        window.title = "Add Node"
        window.contentViewController = NSHostingController(rootView: content)
        window.isReleasedWhenClosed = false
        window.delegate = self
        window.center()

        self.window = window
        NSApplication.shared.activate(ignoringOtherApps: true)
        window.makeKeyAndOrderFront(nil)
    }

    func windowWillClose(_ notification: Notification) {
        window = nil
    }
}
