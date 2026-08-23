import Foundation

protocol SSHTransport: Sendable {
    func run(_ command: String, on site: SavedSite) async throws -> String
}

enum SSHTransportError: LocalizedError, Equatable {
    case keyUnavailable
    case launchFailed(String)
    case timedOut
    case commandFailed(String)

    var errorDescription: String? {
        switch self {
        case .keyUnavailable:
            "The selected SSH private key is no longer available."
        case .launchFailed(let message):
            "SSH could not start: \(message)"
        case .timedOut:
            "The SSH connection timed out."
        case .commandFailed(let message):
            message.isEmpty ? "SSH could not connect to this node." : message
        }
    }
}
