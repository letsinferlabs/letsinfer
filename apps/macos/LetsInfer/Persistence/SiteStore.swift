import Foundation

@MainActor
final class SiteStore: ObservableObject {
    enum StoreError: LocalizedError, Equatable {
        case invalidName
        case invalidHost
        case invalidPort
        case invalidUsername
        case privateKeyRequired
        case duplicate
        case saveFailed

        var errorDescription: String? {
            switch self {
            case .invalidName:
                "Enter a name for this node."
            case .invalidHost:
                "Enter a valid hostname or IP address."
            case .invalidPort:
                "Enter a port between 1 and 65535."
            case .invalidUsername:
                "Enter the SSH username."
            case .privateKeyRequired:
                "Choose a private key, or use your SSH agent or config."
            case .duplicate:
                "This node has already been added."
            case .saveFailed:
                "Let's Infer could not save its data."
            }
        }
    }

    @Published private(set) var sites: [SavedSite] = []
    @Published private(set) var loadError: String?

    private let directoryURL: URL
    private let fileURL: URL
    private let fileManager: FileManager

    convenience init() {
        let support = FileManager.default.urls(
            for: .applicationSupportDirectory,
            in: .userDomainMask
        )[0]
        self.init(directoryURL: support.appendingPathComponent("letsinfer", isDirectory: true))
    }

    init(directoryURL: URL, fileManager: FileManager = .default) {
        self.directoryURL = directoryURL
        self.fileURL = directoryURL.appendingPathComponent("sites.json")
        self.fileManager = fileManager
        load()
    }

    func add(_ site: SavedSite) throws {
        let normalized = try prepareForAdd(site)

        var updated = sites
        updated.append(normalized)
        try persist(updated)
        sites = updated
    }

    func prepareForAdd(_ site: SavedSite) throws -> SavedSite {
        let normalized = try validated(site)
        let alreadyExists = sites.contains {
            let sameEndpoint = $0.host.caseInsensitiveCompare(normalized.host) == .orderedSame
                && $0.port == normalized.port
            let incomingID = normalized.hardwareIdentity?.stableIdentifier
            let sameHardware = incomingID != nil
                && $0.hardwareIdentity?.stableIdentifier == incomingID
            let sameSite = normalized.siteID != nil && $0.siteID == normalized.siteID
            return sameEndpoint || sameHardware || sameSite
        }
        guard !alreadyExists else { throw StoreError.duplicate }
        return normalized
    }

    func remove(id: SavedSite.ID) throws {
        let updated = sites.filter { $0.id != id }
        try persist(updated)
        sites = updated
    }

    func recordHardwareIdentity(_ identity: SavedHardwareIdentity, for id: SavedSite.ID) throws {
        guard let index = sites.firstIndex(where: { $0.id == id }) else { return }
        guard sites[index].hardwareIdentity != identity else { return }

        var updated = sites
        updated[index].hardwareIdentity = identity
        try persist(updated)
        sites = updated
    }

    private func load() {
        guard fileManager.fileExists(atPath: fileURL.path) else {
            sites = []
            return
        }

        do {
            let data = try Data(contentsOf: fileURL)
            sites = try JSONDecoder.letsInfer.decode([SavedSite].self, from: data)
        } catch {
            sites = []
            loadError = "Saved node data could not be read."
        }
    }

    private func validated(_ site: SavedSite) throws -> SavedSite {
        var value = site
        value.name = site.name.trimmingCharacters(in: .whitespacesAndNewlines)
        value.host = site.host
            .trimmingCharacters(in: .whitespacesAndNewlines)
            .trimmingCharacters(in: CharacterSet(charactersIn: "."))
        value.username = site.username.trimmingCharacters(in: .whitespacesAndNewlines)

        guard !value.name.isEmpty else { throw StoreError.invalidName }
        guard Self.isValidHost(value.host) else { throw StoreError.invalidHost }
        guard (1...65_535).contains(value.port) else { throw StoreError.invalidPort }
        guard Self.isValidUsername(value.username) else { throw StoreError.invalidUsername }

        if value.authentication == .privateKey, value.privateKeyBookmark == nil {
            throw StoreError.privateKeyRequired
        }

        if value.authentication == .sshConfig {
            value.privateKeyBookmark = nil
            value.privateKeyName = nil
        }

        return value
    }

    private func persist(_ values: [SavedSite]) throws {
        do {
            try fileManager.createDirectory(
                at: directoryURL,
                withIntermediateDirectories: true
            )
            let data = try JSONEncoder.letsInfer.encode(values)
            try data.write(to: fileURL, options: [.atomic])
        } catch {
            throw StoreError.saveFailed
        }
    }

    private static func isValidHost(_ value: String) -> Bool {
        guard !value.isEmpty, value.count <= 253 else { return false }
        let allowed = CharacterSet(charactersIn: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._:")
        return value.unicodeScalars.allSatisfy(allowed.contains)
    }

    private static func isValidUsername(_ value: String) -> Bool {
        guard !value.isEmpty, value.count <= 32 else { return false }
        let allowed = CharacterSet(charactersIn: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-")
        return value.unicodeScalars.allSatisfy(allowed.contains)
    }
}

private extension JSONEncoder {
    static var letsInfer: JSONEncoder {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        encoder.dateEncodingStrategy = .millisecondsSince1970
        return encoder
    }
}

private extension JSONDecoder {
    static var letsInfer: JSONDecoder {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .millisecondsSince1970
        return decoder
    }
}
