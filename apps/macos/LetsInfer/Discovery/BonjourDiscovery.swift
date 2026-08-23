import Foundation

struct DiscoveredSite: Identifiable, Equatable, Sendable {
    let id: String
    let name: String
    let host: String?
    let controlPort: Int?
    let siteID: String?
    let coordinatorID: String?
    let certificateSHA256: String?
    let publicKeySHA256: String?
    let inferenceScheme: String
    let inferencePort: Int
    let directConnectX: Bool
    let adoptable: Bool

    var displayName: String {
        name.replacingOccurrences(of: "Let's Infer — ", with: "")
    }

    var inferenceEndpoint: String? {
        guard let host else { return nil }
        return "\(inferenceScheme)://\(host):\(inferencePort)/v1"
    }
}

@MainActor
final class BonjourDiscovery: NSObject, ObservableObject {
    private static let siteControlProtocol = "letsinfer-node-control-v1"
    @Published private(set) var services: [DiscoveredSite] = []
    @Published private(set) var isSearching = false
    @Published private(set) var errorMessage: String?

    private let browser = NetServiceBrowser()
    private var records: [String: NetService] = [:]

    override init() {
        super.init()
        browser.includesPeerToPeer = true
        browser.delegate = self
    }

    func start() {
        guard !isSearching else { return }
        errorMessage = nil
        isSearching = true
        browser.searchForServices(ofType: "_letsinfer._tcp.", inDomain: "local.")
    }

    func stop() {
        browser.stop()
        records.values.forEach {
            $0.stopMonitoring()
            $0.stop()
        }
        records.removeAll()
        services.removeAll()
        isSearching = false
    }

    func refresh() {
        stop()
        start()
    }

    private func key(for service: NetService) -> String {
        "\(service.name)|\(service.type)|\(service.domain)"
    }

    private func textFields(_ service: NetService) -> [String: String] {
        guard let data = service.txtRecordData() else { return [:] }
        return NetService.dictionary(fromTXTRecord: data).reduce(into: [:]) { result, item in
            guard let value = String(data: item.value, encoding: .utf8) else { return }
            result[item.key] = value
        }
    }

    private static func lowercaseHex(_ value: String?, count: Int) -> String? {
        guard let value, value.utf8.count == count,
              value.utf8.allSatisfy({ byte in
                  (48...57).contains(byte) || (97...102).contains(byte)
              }) else { return nil }
        return value
    }

    static func validatedSite(
        fallbackID: String,
        name: String,
        host: String?,
        port: Int,
        text: [String: String]
    ) -> DiscoveredSite? {
        guard text["protocol"] == "1",
              text["control"] == Self.siteControlProtocol,
              text["role"] == "main",
              text["inference"] == "http",
              text["inference_port"] == "8000" else { return nil }
        guard let siteID = lowercaseHex(text["node"], count: 32),
              let memberID = lowercaseHex(text["machine"], count: 32),
              let certificate = lowercaseHex(text["tls"], count: 64),
              let publicKey = lowercaseHex(text["key"], count: 64),
              ["configured", "adoptable"].contains(text["state"] ?? "") else {
            return nil
        }
        guard text["direct"] == nil || text["direct"] == "connectx" else { return nil }
        let normalizedHost = host?.trimmingCharacters(
            in: CharacterSet(charactersIn: ".")
        )
        return DiscoveredSite(
            id: siteID.isEmpty ? fallbackID : siteID,
            name: name,
            host: normalizedHost?.isEmpty == false ? normalizedHost : nil,
            controlPort: port > 0 && port <= 65_535 ? port : nil,
            siteID: siteID,
            coordinatorID: memberID,
            certificateSHA256: certificate,
            publicKeySHA256: publicKey,
            inferenceScheme: "http",
            inferencePort: 8_000,
            directConnectX: text["direct"] == "connectx",
            adoptable: text["state"] == "adoptable"
        )
    }

    private func rebuildSites() {
        var candidates: [DiscoveredSite] = []
        for (key, service) in records {
            let text = textFields(service)
            guard let candidate = Self.validatedSite(
                fallbackID: key,
                name: service.name,
                host: service.hostName,
                port: service.port,
                text: text
            ) else { continue }
            candidates.append(candidate)
        }
        var unique: [String: DiscoveredSite] = [:]
        for candidate in candidates.sorted(by: { $0.name < $1.name }) {
            unique[candidate.id] = candidate
        }
        services = unique.values.sorted {
            $0.displayName.localizedCaseInsensitiveCompare($1.displayName) == .orderedAscending
        }
    }
}

extension BonjourDiscovery: @preconcurrency NetServiceBrowserDelegate {
    func netServiceBrowser(
        _ browser: NetServiceBrowser,
        didFind service: NetService,
        moreComing: Bool
    ) {
        records[key(for: service)] = service
        service.delegate = self
        service.startMonitoring()
        rebuildSites()
        service.resolve(withTimeout: 5)
    }

    func netServiceBrowser(
        _ browser: NetServiceBrowser,
        didRemove service: NetService,
        moreComing: Bool
    ) {
        if let removed = records.removeValue(forKey: key(for: service)) {
            removed.stopMonitoring()
            removed.stop()
        }
        rebuildSites()
    }

    func netServiceBrowser(
        _ browser: NetServiceBrowser,
        didNotSearch errorDict: [String: NSNumber]
    ) {
        isSearching = false
        errorMessage = "Nearby Let's Infer nodes could not be discovered."
    }
}

extension BonjourDiscovery: @preconcurrency NetServiceDelegate {
    func netServiceDidResolveAddress(_ sender: NetService) {
        rebuildSites()
    }

    func netService(_ sender: NetService, didNotResolve errorDict: [String: NSNumber]) {
        rebuildSites()
    }

    func netService(_ sender: NetService, didUpdateTXTRecord data: Data) {
        rebuildSites()
    }
}
