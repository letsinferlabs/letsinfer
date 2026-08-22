import Foundation

struct MetricHistoryPoint: Identifiable, Equatable, Sendable {
    let id = UUID()
    let timestamp: Date
    let gpuUtilization: Double?
    let memoryUtilization: Double?
    let cpuUtilization: Double?
    let diskUtilization: Double?
    let temperature: Double?
    let generationTokensPerSecond: Double?
}

struct ControllerOneTimeSecret: Identifiable, Equatable, Sendable {
    let id = UUID()
    let keyID: String
    let keyName: String
    let token: String
}

@MainActor
final class SiteMonitoringController: ObservableObject {
    static let presentationHistorySeconds: TimeInterval = 30 * 60
    static let maximumPresentationPoints = 1_801

    @Published private(set) var snapshots: [SavedSite.ID: SiteSnapshot] = [:]
    @Published private(set) var errors: [SavedSite.ID: String] = [:]
    @Published private(set) var history: [SavedSite.ID: [MetricHistoryPoint]] = [:]
    @Published private(set) var siteViews: [SavedSite.ID: ControllerSiteEnvelope] = [:]
    @Published private(set) var telemetryViews: [SavedSite.ID: ControllerTelemetryEnvelope] = [:]
    @Published private(set) var controllerErrors: [SavedSite.ID: String] = [:]
    @Published private(set) var siteActions: [String: ControllerActionRecord] = [:]
    @Published private(set) var siteActionResults: [String: ControllerActionResult] = [:]
    @Published private(set) var apiKeys: [SavedSite.ID: [ControllerAPIKeyRecord]] = [:]
    @Published private(set) var oneTimeSecrets: [SavedSite.ID: ControllerOneTimeSecret] = [:]

    private let dataSource: any SiteDataSource
    private let controllerAPI: any ControllerSiteAPI
    private let pollInterval: Duration
    private var monitoringTasks: [SavedSite.ID: Task<Void, Never>] = [:]
    private var monitoredConfiguration: String?

    init(
        dataSource: any SiteDataSource = RoutingSiteDataSource(),
        controllerAPI: any ControllerSiteAPI = ControllerAPIClient(),
        pollInterval: Duration = .seconds(2)
    ) {
        self.dataSource = dataSource
        self.controllerAPI = controllerAPI
        self.pollInterval = pollInterval
    }

    /// Starts an app-owned polling task. The task deliberately outlives the
    /// transient SwiftUI view that asked monitoring to start.
    func start(sites: [SavedSite]) {
        let configuration = sites
            .map {
                "\($0.id.uuidString):\($0.host):\($0.port):"
                    + "\($0.controlPort ?? 0):\($0.resolvedDataSource)"
            }
            .joined(separator: "|")
        guard configuration != monitoredConfiguration || monitoringTasks.isEmpty else { return }

        monitoringTasks.values.forEach { $0.cancel() }
        monitoringTasks.removeAll()
        monitoredConfiguration = configuration
        pruneRemovedSites(sites)
        guard !sites.isEmpty else { return }

        for site in sites {
            monitoringTasks[site.id] = Task { [weak self] in
                await self?.monitor(site)
            }
        }
    }

    private func monitor(_ site: SavedSite) async {
        await withTaskGroup(of: Void.self) { group in
            group.addTask { [weak self] in
                await self?.monitorMember(site)
            }
            if site.installationID != nil, site.controlPort != nil {
                group.addTask { [weak self] in
                    await self?.monitorController(site)
                }
            }
            await group.waitForAll()
        }
    }

    private func monitorMember(_ site: SavedSite) async {
        let since = Date().addingTimeInterval(-Self.presentationHistorySeconds)
        if let historical = try? await dataSource.fetchHistory(for: site, since: since) {
            applyHistory(historical, for: site.id)
        }

        while !Task.isCancelled {
            if let updates = await dataSource.updates(for: site) {
                do {
                    for try await snapshot in updates {
                        guard !Task.isCancelled else { return }
                        apply(snapshot)
                    }
                } catch {
                    errors[site.id] = error.localizedDescription
                }
                guard !Task.isCancelled else { return }
                // Keep the dashboard useful through SSH while allowing a repaired
                // Watchdog route or newly paired identity to be retried later.
                await poll(site, maximumAttempts: 15)
            } else {
                await poll(site, maximumAttempts: nil)
                return
            }
        }
    }

    private func monitorController(_ site: SavedSite) async {
        while !Task.isCancelled {
            do {
                async let siteView = controllerAPI.site(for: site)
                async let telemetryView = controllerAPI.telemetry(for: site)
                let currentSite = try await siteView
                applySiteView(currentSite, for: site)
                applyTelemetryView(try await telemetryView, for: site.id)
                controllerErrors[site.id] = nil
            } catch {
                controllerErrors[site.id] = error.localizedDescription
            }
            do {
                try await Task.sleep(for: pollInterval)
            } catch {
                return
            }
        }
    }

    private func poll(_ site: SavedSite, maximumAttempts: Int?) async {
        var attempts = 0
        while !Task.isCancelled && (maximumAttempts == nil || attempts < maximumAttempts!) {
            do {
                apply(try await dataSource.fetchSnapshot(for: site))
            } catch {
                errors[site.id] = error.localizedDescription
            }
            if site.installationID != nil, site.controlPort != nil {
                do {
                    async let siteView = controllerAPI.site(for: site)
                    async let telemetryView = controllerAPI.telemetry(for: site)
                    let currentSite = try await siteView
                    applySiteView(currentSite, for: site)
                    applyTelemetryView(try await telemetryView, for: site.id)
                    controllerErrors[site.id] = nil
                } catch {
                    controllerErrors[site.id] = error.localizedDescription
                }
            }
            attempts += 1
            do {
                try await Task.sleep(for: pollInterval)
            } catch {
                return
            }
        }
    }

    func refresh(sites: [SavedSite]) async {
        for site in sites {
            guard !Task.isCancelled else { return }
            do {
                apply(try await dataSource.fetchSnapshot(for: site))
            } catch {
                errors[site.id] = error.localizedDescription
            }
        }
    }

    func runtimeAction(
        _ action: ControllerSiteAction,
        model: String,
        placementID: String,
        site: SavedSite
    ) async {
        await siteAction(
            action,
            model: model,
            engine: nil,
            resourceKey: "placement:\(placementID)",
            site: site
        )
    }

    func installRuntime(model: String, engine: String?, site: SavedSite) async {
        await siteAction(
            .install,
            model: model,
            engine: engine,
            resourceKey: "install:\(model)",
            site: site
        )
    }

    func planPlacement(model: String, engine: String?, site: SavedSite) async {
        await siteAction(
            .topologyPlan,
            model: model,
            engine: engine,
            resourceKey: "topology:\(model)",
            site: site
        )
    }

    func setPublicExposure(enabled: Bool, site: SavedSite) async {
        await siteAction(
            enabled ? .expose : .unexpose,
            model: nil,
            engine: nil,
            resourceKey: "exposure",
            site: site
        )
    }

    private func siteAction(
        _ action: ControllerSiteAction,
        model: String?,
        engine: String?,
        resourceKey: String,
        site: SavedSite
    ) async {
        let key = siteActionKey(site: site.id, resource: resourceKey)
        guard siteActions[key] == nil else { return }
        do {
            let accepted = try await controllerAPI.siteAction(
                action, model: model, engine: engine, for: site
            )
            siteActions[key] = accepted.action
            siteActionResults.removeValue(forKey: key)
            controllerErrors[site.id] = nil
            try await monitorSiteAction(
                operationID: accepted.action.operationID,
                action: action,
                key: key,
                site: site
            )
            applySiteView(try await controllerAPI.site(for: site), for: site)
        } catch {
            controllerErrors[site.id] = error.localizedDescription
            siteActions.removeValue(forKey: key)
        }
    }

    private func monitorSiteAction(
        operationID: String,
        action: ControllerSiteAction,
        key: String,
        site: SavedSite
    ) async throws {
        let clock = ContinuousClock()
        let timeout: Duration = action == .install ? .seconds(12 * 60 * 60) : .seconds(900)
        let deadline = clock.now.advanced(by: timeout)
        while clock.now < deadline {
            try await Task.sleep(for: .seconds(1))
            let envelope = try await controllerAPI.siteActionStatus(
                operationID: operationID,
                for: site
            )
            siteActions[key] = envelope.action
            switch envelope.action.state {
            case "succeeded":
                if let result = envelope.action.result {
                    siteActionResults[key] = result
                }
                siteActions.removeValue(forKey: key)
                return
            case "failed":
                throw ControllerAPIError.rejected(
                    "Site action failed (\(envelope.action.error ?? "unknown"))."
                )
            case "accepted":
                continue
            default:
                throw ControllerAPIError.invalidResponse
            }
        }
        throw ControllerAPIError.rejected("Site action timed out.")
    }

    func runtimeActionPending(siteID: SavedSite.ID, placementID: String) -> Bool {
        siteActionPending(siteID: siteID, resource: "placement:\(placementID)")
    }

    func siteActionPending(siteID: SavedSite.ID, resource: String) -> Bool {
        siteActions[siteActionKey(site: siteID, resource: resource)] != nil
    }

    func siteActionResult(
        siteID: SavedSite.ID, resource: String
    ) -> ControllerActionResult? {
        siteActionResults[siteActionKey(site: siteID, resource: resource)]
    }

    private func siteActionKey(site: SavedSite.ID, resource: String) -> String {
        "\(site.uuidString):\(resource)"
    }

    private func reconcileSiteActions(
        for savedSite: SavedSite,
        site: ControllerSiteEnvelope
    ) {
        for placement in site.site.placements {
            let key = siteActionKey(
                site: savedSite.id,
                resource: "placement:\(placement.placementID)"
            )
            guard let pending = siteActions[key] else { continue }
            if (pending.action == "stop" && placement.state == "stopped")
                || (pending.action == "restart" && placement.state == "running") {
                siteActions.removeValue(forKey: key)
            }
        }
    }

    func refreshAPIKeys(site: SavedSite) async {
        do {
            let envelope = try await controllerAPI.apiKeys(for: site)
            apiKeys[site.id] = envelope.result.keys
            controllerErrors[site.id] = nil
        } catch {
            controllerErrors[site.id] = error.localizedDescription
        }
    }

    func createAPIKey(
        name: String, policy: ControllerAPIKeyPolicy, site: SavedSite
    ) async {
        do {
            let envelope = try await controllerAPI.createAPIKey(
                name: name, policy: policy, for: site
            )
            oneTimeSecrets[site.id] = ControllerOneTimeSecret(
                keyID: envelope.result.key.keyID,
                keyName: envelope.result.key.name,
                token: envelope.result.token
            )
            await refreshAPIKeys(site: site)
        } catch {
            controllerErrors[site.id] = error.localizedDescription
        }
    }

    func rotateAPIKey(_ key: String, site: SavedSite) async {
        do {
            let envelope = try await controllerAPI.rotateAPIKey(
                key: key, for: site
            )
            oneTimeSecrets[site.id] = ControllerOneTimeSecret(
                keyID: envelope.result.key.keyID,
                keyName: envelope.result.key.name,
                token: envelope.result.token
            )
            await refreshAPIKeys(site: site)
        } catch {
            controllerErrors[site.id] = error.localizedDescription
        }
    }

    func revokeAPIKey(_ key: String, site: SavedSite) async {
        do {
            _ = try await controllerAPI.revokeAPIKey(key: key, for: site)
            await refreshAPIKeys(site: site)
        } catch {
            controllerErrors[site.id] = error.localizedDescription
        }
    }

    func updateAPIKeyPolicy(
        _ key: String, policy: ControllerAPIKeyPolicy, site: SavedSite
    ) async {
        do {
            _ = try await controllerAPI.updateAPIKeyPolicy(
                key: key, policy: policy, for: site
            )
            await refreshAPIKeys(site: site)
        } catch {
            controllerErrors[site.id] = error.localizedDescription
        }
    }

    func removeMember(_ memberID: String, site: SavedSite) async {
        do {
            _ = try await controllerAPI.removeMember(
                memberID: memberID, for: site
            )
            applySiteView(try await controllerAPI.site(for: site), for: site)
            controllerErrors[site.id] = nil
        } catch {
            controllerErrors[site.id] = error.localizedDescription
        }
    }

    func drainMember(_ memberID: String, site: SavedSite) async {
        do {
            _ = try await controllerAPI.drainMember(
                memberID: memberID, for: site
            )
            applySiteView(try await controllerAPI.site(for: site), for: site)
            controllerErrors[site.id] = nil
        } catch {
            controllerErrors[site.id] = error.localizedDescription
        }
    }

    func resumeMember(_ memberID: String, site: SavedSite) async {
        do {
            _ = try await controllerAPI.resumeMember(
                memberID: memberID, for: site
            )
            applySiteView(try await controllerAPI.site(for: site), for: site)
            controllerErrors[site.id] = nil
        } catch {
            controllerErrors[site.id] = error.localizedDescription
        }
    }

    func clearOneTimeSecret(siteID: SavedSite.ID) {
        oneTimeSecrets.removeValue(forKey: siteID)
    }

    private func apply(_ snapshot: SiteSnapshot) {
        var enriched = coordinatorFacts(for: snapshot.siteID).map {
            snapshot.enriched(with: $0)
        } ?? snapshot
        if let placement = currentPlacement(for: snapshot.siteID) {
            enriched = enriched.enriched(with: placement)
        }
        if let telemetry = telemetryViews[snapshot.siteID]?.telemetry {
            enriched = enriched.enrichedIfFresh(with: telemetry)
        }
        if snapshots[enriched.siteID].map({ $0.sampledAt <= enriched.sampledAt }) ?? true {
            snapshots[enriched.siteID] = enriched
        }
        errors[enriched.siteID] = nil
        record(enriched)
    }

    private func applySiteView(
        _ envelope: ControllerSiteEnvelope,
        for savedSite: SavedSite
    ) {
        siteViews[savedSite.id] = envelope
        reconcileSiteActions(for: savedSite, site: envelope)
        guard let facts = coordinatorFacts(in: envelope) else { return }
        let enriched = snapshots[savedSite.id].map { $0.enriched(with: facts) }
            ?? SiteSnapshot.controllerFacts(siteID: savedSite.id, facts: facts)
        guard let enriched else { return }
        let resolved: SiteSnapshot
        if let placement = currentPlacement(in: envelope) {
            resolved = enriched.enriched(with: placement)
        } else {
            resolved = enriched
        }
        snapshots[savedSite.id] = resolved
        record(resolved)
    }

    private func applyTelemetryView(
        _ envelope: ControllerTelemetryEnvelope,
        for siteID: SavedSite.ID
    ) {
        telemetryViews[siteID] = envelope
        guard let snapshot = snapshots[siteID] else { return }
        let enriched = snapshot.enrichedIfFresh(with: envelope.telemetry)
        snapshots[siteID] = enriched
        record(enriched)
    }

    private func coordinatorFacts(for siteID: SavedSite.ID) -> SiteMemberFacts? {
        siteViews[siteID].flatMap(coordinatorFacts(in:))
    }

    private func currentPlacement(for siteID: SavedSite.ID) -> SitePlacementRecord? {
        siteViews[siteID].flatMap(currentPlacement(in:))
    }

    private func currentPlacement(
        in envelope: ControllerSiteEnvelope
    ) -> SitePlacementRecord? {
        let current = envelope.site.currentPlacements
        return current.first { $0.state == "running" }
            ?? current.first { $0.state == "starting" }
            ?? current.first { $0.state == "draining" }
            ?? current.first
    }

    private func coordinatorFacts(
        in envelope: ControllerSiteEnvelope
    ) -> SiteMemberFacts? {
        let coordinatorID = envelope.site.identity.coordinatorID
        guard let member = envelope.site.members.first(where: {
            $0.memberID == coordinatorID
        }), let facts = member.facts, facts.memberID == member.memberID else {
            return nil
        }
        return facts
    }

    private func record(_ snapshot: SiteSnapshot) {
        let point = historyPoint(from: snapshot)
        var points = history[snapshot.siteID, default: []]
        upsert(point, into: &points)
        Self.trimPresentationHistory(
            &points,
            newest: max(snapshot.sampledAt, points.last?.timestamp ?? snapshot.sampledAt)
        )
        history[snapshot.siteID] = points
    }

    private func applyHistory(_ snapshots: [SiteSnapshot], for siteID: SavedSite.ID) {
        guard !snapshots.isEmpty else { return }
        let newest = snapshots.map(\.sampledAt).max() ?? Date()
        let cutoff = newest.addingTimeInterval(-Self.presentationHistorySeconds)
        var pointsByMillisecond: [Int64: MetricHistoryPoint] = [:]
        for point in history[siteID, default: []] where point.timestamp >= cutoff {
            pointsByMillisecond[millisecondKey(point.timestamp)] = point
        }
        for snapshot in snapshots where snapshot.sampledAt >= cutoff {
            let point = historyPoint(from: snapshot)
            pointsByMillisecond[millisecondKey(point.timestamp)] = point
        }
        var points = pointsByMillisecond.values.sorted { $0.timestamp < $1.timestamp }
        Self.trimPresentationHistory(&points, newest: newest)
        history[siteID] = points
    }

    private func upsert(
        _ point: MetricHistoryPoint,
        into points: inout [MetricHistoryPoint]
    ) {
        let key = millisecondKey(point.timestamp)
        if let last = points.last {
            let lastKey = millisecondKey(last.timestamp)
            if key > lastKey {
                points.append(point)
                return
            }
            if key == lastKey {
                points[points.count - 1] = point
                return
            }
        }

        let index = points.partitioningIndex {
            millisecondKey($0.timestamp) >= key
        }
        if index < points.count, millisecondKey(points[index].timestamp) == key {
            points[index] = point
        } else {
            points.insert(point, at: index)
        }
    }

    static func trimPresentationHistory(
        _ points: inout [MetricHistoryPoint],
        newest: Date
    ) {
        let cutoff = newest.addingTimeInterval(-Self.presentationHistorySeconds)
        let firstVisible = points.partitioningIndex { $0.timestamp >= cutoff }
        if firstVisible > 0 {
            points.removeFirst(firstVisible)
        }
        if points.count > Self.maximumPresentationPoints {
            points.removeFirst(points.count - Self.maximumPresentationPoints)
        }
    }

    private func historyPoint(from snapshot: SiteSnapshot) -> MetricHistoryPoint {
        MetricHistoryPoint(
            timestamp: snapshot.sampledAt,
            gpuUtilization: snapshot.metrics.gpu?.utilizationPercent,
            memoryUtilization: snapshot.metrics.memory?.utilizationPercent,
            cpuUtilization: snapshot.metrics.cpu?.utilizationPercent,
            diskUtilization: snapshot.metrics.storage?.utilizationPercent,
            temperature: snapshot.metrics.gpu?.temperatureCelsius,
            generationTokensPerSecond: snapshot.metrics.llm.first?.generationTokensPerSecond
        )
    }

    private func millisecondKey(_ date: Date) -> Int64 {
        Int64((date.timeIntervalSince1970 * 1_000).rounded())
    }

    private func pruneRemovedSites(_ sites: [SavedSite]) {
        let ids = Set(sites.map(\.id))
        snapshots = snapshots.filter { ids.contains($0.key) }
        errors = errors.filter { ids.contains($0.key) }
        history = history.filter { ids.contains($0.key) }
        siteViews = siteViews.filter { ids.contains($0.key) }
        telemetryViews = telemetryViews.filter { ids.contains($0.key) }
        controllerErrors = controllerErrors.filter { ids.contains($0.key) }
        siteActions = siteActions.filter { value in
            guard let separator = value.key.firstIndex(of: ":") else { return false }
            return UUID(uuidString: String(value.key[..<separator])).map(ids.contains) ?? false
        }
        siteActionResults = siteActionResults.filter { value in
            guard let separator = value.key.firstIndex(of: ":") else { return false }
            return UUID(uuidString: String(value.key[..<separator])).map(ids.contains) ?? false
        }
        apiKeys = apiKeys.filter { ids.contains($0.key) }
        oneTimeSecrets = oneTimeSecrets.filter { ids.contains($0.key) }
        monitoringTasks = monitoringTasks.filter { ids.contains($0.key) }
    }
}

private extension Array {
    func partitioningIndex(where predicate: (Element) -> Bool) -> Int {
        var lower = startIndex
        var upper = endIndex
        while lower < upper {
            let middle = index(lower, offsetBy: distance(from: lower, to: upper) / 2)
            if predicate(self[middle]) {
                upper = middle
            } else {
                lower = index(after: middle)
            }
        }
        return distance(from: startIndex, to: lower)
    }
}
