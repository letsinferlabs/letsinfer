import AppKit
import SwiftUI

struct MenuBarContentView: View {
    private enum ExpandedMetric: Hashable {
        case gpu
        case cpu
    }

    private let dashboardWidth: CGFloat = 404

    @EnvironmentObject private var siteStore: SiteStore
    @EnvironmentObject private var monitoring: SiteMonitoringController
    @EnvironmentObject private var addSiteWindow: AddSiteWindowController
    @EnvironmentObject private var siteInfoWindow: SiteInfoWindowController
    @State private var selectedSiteID: SavedSite.ID?
    @State private var errorMessage: String?
    @State private var expandedMetrics: Set<ExpandedMetric> = []
    @State private var isHistoryExpanded = false

    var body: some View {
        Group {
            if let site = activeSite {
                dashboard(for: site)
            } else if !siteStore.sites.isEmpty {
                topologyPanel
            } else {
                welcomePanel
            }
        }
        .background {
            Rectangle()
                .fill(.regularMaterial)
                .ignoresSafeArea()
        }
        .onReceive(monitoring.$snapshots) { snapshots in
            recordHardwareIdentities(from: snapshots)
        }
    }

    private var activeSite: SavedSite? {
        guard let selectedSiteID else { return nil }
        return siteStore.sites.first { $0.id == selectedSiteID }
    }

    private var welcomePanel: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack(spacing: 10) {
                Image("MenuBarIcon")
                    .resizable()
                    .scaledToFit()
                    .frame(width: 20, height: 22)
                VStack(alignment: .leading, spacing: 1) {
                    Text("Let's Infer")
                        .font(.headline)
                    Text("Local inference operations")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                Spacer()
            }
            .padding(16)

            Divider()

            VStack(alignment: .leading, spacing: 12) {
                Text("Connect a Let's Infer host to monitor runtime health, protection, and live system telemetry.")
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)

                Button {
                    addSiteWindow.show(store: siteStore)
                } label: {
                    Label("Add Site", systemImage: "plus")
                }
                .keyboardShortcut(.defaultAction)
            }
            .padding(16)

            if let message = errorMessage ?? siteStore.loadError {
                Divider()
                errorCard(message)
                    .padding(12)
            }
        }
        .frame(width: 330)
    }

    private var topologyPanel: some View {
        VStack(spacing: 0) {
            HStack(spacing: 10) {
                Image("MenuBarIcon")
                    .resizable()
                    .scaledToFit()
                    .frame(width: 20, height: 22)
                VStack(alignment: .leading, spacing: 1) {
                    Text("Let's Infer").font(.headline)
                    Text("Your inference topology")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                Spacer()
                Button {
                    addSiteWindow.show(store: siteStore)
                } label: {
                    Image(systemName: "plus")
                }
                .buttonStyle(.borderless)
                .help("Add Site")
            }
            .padding(14)

            Divider()

            ScrollView {
                VStack(spacing: 12) {
                    ForEach(siteStore.sites) { site in
                        topologyCard(for: site)
                    }
                }
                .padding(12)
            }
            .frame(maxHeight: 520)

            Divider()
            HStack {
                Text("\(siteStore.sites.count) \(siteStore.sites.count == 1 ? "site" : "sites")")
                    .foregroundStyle(.secondary)
                Spacer()
                Button("Quit") { NSApplication.shared.terminate(nil) }
            }
            .buttonStyle(.plain)
            .font(.subheadline)
            .padding(.horizontal, 14)
            .frame(height: 40)
        }
        .frame(width: dashboardWidth)
    }

    private func topologyCard(for site: SavedSite) -> some View {
        let envelope = monitoring.siteViews[site.id]
        let document = envelope?.site
        let snapshot = monitoring.snapshots[site.id]
        let error = monitoring.errors[site.id] ?? monitoring.controllerErrors[site.id]
        let coordinator = document?.members.first {
            $0.memberID == document?.identity.coordinatorID
        }
        let members = document?.members.filter {
            $0.memberID != document?.identity.coordinatorID
        } ?? []
        let runningModels = document?.currentPlacements
            .filter { $0.state == "running" }
            .map(\.model)
            .sorted() ?? []

        return Button {
            selectedSiteID = site.id
        } label: {
            VStack(alignment: .leading, spacing: 10) {
                HStack {
                    VStack(alignment: .leading, spacing: 1) {
                        Text(document?.identity.displayName ?? site.name)
                            .font(.headline)
                        Text(document?.topology.valid == true ? "Verified topology" : "Connecting…")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                    Spacer()
                    statusBadge(snapshot: snapshot, error: error)
                    Image(systemName: "chevron.right")
                        .font(.caption.weight(.semibold))
                        .foregroundStyle(.tertiary)
                }

                SiteTopologyGraph(
                    coordinatorName: coordinator?.displayName ?? site.name,
                    coordinatorState: coordinator?.state ?? statusText(snapshot: snapshot, error: error).lowercased(),
                    members: members
                )

                HStack(spacing: 6) {
                    if runningModels.isEmpty {
                        Label("No model running", systemImage: "pause.circle")
                            .foregroundStyle(.secondary)
                    } else {
                        ForEach(runningModels.prefix(2), id: \.self) { model in
                            Label(model, systemImage: "bolt.fill")
                                .lineLimit(1)
                        }
                    }
                    Spacer()
                    Text("\((document?.members.count ?? 1)) members")
                        .foregroundStyle(.secondary)
                }
                .font(.caption)
            }
            .padding(12)
            .background(.primary.opacity(0.045), in: RoundedRectangle(cornerRadius: 14))
            .overlay {
                RoundedRectangle(cornerRadius: 14)
                    .stroke(.primary.opacity(0.08), lineWidth: 1)
            }
            .contentShape(RoundedRectangle(cornerRadius: 14))
        }
        .buttonStyle(.plain)
    }

    private func dashboard(for site: SavedSite) -> some View {
        let snapshot = monitoring.snapshots[site.id]
        let error = monitoring.errors[site.id] ?? monitoring.controllerErrors[site.id]
        let siteView = monitoring.siteViews[site.id]

        return VStack(spacing: 0) {
            dashboardHeader(site: site, snapshot: snapshot, error: error)

            if let status = snapshot?.letsinfer {
                runtimeOverview(
                    status: status,
                    metrics: snapshot?.metrics,
                    history: monitoring.history[site.id] ?? [],
                    placement: preferredPlacement(
                        siteView?.site.currentPlacements ?? [],
                        model: status.model
                    ),
                    controllerRole: siteView?.controller.role,
                    activeMemberCount: siteView?.site.activeMemberCount ?? 0,
                    savedSite: site
                )
            }

            if isHistoryExpanded {
                MetricHistoryChart(
                    points: monitoring.history[site.id] ?? [],
                    width: dashboardWidth
                )
            }

            resourceRows(snapshot: snapshot)

            telemetryStrip(snapshot: snapshot)
                .padding(.horizontal, 14)

            if let message = error ?? errorMessage ?? siteStore.loadError {
                errorCard(message)
                    .padding(.horizontal, 10)
                    .padding(.bottom, 9)
            }

            Divider()
                .padding(.horizontal, 10)

            footer(site: site)
        }
        .frame(width: dashboardWidth)
    }

    private func dashboardHeader(
        site: SavedSite,
        snapshot: SiteSnapshot?,
        error: String?
    ) -> some View {
        HStack(spacing: 9) {
            Button {
                selectedSiteID = nil
            } label: {
                Image(systemName: "chevron.left")
                    .font(.system(size: 13, weight: .semibold))
                    .frame(width: 20, height: 24)
            }
            .buttonStyle(.plain)
            .help("Back to topology")

            Image(systemName: "server.rack")
                .font(.system(size: 15, weight: .medium))
                .foregroundStyle(.secondary)
                .frame(width: 24)
                .accessibilityHidden(true)

            VStack(alignment: .leading, spacing: 2) {
                if siteStore.sites.count > 1 {
                    siteSelector(current: site)
                } else {
                    Text(site.name)
                        .font(.system(size: 15, weight: .semibold))
                }

                HStack(spacing: 5) {
                    Text(headerSubtitle(site: site, snapshot: snapshot))
                        .lineLimit(1)
                    if let snapshot {
                        Text("·")
                        Text(sourceName(snapshot.source))
                    }
                }
                .font(.caption)
                .foregroundStyle(.secondary)
            }

            Spacer(minLength: 8)

            statusBadge(snapshot: snapshot, error: error)
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 9)
        .contextMenu {
            Button(
                site.installationID == nil ? "Remove \(site.name)" : "Forget \(site.name)",
                role: .destructive
            ) {
                forget(site)
            }
        }
    }

    private func siteSelector(current site: SavedSite) -> some View {
        Menu {
            ForEach(siteStore.sites) { candidate in
                Button {
                    selectedSiteID = candidate.id
                } label: {
                    if candidate.id == site.id {
                        Label(candidate.name, systemImage: "checkmark")
                    } else {
                        Text(candidate.name)
                    }
                }
            }
        } label: {
            HStack(spacing: 4) {
                Text(site.name)
                    .font(.system(size: 15, weight: .semibold))
                Image(systemName: "chevron.down")
                    .font(.caption2)
                    .foregroundStyle(.secondary)
            }
        }
        .menuStyle(.borderlessButton)
        .fixedSize()
    }

    private func statusBadge(snapshot: SiteSnapshot?, error: String?) -> some View {
        let color = statusColor(snapshot: snapshot, error: error)
        return HStack(spacing: 5) {
            Circle()
                .fill(color)
                .frame(width: 7, height: 7)
            Text(statusText(snapshot: snapshot, error: error))
                .font(.caption.weight(.medium))
        }
        .foregroundStyle(color)
    }

    private func runtimeOverview(
        status: SiteStatus,
        metrics: MemberMetrics?,
        history: [MetricHistoryPoint],
        placement: SitePlacementRecord?,
        controllerRole: String?,
        activeMemberCount: Int,
        savedSite: SavedSite
    ) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(alignment: .top, spacing: 10) {
                VStack(alignment: .leading, spacing: 2) {
                    HStack(spacing: 7) {
                        Text("INFERENCE")
                            .font(.caption2.weight(.bold))
                            .foregroundStyle(.secondary)
                        Text(status.release)
                            .font(.caption2.monospacedDigit())
                            .foregroundStyle(.tertiary)
                            .lineLimit(1)
                    }
                    Text(status.model)
                        .font(.system(size: 16, weight: .semibold, design: .rounded))
                        .lineLimit(1)
                    Text(compactRuntimeIdentity(status))
                        .font(.caption.monospacedDigit())
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                }

                Spacer(minLength: 8)

                HStack(spacing: 8) {
                    runtimeStateBadge(status)
                    if let placement,
                       controllerRole == "operator" || controllerRole == "administrator" {
                        placementMenu(
                            placement,
                            site: savedSite,
                            role: controllerRole,
                            tripLatched: status.tripLatched,
                            allowsPlacementPlanning: activeMemberCount > 1
                        )
                    }
                }
            }

            HStack(spacing: 0) {
                runtimeSummaryMetric(
                    "CONTEXT",
                    value: compactTokens(status.maxContextTokens),
                    systemImage: "text.line.first.and.arrowtriangle.forward"
                )
                .frame(width: 78, alignment: .leading)
                runtimeSummaryDivider
                runtimeSummaryMetric(
                    "LIMITS",
                    value: "\(status.maxActiveRequests) / \(status.maxConnections)",
                    systemImage: "person.2.fill"
                )
                .frame(width: 78, alignment: .leading)

                Spacer(minLength: 12)

                MetricHistoryChart(
                    points: history,
                    width: 174,
                    compact: true
                )
                .contentShape(Rectangle())
                .modifier(ExpandableHoverHighlight(cornerRadius: 7, expansion: 5))
                .onTapGesture {
                    isHistoryExpanded.toggle()
                }
                .accessibilityAddTraits(.isButton)
                .accessibilityLabel(isHistoryExpanded ? "Collapse system load history" : "Expand system load history")
                .accessibilityHint("Shows or hides the detailed system load chart")
                .accessibilityAction {
                    isHistoryExpanded.toggle()
                }
            }

            if let llm = metrics?.llm.first {
                Divider()
                HStack(spacing: 0) {
                    runtimeMetric("DECODE", value: rate(llm.generationTokensPerSecond, unit: "tok/s"))
                    runtimeMetric(
                        "THROUGHPUT",
                        value: rate(llm.aggregateTokensPerSecond, unit: "tok/s")
                    )
                    runtimeMetric("PREFILL", value: rate(llm.prefillTokensPerSecond, unit: "tok/s"))
                    runtimeMetric(
                        "REQUESTS",
                        value: requestCount(running: llm.runningRequests, waiting: llm.waitingRequests)
                    )
                }
            }
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 10)
        .overlay {
            VStack(spacing: 0) {
                Divider()
                Spacer()
                Divider()
            }
        }
    }

    private func preferredPlacement(
        _ placements: [SitePlacementRecord],
        model: String
    ) -> SitePlacementRecord? {
        placements.first { $0.model == model }
            ?? placements.first { $0.state == "running" }
            ?? placements.first
    }

    private func placementMenu(
        _ placement: SitePlacementRecord,
        site: SavedSite,
        role: String?,
        tripLatched: Bool,
        allowsPlacementPlanning: Bool
    ) -> some View {
        Menu {
            Button("Start") {
                Task {
                    await monitoring.runtimeAction(
                        .start,
                        model: placement.model,
                        placementID: placement.placementID,
                        site: site
                    )
                }
            }
            .disabled(placement.state == "running")
            Button("Restart") {
                Task {
                    await monitoring.runtimeAction(
                        .restart,
                        model: placement.model,
                        placementID: placement.placementID,
                        site: site
                    )
                }
            }
            if tripLatched {
                Button("Clear safety trip and restart") {
                    Task {
                        await monitoring.runtimeAction(
                            .recover,
                            model: placement.model,
                            placementID: placement.placementID,
                            site: site
                        )
                    }
                }
            }
            Button("Stop", role: .destructive) {
                Task {
                    await monitoring.runtimeAction(
                        .stop,
                        model: placement.model,
                        placementID: placement.placementID,
                        site: site
                    )
                }
            }
            if role == "administrator", allowsPlacementPlanning {
                Divider()
                Button("Plan placement") {
                    Task {
                        await monitoring.planPlacement(
                            model: placement.model,
                            engine: nil,
                            site: site
                        )
                    }
                }
            }
        } label: {
            Image(systemName: "ellipsis.circle")
        }
        .menuStyle(.borderlessButton)
        .fixedSize()
        .disabled(
            monitoring.runtimeActionPending(
                siteID: site.id,
                placementID: placement.placementID
            )
        )
    }

    private func runtimeStateBadge(_ status: SiteStatus) -> some View {
        let ready = !status.tripLatched
            && status.serviceState.lowercased() == "running"
            && status.engineState.lowercased() == "running"
        let color: Color = status.tripLatched ? .red : (ready ? .green : .orange)
        let label = status.tripLatched ? "TRIPPED" : (ready ? "SERVING" : status.engineState.uppercased())
        return HStack(spacing: 5) {
            Circle()
                .fill(color)
                .frame(width: 6, height: 6)
            Text(label)
                .font(.caption2.weight(.bold).monospaced())
        }
        .foregroundStyle(color)
    }

    private func runtimeSummaryMetric(
        _ title: String,
        value: String,
        systemImage: String? = nil,
        color: Color = .primary
    ) -> some View {
        VStack(alignment: .leading, spacing: 3) {
            Text(title)
                .font(.system(size: 8, weight: .bold))
                .foregroundStyle(.secondary)
            HStack(spacing: 4) {
                if let systemImage {
                    Image(systemName: systemImage)
                        .font(.system(size: 9, weight: .semibold))
                }
                Text(value)
                    .font(.caption.monospacedDigit())
                    .lineLimit(1)
            }
            .foregroundStyle(color)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    private var runtimeSummaryDivider: some View {
        Rectangle()
            .fill(Color.primary.opacity(0.08))
            .frame(width: 1, height: 25)
            .padding(.horizontal, 6)
    }

    private func runtimeMetric(_ title: String, value: String) -> some View {
        VStack(alignment: .leading, spacing: 1) {
            Text(title)
                .font(.system(size: 8, weight: .bold))
                .foregroundStyle(.secondary)
            Text(value)
                .font(.caption.monospacedDigit())
                .foregroundStyle(.primary)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    private func resourceRows(snapshot: SiteSnapshot?) -> some View {
        let metrics = snapshot?.metrics
        return VStack(spacing: 0) {
            metricRow(
                title: "GPU",
                systemImage: "gauge.with.dots.needle.67percent",
                value: percent(metrics?.gpu?.utilizationPercent),
                subtitle: joined([
                    temperature(metrics?.gpu?.temperatureCelsius),
                    clock(metrics?.gpu?.smClockMHz)
                ]),
                utilization: metrics?.gpu?.utilizationPercent,
                metric: .gpu,
                isExpanded: expandedMetrics.contains(.gpu)
            )
            if expandedMetrics.contains(.gpu) {
                tintedUtilizationDetail(.gpu, snapshot: snapshot)
            } else {
                metricRowDivider
            }

            metricRow(
                title: "Unified memory",
                systemImage: "memorychip",
                value: percent(metrics?.memory?.utilizationPercent),
                subtitle: joined([
                    capacity(used: metrics?.memory?.usedBytes, total: metrics?.memory?.totalBytes),
                    clock(metrics?.memory?.clockMHz)
                ]),
                utilization: metrics?.memory?.utilizationPercent
            )

            metricRowDivider

            metricRow(
                title: "CPU",
                systemImage: "cpu",
                value: percent(metrics?.cpu?.utilizationPercent),
                subtitle: joined([
                    temperature(metrics?.cpu?.temperatureCelsius),
                    clock(metrics?.cpu?.averageFrequencyMHz)
                ]),
                utilization: metrics?.cpu?.utilizationPercent,
                metric: .cpu,
                isExpanded: expandedMetrics.contains(.cpu)
            )
            if expandedMetrics.contains(.cpu) {
                tintedUtilizationDetail(.cpu, snapshot: snapshot)
            } else {
                metricRowDivider
            }

            metricRow(
                title: "NVMe",
                systemImage: "internaldrive",
                value: percent(metrics?.storage?.utilizationPercent),
                subtitle: joined([
                    temperature(metrics?.storage?.temperatureCelsius),
                    diskRate(metrics?.storage)
                ]),
                utilization: metrics?.storage?.utilizationPercent
            )
        }
    }

    private var metricRowDivider: some View {
        Divider()
            .padding(.leading, 42)
    }

    @ViewBuilder
    private func metricRow(
        title: String,
        systemImage: String,
        value: String,
        subtitle: String,
        utilization: Double?,
        metric: ExpandedMetric? = nil,
        isExpanded: Bool = false
    ) -> some View {
        if let metric {
            Button {
                toggle(metric)
            } label: {
                metricRowContent(
                    title: title,
                    systemImage: systemImage,
                    value: value,
                    subtitle: subtitle,
                    utilization: utilization,
                    showsDisclosure: true,
                    isExpanded: isExpanded
                )
            }
            .buttonStyle(MetricRowButtonStyle())
            .modifier(ExpandableHoverHighlight())
            .accessibilityHint(isExpanded ? "Collapses utilization detail" : "Expands utilization detail")
        } else {
            metricRowContent(
                title: title,
                systemImage: systemImage,
                value: value,
                subtitle: subtitle,
                utilization: utilization,
                showsDisclosure: false,
                isExpanded: false
            )
        }
    }

    private func metricRowContent(
        title: String,
        systemImage: String,
        value: String,
        subtitle: String,
        utilization: Double?,
        showsDisclosure: Bool,
        isExpanded: Bool
    ) -> some View {
        HStack(alignment: .center, spacing: 8) {
            Image(systemName: systemImage)
                .symbolRenderingMode(.monochrome)
                .foregroundStyle(.secondary)
                .frame(width: 18, height: 18)
            Text(title)
                .font(.caption.weight(.semibold))
                .foregroundStyle(.primary)
                .frame(width: 112, alignment: .leading)
                .lineLimit(1)

            Spacer(minLength: 0)

            VStack(alignment: .leading, spacing: 5) {
                Capsule()
                    .fill(Color.primary.opacity(0.06))
                    .overlay(alignment: .leading) {
                        Capsule()
                            .fill(Color.blue)
                            .frame(width: progressWidth(utilization, available: 214))
                    }
                    .clipped()
                    .frame(width: 214, height: 3)

                HStack(alignment: .firstTextBaseline, spacing: 6) {
                    Text(value)
                        .font(.caption.weight(.semibold).monospacedDigit())
                        .frame(width: 38, alignment: .leading)

                    Spacer(minLength: 0)

                    Text(subtitle)
                        .font(.caption2.monospacedDigit())
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                        .minimumScaleFactor(0.78)
                        .allowsTightening(true)

                    if showsDisclosure {
                        Image(systemName: "chevron.down")
                            .font(.system(size: 8, weight: .bold))
                            .foregroundStyle(.tertiary)
                            .rotationEffect(.degrees(isExpanded ? 180 : 0))
                            .frame(width: 10, height: 12)
                    } else {
                        Color.clear.frame(width: 10, height: 12)
                    }
                }
                .frame(width: 214)
            }
            .frame(width: 214)
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 5)
        .frame(maxWidth: .infinity, minHeight: 44, alignment: .leading)
        .contentShape(Rectangle())
    }

    @ViewBuilder
    private func tintedUtilizationDetail(
        _ metric: ExpandedMetric,
        snapshot: SiteSnapshot?
    ) -> some View {
        utilizationDetail(metric, snapshot: snapshot)
    }

    @ViewBuilder
    private func utilizationDetail(
        _ metric: ExpandedMetric,
        snapshot: SiteSnapshot?
    ) -> some View {
        switch metric {
        case .gpu:
            UtilizationHeatmap(
                title: "GPU engines",
                units: snapshot?.metrics.gpu?.units ?? [],
                width: dashboardWidth
            )
        case .cpu:
            UtilizationHeatmap(
                title: "CPU cores",
                units: snapshot?.metrics.cpu?.units ?? [],
                width: dashboardWidth
            )
        }
    }

    private func telemetryStrip(snapshot: SiteSnapshot?) -> some View {
        HStack(spacing: 0) {
            runtimeSummaryMetric(
                "POWER",
                value: watts(snapshot?.metrics.gpu?.powerWatts),
                systemImage: "bolt.fill"
            )
            runtimeSummaryDivider
            runtimeSummaryMetric(
                "NETWORK",
                value: networkRate(snapshot?.metrics.network),
                systemImage: "network"
            )
            runtimeSummaryDivider
            runtimeSummaryMetric(
                "UPTIME",
                value: compactDuration(snapshot?.uptimeSeconds),
                systemImage: "clock"
            )
        }
        .padding(.vertical, 9)
        .overlay(alignment: .top) {
            Divider()
        }
    }

    private func errorCard(_ message: String) -> some View {
        Label(message, systemImage: "exclamationmark.triangle.fill")
            .font(.caption)
            .foregroundStyle(.red)
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(9)
            .background(Color.red.opacity(0.08), in: RoundedRectangle(cornerRadius: 8))
    }

    private func footer(site: SavedSite) -> some View {
        HStack(spacing: 16) {
            Button {
                addSiteWindow.show(store: siteStore)
            } label: {
                Label("Add", systemImage: "plus")
            }

            Spacer()

            Button {
                siteInfoWindow.show(site: site, monitoring: monitoring)
            } label: {
                Label("Inspect", systemImage: "slider.horizontal.3")
            }

            Button("Quit") {
                NSApplication.shared.terminate(nil)
            }
        }
        .buttonStyle(.plain)
        .font(.subheadline)
        .foregroundStyle(.secondary)
        .padding(.horizontal, 13)
        .frame(height: 40)
    }

    private func toggle(_ metric: ExpandedMetric) {
        if expandedMetrics.contains(metric) {
            expandedMetrics.remove(metric)
        } else {
            expandedMetrics.insert(metric)
        }
    }

    private func progressWidth(_ value: Double?, available: CGFloat) -> CGFloat {
        guard let value else { return 0 }
        return available * CGFloat(max(0, min(100, value))) / 100
    }

    private func statusColor(snapshot: SiteSnapshot?, error: String?) -> Color {
        switch snapshot?.availability {
        case .online: return .green
        case .degraded: return .orange
        case .offline: return .red
        case nil: return error == nil ? .secondary : .red
        }
    }

    private func statusText(snapshot: SiteSnapshot?, error: String?) -> String {
        switch snapshot?.availability {
        case .online: return "Online"
        case .degraded: return "Degraded"
        case .offline: return "Offline"
        case nil: return error == nil ? "Connecting" : "Unavailable"
        }
    }

    private func percent(_ value: Double?) -> String {
        value.map { "\(Int($0.rounded()))%" } ?? "—"
    }

    private func temperature(_ value: Double?) -> String? {
        value.map { "\(Int($0.rounded()))°C" }
    }

    private func watts(_ value: Double?) -> String {
        value.map { String(format: "%.1f W", $0) } ?? "—"
    }

    private func clock(_ value: Double?) -> String? {
        guard let value else { return nil }
        if value >= 1_000 {
            return String(format: "%.2f GHz", value / 1_000)
        }
        return "\(Int(value.rounded())) MHz"
    }

    private func capacity(used: Double?, total: Double?) -> String? {
        guard let used, let total, total > 0 else { return nil }
        return "\(compactBytes(used)) / \(compactBytes(total))"
    }

    private func compactBytes(_ value: Double) -> String {
        let formatter = ByteCountFormatter()
        formatter.countStyle = .memory
        formatter.allowedUnits = value >= 1_000_000_000 ? [.useGB] : [.useMB]
        formatter.includesUnit = true
        formatter.isAdaptive = true
        return formatter.string(fromByteCount: Int64(value))
    }

    private func throughput(_ value: Double?) -> String {
        guard let value else { return "—" }
        if value < 1_024 { return "\(Int(value.rounded())) B/s" }
        if value < 1_048_576 { return String(format: "%.0f KB/s", value / 1_024) }
        if value < 1_073_741_824 { return String(format: "%.1f MB/s", value / 1_048_576) }
        return String(format: "%.1f GB/s", value / 1_073_741_824)
    }

    private func diskRate(_ storage: StorageMetrics?) -> String? {
        guard let read = storage?.readBytesPerSecond, let write = storage?.writeBytesPerSecond else {
            return nil
        }
        let largest = max(read, write)
        if largest < 1_024 {
            return "R/W \(Int(read.rounded()))/\(Int(write.rounded())) B/s"
        }
        if largest < 1_048_576 {
            return String(format: "R/W %.0f/%.0f KB/s", read / 1_024, write / 1_024)
        }
        return String(format: "R/W %.1f/%.1f MB/s", read / 1_048_576, write / 1_048_576)
    }

    private func networkRate(_ network: NetworkMetrics?) -> String {
        guard network?.receiveBytesPerSecond != nil || network?.transmitBytesPerSecond != nil else {
            return "—"
        }
        return "↓ \(throughput(network?.receiveBytesPerSecond)) · ↑ \(throughput(network?.transmitBytesPerSecond))"
    }

    private func compactDuration(_ value: TimeInterval?) -> String {
        guard let value else { return "—" }
        let days = Int(value) / 86_400
        let hours = (Int(value) % 86_400) / 3_600
        if days > 0 { return "\(days)d \(hours)h" }
        let minutes = (Int(value) % 3_600) / 60
        return hours > 0 ? "\(hours)h \(minutes)m" : "\(minutes)m"
    }

    private func rate(_ value: Double?, unit: String) -> String {
        value.map { String(format: "%.1f %@", $0, unit) } ?? "—"
    }

    private func milliseconds(_ value: Double?) -> String {
        value.map { String(format: "%.0f ms", $0) } ?? "—"
    }

    private func ratio(_ value: Double?) -> String {
        value.map { String(format: "%.0f%%", $0 * 100) } ?? "—"
    }

    private func requestCount(running: Int?, waiting: Int?) -> String {
        guard running != nil || waiting != nil else { return "—" }
        return "\(running ?? 0) run · \(waiting ?? 0) wait"
    }

    private func joined(_ values: [String?]) -> String {
        let present = values.compactMap { $0 }.filter { !$0.isEmpty }
        return present.isEmpty ? "No telemetry" : present.joined(separator: " · ")
    }

    private func compactRuntimeIdentity(_ status: SiteStatus) -> String {
        var parts = [engineName(status.engine)]
        if let runtimeName = status.runtimeName, !runtimeName.isEmpty {
            parts.append(runtimeName.split(separator: "/").last.map(String.init) ?? runtimeName)
        }
        if let runtimeVersion = status.runtimeVersion, !runtimeVersion.isEmpty {
            parts.append(runtimeVersion)
        }
        return parts.joined(separator: " · ")
    }

    private func engineName(_ value: String) -> String {
        switch value.lowercased() {
        case "dwarfstar": return "DwarfStar"
        case "vllm": return "vLLM"
        case "sglang": return "SGLang"
        case "llama.cpp": return "llama.cpp"
        default: return value
        }
    }

    private func compactTokens(_ value: Int) -> String {
        if value >= 1_000_000 { return String(format: "%.1fM ctx", Double(value) / 1_000_000) }
        if value >= 1_000 { return "\(Int((Double(value) / 1_000).rounded()))K ctx" }
        return "\(value) ctx"
    }

    private func sourceName(_ source: SiteDataSourceKind) -> String {
        switch source {
        case .controller: return "Site facts"
        case .watchdog: return "Watchdog"
        case .ssh: return "SSH fallback"
        }
    }

    private func headerSubtitle(site: SavedSite, snapshot: SiteSnapshot?) -> String {
        let hardware = snapshot?.identity?.displayName
            ?? [site.hardwareIdentity?.manufacturer, site.hardwareIdentity?.product]
                .compactMap { $0 }
                .joined(separator: " ")
        return hardware.isEmpty ? site.host : "\(hardware) · \(site.host)"
    }

    private func recordHardwareIdentities(from snapshots: [SavedSite.ID: SiteSnapshot]) {
        for site in siteStore.sites {
            guard let snapshot = snapshots[site.id], snapshot.system != nil else { continue }
            do {
                try siteStore.recordHardwareIdentity(
                    SavedHardwareIdentity(snapshot: snapshot),
                    for: site.id
                )
            } catch {
                errorMessage = error.localizedDescription
            }
        }
    }

    private func forget(_ site: SavedSite) {
        do {
            if let installationID = site.installationID {
                try ControllerCredentialStore.shared.forget(
                    installationID: installationID
                )
            }
            try siteStore.remove(id: site.id)
            if selectedSiteID == site.id {
                selectedSiteID = nil
            }
        } catch {
            errorMessage = error.localizedDescription
        }
    }
}

private struct SiteTopologyGraph: View {
    let coordinatorName: String
    let coordinatorState: String
    let members: [SiteMemberRecord]

    private var visibleMembers: [SiteMemberRecord] {
        Array(members.prefix(4))
    }

    var body: some View {
        GeometryReader { geometry in
            let count = visibleMembers.count
            let centerX = geometry.size.width / 2
            ZStack {
                if count > 0 {
                    Path { path in
                        for index in visibleMembers.indices {
                            let childX = geometry.size.width
                                * (CGFloat(index) + 0.5) / CGFloat(count)
                            path.move(to: CGPoint(x: centerX, y: 65))
                            path.addCurve(
                                to: CGPoint(x: childX, y: 105),
                                control1: CGPoint(x: centerX, y: 88),
                                control2: CGPoint(x: childX, y: 82)
                            )
                        }
                    }
                    .stroke(
                        Color.accentColor.opacity(0.35),
                        style: StrokeStyle(lineWidth: 1.5, lineCap: .round)
                    )
                }

                topologyNode(
                    name: coordinatorName,
                    role: "Coordinator",
                    state: coordinatorState,
                    systemImage: "server.rack"
                )
                .frame(width: 140)
                .position(x: centerX, y: 34)

                ForEach(Array(visibleMembers.enumerated()), id: \.element.id) { index, member in
                    let childX = geometry.size.width
                        * (CGFloat(index) + 0.5) / CGFloat(max(1, count))
                    topologyNode(
                        name: member.displayName,
                        role: "Member",
                        state: member.state,
                        systemImage: "cube.box.fill"
                    )
                    .frame(width: min(100, geometry.size.width / CGFloat(max(1, count)) - 4))
                    .position(x: childX, y: 135)
                }

                if members.count > visibleMembers.count {
                    Text("+\(members.count - visibleMembers.count) more")
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                        .position(x: centerX, y: 174)
                }
            }
        }
        .frame(height: members.isEmpty ? 72 : (members.count > 4 ? 188 : 170))
        .accessibilityElement(children: .combine)
        .accessibilityLabel(
            "Coordinator \(coordinatorName), \(members.count) connected members"
        )
    }

    private func topologyNode(
        name: String,
        role: String,
        state: String,
        systemImage: String
    ) -> some View {
        VStack(spacing: 4) {
            ZStack(alignment: .bottomTrailing) {
                Circle()
                    .fill(.primary.opacity(0.07))
                    .frame(width: 42, height: 42)
                Image(systemName: systemImage)
                    .font(.system(size: 17, weight: .medium))
                    .foregroundStyle(.primary)
                    .frame(width: 42, height: 42)
                Circle()
                    .fill(stateColor(state))
                    .frame(width: 8, height: 8)
                    .overlay(Circle().stroke(.background, lineWidth: 2))
            }
            Text(name)
                .font(.caption.weight(.semibold))
                .lineLimit(1)
            Text(role)
                .font(.caption2)
                .foregroundStyle(.secondary)
        }
    }

    private func stateColor(_ state: String) -> Color {
        switch state.lowercased() {
        case "active", "online", "running": .green
        case "draining", "degraded", "connecting": .orange
        case "failed", "offline", "removed": .red
        default: .secondary
        }
    }
}

private struct MetricRowButtonStyle: ButtonStyle {
    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .background {
                Rectangle()
                    .fill(Color.primary.opacity(configuration.isPressed ? 0.05 : 0))
            }
    }
}

private struct ExpandableHoverHighlight: ViewModifier {
    @State private var isHovering = false
    let cornerRadius: CGFloat
    let expansion: CGFloat

    init(cornerRadius: CGFloat = 0, expansion: CGFloat = 0) {
        self.cornerRadius = cornerRadius
        self.expansion = expansion
    }

    func body(content: Content) -> some View {
        content
            .background {
                RoundedRectangle(cornerRadius: cornerRadius, style: .continuous)
                    .fill(Color.primary.opacity(isHovering ? 0.045 : 0))
                    .padding(-expansion)
            }
            .onHover { isHovering = $0 }
    }
}
