import AppKit
import SwiftUI

struct SiteInfoView: View {
    @EnvironmentObject private var monitoring: SiteMonitoringController
    let site: SavedSite
    @State private var installModel = ""
    @State private var installEngine = ""
    @State private var newKeyName = ""
    @State private var newKeyPolicy = APIKeyPolicyDraft()
    @State private var editingKey: ControllerAPIKeyRecord?
    @State private var memberToRemove: SiteMemberRecord?
    @State private var inputError: String?

    private var snapshot: SiteSnapshot? { monitoring.snapshots[site.id] }
    private var identity: MemberIdentity? { snapshot?.identity }
    private var system: MemberSystemInfo? { snapshot?.system }
    private var metrics: MemberMetrics? { snapshot?.metrics }
    private var letsinfer: SiteStatus? { snapshot?.letsinfer }
    private var siteView: ControllerSiteEnvelope? { monitoring.siteViews[site.id] }
    private var telemetryView: ControllerTelemetryEnvelope? {
        monitoring.telemetryViews[site.id]
    }

    var body: some View {
        List {
            if let siteView {
                Section("Node") {
                    row("Name", siteView.site.identity.displayName)
                    row("Node ID", siteView.site.identity.siteID)
                    row("Main", siteView.site.identity.coordinatorAddress)
                    row("Topology", siteView.site.topology.valid ? "Verified" : "Unavailable")
                    row("Access role", siteView.controller.role.capitalized)
                }
                Section("Main and children") {
                    ForEach(siteView.site.nodes) { member in
                        let telemetry = memberTelemetry(member.memberID)
                        VStack(alignment: .leading, spacing: 4) {
                            HStack {
                                LabeledContent(member.displayName) {
                                    Text("\(member.role.capitalized) · \(member.state)")
                                        .foregroundStyle(.secondary)
                                }
                                if siteView.controller.role == "administrator" {
                                    if member.state == "active" {
                                        Button("Drain") {
                                            Task {
                                                await monitoring.drainMember(
                                                    member.memberID, site: site
                                                )
                                            }
                                        }
                                        .buttonStyle(.borderless)
                                    } else if member.state == "draining" {
                                        Button("Resume") {
                                            Task {
                                                await monitoring.resumeMember(
                                                    member.memberID, site: site
                                                )
                                            }
                                        }
                                        .buttonStyle(.borderless)
                                    }
                                    if member.memberID != siteView.site.identity.coordinatorID {
                                        Button("Remove", role: .destructive) {
                                            memberToRemove = member
                                        }
                                        .buttonStyle(.borderless)
                                    }
                                }
                            }
                            if let telemetry {
                                Text(memberTelemetrySummary(telemetry))
                                    .font(.caption.monospacedDigit())
                                    .foregroundStyle(telemetry.stale ? .orange : .secondary)
                            }
                        }
                    }
                }
                if siteView.controller.role == "administrator" {
                    administrationSections(siteView)
                }
            }

            Section("Device") {
                row("Manufacturer", identity?.manufacturerName ?? site.hardwareIdentity?.manufacturer)
                row("Raw manufacturer", identity?.vendor)
                row("Model", identity?.product ?? site.hardwareIdentity?.product)
                row("Product version", system?.productVersion ?? site.hardwareIdentity?.productVersion)
                row("System serial", serialValue(system?.serialNumber ?? site.hardwareIdentity?.serialNumber))
                row("Serial source", system?.serialSource)
                row("System UUID", serialValue(system?.systemUUID ?? site.hardwareIdentity?.systemUUID))
                row("Stable node fingerprint", system?.machineIDHash ?? site.hardwareIdentity?.machineIDHash)
                row("Hostname", system?.hostname ?? site.host)
                row("Addresses", networkAddresses(system?.networkAddresses))
                row("Default interface", system?.defaultNetworkInterface)
            }

            if let letsinfer {
                Section("Let's Infer") {
                    row("Release", letsinfer.release)
                    row("Model", letsinfer.model)
                    row("Runtime", runtimeName(letsinfer))
                    row("Engine", letsinfer.engine)
                    row("Watchdog", letsinfer.serviceState)
                    row("Inference engine", letsinfer.engineState)
                    row("Protection", protectionName(letsinfer))
                    row("Prefix cache", cacheName(letsinfer))
                    row("Inference port", String(letsinfer.inferencePort))
                    row("Maximum connections", String(letsinfer.maxConnections))
                    row("Maximum active requests", String(letsinfer.maxActiveRequests))
                    row("Maximum context", tokenCount(letsinfer.maxContextTokens))
                    row("Manifest", letsinfer.manifestSHA256)
                }
            }

            Section("Board and firmware") {
                row("Board manufacturer", system?.boardVendor)
                row("Board model", system?.boardName)
                row("Board version", system?.boardVersion)
                row("Board serial", serialValue(system?.boardSerial))
                row("Chassis manufacturer", system?.chassisVendor)
                row("Chassis type", chassisType(system?.chassisType))
                row("Chassis serial", serialValue(system?.chassisSerial))
                row("BIOS manufacturer", system?.biosVendor)
                row("BIOS version", system?.biosVersion)
                row("BIOS date", system?.biosDate)
            }

            Section("Hardware") {
                row("Architecture", identity?.architecture)
                row("CPU", system?.cpuModel)
                row("CPU cores", system?.cpuCoreCount.map(String.init))
                row("GPU", identity?.gpuName)
                row("GPU UUID", system?.gpuUUID)
                row("NVIDIA driver", system?.nvidiaDriverVersion)
                row("NVMe model", system?.nvmeModel)
                row("NVMe serial", system?.nvmeSerial)
                row("NVMe firmware", system?.nvmeFirmware)
            }

            Section("Software") {
                row("Operating system", system?.operatingSystem)
                row("Kernel", system?.kernelVersion)
                row("NVIDIA image", system?.dgxName)
                row("DGX software version", system?.dgxSoftwareVersion)
                row("DGX base build", system?.dgxBaseBuildVersion)
                row("DGX build date", system?.dgxBuildDate)
                row("DGX update date", system?.dgxUpdateDate)
                row("DGX commit", system?.dgxCommitID)
                row("DGX platform", system?.dgxPlatform)
                row("Firmware upgrades available", system?.firmwareUpdateCount.map(String.init))
                row("Uptime", duration(snapshot?.uptimeSeconds))
                row("Data source", dataSourceName)
            }

            Section("System activity") {
                row("Processes", system?.processCount.map(String.init))
                row("Logged-in users", activeUsers(system?.activeUsers))
                row("Login sessions", system?.loginSessionCount.map(String.init))
                row("Latest interactive login", system?.lastLogin)
            }

            Section("GPU") {
                row("Utilization", percent(metrics?.gpu?.utilizationPercent))
                row("Temperature", temperature(metrics?.gpu?.temperatureCelsius))
                row("NVIDIA-reported power", watts(metrics?.gpu?.powerWatts))
                row("Power limit", watts(metrics?.gpu?.powerLimitWatts))
                row("Performance state", metrics?.gpu?.performanceState)
                row("Graphics clock", megahertz(metrics?.gpu?.graphicsClockMHz))
                row("SM clock", megahertz(metrics?.gpu?.smClockMHz))
                row("Maximum SM clock", megahertz(metrics?.gpu?.maxSMClockMHz))
                row("Memory clock", megahertz(metrics?.gpu?.memoryClockMHz))
                row("Compute mode", metrics?.gpu?.computeMode)
                row("Display active", yesNo(metrics?.gpu?.displayActive))
                row("PCIe link", pcie(metrics?.gpu))
                row("Throttled", yesNo(metrics?.gpu?.isThrottled))
            }

            Section("CPU and memory") {
                row("CPU utilization", percent(metrics?.cpu?.utilizationPercent))
                row("Platform temperature", temperature(metrics?.cpu?.temperatureCelsius))
                row("Average frequency", megahertz(metrics?.cpu?.averageFrequencyMHz))
                row("System RAM clock", megahertz(metrics?.memory?.clockMHz))
                row("Load average", loadAverage(metrics?.cpu))
                row("CPU pressure (10s)", percent(metrics?.cpu?.pressureAverage10Seconds))
                row("Unified memory used", bytes(metrics?.memory?.usedBytes))
                row("Unified memory available", bytes(metrics?.memory?.availableBytes))
                row("Unified memory total", bytes(metrics?.memory?.totalBytes))
                row("Cached memory", bytes(metrics?.memory?.cachedBytes))
                row("Swap used", bytes(metrics?.memory?.swapUsedBytes))
                row("Swap total", bytes(metrics?.memory?.swapTotalBytes))
                row("Memory pressure (10s)", percent(metrics?.memory?.pressureAverage10Seconds))
            }

            Section("Storage and network") {
                row("Root storage used", bytes(metrics?.storage?.usedBytes))
                row("Root storage available", bytes(metrics?.storage?.availableBytes))
                row("Root storage total", bytes(metrics?.storage?.totalBytes))
                row("NVMe temperature", temperature(metrics?.storage?.temperatureCelsius))
                row("Disk read", rate(metrics?.storage?.readBytesPerSecond))
                row("Disk write", rate(metrics?.storage?.writeBytesPerSecond))
                row("I/O pressure (10s)", percent(metrics?.storage?.pressureAverage10Seconds))
                row("Network receive", rate(metrics?.network?.receiveBytesPerSecond))
                row("Network transmit", rate(metrics?.network?.transmitBytesPerSecond))
                row("Receive errors / drops", counters(metrics?.network?.receiveErrors, metrics?.network?.receiveDrops))
                row("Transmit errors / drops", counters(metrics?.network?.transmitErrors, metrics?.network?.transmitDrops))
            }

            if let containers = system?.containers, !containers.isEmpty {
                Section("Containers") {
                    ForEach(containers) { container in
                        LabeledContent(container.name) {
                            VStack(alignment: .trailing, spacing: 2) {
                                if let image = container.image {
                                    Text(image)
                                        .lineLimit(1)
                                }
                                if let status = container.status {
                                    Text(status)
                                        .font(.caption)
                                        .foregroundStyle(.secondary)
                                }
                            }
                            .textSelection(.enabled)
                        }
                    }
                }
            }
        }
        .listStyle(.inset)
        .overlay {
            if snapshot == nil {
                ProgressView("Waiting for telemetry…")
                    .padding()
                    .background(.regularMaterial, in: .rect(cornerRadius: 10))
            }
        }
        .frame(minWidth: 520, minHeight: 480)
        .task(id: siteView?.controller.role) {
            if siteView?.controller.role == "administrator" {
                await monitoring.refreshAPIKeys(site: site)
            }
        }
        .confirmationDialog(
            "Remove child?",
            isPresented: Binding(
                get: { memberToRemove != nil },
                set: { if !$0 { memberToRemove = nil } }
            ),
            presenting: memberToRemove
        ) { member in
            Button("Remove \(member.displayName)", role: .destructive) {
                Task {
                    await monitoring.removeMember(member.memberID, site: site)
                    memberToRemove = nil
                }
            }
            Button("Cancel", role: .cancel) { memberToRemove = nil }
        } message: { member in
            Text("The child must not own a placement in an installed placement group. Its model and cache data remain on that node.")
        }
        .sheet(item: $editingKey) { key in
            APIKeyPolicyEditor(key: key) { policy in
                await monitoring.updateAPIKeyPolicy(
                    key.keyID, policy: policy, site: site
                )
            }
        }
        .sheet(item: oneTimeSecretBinding) { secret in
            OneTimeAPIKeyView(secret: secret) {
                monitoring.clearOneTimeSecret(siteID: site.id)
            }
        }
    }

    @ViewBuilder
    private func administrationSections(
        _ envelope: ControllerSiteEnvelope
    ) -> some View {
        Section("Runtime administration") {
            TextField("Model, for example example-model", text: $installModel)
            TextField("Engine (optional)", text: $installEngine)
            HStack {
                Button("Install runtime") {
                    let model = installModel.trimmingCharacters(in: .whitespacesAndNewlines)
                    guard !model.isEmpty else {
                        inputError = "Enter a model before installing."
                        return
                    }
                    inputError = nil
                    Task {
                        await monitoring.installRuntime(
                            model: model,
                            engine: nilIfEmpty(installEngine),
                            site: site
                        )
                    }
                }
                .disabled(
                    installModel.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
                    || monitoring.siteActionPending(
                        siteID: site.id,
                        resource: "install:\(installModel.trimmingCharacters(in: .whitespacesAndNewlines))"
                    )
                )
                if monitoring.siteActions.keys.contains(where: {
                    $0.hasPrefix("\(site.id.uuidString):install:")
                }) {
                    ProgressView().controlSize(.small)
                }
            }
            if envelope.site.activeNodeCount > 1 {
                ForEach(envelope.site.services) { service in
                    DisclosureGroup {
                        ForEach(service.placementGroups.sorted { $0.placementGroupID < $1.placementGroupID }) { placementGroup in
                            LabeledContent(
                                placementGroup.placements.compactMap { placement in
                                    envelope.site.nodes.first {
                                        $0.memberID == placement.nodeID
                                    }?.displayName
                                }.joined(separator: " + ")
                            ) {
                                Text(placementGroup.state.capitalized)
                                .font(.caption.monospaced())
                            }
                        }
                    } label: {
                        HStack {
                            Text(service.model)
                            Spacer()
                            Text(
                                service.placementGroups.count == 1
                                    ? "1 placement group"
                                    : "\(service.placementGroups.count) placement groups"
                            )
                            .foregroundStyle(.secondary)
                            Button("Plan placement") {
                                Task {
                                    await monitoring.planPlacement(
                                        model: service.model,
                                        engine: nil,
                                        site: site
                                    )
                                }
                            }
                            .disabled(
                                monitoring.siteActionPending(
                                    siteID: site.id,
                                    resource: "topology:\(service.model)"
                                )
                            )
                        }
                    }
                    if let result = monitoring.siteActionResult(
                        siteID: site.id,
                        resource: "topology:\(service.model)"
                    ) {
                        Text(
                            result.state == "pending"
                                ? "A verified placement plan is pending; no runtime was restarted."
                                : "The current placement already fits the active nodes."
                        )
                        .font(.caption)
                        .foregroundStyle(.secondary)
                    }
                }
            }
            ForEach(envelope.site.pendingTopologyPlans) { plan in
                LabeledContent("Pending placement plan") {
                    Text("\(plan.model) · \(plan.planID.prefix(8))")
                        .font(.caption.monospaced())
                }
            }
        }

        Section("Inference exposure") {
            row("State", envelope.site.exposure.state.capitalized)
            row(
                "Public URL",
                envelope.site.exposure.publicURL.isEmpty
                    ? nil : envelope.site.exposure.publicURL
            )
            HStack {
                Button(
                    envelope.site.exposure.state == "enabled"
                        ? "Disable public inference" : "Enable public inference",
                    role: envelope.site.exposure.state == "enabled" ? .destructive : nil
                ) {
                    Task {
                        await monitoring.setPublicExposure(
                            enabled: envelope.site.exposure.state != "enabled",
                            site: site
                        )
                    }
                }
                .disabled(
                    monitoring.siteActionPending(
                        siteID: site.id, resource: "exposure"
                    )
                )
                if monitoring.siteActionPending(
                    siteID: site.id, resource: "exposure"
                ) {
                    ProgressView().controlSize(.small)
                }
            }
            Text("Only the OpenAI-compatible inference endpoint is published. Node control and telemetry stay private.")
                .font(.caption)
                .foregroundStyle(.secondary)
        }

        Section("Inference API keys") {
            ForEach(monitoring.apiKeys[site.id] ?? []) { key in
                HStack {
                    VStack(alignment: .leading) {
                        Text(key.name)
                        Text(keyPolicySummary(key))
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                    Spacer()
                    Text(key.revokedAtUnix == nil ? "Active" : "Revoked")
                        .foregroundStyle(key.revokedAtUnix == nil ? .green : .secondary)
                    if key.revokedAtUnix == nil {
                        Menu {
                            Button("Edit policy") { editingKey = key }
                            Button("Rotate") {
                                Task { await monitoring.rotateAPIKey(key.keyID, site: site) }
                            }
                            Divider()
                            Button("Revoke", role: .destructive) {
                                Task { await monitoring.revokeAPIKey(key.keyID, site: site) }
                            }
                        } label: {
                            Image(systemName: "ellipsis.circle")
                        }
                        .menuStyle(.borderlessButton)
                    }
                }
            }
            TextField("New key name", text: $newKeyName)
            APIKeyPolicyFields(draft: $newKeyPolicy)
            Button("Create API key") {
                let name = newKeyName.trimmingCharacters(in: .whitespacesAndNewlines)
                guard !name.isEmpty else {
                    inputError = "Enter a lowercase key name."
                    return
                }
                guard let policy = newKeyPolicy.policy else {
                    inputError = newKeyPolicy.validationError
                    return
                }
                inputError = nil
                Task {
                    await monitoring.createAPIKey(name: name, policy: policy, site: site)
                    newKeyName = ""
                }
            }
            if let inputError {
                Text(inputError).font(.caption).foregroundStyle(.red)
            }
            if let error = monitoring.controllerErrors[site.id] {
                Text(error).font(.caption).foregroundStyle(.red)
            }
        }
    }

    private var oneTimeSecretBinding: Binding<ControllerOneTimeSecret?> {
        Binding(
            get: { monitoring.oneTimeSecrets[site.id] },
            set: { value in
                if value == nil { monitoring.clearOneTimeSecret(siteID: site.id) }
            }
        )
    }

    private var dataSourceName: String? {
        switch snapshot?.source {
        case .controller: "Authenticated node facts"
        case .watchdog: "Let's Infer Watchdog"
        case .ssh: "Direct SSH"
        case nil: nil
        }
    }

    private func nilIfEmpty(_ value: String) -> String? {
        let normalized = value.trimmingCharacters(in: .whitespacesAndNewlines)
        return normalized.isEmpty ? nil : normalized
    }

    private func memberTelemetry(_ memberID: String) -> SiteMemberTelemetry? {
        telemetryView?.telemetry.members.first { $0.id == memberID }
    }

    private func memberTelemetrySummary(_ telemetry: SiteMemberTelemetry) -> String {
        let system = telemetry.sample.system
        let inference = telemetry.sample.inference
        let freshness = telemetry.stale ? "Stale" : "Live"
        return [
            freshness,
            "CPU \(integerPercent(system.cpuPercent))",
            "GPU \(integerPercent(system.gpuPercent))",
            "RAM \(integerPercent(system.memoryPercent))",
            "\(inference.activeRequests) active",
            "\(inference.queuedRequests) queued",
            memberRate(telemetry.rates.outputTokensPerSecond),
        ].joined(separator: " · ")
    }

    private func integerPercent(_ value: Int) -> String {
        value < 0 ? "—" : "\(value)%"
    }

    private func memberRate(_ value: Double?) -> String {
        value.map { String(format: "%.1f tok/s", $0) } ?? "— tok/s"
    }

    private func keyPolicySummary(_ key: ControllerAPIKeyRecord) -> String {
        let models = key.models.isEmpty ? "all models" : key.models.joined(separator: ", ")
        let concurrency = key.concurrencyLimit.map { "c\($0)" } ?? "unbounded concurrency"
        return "\(models) · \(concurrency)"
    }

    @ViewBuilder
    private func row(_ title: String, _ value: String?) -> some View {
        LabeledContent(title) {
            Text(value ?? "—")
                .foregroundStyle(value == nil ? .secondary : .primary)
                .textSelection(.enabled)
        }
    }

    private func serialValue(_ value: String?) -> String? {
        if let value { return value }
        return system?.dmiSerialRequiresPrivilege == true ? "Requires privileged access" : nil
    }

    private func chassisType(_ value: String?) -> String? {
        guard let value else { return nil }
        if value == "17" { return "Main server chassis (17)" }
        return value
    }

    private func networkAddresses(_ values: [NetworkAddress]?) -> String? {
        guard let values, !values.isEmpty else { return nil }
        return values.map { address in
            let family = address.family == "inet6" ? "IPv6" : "IPv4"
            return "\(address.interface) · \(family) · \(address.address)"
        }.joined(separator: "\n")
    }

    private func activeUsers(_ values: [String]?) -> String? {
        guard let values, !values.isEmpty else { return nil }
        return values.joined(separator: ", ")
    }

    private func percent(_ value: Double?) -> String? {
        value.map { String(format: "%.1f%%", $0) }
    }

    private func temperature(_ value: Double?) -> String? {
        value.map { String(format: "%.1f°C", $0) }
    }

    private func watts(_ value: Double?) -> String? {
        value.map { String(format: "%.1f W", $0) }
    }

    private func megahertz(_ value: Double?) -> String? {
        value.map { String(format: "%.0f MHz", $0) }
    }

    private func yesNo(_ value: Bool?) -> String? {
        value.map { $0 ? "Yes" : "No" }
    }

    private func runtimeName(_ status: SiteStatus) -> String {
        [status.runtimeName, status.runtimeVersion]
            .compactMap { $0 }
            .joined(separator: " ")
    }

    private func protectionName(_ status: SiteStatus) -> String {
        if status.tripLatched { return "Tripped" }
        if status.protectionArmed { return "Armed" }
        return status.protectionPhase.capitalized
    }

    private func cacheName(_ status: SiteStatus) -> String {
        "\(status.cacheProvider) · \(status.cachePersistent ? "persistent" : "ephemeral")"
    }

    private func tokenCount(_ value: Int) -> String {
        value.formatted(.number.grouping(.automatic)) + " tokens"
    }

    private func pcie(_ gpu: GPUMetrics?) -> String? {
        guard let generation = gpu?.pcieGeneration, let width = gpu?.pcieWidth else { return nil }
        return "Gen \(generation) ×\(width)"
    }

    private func loadAverage(_ cpu: CPUMetrics?) -> String? {
        guard
            let one = cpu?.loadAverage1Minute,
            let five = cpu?.loadAverage5Minutes,
            let fifteen = cpu?.loadAverage15Minutes
        else { return nil }
        return String(format: "%.2f · %.2f · %.2f", one, five, fifteen)
    }

    private func bytes(_ value: Double?) -> String? {
        value.map { ByteCountFormatter.string(fromByteCount: Int64($0), countStyle: .memory) }
    }

    private func rate(_ value: Double?) -> String? {
        bytes(value).map { "\($0)/s" }
    }

    private func counters(_ errors: Double?, _ drops: Double?) -> String? {
        guard errors != nil || drops != nil else { return nil }
        return "\(Int(errors ?? 0)) / \(Int(drops ?? 0))"
    }

    private func duration(_ value: TimeInterval?) -> String? {
        guard let value else { return nil }
        let formatter = DateComponentsFormatter()
        formatter.allowedUnits = [.day, .hour, .minute]
        formatter.unitsStyle = .full
        formatter.maximumUnitCount = 2
        return formatter.string(from: value)
    }
}

private struct APIKeyPolicyDraft: Equatable {
    var models = ""
    var expiresAtUnix = ""
    var requestsPerMinute = ""
    var tokensPerMinute = ""
    var concurrencyLimit = ""
    var contextLimit = ""
    var tenant = ""
    var application = ""

    init() {}

    init(_ key: ControllerAPIKeyRecord) {
        models = key.models.joined(separator: ", ")
        expiresAtUnix = key.expiresAtUnix.map(String.init) ?? ""
        requestsPerMinute = key.requestsPerMinute.map(String.init) ?? ""
        tokensPerMinute = key.tokensPerMinute.map(String.init) ?? ""
        concurrencyLimit = key.concurrencyLimit.map(String.init) ?? ""
        contextLimit = key.contextLimit.map(String.init) ?? ""
        tenant = key.tenant ?? ""
        application = key.application ?? ""
    }

    var validationError: String {
        for (label, value) in numericFields {
            let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
            if !trimmed.isEmpty && (Int(trimmed) ?? 0) <= 0 {
                return "\(label) must be a positive whole number."
            }
        }
        return "The API-key policy is invalid."
    }

    var policy: ControllerAPIKeyPolicy? {
        guard numericFields.allSatisfy({ _, value in
            let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
            return trimmed.isEmpty || (Int(trimmed) ?? 0) > 0
        }) else { return nil }
        return ControllerAPIKeyPolicy(
            models: models.split(separator: ",").map {
                String($0).trimmingCharacters(in: .whitespacesAndNewlines)
            }.filter { !$0.isEmpty },
            expiresAtUnix: integer(expiresAtUnix),
            requestsPerMinute: integer(requestsPerMinute),
            tokensPerMinute: integer(tokensPerMinute),
            concurrencyLimit: integer(concurrencyLimit),
            contextLimit: integer(contextLimit),
            tenant: optional(tenant),
            application: optional(application)
        )
    }

    private var numericFields: [(String, String)] {
        [
            ("Expiry", expiresAtUnix),
            ("Requests per minute", requestsPerMinute),
            ("Tokens per minute", tokensPerMinute),
            ("Concurrency", concurrencyLimit),
            ("Maximum context", contextLimit),
        ]
    }

    private func integer(_ value: String) -> Int? {
        Int(value.trimmingCharacters(in: .whitespacesAndNewlines))
    }

    private func optional(_ value: String) -> String? {
        let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
        return trimmed.isEmpty ? nil : trimmed
    }
}

private struct APIKeyPolicyFields: View {
    @Binding var draft: APIKeyPolicyDraft

    var body: some View {
        DisclosureGroup("Policy") {
            TextField("Models, comma separated (empty means all)", text: $draft.models)
            TextField("Expiry, Unix timestamp (optional)", text: $draft.expiresAtUnix)
            TextField("Requests per minute (optional)", text: $draft.requestsPerMinute)
            TextField("Tokens per minute (optional)", text: $draft.tokensPerMinute)
            TextField("Concurrent requests (optional)", text: $draft.concurrencyLimit)
            TextField("Maximum context tokens (optional)", text: $draft.contextLimit)
            TextField("Tenant (optional)", text: $draft.tenant)
            TextField("Application (optional)", text: $draft.application)
        }
    }
}

private struct APIKeyPolicyEditor: View {
    @Environment(\.dismiss) private var dismiss
    let key: ControllerAPIKeyRecord
    let save: (ControllerAPIKeyPolicy) async -> Void
    @State private var draft: APIKeyPolicyDraft
    @State private var error: String?
    @State private var saving = false

    init(
        key: ControllerAPIKeyRecord,
        save: @escaping (ControllerAPIKeyPolicy) async -> Void
    ) {
        self.key = key
        self.save = save
        _draft = State(initialValue: APIKeyPolicyDraft(key))
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("Edit \(key.name)").font(.headline)
            APIKeyPolicyFields(draft: $draft)
            if let error {
                Text(error).font(.caption).foregroundStyle(.red)
            }
            HStack {
                Spacer()
                Button("Cancel") { dismiss() }
                Button("Save") {
                    guard let policy = draft.policy else {
                        error = draft.validationError
                        return
                    }
                    saving = true
                    Task {
                        await save(policy)
                        saving = false
                        dismiss()
                    }
                }
                .keyboardShortcut(.defaultAction)
                .disabled(saving)
            }
        }
        .padding(20)
        .frame(width: 430)
    }
}

private struct OneTimeAPIKeyView: View {
    @Environment(\.dismiss) private var dismiss
    let secret: ControllerOneTimeSecret
    let onDismiss: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("Save this API key now").font(.headline)
            Text("The main node will not show this token again.")
                .foregroundStyle(.secondary)
            Text(secret.token)
                .font(.system(.body, design: .monospaced))
                .textSelection(.enabled)
                .padding(10)
                .background(.quaternary, in: .rect(cornerRadius: 7))
            HStack {
                Button("Copy") {
                    NSPasteboard.general.clearContents()
                    NSPasteboard.general.setString(secret.token, forType: .string)
                }
                Spacer()
                Button("Done") { dismiss() }
                    .keyboardShortcut(.defaultAction)
            }
        }
        .padding(20)
        .frame(width: 480)
        .onDisappear(perform: onDismiss)
    }
}
