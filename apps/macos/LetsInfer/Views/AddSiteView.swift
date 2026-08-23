import SwiftUI

private enum AddSiteChoice: String, CaseIterable, Identifiable {
    case connect
    case move

    var id: Self { self }
}

private struct MoveReview {
    let source: SavedSite
    let destination: SavedSite
    let plan: SiteMovePlan
    let useConnectX: Bool
}

struct AddSiteView: View {
    @EnvironmentObject private var siteStore: SiteStore
    @StateObject private var discovery = BonjourDiscovery()

    private let dataSource: any SiteDataSource
    private let pairing: any ControllerPairing
    private let controllerAPI: any ControllerSiteAPI
    private let onClose: () -> Void

    @State private var selectedServiceID: DiscoveredSite.ID?
    @State private var isShowingPairing = false
    @State private var isCustomConfiguration = false
    @State private var name = ""
    @State private var host = ""
    @State private var port = 22
    @State private var username = NSUserName()
    @State private var pairingCode = ""
    @State private var verificationCode: String?
    @State private var choice: AddSiteChoice = .connect
    @State private var moveReview: MoveReview?
    @State private var preparedMove: PreparedSiteMove?
    @State private var commitAttempted = false
    @State private var isConnecting = false
    @State private var errorMessage: String?

    init(
        dataSource: any SiteDataSource = RoutingSiteDataSource(),
        pairing: any ControllerPairing = ControllerPairingClient(),
        controllerAPI: any ControllerSiteAPI = ControllerAPIClient(),
        onClose: @escaping () -> Void
    ) {
        self.dataSource = dataSource
        self.pairing = pairing
        self.controllerAPI = controllerAPI
        self.onClose = onClose
    }

    var body: some View {
        VStack(spacing: 0) {
            HStack(alignment: .top, spacing: 14) {
                Image("MenuBarIcon")
                    .resizable()
                    .scaledToFit()
                    .frame(width: 34, height: 34)
                    .padding(9)
                    .background(.primary.opacity(0.07), in: RoundedRectangle(cornerRadius: 13))
                VStack(alignment: .leading, spacing: 4) {
                    Text("Add a Node")
                        .font(.title2.weight(.semibold))
                    Text("Nearby Let's Infer nodes appear automatically.")
                        .foregroundStyle(.secondary)
                }
                Spacer()
                if discovery.isSearching {
                    ProgressView().controlSize(.small).padding(.top, 8)
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(24)

            Divider()

            VStack(alignment: .leading, spacing: 14) {
                HStack {
                    Text("Nearby Nodes").font(.headline)
                    Spacer()
                    Button {
                        discovery.refresh()
                    } label: {
                        Label("Refresh", systemImage: "arrow.clockwise")
                    }
                    .buttonStyle(.borderless)
                }

                nearbySites
            }
            .padding(.horizontal, 24)
            .padding(.top, 18)

            Spacer(minLength: 16)
            Divider()
            HStack {
                Button("Cancel", role: .cancel) {
                    onClose()
                }
                .keyboardShortcut(.cancelAction)
                Spacer()
                Button {
                    beginCustomConfiguration()
                } label: {
                    Label("Custom Configuration", systemImage: "slider.horizontal.3")
                }
                .buttonStyle(.bordered)
            }
            .padding(.horizontal, 24)
            .frame(height: 58)
        }
        .frame(width: 650, height: 500)
        .onAppear { discovery.start() }
        .onDisappear {
            discovery.stop()
            if let review = moveReview, let prepared = preparedMove {
                Task {
                    if prepared.membershipState == "pending" {
                        _ = try? await controllerAPI.cancelPreparedMember(
                            memberID: prepared.memberID,
                            for: review.destination
                        )
                    }
                    _ = try? await controllerAPI.cancelSiteMove(
                        moveID: prepared.moveID,
                        for: review.source
                    )
                }
            }
        }
        .alert("Let's Infer Could Not Complete This Action", isPresented: Binding(
            get: { errorMessage != nil },
            set: { if !$0 { errorMessage = nil } }
        )) {
            Button("OK") { errorMessage = nil }
        } message: {
            Text(errorMessage ?? "Unknown error")
        }
        .sheet(isPresented: $isShowingPairing, onDismiss: resetPairingState) {
            pairingDialog
                .interactiveDismissDisabled(isConnecting || preparedMove != nil)
        }
    }

    @ViewBuilder
    private var nearbySites: some View {
        if discovery.services.isEmpty {
            VStack(spacing: 12) {
                Image(systemName: discovery.isSearching ? "dot.radiowaves.left.and.right" : "network.slash")
                    .font(.system(size: 34, weight: .light))
                    .foregroundStyle(.secondary)
                Text(discovery.isSearching ? "Looking for nodes…" : "No nearby nodes found")
                    .font(.headline)
                Text(
                    discovery.isSearching
                        ? "Nodes on this local network will appear here."
                        : "Check that the node service is running, or use Custom Configuration."
                )
                .font(.callout)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
            }
            .frame(maxWidth: .infinity, minHeight: 230)
        } else {
            ScrollView {
                LazyVGrid(
                    columns: [GridItem(.adaptive(minimum: 150, maximum: 190), spacing: 16)],
                    spacing: 16
                ) {
                    ForEach(discovery.services) { service in
                        nearbySiteButton(service)
                    }
                }
                .padding(2)
            }
            .frame(minHeight: 230)
        }
        if let discoveryError = discovery.errorMessage {
            Label(discoveryError, systemImage: "exclamationmark.triangle")
                .font(.caption)
                .foregroundStyle(.secondary)
        }
    }

    private func nearbySiteButton(_ service: DiscoveredSite) -> some View {
        let connected = siteStore.sites.contains { saved in
            saved.siteID == service.siteID
                || (saved.host == service.host && saved.name == service.displayName)
        }
        return Button {
            beginPairing(service)
        } label: {
            VStack(spacing: 10) {
                ZStack(alignment: .bottomTrailing) {
                    Circle()
                        .fill(.primary.opacity(0.07))
                        .frame(width: 74, height: 74)
                    Image("MenuBarIcon")
                        .resizable()
                        .scaledToFit()
                        .frame(width: 36, height: 40)
                        .frame(width: 74, height: 74)
                    if connected {
                        Image(systemName: "checkmark.circle.fill")
                            .symbolRenderingMode(.palette)
                            .foregroundStyle(.white, .green)
                            .background(Circle().fill(.background))
                    }
                }
                Text(service.displayName)
                    .font(.headline)
                    .lineLimit(1)
                Text(connected ? "Connected" : (service.host ?? "Resolving…"))
                    .font(.caption)
                    .foregroundStyle(connected ? AnyShapeStyle(.green) : AnyShapeStyle(.secondary))
                    .lineLimit(1)
                if service.directConnectX {
                    Label("Direct ConnectX", systemImage: "point.3.connected.trianglepath.dotted")
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                }
            }
            .frame(maxWidth: .infinity, minHeight: 156)
            .padding(12)
            .background(.primary.opacity(0.045), in: RoundedRectangle(cornerRadius: 16))
            .overlay {
                RoundedRectangle(cornerRadius: 16)
                    .stroke(.primary.opacity(0.08), lineWidth: 1)
            }
            .contentShape(RoundedRectangle(cornerRadius: 16))
        }
        .buttonStyle(.plain)
        .disabled(connected || service.host == nil)
        .accessibilityLabel(
            connected ? "\(service.displayName), connected" : "Add \(service.displayName)"
        )
    }

    private var pairingDialog: some View {
        VStack(spacing: 0) {
            VStack(alignment: .leading, spacing: 4) {
                Text(
                    moveReview != nil
                        ? "Move into Home"
                        : (isFreshAdoption ? "Add to Home" : "Pair with \(name.isEmpty ? "Node" : name)")
                )
                .font(.title2.weight(.semibold))
                Text(subtitle).foregroundStyle(.secondary)
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(.horizontal, 20)
            .padding(.top, 20)
            .padding(.bottom, 16)

            Form {
                if let review = moveReview {
                    moveReviewSections(review)
                } else {
                    pairingSections
                }
            }
            .formStyle(.columns)
            .padding(.horizontal, 20)

            Spacer(minLength: 12)
            Divider()
            HStack {
                Button(moveReview == nil ? "Cancel" : "Keep Separate", role: .cancel) {
                    Task { await cancelOrClose() }
                }
                .keyboardShortcut(.cancelAction)
                .disabled(isConnecting)
                Spacer()
                if isConnecting { ProgressView().controlSize(.small) }
                Button(primaryButtonTitle) {
                    Task {
                        if moveReview == nil {
                            if isFreshAdoption {
                                await adoptFreshSite()
                            } else {
                                await pairSite()
                            }
                        } else if preparedMove == nil {
                            await prepareMove()
                        } else {
                            await confirmAndCommitMove()
                        }
                    }
                }
                .buttonStyle(.borderedProminent)
                .keyboardShortcut(.defaultAction)
                .disabled(primaryButtonDisabled)
            }
            .padding(.horizontal, 20)
            .frame(height: 52)
        }
        .frame(width: 560, height: moveReview == nil ? 420 : 590)
    }

    private var subtitle: String {
        if let review = moveReview {
            return "Review everything affected before moving \(review.source.name) into \(review.destination.name)."
        }
        if isFreshAdoption {
            return "Add this fresh node to Home over its verified direct ConnectX link."
        }
        if isCustomConfiguration {
            return "Enter the node address and the one-time code from `letsinfer pair`."
        }
        return "Enter the one-time code shown by `letsinfer pair` on this node."
    }

    private var selectedDiscovery: DiscoveredSite? {
        guard let selectedServiceID else { return nil }
        return discovery.services.first { $0.id == selectedServiceID }
    }

    private var freshAdoptionDestination: SavedSite? {
        guard selectedDiscovery?.adoptable == true,
              selectedDiscovery?.directConnectX == true else { return nil }
        return siteStore.sites.first
    }

    private var isFreshAdoption: Bool { freshAdoptionDestination != nil }

    @ViewBuilder
    private var pairingSections: some View {
        if let destination = freshAdoptionDestination {
            Section("Add to Home") {
                LabeledContent("Home", value: destination.name)
                LabeledContent("Node", value: name)
                LabeledContent("Authorization", value: "Verified direct ConnectX")
                if destination.controllerRole != "administrator" {
                    Label(
                        "Home must be paired with an administrator controller.",
                        systemImage: "exclamationmark.triangle.fill"
                    )
                    .foregroundStyle(.orange)
                }
                Text("Nothing is joined until you click Add to Home. The fresh setup window and one-use signed request prevent later silent adoption.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        } else {
            Section("Node") {
                if isCustomConfiguration {
                    TextField("Name", text: $name, prompt: Text("My Spark"))
                    TextField("Hostname or IP", text: $host, prompt: Text("node-abcd.local"))
                        .textContentType(.URL)
                } else {
                    LabeledContent("Name", value: name)
                    LabeledContent("Address", value: host)
                }
                TextField("Pairing Code", text: $pairingCode, prompt: Text("123-45-678"))
                    .textContentType(.oneTimeCode)
                    .monospacedDigit()
            }

            if let home = siteStore.sites.first {
                Section("After pairing") {
                    Picker("Action", selection: $choice) {
                        Text("Connect as separate node").tag(AddSiteChoice.connect)
                        Text("Move into \(home.name)").tag(AddSiteChoice.move)
                    }
                    .pickerStyle(.radioGroup)
                    Text("Moving is never automatic. You will review active runtimes and credentials before the source node changes.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }

            Section {
                if let verificationCode {
                    LabeledContent("Verify") {
                        Text(verificationCode).font(.title3.monospacedDigit().weight(.semibold))
                    }
                    Text("Confirm that this code matches the terminal running `letsinfer pair`.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                } else {
                    Text("The pairing code is single-use. This Mac creates its controller key locally; the private key never leaves Keychain.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }

        }
    }

    @ViewBuilder
    private func moveReviewSections(_ review: MoveReview) -> some View {
        Section("Destination") {
            LabeledContent("Home", value: review.destination.name)
            LabeledContent("Source", value: review.source.name)
            LabeledContent(
                "Enrollment",
                value: review.useConnectX ? "Verified direct ConnectX" : "Code + comparison"
            )
        }
        Section("Affected source state") {
            LabeledContent("Active runtimes", value: "\(review.plan.placementCount)")
            LabeledContent("API keys reset", value: "\(review.plan.apiKeyCount)")
            LabeledContent("Controllers reset", value: "\(review.plan.controllerCount)")
            ForEach(review.plan.activePlacements) { placement in
                Text("\(placement.model) — \(placement.state)").font(.caption)
            }
            ForEach(review.plan.blockingReasons, id: \.self) { reason in
                Label(reason, systemImage: "exclamationmark.triangle.fill")
                    .foregroundStyle(.orange)
            }
        }
        Section("Preserved on the node") {
            ForEach(review.plan.preservedData, id: \.self) { Text($0) }
        }
        Section("Reset at commit") {
            ForEach(review.plan.resetState, id: \.self) { Text($0) }
        }
        if let preparedMove, let code = preparedMove.comparisonCode {
            Section("Confirm child") {
                LabeledContent("Comparison code") {
                    Text(code).font(.title2.monospacedDigit().weight(.semibold))
                }
                Text("Confirm this code before Home approves the child. The source remains unchanged until approval succeeds.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        }
    }

    private var primaryButtonTitle: String {
        if isConnecting { return "Working…" }
        if isFreshAdoption { return "Add to Home" }
        if moveReview == nil { return choice == .move ? "Pair & Review" : "Pair" }
        if preparedMove == nil { return "Prepare Move" }
        return "Confirm Code & Move"
    }

    private var primaryButtonDisabled: Bool {
        isConnecting
            || (isFreshAdoption && freshAdoptionDestination?.controllerRole != "administrator")
            || (moveReview?.plan.blockingReasons.isEmpty == false)
            || (moveReview == nil && !isFreshAdoption && (
                name.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
                    || host.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
                    || pairingCode.filter(\.isNumber).count != 8
            ))
    }

    private func beginPairing(_ service: DiscoveredSite) {
        resetPairingState()
        selectedServiceID = service.id
        isCustomConfiguration = false
        applySelection(service.id)
        isShowingPairing = true
    }

    private func beginCustomConfiguration() {
        resetPairingState()
        selectedServiceID = nil
        isCustomConfiguration = true
        name = ""
        host = ""
        isShowingPairing = true
    }

    private func resetPairingState() {
        guard !isConnecting, preparedMove == nil else { return }
        selectedServiceID = nil
        isCustomConfiguration = false
        name = ""
        host = ""
        port = 22
        username = NSUserName()
        pairingCode = ""
        verificationCode = nil
        choice = .connect
        moveReview = nil
        commitAttempted = false
        errorMessage = nil
    }

    private func applySelection(_ id: DiscoveredSite.ID?) {
        guard let id, let service = discovery.services.first(where: { $0.id == id }) else {
            return
        }
        name = service.displayName
        host = service.host ?? ""
        port = 22
    }

    private func siteControlEndpoint(host: String, port: Int) -> String? {
        var components = URLComponents()
        components.scheme = "https"
        components.host = host
        components.port = port
        return components.url?.absoluteString.trimmingCharacters(in: CharacterSet(charactersIn: "/"))
    }

    @MainActor
    private func adoptFreshSite() async {
        guard let service = selectedDiscovery,
              let destination = freshAdoptionDestination,
              destination.controllerRole == "administrator",
              let sourceHost = service.host,
              let sourcePort = service.controlPort,
              let sourceEndpoint = siteControlEndpoint(host: sourceHost, port: sourcePort),
              let sourceSiteID = service.siteID,
              let sourceMemberID = service.coordinatorID,
              let sourcePublicKeySHA256 = service.publicKeySHA256,
              let sourceCertificateSHA256 = service.certificateSHA256 else {
            errorMessage = "The fresh node's complete direct-link identity is unavailable."
            return
        }
        do {
            isConnecting = true
            defer { isConnecting = false }
            let adoption = try await controllerAPI.adoptMember(
                sourceEndpoint: sourceEndpoint,
                sourceSiteID: sourceSiteID,
                sourceMemberID: sourceMemberID,
                sourcePublicKeySHA256: sourcePublicKeySHA256,
                sourceCertificateSHA256: sourceCertificateSHA256,
                for: destination
            ).result.adoption
            guard adoption.state == "committed",
                  adoption.destinationSiteID == destination.siteID,
                  adoption.memberID == sourceMemberID else {
                throw ControllerAPIError.invalidResponse
            }
            onClose()
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    @MainActor
    private func pairSite() async {
        do {
            let provisional = try siteStore.prepareForAdd(SavedSite(
                name: name,
                host: host,
                port: port,
                username: username,
                authentication: .sshConfig,
                dataSource: .watchdog(port: WatchdogDataSource.defaultPort)
            ))
            isConnecting = true
            verificationCode = nil
            defer { isConnecting = false }
            let result = try await pairing.pair(
                host: provisional.host,
                setupCode: pairingCode,
                name: provisional.name
            ) { code in
                Task { @MainActor in verificationCode = code }
            }
            var site = provisional
            site.installationID = result.installationID
            site.controllerID = result.controllerID
            site.controlPort = result.controlPort
            site.dataSource = .watchdog(port: result.watchdogPort)
            let logical = try await controllerAPI.site(for: site)
            site.siteID = logical.site.identity.siteID
            site.coordinatorMemberID = logical.site.identity.coordinatorID
            site.memberPublicKeySHA256 = logical.site.identity.memberPublicKeySHA256
            site.controllerRole = logical.controller.role
            if let snapshot = try? await dataSource.fetchSnapshot(for: site) {
                site.hardwareIdentity = SavedHardwareIdentity(snapshot: snapshot)
            }
            try siteStore.add(site)
            guard choice == .move,
                  let destination = siteStore.sites.first(where: { $0.id != site.id }) else {
                onClose()
                return
            }
            guard logical.controller.role == "administrator" else {
                throw ControllerAPIError.rejected("Moving a node requires an administrator controller.")
            }
            guard destination.controllerRole == "administrator" else {
                throw ControllerAPIError.rejected("Home must be paired with an administrator controller.")
            }
            let plan = try await controllerAPI.siteMovePlan(for: site).result.plan
            let directConnectX = selectedServiceID.flatMap { selected in
                discovery.services.first(where: { $0.id == selected })
            }?.directConnectX == true
            moveReview = MoveReview(
                source: site,
                destination: destination,
                plan: plan,
                useConnectX: directConnectX
            )
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    @MainActor
    private func prepareMove() async {
        guard let review = moveReview else { return }
        do {
            isConnecting = true
            defer { isConnecting = false }
            let invite = try await controllerAPI.createMemberInvite(
                mode: review.useConnectX ? "connectx" : "lan",
                candidatePublicKeySHA256: review.useConnectX
                    ? review.source.memberPublicKeySHA256 : nil,
                candidateEndpoint: review.useConnectX
                    ? siteControlEndpoint(host: review.source.host, port: 9770) : nil,
                directInterface: review.useConnectX ? "auto" : nil,
                for: review.destination
            ).result.invite
            preparedMove = try await controllerAPI.prepareSiteMove(
                sourceSiteID: review.plan.sourceSiteID,
                invite: invite,
                memberName: review.source.name,
                memberAddress: review.source.host,
                for: review.source
            ).result.move
            commitAttempted = false
            if preparedMove?.comparisonCode == nil { await confirmAndCommitMove() }
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    @MainActor
    private func confirmAndCommitMove() async {
        guard let review = moveReview, let prepared = preparedMove else { return }
        do {
            isConnecting = true
            defer { isConnecting = false }
            if let code = prepared.comparisonCode {
                let approval = try await controllerAPI.approveMember(
                    memberID: prepared.memberID,
                    comparisonCode: code,
                    for: review.destination
                )
                guard approval.result.membership.state == "active" else {
                    throw ControllerAPIError.invalidResponse
                }
            }
            commitAttempted = true
            let committed = try await controllerAPI.commitSiteMove(
                moveID: prepared.moveID,
                for: review.source
            )
            guard committed.result.move.state == "committed" else {
                throw ControllerAPIError.invalidResponse
            }
            try siteStore.remove(id: review.source.id)
            if let installationID = review.source.installationID {
                try ControllerCredentialStore.shared.forget(installationID: installationID)
            }
            preparedMove = nil
            onClose()
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    @MainActor
    private func cancelOrClose() async {
        guard let review = moveReview else {
            isShowingPairing = false
            return
        }
        guard let prepared = preparedMove else {
            onClose()
            return
        }
        do {
            isConnecting = true
            defer { isConnecting = false }
            if !commitAttempted {
                _ = try await controllerAPI.cancelPreparedMember(
                    memberID: prepared.memberID,
                    for: review.destination
                )
            }
            _ = try await controllerAPI.cancelSiteMove(
                moveID: prepared.moveID,
                for: review.source
            )
            preparedMove = nil
            onClose()
        } catch {
            errorMessage = "The prepared move was not fully cancelled: \(error.localizedDescription)"
        }
    }
}
