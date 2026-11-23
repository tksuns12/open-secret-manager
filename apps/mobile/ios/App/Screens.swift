import AuthenticationServices
import SwiftUI

struct RootView: View {
    @ObservedObject var model: VaultModel
    /// Kept here, not in the list, so that it outlasts an item or the settings being open; let go of at a lock.
    @State private var filter = ItemFilter.all

    /// Where in the unlocked app the owner is. Each is a state of the model,
    /// not a pushed screen, so that locking drops them all at once.
    private enum Route { case items, settings, detail, history, deleted, password, editor }

    private var route: Route {
        if model.editor != nil { return .editor }
        if model.history != nil { return .history }
        if model.deleted != nil { return .deleted }
        if model.passwordChange { return .password }
        if model.detail != nil { return .detail }
        if model.settings { return .settings }
        return .items
    }

    private var title: String {
        guard model.screen == .unlocked else { return "" }
        switch route {
        case .settings: return "Settings"
        case .history: return "History"
        case .deleted: return "Recently deleted"
        case .password: return "Change password"
        default: return ""
        }
    }

    /// The way back from the open screen, and what it is called.
    private var back: (name: String, action: () -> Void)? {
        switch route {
        case .detail: ("Items", model.close)
        case .settings: ("Items", model.closeSettings)
        case .history: (model.history?.detail.title ?? "Item", model.closeHistory)
        case .deleted: ("Settings", model.closeDeleted)
        case .password: ("Settings", model.closePasswordChange)
        case .items, .editor: nil
        }
    }

    var body: some View {
        NavigationStack {
            content
                .navigationTitle(title)
                .navigationBarTitleDisplayMode(.inline)
                .toolbar {
                    if model.screen == .unlocked && route == .items {
                        ToolbarItem(placement: .principal) {
                            HStack(spacing: 6) {
                                BrandMark(size: 20)
                                Text("Open Secret Manager").font(.headline)
                            }
                            .accessibilityElement(children: .combine)
                        }
                    }
                    if model.screen == .unlocked, let back {
                        ToolbarItem(placement: .topBarLeading) {
                            Button(action: back.action) {
                                Label(back.name, systemImage: "chevron.backward").labelStyle(.titleAndIcon)
                            }
                            .accessibilityIdentifier("back")
                        }
                    }
                    if model.screen == .unlocked && route == .items {
                        ToolbarItem(placement: .topBarLeading) {
                            Button(action: model.startNew) { Label("New", systemImage: "plus") }
                                .accessibilityIdentifier("new-item")
                        }
                        ToolbarItem(placement: .topBarTrailing) {
                            Button(action: model.openSettings) { Label("Settings", systemImage: "gearshape") }
                                .accessibilityIdentifier("settings")
                        }
                    }
                    if model.screen == .unlocked && route != .editor {
                        ToolbarItem(placement: .primaryAction) {
                            Button(action: model.lock) { Label("Lock", systemImage: "lock") }
                                .accessibilityIdentifier("lock")
                        }
                    }
                }
        }
        .tint(OSM.accent)
        .onChange(of: model.screen) { _, screen in if screen != .unlocked { filter = .all } }
        .overlay { if let busy = model.busy { BusyCover(what: busy) } }
        .overlay(alignment: .bottom) { NoticeBanner(notice: $model.notice) }
    }

    @ViewBuilder private var content: some View {
        switch model.screen {
        case .opening:
            Message(title: "Opening…")
        case .noVault:
            JoinStart(model: model)
        case .joining:
            JoinConfirm(model: model)
        case .locked:
            ScrollView {
                VStack(alignment: .leading, spacing: 16) {
                    UnlockFields(
                        biometric: model.biometric,
                        busy: model.busy != nil,
                        onUnlock: model.unlock,
                        onBiometrics: model.unlockWithBiometrics
                    )
                    SyncLine(model: model)
                }
                .padding(24)
            }
            .osmScreen()
        case .unlocked:
            switch route {
            case .editor:
                // A new editor, as after a save that met a change made
                // elsewhere, starts from what it holds.
                if let editor = model.editor { ItemEditor(model: model, editor: editor).id(editor) }
            case .history:
                if let history = model.history { HistoryList(model: model, history: history) }
            case .deleted:
                if let deleted = model.deleted { DeletedList(model: model, deleted: deleted) }
            case .password:
                PasswordChange(model: model)
            case .detail:
                if let detail = model.detail { Detail(model: model, detail: detail) }
            case .settings:
                SettingsList(model: model)
            case .items:
                Items(model: model, filter: $filter)
            }
        case .removed:
            Message(
                title: "This phone was removed from the vault",
                detail: "Your other devices moved to a new key that this phone never received. What it already held stays readable here."
            )
        case .unreadable:
            Message(title: "The vault on this phone cannot be opened", detail: model.unreadable)
        }
    }
}

private struct Message: View {
    let title: String
    var detail: String?

    var body: some View {
        VStack(spacing: 12) {
            BrandMark(size: 56)
            Text(title).font(.title2.bold()).multilineTextAlignment(.center).accessibilityIdentifier("message")
            if let detail { Text(detail).foregroundStyle(.secondary).multilineTextAlignment(.center) }
        }
        .padding(24)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .osmScreen()
    }
}

private struct JoinStart: View {
    @ObservedObject var model: VaultModel
    @State private var invitation = ""
    @State private var scanning = false

    var body: some View {
        if scanning {
            ScanInvitation(onInvitation: { text in
                scanning = false
                model.joinStart(text)
            }, onCancel: { scanning = false })
        } else {
            asked
        }
    }

    private var asked: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 14) {
                BrandMark(size: 44)
                Text("Join your vault").font(.largeTitle.bold())
                if InvitationScanner.available {
                    Text("On your computer, open Devices, choose Invite a device, and pick a phone. Scan the QR code it shows, or paste the invitation here.")
                        .foregroundStyle(.secondary)
                    // The camera is asked for only when the owner chooses to scan.
                    Button("Scan the QR code") {
                        Task {
                            if await InvitationScanner.mayUseCamera() {
                                scanning = true
                            } else {
                                model.notice = "Without the camera, paste the invitation instead"
                            }
                        }
                    }
                    .buttonStyle(.wide)
                    .disabled(model.busy != nil)
                    .accessibilityIdentifier("join-scan")
                } else {
                    Text("On your computer, open Devices, choose Invite a device, and pick a phone. Paste the invitation here.")
                        .foregroundStyle(.secondary)
                }
                TextField("Invitation", text: $invitation, axis: .vertical)
                    .lineLimit(3...6)
                    .font(.system(.body, design: .monospaced))
                    .osmField()
                    .autocorrectionDisabled()
                    .textInputAutocapitalization(.never)
                    .accessibilityIdentifier("invitation")
                Button("Continue") { model.joinStart(invitation) }
                    .buttonStyle(.wide)
                    .disabled(invitation.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty || model.busy != nil)
                    .accessibilityIdentifier("join-continue")
            }
            .padding(24)
        }
        .osmScreen()
    }
}

private struct JoinConfirm: View {
    @ObservedObject var model: VaultModel
    @State private var password = ""
    @State private var again = ""

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 14) {
                Text("Compare the codes").font(.largeTitle.bold())
                Text("Your computer shows a code too. Continue only if they are identical.")
                    .foregroundStyle(.secondary)
                Text(model.joinCode ?? "")
                    .font(.system(size: 34, weight: .bold, design: .monospaced))
                    .foregroundStyle(OSM.accent)
                    .minimumScaleFactor(0.6)
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 22)
                    .background(OSM.card, in: RoundedRectangle(cornerRadius: 16, style: .continuous))
                    .accessibilityIdentifier("join-code")
                Text("This phone's password: at least 12 characters. Your other devices keep their own.")
                    .foregroundStyle(.secondary)
                SecureField("New password for this phone", text: $password)
                    .osmField()
                    .accessibilityIdentifier("new-password")
                SecureField("The same again", text: $again)
                    .osmField()
                    .accessibilityIdentifier("new-password-again")
                Button("Codes match · join") { model.joinFinish(password) }
                    .buttonStyle(.wide)
                    .disabled(password.count < 12 || password != again || model.busy != nil)
                    .accessibilityIdentifier("join-finish")
                Button("They differ", action: model.cancelJoin)
                    .buttonStyle(.wideQuiet)
                    .disabled(model.busy != nil)
            }
            .padding(24)
        }
        .osmScreen()
    }
}

/// Which items the list shows.
private enum ItemFilter: CaseIterable {
    case all, favorites, logins, cards, notes, attention

    var label: String {
        switch self {
        case .all: "All"
        case .favorites: "Favorites"
        case .logins: "Logins"
        case .cards: "Cards"
        case .notes: "Notes"
        case .attention: "Needs attention"
        }
    }

    var identifier: String {
        switch self {
        case .all: "filter-all"
        case .favorites: "filter-favorites"
        case .logins: "filter-logins"
        case .cards: "filter-cards"
        case .notes: "filter-notes"
        case .attention: "filter-attention"
        }
    }

    func admits(_ item: ItemSummary, attention: [String: [String]]) -> Bool {
        switch self {
        case .all: true
        case .favorites: item.favorite
        case .logins: item.kind == .login
        case .cards: item.kind == .card
        case .notes: item.kind == .secureNote
        case .attention: attention[item.id] != nil
        }
    }
}

private struct Items: View {
    @ObservedObject var model: VaultModel
    @State private var query = ""
    @Binding var filter: ItemFilter

    private var shown: [ItemSummary] {
        model.items.filter { item in
            filter.admits(item, attention: model.attention) && (query.isEmpty
                || item.title.localizedCaseInsensitiveContains(query) || item.username.localizedCaseInsensitiveContains(query)
                || item.url.localizedCaseInsensitiveContains(query))
        }
    }

    var body: some View {
        List {
            if model.rowsChanged {
                Section {
                    VStack(alignment: .leading, spacing: 4) {
                        Text("Something in this vault's file was taken out or changed").font(.headline).foregroundStyle(.red)
                        Text("Since this phone last wrote to it, something outside the app removed or changed records in the vault's file: an item, an edit, or a device's keys. Your other devices send back what they have at the next sync.")
                            .font(.caption)
                    }
                    .accessibilityElement(children: .combine)
                    .accessibilityIdentifier("rows-changed")
                    Button("I understand", action: model.confirmRowsChanged).accessibilityIdentifier("rows-changed-ok")
                }
                .listRowBackground(OSM.card)
            }
            ScrollView(.horizontal, showsIndicators: false) {
                HStack(spacing: 8) {
                    ForEach(ItemFilter.allCases, id: \.self) { option in
                        Button(option.label) { filter = option }
                            .buttonStyle(ChipStyle(selected: filter == option))
                            .accessibilityIdentifier(option.identifier)
                            .accessibilityAddTraits(filter == option ? .isSelected : [])
                    }
                }
                .padding(.horizontal, 16)
            }
            .listRowInsets(EdgeInsets(top: 4, leading: 0, bottom: 4, trailing: 0))
            .listRowBackground(Color.clear)
            .listRowSeparator(.hidden)
            ForEach(shown, id: \.id) { item in
                Button { model.open(item.id) } label: {
                    HStack(spacing: 12) {
                        ItemAvatar(title: item.title, kind: item.kind)
                        VStack(alignment: .leading, spacing: 2) {
                            Text(item.title).font(.body.weight(.semibold))
                            let below = item.conflict ? "Needs a decision on your computer"
                                : item.kind == .card ? cardLine(brand: item.brand, ending: item.cardEnding)
                                : loginLine(username: item.username, passkeys: item.passkeys)
                            if !below.isEmpty {
                                Text(below).font(.subheadline).foregroundStyle(item.conflict ? Color.red : Color.secondary)
                            }
                        }
                        Spacer(minLength: 0)
                        if model.attention[item.id] != nil {
                            Text("!").font(.body.weight(.bold)).foregroundStyle(.red)
                                .accessibilityLabel("Needs attention")
                                .accessibilityIdentifier("attention:\(item.title)")
                        }
                        if item.favorite {
                            Image(systemName: "star.fill").foregroundStyle(OSM.accent).accessibilityLabel("Favorite")
                        }
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .contentShape(Rectangle())
                }
                .buttonStyle(.plain)
                .accessibilityIdentifier("item:\(item.title)")
                .listRowBackground(Color.clear)
                .listRowSeparatorTint(OSM.hairline)
            }
            if shown.isEmpty {
                Text(model.items.isEmpty ? "No items yet" : filter == .attention && query.isEmpty ? "Nothing needs attention, by what this checks" : "Nothing matches")
                    .foregroundStyle(.secondary)
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 32)
                    .listRowBackground(Color.clear)
                    .listRowSeparator(.hidden)
            }
            SyncLine(model: model)
                .listRowBackground(Color.clear)
                .listRowSeparator(.hidden)
        }
        .listStyle(.plain)
        .scrollContentBackground(.hidden)
        .background(OSM.background)
        .searchable(text: $query)
    }
}

/// A filter's pill.
private struct ChipStyle: ButtonStyle {
    let selected: Bool

    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .font(.subheadline.weight(.semibold))
            .padding(.horizontal, 14)
            .padding(.vertical, 7)
            .foregroundStyle(selected ? Color(light: 0xFFFBF5, dark: 0x1D160E) : Color.primary)
            .background(selected ? OSM.accent : OSM.card, in: Capsule())
            .overlay(Capsule().stroke(selected ? Color.clear : OSM.hairline, lineWidth: 1))
            .opacity(configuration.isPressed ? 0.8 : 1)
    }
}

/// What is not about one item: the lists that bring things back, this phone's
/// password, filling in other apps.
private struct SettingsList: View {
    @ObservedObject var model: VaultModel
    /// Whether this app fills logins in other apps: unknown until the system says.
    @State private var autofill: Bool?
    @Environment(\.scenePhase) private var scenePhase

    var body: some View {
        List {
            Section("Vault") {
                row("Recently deleted", "Bring back what any device deleted", model.openDeleted)
                    .accessibilityIdentifier("recently-deleted")
                row("Change this phone's password", "Only this phone's: other devices keep their own", model.openPasswordChange)
                    .accessibilityIdentifier("change-password")
            }
            .listRowBackground(OSM.card)
            Section("Filling and syncing") {
                if autofill == false {
                    AutofillOffer(enabled: $autofill)
                } else if autofill == true {
                    Label("Filling logins in other apps is on", systemImage: "checkmark.circle.fill")
                        .foregroundStyle(OSM.good)
                }
                SyncLine(model: model)
            }
            .listRowBackground(OSM.card)
        }
        .scrollContentBackground(.hidden)
        .background(OSM.background)
        .task(id: scenePhase) {
            if scenePhase == .active { autofill = await ASCredentialIdentityStore.shared.state().isEnabled }
        }
    }

    private func row(_ title: String, _ help: String, _ action: @escaping () -> Void) -> some View {
        Button(action: action) {
            HStack {
                VStack(alignment: .leading, spacing: 2) {
                    Text(title).foregroundStyle(.primary)
                    Text(help).font(.caption).foregroundStyle(.secondary)
                }
                Spacer()
                Image(systemName: "chevron.right").font(.footnote.weight(.semibold)).foregroundStyle(.tertiary)
            }
            .contentShape(Rectangle())
        }
    }
}

/// Until the owner turns on filling with this app: the way to the setting.
private struct AutofillOffer: View {
    @Binding var enabled: Bool?

    var body: some View {
        Button("Fill logins in other apps…", action: turnOn).accessibilityIdentifier("turn-on-autofill")
    }

    private func turnOn() {
        if #available(iOS 18, *) {
            ASSettingsHelper.requestToTurnOnCredentialProviderExtension { on in
                Task { @MainActor in enabled = on }
            }
        } else {
            ASSettingsHelper.openCredentialProviderAppSettings { _ in }
        }
    }
}

private struct Detail: View {
    @ObservedObject var model: VaultModel
    let detail: ItemDetail
    @State private var confirmingDelete = false
    @State private var removing: PasskeyDetail?

    private var editable: Bool {
        detail.kind != .identity && !detail.conflict
    }

    var body: some View {
        List {
            Section {
                HStack(spacing: 14) {
                    ItemAvatar(title: detail.title, kind: detail.kind, size: 52)
                    Text(detail.title).font(.title2.bold())
                }
                .listRowBackground(Color.clear)
                .listRowInsets(EdgeInsets(top: 8, leading: 4, bottom: 8, trailing: 4))
            }
            Section {
                if detail.conflict {
                    Text("Two devices changed this at once. Choose which version to keep on your computer.")
                        .foregroundStyle(.red)
                }
                if let told = model.attention[detail.id] {
                    VStack(alignment: .leading, spacing: 4) {
                        Text("Worth changing this password").font(.subheadline.weight(.semibold))
                        Text(told.joined(separator: " ")).font(.subheadline)
                    }
                    .accessibilityElement(children: .combine)
                    .accessibilityIdentifier("attention-note")
                }
                if editable {
                    HStack(spacing: 12) {
                        Button("Edit") { model.startEdit(detail) }.accessibilityIdentifier("edit")
                        Button("Delete…") { confirmingDelete = true }.accessibilityIdentifier("delete")
                    }
                    .buttonStyle(.bordered)
                    .listRowBackground(Color.clear)
                    .listRowInsets(EdgeInsets(top: 0, leading: 4, bottom: 8, trailing: 4))
                } else if !detail.conflict {
                    Text("Identities are edited on your computer.").accessibilityIdentifier("edit-elsewhere")
                }
                // A card's own fields: its number by its last four digits
                // only, and the number and code copied rather than shown,
                // as on the computer.
                if let card = detail.card {
                    if !card.cardholder.isEmpty {
                        Field(label: "Cardholder name", value: card.cardholder, identifier: "card-cardholder") {
                            Button("Copy") { model.copyField(detail.id, "Cardholder name") }.accessibilityIdentifier("copy-field:Cardholder name")
                        }
                    }
                    if card.hasNumber {
                        Field(label: "Number", value: card.numberEnding.map { "•••• \($0)" } ?? "••••••••", identifier: "card-number") {
                            Button("Copy") { model.copyField(detail.id, "Number") }.accessibilityIdentifier("copy-field:Number")
                        }
                    }
                    if !card.expiryMonth.isEmpty || !card.expiryYear.isEmpty {
                        Field(label: "Expires", value: "\(card.expiryMonth.isEmpty ? "--" : card.expiryMonth) / \(card.expiryYear.isEmpty ? "----" : card.expiryYear)", identifier: "card-expiry") {}
                    }
                    if card.hasSecurityCode {
                        Field(label: "Security code", value: "•••", identifier: "card-code") {
                            Button("Copy") { model.copyField(detail.id, "Security code") }.accessibilityIdentifier("copy-field:Security code")
                        }
                    }
                    if !card.brand.isEmpty { Field(label: "Brand", value: card.brand, identifier: "card-brand") {} }
                }
                if !detail.username.isEmpty {
                    Field(label: "Username", value: detail.username, identifier: "detail-username") {
                        Button("Copy") { model.copyUsername(detail) }
                    }
                }
                if detail.hasPassword {
                    Field(label: "Password", value: "••••••••••") {
                        Button("Copy") { model.copyPassword(detail.id) }.accessibilityIdentifier("copy-password")
                    }
                }
                if detail.hasOneTimeCode {
                    Field(label: "One-time code", value: "••• •••") {
                        Button("Copy") { model.copyOneTimeCode(detail.id) }.accessibilityIdentifier("copy-code")
                    }
                }
                if !detail.url.isEmpty { Field(label: "Website", value: detail.url) {} }
                // A login's passkeys, by site and account; never a key.
                ForEach(detail.passkeys, id: \.credentialId) { passkey in
                    Field(label: "Passkey for \(passkey.rpId)", value: passkeyAccount(passkey), identifier: "passkey:\(passkey.rpId)") {
                        if !detail.conflict {
                            Button("Remove") { removing = passkey }.accessibilityIdentifier("remove-passkey:\(passkey.rpId)")
                        }
                    }
                }
                // An identity's address, a login's own extras: named, and
                // copied rather than shown, as on the computer.
                ForEach(detail.fields, id: \.self) { name in
                    Field(label: name, value: "••••••••", identifier: "field:\(name)") {
                        Button("Copy") { model.copyField(detail.id, name) }.accessibilityIdentifier("copy-field:\(name)")
                    }
                }
                if !detail.notes.isEmpty { Field(label: "Notes", value: detail.notes, identifier: "detail-notes") {} }
            }
            .listRowBackground(OSM.card)
            Section {
                Button("History: every version, and which device made it") { model.openHistory(detail) }
                    .accessibilityIdentifier("history")
            }
            .listRowBackground(OSM.card)
        }
        .scrollContentBackground(.hidden)
        .background(OSM.background)
        .alert("Delete \(detail.title)?", isPresented: $confirmingDelete) {
            Button("Delete", role: .destructive) { model.delete(detail) }.accessibilityIdentifier("confirm-delete")
            Button("Keep", role: .cancel) {}.accessibilityIdentifier("keep")
        } message: {
            Text("It is deleted on all your devices. Its earlier versions stay in the vault's history and in backups.")
        }
        .alert("Remove this passkey?", isPresented: Binding(get: { removing != nil }, set: { if !$0 { removing = nil } }), presenting: removing) { passkey in
            Button("Remove", role: .destructive) { model.removePasskey(detail, passkey) }.accessibilityIdentifier("confirm-remove-passkey")
            Button("Keep", role: .cancel) {}.accessibilityIdentifier("keep")
        } message: { passkey in
            Text("It is removed on all your devices, and you will no longer sign in to \(passkey.rpId) with it. Its key stays in this item's history and in backups.")
        }
    }
}

/// The account a passkey is for, and when it was made, if that is known.
private func passkeyAccount(_ passkey: PasskeyDetail) -> String {
    let account = passkey.userName.isEmpty ? "No account name"
        : !passkey.userDisplayName.isEmpty && passkey.userDisplayName != passkey.userName ? "\(passkey.userName) (\(passkey.userDisplayName))"
        : passkey.userName
    guard passkey.createdAt > 0 else { return account }
    return "\(account) · made \(Date(timeIntervalSince1970: TimeInterval(passkey.createdAt)).formatted(date: .abbreviated, time: .omitted))"
}

/// Whether a phone restores items of `kind`: all but identities.
private func restoresHere(_ kind: ItemKind) -> Bool {
    kind != .identity
}


/// A time a device recorded, in seconds since 1970, as this phone writes dates.
private func savedTime(_ seconds: UInt64) -> String {
    Date(timeIntervalSince1970: TimeInterval(seconds)).formatted(date: .abbreviated, time: .shortened)
}

private func said(_ version: HistoryEntry) -> String {
    if version.deleted { return "Deleted the item" }
    if version.first { return "Made the item" }
    if version.merged { return "Settled a conflict between versions" }
    if !version.changed.isEmpty { return "Changed \(version.changed.joined(separator: ", "))" }
    return "Saved without a change"
}

/// An item's versions, newest first; one that is not current can be brought back.
private struct HistoryList: View {
    @ObservedObject var model: VaultModel
    let history: History
    @State private var confirming: HistoryEntry?

    private var restorable: Bool {
        restoresHere(history.detail.kind) && history.versions.filter(\.current).count == 1
    }

    var body: some View {
        List {
          Group {
            Section {
                Text("Newest first. Restoring a version makes it the newest; the others stay. Each time is by the clock of the device that saved the version; versions saved before times were kept have none.")
                if !restorable {
                    Text("Identities, and items in conflict, are restored on your computer.")
                        .accessibilityIdentifier("restore-elsewhere")
                }
            }
            ForEach(Array(history.versions.enumerated()), id: \.element.revision) { index, version in
                Section {
                  VStack(alignment: .leading, spacing: 4) {
                    HStack(spacing: 8) {
                        Text(version.thisDevice ? "This phone" : "Device \(version.device)").font(.headline)
                        if version.current {
                            Text("CURRENT")
                                .font(.caption2.weight(.bold))
                                .padding(.horizontal, 8)
                                .padding(.vertical, 2)
                                .foregroundStyle(OSM.accent)
                                .background(OSM.accent.opacity(0.16), in: Capsule())
                        }
                    }
                    Text(version.savedAt.map(savedTime) ?? "Time not recorded")
                        .font(.caption)
                        .accessibilityIdentifier("time-\(index)")
                    Text(said(version)).accessibilityIdentifier("said-\(index)")
                    if !version.deleted {
                        Text([version.title, version.username, version.url].filter { !$0.isEmpty }.joined(separator: " · "))
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                    if restorable && !version.current && !version.deleted {
                        Button("Restore this version…") { confirming = version }
                            .buttonStyle(.borderless)
                            .padding(.top, 4)
                            .accessibilityIdentifier("restore-\(index)")
                    }
                  }
                }
            }
          }
          .listRowBackground(OSM.card)
        }
        .osmList()
        .alert("Restore this version?", isPresented: Binding(get: { confirming != nil }, set: { if !$0 { confirming = nil } })) {
            Button("Restore") { if let version = confirming { model.restore(version) } }.accessibilityIdentifier("confirm-restore")
            Button("Keep the current", role: .cancel) {}.accessibilityIdentifier("keep")
        } message: {
            Text("It becomes the newest version on all your devices. The current one stays in the history.")
        }
    }
}

/// The items deleted on any device, which can be brought back as they were.
/// This phone's password changed, given the current one.
private struct PasswordChange: View {
    @ObservedObject var model: VaultModel
    @State private var current = ""
    @State private var newPassword = ""
    @State private var again = ""

    /// In characters, as the shared code counts them.
    private var long: Bool { newPassword.unicodeScalars.count >= 12 }

    private var problem: String? {
        if !newPassword.isEmpty && !long { return "Use at least 12 characters" }
        if !again.isEmpty && again != newPassword { return "The two passwords differ" }
        return nil
    }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 14) {
                SecureField("Current password", text: $current)
                    .osmField()
                    .accessibilityIdentifier("current-password")
                SecureField("New password, at least 12 characters", text: $newPassword)
                    .osmField()
                    .accessibilityIdentifier("new-password")
                SecureField("New password again", text: $again)
                    .osmField()
                    .accessibilityIdentifier("new-password-again")
                if let problem {
                    Text(problem).font(.caption).foregroundStyle(.red).accessibilityIdentifier("password-problem")
                }
                Text("Only this phone's password changes: your other devices keep their own, and the recovery key opens the vault as before. Unlocking with \(model.biometric.name) is turned off, to be turned on again at the next unlock.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                Button("Change password") { model.changePassword(current: current, newPassword: newPassword) }
                    .buttonStyle(.wide)
                    .disabled(current.isEmpty || !long || again != newPassword || model.busy != nil)
                    .accessibilityIdentifier("save-password")
            }
            .padding(24)
        }
        .osmScreen()
    }
}

private struct DeletedList: View {
    @ObservedObject var model: VaultModel
    let deleted: [DeletedEntry]

    var body: some View {
        List {
          Group {
            Section {
                Text(deleted.isEmpty
                    ? "Nothing has been deleted."
                    : "Deleted on any of your devices, most recently first. Restoring one brings it back on all of them, as it was before it was deleted.")
                    .foregroundStyle(.secondary)
                    .accessibilityIdentifier("deleted-hint")
            }
            .listRowBackground(Color.clear)
            ForEach(deleted, id: \.id) { entry in
                Section {
                    HStack(alignment: .top, spacing: 12) {
                        ItemAvatar(title: entry.title, kind: entry.kind)
                        VStack(alignment: .leading, spacing: 3) {
                            Text(entry.title).font(.headline).accessibilityIdentifier("deleted:\(entry.title)")
                            let shown = [entry.username, entry.url].filter { !$0.isEmpty }
                            if !shown.isEmpty { Text(shown.joined(separator: " · ")).font(.caption).foregroundStyle(.secondary) }
                            Text("Deleted on " + (entry.thisDevice ? "this phone" : "device \(entry.device)")
                                + (entry.deletedAt.map { " · " + savedTime($0) } ?? "")).font(.caption).foregroundStyle(.secondary)
                            if restoresHere(entry.kind) {
                                Button("Restore") { model.restoreDeleted(entry) }
                                    .buttonStyle(.bordered)
                                    .padding(.top, 4)
                                    .accessibilityIdentifier("restore:\(entry.title)")
                            } else {
                                Text("Identities are restored on your computer.").font(.caption)
                            }
                        }
                    }
                }
            }
          }
          .listRowBackground(OSM.card)
        }
        .osmList()
    }
}

/// Writing a login or a secure note: a new one, or `detail` as it was read.
/// A blank password or one-time code secret keeps what the item has.
private struct ItemEditor: View {
    @ObservedObject var model: VaultModel
    let detail: ItemDetail?
    let changedElsewhere: [String]
    @State private var kind: ItemKind
    @State private var title: String
    @State private var username: String
    @State private var url: String
    @State private var password: String
    @State private var showPassword: Bool
    /// The password the generator made, which the field holds until the owner types over it.
    @State private var made: String?
    @State private var generatorOpen = false
    @State private var code: String
    @State private var removeCode: Bool
    @State private var notes: String
    @State private var favorite: Bool
    @State private var cardholder: String
    @State private var number: String
    @State private var showNumber = false
    @State private var expiryMonth: String
    @State private var expiryYear: String
    @State private var securityCode: String
    @State private var removeSecurityCode: Bool
    /// The brand the owner typed; `nil` until then, for the one the number names.
    @State private var brand: String?

    /// Starts from the editor's draft when it has one, otherwise from the
    /// item as it was read (or empty, for a new item).
    init(model: VaultModel, editor: Editor) {
        self.model = model
        let detail = editor.detail
        self.detail = detail
        changedElsewhere = editor.changedElsewhere
        let draft = editor.draft
        _kind = State(initialValue: draft?.kind ?? detail?.kind ?? .login)
        _title = State(initialValue: draft?.title ?? detail?.title ?? "")
        _username = State(initialValue: draft?.username ?? detail?.username ?? "")
        _url = State(initialValue: draft?.url ?? detail?.url ?? "")
        _password = State(initialValue: draft?.password ?? editor.generated ?? "")
        let made = draft == nil ? editor.generated : nil
        _made = State(initialValue: made)
        _showPassword = State(initialValue: made != nil)
        _code = State(initialValue: draft?.oneTimeCodeSecret ?? "")
        _removeCode = State(initialValue: draft?.oneTimeCodeSecret == "")
        _notes = State(initialValue: draft?.notes ?? detail?.notes ?? "")
        _favorite = State(initialValue: draft?.favorite ?? detail?.favorite ?? false)
        _cardholder = State(initialValue: draft?.card?.cardholder ?? detail?.card?.cardholder ?? "")
        _number = State(initialValue: draft?.card?.number ?? "")
        _expiryMonth = State(initialValue: draft?.card?.expiryMonth ?? detail?.card?.expiryMonth ?? "")
        _expiryYear = State(initialValue: draft?.card?.expiryYear ?? detail?.card?.expiryYear ?? "")
        _securityCode = State(initialValue: draft?.card?.securityCode ?? "")
        _removeSecurityCode = State(initialValue: draft?.card?.securityCode == "")
        _brand = State(initialValue: draft?.card?.brand)
    }

    private func generate() {
        password = model.generatePassword()
        made = password
        showPassword = true
    }

    private var draft: ItemDraft {
        let login = kind == .login
        return ItemDraft(
            title: title,
            kind: kind,
            username: login ? username : "",
            url: login ? url : "",
            notes: notes,
            favorite: favorite,
            password: login && !password.isEmpty ? password : nil,
            oneTimeCodeSecret: !login ? nil : removeCode ? "" : code.trimmingCharacters(in: .whitespaces).isEmpty ? nil : code,
            // Blank, the number and the code stay as they are.
            card: kind != .card ? nil : CardDraft(
                cardholder: cardholder,
                expiryMonth: expiryMonth,
                expiryYear: expiryYear,
                brand: brand,
                number: number.isEmpty ? nil : number,
                securityCode: removeSecurityCode ? "" : securityCode.trimmingCharacters(in: .whitespaces).isEmpty ? nil : securityCode
            )
        )
    }

    private var numberCheck: CardNumberCheck { checkCardNumber(number: number) }

    var body: some View {
        Form {
          Group {
            if !changedElsewhere.isEmpty {
                Section {
                    VStack(alignment: .leading, spacing: 4) {
                        Text("Another device changed this item while you edited it").font(.headline)
                        Text("It changed its \(changedElsewhere.joined(separator: ", ")). What you typed is kept, on top of the item as it is now; nothing is saved until you save.")
                            .font(.callout)
                            .foregroundStyle(.secondary)
                    }
                    .accessibilityElement(children: .combine)
                    .accessibilityIdentifier("changed-elsewhere")
                }
            }
            Section {
                Picker("Kind", selection: $kind) {
                    Text("Login").tag(ItemKind.login)
                    Text("Secure note").tag(ItemKind.secureNote)
                    Text("Card").tag(ItemKind.card)
                }
                .pickerStyle(.segmented)
                .accessibilityIdentifier("edit-kind")
                LabeledContent("Title") {
                    TextField("Title", text: $title).accessibilityIdentifier("edit-title")
                }
            }
            if kind == .login {
                Section {
                    LabeledContent("Username") {
                        TextField("Username", text: $username)
                            .textInputAutocapitalization(.never)
                            .autocorrectionDisabled()
                            .accessibilityIdentifier("edit-username")
                    }
                    LabeledContent("Website") {
                        TextField("https://", text: $url)
                            .keyboardType(.URL)
                            .textInputAutocapitalization(.never)
                            .autocorrectionDisabled()
                            .accessibilityIdentifier("edit-url")
                    }
                }
                Section {
                    // Marked as codes, these fields are left alone by iOS's
                    // Automatic Strong Passwords, which otherwise takes this
                    // form for a sign-up and fills them with a password of
                    // its own.
                    Group {
                        if showPassword {
                            TextField("Password", text: $password)
                                .textInputAutocapitalization(.never)
                                .autocorrectionDisabled()
                        } else {
                            SecureField(detail?.hasPassword == true ? "Unchanged" : "Password", text: $password)
                        }
                    }
                    .textContentType(.oneTimeCode)
                    .accessibilityIdentifier("edit-password")
                    HStack {
                        Button(showPassword ? "Hide" : "Show") { showPassword.toggle() }.accessibilityIdentifier("show-password")
                        Spacer()
                        Button("Clear") { password = "" }
                            .disabled(password.isEmpty)
                            .accessibilityIdentifier("clear-password")
                        Spacer()
                        Button(generatorOpen ? "Close options" : "Options") { generatorOpen.toggle() }
                            .accessibilityIdentifier("generator-open")
                        Spacer()
                        Button("Generate", action: generate).accessibilityIdentifier("generate")
                    }
                    .buttonStyle(.borderless)
                    // Each change makes the password again with it.
                    if generatorOpen {
                        GeneratorOptions { generate() }
                    }
                } footer: {
                    if made != nil && password == made {
                        Text("Made for this item with the generator's choice. Type over it, or clear it.")
                            .accessibilityIdentifier("password-made")
                    } else if detail?.hasPassword == true {
                        Text("Left blank, the password stays as it is.")
                    }
                }
                Section {
                    SecureField(detail?.hasOneTimeCode == true ? "Unchanged" : "One-time code secret (optional)", text: $code)
                        .textContentType(.oneTimeCode)
                        .disabled(removeCode)
                        .accessibilityIdentifier("edit-code")
                    if detail?.hasOneTimeCode == true {
                        Toggle("Remove the one-time code", isOn: $removeCode).accessibilityIdentifier("remove-code")
                    }
                } footer: {
                    if detail?.hasOneTimeCode == true { Text("Left blank, the one-time code stays as it is.") }
                }
            }
            if kind == .card {
                Section {
                    LabeledContent("Cardholder name") {
                        TextField("Cardholder name", text: $cardholder)
                            .autocorrectionDisabled()
                            .accessibilityIdentifier("edit-cardholder")
                    }
                    // Marked as codes, as the password is, so that iOS
                    // offers nothing of its own here.
                    Group {
                        if showNumber {
                            TextField("Number", text: $number)
                        } else {
                            SecureField(detail?.card?.hasNumber == true ? "Unchanged" + (detail?.card?.numberEnding.map { " (•••• \($0))" } ?? "") : "Number", text: $number)
                        }
                    }
                    .keyboardType(.numberPad)
                    .textContentType(.oneTimeCode)
                    .accessibilityIdentifier("edit-number")
                    Button(showNumber ? "Hide" : "Show") { showNumber.toggle() }
                        .buttonStyle(.borderless)
                        .accessibilityIdentifier("show-number")
                    if numberCheck.complete && !numberCheck.passes {
                        Text("This number fails a card number's check: a digit may be mistyped. It is saved as typed.")
                            .font(.caption)
                            .foregroundStyle(.red)
                            .accessibilityIdentifier("number-check")
                    }
                    HStack {
                        TextField("MM", text: $expiryMonth)
                            .keyboardType(.numberPad)
                            .accessibilityIdentifier("edit-expiry-month")
                        Text("/")
                        TextField("YYYY", text: $expiryYear)
                            .keyboardType(.numberPad)
                            .accessibilityIdentifier("edit-expiry-year")
                    }
                    SecureField(detail?.card?.hasSecurityCode == true ? "Unchanged" : "Security code", text: $securityCode)
                        .keyboardType(.numberPad)
                        .textContentType(.oneTimeCode)
                        .disabled(removeSecurityCode)
                        .accessibilityIdentifier("edit-security-code")
                    if detail?.card?.hasSecurityCode == true {
                        Toggle("Remove the security code", isOn: $removeSecurityCode).accessibilityIdentifier("remove-security-code")
                    }
                    // Untouched, the brand is the one a new number names, or else the stored one.
                    LabeledContent("Brand") {
                        TextField("From the number", text: Binding(
                            get: { brand ?? (number.isEmpty ? detail?.card?.brand ?? "" : numberCheck.brand ?? "") },
                            set: { brand = $0 }
                        ))
                        .autocorrectionDisabled()
                        .accessibilityIdentifier("edit-brand")
                    }
                } footer: {
                    if detail?.card?.hasNumber == true { Text("Left blank, the number and the security code stay as they are.") }
                }
            }
            Section {
                TextField("Notes", text: $notes, axis: .vertical)
                    .lineLimit(kind == .secureNote ? 6...12 : 3...8)
                    .accessibilityIdentifier("edit-notes")
                Toggle("Favorite", isOn: $favorite).accessibilityIdentifier("edit-favorite")
            }
          }
          .listRowBackground(OSM.card)
        }
        .osmList()
        .navigationTitle(detail == nil ? "New item" : "Edit item")
        .toolbar {
            ToolbarItem(placement: .cancellationAction) {
                Button("Cancel", action: model.closeEditor).accessibilityIdentifier("cancel-edit")
            }
            ToolbarItem(placement: .confirmationAction) {
                Button("Save") { model.save(draft) }
                    .disabled(title.trimmingCharacters(in: .whitespaces).isEmpty || model.busy != nil)
                    .accessibilityIdentifier("save")
            }
        }
    }
}

/// A labelled value, with an action beside it.
private struct Field<Action: View>: View {
    let label: String
    let value: String
    var identifier: String?
    @ViewBuilder let action: () -> Action

    var body: some View {
        HStack {
            VStack(alignment: .leading, spacing: 2) {
                Text(label).font(.caption).foregroundStyle(.secondary)
                Text(value).accessibilityIdentifier(identifier ?? "")
            }
            Spacer()
            action().buttonStyle(.borderless)
        }
    }
}

private struct SyncLine: View {
    @ObservedObject var model: VaultModel

    private var text: String {
        guard let sync = model.sync else { return "Offline" }
        let state: String = switch sync.state {
        case .offline: "Offline"
        case .syncing: "Syncing…"
        case .removed: "Removed from the vault"
        case .error: "Last sync failed" + (sync.message.map { " · \($0)" } ?? "")
        default: sync.lastSyncedAt.map {
                "Synced " + RelativeDateTimeFormatter().localizedString(for: Date(timeIntervalSince1970: TimeInterval($0)), relativeTo: Date())
            } ?? "Not synced yet"
        }
        let members = Int(sync.members)
        return state + (members > 0 ? " · \(members) other \(members == 1 ? "device" : "devices")" : "")
    }

    var body: some View {
        HStack {
            Text(text).font(.caption).accessibilityIdentifier("sync")
            Spacer()
            Button("Sync now", action: model.syncNow).buttonStyle(.borderless)
        }
    }
}

/// The generator's choice, to change, kept as it changes (`Generator`): the
/// length, the kinds of characters, the last of which cannot be turned off,
/// and the look-alikes. `onChange` follows each change.
struct GeneratorOptions: View {
    let onChange: () -> Void
    @State private var options = Generator.options

    private struct Kind: Identifiable {
        let label: String
        let path: WritableKeyPath<PasswordOptions, Bool>
        var id: String { label }
    }

    private let kinds = [
        Kind(label: "A–Z", path: \.uppercase), Kind(label: "a–z", path: \.lowercase),
        Kind(label: "0–9", path: \.digits), Kind(label: "!@#$", path: \.symbols),
    ]

    var body: some View {
        let chosen = kinds.filter { options[keyPath: $0.path] }.count
        VStack(alignment: .leading, spacing: 8) {
            Text("Length \(options.length)").accessibilityIdentifier("generator-length-shown")
            Slider(
                value: Binding(get: { Double(options.length) }, set: { value in
                    let length = UInt32(value.rounded())
                    if length != options.length { change { $0.length = length } }
                }),
                in: Double(Generator.lengths.lowerBound)...Double(Generator.lengths.upperBound),
                step: 1
            )
            .accessibilityIdentifier("generator-length")
            ForEach(kinds) { kind in
                Toggle(kind.label, isOn: Binding(get: { options[keyPath: kind.path] }, set: { on in change { $0[keyPath: kind.path] = on } }))
                    .disabled(options[keyPath: kind.path] && chosen == 1)
                    .accessibilityIdentifier("generator-kind:\(kind.label)")
            }
            Toggle("Avoid look-alikes: l I 1 O 0", isOn: Binding(get: { options.avoidLookAlike }, set: { on in change { $0.avoidLookAlike = on } }))
                .accessibilityIdentifier("generator-avoid-look-alike")
        }
    }

    private func change(_ edit: (inout PasswordOptions) -> Void) {
        edit(&options)
        Generator.options = options
        onChange()
    }
}
