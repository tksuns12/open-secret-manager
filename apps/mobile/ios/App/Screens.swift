import AuthenticationServices
import SwiftUI

struct RootView: View {
    @ObservedObject var model: VaultModel

    var body: some View {
        NavigationStack {
            content
                .navigationTitle("Open Secret Manager")
                .navigationBarTitleDisplayMode(.inline)
                .toolbar {
                    if model.screen == .unlocked && model.editor == nil {
                        if model.detail == nil && model.history == nil && model.deleted == nil && !model.passwordChange {
                            ToolbarItem(placement: .topBarLeading) {
                                Button("New", action: model.startNew).accessibilityIdentifier("new-item")
                            }
                        }
                        ToolbarItem(placement: .primaryAction) {
                            Button("Lock", action: model.lock).accessibilityIdentifier("lock")
                        }
                    }
                }
        }
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
        case .unlocked:
            if let editor = model.editor {
                // A new editor, as after a save that met a change made
                // elsewhere, starts from what it holds.
                ItemEditor(model: model, editor: editor).id(editor)
            } else if let history = model.history {
                HistoryList(model: model, history: history)
            } else if let deleted = model.deleted {
                DeletedList(model: model, deleted: deleted)
            } else if model.passwordChange {
                PasswordChange(model: model)
            } else if let detail = model.detail {
                Detail(model: model, detail: detail)
            } else {
                Items(model: model)
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
        VStack(alignment: .leading, spacing: 8) {
            Text(title).font(.title2).accessibilityIdentifier("message")
            if let detail { Text(detail) }
        }
        .padding(24)
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .leading)
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
            VStack(alignment: .leading, spacing: 12) {
                Text("Join your vault").font(.title2)
                if InvitationScanner.available {
                    Text("On your computer, open Devices, choose Invite a device, and pick a phone. Scan the QR code it shows, or paste the invitation here.")
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
                    .buttonStyle(.borderedProminent)
                    .disabled(model.busy != nil)
                    .accessibilityIdentifier("join-scan")
                } else {
                    Text("On your computer, open Devices, choose Invite a device, and pick a phone. Paste the invitation here.")
                }
                TextField("Invitation", text: $invitation, axis: .vertical)
                    .lineLimit(3...6)
                    .textFieldStyle(.roundedBorder)
                    .autocorrectionDisabled()
                    .textInputAutocapitalization(.never)
                    .accessibilityIdentifier("invitation")
                Button("Continue") { model.joinStart(invitation) }
                    .buttonStyle(.borderedProminent)
                    .disabled(invitation.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty || model.busy != nil)
                    .accessibilityIdentifier("join-continue")
            }
            .padding(24)
        }
    }
}

private struct JoinConfirm: View {
    @ObservedObject var model: VaultModel
    @State private var password = ""
    @State private var again = ""

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 12) {
                Text("Compare the codes").font(.title2)
                Text("Your computer shows a code too. Continue only if they are identical.")
                Text(model.joinCode ?? "")
                    .font(.system(size: 34, design: .monospaced))
                    .accessibilityIdentifier("join-code")
                Text("This phone's password: at least 12 characters. Your other devices keep their own.")
                SecureField("New password for this phone", text: $password)
                    .textFieldStyle(.roundedBorder)
                    .accessibilityIdentifier("new-password")
                SecureField("The same again", text: $again)
                    .textFieldStyle(.roundedBorder)
                    .accessibilityIdentifier("new-password-again")
                HStack(spacing: 12) {
                    Button("They differ", action: model.cancelJoin)
                        .buttonStyle(.bordered)
                        .disabled(model.busy != nil)
                    Button("Codes match · join") { model.joinFinish(password) }
                        .buttonStyle(.borderedProminent)
                        .disabled(password.count < 12 || password != again || model.busy != nil)
                        .accessibilityIdentifier("join-finish")
                }
            }
            .padding(24)
        }
    }
}

private struct Items: View {
    @ObservedObject var model: VaultModel
    @State private var query = ""
    /// Whether this app fills logins in other apps: unknown until the system says.
    @State private var autofill: Bool?
    @Environment(\.scenePhase) private var scenePhase

    private var shown: [ItemSummary] {
        guard !query.isEmpty else { return model.items }
        return model.items.filter {
            $0.title.localizedCaseInsensitiveContains(query) || $0.username.localizedCaseInsensitiveContains(query)
                || $0.url.localizedCaseInsensitiveContains(query)
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
            }
            ForEach(shown, id: \.id) { item in
                Button { model.open(item.id) } label: {
                    VStack(alignment: .leading, spacing: 2) {
                        Text(item.title + (item.conflict ? " · needs a decision on your computer" : ""))
                        let below = item.kind == .card ? cardLine(brand: item.brand, ending: item.cardEnding) : item.username
                        if !below.isEmpty {
                            Text(below).font(.caption).foregroundStyle(.secondary)
                        }
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .contentShape(Rectangle())
                }
                .buttonStyle(.plain)
                .accessibilityIdentifier("item:\(item.title)")
            }
            Section {
                Button("Recently deleted…", action: model.openDeleted).accessibilityIdentifier("recently-deleted")
                Button("Change this phone's password…", action: model.openPasswordChange).accessibilityIdentifier("change-password")
                if autofill == false { AutofillOffer(enabled: $autofill) }
                SyncLine(model: model)
            }
        }
        .searchable(text: $query)
        .task(id: scenePhase) {
            if scenePhase == .active { autofill = await ASCredentialIdentityStore.shared.state().isEnabled }
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

    private var editable: Bool {
        detail.kind != .identity && !detail.conflict
    }

    var body: some View {
        List {
            Section {
                Button("‹ All items", action: model.close).accessibilityIdentifier("back")
            }
            Section {
                Text(detail.title).font(.title2)
                if detail.conflict {
                    Text("Two devices changed this at once. Choose which version to keep on your computer.")
                        .foregroundStyle(.red)
                }
                if editable {
                    HStack(spacing: 12) {
                        Button("Edit") { model.startEdit(detail) }.accessibilityIdentifier("edit")
                        Button("Delete…") { confirmingDelete = true }.accessibilityIdentifier("delete")
                    }
                    .buttonStyle(.bordered)
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
                // An identity's address, a login's own extras: named, and
                // copied rather than shown, as on the computer.
                ForEach(detail.fields, id: \.self) { name in
                    Field(label: name, value: "••••••••", identifier: "field:\(name)") {
                        Button("Copy") { model.copyField(detail.id, name) }.accessibilityIdentifier("copy-field:\(name)")
                    }
                }
                if !detail.notes.isEmpty { Field(label: "Notes", value: detail.notes, identifier: "detail-notes") {} }
            }
            Section {
                Button("History: every version, and which device made it") { model.openHistory(detail) }
                    .accessibilityIdentifier("history")
            }
        }
        .alert("Delete \(detail.title)?", isPresented: $confirmingDelete) {
            Button("Delete", role: .destructive) { model.delete(detail) }.accessibilityIdentifier("confirm-delete")
            Button("Keep", role: .cancel) {}.accessibilityIdentifier("keep")
        } message: {
            Text("It is deleted on all your devices. Its earlier versions stay in the vault's history and in backups.")
        }
    }
}

/// Whether a phone restores items of `kind`: all but identities.
private func restoresHere(_ kind: ItemKind) -> Bool {
    kind != .identity
}

/// A card as a list names it: its brand and the last four digits of its number, nothing else of it.
func cardLine(brand: String?, ending: String?) -> String {
    let brand = (brand?.trimmingCharacters(in: .whitespaces).isEmpty ?? true) ? "Card" : brand!
    return [brand, ending.map { "•••• \($0)" }].compactMap { $0 }.joined(separator: " ")
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
            Section {
                Button("‹ \(history.detail.title)", action: model.closeHistory).accessibilityIdentifier("back")
            }
            Section {
                Text("Newest first. Restoring a version makes it the newest; the others stay. Each time is by the clock of the device that saved the version; versions saved before times were kept have none.")
                if !restorable {
                    Text("Identities, and items in conflict, are restored on your computer.")
                        .accessibilityIdentifier("restore-elsewhere")
                }
            }
            ForEach(Array(history.versions.enumerated()), id: \.element.revision) { index, version in
                Section {
                    Text((version.thisDevice ? "This phone" : "Device \(version.device)") + (version.current ? " · current" : ""))
                        .font(.headline)
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
                        Button("Restore this version…") { confirming = version }.accessibilityIdentifier("restore-\(index)")
                    }
                }
            }
        }
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
            VStack(alignment: .leading, spacing: 12) {
                Button("‹ All items", action: model.closePasswordChange).accessibilityIdentifier("back")
                Text("Change this phone's password").font(.title2)
                SecureField("Current password", text: $current)
                    .textFieldStyle(.roundedBorder)
                    .accessibilityIdentifier("current-password")
                SecureField("New password, at least 12 characters", text: $newPassword)
                    .textFieldStyle(.roundedBorder)
                    .accessibilityIdentifier("new-password")
                SecureField("New password again", text: $again)
                    .textFieldStyle(.roundedBorder)
                    .accessibilityIdentifier("new-password-again")
                if let problem {
                    Text(problem).font(.caption).foregroundStyle(.red).accessibilityIdentifier("password-problem")
                }
                Text("Only this phone's password changes: your other devices keep their own, and the recovery key opens the vault as before. Unlocking with \(model.biometric.name) is turned off, to be turned on again at the next unlock.")
                    .font(.caption)
                Button("Change password") { model.changePassword(current: current, newPassword: newPassword) }
                    .buttonStyle(.borderedProminent)
                    .disabled(current.isEmpty || !long || again != newPassword || model.busy != nil)
                    .accessibilityIdentifier("save-password")
            }
            .padding(24)
        }
    }
}

private struct DeletedList: View {
    @ObservedObject var model: VaultModel
    let deleted: [DeletedEntry]

    var body: some View {
        List {
            Section {
                Button("‹ All items", action: model.closeDeleted).accessibilityIdentifier("back")
            }
            Section {
                Text(deleted.isEmpty
                    ? "Nothing has been deleted."
                    : "Deleted on any of your devices, most recently first. Restoring one brings it back on all of them, as it was before it was deleted.")
                    .accessibilityIdentifier("deleted-hint")
            }
            ForEach(deleted, id: \.id) { entry in
                Section {
                    Text(entry.title).font(.headline).accessibilityIdentifier("deleted:\(entry.title)")
                    let shown = [entry.username, entry.url].filter { !$0.isEmpty }
                    if !shown.isEmpty { Text(shown.joined(separator: " · ")).font(.caption).foregroundStyle(.secondary) }
                    Text("Deleted on " + (entry.thisDevice ? "this phone" : "device \(entry.device)")
                        + (entry.deletedAt.map { " · " + savedTime($0) } ?? "")).font(.caption)
                    if restoresHere(entry.kind) {
                        Button("Restore") { model.restoreDeleted(entry) }.accessibilityIdentifier("restore:\(entry.title)")
                    } else {
                        Text("Identities are restored on your computer.").font(.caption)
                    }
                }
            }
        }
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
    @State private var showPassword = false
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
        _password = State(initialValue: draft?.password ?? "")
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
                        Button("Generate") {
                            password = model.generatePassword()
                            showPassword = true
                        }
                        .accessibilityIdentifier("generate")
                    }
                    .buttonStyle(.borderless)
                } footer: {
                    if detail?.hasPassword == true { Text("Left blank, the password stays as it is.") }
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
