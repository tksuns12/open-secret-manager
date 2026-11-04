import Foundation

/// What a login form submitted, which the system asks to save.
struct Saving {
    let username: String
    let password: String
    /// A name the system suggests for the login, if any.
    let title: String?
}

/// The fill or save screen's state: the device opened on the vault the app
/// shares, never online, unlocked for this one fill or save and dropped when
/// it ends. A fill is of a login's username and password or, for a field
/// that asks for one, of its current one-time code; for text to insert, of
/// one field of any item.
@MainActor
final class FillModel: ObservableObject {
    enum Stage: Equatable { case opening, locked, unlocked, noVault, removed, unreadable(String), nothingToFill }

    let requester: FillRequester
    /// Set when the screen saves rather than fills.
    let saving: Saving?
    /// Set when the screen fills a one-time code.
    let oneTimeCode: Bool
    /// Set when the screen gives the text of one field of any item.
    let inserting: Bool
    /// For text to insert: the item chosen, and what of it can be inserted.
    @Published private(set) var insertingFrom: (item: ItemSummary, fields: [InsertField])?
    @Published private(set) var stage: Stage = .opening
    /// What may be filled: the logins for the origins, or those chosen for the app.
    @Published private(set) var offered: [ItemSummary] = []
    /// Every login, once the owner asks to choose one for an app.
    @Published private(set) var all: [ItemSummary]?
    /// For a save: the logins the form could be filled with, under its username.
    @Published private(set) var candidates: [SaveCandidate] = []
    @Published private(set) var busy: String?
    @Published var notice: String?
    let biometric = BiometricUnlock()

    private let queue = DispatchQueue(label: "org.opensecretmanager.autofill")
    private var device: Device?
    /// The request ended: a device still opening is let go at once.
    private var closed = false
    /// A face or a finger was asked for as the screen showed: see `askAtOnce`.
    private var askedAtOnce = false
    /// A face or a finger is being asked for: a second ask would cancel it.
    private var asking = false
    private let onFill: (FillCredentials) -> Void
    private let onCode: (String) -> Void
    private let onSaved: () -> Void
    private let onText: (String) -> Void
    private let onCancel: () -> Void

    init(
        requester: FillRequester,
        saving: Saving? = nil,
        oneTimeCode: Bool = false,
        inserting: Bool = false,
        onFill: @escaping (FillCredentials) -> Void = { _ in },
        onCode: @escaping (String) -> Void = { _ in },
        onSaved: @escaping () -> Void = {},
        onText: @escaping (String) -> Void = { _ in },
        onCancel: @escaping () -> Void
    ) {
        self.requester = requester
        self.saving = saving
        self.oneTimeCode = oneTimeCode
        self.inserting = inserting
        self.onFill = onFill
        self.onCode = onCode
        self.onSaved = onSaved
        self.onText = onText
        self.onCancel = onCancel
        if case .notHTTPS = requester {
            stage = .nothingToFill
            return
        }
        Task { await open() }
    }

    private func call<T>(_ busy: String? = nil, _ work: @escaping (Device) throws -> T) async -> T? {
        if let busy { self.busy = busy }
        defer { if busy != nil { self.busy = nil } }
        do {
            return try await withCheckedThrowingContinuation { continuation in
                queue.async { [device] in
                    guard let device else { return continuation.resume(throwing: MobileError.NoVault) }
                    continuation.resume(with: Result { try work(device) })
                }
            }
        } catch {
            notice = describe(error)
            return nil
        }
    }

    private func open() async {
        do {
            let folder = try DeviceFolder.url()
            let opened = try await withCheckedThrowingContinuation { continuation in
                queue.async {
                    continuation.resume(with: Result {
                        let device = try Device.open(folder: folder.path, keystore: KeychainKeystore.shared)
                        EarlierAppLogins.move(into: device)
                        return device
                    })
                }
            }
            guard !closed else { return }
            device = opened
            switch opened.state() {
            case .locked: stage = .locked
            case .unlocked: await listOffered()
            case .removed: stage = .removed
            case .noVault, .joining: stage = .noVault
            }
        } catch MobileError.UnreadableVault(let reason) {
            stage = .unreadable(reason)
        } catch {
            stage = .unreadable(describe(error))
        }
    }

    func unlock(password: String, keepForBiometrics: Bool) {
        Task {
            guard await call("Unlocking…", { try $0.unlock(password: password) }) != nil else { return }
            if keepForBiometrics { biometric.keep(password) }
            await listOffered()
        }
    }

    /// Asks for a face or a finger as the screen first shows the vault
    /// locked, once per request, if a password is kept for one.
    func askAtOnce() {
        guard !askedAtOnce else { return }
        askedAtOnce = true
        if biometric.available && biometric.enabled { unlockWithBiometrics() }
    }

    func unlockWithBiometrics() {
        guard !asking else { return }
        asking = true
        Task {
            let biometric = biometric
            let reason = saving != nil ? "Unlock the vault to save a login" : inserting ? "Unlock the vault to insert text" : "Unlock the vault to fill a login"
            let outcome = await withCheckedContinuation { continuation in
                DispatchQueue.global().async { continuation.resume(returning: biometric.read(reason: reason)) }
            }
            asking = false
            let password: String
            switch outcome {
            case let .password(kept): password = kept
            case .cancelled: return
            case let .failed(reason):
                notice = reason
                return
            }
            guard await call("Unlocking…", { try $0.unlock(password: password) }) != nil else { return }
            await listOffered()
        }
    }

    private func listOffered() async {
        if inserting {
            // Any item's field, for the field the owner chose.
            offered = await call { device in
                try device.items().sorted { $0.title.localizedCaseInsensitiveCompare($1.title) == .orderedAscending }
            } ?? []
            stage = .unlocked
            return
        }
        // The vault's offer: a page's logins for its origins, an app's chosen
        // logins, nothing for no one named.
        let asked = requester.asked
        let asks = asks
        let found: [ItemSummary]? = await call { device in
            guard let asked else { return [] }
            return try device.offer(requester: asked, asks: asks).logins
        }
        guard let found else { return }
        offered = found.sorted { $0.title.localizedCaseInsensitiveCompare($1.title) == .orderedAscending }
        if saving != nil {
            await listCandidates()
        }
        stage = .unlocked
        if saving == nil, case .unnamed = requester { await chooseAny() }
    }

    /// Of the logins the form could be filled with, those its save could go into.
    private func listCandidates() async {
        guard let saving, let asked = requester.asked else { return }
        candidates = await call { device in
            try device.saveCandidatesFor(requester: asked, username: saving.username, password: saving.password)
        }?.sorted { $0.title.localizedCaseInsensitiveCompare($1.title) == .orderedAscending } ?? []
    }

    /// Every login (with a one-time code, for a code), for an app the owner
    /// chooses one for.
    func chooseAny() async {
        let asks = asks
        all = await call { device in
            try device.loginsToChoose(asks: asks)
                .sorted { $0.title.localizedCaseInsensitiveCompare($1.title) == .orderedAscending }
        }
    }

    /// What the form asks for: a login, or a one-time code.
    private var asks: Asks { oneTimeCode ? .oneTimeCode : .login }

    /// Fills a login the vault offered this requester.
    func fill(_ login: ItemSummary) {
        fill(login, chosenNow: false)
    }

    /// Fills a login the owner chose among every login: for an app, which
    /// the vault then keeps it for, or for a request that names no one.
    func fillChosen(_ login: ItemSummary) {
        fill(login, chosenNow: true)
    }

    private func fill(_ login: ItemSummary, chosenNow: Bool) {
        guard let asked = requester.asked else { return }
        let asks = asks
        Task {
            guard let filled = await call(nil, { device -> Filled in
                try chosenNow
                    ? device.fillChosen(requester: asked, id: login.id, asks: asks)
                    : device.fill(requester: asked, id: login.id, asks: asks)
            }) else { return }
            close()
            if let code = filled.oneTimeCode {
                onCode(code)
            } else if let credentials = filled.credentials {
                onFill(credentials)
            }
        }
    }

    /// What of `item` can be inserted, once the owner chose it.
    func chooseToInsert(_ item: ItemSummary) {
        Task {
            guard let detail = await call(nil, { try $0.item(id: item.id) }) else { return }
            insertingFrom = (item, InsertField.of(detail))
        }
    }

    /// Back to the list of items.
    func chooseAnotherToInsert() {
        insertingFrom = nil
    }

    /// Gives the text of `field` of the item chosen, and ends the request.
    func insert(_ field: InsertField) {
        guard let item = insertingFrom?.item else { return }
        Task {
            guard let text = await call(nil, { try field.text(of: item.id, in: $0) }) else { return }
            close()
            onText(text)
        }
    }

    /// The title a new login from this save starts with.
    var suggestedTitle: String {
        if let title = saving?.title?.trimmingCharacters(in: .whitespaces), !title.isEmpty { return title }
        switch requester {
        case let .origins(origins): return origins.first.map { $0.replacingOccurrences(of: "https://", with: "") } ?? ""
        case let .app(_, name): return name
        case .notHTTPS, .unnamed: return ""
        }
    }

    /// Saves the form's login as a new one: for the page's origin, or for
    /// the app the system names.
    func saveNew(title: String) {
        // For the page's origin, or for the app, which the vault keeps it for.
        guard let saving, let asked = requester.asked else { return }
        Task {
            guard await call("Saving…", {
                try $0.saveNew(requester: asked, title: title, username: saving.username, password: saving.password)
            }) != nil else { return }
            finishSave()
        }
    }

    /// Puts the form's password into `candidate`, as it was read. If it
    /// changed since, it is read again for the owner to choose again.
    func update(_ candidate: SaveCandidate) {
        guard let saving, let asked = requester.asked else { return }
        Task {
            do {
                busy = "Saving…"
                defer { busy = nil }
                try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
                    queue.async { [device] in
                        guard let device else { return continuation.resume(throwing: MobileError.NoVault) }
                        continuation.resume(with: Result {
                            try device.updateSaved(
                                requester: asked, id: candidate.id, revision: candidate.revision,
                                username: saving.username, password: saving.password
                            )
                        })
                    }
                }
                finishSave()
            } catch MobileError.ChangedElsewhere {
                notice = "That login changed since this screen read it · choose again"
                await listCandidates()
            } catch {
                notice = describe(error)
            }
        }
    }

    /// The vault has the form's login already, or has it now.
    func finishSave() {
        close()
        onSaved()
    }

    func cancel() {
        close()
        onCancel()
    }

    /// Locks and lets the device go: nothing of the vault stays open.
    func close() {
        closed = true
        let device = device
        self.device = nil
        queue.async { device?.lock() }
    }
}

/// A field of an item that can be inserted as text, by how its value is
/// had: some from what the item shows, the secrets only when chosen.
struct InsertField: Identifiable, Equatable {
    enum Source: Equatable {
        case shown(String)
        case password
        case oneTimeCode
        case field(String)
    }

    let label: String
    let source: Source
    var id: String { label }

    /// What of `detail` can be inserted: for a login its username, password,
    /// code, and website; for a card its number, security code, cardholder,
    /// and expiry; then any other field, and the notes.
    static func of(_ detail: ItemDetail) -> [InsertField] {
        var fields: [InsertField] = []
        if let card = detail.card {
            if card.hasNumber { fields.append(InsertField(label: "Number", source: .field("Number"))) }
            if card.hasSecurityCode { fields.append(InsertField(label: "Security code", source: .field("Security code"))) }
            if !card.cardholder.isEmpty { fields.append(InsertField(label: "Cardholder name", source: .shown(card.cardholder))) }
            if !card.expiryMonth.isEmpty && !card.expiryYear.isEmpty {
                let year = card.expiryYear.count == 4 ? String(card.expiryYear.suffix(2)) : card.expiryYear
                fields.append(InsertField(label: "Expiry (MM/YY)", source: .shown("\(card.expiryMonth)/\(year)")))
            }
            if !card.expiryMonth.isEmpty { fields.append(InsertField(label: "Expiry month", source: .shown(card.expiryMonth))) }
            if !card.expiryYear.isEmpty { fields.append(InsertField(label: "Expiry year", source: .shown(card.expiryYear))) }
        }
        if !detail.username.isEmpty { fields.append(InsertField(label: "Username", source: .shown(detail.username))) }
        if detail.hasPassword { fields.append(InsertField(label: "Password", source: .password)) }
        if detail.hasOneTimeCode { fields.append(InsertField(label: "One-time code", source: .oneTimeCode)) }
        if !detail.url.isEmpty { fields.append(InsertField(label: "Website", source: .shown(detail.url))) }
        fields += detail.fields.map { InsertField(label: $0, source: .field($0)) }
        if !detail.notes.isEmpty { fields.append(InsertField(label: "Notes", source: .shown(detail.notes))) }
        return fields
    }

    /// Whether its value is a secret, which the screen does not show.
    var isSecret: Bool {
        if case .shown = source { return false }
        return true
    }

    func text(of id: String, in device: Device) throws -> String {
        switch source {
        case let .shown(text): text
        case .password: try device.password(id: id)
        case .oneTimeCode: try device.oneTimeCode(id: id)
        case let .field(name): try device.field(id: id, name: name)
        }
    }
}
