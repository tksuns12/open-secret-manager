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
/// that asks for one, of its current one-time code.
@MainActor
final class FillModel: ObservableObject {
    enum Stage: Equatable { case opening, locked, unlocked, noVault, removed, unreadable(String), nothingToFill }

    let requester: FillRequester
    /// Set when the screen saves rather than fills.
    let saving: Saving?
    /// Set when the screen fills a one-time code.
    let oneTimeCode: Bool
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
    /// For each offered login, the origin it is filled for.
    private var originOf: [String: String] = [:]
    private let onFill: (FillCredentials) -> Void
    private let onCode: (String) -> Void
    private let onSaved: () -> Void
    private let onCancel: () -> Void

    init(
        requester: FillRequester,
        saving: Saving? = nil,
        oneTimeCode: Bool = false,
        onFill: @escaping (FillCredentials) -> Void = { _ in },
        onCode: @escaping (String) -> Void = { _ in },
        onSaved: @escaping () -> Void = {},
        onCancel: @escaping () -> Void
    ) {
        self.requester = requester
        self.saving = saving
        self.oneTimeCode = oneTimeCode
        self.onFill = onFill
        self.onCode = onCode
        self.onSaved = onSaved
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
                queue.async { continuation.resume(with: Result { try Device.open(folder: folder.path) }) }
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

    func unlockWithBiometrics() {
        Task {
            let biometric = biometric
            let reason = saving == nil ? "Unlock the vault to fill a login" : "Unlock the vault to save a login"
            let outcome = await withCheckedContinuation { continuation in
                DispatchQueue.global().async { continuation.resume(returning: biometric.read(reason: reason)) }
            }
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
        let requester = requester
        let oneTimeCode = oneTimeCode
        let found: ([ItemSummary], [String: String])? = await call { device in
            switch requester {
            case let .origins(origins):
                var logins: [ItemSummary] = []
                var originOf: [String: String] = [:]
                for origin in origins {
                    var forOrigin = try device.loginsForWeb(origin: origin)
                    if oneTimeCode { forOrigin = try device.withOneTimeCodes(ids: forOrigin.map(\.id)) }
                    for login in forOrigin where originOf[login.id] == nil {
                        logins.append(login)
                        originOf[login.id] = origin
                    }
                }
                return (logins, originOf)
            case let .app(id, _):
                let chosen = AppLogins().chosen(id)
                let logins = try device.items().filter { $0.kind == .login && chosen.contains($0.id) }
                return (oneTimeCode ? try device.withOneTimeCodes(ids: logins.map(\.id)) : logins, [:])
            case .unnamed, .notHTTPS:
                return ([], [:])
            }
        }
        guard let found else { return }
        offered = found.0.sorted { $0.title.localizedCaseInsensitiveCompare($1.title) == .orderedAscending }
        originOf = found.1
        if saving != nil {
            await listCandidates()
        }
        stage = .unlocked
        if saving == nil, case .unnamed = requester { await chooseAny() }
    }

    /// Of the logins the form could be filled with, those its save could go into.
    private func listCandidates() async {
        guard let saving else { return }
        let ids = offered.map(\.id)
        candidates = await call { device in
            try device.saveCandidates(ids: ids, username: saving.username, password: saving.password)
        }?.sorted { $0.title.localizedCaseInsensitiveCompare($1.title) == .orderedAscending } ?? []
    }

    /// Every login (with a one-time code, for a code), for an app the owner
    /// chooses one for.
    func chooseAny() async {
        let oneTimeCode = oneTimeCode
        all = await call { device in
            let logins = try device.items().filter { $0.kind == .login }
            return try (oneTimeCode ? device.withOneTimeCodes(ids: logins.map(\.id)) : logins)
                .sorted { $0.title.localizedCaseInsensitiveCompare($1.title) == .orderedAscending }
        }
    }

    func fill(_ login: ItemSummary) {
        let origin = originOf[login.id]
        let requester = requester
        // A page or an app of an origin gets only a login offered for it.
        if case .origins = requester, origin == nil {
            notice = describe(MobileError.NotForThisPage)
            return
        }
        if oneTimeCode {
            Task {
                guard let code = await call(nil, { device -> String in
                    if let origin { return try device.oneTimeCodeForWeb(id: login.id, origin: origin) }
                    return try device.oneTimeCode(id: login.id)
                }) else { return }
                if case let .app(id, _) = requester { AppLogins().remember(id, login.id) }
                close()
                onCode(code)
            }
            return
        }
        Task {
            guard let credentials = await call(nil, { device -> FillCredentials in
                if let origin { return try device.fillForWeb(id: login.id, origin: origin) }
                return try device.fillForApp(id: login.id)
            }) else { return }
            if case let .app(id, _) = requester { AppLogins().remember(id, login.id) }
            close()
            onFill(credentials)
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
        guard let saving else { return }
        let url: String
        if case let .origins(origins) = requester { url = origins.first ?? "" } else { url = "" }
        let draft = ItemDraft(
            title: title, kind: .login, username: saving.username, url: url,
            notes: "", favorite: false, password: saving.password, oneTimeCodeSecret: nil
        )
        let requester = requester
        Task {
            guard let id = await call("Saving…", { try $0.createItem(draft: draft) }) else { return }
            if case let .app(app, _) = requester { AppLogins().remember(app, id) }
            finishSave()
        }
    }

    /// Puts the form's password into `candidate`, as it was read. If it
    /// changed since, it is read again for the owner to choose again.
    func update(_ candidate: SaveCandidate) {
        guard let saving else { return }
        Task {
            do {
                busy = "Saving…"
                defer { busy = nil }
                try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
                    queue.async { [device] in
                        guard let device else { return continuation.resume(throwing: MobileError.NoVault) }
                        continuation.resume(with: Result {
                            try device.updatePassword(id: candidate.id, revision: candidate.revision, password: saving.password)
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
