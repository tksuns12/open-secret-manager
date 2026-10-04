import Foundation

/// The fill screen's state: the device opened on the vault the app shares,
/// never online, unlocked for this one fill and dropped when it ends.
@MainActor
final class FillModel: ObservableObject {
    enum Stage: Equatable { case opening, locked, unlocked, noVault, removed, unreadable(String), nothingToFill }

    let requester: FillRequester
    @Published private(set) var stage: Stage = .opening
    /// What may be filled: the logins for the origins, or those chosen for the app.
    @Published private(set) var offered: [ItemSummary] = []
    /// Every login, once the owner asks to choose one for an app.
    @Published private(set) var all: [ItemSummary]?
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
    private let onCancel: () -> Void

    init(requester: FillRequester, onFill: @escaping (FillCredentials) -> Void, onCancel: @escaping () -> Void) {
        self.requester = requester
        self.onFill = onFill
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
            let outcome = await withCheckedContinuation { continuation in
                DispatchQueue.global().async { continuation.resume(returning: biometric.read(reason: "Unlock the vault to fill a login")) }
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
        let found: ([ItemSummary], [String: String])? = await call { device in
            switch requester {
            case let .origins(origins):
                var logins: [ItemSummary] = []
                var originOf: [String: String] = [:]
                for origin in origins {
                    for login in try device.loginsForWeb(origin: origin) where originOf[login.id] == nil {
                        logins.append(login)
                        originOf[login.id] = origin
                    }
                }
                return (logins, originOf)
            case let .app(id, _):
                let chosen = AppLogins().chosen(id)
                return (try device.items().filter { $0.kind == .login && chosen.contains($0.id) }, [:])
            case .unnamed, .notHTTPS:
                return ([], [:])
            }
        }
        guard let found else { return }
        offered = found.0.sorted { $0.title.localizedCaseInsensitiveCompare($1.title) == .orderedAscending }
        originOf = found.1
        stage = .unlocked
        if case .unnamed = requester { await chooseAny() }
    }

    /// Every login, for an app the owner chooses one for.
    func chooseAny() async {
        all = await call { device in
            try device.items().filter { $0.kind == .login }
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
