import Foundation
import UIKit

/// What the app shows.
enum Screen: Equatable { case opening, noVault, joining, locked, unlocked, removed, unreadable }

/// An item being written: a new one when `detail` is nil, otherwise that
/// item as it was read.
struct Editor: Equatable {
    let detail: ItemDetail?
}

/// The device of the vault, as the screens use it. Every call to it runs off
/// the main thread, one at a time; the screens follow what is published.
@MainActor
final class VaultModel: ObservableObject {
    @Published private(set) var screen: Screen = .opening
    @Published private(set) var items: [ItemSummary] = []
    @Published private(set) var detail: ItemDetail?
    @Published private(set) var sync: SyncStatus?
    /// The code to compare with the inviting device's, while joining.
    @Published private(set) var joinCode: String?
    /// What is under way, while something takes a while.
    @Published private(set) var busy: String?
    /// The outcome of the last thing the owner did, to show once.
    @Published var notice: String?
    @Published private(set) var unreadable: String?
    /// While the editor is open.
    @Published private(set) var editor: Editor?
    let biometric = BiometricUnlock()

    private let queue = DispatchQueue(label: "org.opensecretmanager.device")
    private var device: Device?
    private var refresher: Task<Void, Never>?

    private func onQueue<T>(_ work: @escaping () throws -> T) async throws -> T {
        try await withCheckedThrowingContinuation { continuation in
            queue.async { continuation.resume(with: Result { try work() }) }
        }
    }

    /// Runs `work` with the device, showing `busy` meanwhile and any failure,
    /// then reads where the device stands.
    @discardableResult
    private func call<T>(_ busy: String? = nil, _ work: @escaping (Device) throws -> T) async -> T? {
        guard let device else { return nil }
        if let busy {
            self.busy = busy
            notice = nil
        }
        defer { if busy != nil { self.busy = nil } }
        do {
            let result = try await onQueue { try work(device) }
            await refresh()
            return result
        } catch MobileError.UnreadableVault(let reason) {
            screen = .unreadable
            unreadable = reason
        } catch {
            notice = describe(error)
            await refresh()
        }
        return nil
    }

    /// Reads where the device stands, and what an unlocked vault holds.
    private func refresh() async {
        guard let device else { return }
        guard let (state, items, sync) = try? await onQueue({ () -> (DeviceState, [ItemSummary], SyncStatus) in
            let state = device.state()
            let items = state == .unlocked ? ((try? device.items()) ?? []) : []
            return (state, items, device.syncStatus())
        }) else { return }
        guard screen != .unreadable else { return }
        screen = switch state {
        case .noVault: .noVault
        case .joining: .joining
        case .locked: .locked
        case .unlocked: .unlocked
        case .removed: .removed
        }
        self.items = items.sorted { $0.title.localizedCaseInsensitiveCompare($1.title) == .orderedAscending }
        self.sync = sync
        // A detail stays open only while its item does.
        if let detail, !(screen == .unlocked && items.contains { $0.id == detail.id }) { self.detail = nil }
        if screen != .joining { joinCode = nil }
        if screen != .unlocked { editor = nil }
    }

    private func openDevice() async {
        do {
            let folder = try DeviceFolder.url()
            #if DEBUG
            TestSupport.prepareOnce(folder)
            #endif
            device = try await onQueue { try Device.open(folder: folder.path) }
            await refresh()
        } catch MobileError.UnreadableVault(let reason) {
            screen = .unreadable
            unreadable = reason
        } catch {
            screen = .unreadable
            unreadable = describe(error)
        }
    }

    func unlock(password: String, keepForBiometrics: Bool) {
        Task {
            guard await call("Unlocking…", { try $0.unlock(password: password) }) != nil else { return }
            if keepForBiometrics, !biometric.keep(password) {
                notice = "Set a passcode on this phone to unlock with \(biometric.name)"
            }
            await call { try? $0.goOnline() }
        }
    }

    func unlockWithBiometrics() {
        Task {
            let biometric = biometric
            let outcome = await withCheckedContinuation { continuation in
                DispatchQueue.global().async { continuation.resume(returning: biometric.read(reason: "Unlock the vault")) }
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
            await call { try? $0.goOnline() }
        }
    }

    func lock() {
        Task {
            detail = nil
            editor = nil
            await call { $0.lock() }
        }
    }

    func joinStart(_ invitation: String) {
        Task {
            let trimmed = invitation.trimmingCharacters(in: .whitespacesAndNewlines)
            if let code = await call("Reaching the inviting device…", { try $0.joinStart(invitation: trimmed) }) {
                joinCode = code
            }
        }
    }

    func joinFinish(_ password: String) {
        Task {
            if await call("Waiting for your other devices to add this phone…", { try $0.joinFinish(password: password) }) != nil {
                joinCode = nil
                notice = "Joined · the vault arrives as it syncs"
            }
        }
    }

    func cancelJoin() {
        Task {
            joinCode = nil
            await call { $0.cancelJoin() }
        }
    }

    func syncNow() {
        Task { await call("Syncing…") { _ = try $0.syncNow() } }
    }

    func open(_ id: String) {
        Task {
            if let detail = await call(nil, { try $0.item(id: id) }) { self.detail = detail }
        }
    }

    func close() {
        detail = nil
    }

    func startNew() {
        editor = Editor(detail: nil)
    }

    func startEdit(_ detail: ItemDetail) {
        editor = Editor(detail: detail)
        #if DEBUG
        TestSupport.changeWhileEditing(detail.id)
        #endif
    }

    func closeEditor() {
        editor = nil
    }

    /// Saves the editor's draft: a new item, or an edit of the item as it was read.
    func save(_ draft: ItemDraft) {
        guard let device else { return }
        let editing = editor?.detail
        Task {
            busy = "Saving…"
            notice = nil
            defer { busy = nil }
            do {
                let saved = try await onQueue { () -> ItemDetail in
                    if let editing {
                        try device.updateItem(id: editing.id, revision: editing.revision, draft: draft)
                        return try device.item(id: editing.id)
                    }
                    return try device.item(id: try device.createItem(draft: draft))
                }
                editor = nil
                detail = saved
                notice = editing == nil ? "Item created" : "Changes saved"
            } catch MobileError.ChangedElsewhere {
                // What was read is out of date: show the item as it is now.
                let current = try? await onQueue { try device.item(id: editing?.id ?? "") }
                editor = nil
                detail = current
                notice = describe(MobileError.ChangedElsewhere)
            } catch {
                notice = describe(error)
            }
            await refresh()
        }
    }

    /// Deletes the item as it was read, on every device.
    func delete(_ item: ItemDetail) {
        Task {
            if await call(nil, { try $0.deleteItem(id: item.id, revision: item.revision) }) != nil {
                detail = nil
                notice = "Item deleted"
            }
        }
    }

    /// A new password from the shared generator.
    func generatePassword() -> String {
        (try? OpenSecretManager.generatePassword(length: 20)) ?? ""
    }

    func copyUsername(_ detail: ItemDetail) {
        SecretPasteboard.copy(detail.username, secret: false)
        notice = "Username copied"
    }

    func copyPassword(_ id: String) {
        Task {
            guard let password = await call(nil, { try $0.password(id: id) }) else { return }
            SecretPasteboard.copy(password, secret: true)
            notice = "Password copied · cleared in 30 seconds"
        }
    }

    func copyOneTimeCode(_ id: String) {
        Task {
            guard let code = await call(nil, { try $0.oneTimeCode(id: id) }) else { return }
            SecretPasteboard.copy(code, secret: true)
            notice = "Code copied · cleared in 30 seconds"
        }
    }

    /// The app came to the front: open the device again if it was let go,
    /// take part, and keep the list current.
    func becameActive() {
        refresher?.cancel()
        refresher = Task {
            if device == nil { await openDevice() }
            if screen == .locked || screen == .unlocked { await call { try? $0.goOnline() } }
            while !Task.isCancelled {
                try? await Task.sleep(for: .seconds(5))
                if Task.isCancelled { break }
                await refresh()
            }
        }
    }

    /// The app left the screen: lock, stop taking part, end a join, and let
    /// the device go, so that no file of the shared folder stays open while
    /// iOS suspends the app.
    func wentToBackground() {
        refresher?.cancel()
        refresher = nil
        guard let device else { return }
        self.device = nil
        detail = nil
        editor = nil
        if joinCode != nil {
            joinCode = nil
            notice = "The join stopped when the app left the screen · start again from your computer"
        }
        if screen == .unlocked || screen == .joining { screen = screen == .unlocked ? .locked : .noVault }
        let app = UIApplication.shared
        var task = UIBackgroundTaskIdentifier.invalid
        task = app.beginBackgroundTask { app.endBackgroundTask(task) }
        queue.async {
            if device.state() == .joining { device.cancelJoin() }
            device.lock()
            device.goOffline()
            DispatchQueue.main.async { app.endBackgroundTask(task) }
        }
    }
}
