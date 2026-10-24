import Foundation
import UIKit

/// What the app shows.
enum Screen: Equatable { case opening, noVault, joining, locked, unlocked, removed, unreadable }

/// An item being written: a new one when `detail` is nil, otherwise that
/// item as it was read. A save refused because the item changed elsewhere
/// opens it again with `draft`, what was typed put on top of the item as it
/// is now, and names what changed in `changedElsewhere`. A new item comes
/// with a password made for it, `generated`.
struct Editor: Hashable {
    let detail: ItemDetail?
    var draft: ItemDraft? = nil
    var changedElsewhere: [String] = []
    var generated: String? = nil
}

/// An item's versions, newest first, while its history is open.
struct History: Equatable {
    let detail: ItemDetail
    let versions: [HistoryEntry]
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
    /// While an item's history is open.
    @Published private(set) var history: History?
    /// The items deleted, while that list is open.
    @Published private(set) var deleted: [DeletedEntry]?
    /// The last unlock found records taken out of the vault's file.
    @Published private(set) var rowsChanged = false
    /// The screen that changes this phone's password is open.
    @Published private(set) var passwordChange = false
    let biometric = BiometricUnlock()

    private let queue = DispatchQueue(label: "org.opensecretmanager.device")
    private var device: Device?
    private var refresher: Task<Void, Never>?
    /// Whether the vault, shown locked when the app opens or comes back,
    /// asks for a face or a finger at once: not after the owner's own Lock,
    /// and once only, so that a cancel leaves the button.
    private var askAtOnce = true
    /// A face or a finger is being asked for: a second ask would cancel it.
    private var asking = false

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
        guard let (state, items, sync, rowsChanged) = try? await onQueue({ () -> (DeviceState, [ItemSummary], SyncStatus, Bool) in
            let state = device.state()
            let items = state == .unlocked ? ((try? device.items()) ?? []) : []
            return (state, items, device.syncStatus(), state == .unlocked && device.rowsChanged())
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
        self.rowsChanged = rowsChanged
        // A detail stays open only while its item does.
        if let detail, !(screen == .unlocked && items.contains { $0.id == detail.id }) { self.detail = nil }
        if screen != .joining { joinCode = nil }
        if screen != .unlocked {
            editor = nil
            history = nil
            deleted = nil
            passwordChange = false
        }
    }

    private func openDevice() async {
        do {
            let folder = try DeviceFolder.url()
            #if DEBUG
            TestSupport.prepareOnce(folder)
            #endif
            device = try await onQueue { try Device.open(folder: folder.path, keystore: KeychainKeystore.shared) }
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
        guard !asking else { return }
        asking = true
        Task {
            let biometric = biometric
            let outcome = await withCheckedContinuation { continuation in
                DispatchQueue.global().async { continuation.resume(returning: biometric.read(reason: "Unlock the vault")) }
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
            await call { try? $0.goOnline() }
        }
    }

    /// The owner's own Lock, which asks for no face or finger until the app leaves the screen.
    func lock() {
        askAtOnce = false
        Task {
            detail = nil
            editor = nil
            history = nil
            deleted = nil
            passwordChange = false
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
        editor = Editor(detail: nil, generated: generatePassword())
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
                // What was read is out of date: what was typed is put on top
                // of the item as it is now, and the edit stays open. The
                // item is read before the edit is moved, so a change between
                // the two is refused again rather than undone.
                guard let editing else { return }
                do {
                    let (current, edit) = try await onQueue { () -> (ItemDetail, RebasedEdit) in
                        let current = try device.item(id: editing.id)
                        return (current, try device.rebaseEdit(id: editing.id, revision: editing.revision, draft: draft))
                    }
                    editor = Editor(detail: current, draft: edit.draft, changedElsewhere: edit.changedElsewhere)
                    notice = "Changed on another device meanwhile · your changes are kept"
                } catch {
                    // It cannot be moved (it is now in conflict, or gone):
                    // show the item as it is now.
                    editor = nil
                    detail = try? await onQueue { try device.item(id: editing.id) }
                    notice = describe(MobileError.ChangedElsewhere)
                }
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

    /// Removes `passkey` of the login `item` shows, on every device, and shows the login as it is then.
    func removePasskey(_ item: ItemDetail, _ passkey: PasskeyDetail) {
        Task {
            if let shown = await call(nil, { device -> ItemDetail in
                try device.removePasskey(id: item.id, revision: item.revision, credentialId: passkey.credentialId)
                return try device.item(id: item.id)
            }) {
                detail = shown
                notice = "Passkey removed"
            }
        }
    }

    func openHistory(_ detail: ItemDetail) {
        Task {
            if let versions = await call(nil, { try $0.history(id: detail.id) }) {
                history = History(detail: detail, versions: versions)
            }
        }
    }

    func closeHistory() {
        history = nil
    }

    /// Brings back what `version` held as the newest version, following the
    /// current versions the history showed. If the item changed since, the
    /// history is read again.
    func restore(_ version: HistoryEntry) {
        guard let device, let shown = history else { return }
        let heads = shown.versions.filter(\.current).map(\.revision)
        Task {
            busy = "Restoring…"
            notice = nil
            defer { busy = nil }
            do {
                let now = try await onQueue { () -> ItemDetail in
                    try device.restore(id: shown.detail.id, revision: version.revision, heads: heads)
                    return try device.item(id: shown.detail.id)
                }
                history = nil
                detail = now
                notice = "Version restored"
            } catch MobileError.ChangedElsewhere {
                if let versions = try? await onQueue({ try device.history(id: shown.detail.id) }) {
                    history = History(detail: shown.detail, versions: versions)
                }
                notice = describe(MobileError.ChangedElsewhere)
            } catch {
                notice = describe(error)
            }
            await refresh()
        }
    }

    func openDeleted() {
        Task {
            if let items = await call(nil, { try $0.deletedItems() }) { deleted = items }
        }
    }

    func closeDeleted() {
        deleted = nil
    }

    func openPasswordChange() {
        passwordChange = true
    }

    func closePasswordChange() {
        passwordChange = false
    }

    /// Makes `newPassword` this phone's password from now on, given
    /// `current`. The password kept for Face ID or Touch ID is the old one,
    /// so that is turned off, to be turned on again at an unlock. A wrong
    /// current password changes nothing, and the screen stays open.
    func changePassword(current: String, newPassword: String) {
        Task {
            guard let device else { return }
            busy = "Changing the password…"
            notice = nil
            defer { busy = nil }
            do {
                try await onQueue { try device.changePassword(currentPassword: current, newPassword: newPassword) }
            } catch MobileError.InvalidCredentials {
                notice = "That is not this phone's current password · nothing was changed"
                return
            } catch {
                notice = describe(error)
                await refresh()
                return
            }
            let hadBiometrics = biometric.enabled
            biometric.disable()
            passwordChange = false
            notice = hadBiometrics ? "Password changed · turn on \(biometric.name) again at the next unlock" : "Password changed"
        }
    }

    /// The owner has seen that records were taken out of the vault's file.
    func confirmRowsChanged() {
        Task { _ = await call(nil, { try $0.confirmRowsChanged() }) }
    }

    /// Brings back a deleted item as it was before it was deleted.
    func restoreDeleted(_ entry: DeletedEntry) {
        Task {
            guard let now = await call("Restoring…", { device -> ItemDetail in
                try device.restore(id: entry.id, revision: entry.last, heads: entry.heads)
                return try device.item(id: entry.id)
            }) else { return }
            deleted = nil
            detail = now
            notice = "\(entry.title) restored"
        }
    }

    /// A new password from the shared generator, as the owner chose (`Generator`).
    func generatePassword() -> String {
        (try? OpenSecretManager.generatePassword(options: Generator.options)) ?? ""
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

    /// Copies the value of one of the item's other fields, as a secret.
    func copyField(_ id: String, _ name: String) {
        Task {
            guard let value = await call(nil, { try $0.field(id: id, name: name) }) else { return }
            SecretPasteboard.copy(value, secret: true)
            notice = "\(name) copied · cleared in 30 seconds"
        }
    }

    /// The app came to the front: open the device again if it was let go,
    /// ask for a face or a finger if it opens locked, take part, and keep the
    /// list current. The phone's own sheet for the check makes the app
    /// inactive and active again, which asks nothing more.
    func becameActive() {
        refresher?.cancel()
        refresher = Task {
            if device == nil { await openDevice() }
            if askAtOnce {
                askAtOnce = false
                if screen == .locked && biometric.available && biometric.enabled { unlockWithBiometrics() }
            }
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
        askAtOnce = true
        refresher?.cancel()
        refresher = nil
        guard let device else { return }
        self.device = nil
        detail = nil
        editor = nil
        history = nil
        deleted = nil
        passwordChange = false
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
