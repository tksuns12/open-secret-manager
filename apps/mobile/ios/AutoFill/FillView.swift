import SwiftUI

/// The fill screen: who asks, an unlock, and what may be filled.
struct FillView: View {
    @ObservedObject var model: FillModel

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(alignment: .leading, spacing: 20) {
                    Asker(requester: model.requester)
                    Divider()
                    content
                }
                .padding()
            }
            .navigationTitle("Fill a login")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel", action: model.cancel).accessibilityIdentifier("cancel")
                }
            }
        }
        .overlay { if let busy = model.busy { BusyCover(what: busy) } }
        .overlay(alignment: .bottom) { NoticeBanner(notice: $model.notice) }
    }

    @ViewBuilder private var content: some View {
        switch model.stage {
        case .opening:
            Text("Opening…")
        case .locked:
            UnlockFields(
                biometric: model.biometric,
                busy: model.busy != nil,
                onUnlock: model.unlock,
                onBiometrics: model.unlockWithBiometrics
            )
        case .unlocked:
            Logins(model: model)
        case .noVault:
            Explanation(title: "This phone has no vault yet", detail: "Join your vault in Open Secret Manager first.")
        case .removed:
            Explanation(title: "This phone was removed from the vault", detail: nil)
        case let .unreadable(reason):
            Explanation(title: "The vault on this phone cannot be opened", detail: reason)
        case .nothingToFill:
            Explanation(title: "Nothing to fill", detail: "Logins are filled only into pages over https.")
        }
    }
}

/// Who the login would go to, as the owner should check it.
private struct Asker: View {
    let requester: FillRequester

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            switch requester {
            case let .origins(origins):
                Text("For \(origins.map { $0.replacingOccurrences(of: "https://", with: "") }.joined(separator: ", "))")
                    .font(.headline).accessibilityIdentifier("asker")
            case let .app(id, name):
                Text("For the app \(name)").font(.headline).accessibilityIdentifier("asker")
                Text(id).font(.caption).foregroundStyle(.secondary)
            case let .notHTTPS(address):
                Text("For \(address)").font(.headline).accessibilityIdentifier("asker")
            case .unnamed:
                Text("For an app that does not say which site it belongs to").font(.headline).accessibilityIdentifier("asker")
            }
        }
    }
}

private struct Logins: View {
    @ObservedObject var model: FillModel

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            if case .origins = model.requester, model.offered.isEmpty {
                Explanation(
                    title: "No login for this site",
                    detail: "A login is offered only on the site it was saved for: over https, on the same host and port."
                )
                .accessibilityIdentifier("no-logins")
            }
            Rows(logins: model.offered, onChoose: model.fill)
            if let all = model.all {
                Text(warning)
                    .foregroundStyle(.red)
                    .accessibilityIdentifier("warning")
                Rows(logins: all, onChoose: model.fill)
            } else if case .app = model.requester {
                Button(model.offered.isEmpty ? "Choose a login for this app…" : "Choose another login…") {
                    Task { await model.chooseAny() }
                }
                .accessibilityIdentifier("choose-another")
            }
        }
    }

    private var warning: String {
        switch model.requester {
        case let .app(_, name):
            "An app cannot be checked against a login's address. Choose only a login meant for \(name): it is offered to this app again, and to no other."
        default:
            "This app cannot be checked against a login's address, and it does not say which app it is. Choose only a login meant for it."
        }
    }
}

private struct Rows: View {
    let logins: [ItemSummary]
    let onChoose: (ItemSummary) -> Void

    var body: some View {
        ForEach(logins, id: \.id) { login in
            Button { onChoose(login) } label: {
                VStack(alignment: .leading, spacing: 2) {
                    Text(login.title).font(.body)
                    if !login.username.isEmpty {
                        Text(login.username).font(.caption).foregroundStyle(.secondary)
                    }
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
            .accessibilityIdentifier("fill:\(login.title)")
            Divider()
        }
    }
}

private struct Explanation: View {
    let title: String
    let detail: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text(title).font(.headline).accessibilityIdentifier("message")
            if let detail { Text(detail).font(.body) }
        }
    }
}
