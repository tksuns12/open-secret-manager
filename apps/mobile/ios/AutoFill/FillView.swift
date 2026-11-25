import SwiftUI

/// The fill or save screen: who asks, an unlock, and what may be filled, or
/// where what the form submitted may be saved.
struct FillView: View {
    @ObservedObject var model: FillModel

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(alignment: .leading, spacing: 20) {
                    if model.inserting {
                        // iOS says nothing of where the text goes.
                        Text("Into the field you chose").font(.headline).accessibilityIdentifier("asker")
                    } else {
                        Asker(requester: model.requester)
                    }
                    Divider()
                    content
                }
                .padding()
            }
            .osmScreen()
            // Locked, Face ID or Touch ID is asked for at once.
            .task(id: model.stage) { if model.stage == .locked { model.askAtOnce() } }
            .navigationTitle(model.saving != nil ? "Save a login" : model.inserting ? "Insert text" : model.oneTimeCode ? "Fill a one-time code" : "Fill a login")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel", action: model.cancel).accessibilityIdentifier("cancel")
                }
            }
        }
        .tint(OSM.accent)
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
            if let saving = model.saving {
                SaveChoices(model: model, saving: saving)
            } else if model.inserting {
                InsertChoices(model: model)
            } else {
                Logins(model: model)
            }
        case .noVault:
            Explanation(title: "This phone has no vault yet", detail: "Join your vault in Open Secret Manager first.")
        case .removed:
            Explanation(title: "This phone was removed from the vault", detail: nil)
        case let .unreadable(reason):
            Explanation(title: "The vault on this phone cannot be opened", detail: reason)
        case .nothingToFill:
            if model.saving == nil {
                Explanation(title: "Nothing to fill", detail: "Logins are filled only into pages over https.")
            } else {
                Explanation(title: "Nothing to save", detail: "Logins are saved only for pages over https.")
            }
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
    @State private var query = ""

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            if case .origins = model.requester, model.offered.isEmpty {
                Explanation(
                    title: model.oneTimeCode ? "No login with a one-time code for this site" : "No login for this site",
                    detail: "A login is offered only on the site it was saved for: over https, on the same host and port."
                )
                .accessibilityIdentifier("no-logins")
            }
            Rows(logins: model.offered, onChoose: model.fill)
            if let all = model.all {
                Text(warning)
                    .foregroundStyle(.red)
                    .accessibilityIdentifier("warning")
                // Every login, narrowed as the app's list is.
                TextField("Search", text: $query)
                    .textFieldStyle(.roundedBorder)
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
                    .accessibilityIdentifier("fill-search")
                Rows(logins: all.filter { login in
                    query.isEmpty || login.title.localizedCaseInsensitiveContains(query)
                        || login.username.localizedCaseInsensitiveContains(query)
                        || login.url.localizedCaseInsensitiveContains(query)
                }, onChoose: model.fillChosen)
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

/// Where what the form submitted goes: into a login the same form could be
/// filled with, under the username it sent, or into a new login.
private struct SaveChoices: View {
    @ObservedObject var model: FillModel
    let saving: Saving
    @State private var title: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            VStack(alignment: .leading, spacing: 4) {
                Text("Username").font(.caption).foregroundStyle(.secondary)
                Text(saving.username.isEmpty ? "None" : saving.username).accessibilityIdentifier("save-username")
                Text("The password the form sent is not shown.").font(.caption).foregroundStyle(.secondary)
            }
            if let already = model.candidates.first(where: \.hasThisPassword) {
                Text("Already saved, in \(already.title)").font(.headline).accessibilityIdentifier("already-saved")
                Button("Done", action: model.finishSave)
                    .buttonStyle(.borderedProminent)
                    .accessibilityIdentifier("done")
            } else {
                if !model.candidates.isEmpty {
                    Divider()
                    Text("Update a login").font(.headline)
                    ForEach(model.candidates, id: \.id) { candidate in
                        let label = candidate.username.isEmpty
                            ? "Update the password of \(candidate.title)"
                            : "Update the password of \(candidate.title) (\(candidate.username))"
                        Button(label) { model.update(candidate) }
                            .buttonStyle(.bordered)
                            .disabled(model.busy != nil)
                            .accessibilityIdentifier("update:\(candidate.title)")
                    }
                }
                Divider()
                Text(model.candidates.isEmpty ? "Save a new login" : "Or save a new login").font(.headline)
                TextField("Title", text: titleBinding)
                    .textFieldStyle(.roundedBorder)
                    .accessibilityIdentifier("save-title")
                Text(whereOffered).font(.caption).foregroundStyle(.secondary)
                Button("Save as a new login") { model.saveNew(title: titleBinding.wrappedValue) }
                    .buttonStyle(.borderedProminent)
                    .disabled(titleBinding.wrappedValue.trimmingCharacters(in: .whitespaces).isEmpty || model.busy != nil)
                    .accessibilityIdentifier("save-new")
            }
        }
    }

    /// The title field, starting from what the model suggests.
    private var titleBinding: Binding<String> {
        Binding(get: { title ?? model.suggestedTitle }, set: { title = $0 })
    }

    private var whereOffered: String {
        switch model.requester {
        case let .origins(origins):
            "It is offered on \(origins.first.map { $0.replacingOccurrences(of: "https://", with: "") } ?? "this site") only."
        case let .app(_, name):
            "It is offered to \(name) again, and to no other app."
        case .notHTTPS, .unnamed:
            "This app does not say which site it belongs to: to fill the login into it, you choose it, warned."
        }
    }
}

/// For text to insert: any item, then one of its fields, whose text goes
/// into the field the owner chose. A secret is not shown.
private struct InsertChoices: View {
    @ObservedObject var model: FillModel
    @State private var query = ""

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            if let chosen = model.insertingFrom {
                Text(chosen.item.title).font(.headline).accessibilityIdentifier("insert-item")
                ForEach(chosen.fields) { field in
                    Button { model.insert(field) } label: {
                        VStack(alignment: .leading, spacing: 2) {
                            Text(field.label).font(.body)
                            if case let .shown(text) = field.source, !field.isSecret {
                                Text(text).font(.caption).foregroundStyle(.secondary).lineLimit(1)
                            }
                        }
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .contentShape(Rectangle())
                    }
                    .buttonStyle(.plain)
                    .accessibilityIdentifier("insert-field:\(field.label)")
                    Divider()
                }
                Button("Choose another item", action: model.chooseAnotherToInsert).accessibilityIdentifier("insert-another")
            } else {
                Text("Choose an item, then what of it goes into the field: a card's number, a password, or another. Insert it only where you mean it to go.")
                    .font(.callout)
                TextField("Search", text: $query)
                    .textFieldStyle(.roundedBorder)
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
                    .accessibilityIdentifier("fill-search")
                ForEach(model.offered.filter { item in
                    query.isEmpty || item.title.localizedCaseInsensitiveContains(query)
                        || item.username.localizedCaseInsensitiveContains(query)
                        || item.url.localizedCaseInsensitiveContains(query)
                }, id: \.id) { item in
                    Button { model.chooseToInsert(item) } label: {
                        VStack(alignment: .leading, spacing: 2) {
                            Text(item.title).font(.body)
                            let below = item.kind == .card ? cardLine(brand: item.brand, ending: item.cardEnding) : item.username
                            if !below.isEmpty { Text(below).font(.caption).foregroundStyle(.secondary) }
                        }
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .contentShape(Rectangle())
                    }
                    .buttonStyle(.plain)
                    .accessibilityIdentifier("insert:\(item.title)")
                    Divider()
                }
            }
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
