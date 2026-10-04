import SwiftUI

/// The app's process: one device of a vault, in the folder it shares with its
/// AutoFill extension. Leaving the app locks the vault and stops taking part;
/// coming back takes part again.
@main
struct OpenSecretManagerApp: App {
    @StateObject private var model = VaultModel()
    @Environment(\.scenePhase) private var scenePhase

    var body: some Scene {
        WindowGroup {
            RootView(model: model)
                // Nothing of the vault in the app switcher's picture of it.
                .overlay { if scenePhase != .active { PrivacyCover() } }
        }
        .onChange(of: scenePhase) { _, phase in
            switch phase {
            case .active: model.becameActive()
            case .background: model.wentToBackground()
            default: break
            }
        }
    }
}

private struct PrivacyCover: View {
    var body: some View {
        ZStack {
            Color(uiColor: .systemBackground).ignoresSafeArea()
            Image(systemName: "lock.shield").font(.system(size: 56)).foregroundStyle(.secondary)
        }
    }
}
