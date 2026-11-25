import SwiftUI
import UIKit

/// Disallows third-party keyboard extensions inside the vault app so typed
/// passwords and passphrases cannot be captured by an external keyboard.
final class AppDelegate: NSObject, UIApplicationDelegate {
    func application(
        _ application: UIApplication,
        shouldAllowExtensionPointIdentifier extensionPointIdentifier: UIApplication.ExtensionPointIdentifier
    ) -> Bool {
        extensionPointIdentifier != .keyboard
    }
}

/// The app's process: one device of a vault, in the folder it shares with its
/// AutoFill extension. Leaving the app locks the vault and stops taking part;
/// coming back takes part again.
@main
struct OpenSecretManagerApp: App {
    @UIApplicationDelegateAdaptor(AppDelegate.self) private var appDelegate
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
