import SwiftUI

/// An unlock's password field and buttons, in the app and in the fill screen.
struct UnlockFields: View {
    let biometric: BiometricUnlock
    let busy: Bool
    let onUnlock: (_ password: String, _ keepForBiometrics: Bool) -> Void
    let onBiometrics: () -> Void
    @State private var password = ""
    @State private var keepForBiometrics = false

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            BrandMark(size: 44)
            Text("Vault locked").font(.largeTitle.bold()).accessibilityIdentifier("locked")
            SecureField("This phone's password", text: $password)
                .osmField()
                .submitLabel(.go)
                .onSubmit(unlock)
                .accessibilityIdentifier("password")
            if biometric.available && !biometric.enabled {
                Toggle("Unlock with \(biometric.name) next time", isOn: $keepForBiometrics)
                    .tint(OSM.accent)
                    .accessibilityIdentifier("remember-biometric")
            }
            Button("Unlock", action: unlock)
                .buttonStyle(.wide)
                .disabled(password.isEmpty || busy)
                .accessibilityIdentifier("unlock")
            if biometric.available && biometric.enabled {
                Button("Use \(biometric.name)", action: onBiometrics)
                    .buttonStyle(.wideQuiet)
                    .accessibilityIdentifier("unlock-biometric")
            }
        }
    }

    private func unlock() {
        guard !password.isEmpty else { return }
        let typed = password
        password = ""
        onUnlock(typed, keepForBiometrics)
    }
}

/// What is under way, over the screen.
struct BusyCover: View {
    let what: String

    var body: some View {
        VStack(spacing: 12) {
            ProgressView()
            Text(what).accessibilityIdentifier("busy")
        }
        .padding(24)
        .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 16, style: .continuous))
    }
}

/// The outcome of the last thing the owner did, shown for a few seconds.
struct NoticeBanner: View {
    @Binding var notice: String?

    var body: some View {
        if let notice {
            Text(notice)
                .padding(12)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 14, style: .continuous))
                .overlay(RoundedRectangle(cornerRadius: 14, style: .continuous).stroke(OSM.hairline, lineWidth: 1))
                .padding()
                .accessibilityIdentifier("notice")
                .task(id: notice) {
                    try? await Task.sleep(for: .seconds(4))
                    if self.notice == notice { self.notice = nil }
                }
        }
    }
}
