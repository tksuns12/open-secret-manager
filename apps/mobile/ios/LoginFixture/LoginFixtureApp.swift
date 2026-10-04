import SwiftUI

/// A stand-in for another app with a login form, for the AutoFill tests
/// (UITests). It shows what was filled, for the tests to read. Never shipped.
@main
struct LoginFixtureApp: App {
    var body: some Scene {
        WindowGroup { LoginForm() }
    }
}

private struct LoginForm: View {
    @State private var username = ""
    @State private var password = ""

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("Sign in").font(.title)
            TextField("Account", text: $username)
                .textContentType(.username)
                .textInputAutocapitalization(.never)
                .autocorrectionDisabled()
                .textFieldStyle(.roundedBorder)
                .accessibilityIdentifier("fixture-username")
            SecureField("Password", text: $password)
                .textContentType(.password)
                .textFieldStyle(.roundedBorder)
                .accessibilityIdentifier("fixture-password")
            Text("\(username)|\(password)").accessibilityIdentifier("filled")
            Spacer()
        }
        .padding()
    }
}
