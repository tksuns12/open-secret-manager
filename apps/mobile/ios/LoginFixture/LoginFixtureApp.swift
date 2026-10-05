import SwiftUI

/// A stand-in for another app with a login form, for the AutoFill tests
/// (UITests). It shows what was filled, for the tests to read; signing in
/// takes the form away, as an app does. Never shipped.
@main
struct LoginFixtureApp: App {
    var body: some Scene {
        WindowGroup { LoginForm() }
    }
}

private struct LoginForm: View {
    @State private var username = ""
    @State private var password = ""
    @State private var signedIn = false

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            if signedIn {
                Text("Signed in").font(.title).accessibilityIdentifier("signed-in")
            } else {
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
                Button("Sign in") { signedIn = true }
                    .buttonStyle(.borderedProminent)
                    .accessibilityIdentifier("fixture-sign-in")
            }
            Text("\(username)|\(password)").accessibilityIdentifier("filled")
            Spacer()
        }
        .padding()
    }
}
