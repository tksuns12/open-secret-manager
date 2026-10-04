import AuthenticationServices
import SwiftUI

/// What the system opens when the owner chooses this app to fill a login
/// form in another app or a page. It registers no logins with the system,
/// so the system knows nothing of the vault, and every fill starts here.
final class CredentialProviderViewController: ASCredentialProviderViewController {
    private var model: FillModel?

    override func prepareCredentialList(for serviceIdentifiers: [ASCredentialServiceIdentifier]) {
        let model = FillModel(
            requester: FillRequester(serviceIdentifiers),
            onFill: { [weak self] credentials in
                self?.extensionContext.completeRequest(
                    withSelectedCredential: ASPasswordCredential(user: credentials.username, password: credentials.password),
                    completionHandler: nil
                )
            },
            onCancel: { [weak self] in
                self?.extensionContext.cancelRequest(withError: NSError(
                    domain: ASExtensionErrorDomain,
                    code: ASExtensionError.Code.userCanceled.rawValue
                ))
            }
        )
        self.model = model
        let host = UIHostingController(rootView: FillView(model: model))
        addChild(host)
        host.view.frame = view.bounds
        host.view.autoresizingMask = [.flexibleWidth, .flexibleHeight]
        view.addSubview(host.view)
        host.didMove(toParent: self)
    }

    override func provideCredentialWithoutUserInteraction(for credentialRequest: any ASCredentialRequest) {
        extensionContext.cancelRequest(withError: NSError(
            domain: ASExtensionErrorDomain,
            code: ASExtensionError.Code.userInteractionRequired.rawValue
        ))
    }

    override func viewDidDisappear(_ animated: Bool) {
        super.viewDidDisappear(animated)
        model?.close()
    }
}
