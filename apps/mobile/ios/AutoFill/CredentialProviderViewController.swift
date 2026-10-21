import AuthenticationServices
import SwiftUI

/// What the system opens when the owner chooses this app to fill a login
/// form in another app or a page, from iOS 18 to insert the text of an
/// item's field, or, from iOS 26.2, to save what a login form submitted. It
/// registers no logins with the system, so the system knows nothing of the
/// vault, and every fill and save starts here.
final class CredentialProviderViewController: ASCredentialProviderViewController {
    private var model: FillModel?

    private var userCanceled: NSError {
        NSError(domain: ASExtensionErrorDomain, code: ASExtensionError.Code.userCanceled.rawValue)
    }

    private func show(_ model: FillModel) {
        self.model = model
        let host = UIHostingController(rootView: FillView(model: model))
        addChild(host)
        host.view.frame = view.bounds
        host.view.autoresizingMask = [.flexibleWidth, .flexibleHeight]
        view.addSubview(host.view)
        host.didMove(toParent: self)
    }

    override func prepareCredentialList(for serviceIdentifiers: [ASCredentialServiceIdentifier]) {
        show(FillModel(
            requester: FillRequester(serviceIdentifiers),
            onFill: { [weak self] credentials in
                self?.extensionContext.completeRequest(
                    withSelectedCredential: ASPasswordCredential(user: credentials.username, password: credentials.password),
                    completionHandler: nil
                )
            },
            onCancel: { [weak self] in
                guard let self else { return }
                extensionContext.cancelRequest(withError: userCanceled)
            }
        ))
    }

    /// A one-time code for a field that asks for one. Not reached yet: the
    /// extension does not declare `ProvidesOneTimeCodes`, since iOS offers a
    /// provider's codes only for the sites it registered with the system,
    /// and it registers none.
    @available(iOS 18.0, *)
    override func prepareOneTimeCodeCredentialList(for serviceIdentifiers: [ASCredentialServiceIdentifier]) {
        show(FillModel(
            requester: FillRequester(serviceIdentifiers),
            oneTimeCode: true,
            onCode: { [weak self] code in
                self?.extensionContext.completeOneTimeCodeRequest(using: ASOneTimeCodeCredential(code: code), completionHandler: nil)
            },
            onCancel: { [weak self] in
                guard let self else { return }
                extensionContext.cancelRequest(withError: userCanceled)
            }
        ))
    }

    /// The text of one field of an item, for the field the owner chose
    /// AutoFill and then Passwords in: a card's number or security code, a
    /// password, or another. iOS lets no other app fill a card, and this is
    /// how one goes into a card form here. iOS says nothing of where the
    /// text goes, so it is the owner's choice alone, as a paste is.
    @available(iOS 18.0, *)
    override func prepareInterfaceForUserChoosingTextToInsert() {
        show(FillModel(
            requester: .unnamed,
            inserting: true,
            onText: { [weak self] text in
                self?.extensionContext.completeRequest(withTextToInsert: text, completionHandler: nil)
            },
            onCancel: { [weak self] in
                guard let self else { return }
                extensionContext.cancelRequest(withError: userCanceled)
            }
        ))
    }

    override func provideCredentialWithoutUserInteraction(for credentialRequest: any ASCredentialRequest) {
        extensionContext.cancelRequest(withError: NSError(
            domain: ASExtensionErrorDomain,
            code: ASExtensionError.Code.userInteractionRequired.rawValue
        ))
    }

    /// Nothing is saved without the owner, who unlocks and chooses where it
    /// goes: the system is asked for the save screen. A password the system
    /// generated and filled into a form not yet sent is not saved apart; the
    /// form's submission brings it again.
    @available(iOS 26.2, *)
    override func performWithoutUserInteractionIfPossible(savePasswordRequest: ASSavePasswordRequest) {
        let code: ASExtensionError.Code = savePasswordRequest.event == .generatedPasswordFilled ? .failed : .userInteractionRequired
        extensionContext.cancelRequest(withError: NSError(domain: ASExtensionErrorDomain, code: code.rawValue))
    }

    @available(iOS 26.2, *)
    override func prepareInterface(for savePasswordRequest: ASSavePasswordRequest) {
        let credential = savePasswordRequest.credential
        show(FillModel(
            requester: FillRequester([savePasswordRequest.serviceIdentifier]),
            saving: Saving(username: credential.user, password: credential.password, title: savePasswordRequest.title),
            onSaved: { [weak self] in
                self?.extensionContext.completeSavePasswordRequest(completionHandler: nil)
            },
            onCancel: { [weak self] in
                guard let self else { return }
                extensionContext.cancelRequest(withError: userCanceled)
            }
        ))
    }

    override func viewDidDisappear(_ animated: Bool) {
        super.viewDidDisappear(animated)
        model?.close()
    }
}
