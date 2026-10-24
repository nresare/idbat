import AppKit
import AuthenticationServices
import LocalAuthentication

final class CredentialProviderViewController: ASCredentialProviderViewController {
    private var request: ASPasskeyCredentialRequest?
    private var registering = false
    private var shouldAuthenticateOnAppearance = false
    private let titleLabel = NSTextField(labelWithString: "")
    private let detailLabel = NSTextField(wrappingLabelWithString: "")
    private let actionButton = NSButton(title: "", target: nil, action: nil)

    override func loadView() {
        view = NSView(frame: NSRect(x: 0, y: 0, width: 420, height: 220))
        preferredContentSize = NSSize(width: 420, height: 220)
        titleLabel.font = .boldSystemFont(ofSize: 17)
        detailLabel.font = .systemFont(ofSize: 13)
        detailLabel.textColor = .secondaryLabelColor
        actionButton.target = self
        actionButton.action = #selector(approve)
        actionButton.bezelStyle = .rounded

        let stack = NSStackView(views: [titleLabel, detailLabel, actionButton])
        stack.orientation = .vertical
        stack.alignment = .leading
        stack.spacing = 14
        stack.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(stack)
        NSLayoutConstraint.activate([
            stack.leadingAnchor.constraint(equalTo: view.leadingAnchor, constant: 24),
            stack.trailingAnchor.constraint(equalTo: view.trailingAnchor, constant: -24),
            stack.centerYAnchor.constraint(equalTo: view.centerYAnchor),
        ])
    }

    override func viewDidAppear() {
        super.viewDidAppear()
        authenticateIfReady()
    }

    override func prepareInterface(forPasskeyRegistration registrationRequest: any ASCredentialRequest) {
        guard let request = registrationRequest as? ASPasskeyCredentialRequest else {
            fail("Unexpected registration request")
            return
        }
        show(request, registering: true)
    }

    override func prepareInterfaceToProvideCredential(for credentialRequest: any ASCredentialRequest) {
        guard let request = credentialRequest as? ASPasskeyCredentialRequest else {
            fail("Unexpected sign-in request")
            return
        }
        show(request, registering: false)
    }

    override func provideCredentialWithoutUserInteraction(for credentialRequest: any ASCredentialRequest) {
        extensionContext.cancelRequest(withError: NSError(
            domain: ASExtensionErrorDomain,
            code: ASExtensionError.Code.userInteractionRequired.rawValue
        ))
    }

    private func show(_ request: ASPasskeyCredentialRequest, registering: Bool) {
        loadViewIfNeeded()
        self.request = request
        self.registering = registering
        let identity = request.credentialIdentity as? ASPasskeyCredentialIdentity
        let site = identity?.relyingPartyIdentifier ?? "this website"
        titleLabel.stringValue = registering ? "Create passkey for \(site)?" : "Sign in to \(site)?"
        detailLabel.stringValue = registering
            ? "This prototype creates a key protected by this Mac's Secure Enclave. Account: \(identity?.userName ?? "unknown")"
            : "Confirm with Touch ID or your Mac password."
        actionButton.title = registering ? "Create passkey" : "Sign in"
        actionButton.isEnabled = true
        shouldAuthenticateOnAppearance = !registering
        if view.window != nil {
            authenticateIfReady()
        }
    }

    private func authenticateIfReady() {
        guard shouldAuthenticateOnAppearance else { return }
        shouldAuthenticateOnAppearance = false
        approve()
    }

    @objc private func approve() {
        guard let request, actionButton.isEnabled else { return }
        actionButton.isEnabled = false
        let context = LAContext()
        context.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: registering ? "Create a passkey" : "Use a passkey") { [weak self] success, error in
            DispatchQueue.main.async {
                guard let self else { return }
                guard success else {
                    self.fail(error?.localizedDescription ?? "Authentication was cancelled")
                    return
                }
                if self.registering {
                    self.registerPasskey(request, authenticationContext: context)
                } else {
                    self.assertPasskey(request, authenticationContext: context)
                }
            }
        }
    }

    private func registerPasskey(_ request: ASPasskeyCredentialRequest, authenticationContext: LAContext) {
        do {
            let (credential, identity) = try Passkey.register(request, authenticationContext: authenticationContext)
            ASCredentialIdentityStore.shared.saveCredentialIdentities([identity]) { [weak self] saved, error in
                DispatchQueue.main.async {
                    guard let self else { return }
                    guard saved else {
                        do {
                            try CredentialStore.deleteKey(credentialID: identity.credentialID)
                        } catch {
                            self.fail("Could not save the passkey identity or remove its key: \(error.localizedDescription)")
                            return
                        }
                        self.fail(error?.localizedDescription ?? "Could not save the passkey identity")
                        return
                    }
                    self.extensionContext.completeRegistrationRequest(using: credential, completionHandler: nil)
                }
            }
        } catch {
            fail(error.localizedDescription)
        }
    }

    private func assertPasskey(_ request: ASPasskeyCredentialRequest, authenticationContext: LAContext) {
        do {
            let credential = try Passkey.assert(request, authenticationContext: authenticationContext)
            extensionContext.completeAssertionRequest(using: credential, completionHandler: nil)
        } catch {
            fail(error.localizedDescription)
        }
    }

    private func fail(_ reason: String) {
        extensionContext.cancelRequest(withError: NSError(
            domain: ASExtensionErrorDomain,
            code: 0,
            userInfo: [NSLocalizedDescriptionKey: reason]
        ))
    }
}
