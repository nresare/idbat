import AppKit
import AuthenticationServices
import LocalAuthentication

final class CredentialProviderViewController: ASCredentialProviderViewController {
    private var request: ASPasskeyCredentialRequest?
    private var registering = false
    private var shouldAuthenticateOnAppearance = false
    private var displayedFailure: NSError?
    private var credentialChoices: [ASPasskeyCredentialRequest] = []
    private let titleLabel = NSTextField(labelWithString: "")
    private let detailLabel = NSTextField(wrappingLabelWithString: "")
    private let actionButton = NSButton(title: "", target: nil, action: nil)
    private let accountPicker = NSPopUpButton(frame: .zero, pullsDown: false)

    override func loadView() {
        view = NSView(frame: NSRect(x: 0, y: 0, width: 420, height: 220))
        preferredContentSize = NSSize(width: 420, height: 220)
        titleLabel.font = .boldSystemFont(ofSize: 17)
        detailLabel.font = .systemFont(ofSize: 13)
        detailLabel.textColor = .secondaryLabelColor
        actionButton.target = self
        actionButton.action = #selector(approve)
        actionButton.bezelStyle = .rounded

        accountPicker.isHidden = true
        let stack = NSStackView(views: [titleLabel, detailLabel, accountPicker, actionButton])
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
        guard let identity = request.credentialIdentity as? ASPasskeyCredentialIdentity else {
            fail("The system did not provide a passkey identity.")
            return
        }
        do {
            guard try CredentialStore.contains(credentialID: identity.credentialID) else {
                showMissingKey(for: identity.relyingPartyIdentifier)
                return
            }
            show(request, registering: false)
        } catch {
            fail(error.localizedDescription)
        }
    }

    override func prepareCredentialList(for serviceIdentifiers: [ASCredentialServiceIdentifier]) {
        showFailure(
            title: "No password credentials",
            message: "idbat provides passkeys only. Choose passkey sign-in on the website.",
            code: .credentialIdentityNotFound
        )
    }

    override func prepareCredentialList(for serviceIdentifiers: [ASCredentialServiceIdentifier], requestParameters: ASPasskeyCredentialRequestParameters) {
        loadViewIfNeeded()
        request = nil
        shouldAuthenticateOnAppearance = false
        displayedFailure = nil
        credentialChoices = []
        accountPicker.isHidden = true
        titleLabel.stringValue = "Finding passkeys…"
        detailLabel.stringValue = requestParameters.relyingPartyIdentifier
        actionButton.isEnabled = false
        actionButton.isHidden = true

        Task { @MainActor [weak self] in
            do {
                let credentials = try await CredentialStore.list()
                guard let self else { return }
                let matches = CredentialStore.matchingPasskeys(
                    in: credentials,
                    relyingParty: requestParameters.relyingPartyIdentifier,
                    allowedCredentials: requestParameters.allowedCredentials
                )
                let choices = matches.compactMap { credential -> ASPasskeyCredentialRequest? in
                    guard let identity = credential.identity else { return nil }
                    return ASPasskeyCredentialRequest(
                        credentialIdentity: identity,
                        clientDataHash: requestParameters.clientDataHash,
                        userVerificationPreference: requestParameters.userVerificationPreference,
                        supportedAlgorithms: [ASCOSEAlgorithmIdentifier]()
                    )
                }
                if choices.count == 1, let choice = choices.first {
                    self.prepareInterfaceToProvideCredential(for: choice)
                } else if choices.isEmpty {
                    self.showMissingKey(for: requestParameters.relyingPartyIdentifier)
                } else {
                    self.credentialChoices = choices
                    self.registering = false
                    self.titleLabel.stringValue = "Choose a passkey"
                    self.detailLabel.stringValue = "Sign in to \(requestParameters.relyingPartyIdentifier)."
                    self.accountPicker.removeAllItems()
                    self.accountPicker.addItems(withTitles: matches.map {
                        "\($0.userName) (\($0.id.prefix(8)))"
                    })
                    self.accountPicker.isHidden = false
                    self.actionButton.title = "Sign in"
                    self.actionButton.action = #selector(self.approve)
                    self.actionButton.isEnabled = true
                    self.actionButton.isHidden = false
                }
            } catch {
                self?.fail(error.localizedDescription)
            }
        }
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
        displayedFailure = nil
        credentialChoices = []
        accountPicker.isHidden = true
        let identity = request.credentialIdentity as? ASPasskeyCredentialIdentity
        let site = identity?.relyingPartyIdentifier ?? "this website"
        titleLabel.stringValue = registering ? "Create passkey for \(site)" : "Sign in to \(site)"
        detailLabel.stringValue = registering
            ? "Account: \(identity.map { displayName($0.userName) } ?? "unknown")\nConfirm with Touch ID or your Mac password."
            : "Confirm with Touch ID or your Mac password."
        actionButton.title = registering ? "Create passkey" : "Sign in"
        actionButton.isEnabled = true
        actionButton.action = #selector(approve)
        actionButton.isHidden = true
        shouldAuthenticateOnAppearance = true
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
        if !credentialChoices.isEmpty {
            let index = accountPicker.indexOfSelectedItem
            guard credentialChoices.indices.contains(index) else { return }
            request = credentialChoices[index]
        }
        guard let request, actionButton.isEnabled else { return }
        actionButton.isEnabled = false
        // Sign-in starts on its own, so the system prompt is often all the user
        // reads. Name the website there.
        let site = (request.credentialIdentity as? ASPasskeyCredentialIdentity)?.relyingPartyIdentifier ?? "this website"
        let reason = registering ? "create a passkey for \(site)" : "sign in to \(site)"
        let context = LAContext()
        context.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: reason) { [weak self] success, error in
            DispatchQueue.main.async {
                guard let self else { return }
                guard success else {
                    if let authenticationError = error as? LAError,
                       [.userCancel, .appCancel, .systemCancel].contains(authenticationError.code) {
                        self.extensionContext.cancelRequest(withError: NSError(
                            domain: ASExtensionErrorDomain,
                            code: ASExtensionError.Code.userCanceled.rawValue,
                            userInfo: [NSLocalizedDescriptionKey: authenticationError.localizedDescription]
                        ))
                    } else {
                        self.fail(error?.localizedDescription ?? "Authentication failed")
                    }
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
        } catch CredentialStoreError.missingKey {
            let identity = request.credentialIdentity as? ASPasskeyCredentialIdentity
            showMissingKey(for: identity?.relyingPartyIdentifier ?? "this website")
        } catch {
            fail(error.localizedDescription)
        }
    }

    private func fail(_ reason: String) {
        showFailure(title: "Could not complete request", message: reason, code: .failed)
    }

    private func showMissingKey(for site: String) {
        showFailure(
            title: "Passkey not found",
            message: "No matching passkey for \(site) is stored in idbat on this Mac. It may have been deleted. Use another sign-in method, then register a new passkey.",
            code: .credentialIdentityNotFound
        )
    }

    private func showFailure(title: String, message: String, code: ASExtensionError.Code) {
        loadViewIfNeeded()
        request = nil
        shouldAuthenticateOnAppearance = false
        credentialChoices = []
        accountPicker.isHidden = true
        displayedFailure = NSError(
            domain: ASExtensionErrorDomain,
            code: code.rawValue,
            userInfo: [NSLocalizedDescriptionKey: message]
        )
        titleLabel.stringValue = title
        detailLabel.stringValue = message
        actionButton.title = "Close"
        actionButton.action = #selector(closeFailure)
        actionButton.isEnabled = true
        actionButton.isHidden = false
    }

    @objc private func closeFailure() {
        guard let displayedFailure else { return }
        actionButton.isEnabled = false
        extensionContext.cancelRequest(withError: displayedFailure)
    }
}
