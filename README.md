# idbat

An experimental, open source macOS passkey credential provider written in Swift. Its first goal is to create a passkey from Safari and complete a sign-in with that passkey. It uses Apple's native `AuthenticationServices` credential provider extension, with no browser extension or server.

## Build and try it

1. Open `idbat.xcodeproj` in Xcode 27 or later.
2. Choose your Apple Developer team for **both** the `idbat` and `IdbatProvider` targets under Signing & Capabilities. Change the bundle IDs if `re.noa.idbat` and `re.noa.idbat.provider` do not belong to your team. Keep the provider ID under the app ID.
3. Build and run the `idbat` scheme on your Mac.
4. Enable **idbat Passkeys** in System Settings → General → AutoFill & Passwords (the exact location varies by macOS version). The app has a button to open credential provider settings.
5. In Safari, visit [webauthn.io](https://webauthn.io), enter a test username, and choose **Register**. Select idbat as the passkey provider, then approve the local authentication prompt.
6. Try **Authenticate** with the same username. Safari should offer the idbat credential.

You can verify the project compiles without signing with:

```sh
xcodebuild -project idbat.xcodeproj -scheme idbat \
  -derivedDataPath /tmp/idbat-derived CODE_SIGNING_ALLOWED=NO build
```

## Current design

- Registration and assertion use ES256 (P-256 with SHA-256).
- Private keys are software keys kept in the local, device-only Keychain. The Secure Enclave is **not** used yet.
- The extension asks macOS to verify the user before it creates or uses a key. Touch ID or the Mac password may be used.
- Credentials use `none` attestation and a zero signature counter.
- The provider saves credential metadata in `ASCredentialIdentityStore` so Safari can find the passkey again.

## Important prototype limitations

This is for testing with disposable accounts. There is no credential list, deletion UI, migration, recovery, security review, or protection against orphaned keys if a website rejects a registration after the extension finishes.

Apple's credential provider flow currently appears to require the WebAuthn backup eligibility and backup state flags to be set. This prototype sets both flags, even though its local Keychain keys have no backup. **The flags therefore do not accurately describe the key's storage.** Resolving that platform limitation is required before presenting this as a trustworthy device-bound passkey provider.

Building and running the extension requires a configured developer team. To check the complete flow, use a signed build and verify both registration and authentication in Safari.
