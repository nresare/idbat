# idbat

An experimental, open source macOS passkey credential provider written in Swift. Its first goal is to create a passkey from Safari and complete a sign-in with that passkey. It uses Apple's native `AuthenticationServices` credential provider extension, with no browser extension or server.

## Build and try it

1. Open `idbat.xcodeproj` in Xcode 27 or later.
2. Choose your Apple Developer team for **both** the `idbat` and `IdbatProvider` targets under Signing & Capabilities. Change the bundle IDs if `re.noa.idbat` and `re.noa.idbat.provider` do not belong to your team. Keep the provider ID under the app ID. Both targets use Keychain Sharing with the group `$(AppIdentifierPrefix)re.noa.idbat.provider`; if you change the provider's bundle ID, update that group in both entitlements files to match.
3. Build and run the `idbat` scheme on your Mac.
4. Enable **idbat Passkeys** in System Settings → General → AutoFill & Passwords (the exact location varies by macOS version). The app has a button to open credential provider settings.
5. In Safari, visit [webauthn.io](https://webauthn.io), enter a test username, and choose **Register**. Select idbat as the passkey provider, then approve the local authentication prompt.
6. Try **Authenticate** with the same username. Safari should offer the idbat credential.
7. Open idbat to see saved credentials. The list refreshes when the app becomes active, or when you click **Refresh**. Use the trash button to delete a credential's local key and AutoFill entry. This does not remove the passkey registration from the website; manage that separately in the website's account settings.

You can verify the project compiles without signing with:

```sh
xcodebuild -project idbat.xcodeproj -scheme idbat \
  -derivedDataPath /tmp/idbat-derived CODE_SIGNING_ALLOWED=NO build
```

## Current design

- Registration and assertion use ES256 (P-256 with SHA-256).
- Private keys are generated and used in the Secure Enclave. The local, device-only Keychain stores their encrypted representations, not raw private keys. Registration and authentication require a Mac with an available Secure Enclave; there is no software-key fallback.
- The extension asks macOS to verify the user before it creates or uses a key. Touch ID or the Mac password may be used. Secure Enclave keys also require user presence through their access-control policy. Sign-in starts verification automatically when the provider interface appears.
- Credentials use `none` attestation and a zero signature counter.
- The provider saves credential metadata in `ASCredentialIdentityStore` so Safari can find the passkey again.
- The app and extension share a Keychain access group. Website, account, user handle, and creation date are saved as attributes alongside each encrypted key representation. Listing credentials reads attributes only. AutoFill entries with missing keys are also shown so they can be removed. Existing keys without saved metadata use AutoFill names when available on macOS 14.4 or later; otherwise they appear with an unknown website/account.
- When a sign-in request reaches idbat without a matching local key, the provider shows **Passkey not found**. Closing that message returns a credential-not-found error to macOS. If Safari does not invoke idbat, the browser and website control the failure indication.

## Important prototype limitations

This is for testing with disposable accounts. There is no migration, recovery, security review, or protection against orphaned keys if a website rejects a registration after the extension finishes. Deletion is permanent; keep another way to sign in.

Apple's credential provider flow currently appears to require the WebAuthn backup eligibility and backup state flags to be set. This prototype sets both flags, even though its device-bound keys have no backup. **The flags therefore do not accurately describe the key's storage.** Resolving that platform limitation is required before presenting this as a trustworthy device-bound passkey provider.

Building and running the extension requires a configured developer team. To check the complete flow, use a signed build and verify both registration and authentication in Safari.
