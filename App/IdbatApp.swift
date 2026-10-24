import AuthenticationServices
import SwiftUI

@main
struct IdbatApp: App {
    var body: some Scene {
        WindowGroup {
            VStack(alignment: .leading, spacing: 16) {
                Text("idbat").font(.largeTitle.bold())
                Text("A small macOS passkey provider experiment.")
                Text("Enable idbat in System Settings → General → AutoFill & Passwords (or Extensions, depending on macOS version). Then open webauthn.io in Safari and choose idbat when creating a passkey.")
                    .fixedSize(horizontal: false, vertical: true)
                Button("Open AutoFill settings") {
                    ASSettingsHelper.openCredentialProviderAppSettings()
                }
                Text("Keys are software P-256 keys stored locally in the Keychain. This is an experimental build; keep another way to access your accounts.")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
            }
            .padding(28)
            .frame(width: 500)
        }
    }
}
