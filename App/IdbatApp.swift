import AuthenticationServices
import SwiftUI

@main
struct IdbatApp: App {
    var body: some Scene {
        WindowGroup {
            CredentialListView()
        }
        .defaultSize(width: 680, height: 500)
    }
}

private struct CredentialListView: View {
    @Environment(\.scenePhase) private var scenePhase
    @State private var credentials: [StoredCredential] = []
    @State private var pendingDeletion: StoredCredential?
    @State private var isBusy = false
    @State private var hasLoaded = false
    @State private var errorMessage: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            HStack {
                VStack(alignment: .leading, spacing: 4) {
                    Text("idbat").font(.largeTitle.bold())
                    Text("Passkeys stored on this Mac").foregroundStyle(.secondary)
                }
                Spacer()
                if isBusy { ProgressView().controlSize(.small) }
                Button("Refresh", systemImage: "arrow.clockwise") {
                    Task { await refresh() }
                }
                .disabled(isBusy)
                Button("Open AutoFill settings") {
                    ASSettingsHelper.openCredentialProviderAppSettings()
                }
            }

            if let errorMessage {
                Text(errorMessage)
                    .foregroundStyle(.red)
                    .textSelection(.enabled)
            }

            List {
                ForEach(credentials) { credential in
                    HStack(spacing: 16) {
                        Image(systemName: "key.fill").foregroundStyle(.secondary)
                        VStack(alignment: .leading, spacing: 4) {
                            Text(credential.relyingParty).font(.headline)
                            Text(credential.userName)
                            HStack {
                                Text(String(credential.id.prefix(12)))
                                    .font(.system(.caption, design: .monospaced))
                                if let date = credential.metadata?.createdAt {
                                    Text(date, style: .date).font(.caption)
                                }
                                if !credential.hasKey {
                                    Text("Key unavailable").font(.caption)
                                }
                            }
                            .foregroundStyle(.secondary)
                        }
                        .textSelection(.enabled)
                        Spacer()
                        Button(role: .destructive) {
                            pendingDeletion = credential
                        } label: {
                            Image(systemName: "trash")
                        }
                        .buttonStyle(.borderless)
                        .accessibilityLabel("Delete passkey for \(credential.userName) at \(credential.relyingParty)")
                        .disabled(isBusy)
                    }
                    .padding(.vertical, 6)
                }
            }
            .overlay {
                if hasLoaded && credentials.isEmpty {
                    ContentUnavailableView {
                        Label("No saved passkeys", systemImage: "key")
                    } description: {
                        Text("Enable idbat in AutoFill settings, then create a passkey in Safari.")
                    }
                }
            }

            Text("Passkeys are protected by this Mac’s Secure Enclave. Deleting a passkey here does not remove it from the website’s account settings. This is an experimental build; keep another way to access your accounts.")
                .font(.footnote)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
        }
        .padding(24)
        .frame(minWidth: 620, minHeight: 420)
        .task { await refresh() }
        .onChange(of: scenePhase) { _, phase in
            if phase == .active { Task { await refresh() } }
        }
        .alert(item: $pendingDeletion) { credential in
            Alert(
                title: Text("Delete passkey?"),
                message: Text("Delete the passkey for \(credential.userName) at \(credential.relyingParty) from this Mac? This cannot be undone. Make sure you have another way to sign in."),
                primaryButton: .destructive(Text("Delete")) {
                    Task { await remove(credential) }
                },
                secondaryButton: .cancel()
            )
        }
    }

    @MainActor
    private func refresh() async {
        guard !isBusy else { return }
        isBusy = true
        defer { isBusy = false }
        do {
            credentials = try await CredentialStore.list()
            hasLoaded = true
            errorMessage = nil
        } catch {
            errorMessage = "Could not load passkeys: \(error.localizedDescription)"
        }
    }

    @MainActor
    private func remove(_ credential: StoredCredential) async {
        guard !isBusy else { return }
        isBusy = true
        defer { isBusy = false }
        do {
            try await CredentialStore.delete(credential)
            errorMessage = nil
        } catch {
            errorMessage = "Could not finish deleting the passkey. Refresh and retry: \(error.localizedDescription)"
        }
        do {
            credentials = try await CredentialStore.list()
            hasLoaded = true
        } catch {
            errorMessage = "Could not reload passkeys after deletion: \(error.localizedDescription)"
        }
    }
}
