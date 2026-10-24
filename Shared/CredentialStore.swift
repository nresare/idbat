import AuthenticationServices
import Foundation
import Security

enum CredentialStoreError: LocalizedError {
    case keychain(OSStatus)
    case missingKey

    var errorDescription: String? {
        switch self {
        case .keychain(let status): "Keychain error: \(status)."
        case .missingKey: "The passkey could not be found in the Keychain."
        }
    }
}

struct CredentialMetadata: Codable, Equatable {
    let relyingParty: String
    let userName: String
    let userHandle: Data
    let createdAt: Date

    func identity(credentialID: Data) -> ASPasskeyCredentialIdentity {
        ASPasskeyCredentialIdentity(
            relyingPartyIdentifier: relyingParty,
            userName: userName,
            credentialID: credentialID,
            userHandle: userHandle,
            recordIdentifier: credentialID.base64EncodedString()
        )
    }
}

struct StoredCredential: Identifiable {
    let credentialID: Data
    let metadata: CredentialMetadata?
    let identity: ASPasskeyCredentialIdentity?
    let hasKey: Bool

    var id: String { credentialID.base64EncodedString() }
    var relyingParty: String { metadata?.relyingParty ?? identity?.relyingPartyIdentifier ?? "Unknown website" }
    var userName: String { metadata?.userName ?? identity?.userName ?? "Unknown account" }
}

/// Both targets use the provider's Keychain access group. Listing requests only
/// attributes; it never loads the encrypted key representations.
enum CredentialStore {
    private static let service = "is.idbat.passkeys.secure-enclave"

    private static var baseQuery: [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecUseDataProtectionKeychain as String: true,
        ]
    }

    static func save(_ representation: Data, credentialID: Data, metadata: CredentialMetadata) throws {
        var query = baseQuery
        query[kSecAttrAccount as String] = credentialID.base64EncodedString()
        query[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        query[kSecAttrGeneric as String] = try JSONEncoder().encode(metadata)
        query[kSecAttrLabel as String] = "\(metadata.relyingParty) — \(metadata.userName)"
        query[kSecValueData as String] = representation
        let status = SecItemAdd(query as CFDictionary, nil)
        guard status == errSecSuccess else { throw CredentialStoreError.keychain(status) }
    }

    static func load(credentialID: Data) throws -> Data {
        var query = baseQuery
        query[kSecAttrAccount as String] = credentialID.base64EncodedString()
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecItemNotFound { throw CredentialStoreError.missingKey }
        guard status == errSecSuccess else { throw CredentialStoreError.keychain(status) }
        guard let data = result as? Data else { throw CredentialStoreError.missingKey }
        return data
    }

    static func deleteKey(credentialID: Data) throws {
        var query = baseQuery
        query[kSecAttrAccount as String] = credentialID.base64EncodedString()
        let status = SecItemDelete(query as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw CredentialStoreError.keychain(status)
        }
    }

    static func list() async throws -> [StoredCredential] {
        let identities: [ASPasskeyCredentialIdentity]
        if #available(macOS 14.4, *) {
            identities = await ASCredentialIdentityStore.shared.credentialIdentities(
                forService: nil, credentialIdentityTypes: .passkey
            ).compactMap { $0 as? ASPasskeyCredentialIdentity }
        } else {
            identities = []
        }
        var query = baseQuery
        query[kSecReturnAttributes as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitAll
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw CredentialStoreError.keychain(status)
        }
        let attributes = result as? [[String: Any]] ?? []
        return merge(attributes: attributes, identities: identities)
    }

    static func merge(attributes: [[String: Any]], identities: [ASPasskeyCredentialIdentity]) -> [StoredCredential] {
        var records: [String: StoredCredential] = [:]
        for identity in identities {
            let record = StoredCredential(credentialID: identity.credentialID, metadata: nil, identity: identity, hasKey: false)
            records[record.id] = record
        }
        for item in attributes {
            guard let account = item[kSecAttrAccount as String] as? String,
                  let credentialID = Data(base64Encoded: account) else { continue }
            // Older items have no metadata. AutoFill identities can supply their names.
            let metadata = (item[kSecAttrGeneric as String] as? Data).flatMap {
                try? JSONDecoder().decode(CredentialMetadata.self, from: $0)
            }
            let identity = records[account]?.identity ?? metadata?.identity(credentialID: credentialID)
            records[account] = StoredCredential(credentialID: credentialID, metadata: metadata, identity: identity, hasKey: true)
        }
        return records.values.sorted {
            if $0.relyingParty != $1.relyingParty { return $0.relyingParty < $1.relyingParty }
            if $0.userName != $1.userName { return $0.userName < $1.userName }
            return $0.id < $1.id
        }
    }

    static func delete(_ credential: StoredCredential) async throws {
        // Delete the key first. If removing the AutoFill entry fails, list() still
        // shows that entry without a key, so the user can retry its removal.
        try deleteKey(credentialID: credential.credentialID)
        let store = ASCredentialIdentityStore.shared
        let state = await store.state()
        if state.isEnabled, let identity = credential.identity {
            try await store.removeCredentialIdentities([identity])
        }
    }
}
