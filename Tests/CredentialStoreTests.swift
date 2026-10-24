import AuthenticationServices
import Foundation
import Security

@main
enum CredentialStoreTests {
    static func main() throws {
        let keyID = Data([1, 2, 3])
        let staleID = Data([4, 5, 6])
        let unknownID = Data([7, 8, 9])
        let metadata = CredentialMetadata(
            relyingParty: "example.com", userName: "alice",
            userHandle: Data([42]), createdAt: Date(timeIntervalSince1970: 1234)
        )
        let encoded = try JSONEncoder().encode(metadata)
        let identity = metadata.identity(credentialID: keyID)
        let staleIdentity = metadata.identity(credentialID: staleID)
        let attributes: [[String: Any]] = [
            [kSecAttrAccount as String: keyID.base64EncodedString(), kSecAttrGeneric as String: encoded],
            [kSecAttrAccount as String: unknownID.base64EncodedString(), kSecAttrGeneric as String: Data("invalid json".utf8)],
        ]

        // Metadata survives even when AutoFill is disabled and its index is empty.
        let withoutAutoFill = CredentialStore.merge(attributes: attributes, identities: [])
        precondition(withoutAutoFill.count == 2)
        let stored = withoutAutoFill.first { $0.credentialID == keyID }!
        precondition(stored.metadata == metadata)
        precondition(stored.identity?.userHandle == metadata.userHandle)
        precondition(stored.hasKey)

        // Existing keys without metadata get their names from the AutoFill index.
        let oldAttributes = [[kSecAttrAccount as String: keyID.base64EncodedString()]]
        let oldKey = CredentialStore.merge(attributes: oldAttributes, identities: [identity])
        precondition(oldKey.count == 1)
        precondition(oldKey[0].userName == "alice" && oldKey[0].hasKey)

        // A stale AutoFill entry must remain visible for a deletion retry.
        let combined = CredentialStore.merge(attributes: attributes, identities: [identity, staleIdentity])
        precondition(combined.count == 3)
        precondition(combined.first { $0.credentialID == staleID }?.hasKey == false)
        precondition(combined.first { $0.credentialID == keyID }?.metadata == metadata)

        // Missing or malformed metadata must not hide a deletable key.
        let unknown = combined.first { $0.credentialID == unknownID }!
        precondition(unknown.hasKey && unknown.metadata == nil)
        precondition(unknown.relyingParty == "Unknown website")
        precondition(Set(combined.map(\.id)).count == combined.count)
        precondition(CredentialStore.merge(attributes: [], identities: []).isEmpty)
        print("Credential catalog checks passed")
    }
}
