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
            userHandle: Data([42]), createdAt: Date(timeIntervalSince1970: 1234), backupEligible: nil
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

        // Website requests must never match another RP or an unavailable key.
        let matches = CredentialStore.matchingPasskeys(in: combined, relyingParty: "example.com", allowedCredentials: [])
        precondition(matches.map(\.credentialID) == [keyID])
        precondition(CredentialStore.matchingPasskeys(in: combined, relyingParty: "other.example.com", allowedCredentials: []).isEmpty)

        // An explicit allow-list containing a deleted key must report no match,
        // even if a different credential for the same website still exists.
        precondition(CredentialStore.matchingPasskeys(in: combined, relyingParty: "example.com", allowedCredentials: [staleID]).isEmpty)
        precondition(CredentialStore.matchingPasskeys(in: combined, relyingParty: "example.com", allowedCredentials: [keyID]).count == 1)

        // Isolate the AAGUID experiment while preserving the backup flags
        // required by macOS. These flags do not describe our physical storage.
        precondition(Passkey.registrationFlags == 0x5d)
        precondition(Passkey.registrationFlags & 0x18 == 0x18)
        precondition(Passkey.aaguid.count == 16)
        precondition(Passkey.aaguid.map { String(format: "%02x", $0) }.joined() == "b43e6a34f345407f9ba21ae73907faca")
        let deviceBound = CredentialMetadata(
            relyingParty: metadata.relyingParty, userName: metadata.userName,
            userHandle: metadata.userHandle, createdAt: metadata.createdAt,
            backupEligible: false
        )
        let decodedDeviceBound = try JSONDecoder().decode(CredentialMetadata.self, from: JSONEncoder().encode(deviceBound))
        precondition(Passkey.assertionFlags(for: decodedDeviceBound) == 0x05)
        let newRegistration = CredentialMetadata(
            relyingParty: metadata.relyingParty, userName: metadata.userName,
            userHandle: metadata.userHandle, createdAt: metadata.createdAt,
            backupEligible: Passkey.registrationFlags & 0x08 != 0
        )
        precondition(Passkey.registrationFlags & 0xbf == Passkey.assertionFlags(for: newRegistration))

        // Older JSON does not contain the new field. Its assertion flags must
        // still match what was sent when those credentials were registered.
        let oldJSON = try JSONSerialization.jsonObject(with: encoded) as! [String: Any]
        precondition(oldJSON["backupEligible"] == nil)
        let decodedOld = try JSONDecoder().decode(CredentialMetadata.self, from: encoded)
        precondition(decodedOld.backupEligible == nil)
        precondition(Passkey.assertionFlags(for: decodedOld) == 0x1d)
        precondition(Passkey.assertionFlags(for: nil) == 0x1d)
        print("Credential catalog checks passed")
    }
}
