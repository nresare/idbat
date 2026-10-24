import AuthenticationServices
import CryptoKit
import Foundation
import Security

enum PasskeyError: LocalizedError {
    case unsupportedAlgorithm
    case invalidPublicKey
    case keychain(OSStatus)
    case missingKey
    case invalidIdentity

    var errorDescription: String? {
        switch self {
        case .unsupportedAlgorithm: "This site does not support ES256 passkeys."
        case .invalidPublicKey: "The generated public key has an unexpected format."
        case .keychain(let status): "Keychain error: \(status)."
        case .missingKey: "The passkey could not be found in the Keychain."
        case .invalidIdentity: "The system did not provide a passkey identity."
        }
    }
}

/// The first prototype uses a software P-256 key in the local Keychain.
/// It deliberately makes no claim that the key is Secure Enclave backed.
enum Passkey {
    private static let service = "is.idbat.passkeys"

    static func register(_ request: ASPasskeyCredentialRequest) throws -> (ASPasskeyRegistrationCredential, ASPasskeyCredentialIdentity) {
        guard request.supportedAlgorithms.contains(where: { $0.rawValue == -7 }) else {
            throw PasskeyError.unsupportedAlgorithm
        }

        guard let requestedIdentity = request.credentialIdentity as? ASPasskeyCredentialIdentity else {
            throw PasskeyError.invalidIdentity
        }
        let rpID = requestedIdentity.relyingPartyIdentifier
        let credentialID = Data((0..<32).map { _ in UInt8.random(in: 0...255) })
        let privateKey = P256.Signing.PrivateKey()
        let publicKey = privateKey.publicKey.x963Representation
        guard publicKey.count == 65, publicKey.first == 0x04 else {
            throw PasskeyError.invalidPublicKey
        }

        var authData = Data(SHA256.hash(data: Data(rpID.utf8)))
        authData.append(0x5d) // UP, UV, BE, BS, AT. Apple currently requires BE and BS.
        authData.append(contentsOf: [0, 0, 0, 0]) // No signature counter.
        authData.append(contentsOf: repeatElement(UInt8(0), count: 16)) // Privacy-preserving AAGUID.
        authData.append(UInt8(credentialID.count >> 8))
        authData.append(UInt8(credentialID.count & 0xff))
        authData.append(credentialID)
        authData.append(CBOR.map([
            (CBOR.int(1), CBOR.int(2)), // EC2 key type
            (CBOR.int(3), CBOR.int(-7)), // ES256
            (CBOR.int(-1), CBOR.int(1)), // P-256
            (CBOR.int(-2), CBOR.bytes(Data(publicKey[1..<33]))),
            (CBOR.int(-3), CBOR.bytes(Data(publicKey[33..<65]))),
        ]))

        let attestation = CBOR.map([
            (CBOR.text("fmt"), CBOR.text("none")),
            (CBOR.text("attStmt"), CBOR.map([])),
            (CBOR.text("authData"), CBOR.bytes(authData)),
        ])
        try save(privateKey.rawRepresentation, credentialID: credentialID)

        let identity = ASPasskeyCredentialIdentity(
            relyingPartyIdentifier: rpID,
            userName: requestedIdentity.userName,
            credentialID: credentialID,
            userHandle: requestedIdentity.userHandle,
            recordIdentifier: credentialID.base64EncodedString()
        )
        let credential = ASPasskeyRegistrationCredential(
            relyingParty: rpID,
            clientDataHash: request.clientDataHash,
            credentialID: credentialID,
            attestationObject: attestation
        )
        return (credential, identity)
    }

    static func assert(_ request: ASPasskeyCredentialRequest) throws -> ASPasskeyAssertionCredential {
        guard let identity = request.credentialIdentity as? ASPasskeyCredentialIdentity else {
            throw PasskeyError.invalidIdentity
        }
        let privateKey = try P256.Signing.PrivateKey(rawRepresentation: load(credentialID: identity.credentialID))
        var authData = Data(SHA256.hash(data: Data(identity.relyingPartyIdentifier.utf8)))
        authData.append(0x1d) // UP, UV, BE, BS.
        authData.append(contentsOf: [0, 0, 0, 0])
        let signature = try privateKey.signature(for: authData + request.clientDataHash).derRepresentation
        return ASPasskeyAssertionCredential(
            userHandle: identity.userHandle,
            relyingParty: identity.relyingPartyIdentifier,
            signature: signature,
            clientDataHash: request.clientDataHash,
            authenticatorData: authData,
            credentialID: identity.credentialID
        )
    }

    private static func save(_ key: Data, credentialID: Data) throws {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: credentialID.base64EncodedString(),
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            kSecUseDataProtectionKeychain as String: true,
            kSecValueData as String: key,
        ]
        let status = SecItemAdd(query as CFDictionary, nil)
        guard status == errSecSuccess else { throw PasskeyError.keychain(status) }
    }

    private static func load(credentialID: Data) throws -> Data {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: credentialID.base64EncodedString(),
            kSecUseDataProtectionKeychain as String: true,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        guard status == errSecSuccess else {
            if status == errSecItemNotFound { throw PasskeyError.missingKey }
            throw PasskeyError.keychain(status)
        }
        guard let data = result as? Data else { throw PasskeyError.missingKey }
        return data
    }

    static func delete(credentialID: Data) {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: credentialID.base64EncodedString(),
            kSecUseDataProtectionKeychain as String: true,
        ]
        SecItemDelete(query as CFDictionary)
    }
}

/// Small CBOR encoder for the exact WebAuthn structures above.
private enum CBOR {
    static func int(_ value: Int) -> Data {
        if value >= 0 { return header(major: 0, value: UInt64(value)) }
        return header(major: 1, value: UInt64(-1 - value))
    }

    static func bytes(_ value: Data) -> Data { header(major: 2, value: UInt64(value.count)) + value }
    static func text(_ value: String) -> Data {
        let utf8 = Data(value.utf8)
        return header(major: 3, value: UInt64(utf8.count)) + utf8
    }

    static func map(_ entries: [(Data, Data)]) -> Data {
        entries.reduce(into: header(major: 5, value: UInt64(entries.count))) { result, entry in
            result.append(entry.0)
            result.append(entry.1)
        }
    }

    private static func header(major: UInt8, value: UInt64) -> Data {
        if value < 24 { return Data([major << 5 | UInt8(value)]) }
        if value <= 0xff { return Data([major << 5 | 24, UInt8(value)]) }
        if value <= 0xffff { return Data([major << 5 | 25, UInt8(value >> 8), UInt8(value & 0xff)]) }
        return Data([major << 5 | 26, UInt8((value >> 24) & 0xff), UInt8((value >> 16) & 0xff), UInt8((value >> 8) & 0xff), UInt8(value & 0xff)])
    }
}
