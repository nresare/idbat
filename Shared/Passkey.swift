import AuthenticationServices
import CryptoKit
import Foundation
import LocalAuthentication
import Security

enum PasskeyError: LocalizedError {
    case unsupportedAlgorithm
    case invalidPublicKey
    case invalidIdentity
    case secureEnclaveUnavailable
    case accessControlCreationFailed
    case relyingPartyMismatch

    var errorDescription: String? {
        switch self {
        case .unsupportedAlgorithm: "This site does not support ES256 passkeys."
        case .invalidPublicKey: "The generated public key has an unexpected format."
        case .invalidIdentity: "The system did not provide a passkey identity."
        case .secureEnclaveUnavailable: "This Mac does not have an available Secure Enclave."
        case .accessControlCreationFailed: "Could not configure Secure Enclave key protection."
        case .relyingPartyMismatch: "This passkey belongs to a different website."
        }
    }
}

/// New keys are generated and used inside the Secure Enclave. The Keychain
/// stores an encrypted representation usable only by this device's enclave.
enum Passkey {
    // UP, UV, BE, BS, AT. Clearing the backup flags causes macOS to reject
    // registration with "AuthData is missing a required flag."
    static let registrationFlags: UInt8 = 0x5d
    // Stable identifier for the idbat Secure Enclave authenticator model.
    // B43E6A34-F345-407F-9BA2-1AE73907FACA
    static let aaguid = Data([
        0xb4, 0x3e, 0x6a, 0x34, 0xf3, 0x45, 0x40, 0x7f,
        0x9b, 0xa2, 0x1a, 0xe7, 0x39, 0x07, 0xfa, 0xca,
    ])

    static func assertionFlags(for metadata: CredentialMetadata?) -> UInt8 {
        // Backup eligibility cannot change after registration. Keep each
        // credential's original protocol flags, including the compatibility flags.
        metadata?.backupEligible == false ? 0x05 : 0x1d
    }

    static func register(_ request: ASPasskeyCredentialRequest, authenticationContext: LAContext) throws -> (ASPasskeyRegistrationCredential, ASPasskeyCredentialIdentity) {
        guard SecureEnclave.isAvailable else {
            throw PasskeyError.secureEnclaveUnavailable
        }
        guard request.supportedAlgorithms.contains(where: { $0.rawValue == -7 }) else {
            throw PasskeyError.unsupportedAlgorithm
        }

        guard let requestedIdentity = request.credentialIdentity as? ASPasskeyCredentialIdentity else {
            throw PasskeyError.invalidIdentity
        }
        let rpID = requestedIdentity.relyingPartyIdentifier
        let credentialID = Data((0..<32).map { _ in UInt8.random(in: 0...255) })
        var accessControlError: Unmanaged<CFError>?
        guard let accessControl = SecAccessControlCreateWithFlags(
            nil,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            [.privateKeyUsage, .userPresence],
            &accessControlError
        ) else {
            if let accessControlError {
                throw accessControlError.takeRetainedValue() as Error
            }
            throw PasskeyError.accessControlCreationFailed
        }
        let privateKey = try SecureEnclave.P256.Signing.PrivateKey(
            accessControl: accessControl,
            authenticationContext: authenticationContext
        )
        let publicKey = privateKey.publicKey.x963Representation
        guard publicKey.count == 65, publicKey.first == 0x04 else {
            throw PasskeyError.invalidPublicKey
        }

        var authData = Data(SHA256.hash(data: Data(rpID.utf8)))
        authData.append(registrationFlags)
        authData.append(contentsOf: [0, 0, 0, 0]) // No signature counter.
        authData.append(aaguid)
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
        try CredentialStore.save(
            privateKey.dataRepresentation,
            credentialID: credentialID,
            metadata: CredentialMetadata(
                relyingParty: rpID,
                userName: requestedIdentity.userName,
                userHandle: requestedIdentity.userHandle,
                createdAt: Date(),
                backupEligible: registrationFlags & 0x08 != 0
            )
        )

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

    static func assert(_ request: ASPasskeyCredentialRequest, authenticationContext: LAContext) throws -> ASPasskeyAssertionCredential {
        guard let identity = request.credentialIdentity as? ASPasskeyCredentialIdentity else {
            throw PasskeyError.invalidIdentity
        }
        let key = try CredentialStore.load(credentialID: identity.credentialID)
        try checkRelyingParty(identity.relyingPartyIdentifier, for: key.metadata)
        var authData = Data(SHA256.hash(data: Data(identity.relyingPartyIdentifier.utf8)))
        authData.append(assertionFlags(for: key.metadata))
        authData.append(contentsOf: [0, 0, 0, 0])
        let signature = try sign(authData + request.clientDataHash, keyRepresentation: key.representation, authenticationContext: authenticationContext)
        return ASPasskeyAssertionCredential(
            userHandle: identity.userHandle,
            relyingParty: identity.relyingPartyIdentifier,
            signature: signature,
            clientDataHash: request.clientDataHash,
            authenticatorData: authData,
            credentialID: identity.credentialID
        )
    }

    /// Never sign for a website other than the one the key was registered for,
    /// whatever identity the request carries. Older keys without metadata
    /// cannot be checked.
    static func checkRelyingParty(_ relyingParty: String, for metadata: CredentialMetadata?) throws {
        if let metadata, metadata.relyingParty != relyingParty {
            throw PasskeyError.relyingPartyMismatch
        }
    }

    private static func sign(_ data: Data, keyRepresentation: Data, authenticationContext: LAContext) throws -> Data {
        guard SecureEnclave.isAvailable else {
            throw PasskeyError.secureEnclaveUnavailable
        }
        let privateKey = try SecureEnclave.P256.Signing.PrivateKey(
            dataRepresentation: keyRepresentation,
            authenticationContext: authenticationContext
        )
        return try privateKey.signature(for: data).derRepresentation
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
