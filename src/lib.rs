use p256::{
    ecdsa::{SigningKey, VerifyingKey},
    NistP256,
};
use sha2::{Digest, Sha256};

/// Verifies a WebAuthn response signature.
///
/// This function validates the signature of a WebAuthn authentication response by:
///
/// 1. Concatenating the `authenticator_data` and `client_data_hash` to form the message.
/// 2. Verifying the `signature` against the message using the provided `public_key_der`.
///
/// The `public_key_der` should be in DER format and correspond to an ECDSA P-256 public key,
/// as specified in the WebAuthn standard.
///
/// # Arguments
///
/// * `authenticator_data` - The raw bytes of the authenticator data provided by the authenticator.
/// * `client_data_hash` - The SHA-256 hash of the client data JSON.
/// * `signature` - The signature generated by the authenticator.
/// * `public_key_der` - The public key in DER format extracted from the authenticator's attestation data.
///
/// # Returns
///
/// * `true` if the signature is valid.
/// * `false` if the signature is invalid.
///
/// # Example
///
/// ```ignore
/// let authenticator_data = /* ... */;
/// let client_data_hash = /* ... */;
/// let signature = /* ... */;
/// let public_key_der = /* ... */;
///
/// let is_valid = verify_webauthn_response(
///     &authenticator_data,
///     &client_data_hash,
///     &signature,
///     &public_key_der,
/// );
///
/// assert!(is_valid);
/// ```
/// # References
///
/// * [Web Authentication: An API for accessing Public Key Credentials Level 2 - §7.2. Verifying an Authentication Assertion](https://www.w3.org/TR/webauthn/#sctn-verifying-assertion)

pub fn verify_webauthn_response(
    authenticator_data: &[u8],
    client_data_json: &[u8],
    signature: &[u8],
    credential_public_key_der: &[u8],
) -> bool {
    // Compute client data hash
    let client_data_hash: [u8; 32] = Sha256::digest(client_data_json).into();

    // Concatenate authenticator data and client data hash
    let mut message =
        Vec::with_capacity(authenticator_data.len() + client_data_hash.as_ref().len());
    message.extend_from_slice(authenticator_data);
    message.extend_from_slice(client_data_hash.as_ref());

    // Create an unparsed public key for signature verification.
    let credential_public_key: VerifyingKey = credential_public_key_der; // Pending to include coset crate and use it to extract public key and then create a VerifyingKey using that public to verify the data, unless coset can verify

    // Verify the signature.
    credential_public_key.verify(&message, signature).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::digest::SHA256;
    use ring::rand::SystemRandom;
    use ring::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_FIXED_SIGNING};

    #[test]
    fn test_verify_webauthn_response_valid() {
        let rng = SystemRandom::new();

        // Generate ECDSA P-256 key pair
        let pkcs8_bytes = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng)
            .expect("Failed to generate key pair");
        let key_pair =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8_bytes.as_ref(), &rng)
                .expect("Failed to parse key pair");

        // Extract public key in DER format
        let public_key_der = key_pair.public_key().as_ref();

        // Sample authenticator data
        let authenticator_data = b"example authenticator data";

        // Sample client data JSON
        let client_data_json = br#"{
            "challenge": "test-challenge",
            "origin": "https://example.com",
            "type": "webauthn.get"
        }"#;

        // Compute client data hash
        let client_data_hash = ring::digest::digest(&SHA256, client_data_json);

        // Concatenate authenticator data and client data hash
        let mut message = Vec::new();
        message.extend_from_slice(authenticator_data);
        message.extend_from_slice(client_data_hash.as_ref());

        // Sign the message
        let signature = key_pair
            .sign(&rng, &message)
            .expect("Failed to sign message");

        // Verify the signature
        let is_valid = verify_webauthn_response(
            authenticator_data,
            client_data_json.as_ref(),
            signature.as_ref(),
            public_key_der,
        );

        assert!(
            is_valid,
            "The signature should be valid with the generated sample data."
        );
    }

    #[test]
    fn test_verify_webauthn_response_invalid() {
        let rng = SystemRandom::new();

        // Generate ECDSA P-256 key pair
        let pkcs8_bytes = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng)
            .expect("Failed to generate key pair");
        let key_pair =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8_bytes.as_ref(), &rng)
                .expect("Failed to parse key pair");

        // Extract public key in DER format
        let public_key_der = key_pair.public_key().as_ref();

        // Sample authenticator data
        let authenticator_data = b"example authenticator data";

        // Sample client data JSON
        let client_data_json = br#"{
            "challenge": "test-challenge",
            "origin": "https://example.com",
            "type": "webauthn.get"
        }"#;

        // Compute client data hash
        let client_data_hash = ring::digest::digest(&SHA256, client_data_json);

        // Concatenate authenticator data and client data hash
        let mut message = Vec::new();
        message.extend_from_slice(authenticator_data);
        message.extend_from_slice(client_data_hash.as_ref());

        // Sign the message
        let signature = key_pair
            .sign(&rng, &message)
            .expect("Failed to sign message");

        // Tamper with the message
        let mut tampered_authenticator_data = authenticator_data.to_vec();
        tampered_authenticator_data[0] ^= 0xFF; // Flip some bits

        // Verify the signature with tampered data
        let is_valid = verify_webauthn_response(
            &tampered_authenticator_data,
            client_data_hash.as_ref(),
            signature.as_ref(),
            public_key_der,
        );

        assert!(
            !is_valid,
            "The signature should be invalid due to tampered authenticator data."
        );
    }
}
