//! Verifies a WebAuthn response signature.
//!
//! This function validates the signature of a WebAuthn authentication response by:
//!
//! 1. Concatenating the `authenticator_data` and the hashed `client_data_json` to form the message.
//! 2. Verifying the `signature_der` against the message using the provided `credential_public_key_cbor`.
//!
//! The `credential_public_key_cbor` should be in COSE format and correspond to an ECDSA P-256 public key,
//! as specified in the WebAuthn standard.
//!
//! # Arguments
//!
//! * `authenticator_data` - The raw bytes of the authenticator data provided by the authenticator.
//! * `client_data_json` - The client data JSON.
//! * `signature_der` - The signature generated by the authenticator.
//! * `credential_public_key_cbor` - The public key in COSE format extracted from the authenticator's attestation data.
//!
//! # Returns
//!
//! * `true` if the signature is valid.
//! * `false` if the signature is invalid.
//!
//! # Example
//!
//! ```ignore
//! let authenticator_data = /* ... */;
//! let client_data_json = /* ... */;
//! let signature_der = /* ... */;
//! let credential_public_key_cbor = /* ... */;
//!
//! let is_valid = verify_webauthn_response(
//!     &authenticator_data,
//!     &client_data_json,
//!     &signature_der,
//!     &credential_public_key_cbor,
//! );
//!
//! assert!(is_valid);
//! ```
//!
//! # References
//!
//! * [Web Authentication: An API for accessing Public Key Credentials Level 2 - §7.2. Verifying an Authentication Assertion](https://www.w3.org/TR/webauthn/#sctn-verifying-assertion)
//! * "20. Using credentialPublicKey, verify that sig is a valid signature over the binary concatenation of authData and hash."
//! * https://www.w3.org/TR/webauthn/#fig-signature
//! * https://www.w3.org/TR/webauthn/images/fido-signature-formats-figure2.svg

use coset::{CborSerializable, CoseKey};
use p256::{
    ecdsa::{signature::Verifier, Signature, VerifyingKey},
    elliptic_curve::PublicKey,
    pkcs8::DecodePublicKey,
    NistP256,
};
use passkey::authenticator;
use sha2::{Digest, Sha256};

pub fn verify_webauthn_response(
    authenticator_data: &[u8],
    client_data_json: &[u8],
    signature_der: &[u8],
    credential_public_key_cbor: &[u8],
) -> bool {
    // Step 1: Compute the SHA-256 hash of the client data JSON
    let client_data_hash: [u8; 32] = Sha256::digest(client_data_json).into();

    // Step 2: Concatenate authenticator data and client data hash
    let mut message = Vec::with_capacity(authenticator_data.len() + client_data_hash.len());
    message.extend_from_slice(authenticator_data);
    message.extend_from_slice(&client_data_hash);

    // Step 3: Parse the COSE public key, convert it to DER format, and parse it
    let public_key_cose = match CoseKey::from_slice(credential_public_key_cbor) {
        Ok(key) => key,
        Err(e) => {
            eprintln!("Failed to parse COSE public key: {:?}", e);
            return false;
        }
    };

    let public_key_der = match authenticator::public_key_der_from_cose_key(&public_key_cose) {
        Ok(der) => der,
        Err(e) => {
            eprintln!("Failed to convert COSE key to DER format: {:?}", e);
            return false;
        }
    };

    let public_key = match PublicKey::<NistP256>::from_public_key_der(&public_key_der) {
        Ok(key) => key,
        Err(e) => {
            eprintln!("Failed to parse public key DER: {:?}", e);
            return false;
        }
    };

    let verifying_key = VerifyingKey::from(public_key);

    // Step 4: Parse the DER signature
    let signature = match Signature::from_der(signature_der) {
        Ok(sig) => sig,
        Err(e) => {
            eprintln!("Failed to parse signature DER: {:?}", e);
            return false;
        }
    };

    // Step 5: Verify the signature
    if verifying_key.verify(&message, &signature).is_err() {
        eprintln!("Signature verification failed");
        return false;
    }

    println!("Signature verification succeeded");

    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use coset::{
        iana::{Algorithm, EllipticCurve},
        CborSerializable, CoseKeyBuilder,
    };
    use p256::ecdsa::{signature::Signer, Signature, SigningKey};
    use rand::rngs::OsRng;
    use sha2::{Digest, Sha256};

    #[test]
    fn test_verify_registration_webauthn_response_with_replicated_data() {
        let authenticator_data = b"dKbqkhPJnC90siSSsyDPQCYqlMGpUKA5fyklC2CEHvBFAAAAAQAAAAAAAAAAAAAAAAAAAAAAIK1-GLJEntO1EGz7VIEmTzktMEcucNozCVY5w-r1zzbKpQECAyYgASFYIME615EvcyE68YdSKzkIxhy0DGN1da1_WvI1AEeagOHoIlggu6X6IegkSRbcyLzZbFg3rzMjBwa4C3DfMlStM9rf4Po";
        let client_data_json = b"eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiRUFVdHF5clRadUpKVEx3emRVOVRBaDltYjZnTU02cldXRUVGV0FkMTJvV0FBS216Mk4zYWdKLW1VUm0zWk1yQkMxYklWNnFLTTNzMGtLLWxrYjhJalEiLCJvcmlnaW4iOiJodHRwczovL3dlYmF1dGhuLmlvIiwiY3Jvc3NPcmlnaW4iOmZhbHNlLCJvdGhlcl9rZXlzX2Nhbl9iZV9hZGRlZF9oZXJlIjoiZG8gbm90IGNvbXBhcmUgY2xpZW50RGF0YUpTT04gYWdhaW5zdCBhIHRlbXBsYXRlLiBTZWUgaHR0cHM6Ly9nb28uZ2wveWFiUGV4In0";

        // Step 4: Serialize the COSE key pair
        let public_key_cbor = b"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEwTrXkS9zITrxh1IrOQjGHLQMY3V1rX9a8jUAR5qA4ei7pfoh6CRJFtzIvNlsWDevMyMHBrgLcN8yVK0z2t_g-g";

        // // Step 5: Compute client_data_hash and message
        // let client_data_hash = Sha256::digest(client_data_json);
        // let mut message = Vec::with_capacity(authenticator_data.len() + client_data_hash.len());
        // message.extend_from_slice(authenticator_data);
        // message.extend_from_slice(&client_data_hash);

        // Step 6: Sign the message to get the signature in DER format
        // ? Should this be in COSE format? I couldn't get coset::CoseSign1 to work
        // ? https://github.com/google/coset/blob/main/examples/signature.rs
        // ? Check the above link for an example of how to sign a message in COSE format
        let signature_der = b"o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVikdKbqkhPJnC90siSSsyDPQCYqlMGpUKA5fyklC2CEHvBFAAAAAQAAAAAAAAAAAAAAAAAAAAAAIK1-GLJEntO1EGz7VIEmTzktMEcucNozCVY5w-r1zzbKpQECAyYgASFYIME615EvcyE68YdSKzkIxhy0DGN1da1_WvI1AEeagOHoIlggu6X6IegkSRbcyLzZbFg3rzMjBwa4C3DfMlStM9rf4Po";

        // Step 7: Verify the signature
        let is_valid = verify_webauthn_response(
            authenticator_data,
            client_data_json,
            signature_der,
            public_key_cbor,
        );

        assert!(
            is_valid,
            "The signature should be valid with the generated sample data."
        );
    }

    #[test]
    fn test_verify_webauthn_response_with_generated_data() {
        let authenticator_data = b"example authenticator data";
        let client_data_json = br#"{
            "challenge": "test-challenge",
            "origin": "https://example.com",
            "type": "webauthn.get"
        }"#;

        // Step 1: Generate a private key using the P-256 curve
        let private_key = SigningKey::random(&mut OsRng);
        let public_key = private_key.verifying_key().to_encoded_point(false); // Uncompressed point

        // Step 2: Extract the affine coordinates (x, y)
        // SAFETY: These unwraps are safe because the public_key above is not compressed (false
        // parameter) therefore x and y are guaranteed to contain values.
        let x = public_key.x().unwrap().as_slice().to_vec();
        let y = public_key.y().unwrap().as_slice().to_vec();

        // Step 3: Construct the COSE key pair
        let public_key_cose = CoseKeyBuilder::new_ec2_pub_key(EllipticCurve::P_256, x, y)
            .algorithm(Algorithm::ES256)
            .build();

        // Step 4: Serialize the COSE key pair
        let public_key_cbor = public_key_cose
            .to_vec()
            .expect("Failed to serialize COSE key");

        // Step 5: Compute client_data_hash and message
        let client_data_hash = Sha256::digest(client_data_json);
        let mut message = Vec::with_capacity(authenticator_data.len() + client_data_hash.len());
        message.extend_from_slice(authenticator_data);
        message.extend_from_slice(&client_data_hash);

        // Step 6: Sign the message to get the signature in DER format
        // ? Should this be in COSE format? I couldn't get coset::CoseSign1 to work
        // ? https://github.com/google/coset/blob/main/examples/signature.rs
        // ? Check the above link for an example of how to sign a message in COSE format
        let signature: Signature = private_key.sign(&message);
        let signature_der = signature.to_der();

        // Step 7: Verify the signature
        let is_valid = verify_webauthn_response(
            authenticator_data,
            client_data_json,
            signature_der.as_bytes(),
            public_key_cbor.as_slice(),
        );

        assert!(
            is_valid,
            "The signature should be valid with the generated sample data."
        );
    }

    #[test]
    fn test_verify_webauthn_response_with_invalid_signature() {
        let authenticator_data = b"example authenticator data";
        let client_data_json = br#"{
            "challenge": "test-challenge",
            "origin": "https://example.com",
            "type": "webauthn.get"
        }"#;

        // Step 1: Generate a private key using the P-256 curve
        let private_key = SigningKey::random(&mut OsRng);
        let public_key = private_key.verifying_key().to_encoded_point(false); // Uncompressed point

        // Step 2: Extract the affine coordinates (x, y)
        let x = public_key.x().unwrap().as_slice().to_vec();
        let y = public_key.y().unwrap().as_slice().to_vec();

        // Step 3: Construct the COSE key pair
        let public_key_cose = CoseKeyBuilder::new_ec2_pub_key(EllipticCurve::P_256, x, y)
            .algorithm(Algorithm::ES256)
            .build();

        // Step 4: Serialize the COSE key pair
        let public_key_cbor = public_key_cose
            .to_vec()
            .expect("Failed to serialize COSE key");

        // Step 5: Compute client_data_hash and message
        let client_data_hash = Sha256::digest(client_data_json);
        let mut message = Vec::with_capacity(authenticator_data.len() + client_data_hash.len());
        message.extend_from_slice(authenticator_data);
        message.extend_from_slice(&client_data_hash);

        // Step 6: Sign the message to get the signature in DER format
        let signature: Signature = private_key.sign(&message);
        let signature_der = signature.to_der();

        // Step 7: Tamper with the signature to make it invalid
        let mut tampered_signature_der = signature_der.as_bytes().to_vec();
        tampered_signature_der[0] ^= 0xFF; // Flip some bits

        // Step 8: Verify the signature (should fail)
        let is_valid = verify_webauthn_response(
            authenticator_data,
            client_data_json,
            &tampered_signature_der,
            public_key_cbor.as_slice(),
        );

        assert!(
            !is_valid,
            "The signature verification should fail with an invalid signature."
        );
    }
}
