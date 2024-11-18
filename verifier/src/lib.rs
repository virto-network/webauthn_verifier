#![cfg_attr(not(feature = "std"), no_std)]

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
//! * <https://www.w3.org/TR/webauthn/#fig-signature>
//! * <https://www.w3.org/TR/webauthn/images/fido-signature-formats-figure2.svg>

extern crate alloc;
use p256::{
    ecdsa::{signature::Verifier, DerSignature, VerifyingKey},
    elliptic_curve::PublicKey,
    pkcs8::DecodePublicKey,
    NistP256,
};
use sha2::{Digest, Sha256};

#[cfg(test)]
mod tests;

#[derive(Debug)]
pub enum VerifyError {
    ExtractPublicKey,
    ParseSignature,
    VerifySignature,
}

const LOG_TARGET: &str = "verifier::verify_signature";

pub fn webauthn_verify(
    authenticator_data: &[u8],
    client_data_json: &[u8],
    signature_der: &[u8],
    credential_public_key_der: &[u8],
) -> Result<(), VerifyError> {
    // Step 1: Compute the SHA-256 hash of the client data JSON
    let client_data_hash: [u8; 32] = Sha256::digest(client_data_json).into();

    // Step 2: Concatenate authenticator data and client data hash
    let message = [authenticator_data, &client_data_hash].concat();

    // Step 3: Extract public key from DER format
    let public_key: PublicKey<NistP256> =
        DecodePublicKey::from_public_key_der(credential_public_key_der)
            .map_err(|_| VerifyError::ExtractPublicKey)?;

    let verifying_key = VerifyingKey::from(public_key);

    // Step 4: Parse the DER signature
    let signature =
        DerSignature::try_from(signature_der).map_err(|_| VerifyError::ParseSignature)?;

    log::trace!(
        "Run WebAuthn verify_signature: message={:?}, public_key={:?}, signature={:?}",
        &message,
        &public_key,
        &signature
    );
    // Step 5: Verify the signature
    verifying_key
        .verify(&message, &signature)
        .map(|_| ())
        .map_err(|_| VerifyError::VerifySignature)
}
