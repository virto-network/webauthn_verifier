use coset::CborSerializable;
use p256::ecdsa::SigningKey;
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};

fn main() {
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
    // parameter) therefore x and y are guarateed to contain values.
    let x = public_key.x().unwrap().as_slice().to_vec();
    let y = public_key.y().unwrap().as_slice().to_vec();

    // Step 3: Construct the COSE key pair
    let public_key_cose =
        coset::CoseKeyBuilder::new_ec2_pub_key(coset::iana::EllipticCurve::P_256, x, y)
            .algorithm(coset::iana::Algorithm::ES256)
            .build();

    // Step 4: Serialize the COSE key pair
    let public_key_cbor = public_key_cose
        .to_vec()
        .expect("Failed to serialize COSE key");

    // Compute client_data_hash and message
    let client_data_hash = Sha256::digest(client_data_json);
    let mut message = Vec::with_capacity(authenticator_data.len() + client_data_hash.len());
    message.extend_from_slice(authenticator_data);
    message.extend_from_slice(&client_data_hash);

    // Sign the message to get the signature in DER format
    // ? Should this be in COSE format? I couldn't get coset::CoseSign1 to work
    // ? https://github.com/google/coset/blob/main/examples/signature.rs
    // ? Check the above link for an example of how to sign a message in COSE format
    let (signature, _recovery_id) = private_key.sign_recoverable(&message).unwrap();
    let signature_der = signature.to_der();

    webauthn_verifier::verify_webauthn_response(
        authenticator_data,
        client_data_json,
        signature_der.as_bytes(),
        public_key_cbor.as_slice(),
    );
}
