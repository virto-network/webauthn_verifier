use coset::{iana, CborSerializable};
use p256::ecdsa::SigningKey;

/// Random number generator utilities used for tests
use rand::{rngs::OsRng, RngCore};

fn random_fill(buffer: &mut [u8]) {
    let mut random = rand::thread_rng();
    random.fill_bytes(buffer);
}

/// Generate random data of specific length.
pub fn random_vec(len: usize) -> Vec<u8> {
    let mut data = vec![0u8; len];
    random_fill(&mut data);
    data
}

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

    let _private_key_cose = coset::CoseKeyBuilder::new_ec2_priv_key(
        coset::iana::EllipticCurve::P_256,
        x.clone(),
        y.clone(),
        private_key.to_bytes().to_vec(),
    )
    .algorithm(coset::iana::Algorithm::ES256)
    .build();

    let public_key_cose =
        coset::CoseKeyBuilder::new_ec2_pub_key(coset::iana::EllipticCurve::P_256, x, y)
            .algorithm(coset::iana::Algorithm::ES256)
            .build();

    // Step 4: Serialize the COSE key pair
    let public_key_data = public_key_cose
        .to_vec()
        .expect("Failed to serialize COSE key");

    // Inputs.
    let pt = b"This is the content";

    // Build a `CoseSign1` object.
    let protected = coset::HeaderBuilder::new()
        .algorithm(iana::Algorithm::ES256)
        .key_id(b"11".to_vec())
        .build();
    let sign1 = coset::CoseSign1Builder::new()
        .protected(protected)
        .payload(pt.to_vec())
        .create_signature(authenticator_data, |pt| {
            let (signature, _recovery_id) = private_key.sign_recoverable(pt).unwrap();
            signature.to_vec()
        })
        .build();

    // Serialize the `CoseSign1` object.
    let sign1_data = sign1.to_vec().expect("Failed to serialize COSE Sign1");

    webauthn_verifier::verify_webauthn_response(
        authenticator_data,
        client_data_json,
        sign1_data.as_slice(),
        public_key_data.as_slice(),
    );
}
