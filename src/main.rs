use coset::{
    iana, CborSerializable, CoseError};
use webauthn_verifier;

/// Random number generator utilities used for tests
use rand::RngCore;

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

#[derive(Copy, Clone)]
struct FakeSigner {}

/// Use a fake signer/verifier (to avoid pulling in lots of dependencies).
impl FakeSigner {
    fn sign(&self, data: &[u8]) -> Vec<u8> {
        data.to_vec()
    }
}

fn main() -> Result<(), CoseError> {
    let authenticator_data = b"example authenticator data";
    let client_data_json = br#"{
        "challenge": "test-challenge",
        "origin": "https://example.com",
        "type": "webauthn.get"
    }"#;

    // Build a fake signer/verifier (to avoid pulling in lots of dependencies).
    let signer = FakeSigner {};

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
        .create_signature(authenticator_data, |pt| signer.sign(pt))
        .build();

    // Serialize to bytes.
    let sign1_data = sign1.to_vec()?;

    println!("1: {:?}", sign1_data);

    let key = coset::CoseKeyBuilder::new_ec2_pub_key(
        coset::iana::EllipticCurve::P_256,
        random_vec(2),
        random_vec(2),
    )
    .build();

    let key_data = key.to_vec()?;

    webauthn_verifier::verify_webauthn_response(
        authenticator_data,
        client_data_json,
        sign1_data.as_slice(),
        key_data.as_slice(),
    )?;

    Ok(())
}
