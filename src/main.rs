use ciborium::{cbor, value::Value};
use coset::{iana, AsCborValue, CborSerializable, CoseError, CoseKey, CoseKeyBuilder};
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

fn main() -> Result<(), CoseError> {
    let authenticator_data = b"example authenticator data";
    let client_data_json = br#"{
        "challenge": "test-challenge",
        "origin": "https://example.com",
        "type": "webauthn.get"
    }"#;
    let signature = b"signature";

    let key = coset::CoseKeyBuilder::new_ec2_pub_key(
        coset::iana::EllipticCurve::P_256,
        random_vec(2),
        random_vec(2),
    )
    .build();

    println!("{}", format!("{:?}", key.clone()));

    let key_bytes = key.to_vec().unwrap();

    println!("1: {:?}\n", key_bytes);

    let cose_key = CoseKey::from_slice(&key_bytes)?;

    println!("{}", format!("{:?}", cose_key));

    // webauthn_verifier::verify_webauthn_response(
    //     authenticator_data,
    //     client_data_json,
    //     signature,
    //     signature,
    // );

    Ok(())
}
