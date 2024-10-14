use codec::Decode;
use frame_support::sp_runtime::traits::TrailingZeroInput;
use frame_system::pallet_prelude::BlockNumberFor;
use futures::executor::block_on;

use passkey_authenticator::{Authenticator, MockUserValidationMethod};
use passkey_client::{Client, DefaultClientData};
use passkey_types::{ctap2::Aaguid, webauthn::*, Bytes, Passkey};

use traits_authn::{Challenger, HashedUserId};
use url::Url;

use crate::DEREncodedPublicKey;

use super::{BlockChallenger, Test};

pub struct WebAuthnClient {
    origin: Url,
    client: Client<Option<Passkey>, MockUserValidationMethod, public_suffix::PublicSuffixList>,
}

impl WebAuthnClient {
    pub fn new(origin: &'static str) -> Self {
        // Create Authenticator
        let authenticator = Authenticator::new(
            Aaguid::new_empty(),
            None,
            MockUserValidationMethod::verified_user(1),
        );
        Self {
            origin: Url::parse(origin).expect("invalid url provided"),
            client: Client::new(authenticator),
        }
    }

    pub fn create_credential_sync(
        &mut self,
        user_id: HashedUserId,
        challenge: impl Into<Bytes>,
    ) -> Result<(Vec<u8>, DEREncodedPublicKey), ()> {
        let creation_options = CredentialCreationOptions {
            public_key: PublicKeyCredentialCreationOptions {
                rp: PublicKeyCredentialRpEntity {
                    id: None,
                    name: self.origin.domain().unwrap().into(),
                },
                user: PublicKeyCredentialUserEntity {
                    id: user_id.as_slice().into(),
                    display_name: "".into(),
                    name: "".into(),
                },
                challenge: challenge.into(),
                pub_key_cred_params: vec![PublicKeyCredentialParameters {
                    ty: PublicKeyCredentialType::PublicKey,
                    alg: coset::iana::Algorithm::ES256,
                }],
                timeout: None,
                exclude_credentials: None,
                authenticator_selection: None,
                hints: None,
                attestation: AttestationConveyancePreference::Direct,
                attestation_formats: Some(vec![AttestationStatementFormatIdentifiers::Packed]),
                extensions: None,
            },
        };

        // Register the credential and block until result
        let result = block_on(self.client.register(
            &self.origin,
            creation_options,
            DefaultClientData,
        ))
        .map_err(|_| ())?;

        // Extracting required fields
        let public_key: DEREncodedPublicKey = result
            .response
            .public_key
            .map(|pk| {
                Decode::decode(&mut TrailingZeroInput::new(&*pk))
                    .expect("Invalid public key length")
            })
            .ok_or(())?;

        Ok((result.raw_id.into(), public_key))
    }

    pub fn authenticate_credential_sync(
        &mut self,
        credential_id: impl Into<Bytes>,
        challenge: impl Into<Bytes>,
    ) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>), ()> {
        let request_options = CredentialRequestOptions {
            public_key: PublicKeyCredentialRequestOptions {
                challenge: challenge.into(), // Provided as input
                rp_id: Some(self.origin.domain().unwrap().into()),
                allow_credentials: Some(vec![PublicKeyCredentialDescriptor {
                    ty: PublicKeyCredentialType::PublicKey,
                    id: credential_id.into(),
                    transports: None,
                }]),
                timeout: None,
                user_verification: UserVerificationRequirement::default(),
                hints: None,
                attestation: AttestationConveyancePreference::None,
                attestation_formats: None,
                extensions: None,
            },
        };

        // Assuming you have already initialized `client`
        let result = block_on(self.client.authenticate(
            &self.origin,
            request_options,
            DefaultClientData,
        ))
        .map_err(|_| ())?;

        // Extracting required fields
        let authenticator_data = result.response.authenticator_data.to_vec();
        let client_data = result.response.client_data_json.to_vec();
        let signature = result.response.signature.to_vec();

        Ok((authenticator_data, client_data, signature))
    }

    pub fn attestation(
        &mut self,
        user_id: HashedUserId,
        context: BlockNumberFor<Test>,
    ) -> crate::Attestation<BlockNumberFor<Test>> {
        let challenge = BlockChallenger::generate(&context);

        let (credential_id, public_key) = self
            .create_credential_sync(user_id, challenge.as_slice())
            .expect("Failed creating credential");
        let (authenticator_data, client_data, signature) = self
            .authenticate_credential_sync(credential_id, challenge.as_slice())
            .expect("Failed retrieving credential");

        crate::Attestation {
            credential_id,
            context,
            authenticator_data,
            client_data,
            public_key,
            signature,
        }
    }

    pub fn credential(
        &mut self,
        credential_id: impl Into<Bytes>,
        context: BlockNumberFor<Test>,
    ) -> crate::Credential<BlockNumberFor<Test>> {
        let challenge = BlockChallenger::generate(&context);

        let (authenticator_data, client_data, signature) = self
            .authenticate_credential_sync(credential_id, challenge.as_slice())
            .expect("Failed retrieving credential");

        crate::Credential {
            context,
            authenticator_data,
            client_data,
            signature,
        }
    }
}
