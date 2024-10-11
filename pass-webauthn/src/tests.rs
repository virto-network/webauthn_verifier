//! Test environment for pass webauthn.

use frame_support::{
    assert_noop, assert_ok, derive_impl, parameter_types,
    sp_runtime::{str_array as s, traits::Hash},
    traits::{ConstU64, Get},
    PalletId,
};
use frame_system::{pallet_prelude::BlockNumberFor, Config, EnsureRootWithSuccess};
use traits_authn::{util::AuthorityFromPalletId, Challenger, HashedUserId};

use crate::{Attestation, Authenticator};

#[frame_support::runtime]
pub mod runtime {
    #[runtime::runtime]
    #[runtime::derive(
        RuntimeCall,
        RuntimeEvent,
        RuntimeError,
        RuntimeOrigin,
        RuntimeTask,
        RuntimeHoldReason,
        RuntimeFreezeReason
    )]
    pub struct Test;

    #[runtime::pallet_index(0)]
    pub type System = frame_system;
    #[runtime::pallet_index(1)]
    pub type Pass = pallet_pass;

    #[runtime::pallet_index(10)]
    pub type Balances = pallet_balances;
}

pub type Block = frame_system::mocking::MockBlock<Test>;
pub type AccountId = <Test as frame_system::Config>::AccountId;

#[derive_impl(frame_system::config_preludes::TestDefaultConfig as frame_system::DefaultConfig)]
impl frame_system::Config for Test {
    type BaseCallFilter = frame_support::traits::Everything;
    type Block = Block;
    type AccountData = pallet_balances::AccountData<AccountId>;
}

#[derive_impl(pallet_balances::config_preludes::TestDefaultConfig as pallet_balances::DefaultConfig)]
impl pallet_balances::Config for Test {
    type AccountStore = System;
}

parameter_types! {
  pub PassPalletId: PalletId = PalletId(*b"pass/web");
  pub NeverPays: Option<pallet_pass::DepositInformation<Test>> = None;
}

type AuthorityId = AuthorityFromPalletId<PassPalletId>;

pub struct BlockChallenger;

impl Challenger for BlockChallenger {
    type Context = BlockNumberFor<Test>;

    fn generate(ctx: &Self::Context) -> traits_authn::Challenge {
        <Test as Config>::Hashing::hash(&ctx.to_le_bytes()).0
    }
}

impl pallet_pass::Config for Test {
    type RuntimeEvent = RuntimeEvent;
    type RuntimeCall = RuntimeCall;
    type Currency = Balances;
    type Authenticator = Authenticator<BlockChallenger, AuthorityId>;
    type PalletsOrigin = OriginCaller;
    type PalletId = PassPalletId;
    type MaxSessionDuration = ConstU64<10>;
    type RegisterOrigin = EnsureRootWithSuccess<Self::AccountId, NeverPays>;
    type WeightInfo = ();
}

fn new_test_ext() -> sp_io::TestExternalities {
    let mut t = sp_io::TestExternalities::default();
    t.execute_with(|| {
        System::set_block_number(1);
    });
    t
}

const USER: HashedUserId = s("the_user");

fn build_attesttation_fields(ctx: &BlockNumberFor<Test>) -> (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) {
    use futures::executor::block_on;
    use passkey_authenticator::{
        public_key_der_from_cose_key, Authenticator, MockUserValidationMethod,
    };
    use passkey_client::{Client, DefaultClientData};
    use passkey_types::{
        ctap2::Aaguid,
        webauthn::{
            AttestationConveyancePreference, CredentialRequestOptions,
            PublicKeyCredentialRequestOptions, UserVerificationRequirement,
        },
        Passkey,
    };
    use url::Url;

    let aaguid = Aaguid::new_empty();
    let rp_id = String::from_utf8(PassPalletId::get().0.to_vec())
        .expect("converting from ascii to utf-8 is guaranteed; qed");
    let origin =
        Url::parse(&format!("urn://blockchain/{rp_id}")).expect("urn parses as a valid URL");
    let key = Passkey::mock(rp_id.clone()).build();
    let store = Some(key.clone());

    let authenticator = Authenticator::new(aaguid, store, MockUserValidationMethod::new());
    let mut client = Client::new(authenticator);

    let request = CredentialRequestOptions {
        public_key: PublicKeyCredentialRequestOptions {
            challenge: BlockChallenger::generate(ctx).as_slice().into(),
            timeout: None,
            rp_id: Some(rp_id),
            allow_credentials: None,
            user_verification: UserVerificationRequirement::default(),
            hints: None,
            attestation: AttestationConveyancePreference::None,
            attestation_formats: None,
            extensions: None,
        },
    };

    let authenticated_request = block_on(client.authenticate(&origin, request, DefaultClientData))
        .expect("authenticate works");

    let authenticator_data = authenticated_request.response.authenticator_data;
    let client_data = authenticated_request.response.client_data_json;
    let public_key = public_key_der_from_cose_key(&key.key).expect("key conversion works");
    let signature = authenticated_request.response.signature;

    (
        authenticator_data.to_vec(),
        client_data.to_vec(),
        public_key.to_vec(),
        signature.to_vec(),
    )
}

#[test]
fn registration_fails_if_attestation_is_invalid() {
    new_test_ext().execute_with(|| {
        let (authenticator_data, client_data, public_key, signature) =
            build_attesttation_fields(&System::block_number());
        let signature = [signature, b"Whoops!".to_vec()].concat();
        let attestation = Attestation::new(authenticator_data, client_data, public_key, signature);

        assert_noop!(
            Pass::register(RuntimeOrigin::root(), USER, attestation),
            pallet_pass::Error::<Test>::DeviceAttestationInvalid,
        );
    })
}

#[test]
fn registration_works_if_attestation_is_valid() {
    new_test_ext().execute_with(|| {
        let (authenticator_data, client_data, public_key, signature) =
            build_attesttation_fields(&System::block_number());
        let attestation = Attestation::new(authenticator_data, client_data, public_key, signature);

        assert_ok!(Pass::register(RuntimeOrigin::root(), USER, attestation));
    })
}
