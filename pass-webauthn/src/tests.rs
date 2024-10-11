//! Test environment for pass webauthn.

use frame_support::{
    assert_noop, assert_ok, derive_impl, parameter_types,
    sp_runtime::{str_array as s, traits::Hash},
    traits::ConstU64,
    PalletId,
};
use frame_system::{pallet_prelude::BlockNumberFor, Config, EnsureRootWithSuccess};
use traits_authn::{util::AuthorityFromPalletId, Challenger, HashedUserId};

use crate::{Attestation, Authenticator, Credential};

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
  pub PassPalletId: PalletId = PalletId(*b"pass_web");
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
    #[cfg(feature = "runtime-benchmarks")]
    type BenchmarkHelper = Helper;
}

#[cfg(feature = "runtime-benchmarks")]
pub struct Helper;
#[cfg(feature = "runtime-benchmarks")]
impl pallet_pass::BenchmarkHelper<Test> for Helper {
    fn register_origin() -> frame_system::pallet_prelude::OriginFor<Test> {
        RuntimeOrigin::root()
    }

    fn device_attestation(_: traits_authn::DeviceId) -> pallet_pass::DeviceAttestationOf<Test, ()> {
        let (a, b, c, d) = build_attesttation_fields(&System::block_number());
        Attestation::new(a, b, c, d)
    }

    fn credential(_: HashedUserId) -> pallet_pass::CredentialOf<Test, ()> {
        let (a, b, c, d) = build_attesttation_fields(&System::block_number());
        Credential::new(a, b, c, d)
    }
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
        Url::parse(&format!("https://{rp_id}.pallet-pass.int")).expect("urn parses as a valid URL");
    let key = Passkey::mock(rp_id).build();
    let store = Some(key.clone());

    let authenticator =
        Authenticator::new(aaguid, store, MockUserValidationMethod::verified_user(1));
    let mut client = Client::new(authenticator);

    let request = CredentialRequestOptions {
        public_key: PublicKeyCredentialRequestOptions {
            challenge: BlockChallenger::generate(ctx).as_slice().into(),
            timeout: None,
            rp_id: None,
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

        use passkey_types::ctap2::AuthenticatorData;
        let raw_authenticator_data = AuthenticatorData::from_slice(&authenticator_data)
            .expect("this conversion works both ways");

        println!(
            "authenticator_data = {:?}\nclient_data_json = {}",
            &raw_authenticator_data,
            &String::from_utf8(client_data.clone()).expect("converting json works")
        );

        let attestation = Attestation::new(
            authenticator_data.to_vec(),
            client_data,
            public_key,
            signature,
        );

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
