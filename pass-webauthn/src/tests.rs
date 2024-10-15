//! Test environment for pass webauthn.

use frame_support::{
    assert_noop, assert_ok, derive_impl, parameter_types,
    sp_runtime::{str_array as s, traits::Hash},
    traits::ConstU64,
    PalletId,
};
use frame_system::{pallet_prelude::BlockNumberFor, Config, EnsureRootWithSuccess};
use sp_io::hashing::blake2_256;
use traits_authn::{util::AuthorityFromPalletId, Challenger, HashedUserId};

use crate::Authenticator;

mod authenticator_client;

use authenticator_client::*;

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
        WebAuthnClient::new("https://pass_web.pass.int")
            .attestation(blake2_256(b"USER_ID"), System::block_number())
            .1
    }

    fn credential(user_id: HashedUserId) -> pallet_pass::CredentialOf<Test, ()> {
        let mut client = WebAuthnClient::new("https://helper.pass.int");
        let (credential_id, _) = client.attestation(user_id, System::block_number());
        client.credential(credential_id.as_slice(), System::block_number())
    }
}

struct TestExt(pub sp_io::TestExternalities, pub WebAuthnClient);
impl TestExt {
    pub fn execute_with<R>(&mut self, execute: impl FnOnce(&mut WebAuthnClient) -> R) -> R {
        self.0.execute_with(|| execute(&mut self.1))
    }
}

fn new_test_ext() -> TestExt {
    let mut t = sp_io::TestExternalities::default();
    t.execute_with(|| {
        System::set_block_number(1);
    });
    TestExt(t, WebAuthnClient::new("https://pass_web.pass.int"))
}

const USER: HashedUserId = s("the_user");

#[test]
fn registration_fails_if_attestation_is_invalid() {
    new_test_ext().execute_with(|client| {
        let (_, mut attestation) = client.attestation(USER, System::block_number());

        // Alters "challenge", so this will fail
        attestation.client_data = String::from_utf8(attestation.client_data)
            .and_then(|client_data| {
                Ok(client_data
                    .replace("challenge", "chellang")
                    .as_bytes()
                    .to_vec())
            })
            .expect("`client_data` is a buffer representation of a utf-8 encoded json");

        assert_noop!(
            Pass::register(RuntimeOrigin::root(), USER, attestation),
            pallet_pass::Error::<Test>::DeviceAttestationInvalid,
        );
    })
}

#[test]
fn registration_works_if_attestation_is_valid() {
    new_test_ext().execute_with(|client| {
        assert_ok!(Pass::register(
            RuntimeOrigin::root(),
            USER,
            client.attestation(USER, System::block_number()).1
        ));
    })
}
