//! Test environment for pass webauthn.

use frame_support::{
    assert_noop, assert_ok, derive_impl, parameter_types,
    sp_runtime::{str_array as s, traits::Hash},
    traits::ConstU64,
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

pub struct BlockChallenger;

impl Challenger for BlockChallenger {
    type Context = BlockNumberFor<Test>;

    fn generate(_: &Self::Context) -> traits_authn::Challenge {
        <Test as Config>::Hashing::hash(&System::block_number().to_le_bytes()).0
    }
}

impl pallet_pass::Config for Test {
    type RuntimeEvent = RuntimeEvent;
    type RuntimeCall = RuntimeCall;
    type Currency = Balances;
    type Authenticator = Authenticator<BlockChallenger, AuthorityFromPalletId<PassPalletId>>;
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

#[test]
fn registration_fails_if_attestation_is_invalid() {
    new_test_ext().execute_with(|| {
        // TODO: Fill with garbage data or incorrect signature (whatever works best)
        assert_noop!(
            Pass::register(
                RuntimeOrigin::root(),
                USER,
                Attestation::new(b"".to_vec(), b"".to_vec(), b"".to_vec(), b"".to_vec())
            ),
            pallet_pass::Error::<Test>::DeviceAttestationInvalid,
        );
    })
}

#[test]
fn registration_works_if_attestation_is_valid() {
    new_test_ext().execute_with(|| {
        // TODO: Fill with valid data and signature
        assert_ok!(Pass::register(
            RuntimeOrigin::root(),
            USER,
            Attestation::new(b"".to_vec(), b"".to_vec(), b"".to_vec(), b"".to_vec())
        ));
    })
}
