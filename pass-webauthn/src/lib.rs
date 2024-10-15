#![cfg_attr(not(feature = "std"), no_std)]

use codec::{Decode, Encode, MaxEncodedLen};
use scale_info::TypeInfo;
use traits_authn::{
    util::{Auth, Dev},
    Challenger, DeviceId, HashedUserId,
};

type CxOf<Ch> = <Ch as Challenger>::Context;

#[cfg(any(feature = "runtime", test))]
mod runtime_helpers;
#[cfg(any(feature = "runtime", test))]
pub mod runtime_impls;

#[cfg(test)]
mod tests;

pub type DEREncodedPublicKey = [u8; 91];

#[cfg(any(feature = "runtime", test))]
pub type Authenticator<Ch, A> = Auth<Device<Ch, A>, Attestation<CxOf<Ch>>>;
#[cfg(any(feature = "runtime", test))]
pub type Device<Ch, A> = Dev<Credential, A, Ch, Assertion<CxOf<Ch>>>;

#[cfg(any(feature = "runtime", test))]
#[derive(MaxEncodedLen, TypeInfo, Decode, Encode)]
pub struct Credential {
    device_id: DeviceId,
    //. A DER-encoded public key
    public_key: DEREncodedPublicKey,
}

#[derive(Encode, Decode, TypeInfo, Debug, PartialEq, Eq, Clone, Copy)]
pub struct AttestationMeta<Cx> {
    pub(crate) device_id: DeviceId,
    pub(crate) context: Cx,
}

#[derive(Encode, Decode, TypeInfo, Debug, PartialEq, Eq, Clone)]
pub struct Attestation<Cx> {
    pub(crate) meta: AttestationMeta<Cx>,
    pub(crate) authenticator_data: Vec<u8>,
    pub(crate) client_data: Vec<u8>,
    pub(crate) public_key: DEREncodedPublicKey,
}

#[derive(Encode, Decode, TypeInfo, Debug, PartialEq, Eq, Clone, Copy)]
pub struct AssertionMeta<Cx> {
    pub(crate) user_id: HashedUserId,
    pub(crate) context: Cx,
}

#[derive(Encode, Decode, TypeInfo, Debug, PartialEq, Eq, Clone)]
pub struct Assertion<Cx> {
    pub(crate) meta: AssertionMeta<Cx>,
    pub(crate) authenticator_data: Vec<u8>,
    pub(crate) client_data: Vec<u8>,
    pub(crate) signature: Vec<u8>,
}
