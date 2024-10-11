#![cfg_attr(not(feature = "std"), no_std)]

use codec::{Decode, Encode};
use frame_support::{DebugNoBound, Parameter};
use scale_info::TypeInfo;
use traits_authn::{AuthorityId, Challenge, Challenger, DeviceId, HashedUserId};

#[cfg(test)]
mod tests;

mod impls;

#[derive(Encode, Decode, TypeInfo, DebugNoBound, PartialEq, Eq, Clone)]
pub struct Attestation<Cx: Parameter> {
    pub(crate) rp_id: AuthorityId,
    pub(crate) device_id: DeviceId,
    pub(crate) challenge_info: (Cx, Challenge),
    pub(crate) authenticator_data: Vec<u8>,
    pub(crate) client_data: Vec<u8>,
    pub(crate) public_key: Vec<u8>,
    pub(crate) signature: Vec<u8>,
}

#[derive(Encode, Decode, TypeInfo, DebugNoBound, PartialEq, Eq, Clone)]
pub struct Credential<Cx: Parameter> {
    pub(crate) rp_id: AuthorityId,
    pub(crate) user_id: HashedUserId,
    pub(crate) challenge_info: (Cx, Challenge),
    pub(crate) authenticator_data: Vec<u8>,
    pub(crate) client_data: Vec<u8>,
    pub(crate) public_key: Vec<u8>,
    pub(crate) signature: Vec<u8>,
}
