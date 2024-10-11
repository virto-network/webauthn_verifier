#![cfg_attr(not(feature = "std"), no_std)]

use codec::{Decode, Encode};
use frame_support::{DebugNoBound, Parameter};
use scale_info::TypeInfo;
use traits_authn::{AuthorityId, Challenge, Challenger};

#[cfg(test)]
mod tests;

mod impls;

type CxOf<Ch> = <Ch as Challenger>::Context;

#[derive(Encode, Decode, TypeInfo, Debug, PartialEq, Eq, Clone)]
pub struct Assertions {
    challenge: Challenge,
}

#[derive(Encode, Decode, TypeInfo, DebugNoBound, PartialEq, Eq, Clone)]
pub struct Attestation<Cx: Parameter> {
    pub(crate) rp_id: AuthorityId,
    pub(crate) context: Cx,
    pub(crate) authenticator_data: Assertions,
    pub(crate) client_data: Vec<u8>,
    pub(crate) signature: Vec<u8>,
    pub(crate) public_key: Vec<u8>,
}

#[derive(Encode, Decode)]
pub struct Credential<Cx: Parameter> {
    pub(crate) rp_id: AuthorityId,
    pub(crate) context: Cx,
    pub(crate) authenticator_data: Assertions,
    pub(crate) client_data: Vec<u8>,
    pub(crate) signature: Vec<u8>,
}
