#![cfg_attr(not(feature = "std"), no_std)]

use core::marker::PhantomData;

use codec::{Decode, Encode};
use frame_support::{DebugNoBound, Parameter};
use scale_info::TypeInfo;
use traits_authn::{
    util::{Auth, Dev},
    AuthorityId, Challenge, Challenger, HashedUserId,
};

type CxOf<Ch> = <Ch as Challenger>::Context;

#[cfg(test)]
mod tests;

mod impls;

pub type Authenticator<Ch, A> = Auth<Device<Ch, A>, Attestation<CxOf<Ch>>>;
pub type Device<Ch, A> = Dev<Vec<u8>, A, Ch, Credential<CxOf<Ch>>>;

#[derive(Encode, Decode, TypeInfo, DebugNoBound, PartialEq, Eq, Clone)]
pub struct Attestation<Cx: Parameter> {
    __phantom: PhantomData<Cx>,
    pub(crate) authenticator_data: Vec<u8>,
    pub(crate) client_data: Vec<u8>,
    pub(crate) public_key: Vec<u8>,
    pub(crate) signature: Vec<u8>,
}

impl<A, Ch, Cred> From<Attestation<CxOf<Ch>>> for (Vec<u8>, PhantomData<(A, Ch, Cred)>)
where
    Ch: Challenger,
    CxOf<Ch>: Parameter,
{
    fn from(value: Attestation<CxOf<Ch>>) -> Self {
        (value.public_key, PhantomData)
    }
}

#[derive(Encode, Decode, TypeInfo, DebugNoBound, PartialEq, Eq, Clone)]
pub struct Credential<Cx: Parameter> {
    __phantom: PhantomData<Cx>,
    pub(crate) authenticator_data: Vec<u8>,
    pub(crate) client_data: Vec<u8>,
    pub(crate) public_key: Vec<u8>,
    pub(crate) signature: Vec<u8>,
}
