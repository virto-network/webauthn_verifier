#![cfg_attr(not(feature = "std"), no_std)]

use core::marker::PhantomData;

use codec::{Decode, Encode};
use frame_support::Parameter;
use scale_info::TypeInfo;
use traits_authn::{
    util::{Auth, Dev},
    Challenger,
};

type CxOf<Ch> = <Ch as Challenger>::Context;

#[cfg(test)]
mod tests;

mod impls;

#[cfg(any(feature = "runtime", test))]
pub type Authenticator<Ch, A> = Auth<Device<Ch, A>, Attestation<CxOf<Ch>>>;
#[cfg(any(feature = "runtime", test))]
pub type Device<Ch, A> = Dev<Vec<u8>, A, Ch, Credential<CxOf<Ch>>>;

#[derive(Encode, Decode, TypeInfo, Debug, PartialEq, Eq, Clone)]
pub struct Attestation<Cx> {
    __phantom: PhantomData<Cx>,
    pub(crate) authenticator_data: Vec<u8>,
    pub(crate) client_data: Vec<u8>,
    pub(crate) public_key: Vec<u8>,
    pub(crate) signature: Vec<u8>,
}

#[cfg(any(feature = "runtime", test))]
impl<Ch, A> From<Attestation<CxOf<Ch>>> for Device<Ch, A>
where
    Ch: Challenger,
    CxOf<Ch>: Parameter,
{
    fn from(value: Attestation<CxOf<Ch>>) -> Self {
        Device::new(value.public_key)
    }
}

#[derive(Encode, Decode, TypeInfo, Debug, PartialEq, Eq, Clone)]
pub struct Credential<Cx> {
    __phantom: PhantomData<Cx>,
    pub(crate) authenticator_data: Vec<u8>,
    pub(crate) client_data: Vec<u8>,
    pub(crate) public_key: Vec<u8>,
    pub(crate) signature: Vec<u8>,
}
