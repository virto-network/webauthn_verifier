#![cfg_attr(not(feature = "std"), no_std)]

use core::marker::PhantomData;

use codec::{Decode, Encode, MaxEncodedLen};
use scale_info::TypeInfo;
use traits_authn::{
    util::{Auth, Dev},
    Challenger, DeviceId,
};

type CxOf<Ch> = <Ch as Challenger>::Context;

#[cfg(test)]
mod tests;

mod impls;

#[cfg(any(feature = "runtime", test))]
pub type Authenticator<Ch, A> = Auth<Device<Ch, A>, Attestation<CxOf<Ch>>>;
#[cfg(any(feature = "runtime", test))]
pub type Device<Ch, A> = Dev<DeviceInfo, A, Ch, Credential<CxOf<Ch>>>;

#[cfg(any(feature = "runtime", test))]
#[derive(MaxEncodedLen, TypeInfo, Decode, Encode)]
pub struct DeviceInfo(DeviceId);

#[derive(Encode, Decode, TypeInfo, Debug, PartialEq, Eq, Clone)]
pub struct Attestation<Cx> {
    __phantom: PhantomData<Cx>,
    pub(crate) authenticator_data: Vec<u8>,
    pub(crate) client_data: Vec<u8>,
    pub(crate) public_key: Vec<u8>,
    pub(crate) signature: Vec<u8>,
}

#[derive(Encode, Decode, TypeInfo, Debug, PartialEq, Eq, Clone)]
pub struct Credential<Cx> {
    __phantom: PhantomData<Cx>,
    pub(crate) authenticator_data: Vec<u8>,
    pub(crate) client_data: Vec<u8>,
    pub(crate) public_key: Vec<u8>,
    pub(crate) signature: Vec<u8>,
}
