#![cfg_attr(not(feature = "std"), no_std)]

use codec::{Decode, Encode, MaxEncodedLen};
use scale_info::TypeInfo;
use traits_authn::{
    util::{Auth, Dev},
    Challenger, DeviceId, HashedUserId,
};

type CxOf<Ch> = <Ch as Challenger>::Context;

mod impls;
#[cfg(test)]
mod tests;

pub type DEREncodedPublicKey = [u8; 91];

#[cfg(any(feature = "runtime", test))]
pub type Authenticator<Ch, A> = Auth<Device<Ch, A>, Attestation<CxOf<Ch>>>;
#[cfg(any(feature = "runtime", test))]
pub type Device<Ch, A> = Dev<DeviceInfo, A, Ch, Credential<CxOf<Ch>>>;

#[cfg(any(feature = "runtime", test))]
#[derive(MaxEncodedLen, TypeInfo, Decode, Encode)]
pub struct DeviceInfo {
    device_id: DeviceId,
    //. A DER-encoded public key
    public_key: DEREncodedPublicKey,
}

#[derive(Encode, Decode, TypeInfo, Debug, PartialEq, Eq, Clone)]
pub struct Attestation<Cx> {
    pub(crate) credential_id: DeviceId,
    pub(crate) context: Cx,
    pub(crate) authenticator_data: Vec<u8>,
    pub(crate) attestation_data: Vec<u8>,
    pub(crate) public_key: DEREncodedPublicKey,
}

#[derive(Encode, Decode, TypeInfo, Debug, PartialEq, Eq, Clone)]
pub struct Credential<Cx> {
    pub(crate) user_id: HashedUserId,
    pub(crate) context: Cx,
    pub(crate) authenticator_data: Vec<u8>,
    pub(crate) client_data: Vec<u8>,
    pub(crate) signature: Vec<u8>,
}
