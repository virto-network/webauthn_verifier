use core::marker::PhantomData;

use frame_support::Parameter;
use traits_authn::{
    AuthorityId, Challenge, DeviceChallengeResponse, DeviceId, HashedUserId, UserChallengeResponse,
};
use verifier::webauthn_verify;

use crate::{Attestation, Credential};

impl<Cx> Attestation<Cx>
where
    Cx: Parameter,
{
    pub fn new(
        authenticator_data: Vec<u8>,
        client_data: Vec<u8>,
        signature: Vec<u8>,
        public_key: Vec<u8>,
    ) -> Self {
        Self {
            __phantom: PhantomData,
            authenticator_data,
            client_data,
            signature,
            public_key,
        }
    }

    fn context(&self) -> Cx {
        todo!("Extract `context` into `Cx` format (you can conveniently use `.decode()`)");
    }

    fn challenge(&self) -> Challenge {
        todo!("Extract `challenge`, format into `Challenge` format (that is, [u8; 32])");
    }
}

#[cfg(any(feature = "runtime", test))]
impl<Cx> DeviceChallengeResponse<Cx> for Attestation<Cx>
where
    Cx: Parameter + Copy + 'static,
{
    fn is_valid(&self) -> bool {
        webauthn_verify(
            self.authenticator_data.as_ref(),
            &self.client_data,
            &self.signature,
            &self.public_key,
        )
        .is_ok()
    }

    fn used_challenge(&self) -> (Cx, Challenge) {
        (self.context(), self.challenge())
    }

    fn authority(&self) -> AuthorityId {
        todo!("Extract `rp_id`, format into `AuthorityId` format (that is, [u8; 32])");
    }

    fn device_id(&self) -> &DeviceId {
        todo!("Extract `device_id`, format into `DeviceId` format (that is, [u8; 32])");
    }
}

impl<Cx> Credential<Cx>
where
    Cx: Parameter,
{
    pub fn new(
        authenticator_data: Vec<u8>,
        client_data: Vec<u8>,
        signature: Vec<u8>,
        public_key: Vec<u8>,
    ) -> Self {
        Self {
            __phantom: PhantomData,
            authenticator_data,
            client_data,
            signature,
            public_key,
        }
    }

    fn context(&self) -> Cx {
        todo!("Extract `context` into `Cx` format (you can conveniently use `.decode()`)");
    }

    fn challenge(&self) -> Challenge {
        todo!("Extract `challenge`, format into `Challenge` format (that is, [u8; 32])");
    }
}

#[cfg(any(feature = "runtime", test))]
impl<Cx> UserChallengeResponse<Cx> for Credential<Cx>
where
    Cx: Parameter + Copy + 'static,
{
    fn is_valid(&self) -> bool {
        webauthn_verify(
            self.authenticator_data.as_ref(),
            &self.client_data,
            &self.signature,
            &self.public_key,
        )
        .is_ok()
    }

    fn used_challenge(&self) -> (Cx, Challenge) {
        (self.context(), self.challenge())
    }

    fn authority(&self) -> AuthorityId {
        todo!("Extract `rp_id`, format into `AuthorityId` format (that is, [u8; 32])");
    }

    fn user_id(&self) -> HashedUserId {
        todo!("Extract `user_id`, format into `HashedUserId` format (that is, [u8; 32])");
    }
}
