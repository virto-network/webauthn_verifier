use frame_support::Parameter;
use traits_authn::{Challenger, DeviceChallengeResponse, UserChallengeResponse};
use verifier::webauthn_verify;

use crate::{Assertions, Attestation};

impl AsRef<[u8]> for Assertions {
    fn as_ref(&self) -> &[u8] {
        // See https://www.w3.org/TR/webauthn/#clientdatajson-serialization for more details
        todo!("Concatenate assertions into the desired `authenticator_data`")
    }
}

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

    fn used_challenge(&self) -> (Cx, traits_authn::Challenge) {
        (self.context, self.authenticator_data.challenge)
    }

    fn authority(&self) -> traits_authn::AuthorityId {
        self.rp_id
    }

    fn device_id(&self) -> &traits_authn::DeviceId {
        todo!()
    }
}
