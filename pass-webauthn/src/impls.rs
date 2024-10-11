use frame_support::Parameter;
use traits_authn::{DeviceChallengeResponse, UserChallengeResponse};
use verifier::webauthn_verify;

use crate::{Attestation, Credential};

impl<Cx> DeviceChallengeResponse<Cx> for Attestation<Cx>
where
    Cx: Parameter + Copy + 'static,
{
    fn is_valid(&self) -> bool {
        // TODO: Add sanity tests to verify that the information that's in the structure
        // (`challenge_info`, `rp_id`, `device_id`) corresponds to the information in
        // `authenticator_data` and `client_data`, and all that is congruent.
        //
        // Note: This might require using a json parsing library?

        webauthn_verify(
            self.authenticator_data.as_ref(),
            &self.client_data,
            &self.signature,
            &self.public_key,
        )
        .is_ok()
    }

    fn used_challenge(&self) -> (Cx, traits_authn::Challenge) {
        self.challenge_info
    }

    fn authority(&self) -> traits_authn::AuthorityId {
        self.rp_id
    }

    fn device_id(&self) -> &traits_authn::DeviceId {
        &self.device_id
    }
}

impl<Cx> UserChallengeResponse<Cx> for Credential<Cx>
where
    Cx: Parameter + Copy + 'static,
{
    fn is_valid(&self) -> bool {
        // TODO: Add sanity tests to verify that the information that's in the structure
        // (`challenge_info`, `rp_id`, `device_id`) corresponds to the information in
        // `authenticator_data` and `client_data`, and all that is congruent.
        //
        // Note: This might require using a json parsing library?

        webauthn_verify(
            self.authenticator_data.as_ref(),
            &self.client_data,
            &self.signature,
            &self.public_key,
        )
        .is_ok()
    }

    fn used_challenge(&self) -> (Cx, traits_authn::Challenge) {
        self.challenge_info
    }

    fn authority(&self) -> traits_authn::AuthorityId {
        self.rp_id
    }

    fn user_id(&self) -> traits_authn::HashedUserId {
        self.user_id
    }
}
