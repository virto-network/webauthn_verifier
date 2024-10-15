use frame_support::Parameter;
use traits_authn::{AuthorityId, Challenge, DeviceChallengeResponse, DeviceId};

use crate::{runtime_helpers::*, Assertion, Attestation, Credential};

pub mod assertion;
pub mod attestation;
pub mod credential;
