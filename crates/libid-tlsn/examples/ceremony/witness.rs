//! The identity-link circuit's witness for one ceremony, as JSON.
//!
//! Included by `#[path]` from `ceremony_fixtures` and
//! `tests/ceremony_end_to_end.rs`, each beside `common`; not an example of its
//! own.
//!
//! The circuit opens four committed ranges: the bearer in the token response,
//! the bearer in the identity request, and the id and the handle in the
//! identity response. Each is located by the scan its layout was built from,
//! paired with its opening, and checked: `SHA256(value || blinder)` must equal
//! the commitment the notary signed over that range.

use std::ops::Range;

use libid_tlsn::{
    CommitmentOpening,
    Direction,
};
use libid_transcript::{
    attestation::AttestedData,
    ceremony::{
        identity_bearer,
        token_bearer,
        IdentityMembers,
        Profile,
    },
};
use serde_json::{
    json,
    Value,
};
use sha2::Digest as _;

use super::common::hex0x;

/// One notarized session as its prover holds it: both directions in full, the
/// opening of every commitment, and the record the notary signed.
pub struct Held {
    pub sent: Vec<u8>,
    pub recv: Vec<u8>,
    pub openings: Vec<CommitmentOpening>,
    pub record: AttestedData,
}

/// `identity_link_witness` for `profile`'s token and identity sessions:
/// `{platform, token_bearer, identity_bearer, id, handle}`, each value
/// `{value, blinder, commitment}`, the value as the wire carried it and the
/// other two `0x` lowercase hex. An error names the value that failed and
/// never carries a value or a blinder.
pub fn identity_link_witness(
    profile: &Profile,
    token: &Held,
    identity: &Held,
) -> Result<Value, String> {
    let session = profile.identity.ok_or_else(|| {
        format!("the `{}` profile has no identity session", profile.platform)
    })?;
    let token_bearer = token_bearer(&token.recv)
        .map_err(|e| format!("token bearer: {e}"))?
        .value;
    let identity_bearer =
        identity_bearer(&identity.sent).map_err(|e| format!("identity bearer: {e}"))?;
    let members = IdentityMembers::in_response(&identity.recv, &session)
        .map_err(|e| format!("id and handle: {e}"))?;

    let token_bearer = open("token bearer", token, Direction::Received, token_bearer)?;
    let identity_bearer = open(
        "identity bearer",
        identity,
        Direction::Sent,
        identity_bearer,
    )?;
    if token_bearer["value"] != identity_bearer["value"] {
        return Err(
            "the token response's bearer and the identity request's bearer differ".into(),
        );
    }
    Ok(json!({
        "platform": profile.platform,
        "token_bearer": token_bearer,
        "identity_bearer": identity_bearer,
        "id": open("id", identity, Direction::Received, members.id.value)?,
        "handle": open("handle", identity, Direction::Received, members.handle.value)?,
    }))
}

/// The opening of the commitment over exactly `range`, checked against the
/// signed record.
fn open(
    what: &str,
    at: &Held,
    direction: Direction,
    range: Range<usize>,
) -> Result<Value, String> {
    let opening = at
        .openings
        .iter()
        .find(|o| o.direction == direction && o.ranges == [range.clone()])
        .ok_or_else(|| format!("{what}: no opening covers exactly its range"))?;
    let (bytes, block) = match direction {
        Direction::Sent => (&at.sent, &at.record.sent),
        Direction::Received => (&at.recv, &at.record.received),
    };
    let signed = block
        .commitments
        .iter()
        .find(|c| c.start as usize == range.start && c.end as usize == range.end)
        .ok_or_else(|| {
            format!("{what}: the record commits nothing over exactly its range")
        })?;
    let value = &bytes[range];
    let commitment: [u8; 32] = sha2::Sha256::new()
        .chain_update(value)
        .chain_update(&opening.blinder)
        .finalize()
        .into();
    if signed.commitment != commitment {
        return Err(format!(
            "{what}: the signed commitment is not SHA256(value || blinder)"
        ));
    }
    let value = ascii(value).ok_or_else(|| format!("{what}: not ASCII"))?;
    Ok(json!({
        "value": value,
        "blinder": hex0x(&opening.blinder),
        "commitment": hex0x(&commitment),
    }))
}

/// A committed value as text: the witness and the identity request carry it
/// as the wire did, and every value the circuit opens is ASCII.
fn ascii(value: &[u8]) -> Option<&str> {
    std::str::from_utf8(value).ok().filter(|v| v.is_ascii())
}
