//! The identity-link circuit's witness for one ceremony.
//!
//! A prover that notarized a ceremony's two sessions holds both transcripts in
//! full and the opening of every commitment it made. The circuit opens four of
//! those commitments: the bearer in the token response, the bearer in the
//! identity request, and the id and the handle in the identity response. This
//! picks them out by the same scans the layouts were built from, so the ranges
//! a prover opens are the ranges the verifier framed.
//!
//! # Secrets
//!
//! Everything here except the commitments is secret. The bearer is a live
//! credential until the token is revoked. The id and handle blinders stay
//! secret for good: a leaked witness links the on-chain commitments to the
//! plaintext account, and revoking the token does not undo that. `Debug`
//! prints commitments only, and no error carries a value or a blinder.

use std::ops::Range;

use serde::{
    Serialize,
    Serializer,
};
use sha2::Digest as _;

use super::{
    IdentityMembers,
    Layout,
    LayoutError,
    Profile,
};
use crate::{
    attestation::AttestedData,
    ranges::JsonMember,
};

/// The width of a commitment blinder, as the commitment scheme fixes it.
pub const BLINDER_LEN: usize = 16;

/// Which direction of a session's transcript a range belongs to.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Direction {
    /// The bytes the prover sent.
    Sent,
    /// The bytes the server returned.
    Received,
}

impl Direction {
    /// `sent` or `received`, as tlsn spells it.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sent => "sent",
            Self::Received => "received",
        }
    }
}

impl std::fmt::Display for Direction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The opening of one commitment a session made: its direction, the ranges it
/// covers and the blinder.
#[derive(Clone, PartialEq, Eq)]
pub struct Opening {
    pub direction: Direction,
    pub ranges: Vec<Range<usize>>,
    pub blinder: Vec<u8>,
}

impl std::fmt::Debug for Opening {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Opening")
            .field("direction", &self.direction)
            .field("ranges", &self.ranges)
            .finish_non_exhaustive()
    }
}

/// One notarized session as its prover holds it: both directions in full, the
/// opening of every commitment, and the record the notary signed.
#[derive(Clone, Copy)]
pub struct ProvedSession<'a> {
    pub sent: &'a [u8],
    pub recv: &'a [u8],
    pub openings: &'a [Opening],
    pub record: &'a AttestedData,
}

/// Which of the four opened values a [`WitnessError`] is about.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WitnessValue {
    TokenBearer,
    IdentityBearer,
    Id,
    Handle,
}

impl std::fmt::Display for WitnessValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::TokenBearer => "token bearer",
            Self::IdentityBearer => "identity bearer",
            Self::Id => "id",
            Self::Handle => "handle",
        })
    }
}

/// Why a witness could not be built. No variant carries a value or a blinder.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum WitnessError {
    #[error("the `{0}` profile notarizes no token and identity session pair")]
    NoSessions(&'static str),
    #[error("the {value} cannot be located: {source}")]
    Missing {
        value: WitnessValue,
        source: LayoutError,
    },
    #[error(
        "the identity request commits {0} ranges where the layout commits one, the bearer"
    )]
    IdentityRequestShape(usize),
    #[error("no opening covers exactly the {0}'s range")]
    NoOpening(WitnessValue),
    #[error("the {0}'s blinder is {1} bytes, not {BLINDER_LEN}")]
    BlinderLength(WitnessValue, usize),
    #[error("the signed record carries no commitment over exactly the {0}'s range")]
    NotInRecord(WitnessValue),
    #[error("the signed commitment over the {0} is not SHA256(value || blinder)")]
    CommitmentMismatch(WitnessValue),
    #[error("the {0} is not ASCII")]
    NotAscii(WitnessValue),
    #[error("the token response's bearer and the identity request's bearer differ")]
    BearerMismatch,
}

/// One opened commitment: the value as the wire carried it, its blinder, and
/// the commitment they hash to.
#[derive(Clone, PartialEq, Eq, Serialize)]
pub struct OpenedValue {
    value: String,
    #[serde(serialize_with = "hex0x")]
    blinder: [u8; BLINDER_LEN],
    #[serde(serialize_with = "hex0x")]
    commitment: [u8; 32],
}

impl OpenedValue {
    /// The value, ASCII, as the wire carried it.
    pub fn value(&self) -> &str {
        &self.value
    }

    pub fn blinder(&self) -> &[u8; BLINDER_LEN] {
        &self.blinder
    }

    /// `SHA256(value || blinder)`, equal to the one in the signed record.
    pub fn commitment(&self) -> &[u8; 32] {
        &self.commitment
    }
}

impl std::fmt::Debug for OpenedValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OpenedValue")
            .field("commitment", &Hex(&self.commitment))
            .finish_non_exhaustive()
    }
}

/// The identity-link circuit's witness: the bearer as the token response and
/// the identity request each carried it, the id and the handle, each with the
/// blinder of its commitment.
///
/// Serializes as the circuit's witness script reads it:
/// `{"platform", "token_bearer", "identity_bearer", "id", "handle"}`, each
/// value `{"value", "blinder", "commitment"}` with the value a string and the
/// other two `0x`-hex.
///
/// The handle is the wire's spelling. The circuit folds it; a builder that
/// folded first would prove a different relation.
#[derive(Clone, PartialEq, Eq, Serialize)]
pub struct IdentityLinkWitness {
    platform: &'static str,
    token_bearer: OpenedValue,
    identity_bearer: OpenedValue,
    id: OpenedValue,
    handle: OpenedValue,
}

impl std::fmt::Debug for IdentityLinkWitness {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IdentityLinkWitness")
            .field("platform", &self.platform)
            .field("token_bearer", &self.token_bearer)
            .field("identity_bearer", &self.identity_bearer)
            .field("id", &self.id)
            .field("handle", &self.handle)
            .finish()
    }
}

impl IdentityLinkWitness {
    /// The witness for `profile`'s ceremony, from its token and identity
    /// sessions.
    ///
    /// Each value is located by the scan its layout was built from and must be
    /// exactly one committed range with a [`BLINDER_LEN`]-byte blinder. Its
    /// commitment is recomputed as `SHA256(value || blinder)` and must equal
    /// the one the notary signed over that range, so a witness this returns
    /// opens the record it came from. The two bearers must be the same bytes:
    /// that is the relation the circuit proves.
    pub fn build(
        profile: &Profile,
        token: ProvedSession<'_>,
        identity: ProvedSession<'_>,
    ) -> Result<Self, WitnessError> {
        let (Some(_), Some(session)) = (profile.token, profile.identity) else {
            return Err(WitnessError::NoSessions(profile.platform));
        };

        let token_bearer = JsonMember::in_response(token.recv, "access_token")
            .ok_or(WitnessError::Missing {
                value: WitnessValue::TokenBearer,
                source: LayoutError::MissingField("access_token".into()),
            })?
            .value;
        let identity_bearer = Layout::identity_request(identity.sent)
            .map_err(|source| WitnessError::Missing {
                value: WitnessValue::IdentityBearer,
                source,
            })?
            .commit;
        let [identity_bearer] = <[Range<usize>; 1]>::try_from(identity_bearer)
            .map_err(|ranges| WitnessError::IdentityRequestShape(ranges.len()))?;
        let members =
            IdentityMembers::in_response(identity.recv, &session).map_err(|source| {
                let value = match &source {
                    LayoutError::MissingField(field) if field == session.handle_field => {
                        WitnessValue::Handle
                    }
                    _ => WitnessValue::Id,
                };
                WitnessError::Missing { value, source }
            })?;

        let token_bearer = open(
            WitnessValue::TokenBearer,
            token,
            Direction::Received,
            token_bearer,
        )?;
        let identity_bearer = open(
            WitnessValue::IdentityBearer,
            identity,
            Direction::Sent,
            identity_bearer,
        )?;
        if token_bearer.value != identity_bearer.value {
            return Err(WitnessError::BearerMismatch);
        }
        Ok(Self {
            platform: profile.platform,
            token_bearer,
            identity_bearer,
            id: open(
                WitnessValue::Id,
                identity,
                Direction::Received,
                members.id.value,
            )?,
            handle: open(
                WitnessValue::Handle,
                identity,
                Direction::Received,
                members.handle.value,
            )?,
        })
    }

    /// The profile's platform name.
    pub fn platform(&self) -> &'static str {
        self.platform
    }

    pub fn token_bearer(&self) -> &OpenedValue {
        &self.token_bearer
    }

    pub fn identity_bearer(&self) -> &OpenedValue {
        &self.identity_bearer
    }

    pub fn id(&self) -> &OpenedValue {
        &self.id
    }

    pub fn handle(&self) -> &OpenedValue {
        &self.handle
    }
}

/// The opening of the commitment over exactly `range`, checked against the
/// signed record.
fn open(
    what: WitnessValue,
    at: ProvedSession<'_>,
    direction: Direction,
    range: Range<usize>,
) -> Result<OpenedValue, WitnessError> {
    let opening = at
        .openings
        .iter()
        .find(|o| o.direction == direction && o.ranges == [range.clone()])
        .ok_or(WitnessError::NoOpening(what))?;
    let blinder: [u8; BLINDER_LEN] = opening
        .blinder
        .as_slice()
        .try_into()
        .map_err(|_| WitnessError::BlinderLength(what, opening.blinder.len()))?;
    let (bytes, block) = match direction {
        Direction::Sent => (at.sent, &at.record.sent),
        Direction::Received => (at.recv, &at.record.received),
    };
    let value = bytes
        .get(range.clone())
        .ok_or(WitnessError::NoOpening(what))?;
    let signed = block
        .commitments
        .iter()
        .find(|c| c.start as usize == range.start && c.end as usize == range.end)
        .ok_or(WitnessError::NotInRecord(what))?;
    let commitment: [u8; 32] = sha2::Sha256::new()
        .chain_update(value)
        .chain_update(blinder)
        .finalize()
        .into();
    if signed.commitment != commitment {
        return Err(WitnessError::CommitmentMismatch(what));
    }
    if !value.is_ascii() {
        return Err(WitnessError::NotAscii(what));
    }
    Ok(OpenedValue {
        // ASCII is UTF-8.
        value: value.iter().map(|&b| b as char).collect(),
        blinder,
        commitment,
    })
}

fn hex0x<S: Serializer>(
    bytes: impl AsRef<[u8]>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    serializer.collect_str(&format_args!("0x{}", Hex(bytes.as_ref())))
}

/// Lowercase hex, no prefix.
struct Hex<'a>(&'a [u8]);

impl std::fmt::Display for Hex<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.iter().try_for_each(|b| write!(f, "{b:02x}"))
    }
}

impl std::fmt::Debug for Hex<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "0x{self}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attestation::{
        DirectionBlock,
        RangeCommitment,
    };

    const TOKEN_SENT: &[u8] = b"POST /2/oauth2/token HTTP/1.1\r\nhost: api.x.com\r\n\r\ngrant_type=authorization_code";
    const TOKEN_RECV: &[u8] =
        b"HTTP/1.1 200 OK\r\n\r\n{\"token_type\":\"bearer\",\"access_token\":\"BEARER-1\"}";
    const X_SENT: &[u8] = b"GET /2/users/me HTTP/1.1\r\nhost: api.x.com\r\nauthorization: Bearer BEARER-1\r\n\r\n";
    const X_RECV: &[u8] = b"HTTP/1.1 200 OK\r\n\r\n{\"data\":{\"id\":\"2244994945\",\"name\":\"Al\",\"username\":\"Alice_1\"}}";

    fn sha256(value: &[u8], blinder: &[u8]) -> [u8; 32] {
        sha2::Sha256::new()
            .chain_update(value)
            .chain_update(blinder)
            .finalize()
            .into()
    }

    /// A session as its prover would hold it: every committed range opened
    /// with blinder `[seed + i; 16]`, and a record carrying SHA256(range ||
    /// blinder) for each.
    struct Held {
        sent: Vec<u8>,
        recv: Vec<u8>,
        openings: Vec<Opening>,
        record: AttestedData,
    }

    impl Held {
        fn new(sent: &[u8], recv: &[u8], sl: &Layout, rl: &Layout, seed: u8) -> Self {
            let mut openings = Vec::new();
            let mut block = |direction, bytes: &[u8], commit: &[Range<usize>]| {
                let mut out = DirectionBlock::default();
                for range in commit {
                    let blinder =
                        vec![seed.wrapping_add(openings.len() as u8); BLINDER_LEN];
                    out.commitments.push(RangeCommitment {
                        start: range.start as u32,
                        end: range.end as u32,
                        commitment: sha256(&bytes[range.clone()], &blinder),
                    });
                    openings.push(Opening {
                        direction,
                        ranges: vec![range.clone()],
                        blinder,
                    });
                }
                out
            };
            let sent_block = block(Direction::Sent, sent, &sl.commit);
            let recv_block = block(Direction::Received, recv, &rl.commit);
            Self {
                sent: sent.to_vec(),
                recv: recv.to_vec(),
                openings,
                record: AttestedData {
                    authority_id: [0; 32],
                    created_at: 0,
                    sent_transcript_length: sent.len() as u32,
                    recv_transcript_length: recv.len() as u32,
                    sent: sent_block,
                    received: recv_block,
                },
            }
        }

        fn token(sent: &[u8], recv: &[u8]) -> Self {
            Self::new(
                sent,
                recv,
                &Layout::token_request(sent),
                &Layout::token_response(recv).unwrap(),
                1,
            )
        }

        fn identity(profile: &Profile, sent: &[u8], recv: &[u8]) -> Self {
            Self::new(
                sent,
                recv,
                &Layout::identity_request(sent).unwrap(),
                &Layout::identity_response(recv, &profile.identity.unwrap()).unwrap(),
                100,
            )
        }

        fn proved(&self) -> ProvedSession<'_> {
            ProvedSession {
                sent: &self.sent,
                recv: &self.recv,
                openings: &self.openings,
                record: &self.record,
            }
        }
    }

    fn x() -> (Held, Held) {
        (
            Held::token(TOKEN_SENT, TOKEN_RECV),
            Held::identity(&super::super::profiles::X, X_SENT, X_RECV),
        )
    }

    #[test]
    fn the_witness_opens_the_four_values_the_layouts_commit() {
        let (token, identity) = x();
        let w = IdentityLinkWitness::build(
            &super::super::profiles::X,
            token.proved(),
            identity.proved(),
        )
        .unwrap();
        assert_eq!(w.platform(), "x");
        assert_eq!(w.token_bearer().value(), "BEARER-1");
        assert_eq!(w.identity_bearer().value(), "BEARER-1");
        assert_eq!(w.id().value(), "2244994945");
        // The wire's spelling: the circuit folds, the witness does not.
        assert_eq!(w.handle().value(), "Alice_1");
        for v in [w.token_bearer(), w.identity_bearer(), w.id(), w.handle()] {
            assert_eq!(*v.commitment(), sha256(v.value().as_bytes(), v.blinder()));
        }
    }

    #[test]
    fn the_witness_serializes_as_the_circuit_script_reads_it() {
        let (token, identity) = x();
        let w = IdentityLinkWitness::build(
            &super::super::profiles::X,
            token.proved(),
            identity.proved(),
        )
        .unwrap();
        let json = serde_json::to_value(&w).unwrap();
        let object = json.as_object().unwrap();
        let mut keys: Vec<&str> = object.keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            [
                "handle",
                "id",
                "identity_bearer",
                "platform",
                "token_bearer"
            ]
        );
        assert_eq!(json["platform"], "x");
        let handle = &json["handle"];
        assert_eq!(handle["value"], "Alice_1");
        // Blinders are `[seed + i; 16]`, so the handle's is one byte, repeated.
        let byte = w.handle().blinder()[0];
        assert_eq!(*w.handle().blinder(), [byte; BLINDER_LEN]);
        assert_eq!(
            handle["blinder"],
            format!("0x{}", format!("{byte:02x}").repeat(16))
        );
        // `hashlib.sha256(b"Alice_1" + bytes([0x68] * 16))`, computed outside
        // this crate.
        assert_eq!(byte, 0x68);
        assert_eq!(
            handle["commitment"],
            "0x7e15e5f1a41218b39907ebe973f6f787f5e0f7724b03cb759c3e82b8246e86a2"
        );
        assert_eq!(handle.as_object().unwrap().len(), 3);
    }

    #[test]
    fn a_github_bare_integer_id_opens_as_its_digits() {
        let github = super::super::profiles::GITHUB;
        let token_sent = b"POST /login/oauth/access_token HTTP/1.1\r\nhost: github.com\r\n\r\nclient_id=a";
        let token_recv =
            b"HTTP/1.1 200 OK\r\n\r\n{\"access_token\":\"gho_X\",\"scope\":\"\"}";
        let sent = b"GET /user HTTP/1.1\r\nhost: api.github.com\r\nauthorization: Bearer gho_X\r\n\r\n";
        let recv = b"HTTP/1.1 200 OK\r\n\r\n{\n  \"login\": \"OctoCat\",\n  \"id\": 583231 ,\n  \"x\": 1\n}";
        let token = Held::token(token_sent, token_recv);
        let identity = Held::identity(&github, sent, recv);
        let w = IdentityLinkWitness::build(&github, token.proved(), identity.proved())
            .unwrap();
        assert_eq!(w.platform(), "github");
        assert_eq!(w.id().value(), "583231");
        assert_eq!(w.handle().value(), "OctoCat");
    }

    #[test]
    fn a_commitment_the_record_does_not_carry_is_refused() {
        let (token, mut identity) = x();
        let members = IdentityMembers::in_response(
            X_RECV,
            &super::super::profiles::X.identity.unwrap(),
        )
        .unwrap();
        let signed = identity
            .record
            .received
            .commitments
            .iter_mut()
            .find(|c| c.start as usize == members.handle.value.start)
            .unwrap();
        signed.commitment[0] ^= 1;
        assert_eq!(
            IdentityLinkWitness::build(
                &super::super::profiles::X,
                token.proved(),
                identity.proved()
            ),
            Err(WitnessError::CommitmentMismatch(WitnessValue::Handle))
        );
    }

    #[test]
    fn a_wrong_blinder_is_a_mismatch() {
        let (token, mut identity) = x();
        let opening = identity
            .openings
            .iter_mut()
            .find(|o| o.direction == Direction::Sent)
            .unwrap();
        opening.blinder[0] ^= 1;
        assert_eq!(
            IdentityLinkWitness::build(
                &super::super::profiles::X,
                token.proved(),
                identity.proved()
            ),
            Err(WitnessError::CommitmentMismatch(
                WitnessValue::IdentityBearer
            ))
        );
    }

    #[test]
    fn two_different_bearers_are_refused() {
        // Each session is self-consistent; the relation between them is not.
        let token = Held::token(
            TOKEN_SENT,
            b"HTTP/1.1 200 OK\r\n\r\n{\"token_type\":\"bearer\",\"access_token\":\"BEARER-2\"}",
        );
        let identity = Held::identity(&super::super::profiles::X, X_SENT, X_RECV);
        let err = IdentityLinkWitness::build(
            &super::super::profiles::X,
            token.proved(),
            identity.proved(),
        )
        .unwrap_err();
        assert_eq!(err, WitnessError::BearerMismatch);
        assert!(!err.to_string().contains("BEARER"));
    }

    #[test]
    fn a_blinder_of_another_width_is_refused() {
        let (mut token, identity) = x();
        for opening in &mut token.openings {
            opening.blinder = vec![7; 32];
        }
        assert_eq!(
            IdentityLinkWitness::build(
                &super::super::profiles::X,
                token.proved(),
                identity.proved()
            ),
            Err(WitnessError::BlinderLength(WitnessValue::TokenBearer, 32))
        );
    }

    #[test]
    fn a_value_without_an_opening_is_refused() {
        let (token, mut identity) = x();
        identity.openings.retain(|o| o.direction == Direction::Sent);
        assert_eq!(
            IdentityLinkWitness::build(
                &super::super::profiles::X,
                token.proved(),
                identity.proved()
            ),
            Err(WitnessError::NoOpening(WitnessValue::Id))
        );
    }

    #[test]
    fn a_non_ascii_handle_is_named_and_not_printed() {
        let recv = "HTTP/1.1 200 OK\r\n\r\n{\"data\":{\"id\":\"7\",\"username\":\"Al\u{00ef}ce\"}}";
        let (token, _) = x();
        let identity =
            Held::identity(&super::super::profiles::X, X_SENT, recv.as_bytes());
        let err = IdentityLinkWitness::build(
            &super::super::profiles::X,
            token.proved(),
            identity.proved(),
        )
        .unwrap_err();
        assert_eq!(err, WitnessError::NotAscii(WitnessValue::Handle));
        assert_eq!(err.to_string(), "the handle is not ASCII");
    }

    #[test]
    fn a_profile_without_both_sessions_has_no_witness() {
        let (token, identity) = x();
        assert_eq!(
            IdentityLinkWitness::build(
                &super::super::profiles::GOOGLE,
                token.proved(),
                identity.proved()
            ),
            Err(WitnessError::NoSessions("google"))
        );
    }

    #[test]
    fn debug_prints_no_secret() {
        let (token, identity) = x();
        let w = IdentityLinkWitness::build(
            &super::super::profiles::X,
            token.proved(),
            identity.proved(),
        )
        .unwrap();
        let printed = format!("{w:?} {:?}", identity.openings);
        for secret in ["BEARER-1", "2244994945", "Alice_1"] {
            assert!(!printed.contains(secret), "{secret} in {printed}");
        }
        let blinder = format!("{}", Hex(w.handle().blinder()));
        assert!(!printed.contains(&blinder));
    }
}
