//! Choosing what a notarized session reveals.
//!
//! Each layout names what it reveals and commits the complement, so it tiles
//! the transcript as the Platform Verifier requires. [`token_bearer`],
//! [`identity_bearer`] and [`IdentityMembers`] locate the committed values the
//! identity-link circuit opens.

use std::ops::Range;

use crate::ranges::{
    find_first,
    JsonMember,
};

/// What one direction of one session discloses.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Layout {
    /// Ascending, non-overlapping.
    pub reveal: Vec<Range<usize>>,
    /// The complement of `reveal` over the whole direction.
    pub commit: Vec<Range<usize>>,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum LayoutError {
    #[error("the request has no `{0}` header, so the layout has nothing to anchor on")]
    MissingHeader(&'static str),
    #[error("the response carries no `{0}` field where the profile expects one")]
    MissingField(String),
    #[error("the response's `{0}` field is empty, so there is no value to commit")]
    EmptyField(String),
    #[error("the request holds {0} head boundaries (`\\r\\n\\r\\n`) where one HTTP request holds exactly one")]
    NoHeadBoundary(usize),
    #[error("the request's `{0}` header has an empty value, so there is no credential to commit")]
    EmptyHeader(&'static str),
    #[error("{0} bytes follow the head of a request that has no body")]
    BytesAfterRequest(usize),
}

/// Why a token body could not be serialized from a profile's field list.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum TokenBodyError {
    #[error("the profile's body names `{0}`, which the caller has no value for")]
    MissingField(String),
    #[error("the caller names `{0}`, which the profile's body does not take")]
    UnknownField(String),
    #[error("the value of `{0}` is empty, and the verifier refuses an empty field")]
    EmptyField(String),
}

/// The value of `grant_type` on every token request: RFC 6749 section 4.1.3
/// fixes it, so no profile and no caller chooses it.
pub const AUTHORIZATION_CODE_GRANT: &str = "authorization_code";

/// One value as the `application/x-www-form-urlencoded` serializer spells it
/// (WHATWG URL, section 5.2): `[A-Za-z0-9*._-]` as they are, a space as `+`,
/// every other byte as `%XX` with uppercase digits.
///
/// This is the alphabet the on-chain verifiers hold every token body value to,
/// and the one `URLSearchParams` emits in the browser -- so a body built here
/// and one built there are the same bytes. It is NOT RFC 3986's unreserved
/// set: `~` is escaped and `*` is not, and a body spelled the other way is a
/// body the verifier refuses.
pub fn form_encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for b in value.bytes() {
        match b {
            b'0'..=b'9' | b'A'..=b'Z' | b'a'..=b'z' | b'*' | b'-' | b'.' | b'_' => {
                out.push(b as char)
            }
            b' ' => out.push('+'),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// The token request body a profile's verifier holds the request to:
/// `session.token_fields` in order, each as `name=value` with the value
/// form-encoded, `&` between pairs and nothing after the last.
///
/// `values` holds each field's value by name, decoded, and `grant_type` is
/// always [`AUTHORIZATION_CODE_GRANT`]. The two lists must agree: a name the
/// profile lists and `values` lacks is an error rather than a field left out,
/// because the verifier compares the field list whole and a body missing one
/// verifies nowhere; a name `values` carries and the profile does not list --
/// or `grant_type`, which no caller chooses -- is an error rather than a
/// value dropped, because a caller that named it meant it to be sent. An
/// empty value is refused for the first reason.
pub fn token_body(
    session: &TokenSession,
    values: &[(&str, &str)],
) -> Result<String, TokenBodyError> {
    if let Some((name, _)) = values
        .iter()
        .find(|(name, _)| *name == "grant_type" || !session.token_fields.contains(name))
    {
        return Err(TokenBodyError::UnknownField(name.to_string()));
    }
    let mut body = String::new();
    for (index, name) in session.token_fields.iter().enumerate() {
        let value = match *name {
            "grant_type" => AUTHORIZATION_CODE_GRANT,
            _ => values
                .iter()
                .find(|(field, _)| field == name)
                .map(|(_, value)| *value)
                .ok_or_else(|| TokenBodyError::MissingField(name.to_string()))?,
        };
        if value.is_empty() {
            return Err(TokenBodyError::EmptyField(name.to_string()));
        }
        if index > 0 {
            body.push('&');
        }
        body.push_str(name);
        body.push('=');
        body.push_str(&form_encode(value));
    }
    Ok(body)
}

/// The bytes of `[0, len)` that `reveal` does not cover.
///
/// Deriving the commitments this way is what makes every layout tile. The
/// alternative -- listing both and hoping they agree -- is the mistake the
/// verifier exists to catch.
fn complement(reveal: &[Range<usize>], len: usize) -> Vec<Range<usize>> {
    let mut out = Vec::new();
    let mut at = 0usize;
    for r in reveal {
        if r.start > at {
            out.push(at..r.start);
        }
        at = r.end;
    }
    if at < len {
        out.push(at..len);
    }
    out
}

/// The ceremony profiles, and the types a layout is built from.
///
/// Re-exported rather than restated. `libid-profiles` is generated in
/// libid-contracts from `solidity/contracts/ceremony/profiles.json` -- the same
/// file `CeremonyProfile.sol` is generated from -- so what a prover reveals and
/// what a Platform Verifier compares it against come from one place. A table
/// written again here would be a second copy of values whose whole problem is
/// that copies drift in silence.
///
/// [`IdShape`] used to be declared here. It said the same thing the generated
/// one says, and two spellings of one profile fact is the drift this crate now
/// takes the table to avoid.
pub use libid_profiles::{
    self as profiles,
    IdShape,
    IdentitySession,
    Profile,
    TokenSession,
};

impl Layout {
    /// A layout that reveals these ranges of a direction `len` bytes long, and
    /// commits everything they leave.
    ///
    /// The one door into a tiling `Layout`, and the reason every constructor below
    /// tiles by construction rather than by inspection: no constructor states
    /// `commit`, so no constructor's list can disagree with the reveals it was
    /// supposed to complement. `layout` -- a lowercase homonym of the type it
    /// built, in a module about layouts -- said none of that.
    ///
    /// `complement` walks the reveals once, taking each as starting where the last
    /// one ended, so unsorted input reads as overlap and yields a complement that
    /// tiles nothing -- which the Platform Verifier rejects and nothing here would
    /// catch. Sorting is done once, here, so no caller has to remember: the
    /// layouts that build in order are unaffected, and
    /// [`Layout::identity_response`], whose two members arrive in whatever order
    /// the platform serialized them, carries no sort of its own. Overlapping input
    /// is a caller bug that sorting cannot repair, and the debug assertion is what
    /// says so.
    ///
    /// Private, and `Layout`'s fields stay public beside it. A prover outside
    /// this module may state a layout this module does not know, so tiling is a
    /// property of these constructors and not of the type. A public constructor
    /// advertising a guarantee the type does not enforce would be worse than no
    /// public constructor at all.
    ///
    /// It takes an iterator rather than a `Vec` so that a one-range layout is
    /// spelled `core::iter::once(a..b)`. Both `vec![a..b]` and `[a..b]` trip
    /// `clippy::single_range_in_vec_init`, a lint that exists to catch `vec![0; n]`
    /// typos and cannot tell this apart from one; the iterator form says what is
    /// meant without a named helper standing in for it.
    fn revealing(reveal: impl IntoIterator<Item = Range<usize>>, len: usize) -> Self {
        let mut reveal: Vec<Range<usize>> = reveal.into_iter().collect();
        reveal.sort_by_key(|r| r.start);
        debug_assert!(
            reveal.windows(2).all(|pair| pair[0].end <= pair[1].start),
            "reveal ranges overlap: {reveal:?}"
        );
        let commit = complement(&reveal, len);
        Layout { reveal, commit }
    }

    /// The token request, revealed whole. Refused unless it holds exactly one
    /// head boundary, as the verifier requires.
    pub fn token_request(sent: &[u8]) -> Result<Self, LayoutError> {
        head_end(sent)?;
        Ok(Self::revealing(core::iter::once(0..sent.len()), sent.len()))
    }

    /// The token response: the bearer's anchors revealed, everything else
    /// committed.
    pub fn token_response(recv: &[u8]) -> Result<Self, LayoutError> {
        Ok(Self::revealing(token_bearer(recv)?.anchors(), recv.len()))
    }

    /// The identity request: everything revealed but the committed bearer.
    /// Refused unless `sent` is exactly one bodiless request, as the verifier
    /// requires.
    pub fn identity_request(sent: &[u8]) -> Result<Self, LayoutError> {
        let end = head_end(sent)?;
        if end != sent.len() {
            return Err(LayoutError::BytesAfterRequest(sent.len() - end));
        }
        let bearer = identity_bearer(sent)?;
        Ok(Self::revealing(
            [0..bearer.start, bearer.end..sent.len()],
            sent.len(),
        ))
    }

    /// The identity response: the anchors of the id and handle revealed, each
    /// value and everything else committed, keeping the account's other fields
    /// off chain.
    pub fn identity_response(
        recv: &[u8],
        session: &IdentitySession,
    ) -> Result<Self, LayoutError> {
        let IdentityMembers { id, handle } = IdentityMembers::in_response(recv, session)?;

        // JSON member order is not fixed; `Self::revealing` sorts, so this does
        // not assume one.
        Ok(Self::revealing(
            id.anchors().into_iter().chain(handle.anchors()),
            recv.len(),
        ))
    }
}

/// The offset just past the one head boundary (`\r\n\r\n`) of a request,
/// counting overlapping boundaries as the verifier does.
fn head_end(sent: &[u8]) -> Result<usize, LayoutError> {
    const HEAD_END: &[u8] = b"\r\n\r\n";
    let first = find_first(sent, HEAD_END);
    let heads = core::iter::successors(first, |&at| {
        find_first(&sent[at + 1..], HEAD_END).map(|next| at + 1 + next)
    })
    .count();
    match first {
        Some(at) if heads == 1 => Ok(at + HEAD_END.len()),
        _ => Err(LayoutError::NoHeadBoundary(heads)),
    }
}

/// The bearer's member in every token response (RFC 6749 section 5.1).
const ACCESS_TOKEN: &str = "access_token";

/// The contract's `BEARER_PREFIX`: the bytes before the identity request's bearer.
const BEARER_PREFIX: &[u8] = b"\r\nauthorization: Bearer ";

/// The bearer member in a token response's body, offsets into `recv`.
/// Refused when empty.
pub fn token_bearer(recv: &[u8]) -> Result<JsonMember, LayoutError> {
    nonempty(JsonMember::in_response(recv, ACCESS_TOKEN), ACCESS_TOKEN)
}

/// The bearer in an identity request, offsets into `sent`. Refused when empty.
pub fn identity_bearer(sent: &[u8]) -> Result<Range<usize>, LayoutError> {
    const HEADER: &str = "authorization";
    let start = find_first(sent, BEARER_PREFIX)
        .ok_or(LayoutError::MissingHeader(HEADER))?
        + BEARER_PREFIX.len();
    let end = start
        + find_first(&sent[start..], b"\r\n")
            .ok_or(LayoutError::MissingHeader(HEADER))?;
    if start == end {
        return Err(LayoutError::EmptyHeader(HEADER));
    }
    Ok(start..end)
}

/// Where the two identity members sit in an identity response.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IdentityMembers {
    pub id: JsonMember,
    pub handle: JsonMember,
}

impl IdentityMembers {
    /// Both members of `session`'s profile in `recv`, offsets into `recv`.
    /// Refused when either value is empty.
    pub fn in_response(
        recv: &[u8],
        session: &IdentitySession,
    ) -> Result<Self, LayoutError> {
        let (id_field, handle_field) = (session.id_field, session.handle_field);
        let id = match session.id_shape {
            IdShape::JsonString => JsonMember::in_response(recv, id_field),
            IdShape::JsonInteger => JsonMember::bare_in_response(recv, id_field),
        };
        let id = nonempty(id, id_field)?;
        let handle = nonempty(JsonMember::in_response(recv, handle_field), handle_field)?;
        Ok(Self { id, handle })
    }
}

/// `found`, unless it is absent or its value is empty.
fn nonempty(found: Option<JsonMember>, field: &str) -> Result<JsonMember, LayoutError> {
    match found {
        None => Err(LayoutError::MissingField(field.into())),
        Some(member) if member.value.is_empty() => {
            Err(LayoutError::EmptyField(field.into()))
        }
        Some(member) => Ok(member),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The property every layout must have, checked directly rather than
    /// inferred from the ranges looking plausible.
    fn tiles(l: &Layout, len: usize) -> bool {
        let mut spans: Vec<Range<usize>> =
            l.reveal.iter().chain(l.commit.iter()).cloned().collect();
        spans.sort_by_key(|r| r.start);
        let mut at = 0usize;
        for s in spans {
            if s.start != at || s.end <= s.start {
                return false;
            }
            at = s.end;
        }
        at == len
    }

    /// The launch profiles these layouts are built for. Taking the arguments
    /// from the table rather than restating them is what makes these tests
    /// exercise the values a Platform Verifier actually compares against.
    fn x_token() -> TokenSession {
        libid_profiles::X
            .token
            .expect("x notarizes a token session")
    }

    fn x_identity() -> IdentitySession {
        libid_profiles::X
            .identity
            .expect("x notarizes an identity session")
    }

    fn github_token() -> TokenSession {
        libid_profiles::GITHUB
            .token
            .expect("github notarizes a token session")
    }

    fn github_identity() -> IdentitySession {
        libid_profiles::GITHUB
            .identity
            .expect("github notarizes an identity session")
    }

    const X_TOKEN_REQ: &[u8] =
        b"POST /2/oauth2/token HTTP/1.1\r\nhost: api.x.com\r\n\r\ngrant_type=authorization_code&client_id=abc&code_verifier=xyz";

    #[test]
    fn a_spaced_access_token_delimiter_is_revealed_and_the_bearer_alone_committed() {
        // A token service that pretty-prints puts whitespace inside the
        // delimiter: the delimiter is revealed as served, and the bearer between
        // the two reveals is what is committed -- never the whitespace with it.
        for ws in [" ", "\t", "\r", "\n", " \t\r\n"] {
            let prefix = format!("\"access_token\"{ws}:{ws}\"");
            let recv = format!("HTTP/1.1 200 OK\r\n\r\n{{{prefix}SECRET\"}}");
            let recv = recv.as_bytes();
            let layout = Layout::token_response(recv).unwrap();
            assert!(tiles(&layout, recv.len()));
            assert_eq!(&recv[layout.reveal[0].clone()], prefix.as_bytes());
            assert_eq!(
                &recv[layout.reveal[0].end..layout.reveal[1].start],
                b"SECRET"
            );
            assert_eq!(&recv[layout.reveal[1].clone()], b"\"");
        }
    }

    #[test]
    fn a_bearer_split_by_chunk_framing_is_refused() {
        // The session Rust actually runs. Framing inside the committed range
        // means the circuit opens bytes the token service never returned, and
        // the on-chain framing check passes anyway because it reads the
        // delimiters either side of the commitment, not its contents.
        let mut recv = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec();
        for part in [
            r#"{"access_token":"ghu_AA"#,
            r#"BB","token_type":"bearer"}"#,
        ] {
            recv.extend_from_slice(format!("{:x}\r\n", part.len()).as_bytes());
            recv.extend_from_slice(part.as_bytes());
            recv.extend_from_slice(b"\r\n");
        }
        recv.extend_from_slice(b"0\r\n\r\n");
        assert!(Layout::token_response(&recv).is_err());
    }

    #[test]
    fn an_empty_bearer_is_refused() {
        // The two reveals would be adjacent, the complement would commit
        // nothing, and `requireFramedCommitment` would find no bearer in a
        // direction that carries no commitment at all.
        let recv: &[u8] = br#"HTTP/1.1 200 OK"#;
        let recv = [recv, b"\r\n\r\n", br#"{"access_token":""}"#].concat();
        assert_eq!(
            Layout::token_response(&recv),
            Err(LayoutError::EmptyField("access_token".into()))
        );
        let absent = b"HTTP/1.1 200 OK\r\n\r\n{\"token_type\":\"bearer\"}";
        assert_eq!(
            token_bearer(absent),
            Err(LayoutError::MissingField("access_token".into()))
        );
    }

    #[test]
    fn a_bearer_carrying_structural_bytes_is_committed_whole() {
        // Only `"` closes the value. A scan stopping at `:` or `,` would
        // commit a prefix and REVEAL the rest of the bearer.
        let recv = [
            b"HTTP/1.1 200 OK\r\n\r\n".as_slice(),
            br#"{"access_token":"gh:u,A}BC","token_type":"bearer"}"#,
        ]
        .concat();
        let l = Layout::token_response(&recv).unwrap();
        assert!(tiles(&l, recv.len()));
        assert!(l.commit.iter().any(|c| recv[c.clone()] == *b"gh:u,A}BC"));
        // And no revealed run holds any part of it.
        for r in &l.reveal {
            assert!(
                !recv[r.clone()].windows(3).any(|w| w == b"gh:"),
                "the bearer must not appear in a revealed range"
            );
        }
    }

    #[test]
    fn a_header_cannot_answer_for_the_body() {
        // The old scan started at byte zero, so a response header carrying the
        // delimiter was matched before the body's own member.
        let recv: &[u8] = concat!(
            "HTTP/1.1 200 OK\r\n",
            r#"x-echo: "access_token":"decoy""#,
            "\r\n\r\n",
            r#"{"access_token":"real"}"#,
        )
        .as_bytes();
        let l = Layout::token_response(recv).unwrap();
        let revealed: Vec<u8> = l
            .reveal
            .iter()
            .flat_map(|r| recv[r.clone()].to_vec())
            .collect();
        assert_eq!(revealed, br#""access_token":"""#.to_vec());
        // The committed run is the bearer in the BODY, not the decoy.
        let committed = l.commit.iter().find(|r| r.len() == 4).unwrap();
        assert_eq!(&recv[committed.clone()], b"real");
    }

    #[test]
    fn the_x_token_request_is_revealed_whole() {
        let l = Layout::token_request(X_TOKEN_REQ).unwrap();
        assert_eq!(l.reveal, vec![0..X_TOKEN_REQ.len()]);
        assert!(l.commit.is_empty(), "X hides nothing in its token request");
        assert!(tiles(&l, X_TOKEN_REQ.len()));
        // The verifier locates the body after exactly one head boundary.
        let headless = &X_TOKEN_REQ[..20];
        assert_eq!(
            Layout::token_request(headless),
            Err(LayoutError::NoHeadBoundary(0))
        );
    }

    #[test]
    fn the_github_exchange_is_revealed_whole() {
        let req: &[u8] = b"POST /login/oauth/access_token HTTP/1.1\r\nhost: github.com\r\n\r\nclient_id=Iv1.x&code=abc&code_verifier=xyz&client_secret=deadbeef";
        let l = Layout::token_request(req).unwrap();
        assert_eq!(l.reveal, vec![0..req.len()]);
        assert!(l.commit.is_empty(), "the credential is public and revealed");
        assert!(tiles(&l, req.len()));
        let revealed = &req[l.reveal[0].clone()];
        assert!(revealed.windows(8).any(|w| w == b"deadbeef"));
    }

    #[test]
    fn form_encode_spells_the_whatwg_alphabet() {
        assert_eq!(form_encode("aZ09*-._"), "aZ09*-._");
        assert_eq!(form_encode("a b"), "a+b");
        assert_eq!(form_encode("~/?&=%"), "%7E%2F%3F%26%3D%25");
        assert_eq!(
            form_encode("https://app.example/cb"),
            "https%3A%2F%2Fapp.example%2Fcb"
        );
    }

    #[test]
    fn the_x_token_body_is_the_profile_fields_in_order() {
        let body = token_body(
            &x_token(),
            &[
                ("client_id", "myClient-1"),
                ("code", "abc123"),
                ("redirect_uri", "https://app.example/cb"),
                ("code_verifier", "xyz~"),
            ],
        )
        .unwrap();
        assert_eq!(
            body,
            "grant_type=authorization_code&client_id=myClient-1&code=abc123&redirect_uri=https%3A%2F%2Fapp.example%2Fcb&code_verifier=xyz%7E"
        );
    }

    #[test]
    fn the_github_token_body_is_the_profile_fields_in_order() {
        let body = token_body(
            &github_token(),
            &[
                ("client_id", "Iv1.x"),
                ("code", "abc"),
                ("redirect_uri", "https://app.example/cb"),
                ("code_verifier", "xyz"),
                ("client_secret", "dead beef"),
            ],
        )
        .unwrap();
        assert_eq!(
            body,
            "client_id=Iv1.x&code=abc&redirect_uri=https%3A%2F%2Fapp.example%2Fcb&code_verifier=xyz&client_secret=dead+beef"
        );
    }

    #[test]
    fn a_field_the_caller_cannot_answer_is_an_error() {
        assert_eq!(
            token_body(&github_token(), &[("client_id", "Iv1.x")]),
            Err(TokenBodyError::MissingField("code".into()))
        );
        assert_eq!(
            token_body(&x_token(), &[("client_id", "")]),
            Err(TokenBodyError::EmptyField("client_id".into()))
        );
    }

    #[test]
    fn a_field_the_profile_does_not_take_is_an_error() {
        let x = [
            ("client_id", "myClient-1"),
            ("code", "abc123"),
            ("redirect_uri", "https://app.example/cb"),
            ("code_verifier", "xyz"),
        ];
        let with = |extra| {
            let mut values = x.to_vec();
            values.push(extra);
            token_body(&x_token(), &values)
        };
        assert_eq!(
            with(("client_secret", "never sent")),
            Err(TokenBodyError::UnknownField("client_secret".into()))
        );
        assert_eq!(
            with(("grant_type", "client_credentials")),
            Err(TokenBodyError::UnknownField("grant_type".into()))
        );
        assert_eq!(
            with(("code_verifer", "typo")),
            Err(TokenBodyError::UnknownField("code_verifer".into()))
        );
    }

    #[test]
    fn the_token_response_reveals_only_the_two_anchors() {
        let recv: &[u8] =
            b"HTTP/1.1 200 OK\r\n\r\n{\"token_type\":\"bearer\",\"access_token\":\"SECRETBEARER\"}";
        let l = Layout::token_response(recv).unwrap();
        assert!(tiles(&l, recv.len()));
        assert_eq!(
            recv[l.reveal[0].clone()].to_vec(),
            b"\"access_token\":\"".to_vec()
        );
        assert_eq!(recv[l.reveal[1].clone()].to_vec(), b"\"".to_vec());
        // The bearer is committed, between the two anchors.
        assert!(l.commit.iter().any(|c| recv[c.clone()] == *b"SECRETBEARER"));
    }

    #[test]
    fn the_identity_request_commits_only_the_bearer() {
        let sent: &[u8] = b"GET /2/users/me HTTP/1.1\r\nhost: api.x.com\r\nauthorization: Bearer TOKENVALUE\r\nconnection: close\r\n\r\n";
        let l = Layout::identity_request(sent).unwrap();
        assert!(tiles(&l, sent.len()));
        assert_eq!(l.commit.len(), 1, "exactly one credential is hidden");
        assert_eq!(sent[l.commit[0].clone()].to_vec(), b"TOKENVALUE".to_vec());
        // And the framing bytes the verifier compares are revealed.
        let before = &sent[..l.commit[0].start];
        assert!(before.ends_with(b"\r\nauthorization: Bearer "));
        assert!(sent[l.commit[0].end..].starts_with(b"\r\n"));
    }

    #[test]
    fn the_identity_request_is_one_request_ending_the_direction() {
        const ONE: &[u8] =
            b"GET /2/users/me HTTP/1.1\r\nauthorization: Bearer T\r\nconnection: close\r\n\r\n";
        assert_eq!(
            identity_bearer(ONE).map(|bearer| ONE[bearer].to_vec()),
            Ok(b"T".to_vec())
        );
        let trailing = [ONE, b"x"].concat();
        assert_eq!(
            Layout::identity_request(&trailing),
            Err(LayoutError::BytesAfterRequest(1))
        );
        // A second request after the first: the platform would answer both,
        // and the verifier reads one.
        let two = [ONE, ONE].concat();
        assert_eq!(
            Layout::identity_request(&two),
            Err(LayoutError::NoHeadBoundary(2))
        );
        let unterminated = &ONE[..ONE.len() - 2];
        assert_eq!(
            Layout::identity_request(unterminated),
            Err(LayoutError::NoHeadBoundary(0))
        );
    }

    #[test]
    fn an_empty_bearer_header_is_refused() {
        assert_eq!(
            Layout::identity_request(
                b"GET /2/users/me HTTP/1.1\r\nauthorization: Bearer \r\nhost: api.x.com\r\n\r\n"
            ),
            Err(LayoutError::EmptyHeader("authorization"))
        );
    }

    #[test]
    fn a_request_without_the_credential_header_is_an_error() {
        assert_eq!(
            Layout::identity_request(
                b"GET /2/users/me HTTP/1.1\r\nhost: api.x.com\r\n\r\n"
            ),
            Err(LayoutError::MissingHeader("authorization"))
        );
    }

    /// The revealed bytes, in offset order.
    fn revealed<'a>(l: &Layout, recv: &'a [u8]) -> Vec<&'a [u8]> {
        l.reveal.iter().map(|r| &recv[r.clone()]).collect()
    }

    /// The committed bytes, in offset order.
    fn committed<'a>(l: &Layout, recv: &'a [u8]) -> Vec<&'a [u8]> {
        l.commit.iter().map(|r| &recv[r.clone()]).collect()
    }

    #[test]
    fn the_identity_response_reveals_only_the_anchors() {
        let recv: &[u8] = b"HTTP/1.1 200 OK\r\ncontent-type: application/json\r\n\r\n{\"data\":{\"id\":\"2244994945\",\"name\":\"Al\",\"username\":\"Alice_1\"}}";
        let l = Layout::identity_response(recv, &x_identity()).unwrap();
        assert!(tiles(&l, recv.len()));
        assert_eq!(
            revealed(&l, recv),
            [&b"\"id\":\""[..], b"\"", b"\"username\":\"", b"\""]
        );
        // Each value is its own commitment, exactly as the wire carries it.
        let hidden = committed(&l, recv);
        assert!(hidden.contains(&&b"2244994945"[..]), "{hidden:?}");
        assert!(hidden.contains(&&b"Alice_1"[..]), "{hidden:?}");
    }

    #[test]
    fn an_empty_value_is_refused() {
        // Adjacent anchors commit nothing, and the verifier would find no
        // framed commitment to open.
        let recv: &[u8] =
            b"HTTP/1.1 200 OK\r\n\r\n{\"data\":{\"id\":\"7\",\"username\":\"\"}}";
        assert_eq!(
            Layout::identity_response(recv, &x_identity()),
            Err(LayoutError::EmptyField("username".into()))
        );
    }

    #[test]
    fn the_github_identity_response_reveals_the_id_terminator_and_commits_the_digits() {
        // The bare id closes on a revealed `,` or `}`, which proves the
        // committed digits are the whole number.
        let recv: &[u8] = b"HTTP/1.1 200 OK\r\ncontent-type: application/json\r\n\r\n{\"login\":\"octocat\",\"id\":583231,\"node_id\":\"MDQ=\"}";
        let l = Layout::identity_response(recv, &github_identity()).unwrap();
        assert!(tiles(&l, recv.len()));
        assert_eq!(
            revealed(&l, recv),
            [&b"\"login\":\""[..], b"\"", b"\"id\":", b","]
        );
        let hidden = committed(&l, recv);
        assert!(hidden.contains(&&b"octocat"[..]), "{hidden:?}");
        assert!(hidden.contains(&&b"583231"[..]), "{hidden:?}");
    }

    #[test]
    fn a_github_id_closed_by_a_brace_is_revealed_the_same_way() {
        // JSON member order is not the platform's promise, so the id can be
        // last -- and then `}` closes it instead of `,`. The profile fixes both
        // as acceptable; a layout that only ever produced one would refuse
        // half of GitHub's honest responses.
        let recv: &[u8] = b"HTTP/1.1 200 OK\r\n\r\n{\"login\":\"octocat\",\"id\":583231}";
        let l = Layout::identity_response(recv, &github_identity()).unwrap();
        assert!(tiles(&l, recv.len()));
        assert_eq!(revealed(&l, recv)[2..], [&b"\"id\":"[..], b"}"]);
    }

    #[test]
    fn the_two_profiles_do_not_read_each_other_s_responses() {
        // The point of taking the three arguments as one profile: crossed, they
        // describe a session nobody ran, and that used to be four arguments
        // away. Each direction is refused by the id, where the shapes differ.
        let github: &[u8] =
            b"HTTP/1.1 200 OK\r\n\r\n{\"login\":\"octocat\",\"id\":583231}";
        let x: &[u8] = b"HTTP/1.1 200 OK\r\n\r\n{\"id\":\"7\",\"username\":\"alice\"}";

        // X's shape wants `"id":"`, and GitHub's id is bare: it fails on the id.
        assert_eq!(
            Layout::identity_response(github, &x_identity()),
            Err(LayoutError::MissingField("id".into()))
        );

        // And GitHub's shape wants digits where X puts a quoted string, so it
        // fails on the id as well rather than reaching the handle. It did not
        // always: the bare reader used to stop at the first `,`, which returned
        // `"id":"7",` -- a quoted value read as though it were a number -- and
        // left the mismatch to be caught by the handle name instead.
        assert_eq!(
            Layout::identity_response(x, &github_identity()),
            Err(LayoutError::MissingField("id".into()))
        );
    }

    #[test]
    fn a_response_that_names_the_handle_first_still_reveals_in_offset_order() {
        // The one fixture with the handle first: it exercises the sort in
        // `Layout::revealing`.
        let recv: &[u8] = b"HTTP/1.1 200 OK\r\n\r\n{\"username\":\"alice\",\"id\":\"7\"}";
        let l = Layout::identity_response(recv, &x_identity()).unwrap();
        assert!(tiles(&l, recv.len()));
        assert_eq!(
            revealed(&l, recv),
            [&b"\"username\":\""[..], b"\"", b"\"id\":\"", b"\""]
        );
    }

    #[test]
    fn the_display_name_beside_a_member_stays_committed() {
        // The point of committing the rest: nothing but the anchors around the
        // two values reaches the chain.
        let recv: &[u8] = b"HTTP/1.1 200 OK\r\n\r\n{\"id\":\"7\",\"name\":\"Al\",\"username\":\"alice\"}";
        let l = Layout::identity_response(recv, &x_identity()).unwrap();
        assert!(tiles(&l, recv.len()));
        assert!(!l.commit.is_empty(), "the rest of the response is hidden");
        for r in &l.reveal {
            assert!(
                !recv[r.clone()].windows(2).any(|w| w == b"Al"),
                "the display name is inside a revealed range"
            );
        }
    }

    /// A duplicate member stays committed and undetected; ASM-PROV-06 assumes
    /// the platform never emits one.
    #[test]
    fn a_response_naming_a_member_twice_reveals_only_one() {
        let recv: &[u8] = b"HTTP/1.1 200 OK\r\n\r\n{\"id\":\"7\",\"username\":\"victim\",\"username\":\"alice\"}";
        let l = Layout::identity_response(recv, &x_identity()).unwrap();
        assert!(tiles(&l, recv.len()));
        let revealed: usize = l
            .reveal
            .iter()
            .map(|r| {
                recv[r.clone()]
                    .windows(11)
                    .filter(|w| *w == b"\"username\":")
                    .count()
            })
            .sum();
        assert_eq!(revealed, 1, "the second member is committed, not revealed");
        // And the anchors frame the first one.
        let members = IdentityMembers::in_response(recv, &x_identity()).unwrap();
        assert_eq!(&recv[members.handle.value], b"victim");
    }

    #[test]
    fn a_github_id_s_value_is_the_digits_without_the_whitespace_before_the_comma() {
        // The whitespace before `,` is revealed with the terminator.
        let recv: &[u8] =
            b"HTTP/1.1 200 OK\r\n\r\n{\n  \"login\": \"octocat\",\n  \"id\": 583231 ,\n  \"x\": 1\n}";
        let members = IdentityMembers::in_response(recv, &github_identity()).unwrap();
        assert_eq!(&recv[members.id.value.clone()], b"583231");
        let l = Layout::identity_response(recv, &github_identity()).unwrap();
        assert!(tiles(&l, recv.len()));
        assert!(l.commit.contains(&members.id.value));
        assert!(l
            .reveal
            .contains(&(members.id.value.end..members.id.member.end)));
        assert_eq!(&recv[members.id.value.end..members.id.member.end], b" ,");
    }

    #[test]
    fn a_missing_member_is_an_error() {
        let recv: &[u8] = b"HTTP/1.1 200 OK\r\n\r\n{\"data\":{\"id\":\"7\"}}";
        assert!(matches!(
            Layout::identity_response(recv, &x_identity()),
            Err(LayoutError::MissingField(_))
        ));
    }
}

#[cfg(test)]
mod tables {
    use super::{
        profiles,
        Layout,
    };

    /// The ceremony profiles and the identity system name the same platforms.
    ///
    /// Two generated tables, deliberately: one says how a handle normalizes,
    /// the other says what a session notarizes, and neither belongs inside the
    /// other. libid-contracts keeps them apart the same way and asserts they
    /// agree (`PlatformIdentity.t.sol::test_theTwoTablesAgree`), because a name
    /// bound through one path and read through the other is two keyspaces for
    /// one platform with nothing to make the divergence loud.
    ///
    /// Both crates are generated from libid-contracts, so this is not checking
    /// our transcription -- it is checking that a consumer holding BOTH at
    /// versions it chose independently holds one keyspace. They are separate
    /// crates with separate version requirements, and a lockfile can pin a pair
    /// that never shipped together.
    #[test]
    fn the_two_tables_name_the_same_platforms() {
        use libid_identity::handle_vectors::{
            PLATFORM_GITHUB_DOMAIN,
            PLATFORM_GOOGLE_DOMAIN,
            PLATFORM_X_DOMAIN,
        };

        assert_eq!(profiles::X.platform, PLATFORM_X_DOMAIN);
        assert_eq!(profiles::GITHUB.platform, PLATFORM_GITHUB_DOMAIN);
        assert_eq!(profiles::GOOGLE.platform, PLATFORM_GOOGLE_DOMAIN);
    }

    #[test]
    fn github_pretty_prints_and_the_layout_carries_the_whitespace() {
        // The response GitHub serves for the profile's media type, and the
        // two members the profile reads out of it, revealed as the wire
        // carries them -- whitespace inside, at its offsets.
        let body =
            "{\n  \"login\": \"octocat\",\n  \"id\": 583231,\n  \"node_id\": \"x\"\n}";
        let recv = format!(
            "HTTP/1.1 200 OK\r\ncontent-type: application/json; charset=utf-8\r\ncontent-length: {}\r\n\r\n{body}",
            body.len()
        );
        let layout = Layout::identity_response(
            recv.as_bytes(),
            &profiles::GITHUB.identity.unwrap(),
        )
        .unwrap();
        let revealed: Vec<&[u8]> = layout
            .reveal
            .iter()
            .map(|range| &recv.as_bytes()[range.clone()])
            .collect();
        assert_eq!(
            revealed,
            [&b"\"login\": \""[..], b"\"", b"\"id\": ", b","],
            "the anchors carry the whitespace at its offsets"
        );
    }
}
