//! The stitch between choosing a layout and what the verifier demands of it.
//!
//! Drives `ceremony` layouts through `attest` and asserts, on the decoded
//! record, the rules the Solidity side enforces. No TLS or MPC: sessions are
//! reproduced from the layouts with tlsn's own commitment hashes. Each
//! assertion names the check it mirrors.

#[path = "../examples/ceremony/common.rs"]
mod common;
#[path = "../examples/ceremony/witness.rs"]
mod witness;

use common::hex0x;
use libid_tlsn::{
    attest::{
        FromObserved,
        ObservedSession,
    },
    CommitmentOpening,
};
use libid_transcript::{
    attestation::{
        AttestedData,
        DirectionBlock,
        RangeCommitment,
    },
    ceremony::{
        profiles,
        Layout,
    },
};
use rangeset::set::RangeSet;
use tlsn::{
    hash::{
        Blinder,
        Sha256,
    },
    transcript::{
        hash::{
            hash_plaintext,
            PlaintextHash,
        },
        Direction,
        Transcript,
        TranscriptCommitment,
    },
};
use witness::{
    identity_link_witness,
    Held,
};

/// The server name each session's profile pins: the record's authority.
const X_TOKEN_HOST: &str = profiles::X.token.unwrap().session.authority;
const X_ID_HOST: &str = profiles::X.identity.unwrap().session.authority;
const GITHUB_TOKEN_HOST: &str = profiles::GITHUB.token.unwrap().session.authority;
const GITHUB_ID_HOST: &str = profiles::GITHUB.identity.unwrap().session.authority;

const TOKEN_SENT: &[u8] = b"POST /2/oauth2/token HTTP/1.1\r\nhost: api.x.com\r\n\r\ngrant_type=authorization_code&client_id=abc&code_verifier=5teBDl6cz4U77aFweV5PbMhBJ_lEFv6LLNKzqnDI5lo";
const TOKEN_RECV: &[u8] =
    b"HTTP/1.1 200 OK\r\n\r\n{\"token_type\":\"bearer\",\"access_token\":\"SECRETBEARER\"}";
const ID_SENT: &[u8] = b"GET /2/users/me HTTP/1.1\r\nhost: api.x.com\r\nauthorization: Bearer SECRETBEARER\r\nconnection: close\r\n\r\n";
const ID_RECV: &[u8] = b"HTTP/1.1 200 OK\r\n\r\n{\"data\":{\"id\":\"2244994945\",\"name\":\"Al\",\"username\":\"Alice_1\"}}";

/// GitHub's token exchange and `/user` read, pretty-printed as GitHub serves
/// it: whitespace after each colon, and before the `,` closing the id.
const GITHUB_TOKEN_SENT: &[u8] = b"POST /login/oauth/access_token HTTP/1.1\r\nhost: github.com\r\n\r\nclient_id=Iv1.x&code=abc&code_verifier=xyz&client_secret=deadbeef";
const GITHUB_TOKEN_RECV: &[u8] =
    b"HTTP/1.1 200 OK\r\n\r\n{\"access_token\":\"gho_SECRETBEARER\",\"token_type\":\"bearer\",\"scope\":\"\"}";
const GITHUB_ID_SENT: &[u8] = b"GET /user HTTP/1.1\r\nhost: api.github.com\r\nauthorization: Bearer gho_SECRETBEARER\r\nconnection: close\r\n\r\n";
const GITHUB_ID_RECV: &[u8] = b"HTTP/1.1 200 OK\r\n\r\n{\n  \"login\": \"OctoCat\",\n  \"id\": 583231 ,\n  \"node_id\": \"MDQ6VXNlcjU4MzIzMQ==\",\n  \"plan\": \"pro\"\n}";

/// A distinct, fixed tlsn blinder per commitment, so the records reproduce.
fn blinder(direction: Direction, index: usize) -> Blinder {
    let tag = match direction {
        Direction::Sent => 0x50,
        Direction::Received => 0xA0,
    };
    let bytes: Vec<u8> = (0..16u8)
        .map(|i| tag ^ (index as u8) ^ i.wrapping_mul(17))
        .collect();
    serde_json::from_value(serde_json::json!(bytes)).expect("a 16-byte blinder")
}

/// A pair of layouts as the session MPC would leave: the transcript, the
/// prover's openings, and the record built from the [`ObservedSession`].
fn record(
    sent: &[u8],
    recv: &[u8],
    sl: &Layout,
    rl: &Layout,
    authority: &str,
    created_at: u64,
) -> Held {
    let transcript = Transcript::new(sent, recv);
    let partial = transcript.to_partial(
        RangeSet::from(sl.reveal.clone()),
        RangeSet::from(rl.reveal.clone()),
    );

    let hasher = Sha256::default();
    let mut openings = Vec::new();
    let mut commitments = Vec::new();
    for (direction, bytes, commit) in [
        (Direction::Sent, sent, &sl.commit),
        (Direction::Received, recv, &rl.commit),
    ] {
        for (i, c) in commit.iter().enumerate() {
            let blinder = blinder(direction, i);
            commitments.push(TranscriptCommitment::Hash(PlaintextHash {
                direction,
                idx: RangeSet::from(c.clone()),
                hash: hash_plaintext(&hasher, &bytes[c.clone()], &blinder),
            }));
            openings.push(CommitmentOpening {
                direction,
                ranges: vec![c.clone()],
                blinder: blinder.as_bytes().to_vec(),
            });
        }
    }

    let record = AttestedData::from_observed(ObservedSession {
        transcript: &partial,
        authority,
        commitments: &commitments,
        created_at,
    })
    .expect("the layouts produce an attestable session");
    Held {
        sent: sent.to_vec(),
        recv: recv.to_vec(),
        openings,
        record,
    }
}

/// `CeremonyAttestation.requireExactCoverage`: revealed ranges and commitments
/// account for `[0, length)` with no gap and no overlap.
fn assert_tiles(block: &DirectionBlock, length: u32, what: &str) {
    let mut spans: Vec<(u32, u32)> = block
        .revealed
        .iter()
        .map(|r| (r.start, r.start + r.bytes.len() as u32))
        .chain(block.commitments.iter().map(|c| (c.start, c.end)))
        .collect();
    spans.sort_by_key(|s| s.0);
    let mut at = 0u32;
    for (start, end) in spans {
        assert_eq!(start, at, "{what}: gap or overlap at {at}");
        assert!(end > start, "{what}: empty span at {start}");
        at = end;
    }
    assert_eq!(
        at, length,
        "{what}: coverage stops short of the signed length"
    );
}

/// The revealed bytes of one direction, joined in offset order — what the
/// verifier's cross-range delimiter count reads.
fn joined(block: &DirectionBlock) -> Vec<u8> {
    let mut ranges: Vec<_> = block.revealed.iter().collect();
    ranges.sort_by_key(|r| r.start);
    ranges.iter().flat_map(|r| r.bytes.clone()).collect()
}

fn count(haystack: &[u8], needle: &[u8]) -> usize {
    haystack
        .windows(needle.len())
        .filter(|w| *w == needle)
        .count()
}

/// `CeremonyFields.normalizeJsonBytes`: each run of JSON whitespace goes when
/// the last byte kept before it, or the byte after it, is `:` `,` `{` `}` `[`
/// or `]`; any other run stays.
fn normalized(bytes: &[u8]) -> Vec<u8> {
    let structural = |b: &u8| b":,{}[]".contains(b);
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        let run = bytes[i..]
            .iter()
            .take_while(|b| b" \t\n\r".contains(b))
            .count();
        let k = i + run.max(1);
        if run == 0
            || !(out.last().is_some_and(structural)
                || bytes.get(k).is_some_and(structural))
        {
            out.extend_from_slice(&bytes[i..k]);
        }
        i = k;
    }
    out
}

/// `CeremonyFields.t.sol`'s vectors: a run beside a structural byte goes, a
/// run between two tokens stays.
#[test]
fn normalization_is_the_contract_s() {
    let body = b"{\n  \"login\" \t: \"alice\",\r\n  \"id\" : 123 \n}";
    assert_eq!(normalized(body), br#"{"login":"alice","id":123}"#);
    assert_eq!(normalized(b"{\"id\":123 4}"), b"{\"id\":123 4}");
}

/// The commitments `CeremonyAttestation._anchoredBy` accepts for `prefix`: a
/// revealed range ends where the commitment starts, and ends, normalized, with
/// `prefix`.
fn anchored<'a>(block: &'a DirectionBlock, prefix: &[u8]) -> Vec<&'a RangeCommitment> {
    block
        .commitments
        .iter()
        .filter(|c| {
            block.revealed.iter().any(|r| {
                r.start + r.bytes.len() as u32 == c.start
                    && normalized(&r.bytes).ends_with(prefix)
            })
        })
        .collect()
}

/// The revealed range starting at `at`, if one does.
fn revealed_at(block: &DirectionBlock, at: u32) -> Option<&[u8]> {
    block
        .revealed
        .iter()
        .find(|r| r.start == at)
        .map(|r| r.bytes.as_slice())
}

/// The prefix once across the revealed bytes, and exactly one commitment it
/// anchors whose next revealed range `closes` accepts:
/// `CeremonyAttestation.requireFramedCommitment` with [`quote`],
/// `requireFramedInteger` with [`terminator`].
fn framed<'a>(
    block: &'a DirectionBlock,
    prefix: &[u8],
    closes: fn(&[u8]) -> bool,
) -> &'a RangeCommitment {
    assert_eq!(
        count(&normalized(&joined(block)), prefix),
        1,
        "AmbiguousFraming"
    );
    let framed: Vec<_> = anchored(block, prefix)
        .into_iter()
        .filter(|c| revealed_at(block, c.end).is_some_and(closes))
        .collect();
    let [framed] = framed.as_slice() else {
        panic!("{} commitments framed, not one", framed.len());
    };
    framed
}

/// A string value closes on its quote.
fn quote(next: &[u8]) -> bool {
    next.starts_with(b"\"")
}

/// A bare integer closes on `,` or `}`, past JSON whitespace
/// (`_terminatedAt`).
fn terminator(next: &[u8]) -> bool {
    matches!(
        next.iter()
            .find(|b| !matches!(b, b' ' | b'\t' | b'\n' | b'\r')),
        Some(b',' | b'}')
    )
}

/// `CeremonyAttestation.requireBearerHeaderRequest`'s framing: exactly one
/// commitment, a revealed range ending in the bearer prefix where it starts,
/// and one starting with CRLF where it ends.
fn framed_bearer(block: &DirectionBlock) -> &RangeCommitment {
    let [bearer] = block.commitments.as_slice() else {
        panic!(
            "NotOneCommitment: {} commitments in the identity request",
            block.commitments.len()
        );
    };
    let before = block
        .revealed
        .iter()
        .find(|r| r.start + r.bytes.len() as u32 == bearer.start)
        .expect("a revealed range ends where the commitment begins");
    // The contract's `BEARER_PREFIX`, spelled out rather than taken from the
    // crate under test.
    assert!(
        before.bytes.ends_with(b"\r\nauthorization: Bearer "),
        "BadBearerFraming"
    );
    let after = revealed_at(block, bearer.end)
        .expect("a revealed range begins where the commitment ends");
    assert!(after.starts_with(b"\r\n"), "BadBearerFraming");
    bearer
}

/// The bytes a commitment covers, from the full transcript.
fn covered<'a>(recv: &'a [u8], c: &RangeCommitment) -> &'a [u8] {
    &recv[c.start as usize..c.end as usize]
}

#[test]
fn the_token_session_produces_a_record_the_verifier_accepts() {
    let sl = Layout::token_request(TOKEN_SENT).unwrap();
    let rl = Layout::token_response(TOKEN_RECV).unwrap();
    let data = record(
        TOKEN_SENT,
        TOKEN_RECV,
        &sl,
        &rl,
        X_TOKEN_HOST,
        1_770_000_000,
    )
    .record;

    assert_tiles(&data.sent, data.sent_transcript_length, "token request");
    assert_tiles(
        &data.received,
        data.recv_transcript_length,
        "token response",
    );

    // `_tokenBody`: ONE revealed sent range, anchored at the origin. Every
    // token request is revealed whole.
    assert_eq!(data.sent.revealed.len(), 1);
    assert_eq!(data.sent.revealed[0].start, 0);
    assert!(data.sent.commitments.is_empty());
    assert!(data.sent.revealed[0]
        .bytes
        .starts_with(b"POST /2/oauth2/token "));

    // `_tokenBody` again: exactly one head boundary, or the body is ambiguous.
    assert_eq!(count(&data.sent.revealed[0].bytes, b"\r\n\r\n"), 1);

    // REQ-COMMON-15A: the digest binding is the revealed `code_verifier`.
    assert_eq!(count(&data.sent.revealed[0].bytes, b"code_verifier="), 1);

    // `requireFramedCommitment`: exactly one commitment is framed as the
    // bearer, it covers exactly the bearer, and the bearer is not readable
    // anywhere.
    let bearer = framed(&data.received, b"\"access_token\":\"", quote);
    assert_eq!(covered(TOKEN_RECV, bearer), b"SECRETBEARER");
    assert_eq!(count(&joined(&data.received), b"SECRETBEARER"), 0);
}

#[test]
fn the_identity_session_produces_a_record_the_verifier_accepts() {
    let sl = Layout::identity_request(ID_SENT).unwrap();
    let rl = Layout::identity_response(ID_RECV, &profiles::X.identity.unwrap()).unwrap();
    let data = record(ID_SENT, ID_RECV, &sl, &rl, X_ID_HOST, 1_770_000_000).record;

    assert_tiles(&data.sent, data.sent_transcript_length, "identity request");
    assert_tiles(
        &data.received,
        data.recv_transcript_length,
        "identity response",
    );

    // `_identitySession`: the request line sits at offset 0.
    let first = data.sent.revealed.iter().min_by_key(|r| r.start).unwrap();
    assert_eq!(first.start, 0);
    assert!(first.bytes.starts_with(b"GET /2/users/me "));

    // `requireBearerHeaderRequest`: exactly one commitment, framed by the
    // header bytes REQ-COMMON-40 names.
    let bearer = framed_bearer(&data.sent);
    assert_eq!(covered(ID_SENT, bearer), b"SECRETBEARER");

    // REQ-COMMON-39, counted over the CONCATENATION: one authorization header.
    let mut normalized = joined(&data.sent).to_ascii_lowercase();
    normalized.retain(|&b| b != b' ' && b != b'\t');
    assert_eq!(count(&normalized, b"\r\nauthorization:bearer"), 1);

    // `requireExactCoverage`: the response is tiled, and what it does not
    // reveal it commits -- so the account metadata beside the two members never
    // reaches the chain.
    assert!(
        !data.received.commitments.is_empty(),
        "the rest of the response must be committed, not published"
    );

    // The verifier reads each member's anchor once, and neither value.
    let body = joined(&data.received);
    assert_eq!(count(&body, b"\"id\":\""), 1);
    assert_eq!(count(&body, b"\"username\":\""), 1);
    assert_eq!(count(&body, b"2244994945"), 0, "the id is committed");
    assert_eq!(count(&body, b"Alice_1"), 0, "the handle is committed");
    assert!(
        !body.windows(2).any(|w| w == b"Al"),
        "the display name must stay behind a commitment"
    );

    // `requireFramedCommitment`: each value is exactly one committed range,
    // framed by its revealed anchors, and covers exactly the value.
    let id = framed(&data.received, b"\"id\":\"", quote);
    let handle = framed(&data.received, b"\"username\":\"", quote);
    assert_eq!(covered(ID_RECV, id), b"2244994945");
    assert_eq!(covered(ID_RECV, handle), b"Alice_1");
}

/// `SHA256(value || blinder)`, with the `sha2` crate rather than tlsn's
/// hasher.
fn sha256(value: &[u8], blinder: &[u8]) -> [u8; 32] {
    use sha2::Digest as _;
    sha2::Sha256::new()
        .chain_update(value)
        .chain_update(blinder)
        .finalize()
        .into()
}

/// The witness the identity-link circuit opens, built from the prover's
/// openings, against the commitments the verifier's record carries.
fn assert_the_witness_opens_the_record(
    profile: &profiles::Profile,
    token: &Held,
    identity: &Held,
) {
    let witness = identity_link_witness(profile, token, identity)
        .expect("the witness opens the record");
    assert_eq!(witness["platform"], profile.platform);

    // Each value opens the commitment the verifier's rules select, recomputed
    // with `sha2` independently of the builder.
    let session = profile.identity.unwrap();
    let id = match session.id_shape {
        profiles::IdShape::JsonString => framed(
            &identity.record.received,
            format!("\"{}\":\"", session.id_field).as_bytes(),
            quote,
        ),
        profiles::IdShape::JsonInteger => framed(
            &identity.record.received,
            format!("\"{}\":", session.id_field).as_bytes(),
            terminator,
        ),
    };
    let handle = framed(
        &identity.record.received,
        format!("\"{}\":\"", session.handle_field).as_bytes(),
        quote,
    );
    for (name, bytes, framed) in [
        (
            "token_bearer",
            &token.recv,
            framed(&token.record.received, b"\"access_token\":\"", quote),
        ),
        (
            "identity_bearer",
            &identity.sent,
            framed_bearer(&identity.record.sent),
        ),
        ("id", &identity.recv, id),
        ("handle", &identity.recv, handle),
    ] {
        let opened = &witness[name];
        assert_eq!(opened["commitment"], hex0x(&framed.commitment), "{name}");
        let value = covered(bytes, framed);
        assert_eq!(
            opened["value"].as_str().unwrap().as_bytes(),
            value,
            "{name}"
        );
        let blinder = opened["blinder"].as_str().unwrap();
        let blinder = hex::decode(blinder.strip_prefix("0x").unwrap()).unwrap();
        assert_eq!(blinder.len(), 16, "{name}: the blinder is 16 bytes");
        assert_eq!(sha256(value, &blinder), framed.commitment, "{name}");
    }
}

#[test]
fn the_identity_link_witness_opens_the_records() {
    let x_token = record(
        TOKEN_SENT,
        TOKEN_RECV,
        &Layout::token_request(TOKEN_SENT).unwrap(),
        &Layout::token_response(TOKEN_RECV).unwrap(),
        X_TOKEN_HOST,
        1_770_000_000,
    );
    let x_identity = record(
        ID_SENT,
        ID_RECV,
        &Layout::identity_request(ID_SENT).unwrap(),
        &Layout::identity_response(ID_RECV, &profiles::X.identity.unwrap()).unwrap(),
        X_ID_HOST,
        1_770_000_000,
    );
    assert_the_witness_opens_the_record(&profiles::X, &x_token, &x_identity);

    let github_token = record(
        GITHUB_TOKEN_SENT,
        GITHUB_TOKEN_RECV,
        &Layout::token_request(GITHUB_TOKEN_SENT).unwrap(),
        &Layout::token_response(GITHUB_TOKEN_RECV).unwrap(),
        GITHUB_TOKEN_HOST,
        1_770_000_000,
    );
    let github_identity = record(
        GITHUB_ID_SENT,
        GITHUB_ID_RECV,
        &Layout::identity_request(GITHUB_ID_SENT).unwrap(),
        &Layout::identity_response(GITHUB_ID_RECV, &profiles::GITHUB.identity.unwrap())
            .unwrap(),
        GITHUB_ID_HOST,
        1_770_000_000,
    );
    assert_the_witness_opens_the_record(
        &profiles::GITHUB,
        &github_token,
        &github_identity,
    );

    // GitHub's bare id: the commitment is the digits alone, closed by a
    // revealed ` ,`, and nothing else of the account is revealed.
    let received = &github_identity.record.received;
    assert_tiles(
        received,
        github_identity.record.recv_transcript_length,
        "github identity response",
    );
    let body = joined(received);
    for hidden in [&b"583231"[..], b"OctoCat", b"MDQ6", b"pro"] {
        assert_eq!(count(&body, hidden), 0, "{hidden:?} is committed");
    }
    let id = framed(received, b"\"id\":", terminator);
    assert_eq!(revealed_at(received, id.end), Some(&b" ,"[..]));
}

/// The record has to survive the wire, not merely exist: the encoding is what
/// the notary signs and what the Solidity decoder reads.
#[test]
fn both_sessions_encode_and_carry_their_own_lengths() {
    for (sent, recv, sl, rl, authority) in [
        (
            TOKEN_SENT,
            TOKEN_RECV,
            Layout::token_request(TOKEN_SENT).unwrap(),
            Layout::token_response(TOKEN_RECV).unwrap(),
            X_TOKEN_HOST,
        ),
        (
            ID_SENT,
            ID_RECV,
            Layout::identity_request(ID_SENT).unwrap(),
            Layout::identity_response(ID_RECV, &profiles::X.identity.unwrap()).unwrap(),
            X_ID_HOST,
        ),
    ] {
        let data = record(sent, recv, &sl, &rl, authority, 1_770_000_000).record;
        assert_eq!(data.sent_transcript_length as usize, sent.len());
        assert_eq!(data.recv_transcript_length as usize, recv.len());
        let encoded = data.encode().expect("encodes");
        assert!(encoded.len() > 48, "at least the header");
        assert_ne!(data.digest().unwrap(), [0u8; 32]);
    }
}

/// The GitHub token exchange reveals its request whole, `client_secret`
/// included: it is a public credential the verifier reads.
#[test]
fn the_github_exchange_is_revealed_whole() {
    const SENT: &[u8] = b"POST /login/oauth/access_token HTTP/1.1\r\nhost: github.com\r\n\r\nclient_id=Iv1.x&code=abc&code_verifier=xyz&client_secret=deadbeef";
    const RECV: &[u8] =
        b"HTTP/1.1 200 OK\r\n\r\n{\"token_type\":\"bearer\",\"access_token\":\"SECRETBEARER\"}";

    let sl = Layout::token_request(SENT).unwrap();
    let rl = Layout::token_response(RECV).unwrap();
    let data = record(SENT, RECV, &sl, &rl, GITHUB_TOKEN_HOST, 1_770_000_000).record;

    assert_tiles(&data.sent, data.sent_transcript_length, "github exchange");
    assert_eq!(data.sent.revealed.len(), 1);
    assert_eq!(data.sent.revealed[0].start, 0);
    assert_eq!(data.sent.revealed[0].bytes.len(), SENT.len());
    assert!(data.sent.commitments.is_empty());
    assert_eq!(count(&joined(&data.sent), b"deadbeef"), 1);
}
