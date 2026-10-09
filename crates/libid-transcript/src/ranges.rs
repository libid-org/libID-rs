//! TLS transcript parsing and byte-range helpers for selective disclosure.
//!
//! All functions operate on raw transcript bytes (`sent` / `recv`) and return
//! `Range<usize>` offsets into them. The attested record carries the revealed
//! slices at those offsets and a commitment over each hidden run, and a
//! Platform Verifier reads the revealed bytes and locates each committed value
//! by the revealed anchors around it -- so every helper here
//! fails closed: a range that cannot be located contiguously in the RAW
//! transcript, such as a member split across a chunk boundary, yields `None`
//! rather than a range pointing at bytes nobody sent.

use std::ops::Range;

use crate::{
    Error,
    Result,
};

/// Find the byte range of an HTTP header value in raw TLS data.
pub fn find_header_range(data: &[u8], name: &str) -> Option<Range<usize>> {
    let needle = format!("\r\n{}: ", name);
    let needle_bytes = needle.as_bytes();
    let start = data
        .windows(needle_bytes.len())
        .position(|w| w.eq_ignore_ascii_case(needle_bytes))?;
    let value_start = start.checked_add(needle_bytes.len())?;
    let value_end = data
        .get(value_start..)?
        .windows(2)
        .position(|w| w == b"\r\n")
        .and_then(|pos| value_start.checked_add(pos))?;
    Some(value_start..value_end)
}

/// Extract an HTTP header value from raw TLS data.
pub fn extract_header(data: &[u8], name: &str) -> Option<String> {
    find_header_range(data, name)
        .map(|range| String::from_utf8_lossy(&data[range]).to_string())
}

/// Find the byte range of the HTTP request line in sent data.
pub fn find_request_line_range(sent: &[u8]) -> Range<usize> {
    let end = sent
        .windows(2)
        .position(|w| w == b"\r\n")
        .unwrap_or(sent.len());
    0..end
}

/// Find the byte range of the HTTP response body in received data.
pub fn find_response_body_range(recv: &[u8]) -> Option<Range<usize>> {
    let marker = b"\r\n\r\n";
    recv.windows(marker.len())
        .position(|w| w == marker)
        .and_then(|pos| pos.checked_add(marker.len()))
        .map(|body_start| body_start..recv.len())
}

/// Extract and decode the HTTP response body from received TLS data.
///
/// Handles both chunked and non-chunked transfer encodings.
pub fn extract_response_body(recv: &[u8]) -> Result<Vec<u8>> {
    let range = find_response_body_range(recv).ok_or_else(|| Error::Transcript {
        detail: "no response body found".into(),
    })?;
    let raw_body = &recv[range];

    if let Some(te) = extract_header(recv, "Transfer-Encoding") {
        if te.contains("chunked") {
            return decode_chunked_body(raw_body);
        }
    }

    Ok(raw_body.to_vec())
}

/// Join a chunked body's chunks.
///
/// Every malformed input is an error rather than a shorter body. The reveal
/// ranges are computed over what this returns, so a silent truncation would
/// have the prover select ranges over bytes the server never sent -- and the
/// notary would sign that selection without anyone noticing.
fn decode_chunked_body(raw: &[u8]) -> Result<Vec<u8>> {
    let bad = |detail: &str| Error::Transcript {
        detail: format!("chunked body: {detail}"),
    };

    let mut out = Vec::new();
    let mut rest = raw;
    loop {
        let (header_len, size) = match httparse::parse_chunk_size(rest) {
            Ok(httparse::Status::Complete(v)) => v,
            Ok(httparse::Status::Partial) => {
                return Err(bad("ends inside a chunk header"))
            }
            Err(_) => return Err(bad("chunk size is not hexadecimal")),
        };
        if size == 0 {
            return Ok(out);
        }
        let size =
            usize::try_from(size).map_err(|_| bad("chunk larger than this machine"))?;
        let body_end = header_len
            .checked_add(size)
            .ok_or_else(|| bad("chunk length overflows"))?;
        let chunk = rest
            .get(header_len..body_end)
            .ok_or_else(|| bad("chunk is shorter than its declared size"))?;
        out.extend_from_slice(chunk);

        // The CRLF that closes a chunk. Its absence means the framing is not
        // what it claims, and the next size would be read from the wrong place.
        let after = rest
            .get(body_end..body_end + 2)
            .ok_or_else(|| bad("ends before a chunk terminator"))?;
        if after != b"\r\n" {
            return Err(bad("chunk is not terminated by CRLF"));
        }
        rest = &rest[body_end + 2..];
    }
}

/// A `"field":"value"` member, and the value inside it.
///
/// Two ranges rather than one because a caller that reveals the delimiters and
/// commits the value needs both boundaries, and deriving the inner one from the
/// outer one means restating the template -- which is a second place to change
/// the field name and one place to forget.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JsonMember {
    /// The whole member, both delimiters included.
    pub member: Range<usize>,
    /// The value alone, between the quotes. Empty when the value is `""`.
    pub value: Range<usize>,
}

impl JsonMember {
    /// The member named `field` in `body`, with offsets INTO `body`.
    ///
    /// Raw bytes in, raw offsets out: this scans whatever it is handed, so a
    /// caller passing a whole HTTP response gets whichever match comes first --
    /// a header's, if a header carries the delimiter. [`JsonMember::in_response`]
    /// is the one that locates the body first, and is what a caller building a
    /// reveal layout wants.
    ///
    /// # The template is the reader's
    ///
    /// The reader is `CeremonyAttestation.requireFramedCommitment` in
    /// libid-contracts. It finds the value as the commitment whose preceding
    /// revealed range, JSON whitespace beside a structural byte removed
    /// (`_anchoredBy`), ends with the literal `"<name>":"`, and whose next
    /// revealed byte is the closing `"`. So this accepts exactly what that
    /// removal maps onto the literal -- whitespace between the key and the
    /// colon, and between the colon and the value -- and nothing else. Anything
    /// looser picks a range the reader cannot frame: a body written
    /// `"login" "octocat"`, no colon, would be laid out here and then met with
    /// `NoFramedCommitment` on chain, which is the same refusal reported where
    /// nobody can see why. Failing here fails it where the reason is visible.
    ///
    /// Uniqueness is NOT checked here, and that is deliberate. The reader
    /// refuses a prefix occurring twice in the bytes it was shown
    /// (`AmbiguousFraming`), and which bytes those are is exactly what a layout
    /// decides -- so `identity_response` reveals one member's anchors and
    /// commits the rest, and the reader sees one. Refusing a second occurrence
    /// here would only stop an honest prover from building that layout; a
    /// dishonest one does not run this code at all.
    fn in_body(body: &[u8], field: &str) -> Option<Self> {
        // The key, then `:`, then the value's opening quote, with the
        // whitespace JSON allows on either side of the colon kept inside the
        // member -- [`key_and_value`] says why.
        let (start, quote) = key_and_value(body, field, true)?;
        let value = quote.checked_add(1)?;
        let close = body
            .get(value..)?
            .iter()
            .position(|&b| b == b'"')?
            .checked_add(value)?;
        Some(Self {
            // From the opening `"` of the key through the closing `"` of the value.
            member: start..close.checked_add(1)?,
            value: value..close,
        })
    }

    /// The member named `field_name` in an HTTP response, with offsets into the
    /// RAW `recv` transcript.
    ///
    /// For a caller that reveals a member's delimiters and commits what sits
    /// between them: both boundaries come from the scan that found them, so no
    /// caller restates the template to recover one.
    ///
    /// The offsets are the whole difference from `in_body`, and the reason the
    /// two are named apart. A reveal layout selects ranges of the TRANSCRIPT, so a
    /// body-relative range handed to one selects bytes somewhere up in the
    /// response headers -- a range that is well formed, signed, and pointing at
    /// the wrong thing.
    pub fn in_response(recv: &[u8], field_name: &str) -> Option<Self> {
        Self::locate(recv, field_name, Self::in_body)
    }

    /// The two runs a layout reveals around a committed value: the member's
    /// opening through the byte before the value, and the byte after the value
    /// through the member's close.
    pub(crate) fn anchors(&self) -> [Range<usize>; 2] {
        [
            self.member.start..self.value.start,
            self.value.end..self.member.end,
        ]
    }

    /// The bare (unquoted) integer member named `field` in `body`: `member`
    /// runs from the key's opening `"` through the `,` or `}` that closes the
    /// number, and `value` is the digits alone.
    ///
    /// Digits, then the byte that closes them -- the order
    /// `CeremonyAttestation.requireFramedInteger` frames them in: `"<name>":`
    /// revealed before the committed digits, and a revealed range starting
    /// where they end whose first byte past JSON whitespace is `,` or `}`
    /// (`_terminatedAt`). Scanning instead to the first `,` or `}` would accept
    /// `"id":"7",`, a quoted value returned as though it were a number.
    fn bare_in_body(body: &[u8], field: &str) -> Option<Self> {
        let (start, digits) = key_and_value(body, field, false)?;
        let rest = body.get(digits..)?;
        let width = rest.iter().take_while(|b| b.is_ascii_digit()).count();
        if width == 0 {
            return None;
        }
        // A leading zero is noncanonical, and `0` alone is not a leading zero.
        if width > 1 && rest[0] == b'0' {
            return None;
        }
        let end = digits.checked_add(width)?;

        // The terminator closes the member: it is what proves the digits are
        // the whole number rather than a prefix of a longer one, and the
        // profile fixes it as `,` or `}` and no other byte (REQ-PLAT-51). JSON
        // whitespace may sit before it.
        let term = skip_json_whitespace(body, end);
        match body.get(term) {
            Some(b',') | Some(b'}') => Some(Self {
                member: start..term.checked_add(1)?,
                value: digits..end,
            }),
            _ => None,
        }
    }

    /// [`JsonMember::bare_in_body`] over a whole response, with offsets into
    /// `recv` -- located and checked the way [`JsonMember::in_response`] is.
    pub fn bare_in_response(recv: &[u8], field_name: &str) -> Option<Self> {
        Self::locate(recv, field_name, Self::bare_in_body)
    }

    /// `scan` over the response body of `recv`, with offsets into `recv`.
    ///
    /// Found in both bodies: the decoded body says the member exists, the raw
    /// body says where it sits, and the two must hold the same bytes.
    fn locate(
        recv: &[u8],
        field_name: &str,
        scan: fn(&[u8], &str) -> Option<Self>,
    ) -> Option<Self> {
        let body_range = find_response_body_range(recv)?;
        let raw_body = &recv[body_range.clone()];
        let decoded_body = extract_response_body(recv).ok()?;

        let decoded = scan(&decoded_body, field_name)?;
        let raw = scan(raw_body, field_name)?;
        require_contiguous(
            raw_body.get(raw.member.clone())?,
            decoded_body.get(decoded.member)?,
        )?;

        let at = |offset: usize| body_range.start.checked_add(offset);
        Some(Self {
            member: at(raw.member.start)?..at(raw.member.end)?,
            value: at(raw.value.start)?..at(raw.value.end)?,
        })
    }
}

/// The first occurrence of `needle`, or nothing.
pub(crate) fn find_first(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// The offset past the run of JSON whitespace starting at `at`, or `at`.
fn skip_json_whitespace(body: &[u8], mut at: usize) -> usize {
    while let Some(b' ' | b'\t' | b'\n' | b'\r') = body.get(at) {
        at += 1;
    }
    at
}

/// The first `"field"` in `body` that a colon follows, as the offset of the
/// key's opening quote and the offset of the value's first byte -- past the
/// whitespace JSON allows on either side of the colon (RFC 8259 section 2),
/// and, when `quoted`, only where that byte is the value's opening quote.
///
/// A `"login"` that is another member's value, or a key of another shape, is
/// passed over. GitHub pretty-prints its identity response, so a template
/// without the whitespace allowance matches nothing it serves. The whitespace
/// stays inside the member a caller cuts from these offsets: the verifier
/// reads the range as the wire carried it and removes that whitespace itself
/// before it compares, so the range has to carry it.
fn key_and_value(body: &[u8], field: &str, quoted: bool) -> Option<(usize, usize)> {
    let key = format!("\"{field}\"");
    let mut from = 0;
    loop {
        let start = find_first(body.get(from..)?, key.as_bytes())?.checked_add(from)?;
        let colon = skip_json_whitespace(body, start.checked_add(key.len())?);
        if body.get(colon) == Some(&b':') {
            let value = skip_json_whitespace(body, colon.checked_add(1)?);
            if !quoted || body.get(value) == Some(&b'"') {
                return Some((start, value));
            }
        }
        from = start.checked_add(1)?;
    }
}

/// The raw bytes are the member, and not the member with framing through it.
///
/// A chunked body carries `\r\n<size>\r\n` between chunks, and that framing
/// holds no quote, comma or brace -- so a member split across a boundary is
/// found in the decoded body AND in the raw one, and the raw range silently
/// spans the framing. What that range selects is not the member: revealed, it
/// puts framing inside the handle a verifier reads; committed, it puts framing
/// inside the bearer a circuit opens against the clean value the caller was
/// handed. Re-framing cannot repair it, because a commitment covers one
/// contiguous run and this member is two.
///
/// So the session is refused here, where the reason is a decodable body rather
/// than an unopenable commitment three components later.
fn require_contiguous(raw: &[u8], decoded: &[u8]) -> Option<()> {
    (raw == decoded).then_some(())
}

#[cfg(test)]
mod tests {
    /// A chunk header that is not a hex size used to end the body silently:
    /// the size parsed as `unwrap_or(0)`, the loop hit `break`, and the caller
    /// got a short body with no error. The reveal ranges are computed from
    /// that body, so the prover would select them over bytes the server never
    /// sent -- and never learn.
    #[test]
    fn a_malformed_chunk_size_is_an_error_not_a_short_body() {
        let recv = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n\
5\r\nhello\r\nzz\r\nworld\r\n0\r\n\r\n";
        assert!(super::extract_response_body(recv).is_err());
    }

    #[test]
    fn a_truncated_chunk_is_an_error_too() {
        // The size says 20 bytes and 5 follow.
        let recv = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n\
14\r\nhello";
        assert!(super::extract_response_body(recv).is_err());
    }

    use super::*;

    /// The member range [`JsonMember`] finds in a bare body.
    fn member(body: &[u8], field: &str) -> Option<Range<usize>> {
        JsonMember::in_body(body, field).map(|m| m.member)
    }

    /// The bare-integer member range [`JsonMember`] finds in a bare body.
    fn bare_member(body: &[u8], field: &str) -> Option<Range<usize>> {
        JsonMember::bare_in_body(body, field).map(|m| m.member)
    }

    #[test]
    fn extract_response_body_decodes_chunked() {
        let recv = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n7\r\n{\"a\":1,\r\n8\r\n\"b\":\"x\"}\r\n0\r\n\r\n";
        let body = extract_response_body(recv).unwrap();
        assert_eq!(body, br#"{"a":1,"b":"x"}"#);
    }

    #[test]
    fn a_second_member_is_left_for_the_layout_to_commit() {
        // Not refused here: the reader's uniqueness rule is over the bytes it
        // was shown, and the layout is what decides those. `identity_response`
        // reveals this one's anchors and commits the rest, so the reader sees one.
        let body = br#"{"login":"octocat","user":{"login":"impostor"}}"#;
        let range = member(body, "login").unwrap();
        assert_eq!(&body[range], br#""login":"octocat""#);

        let bare = br#"{"id":1,"user":{"id":2}}"#;
        let range = bare_member(bare, "id").unwrap();
        assert_eq!(&bare[range], br#""id":1,"#);
    }

    #[test]
    fn a_spaced_member_is_found_with_its_whitespace_inside() {
        // GitHub pretty-prints: a space after the colon, a newline and an
        // indent before every key. The reader on chain removes the JSON
        // whitespace beside a structural byte before it looks, so the member
        // is found here and revealed with that whitespace at its offsets.
        let body = b"{\n  \"login\" : \"octocat\",\n  \"id\": 583231\n}";
        let member = member(body, "login").unwrap();
        assert_eq!(&body[member], b"\"login\" : \"octocat\"");
        let id = bare_member(body, "id").unwrap();
        assert_eq!(&body[id], b"\"id\": 583231\n}");
    }

    #[test]
    fn a_key_that_is_only_a_value_is_passed_over() {
        // `"login"` appears first as another member's value; the member is the
        // one a colon and a quote follow.
        let body = br#"{"name":"login","login":"octocat"}"#;
        let member = member(body, "login").unwrap();
        assert_eq!(&body[member], br#""login":"octocat""#);
    }

    #[test]
    fn whitespace_inside_a_number_is_not_a_number() {
        // `123 4` is two tokens where one is expected; the reader on chain
        // keeps that space and refuses it as the terminator, and so nothing is
        // revealed for it here.
        assert_eq!(bare_member(b"{\"id\":123 4}", "id"), None);
    }

    #[test]
    fn every_json_whitespace_byte_is_kept_inside_the_member() {
        // Each byte RFC 8259 section 2 calls whitespace, alone and as a run,
        // on both sides of the colon and before the integer's terminator: the
        // ranges are the members as the wire carries them.
        for ws in [" ", "\t", "\n", "\r", " \t\r\n"] {
            let member = format!("\"login\"{ws}:{ws}\"octocat\"");
            let id = format!("\"id\"{ws}:{ws}123{ws},");
            let recv = format!("HTTP/1.1 200 OK\r\n\r\n{{{id}{member}}}");
            let recv = recv.as_bytes();
            assert_eq!(
                &recv[JsonMember::in_response(recv, "login").unwrap().member],
                member.as_bytes()
            );
            assert_eq!(
                &recv[JsonMember::bare_in_response(recv, "id").unwrap().member],
                id.as_bytes()
            );
        }
    }

    #[test]
    fn a_byte_json_does_not_call_whitespace_is_not_skipped() {
        // Vertical tab and form feed are whitespace to a text editor and not
        // to RFC 8259; the reader on chain keeps them, so nothing is found
        // over them here.
        for ws in ["\u{000b}", "\u{000c}"] {
            let body = format!("{{\"login\":{ws}\"octocat\",\"id\":{ws}123}}");
            assert_eq!(member(body.as_bytes(), "login"), None);
            assert_eq!(bare_member(body.as_bytes(), "id"), None);
        }
    }

    #[test]
    fn a_number_of_another_shape_is_not_a_number() {
        // Digits and nothing else: an exponent or a fraction puts a byte where
        // the terminator must be.
        for value in ["1e3", "1.5"] {
            let body = format!("{{\"id\": {value}}}");
            assert_eq!(bare_member(body.as_bytes(), "id"), None);
        }
    }

    #[test]
    fn whitespace_split_by_chunk_framing_is_not_a_contiguous_member() {
        // The framing lands in the whitespace rather than in the value, and
        // the member still spans two chunks: refused all the same.
        let recv = straddling(r#"{"login" "#, r#": "alice"}"#);
        assert!(JsonMember::in_response(&recv, "login").is_none());
        let recv = straddling(r#"{"id": "#, r#"123}"#);
        assert!(JsonMember::bare_in_response(&recv, "id").is_none());
    }

    #[test]
    fn a_quoted_value_is_not_a_bare_number() {
        // Digits, then the terminator. A scan that instead ran to the first
        // `,` would return `"id":"7",` here, and the chain would find no
        // framed integer -- the same answer, given where the reason is not
        // visible.
        let body = br#"{"login":"octocat","id":"7","x":1}"#;
        assert!(bare_member(body, "id").is_none());
    }

    #[test]
    fn a_leading_zero_is_refused_but_zero_itself_is_not() {
        // `end - at > 1 && data[at] == "0"` on chain: `0123` is noncanonical,
        // `0` is just zero.
        assert!(bare_member(br#"{"id":0123,"x":1}"#, "id").is_none());
        let zero = br#"{"id":0,"x":1}"#;
        let range = bare_member(zero, "id").unwrap();
        assert_eq!(&zero[range], br#""id":0,"#);
    }

    #[test]
    fn a_terminator_the_profile_does_not_fix_is_refused() {
        // Only `,` and `}` close the digits. A `]` means the id sat in an array
        // the profile never described.
        assert!(bare_member(br#"{"a":[1,"id":7]}"#, "id").is_none());
        // And digits running to the end of the range have no terminator at all,
        // which is `Found.None` on chain rather than a value.
        assert!(bare_member(br#"{"id":7"#, "id").is_none());
    }

    #[test]
    fn a_lookalike_key_does_not_match() {
        // `"node_id":` contains `id":` but not `"id":` -- the full delimiter is
        // what keeps a neighbouring member out, on both sides.
        let body = br#"{"node_id":"MDQ=","id":123}"#;
        let range = bare_member(body, "id").unwrap();
        assert_eq!(&body[range], br#""id":123}"#);
    }

    #[test]
    fn a_member_is_found_past_the_headers() {
        let recv = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"body\":\"hello world\",\"user\":{\"login\":\"alice\"}}";

        let range = JsonMember::in_response(recv, "login").unwrap().member;
        assert_eq!(&recv[range], br#""login":"alice""#);

        let range = JsonMember::in_response(recv, "body").unwrap().member;
        assert_eq!(&recv[range], br#""body":"hello world""#);
    }

    /// A chunked response whose `field` value is cut in half by a chunk
    /// boundary. The framing carries no quote, comma or brace, so every scan
    /// here runs straight through it.
    fn straddling(head: &str, tail: &str) -> Vec<u8> {
        let mut out = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec();
        for part in [head, tail] {
            out.extend_from_slice(format!("{:x}\r\n", part.len()).as_bytes());
            out.extend_from_slice(part.as_bytes());
            out.extend_from_slice(b"\r\n");
        }
        out.extend_from_slice(b"0\r\n\r\n");
        out
    }

    /// The property every caller of `JsonMember::in_response` depends on: the
    /// value sits inside the member, and what the member holds either side of
    /// it is exactly the two delimiters. A boundary that drifts breaks this
    /// before it reaches a layout, where the symptom is a committed bearer with
    /// a quote in it.
    fn assert_brackets(recv: &[u8], found: &JsonMember, field: &str, value: &[u8]) {
        assert!(
            found.member.start <= found.value.start
                && found.value.end <= found.member.end,
            "the value must sit inside the member"
        );
        assert_eq!(&recv[found.value.clone()], value, "value bytes");
        assert_eq!(
            &recv[found.member.start..found.value.start],
            format!("\"{field}\":\"").as_bytes(),
            "opening delimiter"
        );
        assert_eq!(
            &recv[found.value.end..found.member.end],
            b"\"",
            "closing quote"
        );
    }

    #[test]
    fn the_member_brackets_its_value_with_the_two_delimiters() {
        let recv = b"HTTP/1.1 200 OK\r\n\r\n{\"access_token\":\"ghu_ABC\",\"x\":1}";
        let found = JsonMember::in_response(recv, "access_token").unwrap();
        assert_brackets(recv, &found, "access_token", b"ghu_ABC");
    }

    #[test]
    fn a_value_carrying_structural_bytes_still_ends_at_its_quote() {
        // Only `"` closes a JSON string, so a value holding `:`, `,` or `}`
        // must not shorten the member -- a scan that stopped at one would
        // commit a prefix of the bearer and reveal the rest of it.
        let recv = b"HTTP/1.1 200 OK\r\n\r\n{\"access_token\":\"a:b,c}d\",\"x\":1}";
        let found = JsonMember::in_response(recv, "access_token").unwrap();
        assert_brackets(recv, &found, "access_token", b"a:b,c}d");
    }

    #[test]
    fn an_empty_value_is_found_with_an_empty_range() {
        // Found, not refused: whether an empty value is usable is the caller's
        // rule, and `token_response` has its own reason to refuse one.
        let recv = b"HTTP/1.1 200 OK\r\n\r\n{\"access_token\":\"\"}";
        let found = JsonMember::in_response(recv, "access_token").unwrap();
        assert!(found.value.is_empty());
        assert_eq!(&recv[found.member.clone()], b"\"access_token\":\"\"");
    }

    #[test]
    fn a_bare_integer_s_value_is_the_digits_alone() {
        // The committed range the circuit opens: digits only, never the
        // whitespace before the terminator nor the terminator itself.
        for (body, tail) in [
            (
                "{\n  \"login\": \"octocat\",\n  \"id\": 583231 \t,\n  \"x\": 1\n}",
                &b" \t,"[..],
            ),
            ("{\"login\":\"octocat\",\"id\":583231\n}", b"\n}"),
        ] {
            let recv = format!("HTTP/1.1 200 OK\r\n\r\n{body}");
            let recv = recv.as_bytes();
            let found = JsonMember::bare_in_response(recv, "id").unwrap();
            assert_eq!(&recv[found.value.clone()], b"583231");
            assert_eq!(&recv[found.value.end..found.member.end], tail);
            assert!(recv[found.member.start..found.value.start].starts_with(b"\"id\":"));
        }
    }

    #[test]
    fn a_member_split_by_chunk_framing_is_refused() {
        // Found in both bodies, and the raw range spans `\r\n<size>\r\n` in the
        // middle of the value. Revealed it would put framing inside the handle
        // a verifier reads; committed, inside the bearer a circuit opens.
        let recv = straddling(r#"{"login":"oct"#, r#"ocat","id":1}"#);
        assert!(JsonMember::in_response(&recv, "login").is_none());
    }

    #[test]
    fn a_bare_id_split_by_chunk_framing_is_refused() {
        let recv = straddling(r#"{"login":"octocat","id":12"#, r#"34,"x":1}"#);
        assert!(JsonMember::bare_in_response(&recv, "id").is_none());
    }

    #[test]
    fn a_chunked_member_inside_one_chunk_still_resolves() {
        // The point is contiguity, not chunking: a body that happens to be
        // chunked is fine as long as the member sits in one piece.
        let recv = straddling(r#"{"login":"octocat","#, r#""id":1}"#);
        let range = JsonMember::in_response(&recv, "login").unwrap().member;
        assert_eq!(&recv[range], br#""login":"octocat""#);
    }

    #[test]
    fn a_missing_member_is_not_found() {
        let recv =
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"foo\":\"bar\"}";
        assert!(JsonMember::in_response(recv, "missing").is_none());
    }
}
