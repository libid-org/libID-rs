//! Capture a platform's two ceremony records from a real session.
//!
//! The fixture generator reproduces what the platforms send; this records
//! it. A real MPC-TLS session against the real platform, with the verifier
//! in this process on the other end of a pipe, signing as anvil #0 -- the
//! key the contract suites trust -- so the records verify under those suites
//! with their signatures unedited. The PKCE challenge is derived from the
//! same Authorization Digest the suites derive, which is what binds the
//! platform's token to that submission.
//!
//! You supply the app and the consent: register the redirect URI below on the
//! app, run this, open the URL it prints, log in, consent. It receives the
//! code, runs the token session and then the identity session, and writes
//! `<platform>-ceremony-real.json` into `--out`, beside the generated fixture.
//!
//! That file is public. It carries no bearer, id or handle: the records commit
//! them. The token request is revealed whole, client credential included, so
//! the file is a public record of a public credential; the code in it is
//! spent.
//!
//! ONE REDIRECT URI SERVES EVERY PLATFORM: `http://127.0.0.1:8722/auth/callback`,
//! the default here and the path the bridge serves. A path naming its platform
//! would mean one app registration per platform to capture from, for a value
//! no ceremony reads -- the profile fixes what the redirect URI must equal, not
//! what it must be.
//!
//! ```sh
//! cargo run -p libid-tlsn --example capture_ceremony -- \
//!     --platform github --client-id ID --client-secret SECRET --out <dir>
//! cargo run -p libid-tlsn --example capture_ceremony -- \
//!     --platform x --client-id ID --out <dir>
//! ```
//!
//! The public record is written first. Then the identity-link circuit's
//! witness -- the bearer, the id and the handle, each with its blinder -- goes
//! to a NEW owner-only file (mode 0600, unix only), by default in the system
//! temporary directory:
//! `$TMPDIR/libid-<platform>-identity-link-witness-<unix time>.secret.json`, or
//! `--witness-out <path>`, which must not exist yet. It prints the path and
//! never the contents.
//!
//! That file is secret. The bearer is a live credential until you revoke the
//! token. The id and handle blinders are secret for good: anyone holding them
//! can link the record's commitments to the plaintext account, and revoking
//! the token does not undo that. Build the circuit's input from it outside
//! every repository with `libID-circuits/scripts/identity-link-witness.py`,
//! then delete it and revoke the token. Never copy it into a fixtures
//! directory.
//!
//! `--redirect-uri` and `--listen` override the pair for an app registered
//! elsewhere; they move together, since the code arrives on the address the
//! platform redirects to.
//!
//! `RUST_LOG=info` shows the session phases. Each session takes the time
//! MPC-TLS takes, tens of seconds.

#[path = "ceremony/common.rs"]
mod common;
#[path = "ceremony/secret_file.rs"]
mod secret_file;
#[path = "ceremony/witness.rs"]
mod witness;

use std::{
    path::PathBuf,
    sync::OnceLock,
    time::{
        SystemTime,
        UNIX_EPOCH,
    },
};

use common::*;
use http_body_util::Full;
use hyper::body::Bytes;
use libid_crypto::{
    hex_to_signing_key,
    keccak256,
    pubkey_to_eth_address,
    sign_eth_claim,
};
use libid_tlsn::{
    attest::{
        FromObserved,
        ObservedSession,
    },
    HttpRequest,
};
use libid_transcript::{
    attestation::AttestedData,
    ceremony::{
        form_encode,
        profiles,
        token_bearer,
        token_body,
        Layout,
    },
};
use serde_json::json;
use tlsn::connection::ServerName;
use tokio::{
    io::{
        AsyncReadExt,
        AsyncWriteExt,
    },
    net::TcpListener,
};
use witness::{
    ascii,
    identity_link_witness,
    Held,
};

/// The redirect URI every platform's app registers, and the address the code
/// comes back on. One pair, so one app registration per platform is enough to
/// capture from and the two cannot drift apart.
const DEFAULT_REDIRECT_URI: &str = "http://127.0.0.1:8722/auth/callback";
const DEFAULT_LISTEN: &str = "127.0.0.1:8722";

struct Args {
    platform: String,
    client_id: String,
    client_secret: Option<String>,
    redirect_uri: String,
    listen: String,
    out: PathBuf,
    witness_out: Option<PathBuf>,
}

fn args() -> Args {
    let mut platform = None;
    let mut client_id = None;
    let mut client_secret = None;
    let mut redirect_uri = DEFAULT_REDIRECT_URI.to_owned();
    let mut listen = DEFAULT_LISTEN.to_owned();
    let mut out = None;
    let mut witness_out = None;
    let mut it = std::env::args().skip(1);
    while let Some(flag) = it.next() {
        let mut value = || it.next().unwrap_or_else(|| panic!("{flag} needs a value"));
        match flag.as_str() {
            "--platform" => platform = Some(value()),
            "--client-id" => client_id = Some(value()),
            "--client-secret" => client_secret = Some(value()),
            "--redirect-uri" => redirect_uri = value(),
            "--listen" => listen = value(),
            "--out" => out = Some(PathBuf::from(value())),
            "--witness-out" => witness_out = Some(PathBuf::from(value())),
            other => panic!("unknown flag {other}"),
        }
    }
    let platform = platform.expect("--platform x|github");
    match platform.as_str() {
        "x" => {}
        "github" => assert!(client_secret.is_some(), "--client-secret for github"),
        other => panic!("unknown platform {other}"),
    }
    Args {
        platform,
        client_id: client_id.expect("--client-id"),
        client_secret,
        redirect_uri,
        listen,
        out: out.expect("--out <dir>"),
        witness_out,
    }
}

fn form_decode(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 2 < bytes.len() => {
                let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap_or("");
                match u8::from_str_radix(hex, 16) {
                    Ok(b) => {
                        out.push(b);
                        i += 3;
                    }
                    Err(_) => {
                        out.push(b'%');
                        i += 1;
                    }
                }
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_secs()
}

/// Wait for the browser's redirect on `listener` and return the code it
/// carries.
async fn receive_code(listener: TcpListener, expected_state: &str) -> String {
    loop {
        let (mut socket, _) = listener.accept().await.expect("accept");
        let mut buf = vec![0u8; 8192];
        let n = socket.read(&mut buf).await.expect("read");
        let head = String::from_utf8_lossy(&buf[..n]).into_owned();
        let line = head.lines().next().unwrap_or("").to_owned();
        let target = line.split(' ').nth(1).unwrap_or("");
        let query = target.split_once('?').map(|(_, q)| q).unwrap_or("");
        let mut code = None;
        let mut state = None;
        for pair in query.split('&') {
            let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
            match k {
                "code" => code = Some(form_decode(v)),
                "state" => state = Some(form_decode(v)),
                _ => {}
            }
        }
        let (status, body) = match (&code, state.as_deref()) {
            (Some(_), Some(s)) if s == expected_state => {
                ("200 OK", "Consent received. You can close this tab.")
            }
            _ => (
                "400 Bad Request",
                "No code, or the wrong state. Try the URL again.",
            ),
        };
        let response = format!(
            "HTTP/1.1 {status}\r\ncontent-type: text/plain\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
            body.len()
        );
        socket
            .write_all(response.as_bytes())
            .await
            .expect("respond");
        socket.shutdown().await.ok();
        if status.starts_with("200") {
            return code.expect("code");
        }
        eprintln!("ignored a request without the expected code and state: {line}");
    }
}

struct Session {
    signature: Vec<u8>,
    created_at: u64,
    authority: String,
    /// Both directions in full, the openings and the record, as the prover
    /// holds them. The witness is built from them; the public record carries
    /// only the record.
    held: Held,
}

/// One notarized session: the prover against the real platform, the
/// verifier in this process on the other end of a pipe, the record built the
/// notary's way and signed the notary's way.
async fn notarize(
    request: HttpRequest<Full<Bytes>>,
    layouts: impl FnOnce(
        &[u8],
        &[u8],
    )
        -> Result<(Layout, Layout), libid_transcript::ceremony::LayoutError>,
    sign: &dyn Fn(&[u8; 32]) -> Vec<u8>,
) -> Result<Session, String> {
    let (to_verifier, from_prover) = tokio::io::duplex(1 << 16);
    let verifier = tokio::spawn(libid_tlsn::verifier(from_prover));
    let mut transcript = None;
    let prover = libid_tlsn::prover_generic(
        to_verifier,
        request,
        |sent, recv| {
            transcript = Some((sent.to_vec(), recv.to_vec()));
            layouts(sent, recv).map_err(|e| libid_tlsn::Error::MpcTlsFailed {
                detail: format!("layout: {e}"),
            })
        },
        |step| eprintln!("  prover: {step:?}"),
    )
    .await;
    let prover = match prover {
        Ok(prover) => prover,
        Err(e) => {
            // Stop the verifier before reporting, so the runtime is not torn
            // down under a live session.
            verifier.abort();
            let _ = verifier.await;
            return Err(format!("the prover's session: {e}"));
        }
    };
    let observed = verifier
        .await
        .map_err(|e| format!("verifier task: {e}"))?
        .map_err(|e| format!("the verifier's session: {e}"))?;
    let (sent, recv) = transcript.expect("the layouts ran on the transcript");
    let ServerName::Dns(ref name) = observed.server_name;
    let authority = name.as_str().to_owned();
    let created_at = now();
    let data = AttestedData::from_observed(ObservedSession {
        transcript: &observed.partial_transcript,
        authority: &authority,
        commitments: &observed.transcript_commitments,
        created_at,
    })
    .expect("record");
    let record = data.encode().expect("encode");
    let signature = sign(&keccak256(&record));
    eprintln!(
        "  record: {} bytes, sent {} revealed / {} committed, received {} revealed / {} committed, authority {authority}",
        record.len(),
        data.sent.revealed.len(),
        data.sent.commitments.len(),
        data.received.revealed.len(),
        data.received.commitments.len()
    );
    Ok(Session {
        signature,
        created_at,
        authority,
        held: Held {
            sent,
            recv,
            openings: prover.commitment_openings,
            record: data,
        },
    })
}

/// Set when the token session starts: from then on a token may have been
/// issued, and every exit says to revoke it.
static REVOKE: OnceLock<String> = OnceLock::new();

fn fail(message: String) -> ! {
    eprintln!("error: {message}");
    if let Some(revoke) = REVOKE.get() {
        eprintln!("{revoke}");
    }
    std::process::exit(1)
}

/// The default witness destination: a new name in the system temporary
/// directory, outside any repository.
fn default_witness_path(platform: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "libid-{platform}-identity-link-witness-{}.secret.json",
        now()
    ))
}

fn session_json(endpoint: &str, session: &Session) -> serde_json::Value {
    json!({
        "endpoint": endpoint,
        "authority": session.authority,
        "created_at": session.created_at,
        "attested_data": hex0x(&session.held.record.encode().expect("encode")),
        "notary_signature": hex0x(&session.signature),
    })
}

fn request(
    method: &str,
    uri: &str,
    headers: &[(&str, String)],
    body: &[u8],
) -> HttpRequest<Full<Bytes>> {
    let mut builder = HttpRequest::builder().method(method).uri(uri);
    for (name, value) in headers {
        builder = builder.header(*name, value.as_str());
    }
    builder
        .body(Full::new(Bytes::copy_from_slice(body)))
        .expect("valid request")
}

#[tokio::main]
async fn main() {
    let args = args();
    std::fs::create_dir_all(&args.out).expect("output directory");
    let key = hex_to_signing_key(NOTARY_KEY).expect("notary key");
    let notary = hex0x(&pubkey_to_eth_address(key.verifying_key()));
    let sign = |digest: &[u8; 32]| sign_eth_claim(&key, digest).expect("sign");
    let verifier = code_verifier();
    let challenge = code_challenge();
    let state =
        hex::encode(&keccak256(format!("libid capture {}", now()).as_bytes())[..16]);

    let (authorize, scope) = match args.platform.as_str() {
        "x" => (
            "https://x.com/i/oauth2/authorize?response_type=code",
            "tweet.read users.read",
        ),
        "github" => ("https://github.com/login/oauth/authorize?", "read:user"),
        other => unreachable!("args() refuses platform {other}"),
    };
    let separator = if authorize.ends_with('?') { "" } else { "&" };
    let url = format!(
        "{authorize}{separator}client_id={}&redirect_uri={}&scope={}&state={state}&code_challenge={challenge}&code_challenge_method=S256",
        form_encode(&args.client_id),
        form_encode(&args.redirect_uri),
        form_encode(scope),
    );
    // Bound before the URL is printed: a consent given while nothing listens
    // is a code lost.
    let listener = TcpListener::bind(&args.listen).await.unwrap_or_else(|e| {
        fail(format!(
            "binding the redirect listener on {}: {e}. Stop whatever holds the port, or pass \
             `--listen` and the matching `--redirect-uri` registered on the app",
            args.listen
        ))
    });
    eprintln!("\nOpen this URL, log in, and consent:\n\n{url}\n\nWaiting for the redirect on {} ...", args.listen);
    let code = receive_code(listener, &state).await;
    eprintln!("code received; running the token session");
    let revoke = format!(
        "Revoke the app's access in {}'s authorized-apps settings: the token is live until then.",
        args.platform
    );
    REVOKE.set(revoke).expect("set once");

    let (profile, token, identity, held) = match args.platform.as_str() {
        "x" => {
            let profile = profiles::X;
            let body = token_body(
                &profile.token.unwrap(),
                &[
                    ("client_id", &args.client_id),
                    ("code", &code),
                    ("redirect_uri", &args.redirect_uri),
                    ("code_verifier", &verifier),
                ],
            )
            .unwrap_or_else(|e| fail(e.to_string()));
            // As the browser's `buildTokenRequest` sets them.
            let token = notarize(
                request(
                    "POST",
                    "https://api.x.com/2/oauth2/token",
                    &[
                        ("Host", "api.x.com".into()),
                        ("Content-Type", "application/x-www-form-urlencoded".into()),
                        ("Content-Length", body.len().to_string()),
                        ("Accept", "application/json".into()),
                        ("Connection", "close".into()),
                    ],
                    body.as_bytes(),
                ),
                |sent, recv| {
                    Ok((Layout::token_request(sent)?, Layout::token_response(recv)?))
                },
                &sign,
            )
            .await
            .unwrap_or_else(|e| fail(e));
            let bearer = bearer_of(&token.held.recv);
            eprintln!("token received; running the identity session");
            let identity = notarize(
                request(
                    "GET",
                    "https://api.x.com/2/users/me",
                    &[
                        ("Authorization", format!("Bearer {bearer}")),
                        ("Accept", "application/json".into()),
                        ("Host", "api.x.com".into()),
                        ("Connection", "close".into()),
                    ],
                    b"",
                ),
                |sent, recv| {
                    Ok((
                        Layout::identity_request(sent)?,
                        Layout::identity_response(recv, &profile.identity.unwrap())?,
                    ))
                },
                &sign,
            )
            .await
            .unwrap_or_else(|e| fail(e));
            (
                profile,
                session_json("https://api.x.com/2/oauth2/token", &token),
                session_json("https://api.x.com/2/users/me", &identity),
                (token.held, identity.held),
            )
        }
        _ => {
            let profile = profiles::GITHUB;
            let secret = args
                .client_secret
                .as_deref()
                .expect("args() requires --client-secret for github");
            let body = token_body(
                &profile.token.unwrap(),
                &[
                    ("client_id", &args.client_id),
                    ("code", &code),
                    ("redirect_uri", &args.redirect_uri),
                    ("code_verifier", &verifier),
                    ("client_secret", secret),
                ],
            )
            .unwrap_or_else(|e| fail(e.to_string()));
            // The body is the profile's `token_fields` in order; hyper appends
            // the length.
            let token = notarize(
                request(
                    "POST",
                    "https://github.com/login/oauth/access_token",
                    &[
                        ("host", "github.com".into()),
                        ("content-type", "application/x-www-form-urlencoded".into()),
                        ("accept", "application/json".into()),
                        ("connection", "close".into()),
                    ],
                    body.as_bytes(),
                ),
                |sent, recv| {
                    Ok((Layout::token_request(sent)?, Layout::token_response(recv)?))
                },
                &sign,
            )
            .await
            .unwrap_or_else(|e| fail(e));
            let bearer = bearer_of(&token.held.recv);
            eprintln!("token received; running the identity session");
            // As the browser's `identityRequest` sets them.
            let identity = notarize(
                request(
                    "GET",
                    "https://api.github.com/user",
                    &[
                        ("Host", "api.github.com".into()),
                        ("Authorization", format!("Bearer {bearer}")),
                        ("Accept", "application/vnd.github+json".into()),
                        ("User-Agent", BROWSER_AGENT.into()),
                        ("X-GitHub-Api-Version", "2022-11-28".into()),
                        ("Connection", "close".into()),
                    ],
                    b"",
                ),
                |sent, recv| {
                    Ok((
                        Layout::identity_request(sent)?,
                        Layout::identity_response(recv, &profile.identity.unwrap())?,
                    ))
                },
                &sign,
            )
            .await
            .unwrap_or_else(|e| fail(e));
            (
                profile,
                session_json("https://github.com/login/oauth/access_token", &token),
                session_json("https://api.github.com/user", &identity),
                (token.held, identity.held),
            )
        }
    };

    let mut file = submission_json(&args.platform, &notary);
    file["source"] = json!("captured: a real MPC-TLS session against the platform, the verifier in-process, by libid-rs examples/capture_ceremony.rs");
    file["captured_at"] = json!(now());
    file["token"] = token;
    file["identity"] = identity;
    let path = args
        .out
        .join(format!("{}-ceremony-real.json", args.platform));
    std::fs::write(&path, serde_json::to_string_pretty(&file).unwrap() + "\n")
        .unwrap_or_else(|e| fail(format!("writing {}: {e}", path.display())));
    println!("wrote {}", path.display());

    // Built after the record is on disk, so a witness that cannot be built
    // or written costs the witness and not the capture.
    let kept = |e: String| -> ! {
        fail(format!("{e}. The public record {} is kept", path.display()))
    };
    let witness = identity_link_witness(&profile, &held.0, &held.1)
        .unwrap_or_else(|e| kept(format!("identity-link witness: {e}")));
    let witness_path = args
        .witness_out
        .clone()
        .unwrap_or_else(|| default_witness_path(&args.platform));
    let json = serde_json::to_string_pretty(&witness).unwrap() + "\n";
    secret_file::write_new(&witness_path, json.as_bytes())
        .unwrap_or_else(|e| kept(format!("the witness: {e}")));
    println!(
        "wrote {}, the identity-link witness: SECRET, see this example's module doc before \
         using it.\n{}",
        witness_path.display(),
        REVOKE.get().expect("set before the token session")
    );
}

/// The bearer the token response carries, which the identity session sends:
/// the bytes the record commits. A failure never prints the response, which
/// holds the bearer.
fn bearer_of(recv: &[u8]) -> String {
    let bearer = token_bearer(recv)
        .unwrap_or_else(|e| fail(format!("the token response's bearer: {e}")))
        .value;
    ascii(&recv[bearer])
        .unwrap_or_else(|| {
            fail("the token response's `access_token` is not ASCII".into())
        })
        .to_owned()
}
