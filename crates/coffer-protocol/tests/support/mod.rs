// Coffer: a native Linux client for Apple Passwords.
// Copyright (C) 2026  Hong Minhee
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

//! Offline test harness: a scripted transport, fixed anisette and entropy
//! sources, a minimal executor, and the synthetic SRP vector every fixture
//! is derived from.
//!
//! Nothing here touches the network.  Every value is synthetic and labelled
//! as such; none belongs to a real Apple Account.

#![allow(dead_code)]

use std::collections::VecDeque;
use std::future::{Future, ready};
use std::path::PathBuf;
use std::pin::pin;
use std::sync::Mutex;
use std::task::{Context, Poll, Waker};

use coffer_protocol::anisette::{AnisetteData, AnisetteError, AnisetteProvider};
use coffer_protocol::entropy::{Entropy, EntropyError};
use coffer_protocol::transport::{Method, Request, Response, Transport, TransportError};
use zeroize::Zeroizing;

// Executor -------------------------------------------------------------------

/// Drives a future to completion on the current thread.
///
/// Every future in these tests resolves without waiting on I/O, so a no-op
/// waker and a poll loop are enough.
pub fn block_on<F: Future>(fut: F) -> F::Output {
    let mut fut = pin!(fut);
    let mut cx = Context::from_waker(Waker::noop());
    loop {
        if let Poll::Ready(value) = fut.as_mut().poll(&mut cx) {
            return value;
        }
    }
}

// Hex ------------------------------------------------------------------------

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn unhex(s: &str) -> Vec<u8> {
    assert!(s.len().is_multiple_of(2), "odd hex length");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex digit"))
        .collect()
}

// Fixtures -------------------------------------------------------------------

pub fn fixture_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

pub fn fixture(name: &str) -> Vec<u8> {
    let path = fixture_dir().join(name);
    std::fs::read(&path).unwrap_or_else(|e| panic!("read fixture {}: {e}", path.display()))
}

// Entropy --------------------------------------------------------------------

/// Returns a fixed byte pattern, making the SRP ephemeral reproducible.
pub struct FixedEntropy(pub Vec<u8>);

impl Entropy for FixedEntropy {
    fn fill(&self, dest: &mut [u8]) -> Result<(), EntropyError> {
        assert!(dest.len() <= self.0.len(), "fixed entropy exhausted");
        dest.copy_from_slice(&self.0[..dest.len()]);
        Ok(())
    }
}

/// Always fails.
pub struct BrokenEntropy;

impl Entropy for BrokenEntropy {
    fn fill(&self, _dest: &mut [u8]) -> Result<(), EntropyError> {
        Err(EntropyError::new("synthetic entropy failure"))
    }
}

// Anisette -------------------------------------------------------------------

pub fn sample_anisette() -> AnisetteData {
    AnisetteData {
        one_time_password: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_owned(),
        machine_id: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
            .to_owned(),
        routing_info: "17106176".to_owned(),
        local_user_id: "SYNTHETICLOCALUSERID000000000000".to_owned(),
        serial_number: "0".to_owned(),
        client_info: "<MacBookPro13,2> <macOS;13.1;22C65> <com.apple.AuthKit/1 (com.apple.dt.Xcode/3594.4.19)>"
            .to_owned(),
        device_id: "00000000-0000-4000-8000-000000000000".to_owned(),
        client_time: "2026-09-04T00:00:00Z".to_owned(),
        time_zone: "UTC".to_owned(),
        locale: "en_US".to_owned(),
    }
}

/// Returns the same synthetic anisette data on every call.
pub struct FixedAnisette;

impl AnisetteProvider for FixedAnisette {
    fn anisette(&self) -> impl Future<Output = Result<AnisetteData, AnisetteError>> + Send {
        ready(Ok(sample_anisette()))
    }
}

/// Always fails.
pub struct BrokenAnisette;

impl AnisetteProvider for BrokenAnisette {
    fn anisette(&self) -> impl Future<Output = Result<AnisetteData, AnisetteError>> + Send {
        ready(Err(AnisetteError::Unavailable {
            detail: "synthetic anisette failure".to_owned(),
        }))
    }
}

/// Returns data with a header-injection attempt in one value.
pub struct InjectingAnisette;

impl AnisetteProvider for InjectingAnisette {
    fn anisette(&self) -> impl Future<Output = Result<AnisetteData, AnisetteError>> + Send {
        let mut data = sample_anisette();
        data.serial_number = "0\r\nX-Injected: yes".to_owned();
        ready(Ok(data))
    }
}

// Transport ------------------------------------------------------------------

/// What the scripted transport does for one request.
pub enum Step {
    Reply {
        status: u16,
        body: Vec<u8>,
    },
    /// Like `Reply`, but ignores `Request::max_response_body`, modelling a
    /// transport that fails to enforce the cap.
    ReplyUncapped {
        status: u16,
        body: Vec<u8>,
    },
    Fail(TransportError),
}

pub fn reply(status: u16, body: impl Into<Vec<u8>>) -> Step {
    Step::Reply {
        status,
        body: body.into(),
    }
}

pub fn ok(body: impl Into<Vec<u8>>) -> Step {
    reply(200, body)
}

/// A request as the transport saw it.
pub struct Recorded {
    pub method: Method,
    pub url: String,
    pub headers: Vec<(String, Zeroizing<String>)>,
    pub body: Option<Zeroizing<Vec<u8>>>,
}

impl Recorded {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

/// Replays a fixed script of responses and records every request.
///
/// A request beyond the end of the script is recorded and answered with a
/// transport error, so an unexpected extra request (a retry) shows up both
/// as a wrong request count and as a failure.
pub struct ScriptedTransport {
    steps: Mutex<VecDeque<Step>>,
    log: Mutex<Vec<Recorded>>,
}

impl ScriptedTransport {
    pub fn new(steps: Vec<Step>) -> Self {
        Self {
            steps: Mutex::new(steps.into()),
            log: Mutex::new(Vec::new()),
        }
    }

    pub fn count(&self) -> usize {
        self.log.lock().unwrap().len()
    }

    pub fn remaining(&self) -> usize {
        self.steps.lock().unwrap().len()
    }

    pub fn requests(&self) -> Vec<Recorded> {
        std::mem::take(&mut *self.log.lock().unwrap())
    }
}

impl Transport for ScriptedTransport {
    fn send(
        &self,
        request: Request,
    ) -> impl Future<Output = Result<Response, TransportError>> + Send {
        let Request {
            method,
            url,
            headers,
            body,
            max_response_body,
        } = request;
        self.log.lock().unwrap().push(Recorded {
            method,
            url,
            headers,
            body,
        });
        let result = match self.steps.lock().unwrap().pop_front() {
            Some(Step::Reply { status, body }) => {
                if body.len() > max_response_body {
                    Err(TransportError::ResponseTooLarge {
                        limit: max_response_body,
                    })
                } else {
                    Ok(Response::new(status, body))
                }
            }
            Some(Step::ReplyUncapped { status, body }) => Ok(Response::new(status, body)),
            Some(Step::Fail(e)) => Err(e),
            None => Err(TransportError::Other {
                detail: "unscripted request".to_owned(),
            }),
        };
        ready(result)
    }
}

// Synthetic vector -----------------------------------------------------------

/// The synthetic Apple SRP vector.
///
/// Inputs are fixed constants; outputs are computed with the `srp` crate's
/// server side, which is an independent implementation of the arithmetic the
/// client under test relies on.  The pinned copy lives in
/// `tests/fixtures/srp/apple_srp_vector.txt`.
pub mod vector {
    use std::collections::BTreeMap;

    use aes::cipher::block_padding::Pkcs7;
    use aes::cipher::{BlockModeEncrypt, KeyIvInit};
    use hmac::{Hmac, KeyInit, Mac};
    use plist::{Dictionary, Value};
    use sha2::{Digest, Sha256};
    use srp::{ClientG2048, ServerG2048};

    pub const ACCOUNT: &str = "coffer-fixture@example.invalid";
    pub const PASSWORD: &str = "synthetic fixture password, not a real credential";
    pub const SALT: &[u8; 16] = b"coffer-salt-0001";
    pub const ITERATIONS: u32 = 20832;
    pub const COOKIE: &str = "synthetic-gsa-cookie-0001";
    pub const ADSID: &str = "000000-00-synthetic-adsid-not-real";
    pub const IDMS_TOKEN: &str = "SYNTHETIC-GSIDMS-TOKEN-NOT-REAL";
    pub const PET: &str = "SYNTHETIC-PET-TOKEN-NOT-REAL";
    pub const SPD_COOKIE: &[u8] = b"synthetic-spd-cookie";
    pub const GIVEN_NAME: &str = "Coffer";
    pub const FAMILY_NAME: &str = "Fixture";
    pub const PET_SERVICE: &str = "com.apple.gs.idms.pet";

    pub fn a_secret() -> Vec<u8> {
        (0..32u32).map(|i| (i * 7 + 3) as u8).collect()
    }

    pub fn b_secret() -> Vec<u8> {
        (0..32u32).map(|i| (i * 13 + 5) as u8).collect()
    }

    pub fn session_key_sk() -> [u8; 32] {
        let mut sk = [0u8; 32];
        for (i, b) in sk.iter_mut().enumerate() {
            *b = (i * 3 + 1) as u8;
        }
        sk
    }

    pub struct Vector {
        pub password_key: [u8; 32],
        pub a_pub: Vec<u8>,
        pub b_pub: Vec<u8>,
        pub m1: Vec<u8>,
        pub m2: Vec<u8>,
        pub k: Vec<u8>,
        pub spd_key: [u8; 32],
        pub spd_iv: [u8; 16],
        pub spd_plaintext: Vec<u8>,
        pub spd_ciphertext: Vec<u8>,
    }

    pub fn password_key() -> [u8; 32] {
        let digest = Sha256::digest(PASSWORD.as_bytes());
        let mut key = [0u8; 32];
        pbkdf2::pbkdf2_hmac::<Sha256>(&digest, SALT, ITERATIONS, &mut key);
        key
    }

    fn hmac(key: &[u8], label: &[u8]) -> [u8; 32] {
        let mut mac = Hmac::<Sha256>::new_from_slice(key).unwrap();
        mac.update(label);
        mac.finalize().into_bytes().into()
    }

    pub fn spd_plaintext() -> Vec<u8> {
        let mut pet = Dictionary::new();
        pet.insert("token".to_owned(), Value::String(PET.to_owned()));
        let mut tokens = Dictionary::new();
        tokens.insert(PET_SERVICE.to_owned(), Value::Dictionary(pet));
        let mut spd = Dictionary::new();
        spd.insert(
            "GsIdmsToken".to_owned(),
            Value::String(IDMS_TOKEN.to_owned()),
        );
        spd.insert("adsid".to_owned(), Value::String(ADSID.to_owned()));
        spd.insert("c".to_owned(), Value::Data(SPD_COOKIE.to_vec()));
        spd.insert("fn".to_owned(), Value::String(GIVEN_NAME.to_owned()));
        spd.insert("ln".to_owned(), Value::String(FAMILY_NAME.to_owned()));
        spd.insert("sk".to_owned(), Value::Data(session_key_sk().to_vec()));
        spd.insert("t".to_owned(), Value::Dictionary(tokens));
        let mut out = Vec::new();
        Value::Dictionary(spd).to_writer_xml(&mut out).unwrap();
        out
    }

    pub fn encrypt_spd(k: &[u8], plaintext: &[u8]) -> ([u8; 32], [u8; 16], Vec<u8>) {
        let key = hmac(k, b"extra data key:");
        let iv_full = hmac(k, b"extra data iv:");
        let mut iv = [0u8; 16];
        iv.copy_from_slice(&iv_full[..16]);
        let ciphertext = cbc::Encryptor::<aes::Aes256>::new_from_slices(&key, &iv)
            .unwrap()
            .encrypt_padded_vec::<Pkcs7>(plaintext);
        (key, iv, ciphertext)
    }

    /// Computes the vector from the inputs using the `srp` server side.
    pub fn compute() -> Vector {
        let password_key = password_key();
        let client = ClientG2048::<Sha256>::new_with_options(false);
        let server = ServerG2048::<Sha256>::new();

        let verifier = client.compute_verifier(ACCOUNT.as_bytes(), &password_key, SALT);
        let b_pub = server.compute_public_ephemeral(&b_secret(), &verifier);
        let a_pub = client.compute_public_ephemeral(&a_secret());

        let client_side = client
            .process_reply(&a_secret(), ACCOUNT.as_bytes(), &password_key, SALT, &b_pub)
            .expect("client accepts B");
        let server_side = server
            .process_reply(ACCOUNT.as_bytes(), SALT, &b_secret(), &verifier, &a_pub)
            .expect("server accepts A");
        let m1 = client_side.proof().to_vec();
        let k = server_side
            .verify_client(&m1)
            .expect("server accepts M1")
            .to_vec();
        let m2 = server_side.proof().to_vec();
        assert_eq!(
            client_side.verify_server(&m2).expect("client accepts M2"),
            &k[..]
        );

        let spd_plaintext = spd_plaintext();
        let (spd_key, spd_iv, spd_ciphertext) = encrypt_spd(&k, &spd_plaintext);
        Vector {
            password_key,
            a_pub,
            b_pub,
            m1,
            m2,
            k,
            spd_key,
            spd_iv,
            spd_plaintext,
            spd_ciphertext,
        }
    }

    /// Renders the vector as `name = hex` lines.
    pub fn render(v: &Vector) -> String {
        let mut lines =
            vec!["# Synthetic Apple SRP vector.  See README.md.  No real credentials.".to_owned()];
        let pairs: BTreeMap<&str, Vec<u8>> = [
            ("account", ACCOUNT.as_bytes().to_vec()),
            ("password", PASSWORD.as_bytes().to_vec()),
            ("salt", SALT.to_vec()),
            ("iterations", ITERATIONS.to_be_bytes().to_vec()),
            ("a", a_secret()),
            ("b", b_secret()),
            ("password_key", v.password_key.to_vec()),
            ("A", v.a_pub.clone()),
            ("B", v.b_pub.clone()),
            ("M1", v.m1.clone()),
            ("M2", v.m2.clone()),
            ("K", v.k.clone()),
            ("spd_key", v.spd_key.to_vec()),
            ("spd_iv", v.spd_iv.to_vec()),
            ("spd_plaintext", v.spd_plaintext.clone()),
            ("spd_ciphertext", v.spd_ciphertext.clone()),
        ]
        .into_iter()
        .collect();
        for (name, bytes) in pairs {
            lines.push(format!("{name} = {}", super::hex(&bytes)));
        }
        lines.join("\n") + "\n"
    }

    /// Parses `name = hex` lines.
    pub fn parse(text: &str) -> BTreeMap<String, Vec<u8>> {
        text.lines()
            .filter(|l| !l.starts_with('#') && !l.trim().is_empty())
            .map(|l| {
                let (name, value) = l.split_once(" = ").expect("name = hex");
                (name.to_owned(), super::unhex(value.trim()))
            })
            .collect()
    }

    // GSA response bodies built from the vector -----------------------------

    pub fn plist_bytes(value: Value) -> Vec<u8> {
        let mut out = Vec::new();
        value.to_writer_xml(&mut out).unwrap();
        out
    }

    pub fn envelope(response: Dictionary) -> Value {
        let mut root = Dictionary::new();
        root.insert("Response".to_owned(), Value::Dictionary(response));
        Value::Dictionary(root)
    }

    pub fn status(ec: i64, em: &str, au: Option<&str>) -> Value {
        let mut status = Dictionary::new();
        if let Some(au) = au {
            status.insert("au".to_owned(), Value::String(au.to_owned()));
        }
        status.insert("ec".to_owned(), Value::Integer(ec.into()));
        status.insert("em".to_owned(), Value::String(em.to_owned()));
        Value::Dictionary(status)
    }

    pub fn init_response_dict(v: &Vector) -> Dictionary {
        let mut response = Dictionary::new();
        response.insert("B".to_owned(), Value::Data(v.b_pub.clone()));
        response.insert("Status".to_owned(), status(0, "", None));
        response.insert("c".to_owned(), Value::String(COOKIE.to_owned()));
        response.insert("i".to_owned(), Value::Integer(i64::from(ITERATIONS).into()));
        response.insert("s".to_owned(), Value::Data(SALT.to_vec()));
        response
    }

    pub fn complete_response_dict(v: &Vector, au: Option<&str>) -> Dictionary {
        let mut response = Dictionary::new();
        response.insert("M2".to_owned(), Value::Data(v.m2.clone()));
        response.insert("Status".to_owned(), status(0, "", au));
        response.insert("spd".to_owned(), Value::Data(v.spd_ciphertext.clone()));
        response
    }

    pub fn init_response(v: &Vector) -> Vec<u8> {
        plist_bytes(envelope(init_response_dict(v)))
    }

    pub fn init_response_error() -> Vec<u8> {
        let mut response = Dictionary::new();
        response.insert(
            "Status".to_owned(),
            status(
                -20101,
                "Synthetic: your Apple Account or password was incorrect.",
                None,
            ),
        );
        plist_bytes(envelope(response))
    }

    pub fn complete_response(v: &Vector, au: Option<&str>) -> Vec<u8> {
        plist_bytes(envelope(complete_response_dict(v, au)))
    }

    pub fn validate_ok() -> Vec<u8> {
        let mut root = Dictionary::new();
        root.insert("ec".to_owned(), Value::Integer(0.into()));
        root.insert("em".to_owned(), Value::String(String::new()));
        plist_bytes(Value::Dictionary(root))
    }

    pub fn validate_rejected() -> Vec<u8> {
        let mut root = Dictionary::new();
        root.insert("ec".to_owned(), Value::Integer((-21669).into()));
        root.insert(
            "em".to_owned(),
            Value::String("Synthetic: incorrect verification code.".to_owned()),
        );
        plist_bytes(Value::Dictionary(root))
    }
}
