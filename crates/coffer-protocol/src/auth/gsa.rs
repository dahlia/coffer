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

//! GSA wire format: request construction and bounded response parsing.
//!
//! GSA (GrandSlam Authentication) speaks XML property lists over HTTPS.  A
//! request body is `{Header: {Version: "1.0.1"}, Request: {...}}` and a
//! response body is `{Response: {..., Status: {ec, em, ...}}}`.  The
//! two-factor endpoints reuse the anisette headers plus an identity token.
//!
//! # Provenance
//!
//! Endpoint URLs, header names, dictionary keys, and the fixed `cpd`
//! entries are protocol facts observed on the wire and corroborated against
//! SideStore's MPL-2.0 `icloud-auth` implementation.  Only the facts were
//! taken; the code here is independent.  Where this crate deliberately
//! departs from what that implementation sends, the difference is noted at
//! the point of use.
//!
//! # Bounds
//!
//! Every response is untrusted input.  The body is size-capped before it is
//! parsed, and every field that is read has its length or range checked
//! against [`ResponseLimits`] before it is used.

use std::io::Cursor;

use base64::Engine as _;
use plist::{Dictionary, Value};
use zeroize::Zeroizing;

use super::error::{AuthErrorKind, Malformed, MalformedReason, ProtocolStatus};
use crate::anisette::AnisetteData;
use crate::secret::{AccountId, AccountName, IdmsToken, VerificationCode};
use crate::transport::{Method, Request};

/// The GSA service endpoint for the password exchange.
pub const GSA_ENDPOINT: &str = "https://gsa.apple.com/grandslam/GsService2";
/// The endpoint that validates a trusted-device verification code.
pub const VALIDATE_ENDPOINT: &str = "https://gsa.apple.com/grandslam/GsService2/validate";
/// The endpoint that pushes a verification code to the trusted devices.
pub const TRUSTED_DEVICE_ENDPOINT: &str = "https://gsa.apple.com/auth/verify/trusteddevice";

/// The only SRP password protocol this crate implements.
///
/// `s2k` derives the SRP password from `PBKDF2-HMAC-SHA256(SHA-256(password),
/// salt, iterations)`.  The request also advertises `s2k_fo`, as observed
/// clients do, but if the server selects it the exchange stops with
/// [`AuthErrorKind::UnsupportedProtocol`].
pub const SUPPORTED_PROTOCOL: &str = "s2k";

const ADVERTISED_PROTOCOLS: [&str; 2] = ["s2k", "s2k_fo"];
const HEADER_VERSION: &str = "1.0.1";
const GSA_USER_AGENT: &str = "akd/1.0 CFNetwork/978.0.7 Darwin/18.7.0";
const PLIST_CONTENT_TYPE: &str = "text/x-xml-plist";
const SECOND_FACTOR_USER_AGENT: &str = "Xcode";
const SECOND_FACTOR_APP_INFO: &str = "com.apple.gs.xcode.auth";
const SECOND_FACTOR_XCODE_VERSION: &str = "11.2 (11B41)";
const SECOND_FACTOR_ACCEPT_LANGUAGE: &str = "en-us";

/// Trusted-device secondary authentication, the only `au` value this crate
/// handles.
pub(crate) const TRUSTED_DEVICE_AU: &str = "trustedDeviceSecondaryAuth";

/// Size and range limits applied to every GSA response.
///
/// The defaults are generous relative to observed traffic (a complete
/// response is a few kilobytes, the PBKDF2 iteration count has been observed
/// around twenty thousand) while keeping a malicious or broken server from
/// forcing large allocations or unbounded work.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResponseLimits {
    /// Maximum response body size in bytes.  Default: 1 MiB.
    pub max_body: usize,
    /// Maximum SRP salt length in bytes.  Default: 64.
    pub max_salt: usize,
    /// Maximum SRP public value (`B`) length in bytes.  Default: 256, the
    /// size of the 2048-bit group modulus.
    pub max_public_value: usize,
    /// Maximum PBKDF2 iteration count.  Default: 1 048 576.
    pub max_iterations: u32,
    /// Maximum length of the opaque `c` cookie, in bytes.  Default: 4096.
    pub max_cookie: usize,
    /// Maximum length of the encrypted server-provided data `spd`, in
    /// bytes.  Default: 64 KiB.
    pub max_encrypted_data: usize,
    /// Maximum length of any string field copied out of a response, in
    /// bytes.  Default: 1024.
    pub max_string: usize,
    /// Maximum length kept from a server error message, in bytes.
    /// Default: 256.
    pub max_message: usize,
    /// Maximum number of per-service tokens accepted from `spd`.  Default:
    /// 64.
    pub max_tokens: usize,
    /// Maximum number of XML elements in any property list, counted before
    /// parsing.  Default: 512.
    ///
    /// This bounds nesting depth as well, which matters because dropping a
    /// deeply nested `plist::Value` recurses once per level and would
    /// otherwise let a server exhaust the stack with a body well under
    /// `max_body`.  Every element start is counted, whatever its name, so
    /// the bound does not depend on how the parser resolves element names.
    pub max_elements: usize,
}

impl Default for ResponseLimits {
    fn default() -> Self {
        Self {
            max_body: 1024 * 1024,
            max_salt: 64,
            max_public_value: 256,
            max_iterations: 1 << 20,
            max_cookie: 4096,
            max_encrypted_data: 64 * 1024,
            max_string: 1024,
            max_message: 256,
            max_tokens: 64,
            max_elements: 512,
        }
    }
}

/// Size in bytes of the 2048-bit SRP group modulus.
///
/// `B` can never legitimately exceed this, and the `srp` crate panics rather
/// than erroring when asked to fit a wider value into the group, so the bound
/// is enforced regardless of [`ResponseLimits::max_public_value`].
const SRP_GROUP_BYTES: usize = 256;

// Request construction ------------------------------------------------------

fn header(name: &str, value: &str) -> (String, Zeroizing<String>) {
    (name.to_owned(), Zeroizing::new(value.to_owned()))
}

/// Headers shared by the two GSA password-exchange requests.
fn gsa_headers(anisette: &AnisetteData) -> Vec<(String, Zeroizing<String>)> {
    vec![
        header("Content-Type", PLIST_CONTENT_TYPE),
        header("Accept", "*/*"),
        header("User-Agent", GSA_USER_AGENT),
        // The header name is spelled `X-MMe-Client-Info` on this endpoint,
        // matching observed traffic; HTTP header names are case-insensitive.
        header("X-MMe-Client-Info", &anisette.client_info),
    ]
}

/// Builds the `cpd` (client-provided data) dictionary.
///
/// It carries the anisette values, minus the client-info string, which
/// travels in the HTTP header instead, plus a fixed set of capability flags
/// observed on the wire.  Keys are sorted so the serialization is
/// deterministic.
fn cpd(anisette: &AnisetteData) -> Dictionary {
    let mut dict = Dictionary::new();
    for (name, value) in anisette.entries() {
        if name == crate::anisette::CLIENT_INFO_HEADER {
            continue;
        }
        dict.insert(name.to_owned(), Value::String(value.to_owned()));
    }
    dict.insert("bootstrap".to_owned(), Value::String("true".to_owned()));
    dict.insert("icscrec".to_owned(), Value::String("true".to_owned()));
    // The observed implementation hardcodes `en_GB` here while sending
    // `en_US` as the locale header.  Coffer sends the provider's locale in
    // both places.
    dict.insert("loc".to_owned(), Value::String(anisette.locale.clone()));
    dict.insert("pbe".to_owned(), Value::String("false".to_owned()));
    dict.insert("prkgen".to_owned(), Value::String("true".to_owned()));
    dict.insert("svct".to_owned(), Value::String("iCloud".to_owned()));
    dict.sort_keys();
    dict
}

/// Wraps a request dictionary in the GSA envelope and serializes it.
fn envelope(mut request: Dictionary) -> Result<Zeroizing<Vec<u8>>, AuthErrorKind> {
    request.sort_keys();
    let mut head = Dictionary::new();
    head.insert(
        "Version".to_owned(),
        Value::String(HEADER_VERSION.to_owned()),
    );
    let mut root = Dictionary::new();
    root.insert("Header".to_owned(), Value::Dictionary(head));
    root.insert("Request".to_owned(), Value::Dictionary(request));
    // The tree holds the anisette attestation values, so it is wiped after
    // serialization rather than simply dropped.
    let mut root = Value::Dictionary(root);
    let mut buffer = Zeroizing::new(Vec::new());
    let result = root.to_writer_xml(&mut *buffer);
    wipe_tree(&mut root);
    result.map_err(|_| AuthErrorKind::Internal {
        detail: "request property list could not be serialized",
    })?;
    Ok(buffer)
}

/// Zeroizes every string and data value in a property-list tree in place.
///
/// The walk is iterative, so it is safe for trees as deep as
/// [`ResponseLimits::max_elements`] allows.  Dictionary keys are not wiped;
/// they are field names, not values.
pub(crate) fn wipe_tree(root: &mut Value) {
    let mut stack = vec![root];
    while let Some(value) = stack.pop() {
        match value {
            Value::Array(items) => stack.extend(items.iter_mut()),
            Value::Dictionary(dict) => stack.extend(dict.values_mut()),
            Value::String(s) => crate::secret::wipe_string(s),
            Value::Data(bytes) => crate::secret::wipe(bytes),
            _ => {}
        }
    }
}

/// Builds the `o = init` request carrying the client's SRP public value.
pub(crate) fn init_request(
    anisette: &AnisetteData,
    account: &AccountName,
    a_pub: &[u8],
    limits: &ResponseLimits,
) -> Result<Request, AuthErrorKind> {
    let mut request = Dictionary::new();
    request.insert("A2k".to_owned(), Value::Data(a_pub.to_vec()));
    request.insert("cpd".to_owned(), Value::Dictionary(cpd(anisette)));
    request.insert("o".to_owned(), Value::String("init".to_owned()));
    request.insert(
        "ps".to_owned(),
        Value::Array(
            ADVERTISED_PROTOCOLS
                .iter()
                .map(|p| Value::String((*p).to_owned()))
                .collect(),
        ),
    );
    request.insert("u".to_owned(), Value::String(account.as_str().to_owned()));
    Ok(Request {
        method: Method::Post,
        url: GSA_ENDPOINT.to_owned(),
        headers: gsa_headers(anisette),
        body: Some(envelope(request)?),
        max_response_body: limits.max_body,
    })
}

/// Builds the `o = complete` request carrying the client proof `M1`.
pub(crate) fn complete_request(
    anisette: &AnisetteData,
    account: &AccountName,
    m1: &[u8],
    cookie: &str,
    limits: &ResponseLimits,
) -> Result<Request, AuthErrorKind> {
    let mut request = Dictionary::new();
    request.insert("M1".to_owned(), Value::Data(m1.to_vec()));
    request.insert("c".to_owned(), Value::String(cookie.to_owned()));
    request.insert("cpd".to_owned(), Value::Dictionary(cpd(anisette)));
    request.insert("o".to_owned(), Value::String("complete".to_owned()));
    request.insert("u".to_owned(), Value::String(account.as_str().to_owned()));
    Ok(Request {
        method: Method::Post,
        url: GSA_ENDPOINT.to_owned(),
        headers: gsa_headers(anisette),
        body: Some(envelope(request)?),
        max_response_body: limits.max_body,
    })
}

/// Computes the `X-Apple-Identity-Token` value: `base64(adsid ":" token)`.
pub(crate) fn identity_token(account_id: &AccountId, token: &IdmsToken) -> Zeroizing<String> {
    let joined = Zeroizing::new(format!("{}:{}", account_id.as_str(), token.expose_secret()));
    Zeroizing::new(base64::engine::general_purpose::STANDARD.encode(joined.as_bytes()))
}

/// Headers shared by the two-factor endpoints.
fn second_factor_headers(
    anisette: &AnisetteData,
    identity_token: &str,
) -> Vec<(String, Zeroizing<String>)> {
    let mut headers: Vec<(String, Zeroizing<String>)> = anisette
        .entries()
        .iter()
        .map(|(name, value)| header(name, value))
        .collect();
    headers.push(header("X-Apple-App-Info", SECOND_FACTOR_APP_INFO));
    headers.push(header("X-Xcode-Version", SECOND_FACTOR_XCODE_VERSION));
    headers.push(header("Content-Type", PLIST_CONTENT_TYPE));
    headers.push(header("Accept", PLIST_CONTENT_TYPE));
    headers.push(header("User-Agent", SECOND_FACTOR_USER_AGENT));
    headers.push(header("Accept-Language", SECOND_FACTOR_ACCEPT_LANGUAGE));
    headers.push(header("X-Apple-Identity-Token", identity_token));
    headers.push(header("Loc", &anisette.locale));
    headers
}

/// Builds the request that pushes a verification code to trusted devices.
pub(crate) fn trusted_device_request(
    anisette: &AnisetteData,
    identity_token: &str,
    limits: &ResponseLimits,
) -> Request {
    Request {
        method: Method::Get,
        url: TRUSTED_DEVICE_ENDPOINT.to_owned(),
        headers: second_factor_headers(anisette, identity_token),
        body: None,
        max_response_body: limits.max_body,
    }
}

/// Builds the request that submits a verification code.
pub(crate) fn validate_request(
    anisette: &AnisetteData,
    identity_token: &str,
    code: &VerificationCode,
    limits: &ResponseLimits,
) -> Request {
    let mut headers = second_factor_headers(anisette, identity_token);
    headers.push(header("security-code", code.as_str()));
    Request {
        method: Method::Get,
        url: VALIDATE_ENDPOINT.to_owned(),
        headers,
        body: None,
        max_response_body: limits.max_body,
    }
}

// Response parsing ----------------------------------------------------------

/// Parses a response body into its root dictionary, enforcing the body cap.
pub(crate) fn parse_body(body: &[u8], limits: &ResponseLimits) -> Result<Dictionary, Malformed> {
    if body.len() > limits.max_body {
        return Err(Malformed::new(
            "body",
            MalformedReason::TooLong {
                limit: limits.max_body,
            },
        ));
    }
    parse_plist(body, "body", limits)
}

/// Parses an XML property list whose root is a dictionary.
///
/// Only the XML form is accepted; GSA answers with `text/x-xml-plist`, and
/// accepting the binary form would add a second parser to audit.  Before
/// parsing, the bytes are scanned for the number of `<array>` and `<dict>`
/// elements, which bounds both the size of the tree and its depth.  Without
/// that bound a body of a few hundred kilobytes could nest tens of thousands
/// of arrays; `plist` builds such a tree iteratively, but dropping it recurses
/// once per level and overflows the stack.
pub(crate) fn parse_plist(
    bytes: &[u8],
    field: &'static str,
    limits: &ResponseLimits,
) -> Result<Dictionary, Malformed> {
    if count_elements(bytes) > limits.max_elements {
        return Err(Malformed::new(
            field,
            MalformedReason::TooComplex {
                limit: limits.max_elements,
            },
        ));
    }
    Value::from_reader_xml(Cursor::new(bytes))
        .map_err(|_| Malformed::new(field, MalformedReason::NotPlist))?
        .into_dictionary()
        .ok_or_else(|| Malformed::new(field, MalformedReason::NotDictionary))
}

/// Counts possible XML element starts: every `<` that does not begin an end
/// tag (`</`), a processing instruction (`<?`), or a declaration (`<!`).
///
/// No assumption is made about what the parser accepts as a name: a `<`
/// followed by a letter, a digit, a non-ASCII byte, or anything else is
/// counted.  The count is therefore an upper bound on the number of
/// collections the parser can build no matter how it resolves names
/// (`plist` matches local names, which makes `<p:array>` a collection too).
/// The scan is deliberately naive: a `<` inside a comment or CDATA section is
/// counted as well, which can only reject a document, never accept one the
/// parser would nest deeper than counted.
fn count_elements(bytes: &[u8]) -> usize {
    bytes
        .iter()
        .enumerate()
        .filter(|&(i, &b)| b == b'<' && !matches!(bytes.get(i + 1), Some(b'/' | b'?' | b'!')))
        .count()
}

/// Extracts the `Response` dictionary of a GSA envelope.
pub(crate) fn response_section(root: &Dictionary) -> Result<&Dictionary, Malformed> {
    get_dictionary(root, "Response")
}

/// The parsed `Status` dictionary.
#[derive(Debug)]
pub(crate) struct Status {
    /// The `ec` error code; zero means success.
    pub code: i64,
    /// The `em` message, truncated.
    pub message: String,
    /// The `au` secondary-authentication request, if any.
    pub secondary_auth: Option<String>,
}

/// Parses the `Status` dictionary.
///
/// The password-exchange responses nest `Status` inside `Response`; the
/// validate endpoint returns the fields at the top level.  Both shapes are
/// accepted: if `dict` has a `Status` dictionary it is used, otherwise
/// `dict` itself must carry `ec`.
pub(crate) fn parse_status(
    dict: &Dictionary,
    limits: &ResponseLimits,
) -> Result<Status, Malformed> {
    let status = match dict.get("Status") {
        Some(Value::Dictionary(status)) => status,
        Some(_) => return Err(Malformed::new("Status", MalformedReason::WrongType)),
        None => dict,
    };
    let code = get_integer(status, "ec")?;
    let message = match status.get("em") {
        None => String::new(),
        Some(Value::String(s)) => sanitize_message(s, limits.max_message),
        Some(_) => return Err(Malformed::new("em", MalformedReason::WrongType)),
    };
    let secondary_auth = match status.get("au") {
        None => None,
        Some(Value::String(s)) => Some(bounded_string(s, "au", limits)?),
        Some(_) => return Err(Malformed::new("au", MalformedReason::WrongType)),
    };
    Ok(Status {
        code,
        message,
        secondary_auth,
    })
}

impl Status {
    /// Converts a non-zero status into a protocol error.
    pub(crate) fn into_result(self) -> Result<Option<String>, ProtocolStatus> {
        if self.code == 0 {
            Ok(self.secondary_auth)
        } else {
            Err(ProtocolStatus::new(self.code, self.message))
        }
    }
}

/// The fields of a successful `init` response.
pub(crate) struct InitResponse {
    /// SRP salt `s`.
    pub salt: Vec<u8>,
    /// SRP server public value `B`.
    pub b_pub: Vec<u8>,
    /// PBKDF2 iteration count `i`.
    pub iterations: u32,
    /// Opaque cookie `c`, echoed in the `complete` request.
    pub cookie: String,
    /// Server-selected password protocol `sp`, if present.
    pub protocol: Option<String>,
}

/// Parses the `Response` dictionary of an `init` reply.
pub(crate) fn parse_init(
    response: &Dictionary,
    limits: &ResponseLimits,
) -> Result<InitResponse, Malformed> {
    let salt = get_data(response, "s", limits.max_salt)?;
    if salt.is_empty() {
        return Err(Malformed::new(
            "s",
            MalformedReason::TooShort { minimum: 1 },
        ));
    }
    let b_pub = get_data(response, "B", limits.max_public_value.min(SRP_GROUP_BYTES))?;
    if b_pub.is_empty() {
        return Err(Malformed::new(
            "B",
            MalformedReason::TooShort { minimum: 1 },
        ));
    }
    let iterations = get_integer(response, "i")?;
    let iterations = u32::try_from(iterations)
        .ok()
        .filter(|i| (1..=limits.max_iterations).contains(i))
        .ok_or_else(|| Malformed::new("i", MalformedReason::OutOfRange))?;
    let cookie = get_string(response, "c", limits.max_cookie)?;
    let protocol = match response.get("sp") {
        None => None,
        Some(Value::String(s)) => Some(bounded_string(s, "sp", limits)?),
        Some(_) => return Err(Malformed::new("sp", MalformedReason::WrongType)),
    };
    Ok(InitResponse {
        salt: salt.to_vec(),
        b_pub: b_pub.to_vec(),
        iterations,
        cookie,
        protocol,
    })
}

/// The fields of a successful `complete` response, before decryption.
pub(crate) struct CompleteResponse {
    /// Server proof `M2`.
    pub m2: [u8; 32],
    /// Encrypted server-provided data `spd`.
    pub encrypted_data: Vec<u8>,
}

/// Parses the `Response` dictionary of a `complete` reply.
pub(crate) fn parse_complete(
    response: &Dictionary,
    limits: &ResponseLimits,
) -> Result<CompleteResponse, Malformed> {
    let m2 = get_data(response, "M2", 32)?;
    let m2: [u8; 32] = m2
        .try_into()
        .map_err(|_| Malformed::new("M2", MalformedReason::WrongLength { expected: 32 }))?;
    let encrypted_data = get_data(response, "spd", limits.max_encrypted_data)?;
    if encrypted_data.is_empty() {
        return Err(Malformed::new(
            "spd",
            MalformedReason::TooShort { minimum: 16 },
        ));
    }
    if encrypted_data.len() % 16 != 0 {
        return Err(Malformed::new("spd", MalformedReason::BadBlockLength));
    }
    Ok(CompleteResponse {
        m2,
        encrypted_data: encrypted_data.to_vec(),
    })
}

// Field helpers -------------------------------------------------------------

pub(crate) fn get_dictionary<'a>(
    dict: &'a Dictionary,
    key: &'static str,
) -> Result<&'a Dictionary, Malformed> {
    match dict.get(key) {
        Some(Value::Dictionary(d)) => Ok(d),
        Some(_) => Err(Malformed::new(key, MalformedReason::WrongType)),
        None => Err(Malformed::new(key, MalformedReason::Missing)),
    }
}

pub(crate) fn get_data<'a>(
    dict: &'a Dictionary,
    key: &'static str,
    max: usize,
) -> Result<&'a [u8], Malformed> {
    match dict.get(key) {
        Some(Value::Data(d)) => {
            if d.len() > max {
                Err(Malformed::new(key, MalformedReason::TooLong { limit: max }))
            } else {
                Ok(d)
            }
        }
        Some(_) => Err(Malformed::new(key, MalformedReason::WrongType)),
        None => Err(Malformed::new(key, MalformedReason::Missing)),
    }
}

pub(crate) fn get_string(
    dict: &Dictionary,
    key: &'static str,
    max: usize,
) -> Result<String, Malformed> {
    match dict.get(key) {
        Some(Value::String(s)) => {
            if s.len() > max {
                Err(Malformed::new(key, MalformedReason::TooLong { limit: max }))
            } else {
                Ok(s.clone())
            }
        }
        Some(_) => Err(Malformed::new(key, MalformedReason::WrongType)),
        None => Err(Malformed::new(key, MalformedReason::Missing)),
    }
}

pub(crate) fn get_integer(dict: &Dictionary, key: &'static str) -> Result<i64, Malformed> {
    match dict.get(key) {
        Some(Value::Integer(i)) => i
            .as_signed()
            .ok_or_else(|| Malformed::new(key, MalformedReason::OutOfRange)),
        Some(_) => Err(Malformed::new(key, MalformedReason::WrongType)),
        None => Err(Malformed::new(key, MalformedReason::Missing)),
    }
}

fn bounded_string(
    s: &str,
    key: &'static str,
    limits: &ResponseLimits,
) -> Result<String, Malformed> {
    if s.len() > limits.max_string {
        Err(Malformed::new(
            key,
            MalformedReason::TooLong {
                limit: limits.max_string,
            },
        ))
    } else {
        Ok(s.to_owned())
    }
}

/// Strips control characters from a server message and truncates it.
///
/// Newlines and escape sequences are removed so that a message rendered in a
/// terminal or a log line cannot forge additional lines or colours.
fn sanitize_message(s: &str, max: usize) -> String {
    let cleaned: String = s.chars().filter(|c| !c.is_control()).collect();
    truncate(&cleaned, max)
}

/// Truncates `s` to at most `max` bytes on a character boundary.
fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_owned();
    }
    let mut end = max;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    s[..end].to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn truncate_respects_char_boundaries() {
        assert_eq!(truncate("abc", 5), "abc");
        assert_eq!(truncate("abcdef", 3), "abc");
        // 'é' is two bytes; cutting at byte 2 must not split it.
        assert_eq!(truncate("aéb", 2), "a");
    }

    #[test]
    fn status_falls_back_to_top_level() {
        let mut dict = Dictionary::new();
        dict.insert("ec".to_owned(), Value::Integer(0.into()));
        let status = parse_status(&dict, &ResponseLimits::default()).unwrap();
        assert_eq!(status.code, 0);
        assert!(status.message.is_empty());
        assert!(status.secondary_auth.is_none());
    }

    #[test]
    fn status_requires_ec() {
        let dict = Dictionary::new();
        let err = parse_status(&dict, &ResponseLimits::default()).unwrap_err();
        assert_eq!(err.field(), "ec");
        assert_eq!(err.reason(), MalformedReason::Missing);
    }

    #[test]
    fn sanitize_message_strips_control_characters() {
        assert_eq!(
            sanitize_message("line1\r\nline2\u{1b}[31m red", 100),
            "line1line2[31m red"
        );
        assert_eq!(sanitize_message("abcdef", 3), "abc");
    }

    #[test]
    fn element_count_matches_start_tags() {
        assert_eq!(count_elements(b"<dict><key>a</key><array/></dict>"), 3);
        assert_eq!(count_elements(b"<p:array><_x><array\n>"), 3);
        assert_eq!(count_elements("<1:array><é:array>< a>".as_bytes()), 3);
        assert_eq!(count_elements(b"<?xml?><!DOCTYPE x></x><!-- c -->"), 0);
        assert_eq!(count_elements(b"<"), 1);
        assert_eq!(count_elements(b""), 0);
    }

    #[test]
    fn binary_plist_is_rejected() {
        let mut out = Vec::new();
        Value::Dictionary(Dictionary::new())
            .to_writer_binary(&mut out)
            .unwrap();
        let err = parse_body(&out, &ResponseLimits::default()).unwrap_err();
        assert_eq!(err.reason(), MalformedReason::NotPlist);
    }

    #[test]
    fn oversized_body_is_rejected_before_parsing() {
        let limits = ResponseLimits {
            max_body: 4,
            ..ResponseLimits::default()
        };
        let err = parse_body(b"<plist", &limits).unwrap_err();
        assert_eq!(err.reason(), MalformedReason::TooLong { limit: 4 });
    }
}
