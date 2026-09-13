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

//! One explicit legacy MobileMe delegate authentication exchange.
//!
//! This offline-tested subset exchanges an existing password-equivalent token
//! (PET) for distinct MME and CloudKit token owners. It does not establish live
//! compatibility, token lifetime, or permission to contact any returned URL.
//! Registration and consent effects remain unknown. See `DELEGATE.md`.

use crate::anisette::{self, AnisetteError, AnisetteProvider};
use crate::auth::Session;
use crate::secret::MAX_ACCOUNT_NAME_LEN;
use crate::tokens::{ResponseStage, TokenError, xml};
use crate::transport::{Method, Request, Transport, TransportError};
use base64::Engine as _;
use core::fmt;
use zeroize::{Zeroize, Zeroizing};

/// Maximum bytes in a caller-supplied client identifier.
pub const MAX_CLIENT_ID_LEN: usize = 256;
/// Maximum bytes in an input ADSID or returned DSID.
pub const MAX_IDENTIFIER_LEN: usize = 1024;
/// Maximum bytes in a PET, MME token, or CloudKit token.
pub const MAX_TOKEN_LEN: usize = 4096;
/// Maximum response bytes, also enforced by the shared XML parser.
pub const MAX_RESPONSE_BODY: usize = xml::MAX_BODY;

const ENDPOINT: &str = "https://setup.icloud.com/setup/iosbuddy/loginDelegates";
const USER_AGENT: &str = "com.apple.iCloudHelper/282 CFNetwork/1408.0.4 Darwin/22.5.0";
const CLIENT_INFO: &str =
    "<MacBookPro18,3> <Mac OS X;13.4.1;22F8> <com.apple.AOSKit/282 (com.apple.accountsd/113)>";

macro_rules! redacted {
    ($ty:ty, $name:literal) => {
        impl fmt::Debug for $ty {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(concat!($name, "(<redacted>)"))
            }
        }
    };
}

/// Fixed failure categories; no remote strings, codes, field names, or sources.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DelegateError {
    /// No PET was supplied; no provider or transport was called.
    MissingPet,
    /// Input failed the bounded printable-ASCII subset; no adapters were called.
    InvalidInput,
    /// Anisette generation or validation failed; nothing was sent.
    Anisette,
    /// Transport failed; issuance may have happened, and must not be retried.
    Transport,
    /// HTTP status was not exactly 200; the body was not decoded.
    Http,
    /// The XML document was malformed, including duplicate fields anywhere.
    Malformed,
    /// A required response field was missing or had an unsupported type/shape.
    Schema,
    /// A byte, scalar, element, or depth bound was exceeded.
    TooLarge,
    /// The response format is outside the XML-only subset.
    Unsupported,
    /// The root integer status was nonzero; no meaning is inferred from it.
    RootRejected,
    /// The delegate integer status was nonzero; no meaning is inferred from it.
    DelegateRejected,
}
impl fmt::Display for DelegateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::MissingPet => "delegate input lacks a password-equivalent token",
            Self::InvalidInput => "delegate input is invalid",
            Self::Anisette => "delegate anisette failed",
            Self::Transport => "delegate transport failed; issuance outcome may be unknown",
            Self::Http => "delegate HTTP response rejected",
            Self::Malformed => "delegate XML is malformed",
            Self::Schema => "delegate response schema is unsupported",
            Self::TooLarge => "delegate response exceeds a bound",
            Self::Unsupported => "delegate response format is unsupported",
            Self::RootRejected => "delegate root status rejected",
            Self::DelegateRejected => "delegate service status rejected",
        })
    }
}
impl std::error::Error for DelegateError {}

fn valid(value: &str, max: usize) -> bool {
    !value.is_empty() && value.len() <= max && value.bytes().all(|b| (0x20..=0x7e).contains(&b))
}

/// Validated borrow of a caller-owned stable client identifier.
///
/// No identifier is generated or derived from anisette. Its binding to local
/// provisioning is the caller's responsibility and remains live-unverified.
///
/// ```compile_fail
/// use coffer_protocol::delegate::ClientIdRef;
/// let id;
/// {
///     let owner = String::from("synthetic-client");
///     id = ClientIdRef::new(&owner).unwrap();
/// }
/// drop(id);
/// ```
pub struct ClientIdRef<'a>(&'a str);
impl<'a> ClientIdRef<'a> {
    /// Checks nonempty printable ASCII of at most [`MAX_CLIENT_ID_LEN`] bytes.
    ///
    /// # Errors
    /// Returns [`DelegateError::InvalidInput`] without allocating or doing I/O.
    pub fn new(value: &'a str) -> Result<Self, DelegateError> {
        if !valid(value, MAX_CLIENT_ID_LEN) {
            return Err(DelegateError::InvalidInput);
        }
        Ok(Self(value))
    }
}
redacted!(ClientIdRef<'_>, "ClientIdRef");

/// Validated, non-cloning borrow consumed by one explicit delegate call.
///
/// The caller owns and wipes the source material. The account name and PET are
/// used identically in Basic and XML, while ADSID is a separate header. No IdMS
/// or Xcode token substitution occurs. A validated constructor proves shape,
/// not authentication success.
///
/// This view cannot outlive its backing storage:
/// ```compile_fail
/// use coffer_protocol::delegate::{ClientIdRef, DelegateMaterialRef};
/// let input;
/// {
///     let pet = String::from("SYNTHETIC-PET");
///     input = DelegateMaterialRef::new("synthetic", "synthetic-adsid",
///         Some(&pet), ClientIdRef::new("synthetic-client").unwrap()).unwrap();
/// }
/// drop(input);
/// ```
pub struct DelegateMaterialRef<'a> {
    account: &'a str,
    adsid: &'a str,
    pet: &'a str,
    client_id: ClientIdRef<'a>,
}
impl<'a> DelegateMaterialRef<'a> {
    /// Borrows account, ADSID, and optional PET from an authenticated session.
    ///
    /// # Errors
    /// Uses exactly the same local checks and errors as [`Self::new`].
    pub fn from_session(
        session: &'a Session,
        client_id: ClientIdRef<'a>,
    ) -> Result<Self, DelegateError> {
        Self::new(
            session.account().as_str(),
            session.account_id().as_str(),
            session
                .password_equivalent_token()
                .map(|pet| pet.expose_secret()),
            client_id,
        )
    }

    /// Validates caller-provided material without copying it or authenticating.
    ///
    /// Account: 1–256 bytes without colon; ADSID: 1–1024 bytes; PET: 1–4096
    /// bytes. All are printable ASCII; spaces and PET colons are preserved.
    /// There is no encoding fallback or normalization.
    ///
    /// # Errors
    /// Returns [`DelegateError::MissingPet`] for `None`, otherwise
    /// [`DelegateError::InvalidInput`] for any invalid field. Both occur before
    /// an anisette provider or transport can be called.
    pub fn new(
        account: &'a str,
        adsid: &'a str,
        pet: Option<&'a str>,
        client_id: ClientIdRef<'a>,
    ) -> Result<Self, DelegateError> {
        let pet = pet.ok_or(DelegateError::MissingPet)?;
        if !valid(account, MAX_ACCOUNT_NAME_LEN)
            || account.contains(':')
            || !valid(adsid, MAX_IDENTIFIER_LEN)
            || !valid(pet, MAX_TOKEN_LEN)
        {
            return Err(DelegateError::InvalidInput);
        }
        Ok(Self {
            account,
            adsid,
            pet,
            client_id,
        })
    }
}
redacted!(DelegateMaterialRef<'_>, "DelegateMaterialRef");

/// A bounded MME authentication token, zeroized on drop.
///
/// This owner cannot be implicitly substituted for a [`CloudKitToken`].
/// No lifetime, reuse guarantee, or remote operation is attached to the value.
///
/// ```compile_fail
/// use coffer_protocol::delegate::{MmeAuthToken, CloudKitToken};
/// fn substitute(token: &MmeAuthToken) -> &CloudKitToken { token }
/// ```
pub struct MmeAuthToken(Zeroizing<String>);
impl MmeAuthToken {
    /// Explicitly borrows the secret; the borrow cannot outlive this owner.
    #[must_use]
    pub fn expose_secret(&self) -> &str {
        &self.0
    }
}
redacted!(MmeAuthToken, "MmeAuthToken");

/// A bounded CloudKit token, zeroized on drop, with no live access guarantee.
///
/// No clone, serialization, expiry inference, or automatic use is provided.
pub struct CloudKitToken(Zeroizing<String>);
impl CloudKitToken {
    /// Explicitly borrows the secret; the borrow cannot outlive this owner.
    ///
    /// ```compile_fail
    /// use coffer_protocol::delegate::CloudKitToken;
    /// fn escape(token: CloudKitToken) -> &'static str { token.expose_secret() }
    /// ```
    #[must_use]
    pub fn expose_secret(&self) -> &str {
        &self.0
    }
}
redacted!(CloudKitToken, "CloudKitToken");

/// Successful 0/0 response material; all owned strings are zeroized on drop.
///
/// Only a bounded string DSID is accepted, preserved without numeric conversion.
/// Unknown fields and other tokens are validated and discarded before return.
pub struct DelegateCredentials {
    dsid: Zeroizing<String>,
    mme: MmeAuthToken,
    cloudkit: CloudKitToken,
}
impl DelegateCredentials {
    /// Borrows the private identifier exactly as decoded from the XML string.
    #[must_use]
    pub fn dsid(&self) -> &str {
        &self.dsid
    }
    /// Borrows the distinct MME token owner.
    #[must_use]
    pub fn mme_auth_token(&self) -> &MmeAuthToken {
        &self.mme
    }
    /// Borrows the distinct CloudKit token owner.
    #[must_use]
    pub fn cloudkit_token(&self) -> &CloudKitToken {
        &self.cloudkit
    }
}
redacted!(DelegateCredentials, "DelegateCredentials");

/// Borrows existing adapters for explicit, single-exchange authentication.
///
/// No concrete transport, provisioning, storage, login, renewal, settings,
/// trust, recovery, or redirect handling is supplied. Adapters must honor
/// their existing no-retry and local-only contracts.
pub struct DelegateClient<'a, T, A> {
    transport: &'a T,
    anisette: &'a A,
}
impl<'a, T: Transport, A: AnisetteProvider> DelegateClient<'a, T, A> {
    /// Borrows adapters without performing I/O.
    pub fn new(transport: &'a T, anisette: &'a A) -> Self {
        Self {
            transport,
            anisette,
        }
    }

    /// Consumes a validated borrow and sends at most one fixed-endpoint POST.
    ///
    /// This is an authentication issuance action with unknown registration and
    /// consent effects. Nothing is automatically retried, even after timeout.
    /// A failed or cancelled exchange may already have issued credentials.
    ///
    /// # Errors
    /// Returns fixed [`DelegateError`] categories; adapter/parser errors are
    /// discarded without chaining arbitrary strings. HTTP 200 alone is not
    /// success: the entire XML must be valid and both integer statuses zero.
    pub async fn issue(
        &self,
        input: DelegateMaterialRef<'_>,
    ) -> Result<DelegateCredentials, DelegateError> {
        let anisette = self.anisette.anisette().await.map_err(|mut error| {
            if let AnisetteError::Unavailable { detail } = &mut error {
                detail.zeroize();
            }
            DelegateError::Anisette
        })?;
        anisette.validate().map_err(|_| DelegateError::Anisette)?;
        let request = request(&input, &anisette);
        drop(anisette);
        let response =
            self.transport
                .send(request)
                .await
                .map_err(|mut error| match &mut error {
                    TransportError::Connect { detail }
                    | TransportError::Tls { detail }
                    | TransportError::Other { detail } => {
                        detail.zeroize();
                        DelegateError::Transport
                    }
                    TransportError::ResponseTooLarge { .. } => DelegateError::TooLarge,
                    _ => DelegateError::Transport,
                })?;
        if response.status() != 200 {
            return Err(DelegateError::Http);
        }
        decode(response.body())
    }
}
impl<T, A> fmt::Debug for DelegateClient<'_, T, A> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DelegateClient(<redacted>)")
    }
}

fn request(input: &DelegateMaterialRef<'_>, data: &anisette::AnisetteData) -> Request {
    // Upper bounds prevent reallocations after secret bytes have been written.
    let mut pair = Zeroizing::new(String::with_capacity(
        input.account.len() + 1 + input.pet.len(),
    ));
    pair.push_str(input.account);
    pair.push(':');
    pair.push_str(input.pet);
    let mut basic = Zeroizing::new(String::with_capacity(6 + pair.len().div_ceil(3) * 4));
    basic.push_str("Basic ");
    base64::engine::general_purpose::STANDARD.encode_string(pair.as_bytes(), &mut basic);
    let mut body = Zeroizing::new(Vec::with_capacity(
        512 + 6 * (input.account.len() + input.pet.len() + input.client_id.0.len()),
    ));
    body.extend_from_slice(
        b"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<plist version=\"1.0\"><dict>",
    );
    for (key, value) in [("apple-id", input.account), ("password", input.pet)] {
        string_entry(&mut body, key, value);
    }
    body.extend_from_slice(
        b"<key>delegates</key><dict><key>com.apple.mobileme</key><dict/></dict>",
    );
    string_entry(&mut body, "client-id", input.client_id.0);
    body.extend_from_slice(b"</dict></plist>\n");
    let mut headers = Vec::with_capacity(15);
    for (name, value) in [
        ("Content-Type", "text/xml"),
        ("User-Agent", USER_AGENT),
        ("X-Mme-Client-Info", CLIENT_INFO),
        ("X-Apple-ADSID", input.adsid),
    ] {
        headers.push((name.to_owned(), Zeroizing::new(value.to_owned())));
    }
    headers.push(("Authorization".to_owned(), basic));
    for (name, value) in data.entries() {
        if name != anisette::CLIENT_INFO_HEADER {
            headers.push((name.to_owned(), Zeroizing::new(value.to_owned())));
        }
    }
    headers.push(("loc".to_owned(), Zeroizing::new(data.locale.clone())));
    Request {
        method: Method::Post,
        url: ENDPOINT.to_owned(),
        headers,
        body: Some(body),
        max_response_body: MAX_RESPONSE_BODY,
    }
}

fn string_entry(out: &mut Vec<u8>, key: &str, value: &str) {
    out.extend_from_slice(b"<key>");
    out.extend_from_slice(key.as_bytes()); // Only static, Coffer-owned keys.
    out.extend_from_slice(b"</key><string>");
    for byte in value.bytes() {
        // Inputs are already printable ASCII.
        match byte {
            b'&' => out.extend_from_slice(b"&amp;"),
            b'<' => out.extend_from_slice(b"&lt;"),
            b'>' => out.extend_from_slice(b"&gt;"),
            b'\"' => out.extend_from_slice(b"&quot;"),
            b'\'' => out.extend_from_slice(b"&apos;"),
            _ => out.push(byte),
        }
    }
    out.extend_from_slice(b"</string>");
}

fn decode(bytes: &[u8]) -> Result<DelegateCredentials, DelegateError> {
    let root = xml::parse_at(bytes, ResponseStage::OuterPlist).map_err(|error| match error {
        TokenError::TooLarge => DelegateError::TooLarge,
        TokenError::Unsupported => DelegateError::Unsupported,
        _ => DelegateError::Malformed,
    })?;
    let schema = |_| DelegateError::Schema;
    let status = root
        .get("status")
        .map_err(schema)?
        .integer()
        .map_err(schema)?;
    if status != 0 {
        return Err(DelegateError::RootRejected);
    }
    let delegate = root
        .get("delegates")
        .map_err(schema)?
        .get("com.apple.mobileme")
        .map_err(schema)?;
    let status = delegate
        .get("status")
        .map_err(schema)?
        .integer()
        .map_err(schema)?;
    if status != 0 {
        return Err(DelegateError::DelegateRejected);
    }
    let dsid = root.get("dsid").map_err(schema)?.text().map_err(schema)?;
    let tokens = delegate
        .get("service-data")
        .map_err(schema)?
        .get("tokens")
        .map_err(schema)?;
    let mme = tokens
        .get("mmeAuthToken")
        .map_err(schema)?
        .text()
        .map_err(schema)?;
    let cloudkit = tokens
        .get("cloudKitToken")
        .map_err(schema)?
        .text()
        .map_err(schema)?;
    if !valid(dsid, MAX_IDENTIFIER_LEN)
        || !valid(mme, MAX_TOKEN_LEN)
        || !valid(cloudkit, MAX_TOKEN_LEN)
    {
        return Err(DelegateError::Schema);
    }
    Ok(DelegateCredentials {
        dsid: Zeroizing::new(dsid.to_owned()),
        mme: MmeAuthToken(Zeroizing::new(mme.to_owned())),
        cloudkit: CloudKitToken(Zeroizing::new(cloudkit.to_owned())),
    })
}

#[cfg(test)]
mod tests {
    #[test]
    fn accepts_synthetic_two_level_success() {
        assert!(super::decode(include_bytes!("../tests/fixtures/delegate/success.plist")).is_ok());
    }
}
