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

//! One explicit service-token exchange using existing GSA session material.
//!
//! This is authentication token issuance, not CloudKit access. No password,
//! login, storage, provisioning, renewal, or retry is performed here. See
//! `SERVICE_TOKENS.md` for the offline evidence and deliberate XML-only scope.

use crate::anisette::AnisetteProvider;
use crate::transport::{Transport, TransportError};
use core::fmt;
use std::time::{SystemTime, UNIX_EPOCH};
use zeroize::{Zeroize, Zeroizing};

mod wire;
mod xml;

/// The only independently evidenced service in this initial implementation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Service {
    /// Xcode authentication (`com.apple.gs.xcode.auth`), not CloudKit.
    XcodeAuthentication,
}
impl Service {
    /// The exact service identifier used in the request and checksum.
    #[must_use]
    pub const fn identifier(self) -> &'static str {
        match self {
            Self::XcodeAuthentication => "com.apple.gs.xcode.auth",
        }
    }
}

/// A validated borrow of the four persisted GSA fields, with no account name.
///
/// The caller owns and zeroizes the underlying material. The view cannot
/// outlive that owner and is consumed by one explicit issuance call.
pub struct SessionMaterialRef<'a> {
    account: &'a str,
    idms: &'a str,
    key: &'a [u8; 32],
    cookie: &'a [u8],
}
impl<'a> SessionMaterialRef<'a> {
    /// Validates existing session fields without copying secrets.
    ///
    /// # Errors
    /// Returns [`TokenError::InvalidSession`] for empty/oversized strings or
    /// cookies, invalid XML characters/control characters, or a non-32-byte key.
    pub fn new(
        account: &'a str,
        idms: &'a str,
        key: &'a [u8],
        cookie: &'a [u8],
    ) -> Result<Self, TokenError> {
        let valid = |s: &str| {
            !s.is_empty()
                && s.len() <= 1024
                && s.chars().all(|c| !c.is_control() && xml::valid_char(c))
        };
        if !valid(account) || !valid(idms) || cookie.is_empty() || cookie.len() > 4096 {
            return Err(TokenError::InvalidSession);
        }
        Ok(Self {
            account,
            idms,
            key: key.try_into().map_err(|_| TokenError::InvalidSession)?,
            cookie,
        })
    }
}
impl fmt::Debug for SessionMaterialRef<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SessionMaterialRef(<redacted>)")
    }
}

/// Checked nonnegative Unix epoch milliseconds, within the wire's signed range.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct EpochMillis(u64);
impl EpochMillis {
    /// Checks the wire range and platform time representation.
    ///
    /// # Errors
    /// Returns [`TokenError::Clock`] if the value exceeds signed 64-bit
    /// milliseconds or cannot be represented as a platform `SystemTime`.
    pub fn new(value: u64) -> Result<Self, TokenError> {
        if value > i64::MAX as u64
            || UNIX_EPOCH
                .checked_add(std::time::Duration::from_millis(value))
                .is_none()
        {
            return Err(TokenError::Clock);
        }
        Ok(Self(value))
    }
    /// Reads the system clock without truncating or wrapping milliseconds.
    ///
    /// # Errors
    /// Returns [`TokenError::Clock`] before the epoch or outside the range.
    pub fn now() -> Result<Self, TokenError> {
        let value = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| TokenError::Clock)?
            .as_millis();
        Self::new(u64::try_from(value).map_err(|_| TokenError::Clock)?)
    }
    /// Returns the checked epoch-millisecond value; callers must not log it.
    #[must_use]
    pub const fn as_u64(self) -> u64 {
        self.0
    }
}
impl fmt::Debug for EpochMillis {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("EpochMillis(<redacted>)")
    }
}

/// An authenticated, account/service-bound token held only in memory.
///
/// Account and opaque token allocations are wiped on drop. The account binding
/// comes from the request/session key, not an unevidenced response account field.
/// This owner is not serializable or cloneable and never updates the session store.
pub struct IssuedToken {
    account: Zeroizing<String>,
    service: Service,
    expires: EpochMillis,
    token: Zeroizing<String>,
}
impl IssuedToken {
    /// The requesting account identifier; never print it.
    #[must_use]
    pub fn account_id(&self) -> &str {
        &self.account
    }
    /// The exact requested service.
    #[must_use]
    pub const fn service(&self) -> Service {
        self.service
    }
    /// The checked expiry of this issued token, not of the GSA session.
    #[must_use]
    pub const fn expires_at(&self) -> EpochMillis {
        self.expires
    }
    /// Borrows the opaque token. The caller must preserve secrecy and check expiry before use.
    #[must_use]
    pub fn expose_secret(&self) -> &str {
        &self.token
    }
    /// Checks local expiry without renewing or making a request.
    #[must_use]
    pub fn is_expired_at(&self, now: EpochMillis) -> bool {
        now >= self.expires
    }
}
impl fmt::Debug for IssuedToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("IssuedToken(<redacted>)")
    }
}

/// Fixed validation locations, never derived from remote field names or values.
///
/// A location describes a failed check, not successful token issuance or permission
/// to retry. Authenticated locations are reached only after AES-GCM verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResponseStage {
    /// Validation of outer plist grammar.
    OuterPlist,
    /// Validation of Response dictionary.
    Response,
    /// Validation of Status dictionary.
    Status,
    /// Validation of protocol status code.
    StatusCode,
    /// Validation of protocol status message type.
    StatusMessage,
    /// Validation of additional authentication selector type.
    AdditionalAuthentication,
    /// Validation of encrypted envelope field or framing.
    Envelope,
    /// Validation of authenticated plaintext plist grammar.
    AuthenticatedPlist,
    /// Validation of token service dictionary.
    Services,
    /// Validation of token field.
    Token,
    /// Validation of expiry field or range.
    Expiry,
}
impl fmt::Display for ResponseStage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::OuterPlist => "outer plist grammar",
            Self::Response => "Response dictionary",
            Self::Status => "Status dictionary",
            Self::StatusCode => "protocol status code",
            Self::StatusMessage => "protocol status message type",
            Self::AdditionalAuthentication => "additional authentication selector type",
            Self::Envelope => "encrypted envelope field or framing",
            Self::AuthenticatedPlist => "authenticated plaintext plist grammar",
            Self::Services => "token service dictionary",
            Self::Token => "token field",
            Self::Expiry => "expiry field or range",
        })
    }
}

/// Secret-free issuance failures. No remote text or underlying error is retained.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenError {
    /// Stored fields are unsuitable; nothing was sent.
    InvalidSession,
    /// Local anisette failed or returned invalid values; nothing was sent.
    Anisette,
    /// A transport failed; the outcome may be unknown and must not be retried.
    Transport,
    /// An HTTP response had a status other than 200.
    ///
    /// Retains only the numeric status, never headers or response material.
    /// This does not establish session expiry or permit a retry.
    Http {
        /// Numeric HTTP status returned by the transport.
        status: u16,
    },
    /// The server rejected the session/request or requested additional authentication.
    /// No undocumented status code is interpreted as session expiry.
    Rejected {
        /// Apple's numeric protocol status, not interpreted as session expiry.
        code: i64,
        /// Whether an additional-authentication selector was present.
        /// The selector value is never retained.
        additional_authentication: bool,
    },
    /// Internal parser classification for invalid grammar, fields, or ranges.
    /// [`TokenClient::issue`] maps response malformations to
    /// [`Self::MalformedResponse`]; callers of that API should match that variant.
    Malformed,
    /// An HTTP 200 response failed a check at a fixed, secret-free location.
    /// No remote bytes, keys, values, or parser error text are retained.
    MalformedResponse {
        /// The validation location, not the underlying cause.
        stage: ResponseStage,
    },
    /// A byte, element, depth, or scalar bound was exceeded.
    TooLarge,
    /// Binary plist, unknown envelope magic, or unsupported service response.
    Unsupported,
    /// AES-GCM authentication failed; no plaintext was parsed.
    AuthenticationTag,
    /// The issued token is already expired according to the injected clock.
    Expired,
    /// The clock cannot represent a valid nonnegative epoch-millisecond value.
    Clock,
}
impl fmt::Display for TokenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidSession => "stored session input is invalid",
            Self::Anisette => "local anisette failed",
            Self::Transport => "token transport failed; outcome may be unknown",
            Self::Http { status } => {
                return write!(f, "service-token request returned HTTP {status}");
            }
            Self::Rejected { code, additional_authentication } => {
                return write!(f, "service-token protocol rejection: code {code}; additional authentication: {additional_authentication}");
            }
            Self::Malformed => "malformed service-token response",
            Self::MalformedResponse { stage } => {
                return write!(f, "malformed service-token response at {stage}");
            }
            Self::TooLarge => "service-token response exceeds a bound",
            Self::Unsupported => "unsupported service-token response format or service",
            Self::AuthenticationTag => "service-token authentication tag mismatch",
            Self::Expired => "issued service token has expired",
            Self::Clock => "service-token clock is invalid",
        })
    }
}
impl std::error::Error for TokenError {}

/// I/O-neutral, one-exchange client borrowing caller-provided adapters.
///
/// Constructing a client performs no work. Each call to `issue` is an explicit
/// authentication action. The transport and provider must never retry internally.
pub struct TokenClient<'a, T, A> {
    transport: &'a T,
    anisette: &'a A,
}
impl<'a, T: Transport, A: AnisetteProvider> TokenClient<'a, T, A> {
    /// Borrows existing adapters; no session reconstruction or I/O occurs.
    pub fn new(transport: &'a T, anisette: &'a A) -> Self {
        Self {
            transport,
            anisette,
        }
    }
    /// Issues exactly one explicitly selected service token.
    ///
    /// The clock is checked before any attestation and again after authenticated
    /// response parsing. Errors stop the operation without retry or store mutation.
    ///
    /// # Errors
    /// See [`TokenError`]. Adapter error details are discarded, never chained.
    pub async fn issue(
        &self,
        session: SessionMaterialRef<'_>,
        service: Service,
        clock: &(impl Fn() -> Result<EpochMillis, TokenError> + Sync),
    ) -> Result<IssuedToken, TokenError> {
        let before = clock()?;
        let anisette = self.anisette.anisette().await.map_err(|mut error| {
            if let crate::anisette::AnisetteError::Unavailable { detail } = &mut error {
                detail.zeroize();
            }
            TokenError::Anisette
        })?;
        anisette.validate().map_err(|_| TokenError::Anisette)?;
        let request = wire::request(&session, service, &anisette)?;
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
                        TokenError::Transport
                    }
                    TransportError::ResponseTooLarge { .. } => TokenError::TooLarge,
                    _ => TokenError::Transport,
                })?;
        if response.status() != 200 {
            return Err(TokenError::Http {
                status: response.status(),
            });
        }
        let token = wire::response(response.body(), &session, service)?;
        let now = clock()?;
        if now < before {
            return Err(TokenError::Clock);
        }
        if token.is_expired_at(now) {
            return Err(TokenError::Expired);
        }
        Ok(token)
    }
}
impl<T, A> fmt::Debug for TokenClient<'_, T, A> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("TokenClient(<redacted>)")
    }
}
