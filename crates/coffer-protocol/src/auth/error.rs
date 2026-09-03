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

//! Authentication errors, tagged with the protocol stage that produced them.

use core::fmt;

use crate::anisette::AnisetteError;
use crate::entropy::EntropyError;
use crate::transport::TransportError;

/// The protocol step during which an [`AuthError`] occurred.
///
/// Apple's password authentication is a two-round SRP exchange, and after a
/// trusted-device verification the whole exchange runs a second time.  The
/// stage records not only which round failed but also whether it was the
/// initial exchange or the post-two-factor one, because the two have
/// different meanings for the user: an initial failure usually means a wrong
/// password, while a post-two-factor failure means the verification did not
/// take effect and the password is not the first thing to suspect.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AuthStage {
    /// The first request of the initial password exchange (`o = init`).
    SrpInit,
    /// The second request of the initial password exchange (`o = complete`).
    SrpComplete,
    /// Asking Apple to push a verification code to the trusted devices.
    TrustedDevicePush,
    /// Submitting the verification code.
    CodeValidation,
    /// The first request of the post-two-factor password exchange.
    ReauthSrpInit,
    /// The second request of the post-two-factor password exchange.
    ReauthSrpComplete,
}

impl AuthStage {
    /// Returns whether the stage belongs to the post-two-factor exchange.
    #[must_use]
    pub fn is_post_second_factor(self) -> bool {
        matches!(self, Self::ReauthSrpInit | Self::ReauthSrpComplete)
    }

    fn label(self) -> &'static str {
        match self {
            Self::SrpInit => "initial SRP init",
            Self::SrpComplete => "initial SRP complete",
            Self::TrustedDevicePush => "trusted-device code request",
            Self::CodeValidation => "verification code submission",
            Self::ReauthSrpInit => "post-2FA SRP init",
            Self::ReauthSrpComplete => "post-2FA SRP complete",
        }
    }
}

impl fmt::Display for AuthStage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

/// A protocol-level failure reported by Apple with HTTP status 200.
///
/// GSA responses carry a `Status` dictionary whose `ec` (error code) is zero
/// on success.  Any other value is a failure even though the HTTP exchange
/// succeeded.  The accompanying `em` message is server-controlled text: it
/// has control characters removed and is truncated to a fixed length, and it
/// is exposed only through [`ProtocolStatus::message`].  `Display` and
/// `Debug` print the code alone, because the server could echo an account
/// identifier or other private text in the message and errors are meant to
/// be loggable.  A user interface may show the message as an untrusted
/// string; nothing should interpret it.
#[derive(Clone, PartialEq, Eq)]
pub struct ProtocolStatus {
    code: i64,
    message: String,
}

impl fmt::Debug for ProtocolStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProtocolStatus")
            .field("code", &self.code)
            .field("message_len", &self.message.len())
            .finish()
    }
}

impl ProtocolStatus {
    pub(crate) fn new(code: i64, message: String) -> Self {
        Self { code, message }
    }

    /// Returns the `ec` value.
    #[must_use]
    pub fn code(&self) -> i64 {
        self.code
    }

    /// Returns the sanitized, truncated `em` text, which may be empty.
    ///
    /// The text is untrusted server output.  It is safe to render (control
    /// characters have been removed) but must not be logged or interpreted.
    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for ProtocolStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "server reported error code {}", self.code)
    }
}

/// A server-chosen selector such as the `sp` password protocol or the `au`
/// secondary-authentication step.
///
/// Apple's selectors are short tokens (`s2k`, `trustedDeviceSecondaryAuth`).
/// The raw, bounded value is always available through
/// [`ServerSelector::as_str`], but `Display` and `Debug` print it only when it
/// consists solely of ASCII letters, digits, `.`, `_`, and `-` and is at most
/// [`ServerSelector::MAX_DISPLAY_LEN`] bytes; anything else is printed as
/// `<redacted>` so that an error can be logged without reproducing arbitrary
/// server text.
#[derive(Clone, PartialEq, Eq)]
pub struct ServerSelector(String);

impl ServerSelector {
    /// Longest value that is shown verbatim by `Display` and `Debug`.
    pub const MAX_DISPLAY_LEN: usize = 64;

    pub(crate) fn new(value: String) -> Self {
        Self(value)
    }

    /// Returns the raw value.  Treat it as untrusted server output.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    fn displayable(&self) -> bool {
        !self.0.is_empty()
            && self.0.len() <= Self::MAX_DISPLAY_LEN
            && self
                .0
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
    }
}

impl fmt::Display for ServerSelector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.displayable() {
            f.write_str(&self.0)
        } else {
            f.write_str("<redacted>")
        }
    }
}

impl fmt::Debug for ServerSelector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ServerSelector({self})")
    }
}

/// Why a response field was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum MalformedReason {
    /// The body is not a property list.
    NotPlist,
    /// The value is not a dictionary where one was required.
    NotDictionary,
    /// The field is absent.
    Missing,
    /// The field has the wrong property-list type.
    WrongType,
    /// The value is longer than the configured limit.
    TooLong {
        /// The limit that was exceeded.
        limit: usize,
    },
    /// A property list contains more XML elements than allowed.
    ///
    /// Deeply nested collections are rejected before they are parsed, because
    /// dropping a very deep tree would exhaust the stack.
    TooComplex {
        /// The maximum number of elements allowed.
        limit: usize,
    },
    /// The value is shorter than the protocol allows.
    TooShort {
        /// The smallest acceptable length.
        minimum: usize,
    },
    /// The value does not have the exact length the protocol requires.
    WrongLength {
        /// The required length.
        expected: usize,
    },
    /// A numeric value is outside the accepted range.
    OutOfRange,
    /// Encrypted data does not decrypt to correctly padded plaintext.
    BadPadding,
    /// Encrypted data is not a whole number of cipher blocks.
    BadBlockLength,
    /// A cryptographic parameter is invalid (for example `B mod N = 0`).
    InvalidParameter,
}

/// A response that does not have the shape the protocol requires.
///
/// Only the field *name* is recorded, never its value, so this error is safe
/// to log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Malformed {
    field: &'static str,
    reason: MalformedReason,
}

impl Malformed {
    pub(crate) fn new(field: &'static str, reason: MalformedReason) -> Self {
        Self { field, reason }
    }

    /// Returns the name of the offending field, or `body` for the whole
    /// response.
    #[must_use]
    pub fn field(&self) -> &'static str {
        self.field
    }

    /// Returns why the field was rejected.
    #[must_use]
    pub fn reason(&self) -> MalformedReason {
        self.reason
    }
}

impl fmt::Display for Malformed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "malformed response field `{}`: ", self.field)?;
        match self.reason {
            MalformedReason::NotPlist => f.write_str("not a property list"),
            MalformedReason::NotDictionary => f.write_str("not a dictionary"),
            MalformedReason::Missing => f.write_str("missing"),
            MalformedReason::WrongType => f.write_str("wrong type"),
            MalformedReason::TooLong { limit } => write!(f, "longer than {limit} bytes"),
            MalformedReason::TooComplex { limit } => {
                write!(f, "more than {limit} XML elements")
            }
            MalformedReason::TooShort { minimum } => {
                write!(f, "shorter than {minimum} bytes")
            }
            MalformedReason::WrongLength { expected } => {
                write!(f, "not exactly {expected} bytes")
            }
            MalformedReason::OutOfRange => f.write_str("out of range"),
            MalformedReason::BadPadding => f.write_str("bad padding after decryption"),
            MalformedReason::BadBlockLength => f.write_str("not a whole number of blocks"),
            MalformedReason::InvalidParameter => f.write_str("invalid cryptographic parameter"),
        }
    }
}

impl std::error::Error for Malformed {}

/// What went wrong, independent of the stage.
///
/// No variant carries the account name, the password, a verification code,
/// SRP values, tokens, or raw response bytes.
#[derive(Debug)]
#[non_exhaustive]
pub enum AuthErrorKind {
    /// The transport did not deliver a response.
    Transport(TransportError),
    /// No usable anisette data was available.
    Anisette(AnisetteError),
    /// The entropy source failed.
    Entropy(EntropyError),
    /// The server answered with a non-success HTTP status.
    HttpStatus(u16),
    /// The server answered HTTP 200 but reported a protocol error.
    Protocol(ProtocolStatus),
    /// The response could not be parsed or violated a size limit.
    Malformed(Malformed),
    /// The server selected an SRP password protocol this crate does not
    /// implement.
    ///
    /// Coffer implements only `s2k`.  Rather than guess how another protocol
    /// derives the password key, the exchange stops here before the second
    /// round, so no password-derived value is sent.
    UnsupportedProtocol {
        /// The `sp` value the server selected.
        protocol: ServerSelector,
    },
    /// The server's proof `M2` did not match.
    ///
    /// Either the password was wrong (the server computed a different key)
    /// or the peer is not the genuine server.  The exchange is not retried.
    ServerProofMismatch,
    /// The post-two-factor exchange still demands a second factor.
    ///
    /// The verification code was accepted, but the re-authentication response
    /// again carried an `au` request.  Coffer never loops here; the user has
    /// to start over.
    SecondFactorStillRequired,
    /// The post-two-factor exchange demands a step this crate does not
    /// implement.
    UnsupportedStep {
        /// The `au` value the server sent.
        step: ServerSelector,
    },
    /// An internal invariant failed while building a request.
    ///
    /// This is reported instead of panicking so that a bug can never abort a
    /// process that holds credentials in memory.
    Internal {
        /// A description of the failed invariant.
        detail: &'static str,
    },
}

impl fmt::Display for AuthErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Transport(e) => write!(f, "{e}"),
            Self::Anisette(e) => write!(f, "{e}"),
            Self::Entropy(e) => write!(f, "{e}"),
            Self::HttpStatus(status) => write!(f, "server answered HTTP {status}"),
            Self::Protocol(status) => write!(f, "{status}"),
            Self::Malformed(m) => write!(f, "{m}"),
            Self::UnsupportedProtocol { protocol } => {
                write!(f, "server selected unsupported SRP protocol `{protocol}`")
            }
            Self::ServerProofMismatch => {
                f.write_str("server proof did not verify (wrong password or untrusted peer)")
            }
            Self::SecondFactorStillRequired => {
                f.write_str("second factor still required after verification")
            }
            Self::UnsupportedStep { step } => {
                write!(f, "server requires unsupported step `{step}`")
            }
            Self::Internal { detail } => write!(f, "internal error: {detail}"),
        }
    }
}

/// An authentication failure.
///
/// Every error names the [`AuthStage`] that produced it, so a caller can
/// tell an initial password failure from a post-two-factor one without
/// inspecting the kind.  Errors carry no secrets and are safe to log or
/// display.
///
/// An `AuthError` is terminal for the flow that produced it: the stage value
/// has been consumed, and the only way to try again is to start a new flow
/// with a fresh user action.
#[derive(Debug)]
pub struct AuthError {
    stage: AuthStage,
    kind: AuthErrorKind,
}

impl AuthError {
    pub(crate) fn new(stage: AuthStage, kind: AuthErrorKind) -> Self {
        Self { stage, kind }
    }

    /// Returns the stage during which the failure occurred.
    #[must_use]
    pub fn stage(&self) -> AuthStage {
        self.stage
    }

    /// Returns what went wrong.
    #[must_use]
    pub fn kind(&self) -> &AuthErrorKind {
        &self.kind
    }

    /// Splits the error into its stage and kind.
    #[must_use]
    pub fn into_parts(self) -> (AuthStage, AuthErrorKind) {
        (self.stage, self.kind)
    }
}

impl fmt::Display for AuthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} failed: {}", self.stage, self.kind)
    }
}

impl std::error::Error for AuthError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match &self.kind {
            AuthErrorKind::Transport(e) => Some(e),
            AuthErrorKind::Anisette(e) => Some(e),
            AuthErrorKind::Entropy(e) => Some(e),
            AuthErrorKind::Malformed(e) => Some(e),
            _ => None,
        }
    }
}
