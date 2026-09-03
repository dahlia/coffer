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

//! The storage-neutral authentication-session port and value types.

use core::fmt;
use std::future::Future;

use coffer_protocol::auth::Session;
use zeroize::Zeroizing;

/// Number of random bytes in an opaque session slot.
pub const SESSION_SLOT_LEN: usize = 16;

/// Maximum serialized envelope size accepted from a backend.
pub const MAX_STORED_SESSION_BYTES: usize = 64 * 1024;

/// An opaque lookup slot for one local Coffer profile.
///
/// The bytes must come from a cryptographically secure random source.  The
/// slot is deliberately unrelated to an Apple Account name, account ID,
/// token, or an unkeyed hash of any of those values.  It is safe to persist as
/// ordinary application metadata, although its `Debug` output is redacted so
/// logs cannot be used to correlate a profile with a Secret Service item.
#[derive(Clone, Copy, Eq, Ord, PartialEq, PartialOrd)]
pub struct SessionSlot([u8; SESSION_SLOT_LEN]);

impl SessionSlot {
    /// Creates a slot from caller-supplied random bytes.
    ///
    /// This function does not generate randomness.  A production caller must
    /// fill `bytes` from the operating system CSPRNG and store the resulting
    /// slot in non-secret local profile metadata.
    #[must_use]
    pub const fn from_random_bytes(bytes: [u8; SESSION_SLOT_LEN]) -> Self {
        Self(bytes)
    }

    pub(crate) const fn as_bytes(&self) -> &[u8; SESSION_SLOT_LEN] {
        &self.0
    }

    pub(crate) fn attribute_value(&self) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut encoded = String::with_capacity(SESSION_SLOT_LEN * 2);
        for byte in self.0 {
            encoded.push(char::from(HEX[usize::from(byte >> 4)]));
            encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
        encoded
    }
}

impl fmt::Debug for SessionSlot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SessionSlot(<redacted>)")
    }
}

/// The minimum GSA session material needed to request fresh service tokens.
///
/// This deliberately excludes the Apple Account name, password, two-factor
/// code, SRP ephemeral/password material, display names, and already-issued
/// per-service tokens.  The four retained values are the inputs of the GSA
/// `apptokens` request: account ID, IdMS token, session key, and opaque cookie.
/// Every field is zeroized on drop and `Debug` reveals no value.
pub struct ReusableSession {
    account_id: Zeroizing<String>,
    idms_token: Zeroizing<String>,
    session_key: Zeroizing<[u8; 32]>,
    cookie: Zeroizing<Vec<u8>>,
}

impl ReusableSession {
    /// Creates reusable material from already-owned protocol values.
    ///
    /// This constructor is useful for deterministic store tests and explicit
    /// migrations that do not have a live [`Session`].  It takes ownership and
    /// immediately places every value in zeroizing storage.  Production login
    /// code should normally use [`ReusableSession::from_session`].
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::EncodingFailed`] when a required value is empty
    /// or exceeds the envelope's field bounds.
    pub fn new(
        account_id: String,
        idms_token: String,
        session_key: [u8; 32],
        cookie: Vec<u8>,
    ) -> Result<Self, StoreError> {
        let value = Self {
            account_id: Zeroizing::new(account_id),
            idms_token: Zeroizing::new(idms_token),
            session_key: Zeroizing::new(session_key),
            cookie: Zeroizing::new(cookie),
        };
        crate::codec::validate_session(&value)?;
        Ok(value)
    }

    /// Copies the reusable subset out of a live protocol session.
    ///
    /// The returned value is independent of the protocol session and owns one
    /// zeroizing copy of each retained field.  Callers should drop the source
    /// session once they no longer need its already-issued service tokens.
    #[must_use]
    pub fn from_session(session: &Session) -> Self {
        let mut session_key = Zeroizing::new([0; 32]);
        session_key.copy_from_slice(session.session_key().expose_secret());
        Self {
            account_id: Zeroizing::new(session.account_id().as_str().to_owned()),
            idms_token: Zeroizing::new(session.idms_token().expose_secret().to_owned()),
            session_key,
            cookie: Zeroizing::new(session.cookie().to_vec()),
        }
    }

    pub(crate) fn from_decoded(
        account_id: Zeroizing<String>,
        idms_token: Zeroizing<String>,
        session_key: Zeroizing<[u8; 32]>,
        cookie: Zeroizing<Vec<u8>>,
    ) -> Self {
        Self {
            account_id,
            idms_token,
            session_key,
            cookie,
        }
    }

    /// Exposes the account ID for construction of a GSA token request.
    #[must_use]
    pub fn expose_account_id(&self) -> &str {
        &self.account_id
    }

    /// Exposes the IdMS bearer token for construction of a GSA token request.
    #[must_use]
    pub fn expose_idms_token(&self) -> &str {
        &self.idms_token
    }

    /// Exposes the HMAC/session key for construction of a GSA token request.
    #[must_use]
    pub fn expose_session_key(&self) -> &[u8; 32] {
        &self.session_key
    }

    /// Exposes the opaque cookie for construction of a GSA token request.
    #[must_use]
    pub fn expose_cookie(&self) -> &[u8] {
        &self.cookie
    }
}

impl fmt::Debug for ReusableSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ReusableSession(<redacted>)")
    }
}

/// An operation performed against the platform backend.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum BackendOperation {
    /// Establishing or checking the Secret Service connection.
    Connect,
    /// Searching for a session item.
    Search,
    /// Reading a session item's secret.
    Read,
    /// Creating or replacing a session item.
    Write,
    /// Deleting one or more session items.
    Delete,
}

/// Why the configured Secret Service backend cannot be used.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum UnavailableReason {
    /// No usable session D-Bus connection exists.
    NoSessionBus,
    /// No process owns the Secret Service bus name.
    NoServiceOwner,
    /// The Secret Service has no default collection configured.
    NoDefaultCollection,
}

/// A safe, explicit failure from a [`SessionStore`].
///
/// No variant carries an account identifier, token, slot, item path, backend
/// error string, or serialized input.  `Debug` and `Display` are therefore
/// safe for ordinary diagnostics.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum StoreError {
    /// The configured Secret Service backend is unavailable.
    Unavailable(UnavailableReason),
    /// The default collection or matching item is locked.
    Locked,
    /// The desktop or sandbox policy denied access.
    Denied,
    /// The user dismissed a local keyring prompt.
    PromptDismissed,
    /// A bounded D-Bus operation timed out.
    TimedOut,
    /// More than one item matches the exact opaque slot.
    Duplicate,
    /// The stored envelope is malformed or violates a field bound.
    Corrupt,
    /// The stored envelope is larger than [`MAX_STORED_SESSION_BYTES`].
    TooLarge,
    /// The envelope version is intact but unsupported.
    UnsupportedVersion(u16),
    /// Encoding a valid in-memory session failed.
    EncodingFailed,
    /// The backend failed without a safely classifiable cause.
    BackendFailure(BackendOperation),
    /// Some matching items were deleted but at least one deletion failed.
    PartialDelete {
        /// Number of items successfully deleted.
        deleted: usize,
        /// Secret-free cause of every failed deletion, in attempt order.
        failures: Vec<DeleteFailure>,
    },
}

/// A safely classified failure for one item in a multi-item delete.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum DeleteFailure {
    /// The backend disappeared or became unavailable.
    Unavailable,
    /// The item or collection is locked.
    Locked,
    /// Policy denied the deletion.
    Denied,
    /// The user dismissed a required local prompt.
    PromptDismissed,
    /// The deletion timed out.
    TimedOut,
    /// The backend failed without a safely classifiable cause.
    Backend,
}

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unavailable(reason) => write!(f, "Secret Service is unavailable: {reason}"),
            Self::Locked => f.write_str("Secret Service is locked; unlock it and try again"),
            Self::Denied => f.write_str("Secret Service access was denied"),
            Self::PromptDismissed => f.write_str("Secret Service prompt was dismissed"),
            Self::TimedOut => f.write_str("Secret Service operation timed out"),
            Self::Duplicate => f.write_str("multiple Secret Service items match this session slot"),
            Self::Corrupt => f.write_str("stored authentication session is corrupt"),
            Self::TooLarge => f.write_str("stored authentication session exceeds the size limit"),
            Self::UnsupportedVersion(version) => {
                write!(
                    f,
                    "stored authentication session uses unsupported version {version}"
                )
            }
            Self::EncodingFailed => f.write_str("authentication session could not be encoded"),
            Self::BackendFailure(operation) => {
                write!(f, "Secret Service failed during {operation}")
            }
            Self::PartialDelete { deleted, failures } => write!(
                f,
                "Secret Service deleted {deleted} matching items but failed to delete {}",
                failures.len()
            ),
        }
    }
}

impl std::error::Error for StoreError {}

impl fmt::Display for UnavailableReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoSessionBus => f.write_str("no session bus"),
            Self::NoServiceOwner => f.write_str("no Secret Service owner"),
            Self::NoDefaultCollection => f.write_str("no default collection"),
        }
    }
}

impl fmt::Display for BackendOperation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Connect => f.write_str("connection"),
            Self::Search => f.write_str("lookup"),
            Self::Read => f.write_str("read"),
            Self::Write => f.write_str("write"),
            Self::Delete => f.write_str("delete"),
        }
    }
}

/// Result of an explicit delete request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeleteOutcome {
    /// No item matched the exact slot.
    NotFound,
    /// Every matching item was deleted.
    Deleted {
        /// Number of items deleted.  This can exceed one when repairing
        /// duplicate remnants.
        count: usize,
    },
}

/// Stores reusable authentication sessions without choosing a platform.
///
/// Implementations must never fall back to plaintext or a regular file.  No
/// method retries implicitly.  `replace` validates an existing item before
/// overwriting it so corrupt or newer data is preserved for explicit repair.
pub trait SessionStore: Send + Sync {
    /// Verifies that the configured backend and collection are usable.
    fn check_available(&self) -> impl Future<Output = Result<(), StoreError>> + Send;

    /// Loads the unique session for `slot`.
    ///
    /// `Ok(None)` distinguishes an absent item from backend and decoding
    /// failures.  Duplicate matches are never resolved by picking one.
    fn load(
        &self,
        slot: &SessionSlot,
    ) -> impl Future<Output = Result<Option<ReusableSession>, StoreError>> + Send;

    /// Atomically creates or replaces the session for `slot`.
    ///
    /// An existing corrupt or unsupported-version item is preserved and
    /// returned as an error rather than silently overwritten.
    fn replace(
        &self,
        slot: &SessionSlot,
        session: &ReusableSession,
    ) -> impl Future<Output = Result<(), StoreError>> + Send;

    /// Explicitly deletes every item matching `slot`.
    ///
    /// Partial failure is reported by [`StoreError::PartialDelete`]; it is
    /// never hidden behind a successful result.
    fn delete(
        &self,
        slot: &SessionSlot,
    ) -> impl Future<Output = Result<DeleteOutcome, StoreError>> + Send;
}
