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

//! Explicit local storage of issued delegate material, separate from GSA v1.

use crate::{SessionSlot, StoreError};
use coffer_protocol::delegate::DelegateCredentials;
use core::fmt;
use std::future::Future;
use zeroize::Zeroizing;

/// Maximum local delegate envelope size, including all headers (16 KiB).
pub const MAX_STORED_DELEGATE_BYTES: usize = 16 * 1024;
pub(crate) const LIMITS: [usize; 5] = [1024, 256, 1024, 4096, 4096];

/// Static failure categories for delegate persistence, without input or source chains.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum DelegateStoreError {
    /// Caller input is empty, non-printable ASCII, or exceeds its field bound.
    InvalidMaterial,
    /// Stored bytes are malformed, noncanonical, or have the wrong magic.
    Corrupt,
    /// The envelope version is unsupported; the record must be preserved.
    UnsupportedVersion,
    /// The backend envelope exceeds the documented size bound.
    TooLarge,
    /// Stored slot, ADSID, or client identifier differs from the caller's expectation.
    BindingMismatch,
    /// Multiple records match the opaque slot and delegate kind.
    Duplicate,
    /// Secret Service is unavailable, with no fallback attempted.
    Unavailable,
    /// The collection or item is locked.
    Locked,
    /// Backend policy denied access.
    Denied,
    /// A local keyring prompt was dismissed.
    PromptDismissed,
    /// An operation timed out; a write might have taken effect.
    TimedOut,
    /// A backend operation failed; a write might have taken effect.
    BackendFailure,
}
impl fmt::Display for DelegateStoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidMaterial => "invalid delegate storage material",
            Self::Corrupt => "corrupt delegate storage envelope",
            Self::UnsupportedVersion => "unsupported delegate storage version",
            Self::TooLarge => "delegate storage envelope exceeds size limit",
            Self::BindingMismatch => "delegate storage binding mismatch",
            Self::Duplicate => "multiple delegate storage items match",
            Self::Unavailable => "delegate Secret Service unavailable",
            Self::Locked => "delegate Secret Service locked",
            Self::Denied => "delegate Secret Service access denied",
            Self::PromptDismissed => "delegate Secret Service prompt dismissed",
            Self::TimedOut => "delegate Secret Service operation timed out",
            Self::BackendFailure => "delegate Secret Service operation failed",
        })
    }
}
impl std::error::Error for DelegateStoreError {}
impl From<StoreError> for DelegateStoreError {
    fn from(error: StoreError) -> Self {
        match error {
            StoreError::Unavailable(_) => Self::Unavailable,
            StoreError::Locked => Self::Locked,
            StoreError::Denied => Self::Denied,
            StoreError::PromptDismissed => Self::PromptDismissed,
            StoreError::TimedOut => Self::TimedOut,
            StoreError::Duplicate => Self::Duplicate,
            _ => Self::BackendFailure,
        }
    }
}

/// Caller-supplied expected ADSID and stable client identifier, borrowed for one operation.
///
/// Validation proves neither authenticated origin nor a relationship to a GSA session.
/// The caller owns and must protect the source strings throughout this borrow.
#[derive(Clone, Copy)]
pub struct DelegateBindingRef<'a> {
    pub(crate) adsid: &'a str,
    pub(crate) client_id: &'a str,
}
impl<'a> DelegateBindingRef<'a> {
    /// Validates without allocating, normalizing, or accessing any backend.
    ///
    /// # Errors
    /// Returns [`DelegateStoreError::InvalidMaterial`] unless both values are
    /// nonempty printable ASCII within the ADSID/client-id bounds (1024/256 bytes).
    pub fn new(adsid: &'a str, client_id: &'a str) -> Result<Self, DelegateStoreError> {
        validate(adsid, LIMITS[0])?;
        validate(client_id, LIMITS[1])?;
        Ok(Self { adsid, client_id })
    }
}
impl fmt::Debug for DelegateBindingRef<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DelegateBindingRef(<redacted>)")
    }
}

/// Zeroizing owner of ADSID, client-id, DSID, MME token, and CloudKit token.
///
/// Contains no account name, password, PET, expiry, or GSA session. This type
/// does not certify authenticated origin, token validity, or successful reuse.
/// It performs no I/O and provides no automatic renewal or network operation.
pub struct StoredDelegateCredentials {
    pub(crate) fields: [Zeroizing<String>; 5],
}
impl StoredDelegateCredentials {
    /// Copies issued fields and explicit caller binding into independent zeroizing owners.
    ///
    /// All lengths and characters are checked before allocating. Each copy is
    /// written into an already zeroizing buffer with sufficient capacity.
    /// Caller binding is an assertion, not evidence of authenticated origin;
    /// even successful issuance does not prove a token's lifetime or reuse.
    /// Drop this owner as soon as the explicit storage/use operation finishes.
    ///
    /// # Errors
    /// Returns [`DelegateStoreError::InvalidMaterial`] for values outside the
    /// local printable-ASCII bounds (DSID 1024 bytes, each token 4096 bytes).
    pub fn from_issued(
        issued: &DelegateCredentials,
        binding: DelegateBindingRef<'_>,
    ) -> Result<Self, DelegateStoreError> {
        Self::from_fields([
            binding.adsid,
            binding.client_id,
            issued.dsid(),
            issued.mme_auth_token().expose_secret(),
            issued.cloudkit_token().expose_secret(),
        ])
    }
    pub(crate) fn from_fields(fields: [&str; 5]) -> Result<Self, DelegateStoreError> {
        for (field, max) in fields.iter().zip(LIMITS) {
            validate(field, max)?;
        }
        Ok(Self {
            fields: fields.map(|field| {
                let mut owned = Zeroizing::new(String::with_capacity(field.len()));
                owned.push_str(field);
                owned
            }),
        })
    }
    pub(crate) fn matches(&self, expected: DelegateBindingRef<'_>) -> bool {
        self.expose_adsid() == expected.adsid && self.expose_client_id() == expected.client_id
    }
    /// Explicitly borrows the caller ADSID; the borrow cannot outlive this owner.
    #[must_use]
    pub fn expose_adsid(&self) -> &str {
        &self.fields[0]
    }
    /// Explicitly borrows the stable client identifier.
    #[must_use]
    pub fn expose_client_id(&self) -> &str {
        &self.fields[1]
    }
    /// Explicitly borrows the DSID exactly as issued, with no numeric conversion.
    #[must_use]
    pub fn expose_dsid(&self) -> &str {
        &self.fields[2]
    }
    /// Explicitly borrows the MME bearer token.
    #[must_use]
    pub fn expose_mme_auth_token(&self) -> &str {
        &self.fields[3]
    }
    /// Explicitly borrows the CloudKit bearer token without asserting access or lifetime.
    ///
    /// ```compile_fail
    /// use coffer_service::StoredDelegateCredentials;
    /// fn escape(value: StoredDelegateCredentials) -> &'static str {
    ///     value.expose_cloudkit_token()
    /// }
    /// ```
    #[must_use]
    pub fn expose_cloudkit_token(&self) -> &str {
        &self.fields[4]
    }
}
impl fmt::Debug for StoredDelegateCredentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("StoredDelegateCredentials(<redacted>)")
    }
}
pub(crate) fn validate(value: &str, max: usize) -> Result<(), DelegateStoreError> {
    if value.is_empty() || value.len() > max || !value.bytes().all(|b| (0x20..=0x7e).contains(&b)) {
        return Err(DelegateStoreError::InvalidMaterial);
    }
    Ok(())
}

/// Explicit, local-only persistence of delegate material under a distinct item kind.
///
/// Implementations must require encrypted storage, never select a duplicate,
/// never overwrite invalid or mismatched material, and never retry a failed write.
/// Concurrent writers are not serialized by this port; callers must serialize
/// operations for a slot. No deletion, migration, login, or renewal is provided.
pub trait DelegateStore: Send + Sync {
    /// Loads the unique item and checks the envelope slot and caller ADSID/client-id.
    ///
    /// Absence is `Ok(None)`; malformed, unsupported, mismatched, duplicate,
    /// or inaccessible items return a static error. No subsequent network use occurs.
    fn load_delegate(
        &self,
        slot: &SessionSlot,
        expected: DelegateBindingRef<'_>,
    ) -> impl Future<Output = Result<Option<StoredDelegateCredentials>, DelegateStoreError>> + Send;
    /// Creates or replaces the one validated item for the supplied binding.
    ///
    /// Existing corrupt, unknown, duplicate, or differently bound items are
    /// preserved. Creation/replacement may have taken effect on timeout, failure,
    /// or cancellation: return control to the caller without retry or fallback.
    fn replace_delegate(
        &self,
        slot: &SessionSlot,
        expected: DelegateBindingRef<'_>,
        value: &StoredDelegateCredentials,
    ) -> impl Future<Output = Result<(), DelegateStoreError>> + Send;
}
