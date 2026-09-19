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

//! Offline CKKS key unwrapping, bounded graphs and payload decryption.
//! No retrieval or trust/recovery operations.
//!
//! Key unwrapping authenticates wrapped bytes, not record identity or trust.
//! The caller must authenticate account/zone/key-class/parent bindings separately.
//! [`hierarchy`] checks supplied metadata for structural consistency only.
//! In particular, successfully unwrapping a self-wrapped key does not establish
//! a trusted root. Supply root keys only from an independently verified source.
//! Item ciphertext has a different envelope, handled only by [`payload`].
//!
//! The format is based on protocol facts in Apple's `CKKSSIV.m` at Security
//! revision `db15acbe6a7f257a859ad9a3bb86097bfe0679d9`, composed using RFC 5297.
//! Independent OpenSSL synthetic vectors and their generation recipe live in
//! `tests/fixtures/ckks-wrap/README.md`. Apple interoperability is unverified.
//!
//! Owned key and working buffers are zeroized on drop; AES, SIV and CMAC
//! zeroization features are enabled. This does not guarantee erasure of every
//! compiler-generated copy or temporary inside external cryptographic code.

/// Bounded, offline validation and selected-path key unwrapping.
pub mod hierarchy;

/// Bounded offline construction of known CKKS v2 item associated data.
pub mod item;

/// Bounded offline payload decryption with caller-ordered associated data.
pub mod payload;

/// Explicit bounded binary-plist views of borrowed offline plaintext.
pub mod plaintext;

use aes_siv::{KeyInit, Tag, siv::Aes256Siv};
use core::fmt;
use zeroize::Zeroizing;

/// A 64-byte AES-256-SIV key owned in zeroizing storage.
///
/// No cloning, serialization, or implicit disclosure is provided. Drop keys
/// promptly after use. This type carries no account, zone, UUID, or trust claim.
pub struct UnwrappingKey(Zeroizing<[u8; 64]>);

impl UnwrappingKey {
    /// Takes ownership of caller-supplied key bytes without establishing trust.
    ///
    /// The caller is responsible for securely obtaining and binding this key.
    #[must_use]
    pub fn new(bytes: Zeroizing<[u8; 64]>) -> Self {
        Self(bytes)
    }

    /// Borrows the key bytes for a subsequent explicitly selected crypto step.
    /// Never log or persist the returned bytes without appropriate protection.
    #[must_use]
    pub fn expose_secret(&self) -> &[u8; 64] {
        &self.0
    }

    /// Authenticates and unwraps exactly one 80-byte CKKS wrapped AES-SIV key.
    ///
    /// The format is a 16-byte SIV tag followed by 64 ciphertext bytes, with
    /// no nonce or associated-data components. There is no fallback or retry.
    /// No plaintext is returned on authentication failure. Caller-owned input
    /// remains unchanged. Success does not authenticate parent/record metadata.
    ///
    /// # Errors
    /// Returns [`UnwrapError::InvalidLength`] unless the input is exactly 80
    /// bytes, or [`UnwrapError::AuthenticationFailed`] if authentication fails.
    pub fn unwrap_key(&self, wrapped: &[u8]) -> Result<Self, UnwrapError> {
        if wrapped.len() != 80 {
            return Err(UnwrapError::InvalidLength);
        }
        let tag = Tag::try_from(&wrapped[..16]).map_err(|_| UnwrapError::InvalidLength)?;
        let mut plaintext = Zeroizing::new([0u8; 64]);
        plaintext.copy_from_slice(&wrapped[16..]);
        let mut cipher = Aes256Siv::new((&*self.0).into());
        // An empty component list is intentional, not one empty AD component.
        cipher
            .decrypt_inout_detached(
                core::iter::empty::<&[u8]>(),
                plaintext.as_mut_slice().into(),
                &tag,
            )
            .map_err(|_| UnwrapError::AuthenticationFailed)?;
        Ok(Self(plaintext))
    }
}

impl fmt::Debug for UnwrappingKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("UnwrappingKey(<redacted>)")
    }
}

/// Fixed, secret-free failures for one offline wrapped-key operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnwrapError {
    /// The input was not exactly 80 bytes; no decryption was attempted.
    InvalidLength,
    /// The key, tag, or ciphertext did not authenticate; no key is returned.
    AuthenticationFailed,
}
impl fmt::Display for UnwrapError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidLength => "invalid CKKS wrapped-key length",
            Self::AuthenticationFailed => "CKKS wrapped-key authentication failed",
        })
    }
}
impl std::error::Error for UnwrapError {}
