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

//! Owning, bounded values crossing the helper boundary.

use core::fmt;

use zeroize::Zeroizing;

use crate::BridgeError;

/// Largest secret input or output accepted by one ADI operation.
pub const MAX_SECRET_BYTES: usize = 1024 * 1024;

/// A bounded byte string that wipes its allocation on drop.
pub struct SecretBytes(Zeroizing<Vec<u8>>);

impl SecretBytes {
    /// Takes ownership of a bounded secret byte string.
    ///
    /// # Errors
    ///
    /// Returns [`BridgeError::InvalidMessage`] when `bytes` exceeds the
    /// one-mebibyte helper boundary.
    pub fn new(bytes: Vec<u8>) -> Result<Self, BridgeError> {
        let bytes = Zeroizing::new(bytes);
        if bytes.len() > MAX_SECRET_BYTES {
            return Err(BridgeError::InvalidMessage);
        }
        Ok(Self(bytes))
    }

    /// Borrows the secret for the immediate operation that consumes it.
    #[must_use]
    pub fn expose(&self) -> &[u8] {
        &self.0
    }

    pub(crate) fn into_zeroizing(mut self) -> Zeroizing<Vec<u8>> {
        Zeroizing::new(core::mem::take(&mut *self.0))
    }

    pub(crate) fn from_zeroizing(mut bytes: Zeroizing<Vec<u8>>) -> Result<Self, BridgeError> {
        Self::new(core::mem::take(&mut *bytes))
    }
}

impl fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretBytes(<redacted>)")
    }
}

/// A bounded UTF-8 secret that wipes its allocation on drop.
pub struct SecretString(Zeroizing<String>);

impl SecretString {
    /// Takes ownership of a nonempty printable-ASCII secret.
    ///
    /// # Errors
    ///
    /// Returns [`BridgeError::InvalidMessage`] for an empty, oversized, or
    /// non-printable value.
    pub fn new(value: String) -> Result<Self, BridgeError> {
        let value = Zeroizing::new(value);
        if value.is_empty()
            || value.len() > 1024
            || !value.bytes().all(|byte| (0x20..=0x7e).contains(&byte))
        {
            return Err(BridgeError::InvalidMessage);
        }
        Ok(Self(value))
    }

    /// Borrows the value for the immediate operation that consumes it.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for SecretString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretString(<redacted>)")
    }
}

/// The directory-services identifier accepted by native ADI calls.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct DirectoryServiceId(i64);

impl DirectoryServiceId {
    /// The sentinel used by the local omnisette composition layer.
    pub const LOCAL_MACHINE: Self = Self(-2);

    /// Creates an explicit directory-services identifier.
    #[must_use]
    pub const fn new(value: i64) -> Self {
        Self(value)
    }

    pub(crate) const fn get(self) -> i64 {
        self.0
    }
}

impl fmt::Debug for DirectoryServiceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DirectoryServiceId(<redacted>)")
    }
}

/// The exact 16 ASCII bytes configured as ADI's Android identifier.
pub struct AndroidId(Zeroizing<[u8; 16]>);

impl AndroidId {
    /// Creates an Android identifier after validating printable ASCII.
    ///
    /// # Errors
    ///
    /// Returns [`BridgeError::InvalidMessage`] for non-printable bytes.
    pub fn new(value: [u8; 16]) -> Result<Self, BridgeError> {
        let value = Zeroizing::new(value);
        if !value.iter().all(|byte| (0x20..=0x7e).contains(byte)) {
            return Err(BridgeError::InvalidMessage);
        }
        Ok(Self(value))
    }

    /// Borrows the fixed-width value.
    #[must_use]
    pub fn expose(&self) -> &[u8; 16] {
        &self.0
    }
}

impl fmt::Debug for AndroidId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AndroidId(<redacted>)")
    }
}

/// Native material returned by `adi_otp_request`.
#[derive(Debug)]
pub struct OtpMaterial {
    /// Machine identifier bytes owned by Rust and wiped on drop.
    pub machine_id: SecretBytes,
    /// One-time-password bytes owned by Rust and wiped on drop.
    pub one_time_password: SecretBytes,
}

/// Native material returned by `adi_synchronize`.
#[derive(Debug)]
pub struct SynchronizeMaterial {
    /// Machine identifier bytes owned by Rust and wiped on drop.
    pub machine_id: SecretBytes,
    /// Synchronization response material owned by Rust and wiped on drop.
    pub srm: SecretBytes,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_secret_bearing_debug_representation_is_redacted() {
        let bytes = SecretBytes::new(b"byte-secret".to_vec()).expect("bytes");
        let string = SecretString::new("string-secret".to_owned()).expect("string");
        let android = AndroidId::new(*b"android-id-value").expect("android");
        let directory = DirectoryServiceId::new(123_456_789);
        let rendered = format!("{bytes:?} {string:?} {android:?} {directory:?}");
        assert!(!rendered.contains("byte-secret"));
        assert!(!rendered.contains("string-secret"));
        assert!(!rendered.contains("android-id-value"));
        assert!(!rendered.contains("123456789"));
    }
}
