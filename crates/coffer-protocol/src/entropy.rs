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

//! Caller-supplied randomness.
//!
//! The protocol layer needs unpredictable bytes for the SRP client ephemeral
//! `a`.  Rather than reaching for the operating system itself, it asks an
//! [`Entropy`] implementation supplied by the caller.  This keeps the crate
//! free of platform dependencies and lets tests inject a fixed value so that
//! every wire byte is reproducible.

use core::fmt;

/// A source of cryptographically secure random bytes.
///
/// Production callers wrap the operating system's CSPRNG (for example
/// `getrandom`).  Tests supply a fixed sequence.
///
/// # Security
///
/// The bytes are used as the SRP private ephemeral.  A predictable
/// implementation lets an observer of the wire recover the session key, so a
/// real implementation must be backed by the OS or another cryptographically
/// secure generator.  Never seed it from time, process identifiers, or
/// similar low-entropy values.
pub trait Entropy: Send + Sync {
    /// Fills `dest` entirely with random bytes.
    ///
    /// # Errors
    ///
    /// Returns [`EntropyError`] when the source cannot produce bytes.  The
    /// protocol layer treats that as a fatal error for the current attempt
    /// and never falls back to a weaker source.
    fn fill(&self, dest: &mut [u8]) -> Result<(), EntropyError>;
}

/// Failure of an [`Entropy`] source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntropyError {
    detail: String,
}

impl EntropyError {
    /// Creates an error with a human-readable, secret-free description.
    #[must_use]
    pub fn new(detail: impl Into<String>) -> Self {
        Self {
            detail: detail.into(),
        }
    }

    /// Returns the description.
    #[must_use]
    pub fn detail(&self) -> &str {
        &self.detail
    }
}

impl fmt::Display for EntropyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "entropy source failed: {}", self.detail)
    }
}

impl std::error::Error for EntropyError {}
