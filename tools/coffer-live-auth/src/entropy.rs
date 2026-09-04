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

//! Kernel-backed randomness for the SRP ephemeral and the profile slot.
//!
//! [`OsEntropy`] is the production [`Entropy`] source.  It calls the
//! `getrandom(2)` system call through `rustix`, which blocks until the kernel
//! pool is initialized and never reads a device file that could be replaced
//! or exhausted.  The wrapper refuses to return a buffer that the kernel did
//! not fill completely or that came back all zero, because either would be a
//! predictable SRP ephemeral, and the protocol layer treats an entropy failure
//! as fatal for the attempt rather than falling back to anything weaker.

use std::io;

use coffer_protocol::entropy::{Entropy, EntropyError};
use rustix::rand::{GetRandomFlags, getrandom};

/// The operating system's CSPRNG through `getrandom(2)`.
#[derive(Debug, Clone, Copy, Default)]
pub struct OsEntropy;

impl Entropy for OsEntropy {
    fn fill(&self, dest: &mut [u8]) -> Result<(), EntropyError> {
        fill_from(dest, |buf| {
            getrandom(buf, GetRandomFlags::empty()).map_err(io::Error::from)
        })
    }
}

/// Fills `dest` from `source`, which returns how many bytes it wrote.
///
/// Every call must make progress, so the loop runs at most `dest.len()`
/// times.  A zero-length result, an over-long result, an I/O error, or an
/// all-zero buffer is reported instead of being papered over.
pub(crate) fn fill_from(
    dest: &mut [u8],
    mut source: impl FnMut(&mut [u8]) -> io::Result<usize>,
) -> Result<(), EntropyError> {
    let mut filled = 0usize;
    while filled < dest.len() {
        let remaining = &mut dest[filled..];
        let written = source(remaining).map_err(|error| match error.kind() {
            io::ErrorKind::Interrupted => EntropyError::new("getrandom was interrupted"),
            io::ErrorKind::Unsupported => EntropyError::new("getrandom is unsupported"),
            _ => EntropyError::new("getrandom failed"),
        })?;
        if written == 0 {
            return Err(EntropyError::new("getrandom returned no bytes"));
        }
        if written > remaining.len() {
            return Err(EntropyError::new("getrandom overran the buffer"));
        }
        filled += written;
    }
    if !dest.is_empty() && dest.iter().all(|byte| *byte == 0) {
        return Err(EntropyError::new("getrandom returned all-zero bytes"));
    }
    Ok(())
}

/// Draws a fixed-size random array from `entropy`.
///
/// # Errors
///
/// Propagates the source's [`EntropyError`].
pub fn random_array<const N: usize>(entropy: &impl Entropy) -> Result<[u8; N], EntropyError> {
    let mut bytes = [0u8; N];
    entropy.fill(&mut bytes)?;
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn os_entropy_fills_and_varies() {
        let first: [u8; 32] = random_array(&OsEntropy).unwrap();
        let second: [u8; 32] = random_array(&OsEntropy).unwrap();
        assert_ne!(first, second);
        assert!(first.iter().any(|b| *b != 0));
    }

    #[test]
    fn short_reads_are_completed_in_bounded_steps() {
        let mut calls = 0usize;
        let mut dest = [0u8; 8];
        fill_from(&mut dest, |buf| {
            calls += 1;
            buf[0] = calls as u8;
            Ok(1)
        })
        .unwrap();
        assert_eq!(calls, 8);
        assert_eq!(dest, [1, 2, 3, 4, 5, 6, 7, 8]);
    }

    #[test]
    fn zero_length_result_is_an_error() {
        let mut dest = [0u8; 4];
        let error = fill_from(&mut dest, |_| Ok(0)).unwrap_err();
        assert_eq!(error.detail(), "getrandom returned no bytes");
    }

    #[test]
    fn overrun_is_an_error() {
        let mut dest = [0u8; 4];
        let error = fill_from(&mut dest, |buf| Ok(buf.len() + 1)).unwrap_err();
        assert_eq!(error.detail(), "getrandom overran the buffer");
    }

    #[test]
    fn all_zero_output_is_refused() {
        let mut dest = [0u8; 16];
        let error = fill_from(&mut dest, |buf| {
            buf.fill(0);
            Ok(buf.len())
        })
        .unwrap_err();
        assert_eq!(error.detail(), "getrandom returned all-zero bytes");
    }

    #[test]
    fn io_errors_are_classified_without_their_text() {
        let mut dest = [0u8; 4];
        let error =
            fill_from(&mut dest, |_| Err(io::Error::other("sensitive detail"))).unwrap_err();
        assert_eq!(error.detail(), "getrandom failed");
        let error = fill_from(&mut dest, |_| {
            Err(io::Error::from(io::ErrorKind::Unsupported))
        })
        .unwrap_err();
        assert_eq!(error.detail(), "getrandom is unsupported");
    }

    #[test]
    fn empty_destination_is_a_no_op() {
        let mut dest = [0u8; 0];
        fill_from(&mut dest, |_| Ok(0)).unwrap();
    }
}
