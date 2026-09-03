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

//! Explicit bounds on everything the remote artifact controls.
//!
//! Every allocation this crate makes on behalf of a downloaded archive is
//! bounded by a field of [`Limits`].  The defaults are chosen with headroom
//! over the artifact as observed in 2026-09, so ordinary growth does not break
//! bootstrap, while a value far outside the observed range fails closed instead
//! of being trusted.
//!
//! [`Limits`] is a plain value type so tests can shrink every bound to a few
//! bytes and exercise the overflow paths without producing large fixtures.

/// One mebibyte, for readability in the constants below.
const MIB: u64 = 1024 * 1024;

/// Bounds applied to the downloaded archive and to everything read out of it.
///
/// # Invariants
///
/// A limit is a hard ceiling, never a target.  Code that consumes remote data
/// checks the declared size against the relevant field *before* allocating, and
/// then checks the produced size again while streaming, because a declared size
/// is itself remote input.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct Limits {
    /// The largest archive Coffer will download or read.
    ///
    /// The observed artifact was about 136 MiB in 2026-09 and has stayed in the
    /// 125 MiB to 136 MiB range since 2021.
    pub max_archive_bytes: u64,
    /// The largest APK Signing Block Coffer will read into memory.
    ///
    /// The observed block was 16 KiB.  One MiB leaves ample room for signer
    /// metadata while bounding the only unverified block read as a whole.
    pub max_signing_block_bytes: u64,
    /// The largest number of one-MiB content-digest chunks.
    ///
    /// The observed artifact needed 138 chunks.  This independent ceiling
    /// keeps a caller-supplied archive-size limit from making the digest loop
    /// effectively unbounded.
    pub max_signature_chunks: u32,
    /// The largest ZIP central directory Coffer will read into memory.
    pub max_central_directory_bytes: u64,
    /// The largest number of entries the central directory may declare.
    ///
    /// The observed artifact declared 4,468.
    pub max_entries: u32,
    /// The largest compressed size any single entry may declare.
    pub max_entry_compressed_bytes: u64,
    /// The largest uncompressed size any single entry may declare.
    ///
    /// The largest observed entry was about 13.3 MiB, and the largest entry
    /// Coffer extracts was about 2.3 MiB.
    pub max_entry_uncompressed_bytes: u64,
    /// The largest sum of declared uncompressed sizes across all entries.
    ///
    /// The observed artifact declared about 286 MiB in total.
    pub max_total_uncompressed_bytes: u64,
    /// The largest ratio of uncompressed to compressed size Coffer will inflate.
    ///
    /// Applied to the entries Coffer actually extracts.  Deflate cannot exceed
    /// about 1032:1, so this bound is what makes a hostile entry a bounded error
    /// rather than a large allocation.
    pub max_compression_ratio: u64,
    /// The longest HTTP response header value retained in install metadata.
    ///
    /// Header values are remote input that ends up in a file on disk, so they
    /// are length-bounded and character-restricted before being recorded.
    pub max_header_value_bytes: usize,
    /// The largest install metadata document Coffer will read back from disk.
    pub max_metadata_bytes: u64,
}

impl Limits {
    /// The bounds used unless a caller supplies its own.
    pub const DEFAULT: Limits = Limits {
        max_archive_bytes: 512 * MIB,
        max_signing_block_bytes: MIB,
        max_signature_chunks: 1_024,
        max_central_directory_bytes: 8 * MIB,
        max_entries: 20_000,
        max_entry_compressed_bytes: 64 * MIB,
        max_entry_uncompressed_bytes: 64 * MIB,
        max_total_uncompressed_bytes: 2048 * MIB,
        max_compression_ratio: 64,
        max_header_value_bytes: 256,
        max_metadata_bytes: MIB,
    };
}

impl Default for Limits {
    fn default() -> Self {
        Limits::DEFAULT
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_leave_headroom_over_the_artifact_observed_in_2026_09() {
        let observed_archive_bytes: u64 = 142_139_820;
        let observed_entries: u32 = 4_468;
        let observed_signing_block_bytes: u64 = 16_384;
        let observed_signature_chunks: u32 = 138;
        let observed_total_uncompressed: u64 = 300_132_707;
        let largest_extracted_entry: u64 = 2_391_768;

        let limits = Limits::DEFAULT;
        assert!(limits.max_archive_bytes > observed_archive_bytes);
        assert!(limits.max_signing_block_bytes > observed_signing_block_bytes);
        assert!(limits.max_signature_chunks > observed_signature_chunks);
        assert!(limits.max_entries > observed_entries);
        assert!(limits.max_total_uncompressed_bytes > observed_total_uncompressed);
        assert!(limits.max_entry_uncompressed_bytes > largest_extracted_entry);
    }

    #[test]
    fn default_impl_matches_the_constant() {
        assert_eq!(Limits::default(), Limits::DEFAULT);
    }
}
