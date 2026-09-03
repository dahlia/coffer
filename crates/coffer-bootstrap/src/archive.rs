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

//! A deliberately narrow ZIP reader for the downloaded artifact.
//!
//! This is not a general ZIP implementation and must not become one.  It reads
//! the central directory, validates every entry in it against
//! [`Limits`], and extracts exactly the two entries named
//! by [`required_entry_names`].  Everything else in the archive is inspected for
//! policy violations and then left unread.
//!
//! # Threat model
//!
//! The archive is remote input.  It is retrieved over HTTPS from an Apple-owned
//! host, but Coffer does not verify the archive's own signature (see the crate
//! documentation for exactly what that means), so this reader assumes the bytes
//! are hostile:
//!
//! - Every allocation is bounded before it is made, from a declared size that
//!   is itself bounded first.
//! - Inflation is bounded by the declared uncompressed size, and the result is
//!   checked against both that size and the declared CRC-32.
//! - Encrypted, duplicate, symbolic-link and other non-regular entries are
//!   refused for the whole archive, not just for the two entries extracted.
//! - Entry names are refused unless they are relative, `/`-separated, free of
//!   `..`, `.`, empty components, backslashes, drive letters and NUL bytes.
//! - ZIP64 is refused rather than parsed.  The artifact has never used it, and
//!   an artifact that suddenly does is a layout change a maintainer should see.

use core::fmt;
use std::collections::BTreeMap;
use std::io::{self, Read, Seek, SeekFrom};

use crate::arch::Architecture;
use crate::limits::Limits;

/// The file name of the support library that exports the ADI entry points.
pub const STORE_SERVICES_CORE_LIBRARY: &str = "libstoreservicescore.so";

/// The file name of the support library the first one loads in turn.
pub const CORE_ADI_LIBRARY: &str = "libCoreADI.so";

/// `PK\x01\x02`, the central directory file header signature.
const CENTRAL_HEADER_SIGNATURE: u32 = 0x0201_4b50;

/// `PK\x03\x04`, the local file header signature.
const LOCAL_HEADER_SIGNATURE: u32 = 0x0403_4b50;

/// `PK\x05\x06`, the end of central directory signature.
const END_OF_CENTRAL_DIRECTORY_SIGNATURE: u32 = 0x0605_4b50;

/// `PK\x06\x07`, the ZIP64 end of central directory locator signature.
const ZIP64_LOCATOR_SIGNATURE: u32 = 0x0706_4b50;

/// The fixed part of an end of central directory record.
const END_OF_CENTRAL_DIRECTORY_BYTES: usize = 22;

/// The fixed part of a central directory file header.
const CENTRAL_HEADER_BYTES: usize = 46;

/// The fixed part of a local file header.
const LOCAL_HEADER_BYTES: usize = 30;

/// The fixed part of a ZIP64 end of central directory locator.
const ZIP64_LOCATOR_BYTES: usize = 20;

/// The largest ZIP archive comment, which bounds the end of central directory
/// search window.
const MAX_ARCHIVE_COMMENT_BYTES: usize = 65_535;

/// The longest entry name this reader will accept.
///
/// Well below any filesystem limit, and far above the names the artifact uses.
const MAX_ENTRY_NAME_BYTES: usize = 4_096;

/// The `Stored` compression method.
const METHOD_STORE: u16 = 0;

/// The `Deflate` compression method.
const METHOD_DEFLATE: u16 = 8;

/// General purpose bit 0: the entry is encrypted.
const FLAG_ENCRYPTED: u16 = 1 << 0;

/// General purpose bit 3: sizes and CRC live in a trailing data descriptor.
const FLAG_DATA_DESCRIPTOR: u16 = 1 << 3;

/// General purpose bit 6: strong encryption.
const FLAG_STRONG_ENCRYPTION: u16 = 1 << 6;

/// General purpose bit 13: central directory values are masked.
const FLAG_MASKED_LOCAL_HEADER: u16 = 1 << 13;

/// The `version made by` host system value for Unix.
const HOST_SYSTEM_UNIX: u16 = 3;

/// `S_IFMT`, the file type mask of a Unix mode.
const S_IFMT: u32 = 0o170_000;

/// `S_IFREG`, a regular file.
const S_IFREG: u32 = 0o100_000;

/// `S_IFDIR`, a directory.
const S_IFDIR: u32 = 0o040_000;

/// `S_IFLNK`, a symbolic link.
const S_IFLNK: u32 = 0o120_000;

/// One of the two Apple support libraries Coffer extracts.
///
/// This enumeration *is* the extraction allowlist.  There is no way to name a
/// third file, so no configuration value, archive entry or caller argument can
/// widen what Coffer takes out of the archive.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[non_exhaustive]
pub enum SupportLibrary {
    /// `libstoreservicescore.so`, which exports the ADI entry points and loads
    /// its companion in turn.
    StoreServicesCore,
    /// `libCoreADI.so`, the implementation behind those entry points.
    CoreAdi,
}

impl SupportLibrary {
    /// Both libraries, in the order Coffer extracts them.
    pub const ALL: [SupportLibrary; 2] =
        [SupportLibrary::StoreServicesCore, SupportLibrary::CoreAdi];

    /// The library's file name.
    #[must_use]
    pub const fn file_name(self) -> &'static str {
        match self {
            SupportLibrary::StoreServicesCore => STORE_SERVICES_CORE_LIBRARY,
            SupportLibrary::CoreAdi => CORE_ADI_LIBRARY,
        }
    }

    /// The library's exact archive entry name for an architecture.
    ///
    /// Names are compared byte for byte against the central directory; no
    /// globbing, no case folding and no path normalization is involved, because
    /// a name that needs normalizing to match is already a name Coffer should
    /// refuse.
    #[must_use]
    pub fn archive_entry_name(self, architecture: Architecture) -> String {
        format!("lib/{}/{}", architecture.android_abi(), self.file_name())
    }

    /// The library's path relative to an install directory.
    ///
    /// This matches [`SupportLibrary::archive_entry_name`] on purpose: the
    /// loader that will eventually consume these files expects to find them
    /// under a `lib/<abi>/` hierarchy, so preserving the archive's own layout
    /// keeps the install directory usable as a library root as it is.
    #[must_use]
    pub fn install_relative_path(self, architecture: Architecture) -> String {
        self.archive_entry_name(architecture)
    }
}

impl fmt::Display for SupportLibrary {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.file_name())
    }
}

/// The archive-relative paths of the two libraries Coffer extracts.
#[must_use]
pub fn required_entry_names(architecture: Architecture) -> [String; 2] {
    SupportLibrary::ALL.map(|library| library.archive_entry_name(architecture))
}

/// A way in which the archive is not the artifact Coffer expects.
///
/// Variants describe archive structure only.  The one variant that carries an
/// entry name, [`ArchiveViolation::MissingRequiredEntry`], carries a name Coffer
/// itself constructed from the host architecture, never a name taken from the
/// archive.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ArchiveViolation {
    /// The archive is too short to contain an end of central directory record.
    TooShort,
    /// No end of central directory record was found in the search window.
    EndOfCentralDirectoryNotFound,
    /// The archive uses ZIP64, which this reader refuses rather than parses.
    Zip64NotSupported,
    /// The archive declares more than one disk, which this reader refuses.
    MultiDiskNotSupported,
    /// The central directory does not lie inside the archive.
    CentralDirectoryOutOfBounds,
    /// The central directory is larger than [`Limits::max_central_directory_bytes`].
    CentralDirectoryTooLarge {
        /// The declared size.
        declared: u64,
        /// The configured ceiling.
        limit: u64,
    },
    /// The archive declares more entries than [`Limits::max_entries`].
    TooManyEntries {
        /// The declared entry count.
        declared: u64,
        /// The configured ceiling.
        limit: u32,
    },
    /// The central directory ended before the declared number of entries was
    /// read, or carried trailing bytes after them.
    CentralDirectoryMalformed,
    /// An entry name is not an acceptable relative archive path.
    EntryNameRejected,
    /// Two entries share a name.
    DuplicateEntry,
    /// An entry is encrypted.
    EncryptedEntry,
    /// An entry is a symbolic link.
    SymlinkEntry,
    /// An entry is neither a regular file nor a directory.
    SpecialEntry,
    /// An entry uses a compression method other than `Stored` or `Deflate`.
    UnsupportedCompressionMethod {
        /// The method the entry declares.
        method: u16,
    },
    /// An entry declares a compressed size over
    /// [`Limits::max_entry_compressed_bytes`].
    EntryCompressedSizeTooLarge {
        /// The declared compressed size.
        declared: u64,
        /// The configured ceiling.
        limit: u64,
    },
    /// An entry declares an uncompressed size over
    /// [`Limits::max_entry_uncompressed_bytes`].
    EntryUncompressedSizeTooLarge {
        /// The declared uncompressed size.
        declared: u64,
        /// The configured ceiling.
        limit: u64,
    },
    /// The declared uncompressed sizes sum to more than
    /// [`Limits::max_total_uncompressed_bytes`].
    TotalUncompressedSizeTooLarge {
        /// The configured ceiling.
        limit: u64,
    },
    /// An entry's declared expansion ratio exceeds
    /// [`Limits::max_compression_ratio`].
    CompressionRatioTooHigh {
        /// The declared uncompressed size.
        uncompressed: u64,
        /// The declared compressed size.
        compressed: u64,
        /// The configured ceiling.
        limit: u64,
    },
    /// An entry's local file header is missing, malformed, or disagrees with
    /// the central directory.
    LocalHeaderMismatch,
    /// An entry's data does not lie inside the archive.
    EntryDataOutOfBounds,
    /// An entry did not inflate, or inflated to the wrong size.
    EntryDataCorrupt,
    /// An entry's CRC-32 does not match the value in the central directory.
    ChecksumMismatch,
    /// One of the two required libraries is not in the archive.
    MissingRequiredEntry {
        /// The archive-relative path Coffer looked for.
        name: String,
    },
    /// Reading the archive from disk failed.
    Io {
        /// The kind of I/O failure, without the path it happened on.
        kind: io::ErrorKind,
    },
}

impl fmt::Display for ArchiveViolation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ArchiveViolation::TooShort => f.write_str("archive is too short to be a ZIP archive"),
            ArchiveViolation::EndOfCentralDirectoryNotFound => {
                f.write_str("archive has no end of central directory record")
            }
            ArchiveViolation::Zip64NotSupported => {
                f.write_str("archive uses ZIP64, which Coffer refuses")
            }
            ArchiveViolation::MultiDiskNotSupported => {
                f.write_str("archive spans multiple disks, which Coffer refuses")
            }
            ArchiveViolation::CentralDirectoryOutOfBounds => {
                f.write_str("archive central directory lies outside the archive")
            }
            ArchiveViolation::CentralDirectoryTooLarge { declared, limit } => write!(
                f,
                "archive central directory is {declared} bytes, over the {limit}-byte limit"
            ),
            ArchiveViolation::TooManyEntries { declared, limit } => write!(
                f,
                "archive declares {declared} entries, over the limit of {limit}"
            ),
            ArchiveViolation::CentralDirectoryMalformed => {
                f.write_str("archive central directory is malformed")
            }
            ArchiveViolation::EntryNameRejected => {
                f.write_str("archive contains an entry whose name is not an acceptable path")
            }
            ArchiveViolation::DuplicateEntry => {
                f.write_str("archive contains two entries with the same name")
            }
            ArchiveViolation::EncryptedEntry => f.write_str("archive contains an encrypted entry"),
            ArchiveViolation::SymlinkEntry => f.write_str("archive contains a symbolic link entry"),
            ArchiveViolation::SpecialEntry => {
                f.write_str("archive contains an entry that is not a regular file or directory")
            }
            ArchiveViolation::UnsupportedCompressionMethod { method } => write!(
                f,
                "archive contains an entry compressed with unsupported method {method}"
            ),
            ArchiveViolation::EntryCompressedSizeTooLarge { declared, limit } => write!(
                f,
                "archive entry declares {declared} compressed bytes, over the {limit}-byte limit"
            ),
            ArchiveViolation::EntryUncompressedSizeTooLarge { declared, limit } => write!(
                f,
                "archive entry declares {declared} uncompressed bytes, over the {limit}-byte limit"
            ),
            ArchiveViolation::TotalUncompressedSizeTooLarge { limit } => write!(
                f,
                "archive entries declare more than the {limit}-byte total uncompressed limit"
            ),
            ArchiveViolation::CompressionRatioTooHigh {
                uncompressed,
                compressed,
                limit,
            } => write!(
                f,
                "archive entry expands {uncompressed} from {compressed} bytes, over the {limit}:1 limit"
            ),
            ArchiveViolation::LocalHeaderMismatch => {
                f.write_str("archive entry disagrees with its local file header")
            }
            ArchiveViolation::EntryDataOutOfBounds => {
                f.write_str("archive entry data lies outside the archive")
            }
            ArchiveViolation::EntryDataCorrupt => {
                f.write_str("archive entry did not decompress to its declared size")
            }
            ArchiveViolation::ChecksumMismatch => {
                f.write_str("archive entry failed its CRC-32 check")
            }
            ArchiveViolation::MissingRequiredEntry { name } => {
                write!(f, "archive does not contain the required entry `{name}`")
            }
            ArchiveViolation::Io { kind } => write!(f, "reading the archive failed: {kind}"),
        }
    }
}

impl std::error::Error for ArchiveViolation {}

impl From<io::Error> for ArchiveViolation {
    fn from(error: io::Error) -> Self {
        ArchiveViolation::Io { kind: error.kind() }
    }
}

/// One central directory entry, after validation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Entry {
    /// The archive-relative name.
    pub(crate) name: String,
    /// The compression method, already restricted to `Stored` or `Deflate`.
    method: u16,
    /// The general purpose bit flag.
    flags: u16,
    /// The declared CRC-32 of the uncompressed data.
    crc32: u32,
    /// The declared compressed size.
    compressed_size: u64,
    /// The declared uncompressed size.
    pub(crate) uncompressed_size: u64,
    /// The offset of the entry's local file header.
    local_header_offset: u64,
}

/// A validated view of the archive's central directory, plus the reader the
/// entry data is extracted from.
pub(crate) struct Archive<R> {
    reader: R,
    entries: BTreeMap<String, Entry>,
    /// Where the central directory starts, which is the end of the entry data
    /// region.  Entry data must lie before it.
    central_directory_offset: u64,
}

impl<R: Read + Seek> Archive<R> {
    /// Reads and validates the central directory.
    ///
    /// # Errors
    ///
    /// Returns the first [`ArchiveViolation`] found.  Nothing is extracted and
    /// no entry data is read here, so a violation costs at most one central
    /// directory read.
    pub(crate) fn open(mut reader: R, limits: &Limits) -> Result<Self, ArchiveViolation> {
        let archive_length = reader.seek(SeekFrom::End(0))?;
        if archive_length < END_OF_CENTRAL_DIRECTORY_BYTES as u64 {
            return Err(ArchiveViolation::TooShort);
        }

        let end = read_end_of_central_directory(&mut reader, archive_length)?;

        if u64::from(end.central_directory_size) > limits.max_central_directory_bytes {
            return Err(ArchiveViolation::CentralDirectoryTooLarge {
                declared: u64::from(end.central_directory_size),
                limit: limits.max_central_directory_bytes,
            });
        }
        if u64::from(end.total_entries) > u64::from(limits.max_entries) {
            return Err(ArchiveViolation::TooManyEntries {
                declared: u64::from(end.total_entries),
                limit: limits.max_entries,
            });
        }
        let directory_end = u64::from(end.central_directory_offset)
            .checked_add(u64::from(end.central_directory_size))
            .ok_or(ArchiveViolation::CentralDirectoryOutOfBounds)?;
        if directory_end > archive_length {
            return Err(ArchiveViolation::CentralDirectoryOutOfBounds);
        }

        let mut directory = vec![0u8; end.central_directory_size as usize];
        reader.seek(SeekFrom::Start(u64::from(end.central_directory_offset)))?;
        reader.read_exact(&mut directory)?;

        let entries = parse_central_directory(
            &directory,
            end.total_entries,
            u64::from(end.central_directory_offset),
            limits,
        )?;

        Ok(Self {
            reader,
            entries,
            central_directory_offset: u64::from(end.central_directory_offset),
        })
    }

    /// The number of entries the archive declares.
    #[cfg(test)]
    pub(crate) fn entry_count(&self) -> usize {
        self.entries.len()
    }

    /// Extracts one entry by exact name.
    ///
    /// # Errors
    ///
    /// Returns [`ArchiveViolation::MissingRequiredEntry`] when the name is not
    /// present, and otherwise the first structural, size, decompression or
    /// checksum violation encountered.
    pub(crate) fn extract(
        &mut self,
        name: &str,
        limits: &Limits,
    ) -> Result<Vec<u8>, ArchiveViolation> {
        let entry = self
            .entries
            .get(name)
            .ok_or_else(|| ArchiveViolation::MissingRequiredEntry {
                name: name.to_owned(),
            })?
            .clone();

        // The central directory pass already bounded both sizes; the ratio is
        // checked only for the entries actually inflated, because it is the
        // inflation that turns a hostile ratio into an allocation.
        check_compression_ratio(&entry, limits)?;

        let data_offset = self.locate_entry_data(&entry)?;
        let compressed_len = usize::try_from(entry.compressed_size)
            .map_err(|_| ArchiveViolation::EntryDataOutOfBounds)?;
        let uncompressed_len = usize::try_from(entry.uncompressed_size)
            .map_err(|_| ArchiveViolation::EntryDataOutOfBounds)?;

        let mut compressed = vec![0u8; compressed_len];
        self.reader.seek(SeekFrom::Start(data_offset))?;
        self.reader.read_exact(&mut compressed)?;

        let plain = match entry.method {
            METHOD_STORE => {
                if compressed.len() != uncompressed_len {
                    return Err(ArchiveViolation::EntryDataCorrupt);
                }
                compressed
            }
            METHOD_DEFLATE => {
                // The limit is the declared uncompressed size, so a stream that
                // expands further stops here instead of allocating.
                miniz_oxide::inflate::decompress_to_vec_with_limit(&compressed, uncompressed_len)
                    .map_err(|_| ArchiveViolation::EntryDataCorrupt)?
            }
            method => return Err(ArchiveViolation::UnsupportedCompressionMethod { method }),
        };

        if plain.len() != uncompressed_len {
            return Err(ArchiveViolation::EntryDataCorrupt);
        }
        let mut hasher = crc32fast::Hasher::new();
        hasher.update(&plain);
        if hasher.finalize() != entry.crc32 {
            return Err(ArchiveViolation::ChecksumMismatch);
        }
        Ok(plain)
    }

    /// Reads and validates an entry's local file header, returning the offset
    /// of its data.
    fn locate_entry_data(&mut self, entry: &Entry) -> Result<u64, ArchiveViolation> {
        if entry.local_header_offset >= self.central_directory_offset {
            return Err(ArchiveViolation::EntryDataOutOfBounds);
        }
        self.reader
            .seek(SeekFrom::Start(entry.local_header_offset))?;
        let mut header = [0u8; LOCAL_HEADER_BYTES];
        self.reader.read_exact(&mut header)?;
        if read_u32(&header, 0) != LOCAL_HEADER_SIGNATURE {
            return Err(ArchiveViolation::LocalHeaderMismatch);
        }
        let local_flags = read_u16(&header, 6);
        let local_method = read_u16(&header, 8);
        let local_crc = read_u32(&header, 14);
        let local_compressed = u64::from(read_u32(&header, 18));
        let local_uncompressed = u64::from(read_u32(&header, 22));
        let name_length = usize::from(read_u16(&header, 26));
        let extra_length = usize::from(read_u16(&header, 28));

        if local_method != entry.method {
            return Err(ArchiveViolation::LocalHeaderMismatch);
        }
        if name_length != entry.name.len() {
            return Err(ArchiveViolation::LocalHeaderMismatch);
        }
        let mut name = vec![0u8; name_length];
        self.reader.read_exact(&mut name)?;
        if name != entry.name.as_bytes() {
            return Err(ArchiveViolation::LocalHeaderMismatch);
        }
        // The two headers must agree about whether a data descriptor follows,
        // because that bit is what decides which copy of the sizes is
        // authoritative.
        if local_flags & FLAG_DATA_DESCRIPTOR != entry.flags & FLAG_DATA_DESCRIPTOR {
            return Err(ArchiveViolation::LocalHeaderMismatch);
        }
        // With bit 3 set the local sizes and CRC are zero placeholders and the
        // real values live in a trailing data descriptor, so only the central
        // directory values are authoritative.  Without it the two must agree.
        if entry.flags & FLAG_DATA_DESCRIPTOR == 0
            && (local_crc != entry.crc32
                || local_compressed != entry.compressed_size
                || local_uncompressed != entry.uncompressed_size)
        {
            return Err(ArchiveViolation::LocalHeaderMismatch);
        }

        let data_offset = entry
            .local_header_offset
            .checked_add(LOCAL_HEADER_BYTES as u64)
            .and_then(|offset| offset.checked_add(name_length as u64))
            .and_then(|offset| offset.checked_add(extra_length as u64))
            .ok_or(ArchiveViolation::EntryDataOutOfBounds)?;
        let data_end = data_offset
            .checked_add(entry.compressed_size)
            .ok_or(ArchiveViolation::EntryDataOutOfBounds)?;
        if data_end > self.central_directory_offset {
            return Err(ArchiveViolation::EntryDataOutOfBounds);
        }
        Ok(data_offset)
    }
}

/// The fields of an end of central directory record this reader uses.
struct EndOfCentralDirectory {
    total_entries: u16,
    central_directory_size: u32,
    central_directory_offset: u32,
}

/// Finds and parses the end of central directory record.
fn read_end_of_central_directory<R: Read + Seek>(
    reader: &mut R,
    archive_length: u64,
) -> Result<EndOfCentralDirectory, ArchiveViolation> {
    let window_length = (END_OF_CENTRAL_DIRECTORY_BYTES + MAX_ARCHIVE_COMMENT_BYTES)
        .min(usize::try_from(archive_length).unwrap_or(usize::MAX));
    let window_start = archive_length - window_length as u64;
    let mut window = vec![0u8; window_length];
    reader.seek(SeekFrom::Start(window_start))?;
    reader.read_exact(&mut window)?;

    // Scan backwards so that a record embedded in entry data cannot shadow the
    // real one, and require the declared comment length to account for exactly
    // the bytes that follow, which is what makes the match unambiguous.
    let mut found = None;
    for start in (0..=window_length - END_OF_CENTRAL_DIRECTORY_BYTES).rev() {
        if read_u32(&window, start) != END_OF_CENTRAL_DIRECTORY_SIGNATURE {
            continue;
        }
        let comment_length = usize::from(read_u16(&window, start + 20));
        if start + END_OF_CENTRAL_DIRECTORY_BYTES + comment_length == window_length {
            found = Some(start);
            break;
        }
    }
    let start = found.ok_or(ArchiveViolation::EndOfCentralDirectoryNotFound)?;

    // A ZIP64 locator sits immediately before the record it applies to.
    if start >= ZIP64_LOCATOR_BYTES
        && read_u32(&window, start - ZIP64_LOCATOR_BYTES) == ZIP64_LOCATOR_SIGNATURE
    {
        return Err(ArchiveViolation::Zip64NotSupported);
    }

    let disk_number = read_u16(&window, start + 4);
    let directory_disk = read_u16(&window, start + 6);
    let entries_on_disk = read_u16(&window, start + 8);
    let total_entries = read_u16(&window, start + 10);
    let central_directory_size = read_u32(&window, start + 12);
    let central_directory_offset = read_u32(&window, start + 16);

    if disk_number != 0 || directory_disk != 0 || entries_on_disk != total_entries {
        return Err(ArchiveViolation::MultiDiskNotSupported);
    }
    // Any saturated field means the real values live in a ZIP64 record.
    if total_entries == u16::MAX
        || central_directory_size == u32::MAX
        || central_directory_offset == u32::MAX
    {
        return Err(ArchiveViolation::Zip64NotSupported);
    }
    Ok(EndOfCentralDirectory {
        total_entries,
        central_directory_size,
        central_directory_offset,
    })
}

/// Parses every central directory file header and applies the archive-wide
/// policy checks.
fn parse_central_directory(
    directory: &[u8],
    declared_entries: u16,
    central_directory_offset: u64,
    limits: &Limits,
) -> Result<BTreeMap<String, Entry>, ArchiveViolation> {
    let mut entries = BTreeMap::new();
    let mut cursor = 0usize;
    let mut total_uncompressed = 0u64;

    for _ in 0..declared_entries {
        if cursor
            .checked_add(CENTRAL_HEADER_BYTES)
            .is_none_or(|end| end > directory.len())
        {
            return Err(ArchiveViolation::CentralDirectoryMalformed);
        }
        let header = &directory[cursor..cursor + CENTRAL_HEADER_BYTES];
        if read_u32(header, 0) != CENTRAL_HEADER_SIGNATURE {
            return Err(ArchiveViolation::CentralDirectoryMalformed);
        }

        let version_made_by = read_u16(header, 4);
        let flags = read_u16(header, 8);
        let method = read_u16(header, 10);
        let crc32 = read_u32(header, 16);
        let compressed_size = u64::from(read_u32(header, 20));
        let uncompressed_size = u64::from(read_u32(header, 24));
        let name_length = usize::from(read_u16(header, 28));
        let extra_length = usize::from(read_u16(header, 30));
        let comment_length = usize::from(read_u16(header, 32));
        let disk_start = read_u16(header, 34);
        let external_attributes = read_u32(header, 38);
        let local_header_offset = u64::from(read_u32(header, 42));

        let name_start = cursor + CENTRAL_HEADER_BYTES;
        let name_end = name_start
            .checked_add(name_length)
            .ok_or(ArchiveViolation::CentralDirectoryMalformed)?;
        let next = name_end
            .checked_add(extra_length)
            .and_then(|offset| offset.checked_add(comment_length))
            .ok_or(ArchiveViolation::CentralDirectoryMalformed)?;
        if next > directory.len() {
            return Err(ArchiveViolation::CentralDirectoryMalformed);
        }

        if disk_start != 0 {
            return Err(ArchiveViolation::MultiDiskNotSupported);
        }
        if compressed_size == u64::from(u32::MAX)
            || uncompressed_size == u64::from(u32::MAX)
            || local_header_offset == u64::from(u32::MAX)
        {
            return Err(ArchiveViolation::Zip64NotSupported);
        }
        if flags & (FLAG_ENCRYPTED | FLAG_STRONG_ENCRYPTION | FLAG_MASKED_LOCAL_HEADER) != 0 {
            return Err(ArchiveViolation::EncryptedEntry);
        }
        if method != METHOD_STORE && method != METHOD_DEFLATE {
            return Err(ArchiveViolation::UnsupportedCompressionMethod { method });
        }
        check_entry_type(version_made_by, external_attributes)?;

        let name = validate_entry_name(&directory[name_start..name_end])?;
        if local_header_offset >= central_directory_offset {
            return Err(ArchiveViolation::EntryDataOutOfBounds);
        }
        if compressed_size > limits.max_entry_compressed_bytes {
            return Err(ArchiveViolation::EntryCompressedSizeTooLarge {
                declared: compressed_size,
                limit: limits.max_entry_compressed_bytes,
            });
        }
        if uncompressed_size > limits.max_entry_uncompressed_bytes {
            return Err(ArchiveViolation::EntryUncompressedSizeTooLarge {
                declared: uncompressed_size,
                limit: limits.max_entry_uncompressed_bytes,
            });
        }
        total_uncompressed = total_uncompressed.checked_add(uncompressed_size).ok_or(
            ArchiveViolation::TotalUncompressedSizeTooLarge {
                limit: limits.max_total_uncompressed_bytes,
            },
        )?;
        if total_uncompressed > limits.max_total_uncompressed_bytes {
            return Err(ArchiveViolation::TotalUncompressedSizeTooLarge {
                limit: limits.max_total_uncompressed_bytes,
            });
        }

        let entry = Entry {
            name: name.clone(),
            method,
            flags,
            crc32,
            compressed_size,
            uncompressed_size,
            local_header_offset,
        };
        if entries.insert(name, entry).is_some() {
            return Err(ArchiveViolation::DuplicateEntry);
        }
        cursor = next;
    }

    if cursor != directory.len() {
        return Err(ArchiveViolation::CentralDirectoryMalformed);
    }
    Ok(entries)
}

/// Refuses symbolic links and other non-regular entries.
///
/// Only Unix-made entries carry a mode; entries made by other host systems have
/// no file type to check, and the extraction allowlist plus the name rules are
/// what constrain those.
fn check_entry_type(
    version_made_by: u16,
    external_attributes: u32,
) -> Result<(), ArchiveViolation> {
    if version_made_by >> 8 != HOST_SYSTEM_UNIX {
        return Ok(());
    }
    let mode = external_attributes >> 16;
    match mode & S_IFMT {
        0 | S_IFREG | S_IFDIR => Ok(()),
        S_IFLNK => Err(ArchiveViolation::SymlinkEntry),
        _ => Err(ArchiveViolation::SpecialEntry),
    }
}

/// Validates an entry name and returns it as a `String`.
///
/// The rules are stricter than the ZIP specification requires.  A name that
/// would have to be normalized before it could be trusted is refused instead,
/// so no later stage has to reason about traversal.
fn validate_entry_name(raw: &[u8]) -> Result<String, ArchiveViolation> {
    if raw.is_empty() || raw.len() > MAX_ENTRY_NAME_BYTES {
        return Err(ArchiveViolation::EntryNameRejected);
    }
    let name = core::str::from_utf8(raw).map_err(|_| ArchiveViolation::EntryNameRejected)?;
    if name.contains('\0') || name.contains('\\') {
        return Err(ArchiveViolation::EntryNameRejected);
    }
    if name.starts_with('/') {
        return Err(ArchiveViolation::EntryNameRejected);
    }
    // A Windows drive-relative or drive-absolute name such as `C:\x` or `C:x`.
    let bytes = name.as_bytes();
    if bytes.len() >= 2 && bytes[1] == b':' && bytes[0].is_ascii_alphabetic() {
        return Err(ArchiveViolation::EntryNameRejected);
    }
    // A trailing `/` marks a directory entry and produces one empty final
    // component, which is the only empty component allowed.
    let body = name.strip_suffix('/').unwrap_or(name);
    if body.is_empty() {
        return Err(ArchiveViolation::EntryNameRejected);
    }
    for component in body.split('/') {
        if component.is_empty() || component == "." || component == ".." {
            return Err(ArchiveViolation::EntryNameRejected);
        }
    }
    Ok(name.to_owned())
}

/// Refuses an entry whose declared expansion ratio is implausible.
fn check_compression_ratio(entry: &Entry, limits: &Limits) -> Result<(), ArchiveViolation> {
    if entry.compressed_size == 0 {
        return if entry.uncompressed_size == 0 {
            Ok(())
        } else {
            Err(ArchiveViolation::CompressionRatioTooHigh {
                uncompressed: entry.uncompressed_size,
                compressed: 0,
                limit: limits.max_compression_ratio,
            })
        };
    }
    // Cross-multiplied rather than divided: integer division rounds down, so
    // `129 / 2 == 64` would slip a 64.5:1 entry past a 64:1 ceiling.  The
    // multiplication cannot overflow silently; a limit large enough to
    // overflow means no ratio is being enforced, so treat it as satisfied.
    let ceiling = entry
        .compressed_size
        .checked_mul(limits.max_compression_ratio);
    if ceiling.is_some_and(|ceiling| entry.uncompressed_size > ceiling) {
        return Err(ArchiveViolation::CompressionRatioTooHigh {
            uncompressed: entry.uncompressed_size,
            compressed: entry.compressed_size,
            limit: limits.max_compression_ratio,
        });
    }
    Ok(())
}

/// Reads a little-endian `u16` at `offset`.
fn read_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([bytes[offset], bytes[offset + 1]])
}

/// Reads a little-endian `u32` at `offset`.
fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::synthetic::{SyntheticArchive, SyntheticEntry};
    use std::io::Cursor;

    fn limits() -> Limits {
        Limits::DEFAULT
    }

    fn open(bytes: Vec<u8>) -> Result<Archive<Cursor<Vec<u8>>>, ArchiveViolation> {
        Archive::open(Cursor::new(bytes), &limits())
    }

    #[test]
    fn reads_a_synthetic_archive_and_extracts_the_allowlisted_entries() {
        let architecture = Architecture::X86_64;
        let [store, adi] = required_entry_names(architecture);
        let archive_bytes = SyntheticArchive::apple_music_like(architecture).build();

        let mut archive = open(archive_bytes).expect("synthetic archive must open");
        assert!(archive.entry_count() >= 3);

        let store_bytes = archive.extract(&store, &limits()).expect("extract");
        let adi_bytes = archive.extract(&adi, &limits()).expect("extract");
        assert_eq!(
            &store_bytes[..4],
            &[0x7f, b'E', b'L', b'F'],
            "the allowlisted entry must round-trip byte for byte"
        );
        assert_eq!(&adi_bytes[..4], &[0x7f, b'E', b'L', b'F']);
    }

    #[test]
    fn extracts_a_stored_entry_as_well_as_a_deflated_one() {
        let payload = b"stored payload, not compressed".to_vec();
        let archive_bytes = SyntheticArchive::new()
            .with_entry(SyntheticEntry::stored(
                "lib/x86_64/plain.bin",
                payload.clone(),
            ))
            .build();
        let mut archive = open(archive_bytes).expect("open");
        assert_eq!(
            archive.extract("lib/x86_64/plain.bin", &limits()).unwrap(),
            payload
        );
    }

    #[test]
    fn reports_a_missing_required_entry_by_name() {
        let architecture = Architecture::X86_64;
        let [store, _] = required_entry_names(architecture);
        let archive_bytes = SyntheticArchive::apple_music_like(architecture)
            .without_entry(&store)
            .build();
        let mut archive = open(archive_bytes).expect("open");
        assert_eq!(
            archive.extract(&store, &limits()),
            Err(ArchiveViolation::MissingRequiredEntry { name: store })
        );
    }

    #[test]
    fn rejects_an_entry_whose_data_was_corrupted_after_the_directory_was_written() {
        let archive_bytes = SyntheticArchive::new()
            .with_entry(SyntheticEntry::stored("a.bin", b"0123456789".to_vec()))
            .build();
        let mut corrupted = archive_bytes.clone();
        // The stored data starts right after the first local file header.
        let data_offset = LOCAL_HEADER_BYTES + "a.bin".len();
        corrupted[data_offset] ^= 0xff;
        let mut archive = open(corrupted).expect("open");
        assert_eq!(
            archive.extract("a.bin", &limits()),
            Err(ArchiveViolation::ChecksumMismatch)
        );
    }

    #[test]
    fn rejects_a_deflated_entry_whose_stream_does_not_match_its_declared_size() {
        let archive_bytes = SyntheticArchive::new()
            .with_entry(
                SyntheticEntry::deflated("a.bin", b"hello hello hello hello".to_vec())
                    .with_declared_uncompressed_size(4),
            )
            .build();
        let mut archive = open(archive_bytes).expect("open");
        assert_eq!(
            archive.extract("a.bin", &limits()),
            Err(ArchiveViolation::EntryDataCorrupt)
        );
    }

    #[test]
    fn rejects_encrypted_entries() {
        let archive_bytes = SyntheticArchive::new()
            .with_entry(SyntheticEntry::stored("a.bin", b"x".to_vec()).with_flags(FLAG_ENCRYPTED))
            .build();
        assert_eq!(
            open(archive_bytes).err(),
            Some(ArchiveViolation::EncryptedEntry)
        );

        let archive_bytes = SyntheticArchive::new()
            .with_entry(
                SyntheticEntry::stored("a.bin", b"x".to_vec()).with_flags(FLAG_STRONG_ENCRYPTION),
            )
            .build();
        assert_eq!(
            open(archive_bytes).err(),
            Some(ArchiveViolation::EncryptedEntry)
        );
    }

    #[test]
    fn rejects_duplicate_entry_names() {
        let archive_bytes = SyntheticArchive::new()
            .with_entry(SyntheticEntry::stored("a.bin", b"first".to_vec()))
            .with_entry(SyntheticEntry::stored("a.bin", b"second".to_vec()))
            .build();
        assert_eq!(
            open(archive_bytes).err(),
            Some(ArchiveViolation::DuplicateEntry)
        );
    }

    #[test]
    fn rejects_symbolic_link_and_special_entries() {
        let archive_bytes = SyntheticArchive::new()
            .with_entry(SyntheticEntry::stored("a.bin", b"/etc/passwd".to_vec()).into_symlink())
            .build();
        assert_eq!(
            open(archive_bytes).err(),
            Some(ArchiveViolation::SymlinkEntry)
        );

        let archive_bytes = SyntheticArchive::new()
            .with_entry(SyntheticEntry::stored("a.bin", Vec::new()).with_unix_mode(0o010_644))
            .build();
        assert_eq!(
            open(archive_bytes).err(),
            Some(ArchiveViolation::SpecialEntry)
        );
    }

    #[test]
    fn accepts_regular_and_directory_entries_made_on_unix() {
        let archive_bytes = SyntheticArchive::new()
            .with_entry(SyntheticEntry::stored("a.bin", b"x".to_vec()).with_unix_mode(0o100_644))
            .with_entry(SyntheticEntry::stored("dir/", Vec::new()).with_unix_mode(0o040_755))
            .build();
        assert!(open(archive_bytes).is_ok());
    }

    #[test]
    fn rejects_entry_names_that_escape_the_extraction_root() {
        for name in [
            "../evil",
            "lib/../../evil",
            "/etc/passwd",
            "lib\\x86_64\\evil.so",
            "C:/evil",
            "c:evil",
            "./evil",
            "lib//evil",
            "",
        ] {
            let archive_bytes = SyntheticArchive::new()
                .with_entry(SyntheticEntry::stored(name, b"x".to_vec()))
                .build();
            assert_eq!(
                open(archive_bytes).err(),
                Some(ArchiveViolation::EntryNameRejected),
                "name {name:?} should have been rejected"
            );
        }
    }

    #[test]
    fn rejects_an_entry_name_containing_a_nul_byte() {
        let archive_bytes = SyntheticArchive::new()
            .with_entry(SyntheticEntry::stored("a\0b", b"x".to_vec()))
            .build();
        assert_eq!(
            open(archive_bytes).err(),
            Some(ArchiveViolation::EntryNameRejected)
        );
    }

    #[test]
    fn rejects_an_entry_name_that_is_not_utf8() {
        let mut entry = SyntheticEntry::stored("ab", b"x".to_vec());
        entry.raw_name = vec![0xff, 0xfe];
        let archive_bytes = SyntheticArchive::new().with_entry(entry).build();
        assert_eq!(
            open(archive_bytes).err(),
            Some(ArchiveViolation::EntryNameRejected)
        );
    }

    #[test]
    fn rejects_an_archive_with_more_entries_than_the_limit() {
        let mut builder = SyntheticArchive::new();
        for index in 0..4 {
            builder = builder.with_entry(SyntheticEntry::stored(
                &format!("entry-{index}.bin"),
                b"x".to_vec(),
            ));
        }
        let archive_bytes = builder.build();
        let tight = Limits {
            max_entries: 3,
            ..Limits::DEFAULT
        };
        assert_eq!(
            Archive::open(Cursor::new(archive_bytes), &tight).err(),
            Some(ArchiveViolation::TooManyEntries {
                declared: 4,
                limit: 3
            })
        );
    }

    #[test]
    fn rejects_an_oversized_central_directory() {
        let archive_bytes = SyntheticArchive::new()
            .with_entry(SyntheticEntry::stored("a.bin", b"x".to_vec()))
            .build();
        let tight = Limits {
            max_central_directory_bytes: 8,
            ..Limits::DEFAULT
        };
        assert!(matches!(
            Archive::open(Cursor::new(archive_bytes), &tight).err(),
            Some(ArchiveViolation::CentralDirectoryTooLarge { .. })
        ));
    }

    #[test]
    fn rejects_an_entry_larger_than_the_per_entry_limits() {
        let archive_bytes = SyntheticArchive::new()
            .with_entry(SyntheticEntry::stored("a.bin", vec![0u8; 64]))
            .build();
        let tight = Limits {
            max_entry_uncompressed_bytes: 16,
            ..Limits::DEFAULT
        };
        assert_eq!(
            Archive::open(Cursor::new(archive_bytes.clone()), &tight).err(),
            Some(ArchiveViolation::EntryUncompressedSizeTooLarge {
                declared: 64,
                limit: 16
            })
        );

        let tight = Limits {
            max_entry_compressed_bytes: 16,
            ..Limits::DEFAULT
        };
        assert_eq!(
            Archive::open(Cursor::new(archive_bytes), &tight).err(),
            Some(ArchiveViolation::EntryCompressedSizeTooLarge {
                declared: 64,
                limit: 16
            })
        );
    }

    #[test]
    fn rejects_an_archive_whose_entries_sum_past_the_total_limit() {
        let archive_bytes = SyntheticArchive::new()
            .with_entry(SyntheticEntry::stored("a.bin", vec![0u8; 32]))
            .with_entry(SyntheticEntry::stored("b.bin", vec![0u8; 32]))
            .build();
        let tight = Limits {
            max_total_uncompressed_bytes: 48,
            ..Limits::DEFAULT
        };
        assert_eq!(
            Archive::open(Cursor::new(archive_bytes), &tight).err(),
            Some(ArchiveViolation::TotalUncompressedSizeTooLarge { limit: 48 })
        );
    }

    #[test]
    fn rejects_an_entry_whose_declared_expansion_ratio_is_implausible() {
        // A highly compressible payload: about 4096:1 declared expansion.
        let payload = vec![0u8; 1 << 16];
        let archive_bytes = SyntheticArchive::new()
            .with_entry(SyntheticEntry::deflated("bomb.bin", payload))
            .build();
        let tight = Limits {
            max_compression_ratio: 4,
            ..Limits::DEFAULT
        };
        let mut archive = Archive::open(Cursor::new(archive_bytes), &tight).expect("open");
        assert!(matches!(
            archive.extract("bomb.bin", &tight),
            Err(ArchiveViolation::CompressionRatioTooHigh { .. })
        ));
    }

    #[test]
    fn enforces_the_compression_ratio_without_rounding_it_down() {
        let tight = Limits {
            max_compression_ratio: 64,
            ..Limits::DEFAULT
        };
        let entry = |uncompressed: u64, compressed: u64| Entry {
            name: "a".to_owned(),
            method: METHOD_DEFLATE,
            flags: 0,
            crc32: 0,
            compressed_size: compressed,
            uncompressed_size: uncompressed,
            local_header_offset: 0,
        };
        // Exactly at the ceiling.
        check_compression_ratio(&entry(128, 2), &tight).expect("64:1 is allowed");
        // 64.5:1, which integer division would have rounded down to 64.
        assert!(matches!(
            check_compression_ratio(&entry(129, 2), &tight),
            Err(ArchiveViolation::CompressionRatioTooHigh { .. })
        ));
        assert!(matches!(
            check_compression_ratio(&entry(130, 2), &tight),
            Err(ArchiveViolation::CompressionRatioTooHigh { .. })
        ));
    }

    #[test]
    fn rejects_a_zero_length_compressed_entry_claiming_output() {
        let entry = Entry {
            name: "a".to_owned(),
            method: METHOD_DEFLATE,
            flags: 0,
            crc32: 0,
            compressed_size: 0,
            uncompressed_size: 1,
            local_header_offset: 0,
        };
        assert!(matches!(
            check_compression_ratio(&entry, &limits()),
            Err(ArchiveViolation::CompressionRatioTooHigh { .. })
        ));
    }

    #[test]
    fn rejects_an_unsupported_compression_method() {
        let archive_bytes = SyntheticArchive::new()
            .with_entry(SyntheticEntry::stored("a.bin", b"x".to_vec()).with_method(12))
            .build();
        assert_eq!(
            open(archive_bytes).err(),
            Some(ArchiveViolation::UnsupportedCompressionMethod { method: 12 })
        );
    }

    #[test]
    fn rejects_a_zip64_archive() {
        let archive_bytes = SyntheticArchive::new()
            .with_entry(SyntheticEntry::stored("a.bin", b"x".to_vec()))
            .with_zip64_locator()
            .build();
        assert_eq!(
            open(archive_bytes).err(),
            Some(ArchiveViolation::Zip64NotSupported)
        );
    }

    #[test]
    fn rejects_a_truncated_archive() {
        let archive_bytes = SyntheticArchive::new()
            .with_entry(SyntheticEntry::stored("a.bin", b"x".to_vec()))
            .build();
        assert_eq!(open(Vec::new()).err(), Some(ArchiveViolation::TooShort));
        assert_eq!(
            open(archive_bytes[..10].to_vec()).err(),
            Some(ArchiveViolation::TooShort)
        );
        // Long enough to hold a record, but without one.
        assert_eq!(
            open(vec![0u8; 512]).err(),
            Some(ArchiveViolation::EndOfCentralDirectoryNotFound)
        );
        // The central directory is gone but the record still points at it.
        let cut = archive_bytes.len() - END_OF_CENTRAL_DIRECTORY_BYTES;
        let mut truncated = archive_bytes[..cut / 2].to_vec();
        truncated.extend_from_slice(&archive_bytes[cut..]);
        assert!(matches!(
            open(truncated).err(),
            Some(
                ArchiveViolation::CentralDirectoryOutOfBounds
                    | ArchiveViolation::CentralDirectoryMalformed
                    | ArchiveViolation::EndOfCentralDirectoryNotFound
            )
        ));
    }

    #[test]
    fn rejects_a_local_header_that_disagrees_with_the_central_directory() {
        let archive_bytes = SyntheticArchive::new()
            .with_entry(SyntheticEntry::stored("a.bin", b"0123456789".to_vec()))
            .build();
        let mut tampered = archive_bytes.clone();
        // Rewrite the local header's CRC-32 field.
        tampered[14..18].copy_from_slice(&0xdead_beefu32.to_le_bytes());
        let mut archive = open(tampered).expect("open");
        assert_eq!(
            archive.extract("a.bin", &limits()),
            Err(ArchiveViolation::LocalHeaderMismatch)
        );

        let mut tampered = archive_bytes;
        // Rewrite the local header signature.
        tampered[..4].copy_from_slice(&0u32.to_le_bytes());
        let mut archive = open(tampered).expect("open");
        assert_eq!(
            archive.extract("a.bin", &limits()),
            Err(ArchiveViolation::LocalHeaderMismatch)
        );
    }

    /// The byte offset of the end of central directory record in an archive
    /// built by [`SyntheticArchive`], which never writes a comment unless asked.
    fn end_of_central_directory_offset(archive: &[u8]) -> usize {
        archive.len() - END_OF_CENTRAL_DIRECTORY_BYTES
    }

    /// Overwrites a little-endian `u16` field of the end record.
    fn patch_end_u16(archive: &mut [u8], field_offset: usize, value: u16) {
        let at = end_of_central_directory_offset(archive) + field_offset;
        archive[at..at + 2].copy_from_slice(&value.to_le_bytes());
    }

    /// Overwrites a little-endian `u32` field of the end record.
    fn patch_end_u32(archive: &mut [u8], field_offset: usize, value: u32) {
        let at = end_of_central_directory_offset(archive) + field_offset;
        archive[at..at + 4].copy_from_slice(&value.to_le_bytes());
    }

    #[test]
    fn extracts_an_entry_whose_sizes_live_in_a_trailing_data_descriptor() {
        // Android build tools emit this layout, so rejecting it would reject
        // the genuine artifact.  The local header's CRC and sizes are zero and
        // the central directory is authoritative.
        let payload = b"a payload written by a streaming zip writer".to_vec();
        let archive_bytes = SyntheticArchive::new()
            .with_entry(
                SyntheticEntry::deflated("lib/x86_64/a.so", payload.clone()).with_data_descriptor(),
            )
            .build();
        let mut archive = open(archive_bytes).expect("open");
        assert_eq!(
            archive.extract("lib/x86_64/a.so", &limits()).unwrap(),
            payload
        );
    }

    #[test]
    fn rejects_an_entry_whose_headers_disagree_about_a_data_descriptor() {
        // Bit 3 in the central directory but not the local header: the two
        // copies disagree about which sizes are authoritative.
        let archive_bytes = SyntheticArchive::new()
            .with_entry(
                SyntheticEntry::stored("a.bin", b"0123456789".to_vec())
                    .with_flags(FLAG_DATA_DESCRIPTOR)
                    .with_local_flags(0),
            )
            .build();
        let mut archive = open(archive_bytes).expect("open");
        assert_eq!(
            archive.extract("a.bin", &limits()),
            Err(ArchiveViolation::LocalHeaderMismatch)
        );

        // And the other way round.
        let archive_bytes = SyntheticArchive::new()
            .with_entry(
                SyntheticEntry::stored("a.bin", b"0123456789".to_vec())
                    .with_local_flags(FLAG_DATA_DESCRIPTOR),
            )
            .build();
        let mut archive = open(archive_bytes).expect("open");
        assert_eq!(
            archive.extract("a.bin", &limits()),
            Err(ArchiveViolation::LocalHeaderMismatch)
        );
    }

    #[test]
    fn rejects_saturated_end_record_fields_that_mean_the_real_values_are_zip64() {
        let base = SyntheticArchive::new()
            .with_entry(SyntheticEntry::stored("a.bin", b"x".to_vec()))
            .build();

        // `total_entries` at offset 10, central directory size at 12, offset
        // at 16.  Each saturates when the true value lives in a ZIP64 record.
        let mut archive_bytes = base.clone();
        patch_end_u16(&mut archive_bytes, 10, u16::MAX);
        patch_end_u16(&mut archive_bytes, 8, u16::MAX);
        assert_eq!(
            open(archive_bytes).err(),
            Some(ArchiveViolation::Zip64NotSupported)
        );

        let mut archive_bytes = base.clone();
        patch_end_u32(&mut archive_bytes, 12, u32::MAX);
        assert_eq!(
            open(archive_bytes).err(),
            Some(ArchiveViolation::Zip64NotSupported)
        );

        let mut archive_bytes = base;
        patch_end_u32(&mut archive_bytes, 16, u32::MAX);
        assert_eq!(
            open(archive_bytes).err(),
            Some(ArchiveViolation::Zip64NotSupported)
        );
    }

    #[test]
    fn rejects_an_archive_that_claims_to_span_several_disks() {
        let base = SyntheticArchive::new()
            .with_entry(SyntheticEntry::stored("a.bin", b"x".to_vec()))
            .build();

        // This disk number at offset 4, the central directory's disk at 6.
        for field in [4usize, 6] {
            let mut archive_bytes = base.clone();
            patch_end_u16(&mut archive_bytes, field, 1);
            assert_eq!(
                open(archive_bytes).err(),
                Some(ArchiveViolation::MultiDiskNotSupported),
                "field at offset {field} should have been rejected"
            );
        }

        // Entries on this disk disagreeing with the total.
        let mut archive_bytes = base;
        patch_end_u16(&mut archive_bytes, 8, 2);
        assert_eq!(
            open(archive_bytes).err(),
            Some(ArchiveViolation::MultiDiskNotSupported)
        );
    }

    #[test]
    fn rejects_trailing_bytes_after_the_last_central_directory_header() {
        let base = SyntheticArchive::new()
            .with_entry(SyntheticEntry::stored("a.bin", b"x".to_vec()))
            .build();
        let end = end_of_central_directory_offset(&base);
        let declared_size = read_u32(&base, end + 12);

        // Four bytes of padding inside the declared central directory that no
        // header accounts for.
        let mut archive_bytes = base[..end].to_vec();
        archive_bytes.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
        archive_bytes.extend_from_slice(&base[end..]);
        patch_end_u32(&mut archive_bytes, 12, declared_size + 4);
        assert_eq!(
            open(archive_bytes).err(),
            Some(ArchiveViolation::CentralDirectoryMalformed)
        );
    }

    #[test]
    fn required_entry_names_are_architecture_specific_and_exact() {
        assert_eq!(
            required_entry_names(Architecture::X86_64),
            [
                "lib/x86_64/libstoreservicescore.so".to_owned(),
                "lib/x86_64/libCoreADI.so".to_owned(),
            ]
        );
        assert_eq!(
            required_entry_names(Architecture::Aarch64),
            [
                "lib/arm64-v8a/libstoreservicescore.so".to_owned(),
                "lib/arm64-v8a/libCoreADI.so".to_owned(),
            ]
        );
    }
}
