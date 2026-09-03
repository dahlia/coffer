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

//! Synthetic archive and shared-object fixtures for the test suite.
//!
//! Every fixture here is generated from constants in this file.  No Apple
//! binary, no fragment of one, and nothing downloaded from Apple is committed
//! to the repository or produced by these builders: the "shared objects" are
//! valid ELF headers followed by filler bytes, and the "archive" is a ZIP file
//! this module writes byte by byte.
//!
//! Writing the ZIP by hand rather than with a ZIP library is deliberate.  The
//! reader in [`crate::archive`] has to be exercised with archives no compliant
//! writer would produce: duplicate names, encrypted flags, symbolic links,
//! traversal names, mismatched local headers and ZIP64 markers.

use std::collections::VecDeque;
use std::io::{self, Cursor, Read};
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

use crate::arch::{Architecture, ElfClass};
use crate::archive::{CORE_ADI_LIBRARY, STORE_SERVICES_CORE_LIBRARY};
use crate::limits::Limits;
use crate::source::{ArtifactSource, FetchError, FetchedArtifact, ObservedArtifact, SourceUrl};

/// `PK\x01\x02`.
const CENTRAL_HEADER_SIGNATURE: u32 = 0x0201_4b50;

/// `PK\x03\x04`.
const LOCAL_HEADER_SIGNATURE: u32 = 0x0403_4b50;

/// `PK\x05\x06`.
const END_OF_CENTRAL_DIRECTORY_SIGNATURE: u32 = 0x0605_4b50;

/// `PK\x06\x07`.
const ZIP64_LOCATOR_SIGNATURE: u32 = 0x0706_4b50;

/// `version made by` for a Unix host claiming ZIP specification 2.0.
const UNIX_VERSION_MADE_BY: u16 = (3 << 8) | 20;

/// A regular file with mode 0644.
const DEFAULT_UNIX_MODE: u32 = 0o100_644;

/// Builds a synthetic ELF shared object for `architecture`.
///
/// The header is a real, well-formed ELF file header; the body is filler so
/// that the object has a plausible size and compresses like real code does not.
pub(crate) fn synthetic_shared_object(architecture: Architecture, body_bytes: usize) -> Vec<u8> {
    let header_bytes = match architecture.elf_class() {
        ElfClass::Elf32 => 52usize,
        ElfClass::Elf64 => 64usize,
    };
    let mut object = vec![0u8; header_bytes];
    object[..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
    object[4] = architecture.elf_class() as u8;
    object[5] = 1; // ELFDATA2LSB
    object[6] = 1; // EV_CURRENT
    object[16..18].copy_from_slice(&3u16.to_le_bytes()); // ET_DYN
    object[18..20].copy_from_slice(&architecture.elf_machine().to_le_bytes());
    object[20..24].copy_from_slice(&1u32.to_le_bytes()); // EV_CURRENT
    object.extend((0..body_bytes).map(|index| (index % 251) as u8));
    object
}

/// One entry in a [`SyntheticArchive`].
#[derive(Clone, Debug)]
pub(crate) struct SyntheticEntry {
    /// The raw name bytes, so a test can write a name that is not valid UTF-8.
    pub(crate) raw_name: Vec<u8>,
    /// The uncompressed contents.
    data: Vec<u8>,
    /// The compression method written to both headers.
    method: u16,
    /// The general purpose bit flag written to both headers.
    flags: u16,
    /// The `version made by` field, whose high byte selects the host system.
    version_made_by: u16,
    /// The external attributes field, whose high 16 bits are the Unix mode.
    external_attributes: u32,
    /// Overrides the uncompressed size written to both headers.
    declared_uncompressed_size: Option<u32>,
    /// Overrides the general purpose bit flag in the local header only.
    local_flags: Option<u16>,
    /// Zeroes the CRC and both sizes in the local header, as a writer that
    /// defers them to a trailing data descriptor does.
    zero_local_sizes: bool,
}

impl SyntheticEntry {
    /// An entry stored without compression.
    pub(crate) fn stored(name: &str, data: Vec<u8>) -> Self {
        Self {
            raw_name: name.as_bytes().to_vec(),
            data,
            method: 0,
            flags: 0,
            version_made_by: UNIX_VERSION_MADE_BY,
            external_attributes: DEFAULT_UNIX_MODE << 16,
            declared_uncompressed_size: None,
            local_flags: None,
            zero_local_sizes: false,
        }
    }

    /// An entry compressed with raw deflate.
    pub(crate) fn deflated(name: &str, data: Vec<u8>) -> Self {
        Self {
            method: 8,
            ..Self::stored(name, data)
        }
    }

    /// Overrides the general purpose bit flag.
    pub(crate) fn with_flags(mut self, flags: u16) -> Self {
        self.flags = flags;
        self
    }

    /// Overrides the compression method without changing the stored bytes.
    pub(crate) fn with_method(mut self, method: u16) -> Self {
        self.method = method;
        self
    }

    /// Overrides the Unix mode in the external attributes.
    pub(crate) fn with_unix_mode(mut self, mode: u32) -> Self {
        self.version_made_by = UNIX_VERSION_MADE_BY;
        self.external_attributes = mode << 16;
        self
    }

    /// Marks the entry as a symbolic link.
    pub(crate) fn into_symlink(self) -> Self {
        self.with_unix_mode(0o120_777)
    }

    /// Writes a different uncompressed size than the data actually has.
    pub(crate) fn with_declared_uncompressed_size(mut self, size: u32) -> Self {
        self.declared_uncompressed_size = Some(size);
        self
    }

    /// Defers the CRC and sizes to a trailing data descriptor, as Android build
    /// tools and streaming ZIP writers do.
    ///
    /// General purpose bit 3 is set in both headers and the local header's CRC
    /// and sizes are zeroed, leaving the central directory authoritative.
    pub(crate) fn with_data_descriptor(mut self) -> Self {
        self.flags |= 1 << 3;
        self.zero_local_sizes = true;
        self
    }

    /// Writes a different general purpose bit flag in the local header than in
    /// the central directory.
    pub(crate) fn with_local_flags(mut self, flags: u16) -> Self {
        self.local_flags = Some(flags);
        self
    }

    /// The bytes written into the archive for this entry.
    fn payload(&self) -> Vec<u8> {
        match self.method {
            8 => miniz_oxide::deflate::compress_to_vec(&self.data, 6),
            _ => self.data.clone(),
        }
    }

    /// The uncompressed size written to both headers.
    fn declared_uncompressed(&self) -> u32 {
        self.declared_uncompressed_size
            .unwrap_or_else(|| u32::try_from(self.data.len()).expect("fixture fits in 32 bits"))
    }

    /// The CRC-32 written to both headers.
    fn crc32(&self) -> u32 {
        let mut hasher = crc32fast::Hasher::new();
        hasher.update(&self.data);
        hasher.finalize()
    }
}

/// A ZIP archive assembled byte by byte for the test suite.
#[derive(Clone, Debug, Default)]
pub(crate) struct SyntheticArchive {
    entries: Vec<SyntheticEntry>,
    zip64_locator: bool,
    comment: Vec<u8>,
}

impl SyntheticArchive {
    /// An empty archive.
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// An archive shaped like the artifact: the two support libraries for the
    /// given architecture, plus unrelated members that must be left alone.
    pub(crate) fn apple_music_like(architecture: Architecture) -> Self {
        let abi = architecture.android_abi();
        let other = if architecture == Architecture::Aarch64 {
            Architecture::X86_64
        } else {
            Architecture::Aarch64
        };
        Self::new()
            .with_entry(SyntheticEntry::stored(
                "AndroidManifest.xml",
                b"synthetic manifest, not Apple's".to_vec(),
            ))
            .with_entry(SyntheticEntry::deflated(
                &format!("lib/{abi}/{STORE_SERVICES_CORE_LIBRARY}"),
                synthetic_shared_object(architecture, 4_096),
            ))
            .with_entry(SyntheticEntry::deflated(
                &format!("lib/{abi}/{CORE_ADI_LIBRARY}"),
                synthetic_shared_object(architecture, 2_048),
            ))
            .with_entry(SyntheticEntry::deflated(
                &format!("lib/{abi}/libunrelated.so"),
                synthetic_shared_object(architecture, 512),
            ))
            .with_entry(SyntheticEntry::deflated(
                &format!("lib/{}/{STORE_SERVICES_CORE_LIBRARY}", other.android_abi()),
                synthetic_shared_object(other, 512),
            ))
    }

    /// Appends an entry.
    pub(crate) fn with_entry(mut self, entry: SyntheticEntry) -> Self {
        self.entries.push(entry);
        self
    }

    /// Removes every entry with the given name.
    pub(crate) fn without_entry(mut self, name: &str) -> Self {
        self.entries
            .retain(|entry| entry.raw_name != name.as_bytes());
        self
    }

    /// Replaces the contents of the named entry, keeping its position.
    pub(crate) fn with_replaced_entry(mut self, name: &str, data: Vec<u8>) -> Self {
        for entry in &mut self.entries {
            if entry.raw_name == name.as_bytes() {
                entry.data = data.clone();
            }
        }
        self
    }

    /// Writes a ZIP64 end of central directory locator before the end record.
    pub(crate) fn with_zip64_locator(mut self) -> Self {
        self.zip64_locator = true;
        self
    }

    /// Sets the archive comment.
    pub(crate) fn with_comment(mut self, comment: &[u8]) -> Self {
        self.comment = comment.to_vec();
        self
    }

    /// Serializes the archive.
    pub(crate) fn build(&self) -> Vec<u8> {
        let mut archive = Vec::new();
        let mut placed = Vec::new();

        for entry in &self.entries {
            let offset = u32::try_from(archive.len()).expect("fixture fits in 32 bits");
            let payload = entry.payload();
            let compressed_size = u32::try_from(payload.len()).expect("fixture fits in 32 bits");
            let uncompressed_size = entry.declared_uncompressed();
            let crc32 = entry.crc32();

            let (local_crc32, local_compressed, local_uncompressed) = if entry.zero_local_sizes {
                (0, 0, 0)
            } else {
                (crc32, compressed_size, uncompressed_size)
            };
            archive.extend(LOCAL_HEADER_SIGNATURE.to_le_bytes());
            archive.extend(20u16.to_le_bytes()); // version needed
            archive.extend(entry.local_flags.unwrap_or(entry.flags).to_le_bytes());
            archive.extend(entry.method.to_le_bytes());
            archive.extend(0u16.to_le_bytes()); // modification time
            archive.extend(0u16.to_le_bytes()); // modification date
            archive.extend(local_crc32.to_le_bytes());
            archive.extend(local_compressed.to_le_bytes());
            archive.extend(local_uncompressed.to_le_bytes());
            archive.extend(
                u16::try_from(entry.raw_name.len())
                    .expect("fixture name fits in 16 bits")
                    .to_le_bytes(),
            );
            archive.extend(0u16.to_le_bytes()); // extra length
            archive.extend_from_slice(&entry.raw_name);
            archive.extend_from_slice(&payload);

            placed.push((entry, offset, compressed_size, uncompressed_size, crc32));
        }

        let central_directory_offset =
            u32::try_from(archive.len()).expect("fixture fits in 32 bits");
        for (entry, offset, compressed_size, uncompressed_size, crc32) in &placed {
            archive.extend(CENTRAL_HEADER_SIGNATURE.to_le_bytes());
            archive.extend(entry.version_made_by.to_le_bytes());
            archive.extend(20u16.to_le_bytes()); // version needed
            archive.extend(entry.flags.to_le_bytes());
            archive.extend(entry.method.to_le_bytes());
            archive.extend(0u16.to_le_bytes()); // modification time
            archive.extend(0u16.to_le_bytes()); // modification date
            archive.extend(crc32.to_le_bytes());
            archive.extend(compressed_size.to_le_bytes());
            archive.extend(uncompressed_size.to_le_bytes());
            archive.extend(
                u16::try_from(entry.raw_name.len())
                    .expect("fixture name fits in 16 bits")
                    .to_le_bytes(),
            );
            archive.extend(0u16.to_le_bytes()); // extra length
            archive.extend(0u16.to_le_bytes()); // comment length
            archive.extend(0u16.to_le_bytes()); // disk start
            archive.extend(0u16.to_le_bytes()); // internal attributes
            archive.extend(entry.external_attributes.to_le_bytes());
            archive.extend(offset.to_le_bytes());
            archive.extend_from_slice(&entry.raw_name);
        }
        let central_directory_size = u32::try_from(archive.len()).expect("fixture fits in 32 bits")
            - central_directory_offset;

        if self.zip64_locator {
            archive.extend(ZIP64_LOCATOR_SIGNATURE.to_le_bytes());
            archive.extend(0u32.to_le_bytes()); // disk with the ZIP64 record
            archive.extend(0u64.to_le_bytes()); // offset of the ZIP64 record
            archive.extend(1u32.to_le_bytes()); // total disks
        }

        let entry_count = u16::try_from(placed.len()).expect("fixture fits in 16 bits");
        archive.extend(END_OF_CENTRAL_DIRECTORY_SIGNATURE.to_le_bytes());
        archive.extend(0u16.to_le_bytes()); // this disk
        archive.extend(0u16.to_le_bytes()); // disk with the central directory
        archive.extend(entry_count.to_le_bytes());
        archive.extend(entry_count.to_le_bytes());
        archive.extend(central_directory_size.to_le_bytes());
        archive.extend(central_directory_offset.to_le_bytes());
        archive.extend(
            u16::try_from(self.comment.len())
                .expect("fixture comment fits in 16 bits")
                .to_le_bytes(),
        );
        archive.extend_from_slice(&self.comment);
        archive
    }
}

/// One scripted answer from a [`FakeSource`].
#[derive(Clone, Debug)]
pub(crate) enum FakeResponse {
    /// A complete, well-formed response whose declared length matches the body.
    Archive(Vec<u8>),
    /// A response whose declared length does not match the body that arrives.
    MisdeclaredLength {
        /// The bytes the reader will produce.
        body: Vec<u8>,
        /// The length the response header declares.
        declared: u64,
    },
    /// A transfer that fails part way through, as an interrupted download does.
    Interrupted {
        /// The bytes delivered before the failure.
        prefix: Vec<u8>,
        /// The length the response header declares.
        declared: u64,
    },
    /// The fetch itself fails.
    Failure(FetchError),
}

/// A deterministic [`ArtifactSource`] that answers from a script.
///
/// The last scripted answer is reused once the script runs out, so a source
/// built from a single response answers every call the same way.
#[derive(Debug)]
pub(crate) struct FakeSource {
    script: Mutex<VecDeque<FakeResponse>>,
    calls: AtomicUsize,
}

impl FakeSource {
    /// A source that answers from `responses`, reusing the last one.
    pub(crate) fn new(responses: Vec<FakeResponse>) -> Self {
        assert!(!responses.is_empty(), "a fake source needs a script");
        Self {
            script: Mutex::new(responses.into()),
            calls: AtomicUsize::new(0),
        }
    }

    /// A source that always serves the same archive.
    pub(crate) fn serving(archive: Vec<u8>) -> Self {
        Self::new(vec![FakeResponse::Archive(archive)])
    }

    /// A source that is never reachable.
    pub(crate) fn offline() -> Self {
        Self::new(vec![FakeResponse::Failure(FetchError::Unreachable)])
    }

    /// How many times [`ArtifactSource::fetch`] has been called.
    pub(crate) fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

impl ArtifactSource for FakeSource {
    fn fetch(&self, url: &SourceUrl, limits: &Limits) -> Result<FetchedArtifact, FetchError> {
        assert_eq!(
            url.as_str(),
            crate::source::APPLE_MUSIC_APK_URL,
            "bootstrap must only ever request the pinned artifact URL"
        );
        self.calls.fetch_add(1, Ordering::SeqCst);

        let mut script = self.script.lock().expect("fake source script");
        let response = if script.len() > 1 {
            script.pop_front().expect("script is not empty")
        } else {
            script.front().expect("script is not empty").clone()
        };
        drop(script);

        let (declared, body): (u64, Box<dyn Read + Send>) = match response {
            FakeResponse::Archive(bytes) => (bytes.len() as u64, Box::new(Cursor::new(bytes))),
            FakeResponse::MisdeclaredLength { body, declared } => {
                (declared, Box::new(Cursor::new(body)))
            }
            FakeResponse::Interrupted { prefix, declared } => {
                (declared, Box::new(InterruptedReader::new(prefix)))
            }
            FakeResponse::Failure(error) => return Err(error),
        };
        if declared > limits.max_archive_bytes {
            return Err(FetchError::DeclaredLengthTooLarge {
                declared,
                limit: limits.max_archive_bytes,
            });
        }
        Ok(FetchedArtifact {
            observed: ObservedArtifact {
                declared_length: declared,
                last_modified: Some("Tue, 15 Apr 2025 18:26:03 GMT".to_owned()),
                etag: Some("\"synthetic-etag\"".to_owned()),
                apple_version_number: Some("0.0.0.1".to_owned()),
                content_type: Some(crate::http::EXPECTED_CONTENT_TYPE.to_owned()),
            },
            body,
        })
    }
}

/// A reader that delivers a prefix and then fails, as a dropped connection does.
#[derive(Debug)]
struct InterruptedReader {
    prefix: Cursor<Vec<u8>>,
}

impl InterruptedReader {
    fn new(prefix: Vec<u8>) -> Self {
        Self {
            prefix: Cursor::new(prefix),
        }
    }
}

impl Read for InterruptedReader {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        match self.prefix.read(buffer)? {
            0 => Err(io::Error::new(
                io::ErrorKind::ConnectionReset,
                "synthetic interrupted transfer",
            )),
            read => Ok(read),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::elf::validate_shared_object;

    #[test]
    fn synthetic_shared_objects_validate_for_their_own_architecture() {
        for architecture in Architecture::ALL {
            let object = synthetic_shared_object(architecture, 128);
            validate_shared_object(&object, architecture)
                .expect("the fixture must satisfy the ELF checks it exists to exercise");
        }
    }

    #[test]
    fn an_archive_comment_does_not_hide_the_end_record() {
        let bytes = SyntheticArchive::new()
            .with_entry(SyntheticEntry::stored("a.bin", b"x".to_vec()))
            .with_comment(b"a synthetic comment")
            .build();
        let archive = crate::archive::Archive::open(
            std::io::Cursor::new(bytes),
            &crate::limits::Limits::DEFAULT,
        )
        .expect("an archive with a comment must still open");
        assert_eq!(archive.entry_count(), 1);
    }
}
