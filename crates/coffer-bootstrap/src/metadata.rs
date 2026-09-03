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

//! What Coffer records about an installation, and what it deliberately does
//! not.
//!
//! Two documents are written.  [`InstallMetadata`] lives inside the install
//! directory and describes where the payload came from and what was checked;
//! [`ActiveInstall`] lives in `XDG_STATE_HOME` and names the install that
//! should be used.  Both are read back and revalidated before an installation
//! is handed to a caller.
//!
//! # Secrets
//!
//! Neither document contains a secret, and neither is allowed to grow one.
//! What is recorded is the artifact URL, HTTP response metadata that has been
//! length-bounded and restricted to printable ASCII, content digests, sizes,
//! the resolved architecture, and which checks ran.  There is no account
//! identifier, no token, no provisioning material and no home directory path in
//! either document; the install directory path in [`ActiveInstall`] is derived
//! from XDG base directories and is the one path Coffer must store to find its
//! own payload again.
//!
//! # Schema
//!
//! Both documents carry a schema number and both readers refuse a number they
//! do not know.  A future Coffer that changes the layout will therefore see a
//! stale document as "not installed" and re-bootstrap, rather than
//! misinterpret it.

use std::collections::BTreeMap;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// The schema number [`InstallMetadata`] documents carry.
pub const INSTALL_METADATA_SCHEMA: u32 = 2;

/// The schema number [`ActiveInstall`] documents carry.
pub const ACTIVE_INSTALL_SCHEMA: u32 = 1;

/// The file name of the install metadata document inside an install directory.
pub const INSTALL_METADATA_FILE: &str = "install.json";

/// A check bootstrap performed on an installation.
///
/// Recorded so that an installation made by an older Coffer, before a check
/// existed, is distinguishable from one that passed it.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum PerformedCheck {
    /// The fetch was made against the pinned Apple artifact URL and nothing
    /// else.
    ///
    /// This records that the [`ArtifactSource`](crate::source::ArtifactSource)
    /// in use was given only a [`SourceUrl`](crate::source::SourceUrl), which
    /// has no value other than the pinned URL.  It is *not* a statement that
    /// this particular installation arrived over HTTPS: `ArtifactSource` is a
    /// public trait, and a caller that supplies its own implementation decides
    /// what the transport actually is.  Only
    /// [`AppleCdnSource`](crate::http::AppleCdnSource) provides the HTTPS
    /// guarantee described in that type's documentation.
    HttpsPinnedEndpoint,
    /// The APK v2 RSA signature and CHUNKED_SHA256 content digest verified.
    ApkSignatureV2,
    /// Both signer DER digests matched source pins that require code review to
    /// update.
    SignerPin,
    /// The archive's ZIP structure passed the bounds and policy checks in
    /// [`crate::archive`].
    ArchiveStructure,
    /// Each extracted entry matched its declared CRC-32.
    EntryChecksum,
    /// Each extracted entry is an ELF shared object for the host architecture.
    ElfHeader,
}

/// Response metadata recorded for an installation.
///
/// Every string field has already passed
/// [`ObservedArtifact::sanitized_header`](crate::source::ObservedArtifact::sanitized_header).
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct SourceRecord {
    /// The URL the archive was fetched from.
    pub url: String,
    /// The `Content-Length` the server declared.
    pub declared_length: u64,
    /// The number of bytes actually received.
    pub received_length: u64,
    /// The SHA-256 of the archive, lowercase hexadecimal.
    pub archive_sha256: String,
    /// The `Last-Modified` header, if usable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_modified: Option<String>,
    /// The `ETag` header, if usable.  Opaque, and not used for a decision.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub etag: Option<String>,
    /// The `x-apple-version-number` header, if usable.  A hint, not a verified
    /// property of the archive.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub apple_version_number: Option<String>,
    /// The `Content-Type` header, if usable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
    /// When the archive was fetched, in seconds since the Unix epoch.
    pub fetched_at_unix_seconds: u64,
}

/// What was installed for one file.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FileRecord {
    /// The file's size in bytes.
    pub length: u64,
    /// The file's SHA-256, lowercase hexadecimal.
    pub sha256: String,
    /// The CRC-32 the archive declared for the entry, lowercase hexadecimal.
    pub crc32: String,
    /// The ELF `e_machine` value observed in the file.
    pub elf_machine: u16,
    /// The ELF class byte observed in the file.
    pub elf_class: u8,
}

/// Cryptographic verification facts recorded for the source APK.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SignatureRecord {
    /// Signature scheme wire name, currently `v2`.
    pub scheme: String,
    /// APK signature algorithm ID in lowercase hexadecimal.
    pub algorithm_id: String,
    /// SHA-256 of the signer certificate DER.
    pub certificate_sha256: String,
    /// SHA-256 of the signer SubjectPublicKeyInfo DER.
    pub spki_sha256: String,
    /// Verified CHUNKED_SHA256 content digest.
    pub content_digest_sha256: String,
    /// Offset of the APK Signing Block.
    pub signing_block_offset: u64,
    /// Total size of the APK Signing Block.
    pub signing_block_bytes: u64,
    /// Number of one-MiB chunks included in the content digest.
    pub content_chunk_count: u32,
    /// Unknown top-level signing-block IDs that were tolerated.
    pub other_block_ids: Vec<String>,
    /// When verification succeeded, in seconds since the Unix epoch.
    pub verified_at_unix_seconds: u64,
}

/// The metadata document written inside an install directory.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct InstallMetadata {
    /// The document schema number, always [`INSTALL_METADATA_SCHEMA`] when
    /// written by this Coffer.
    pub schema: u32,
    /// The install identifier, which is also the install directory's name.
    pub install_id: String,
    /// The Rust `target_arch` the payload is for.
    pub rust_target_arch: String,
    /// The Android ABI directory name the payload came from.
    pub android_abi: String,
    /// Where the payload came from.
    pub source: SourceRecord,
    /// The verified APK signature and signer identity.
    pub signature: SignatureRecord,
    /// The installed files, keyed by their path relative to the install
    /// directory.
    pub files: BTreeMap<String, FileRecord>,
    /// The checks that ran before the install was published.
    pub performed_checks: Vec<PerformedCheck>,
}

/// The pointer document naming the installation Coffer should use.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ActiveInstall {
    /// The document schema number, always [`ACTIVE_INSTALL_SCHEMA`] when
    /// written by this Coffer.
    pub schema: u32,
    /// The active install's identifier.
    pub install_id: String,
    /// The Rust `target_arch` the active install is for.
    pub rust_target_arch: String,
    /// The Android ABI directory name the active install is for.
    pub android_abi: String,
    /// The absolute path of the active install directory.
    pub install_directory: PathBuf,
    /// The SHA-256 of the archive the active install came from.
    pub archive_sha256: String,
    /// When the install was made active, in seconds since the Unix epoch.
    pub activated_at_unix_seconds: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_metadata() -> InstallMetadata {
        let mut files = BTreeMap::new();
        files.insert(
            "lib/x86_64/libCoreADI.so".to_owned(),
            FileRecord {
                length: 1_596_128,
                sha256: "a".repeat(64),
                crc32: "7b0c5a50".to_owned(),
                elf_machine: 62,
                elf_class: 2,
            },
        );
        InstallMetadata {
            schema: INSTALL_METADATA_SCHEMA,
            install_id: "0123456789abcdef".to_owned(),
            rust_target_arch: "x86_64".to_owned(),
            android_abi: "x86_64".to_owned(),
            source: SourceRecord {
                url: crate::source::APPLE_MUSIC_APK_URL.to_owned(),
                declared_length: 142_139_820,
                received_length: 142_139_820,
                archive_sha256: "b".repeat(64),
                last_modified: Some("Tue, 15 Apr 2025 18:26:03 GMT".to_owned()),
                etag: None,
                apple_version_number: Some("4.9.6.1447".to_owned()),
                content_type: Some("application/vnd.android.package-archive".to_owned()),
                fetched_at_unix_seconds: 1_788_000_000,
            },
            signature: SignatureRecord {
                scheme: "v2".to_owned(),
                algorithm_id: "0x0103".to_owned(),
                certificate_sha256: "c".repeat(64),
                spki_sha256: "d".repeat(64),
                content_digest_sha256: "e".repeat(64),
                signing_block_offset: 1_000,
                signing_block_bytes: 2_000,
                content_chunk_count: 3,
                other_block_ids: vec!["0x12345678".to_owned()],
                verified_at_unix_seconds: 1_788_000_000,
            },
            files,
            performed_checks: vec![
                PerformedCheck::HttpsPinnedEndpoint,
                PerformedCheck::ApkSignatureV2,
                PerformedCheck::SignerPin,
                PerformedCheck::ArchiveStructure,
                PerformedCheck::EntryChecksum,
                PerformedCheck::ElfHeader,
            ],
        }
    }

    #[test]
    fn install_metadata_round_trips_through_json() {
        let metadata = sample_metadata();
        let encoded = serde_json::to_string_pretty(&metadata).expect("serialize");
        let decoded: InstallMetadata = serde_json::from_str(&encoded).expect("deserialize");
        assert_eq!(decoded, metadata);
    }

    #[test]
    fn active_install_round_trips_through_json() {
        let active = ActiveInstall {
            schema: ACTIVE_INSTALL_SCHEMA,
            install_id: "0123456789abcdef".to_owned(),
            rust_target_arch: "aarch64".to_owned(),
            android_abi: "arm64-v8a".to_owned(),
            install_directory: PathBuf::from(
                "/cache/coffer/apple-support-libraries/versions/arm64-v8a/0123456789abcdef",
            ),
            archive_sha256: "c".repeat(64),
            activated_at_unix_seconds: 1_788_000_001,
        };
        let encoded = serde_json::to_string_pretty(&active).expect("serialize");
        let decoded: ActiveInstall = serde_json::from_str(&encoded).expect("deserialize");
        assert_eq!(decoded, active);
    }

    #[test]
    fn absent_optional_headers_are_omitted_rather_than_written_as_null() {
        let mut metadata = sample_metadata();
        metadata.source.last_modified = None;
        metadata.source.apple_version_number = None;
        metadata.source.content_type = None;
        let encoded = serde_json::to_string(&metadata).expect("serialize");
        assert!(!encoded.contains("last_modified"));
        assert!(!encoded.contains("apple_version_number"));
        assert!(!encoded.contains("etag"));

        let decoded: InstallMetadata = serde_json::from_str(&encoded).expect("deserialize");
        assert_eq!(decoded, metadata);
    }

    #[test]
    fn metadata_carries_no_provisioning_or_account_material() {
        let encoded = serde_json::to_string(&sample_metadata()).expect("serialize");
        for forbidden in [
            "token",
            "password",
            "passcode",
            "identifier\"",
            "adi.pb",
            "anisette",
            "HOME",
        ] {
            assert!(
                !encoded.contains(forbidden),
                "install metadata must not mention {forbidden}"
            );
        }
    }

    #[test]
    fn performed_checks_use_a_stable_wire_representation() {
        assert_eq!(
            serde_json::to_string(&PerformedCheck::HttpsPinnedEndpoint).unwrap(),
            "\"https-pinned-endpoint\""
        );
        assert_eq!(
            serde_json::to_string(&PerformedCheck::ApkSignatureV2).unwrap(),
            "\"apk-signature-v2\""
        );
        assert_eq!(
            serde_json::to_string(&PerformedCheck::SignerPin).unwrap(),
            "\"signer-pin\""
        );
        assert_eq!(
            serde_json::to_string(&PerformedCheck::ArchiveStructure).unwrap(),
            "\"archive-structure\""
        );
        assert_eq!(
            serde_json::to_string(&PerformedCheck::EntryChecksum).unwrap(),
            "\"entry-checksum\""
        );
        assert_eq!(
            serde_json::to_string(&PerformedCheck::ElfHeader).unwrap(),
            "\"elf-header\""
        );
    }
}
