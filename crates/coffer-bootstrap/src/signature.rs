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

//! APK Signature Scheme v2 verification for the Apple Music artifact.
//!
//! This is deliberately not a general APK verifier.  It implements the
//! bounded subset of Android's published v2 format used by the one artifact
//! Coffer accepts, then narrows it further to one signer, one certificate and
//! algorithm `0x0103`.  Unknown top-level ID-value pairs are tolerated because
//! Android requires that behavior, but duplicate v2 pairs and any v3/v3.1 pair
//! fail closed.
//!
//! # Trust policy
//!
//! Trust is rooted in the SHA-256 digests of both Apple's signer certificate
//! DER and its SubjectPublicKeyInfo DER.  A certificate subject string is not
//! a trust anchor.  Signer rotation is intentionally unavailable at runtime:
//! changing either pin requires a source change and review.
//!
//! The pinned key is only 1024-bit RSA.  Consequently verification must use
//! [`ring::signature::RSA_PKCS1_1024_8192_SHA256_FOR_LEGACY_USE_ONLY`], and the
//! authenticity strength is bounded by that legacy key.  Replacing this with
//! ring's modern 2048-bit-minimum policy would reject the current genuine
//! artifact rather than strengthen it.

use core::fmt;
use std::io::{self, Read, Seek, SeekFrom};

use ring::signature;
use sha2::{Digest, Sha256};

use crate::limits::Limits;

/// SHA-256 of the DER certificate used by the current Apple Music APK signer.
///
/// Rotation is not accepted automatically.  Updating this value requires a
/// reviewed source change backed by a freshly verified Apple artifact.
pub const APPLE_MUSIC_SIGNER_CERTIFICATE_SHA256: [u8; 32] = [
    0x88, 0xba, 0x59, 0x0e, 0xc2, 0xe1, 0xea, 0x33, 0xc4, 0x45, 0x8d, 0xaf, 0x59, 0x48, 0x9f, 0xae,
    0xe2, 0xce, 0xf2, 0x97, 0xa9, 0xb4, 0x07, 0x1e, 0x18, 0xcf, 0x82, 0xef, 0x53, 0x11, 0x00, 0xaa,
];

/// SHA-256 of the DER SubjectPublicKeyInfo used by the current APK signer.
///
/// This is pinned separately from the certificate so the public-key field in
/// the v2 signer cannot be substituted independently of the certificate.
pub const APPLE_MUSIC_SIGNER_SPKI_SHA256: [u8; 32] = [
    0x53, 0xec, 0xa3, 0x35, 0x35, 0x88, 0xf3, 0x7c, 0x23, 0x4f, 0x70, 0xd0, 0x53, 0x5f, 0x74, 0x05,
    0xf3, 0xe4, 0x29, 0x91, 0x5c, 0x84, 0xa1, 0x3a, 0xca, 0x6d, 0x9d, 0xfd, 0xb5, 0xe4, 0xea, 0x4c,
];

/// `APK Sig Block 42`.
const APK_SIGNING_BLOCK_MAGIC: &[u8; 16] = b"APK Sig Block 42";

/// APK Signature Scheme v2 ID-value pair.
const V2_BLOCK_ID: u32 = 0x7109_871a;

/// APK Signature Scheme v3 ID-value pair.
const V3_BLOCK_ID: u32 = 0xf053_68c0;

/// APK Signature Scheme v3.1 ID-value pair.
const V31_BLOCK_ID: u32 = 0x1b93_ad61;

/// v2 algorithm: RSASSA-PKCS1-v1_5 with SHA-256 and CHUNKED_SHA256.
pub const RSA_PKCS1_SHA256_ALGORITHM_ID: u32 = 0x0103;

/// The v2 stripping-protection additional attribute.
const STRIPPING_PROTECTION_ATTRIBUTE_ID: u32 = 0xbeef_f00d;

/// The fixed part of a ZIP end of central directory record.
const END_OF_CENTRAL_DIRECTORY_BYTES: usize = 22;

/// The maximum ZIP comment length.
const MAX_ARCHIVE_COMMENT_BYTES: usize = 65_535;

/// The ZIP64 end of central directory locator size.
const ZIP64_LOCATOR_BYTES: usize = 20;

/// The fixed footer of an APK Signing Block.
const SIGNING_BLOCK_FOOTER_BYTES: u64 = 24;

/// The header size field plus the footer.
const SIGNING_BLOCK_OVERHEAD_BYTES: u64 = 32;

/// Android's content-digest chunk size.
const CONTENT_CHUNK_BYTES: usize = 1 << 20;

/// Maximum number of ignored top-level signing-block IDs retained in metadata.
///
/// Although the signing block has its own byte bound, tiny empty pairs could
/// otherwise expand substantially when rendered in the bounded metadata file.
const MAX_OTHER_BLOCK_IDS: usize = 64;

/// The RSA `AlgorithmIdentifier` accepted in a pinned SubjectPublicKeyInfo.
const RSA_ENCRYPTION_ALGORITHM_IDENTIFIER: &[u8] = &[
    0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00,
];

/// The signature scheme Coffer verified.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum SignatureScheme {
    /// APK Signature Scheme v2.
    V2,
    /// APK Signature Scheme v3.
    V3,
    /// APK Signature Scheme v3.1.
    V31,
}

impl fmt::Display for SignatureScheme {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            SignatureScheme::V2 => "v2",
            SignatureScheme::V3 => "v3",
            SignatureScheme::V31 => "v3.1",
        })
    }
}

/// Facts about a successfully verified APK signature.
///
/// All fields are public artifact metadata, never secret material.  No
/// certificate or APK bytes are retained.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApkSignature {
    /// The verified signing scheme.
    pub scheme: SignatureScheme,
    /// The accepted signature algorithm ID, currently always `0x0103`.
    pub algorithm_id: u32,
    /// SHA-256 of the signer certificate DER.
    pub signer_certificate_sha256: [u8; 32],
    /// SHA-256 of the signer SubjectPublicKeyInfo DER.
    pub signer_spki_sha256: [u8; 32],
    /// The verified CHUNKED_SHA256 digest of the APK contents.
    pub content_digest_sha256: [u8; 32],
    /// Byte offset at which the APK Signing Block begins.
    pub signing_block_offset: u64,
    /// Total APK Signing Block size, including its leading size field.
    pub signing_block_bytes: u64,
    /// Number of one-MiB content chunks covered by the digest.
    pub content_chunk_count: u32,
    /// Other top-level APK Signing Block IDs that were ignored.
    pub other_block_ids: Vec<u32>,
}

/// Why the APK is not signed according to Coffer's pinned Apple policy.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum SignatureViolation {
    /// The input exceeds the configured archive bound.
    ArchiveTooLarge {
        /// The observed length.
        length: u64,
        /// The configured ceiling.
        limit: u64,
    },
    /// The file is too short to contain a ZIP end record.
    TooShort,
    /// No unambiguous ZIP end record was found.
    EndOfCentralDirectoryNotFound,
    /// ZIP64 is not supported by this verifier.
    Zip64NotSupported,
    /// Multi-disk ZIP archives are not supported.
    MultiDiskNotSupported,
    /// The central directory offsets do not tile the end of the archive.
    CentralDirectoryOutOfBounds,
    /// No APK Signing Block or v2 pair is present.
    SignatureMissing,
    /// The signing-block magic is not `APK Sig Block 42`.
    SigningBlockMagicMismatch,
    /// The two signing-block size fields differ.
    SigningBlockSizeMismatch,
    /// The signing block lies outside the file or has an impossible size.
    SigningBlockOutOfBounds,
    /// The signing block exceeds the configured bound.
    SigningBlockTooLarge {
        /// The declared total block size.
        declared: u64,
        /// The configured ceiling.
        limit: u64,
    },
    /// The signing block's length-prefixed structures are malformed.
    Malformed,
    /// More than one v2 ID-value pair is present.
    DuplicateV2Block,
    /// A newer signature scheme is present and requires deliberate support.
    SignatureSchemeNotSupported {
        /// The detected scheme.
        scheme: SignatureScheme,
    },
    /// Coffer's pinned policy requires exactly one signer.
    UnexpectedSignerCount {
        /// The number observed, saturated at `u32::MAX`.
        found: u32,
    },
    /// Coffer's pinned policy requires exactly one digest, signature, or
    /// certificate record.
    UnexpectedRecordCount,
    /// The digest and signature algorithm ID sequences differ.
    SignatureAlgorithmMismatch,
    /// The signer uses an algorithm Coffer has not reviewed.
    UnsupportedSignatureAlgorithm {
        /// The unrecognized or unsupported algorithm ID.
        id: u32,
    },
    /// The signer certificate does not match Apple's pinned certificate.
    SignerCertificateNotPinned {
        /// SHA-256 of the certificate that was presented.
        observed: [u8; 32],
    },
    /// The public-key field does not match Apple's pinned SPKI.
    SignerPublicKeyNotPinned {
        /// SHA-256 of the SPKI that was presented.
        observed: [u8; 32],
    },
    /// The pinned SubjectPublicKeyInfo is not the reviewed RSA DER shape.
    SubjectPublicKeyMalformed,
    /// The RSA signature over signed data is invalid.
    SignatureInvalid,
    /// Signed data carries an additional attribute Coffer has not reviewed.
    UnsupportedAdditionalAttribute {
        /// The attribute ID.
        id: u32,
    },
    /// The v2 stripping-protection attribute requires policy Coffer does not
    /// currently implement.
    StrippingProtectionNotSupported,
    /// The signed CHUNKED_SHA256 digest is not 32 bytes.
    ContentDigestLengthMismatch,
    /// Recomputed APK contents do not match the signed digest.
    ContentDigestMismatch,
    /// Computing the digest would exceed the configured chunk bound.
    TooManyContentChunks {
        /// The computed chunk count.
        declared: u64,
        /// The configured ceiling.
        limit: u32,
    },
    /// Reading the archive failed.
    Io {
        /// The kind of failure, without a filesystem path.
        kind: io::ErrorKind,
    },
}

impl fmt::Display for SignatureViolation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SignatureViolation::ArchiveTooLarge { length, limit } => write!(
                f,
                "archive is {length} bytes, over the {limit}-byte signature-verification limit"
            ),
            SignatureViolation::TooShort => {
                f.write_str("archive is too short for an APK signature")
            }
            SignatureViolation::EndOfCentralDirectoryNotFound => {
                f.write_str("archive has no unambiguous end of central directory record")
            }
            SignatureViolation::Zip64NotSupported => {
                f.write_str("archive uses ZIP64, which signature verification refuses")
            }
            SignatureViolation::MultiDiskNotSupported => {
                f.write_str("archive spans multiple disks, which signature verification refuses")
            }
            SignatureViolation::CentralDirectoryOutOfBounds => {
                f.write_str("archive central directory does not end at the ZIP end record")
            }
            SignatureViolation::SignatureMissing => {
                f.write_str("archive has no APK Signature Scheme v2 signature")
            }
            SignatureViolation::SigningBlockMagicMismatch => {
                f.write_str("APK signing block magic is invalid")
            }
            SignatureViolation::SigningBlockSizeMismatch => {
                f.write_str("APK signing block size fields disagree")
            }
            SignatureViolation::SigningBlockOutOfBounds => {
                f.write_str("APK signing block lies outside the archive")
            }
            SignatureViolation::SigningBlockTooLarge { declared, limit } => write!(
                f,
                "APK signing block is {declared} bytes, over the {limit}-byte limit"
            ),
            SignatureViolation::Malformed => f.write_str("APK signature data is malformed"),
            SignatureViolation::DuplicateV2Block => {
                f.write_str("APK signing block contains duplicate v2 signature pairs")
            }
            SignatureViolation::SignatureSchemeNotSupported { scheme } => write!(
                f,
                "APK Signature Scheme {scheme} is present and requires a reviewed policy update"
            ),
            SignatureViolation::UnexpectedSignerCount { found } => {
                write!(
                    f,
                    "APK v2 signature has {found} signers instead of exactly one"
                )
            }
            SignatureViolation::UnexpectedRecordCount => {
                f.write_str("APK v2 signer does not contain exactly one required record")
            }
            SignatureViolation::SignatureAlgorithmMismatch => {
                f.write_str("APK digest and signature algorithm lists disagree")
            }
            SignatureViolation::UnsupportedSignatureAlgorithm { id } => {
                write!(f, "APK signature algorithm 0x{id:04x} is not supported")
            }
            SignatureViolation::SignerCertificateNotPinned { observed } => write!(
                f,
                "APK signer certificate SHA-256 {} is not pinned",
                Hex(observed)
            ),
            SignatureViolation::SignerPublicKeyNotPinned { observed } => {
                write!(f, "APK signer SPKI SHA-256 {} is not pinned", Hex(observed))
            }
            SignatureViolation::SubjectPublicKeyMalformed => {
                f.write_str("APK signer SubjectPublicKeyInfo is malformed or not RSA")
            }
            SignatureViolation::SignatureInvalid => f.write_str("APK v2 RSA signature is invalid"),
            SignatureViolation::UnsupportedAdditionalAttribute { id } => write!(
                f,
                "APK v2 signed data contains unsupported attribute 0x{id:08x}"
            ),
            SignatureViolation::StrippingProtectionNotSupported => f.write_str(
                "APK v2 stripping-protection attribute requires a reviewed policy update",
            ),
            SignatureViolation::ContentDigestLengthMismatch => {
                f.write_str("APK v2 content digest is not 32 bytes")
            }
            SignatureViolation::ContentDigestMismatch => {
                f.write_str("APK contents do not match the signed digest")
            }
            SignatureViolation::TooManyContentChunks { declared, limit } => write!(
                f,
                "APK signature digest needs {declared} chunks, over the limit of {limit}"
            ),
            SignatureViolation::Io { kind } => {
                write!(
                    f,
                    "reading the APK for signature verification failed: {kind}"
                )
            }
        }
    }
}

impl std::error::Error for SignatureViolation {}

impl From<io::Error> for SignatureViolation {
    fn from(error: io::Error) -> Self {
        SignatureViolation::Io { kind: error.kind() }
    }
}

/// Verifies that an APK was signed by Coffer's pinned Apple signer with APK
/// Signature Scheme v2 and that its signed digest covers the complete APK.
///
/// The reader is left at an unspecified position.  Verification reads at most
/// one bounded signing block into memory and otherwise streams the file with a
/// reusable one-MiB buffer.
///
/// # Security
///
/// This API has no runtime pin override.  Signer rotation requires updating
/// [`APPLE_MUSIC_SIGNER_CERTIFICATE_SHA256`] and
/// [`APPLE_MUSIC_SIGNER_SPKI_SHA256`] in reviewed source.  v1-only, unsigned,
/// v3 and v3.1 APKs are rejected rather than downgraded or guessed at.
///
/// # Errors
///
/// Returns the first [`SignatureViolation`] found.  No failure is retryable as
/// a signature operation: it indicates malformed bytes, tampering, or a signer
/// policy change that requires human review.
pub fn verify_apple_music_apk<R: Read + Seek>(
    reader: &mut R,
    limits: &Limits,
) -> Result<ApkSignature, SignatureViolation> {
    verify_with_policy(reader, limits, &APPLE_SIGNER_POLICY)
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct SignerPolicy {
    pub(crate) certificate_sha256: [u8; 32],
    pub(crate) spki_sha256: [u8; 32],
}

pub(crate) const APPLE_SIGNER_POLICY: SignerPolicy = SignerPolicy {
    certificate_sha256: APPLE_MUSIC_SIGNER_CERTIFICATE_SHA256,
    spki_sha256: APPLE_MUSIC_SIGNER_SPKI_SHA256,
};

pub(crate) fn verify_with_policy<R: Read + Seek>(
    reader: &mut R,
    limits: &Limits,
    policy: &SignerPolicy,
) -> Result<ApkSignature, SignatureViolation> {
    let layout = locate_layout(reader, limits)?;
    let (v2, other_block_ids) = read_v2_block(reader, &layout, limits)?;
    let mut v2_cursor = Cursor::new(&v2);
    let signers = v2_cursor.length_prefixed()?;
    v2_cursor.finish()?;
    let signer = parse_one(signers, CountKind::Signer)?;

    let mut signer_cursor = Cursor::new(signer);
    let signed_data = signer_cursor.length_prefixed()?;
    let signatures = signer_cursor.length_prefixed()?;
    let public_key = signer_cursor.length_prefixed()?;
    signer_cursor.finish()?;

    let signature_record = parse_one(signatures, CountKind::Record)?;
    let mut signature_cursor = Cursor::new(signature_record);
    let signature_algorithm = signature_cursor.u32()?;
    let signature_bytes = signature_cursor.length_prefixed()?;
    signature_cursor.finish()?;
    if signature_algorithm != RSA_PKCS1_SHA256_ALGORITHM_ID {
        return Err(SignatureViolation::UnsupportedSignatureAlgorithm {
            id: signature_algorithm,
        });
    }

    let spki_digest: [u8; 32] = Sha256::digest(public_key).into();
    if spki_digest != policy.spki_sha256 {
        return Err(SignatureViolation::SignerPublicKeyNotPinned {
            observed: spki_digest,
        });
    }
    let rsa_public_key = spki_to_pkcs1(public_key)?;
    let verifier = signature::UnparsedPublicKey::new(
        &signature::RSA_PKCS1_1024_8192_SHA256_FOR_LEGACY_USE_ONLY,
        rsa_public_key,
    );
    verifier
        .verify(signed_data, signature_bytes)
        .map_err(|_| SignatureViolation::SignatureInvalid)?;

    let parsed = parse_signed_data(signed_data, policy)?;
    if parsed.algorithm_id != signature_algorithm {
        return Err(SignatureViolation::SignatureAlgorithmMismatch);
    }

    let (content_digest, content_chunk_count) = compute_content_digest(reader, &layout, limits)?;
    if content_digest.as_slice() != parsed.content_digest {
        return Err(SignatureViolation::ContentDigestMismatch);
    }

    Ok(ApkSignature {
        scheme: SignatureScheme::V2,
        algorithm_id: signature_algorithm,
        signer_certificate_sha256: parsed.certificate_sha256,
        signer_spki_sha256: spki_digest,
        content_digest_sha256: content_digest,
        signing_block_offset: layout.signing_block_offset,
        signing_block_bytes: layout.signing_block_bytes,
        content_chunk_count,
        other_block_ids,
    })
}

struct ParsedSignedData<'a> {
    algorithm_id: u32,
    content_digest: &'a [u8],
    certificate_sha256: [u8; 32],
}

fn parse_signed_data<'a>(
    signed_data: &'a [u8],
    policy: &SignerPolicy,
) -> Result<ParsedSignedData<'a>, SignatureViolation> {
    let mut cursor = Cursor::new(signed_data);
    let digests = cursor.length_prefixed()?;
    let certificates = cursor.length_prefixed()?;
    let attributes = cursor.length_prefixed()?;
    match cursor.remaining() {
        [] | [0, 0, 0, 0] => {}
        _ => return Err(SignatureViolation::Malformed),
    }

    let digest_record = parse_one(digests, CountKind::Record)?;
    let mut digest_cursor = Cursor::new(digest_record);
    let algorithm_id = digest_cursor.u32()?;
    let content_digest = digest_cursor.length_prefixed()?;
    digest_cursor.finish()?;
    if content_digest.len() != 32 {
        return Err(SignatureViolation::ContentDigestLengthMismatch);
    }

    let certificate = parse_one(certificates, CountKind::Record)?;
    let certificate_sha256: [u8; 32] = Sha256::digest(certificate).into();
    if certificate_sha256 != policy.certificate_sha256 {
        return Err(SignatureViolation::SignerCertificateNotPinned {
            observed: certificate_sha256,
        });
    }

    let mut attributes_cursor = Cursor::new(attributes);
    if !attributes_cursor.remaining().is_empty() {
        let attribute = attributes_cursor.length_prefixed()?;
        let mut attribute_cursor = Cursor::new(attribute);
        let id = attribute_cursor.u32()?;
        if id == STRIPPING_PROTECTION_ATTRIBUTE_ID {
            return Err(SignatureViolation::StrippingProtectionNotSupported);
        }
        return Err(SignatureViolation::UnsupportedAdditionalAttribute { id });
    }

    Ok(ParsedSignedData {
        algorithm_id,
        content_digest,
        certificate_sha256,
    })
}

struct Layout {
    archive_length: u64,
    eocd_offset: u64,
    eocd: Vec<u8>,
    central_directory_offset: u64,
    central_directory_size: u64,
    signing_block_offset: u64,
    signing_block_bytes: u64,
}

fn locate_layout<R: Read + Seek>(
    reader: &mut R,
    limits: &Limits,
) -> Result<Layout, SignatureViolation> {
    let archive_length = reader.seek(SeekFrom::End(0))?;
    if archive_length > limits.max_archive_bytes {
        return Err(SignatureViolation::ArchiveTooLarge {
            length: archive_length,
            limit: limits.max_archive_bytes,
        });
    }
    if archive_length < END_OF_CENTRAL_DIRECTORY_BYTES as u64 {
        return Err(SignatureViolation::TooShort);
    }

    let window_length = (END_OF_CENTRAL_DIRECTORY_BYTES + MAX_ARCHIVE_COMMENT_BYTES)
        .min(usize::try_from(archive_length).unwrap_or(usize::MAX));
    let window_offset = archive_length - window_length as u64;
    let mut window = vec![0u8; window_length];
    reader.seek(SeekFrom::Start(window_offset))?;
    reader.read_exact(&mut window)?;

    let found = (0..=window_length - END_OF_CENTRAL_DIRECTORY_BYTES)
        .rev()
        .find(|&offset| {
            window.get(offset..offset + 4) == Some(b"PK\x05\x06")
                && offset
                    .checked_add(END_OF_CENTRAL_DIRECTORY_BYTES)
                    .and_then(|end| {
                        end.checked_add(usize::from(read_u16(&window[offset + 20..offset + 22])))
                    })
                    == Some(window_length)
        })
        .ok_or(SignatureViolation::EndOfCentralDirectoryNotFound)?;
    let eocd_offset = window_offset + found as u64;
    let eocd = window[found..].to_vec();
    if found >= ZIP64_LOCATOR_BYTES
        && window.get(found - ZIP64_LOCATOR_BYTES..found - ZIP64_LOCATOR_BYTES + 4)
            == Some(b"PK\x06\x07")
    {
        return Err(SignatureViolation::Zip64NotSupported);
    }

    let disk_number = read_u16(&eocd[4..6]);
    let directory_disk = read_u16(&eocd[6..8]);
    let entries_on_disk = read_u16(&eocd[8..10]);
    let total_entries = read_u16(&eocd[10..12]);
    let central_directory_size = u64::from(read_u32(&eocd[12..16]));
    let central_directory_offset = u64::from(read_u32(&eocd[16..20]));
    if disk_number != 0 || directory_disk != 0 || entries_on_disk != total_entries {
        return Err(SignatureViolation::MultiDiskNotSupported);
    }
    if total_entries == u16::MAX
        || central_directory_size == u64::from(u32::MAX)
        || central_directory_offset == u64::from(u32::MAX)
    {
        return Err(SignatureViolation::Zip64NotSupported);
    }
    if central_directory_offset.checked_add(central_directory_size) != Some(eocd_offset) {
        return Err(SignatureViolation::CentralDirectoryOutOfBounds);
    }
    if central_directory_offset < SIGNING_BLOCK_FOOTER_BYTES {
        return Err(SignatureViolation::SignatureMissing);
    }

    let footer_offset = central_directory_offset - SIGNING_BLOCK_FOOTER_BYTES;
    reader.seek(SeekFrom::Start(footer_offset))?;
    let mut footer = [0u8; SIGNING_BLOCK_FOOTER_BYTES as usize];
    reader.read_exact(&mut footer)?;
    if &footer[8..] != APK_SIGNING_BLOCK_MAGIC {
        let candidate_size = read_u64(&footer[..8]);
        let candidate_total = candidate_size.checked_add(8);
        let has_plausible_block = candidate_total
            .filter(|&total| total >= SIGNING_BLOCK_OVERHEAD_BYTES)
            .and_then(|total| central_directory_offset.checked_sub(total))
            .and_then(|offset| {
                reader.seek(SeekFrom::Start(offset)).ok()?;
                let mut header = [0u8; 8];
                reader.read_exact(&mut header).ok()?;
                Some(read_u64(&header) == candidate_size)
            })
            .unwrap_or(false);
        return Err(if has_plausible_block {
            SignatureViolation::SigningBlockMagicMismatch
        } else {
            SignatureViolation::SignatureMissing
        });
    }
    let footer_size = read_u64(&footer[..8]);
    let signing_block_bytes = footer_size
        .checked_add(8)
        .ok_or(SignatureViolation::SigningBlockOutOfBounds)?;
    if signing_block_bytes < SIGNING_BLOCK_OVERHEAD_BYTES
        || signing_block_bytes > central_directory_offset
    {
        return Err(SignatureViolation::SigningBlockOutOfBounds);
    }
    if signing_block_bytes > limits.max_signing_block_bytes {
        return Err(SignatureViolation::SigningBlockTooLarge {
            declared: signing_block_bytes,
            limit: limits.max_signing_block_bytes,
        });
    }
    let signing_block_offset = central_directory_offset - signing_block_bytes;

    Ok(Layout {
        archive_length,
        eocd_offset,
        eocd,
        central_directory_offset,
        central_directory_size,
        signing_block_offset,
        signing_block_bytes,
    })
}

fn read_v2_block<R: Read + Seek>(
    reader: &mut R,
    layout: &Layout,
    limits: &Limits,
) -> Result<(Vec<u8>, Vec<u32>), SignatureViolation> {
    let block_length = usize::try_from(layout.signing_block_bytes).map_err(|_| {
        SignatureViolation::SigningBlockTooLarge {
            declared: layout.signing_block_bytes,
            limit: limits.max_signing_block_bytes,
        }
    })?;
    let mut block = vec![0u8; block_length];
    reader.seek(SeekFrom::Start(layout.signing_block_offset))?;
    reader.read_exact(&mut block)?;

    let header_size = read_u64(block.get(..8).ok_or(SignatureViolation::Malformed)?);
    let footer_size = read_u64(
        block
            .get(block_length - SIGNING_BLOCK_FOOTER_BYTES as usize..block_length - 16)
            .ok_or(SignatureViolation::Malformed)?,
    );
    if header_size != footer_size {
        return Err(SignatureViolation::SigningBlockSizeMismatch);
    }
    if header_size.checked_add(8) != Some(layout.signing_block_bytes) {
        return Err(SignatureViolation::SigningBlockSizeMismatch);
    }
    if block.get(block_length - 16..) != Some(APK_SIGNING_BLOCK_MAGIC) {
        return Err(SignatureViolation::SigningBlockMagicMismatch);
    }

    let pair_end = block_length - SIGNING_BLOCK_FOOTER_BYTES as usize;
    let mut offset = 8usize;
    let mut v2 = None;
    let mut other_block_ids = Vec::new();
    while offset < pair_end {
        let length_end = offset.checked_add(8).ok_or(SignatureViolation::Malformed)?;
        let pair_length = usize::try_from(read_u64(
            block
                .get(offset..length_end)
                .ok_or(SignatureViolation::Malformed)?,
        ))
        .map_err(|_| SignatureViolation::Malformed)?;
        if pair_length < 4 {
            return Err(SignatureViolation::Malformed);
        }
        let pair_start = length_end;
        let next = pair_start
            .checked_add(pair_length)
            .filter(|&next| next <= pair_end)
            .ok_or(SignatureViolation::Malformed)?;
        let id = read_u32(
            block
                .get(pair_start..pair_start + 4)
                .ok_or(SignatureViolation::Malformed)?,
        );
        let value = block[pair_start + 4..next].to_vec();
        match id {
            V2_BLOCK_ID => {
                if v2.replace(value).is_some() {
                    return Err(SignatureViolation::DuplicateV2Block);
                }
            }
            V3_BLOCK_ID => {
                return Err(SignatureViolation::SignatureSchemeNotSupported {
                    scheme: SignatureScheme::V3,
                });
            }
            V31_BLOCK_ID => {
                return Err(SignatureViolation::SignatureSchemeNotSupported {
                    scheme: SignatureScheme::V31,
                });
            }
            _ => {
                if other_block_ids.len() == MAX_OTHER_BLOCK_IDS {
                    return Err(SignatureViolation::Malformed);
                }
                other_block_ids.push(id);
            }
        }
        offset = next;
    }
    if offset != pair_end {
        return Err(SignatureViolation::Malformed);
    }
    v2.map(|v2| (v2, other_block_ids))
        .ok_or(SignatureViolation::SignatureMissing)
}

fn compute_content_digest<R: Read + Seek>(
    reader: &mut R,
    layout: &Layout,
    limits: &Limits,
) -> Result<([u8; 32], u32), SignatureViolation> {
    let section_lengths = [
        layout.signing_block_offset,
        layout.central_directory_size,
        layout.archive_length - layout.eocd_offset,
    ];
    let chunk_size = CONTENT_CHUNK_BYTES as u64;
    let chunk_count = section_lengths.iter().try_fold(0u64, |total, &length| {
        let section_chunks = length
            .checked_add(chunk_size - 1)?
            .checked_div(chunk_size)?;
        total.checked_add(section_chunks)
    });
    let chunk_count = chunk_count.ok_or(SignatureViolation::Malformed)?;
    if chunk_count > u64::from(limits.max_signature_chunks) || chunk_count > u64::from(u32::MAX) {
        return Err(SignatureViolation::TooManyContentChunks {
            declared: chunk_count,
            limit: limits.max_signature_chunks,
        });
    }
    let chunk_count = chunk_count as u32;

    let mut top = Sha256::new();
    top.update([0x5a]);
    top.update(chunk_count.to_le_bytes());
    let mut buffer = vec![0u8; CONTENT_CHUNK_BYTES];

    hash_file_section(
        reader,
        0,
        layout.signing_block_offset,
        &mut buffer,
        &mut top,
    )?;
    hash_file_section(
        reader,
        layout.central_directory_offset,
        layout.central_directory_size,
        &mut buffer,
        &mut top,
    )?;

    let mut eocd = layout.eocd.clone();
    let signing_offset = u32::try_from(layout.signing_block_offset)
        .map_err(|_| SignatureViolation::Zip64NotSupported)?;
    eocd[16..20].copy_from_slice(&signing_offset.to_le_bytes());
    for chunk in eocd.chunks(CONTENT_CHUNK_BYTES) {
        hash_chunk(chunk, &mut top);
    }

    Ok((top.finalize().into(), chunk_count))
}

fn hash_file_section<R: Read + Seek>(
    reader: &mut R,
    offset: u64,
    mut length: u64,
    buffer: &mut [u8],
    top: &mut Sha256,
) -> Result<(), SignatureViolation> {
    reader.seek(SeekFrom::Start(offset))?;
    while length > 0 {
        let take = usize::try_from(length.min(buffer.len() as u64))
            .map_err(|_| SignatureViolation::Malformed)?;
        reader.read_exact(&mut buffer[..take])?;
        hash_chunk(&buffer[..take], top);
        length -= take as u64;
    }
    Ok(())
}

fn hash_chunk(chunk: &[u8], top: &mut Sha256) {
    let mut hasher = Sha256::new();
    hasher.update([0xa5]);
    hasher.update((chunk.len() as u32).to_le_bytes());
    hasher.update(chunk);
    top.update(hasher.finalize());
}

fn spki_to_pkcs1(spki: &[u8]) -> Result<&[u8], SignatureViolation> {
    let (outer, consumed) = der_tlv(spki, 0x30)?;
    if consumed != spki.len() {
        return Err(SignatureViolation::SubjectPublicKeyMalformed);
    }
    let (algorithm, algorithm_end) = der_tlv(outer, 0x30)?;
    if algorithm != RSA_ENCRYPTION_ALGORITHM_IDENTIFIER {
        return Err(SignatureViolation::SubjectPublicKeyMalformed);
    }
    let (bits, bits_end) = der_tlv(&outer[algorithm_end..], 0x03)?;
    if algorithm_end
        .checked_add(bits_end)
        .filter(|&end| end == outer.len())
        .is_none()
        || bits.first() != Some(&0)
        || bits.len() < 2
    {
        return Err(SignatureViolation::SubjectPublicKeyMalformed);
    }
    Ok(&bits[1..])
}

fn der_tlv(bytes: &[u8], expected_tag: u8) -> Result<(&[u8], usize), SignatureViolation> {
    if bytes.first() != Some(&expected_tag) {
        return Err(SignatureViolation::SubjectPublicKeyMalformed);
    }
    let first_length = *bytes
        .get(1)
        .ok_or(SignatureViolation::SubjectPublicKeyMalformed)?;
    let (length, header_length) = if first_length < 0x80 {
        (usize::from(first_length), 2usize)
    } else {
        let length_bytes = usize::from(first_length & 0x7f);
        if length_bytes == 0 || length_bytes > core::mem::size_of::<usize>() {
            return Err(SignatureViolation::SubjectPublicKeyMalformed);
        }
        let encoded = bytes
            .get(2..2 + length_bytes)
            .ok_or(SignatureViolation::SubjectPublicKeyMalformed)?;
        if encoded.first() == Some(&0) {
            return Err(SignatureViolation::SubjectPublicKeyMalformed);
        }
        let length = encoded.iter().try_fold(0usize, |value, &byte| {
            value.checked_mul(256)?.checked_add(usize::from(byte))
        });
        let length = length.ok_or(SignatureViolation::SubjectPublicKeyMalformed)?;
        if length < 0x80 {
            return Err(SignatureViolation::SubjectPublicKeyMalformed);
        }
        (length, 2 + length_bytes)
    };
    let end = header_length
        .checked_add(length)
        .filter(|&end| end <= bytes.len())
        .ok_or(SignatureViolation::SubjectPublicKeyMalformed)?;
    Ok((&bytes[header_length..end], end))
}

enum CountKind {
    Signer,
    Record,
}

fn parse_one(bytes: &[u8], kind: CountKind) -> Result<&[u8], SignatureViolation> {
    let mut cursor = Cursor::new(bytes);
    let mut count = 0u32;
    let mut only = None;
    while !cursor.remaining().is_empty() {
        count = count.saturating_add(1);
        let value = cursor.length_prefixed()?;
        if count == 1 {
            only = Some(value);
        }
    }
    if count != 1 {
        return match kind {
            CountKind::Signer => Err(SignatureViolation::UnexpectedSignerCount { found: count }),
            CountKind::Record => Err(SignatureViolation::UnexpectedRecordCount),
        };
    }
    only.ok_or(SignatureViolation::Malformed)
}

struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn remaining(&self) -> &'a [u8] {
        &self.bytes[self.offset..]
    }

    fn u32(&mut self) -> Result<u32, SignatureViolation> {
        let end = self
            .offset
            .checked_add(4)
            .filter(|&end| end <= self.bytes.len())
            .ok_or(SignatureViolation::Malformed)?;
        let value = read_u32(&self.bytes[self.offset..end]);
        self.offset = end;
        Ok(value)
    }

    fn length_prefixed(&mut self) -> Result<&'a [u8], SignatureViolation> {
        let length = usize::try_from(self.u32()?).map_err(|_| SignatureViolation::Malformed)?;
        let end = self
            .offset
            .checked_add(length)
            .filter(|&end| end <= self.bytes.len())
            .ok_or(SignatureViolation::Malformed)?;
        let value = &self.bytes[self.offset..end];
        self.offset = end;
        Ok(value)
    }

    fn finish(&self) -> Result<(), SignatureViolation> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(SignatureViolation::Malformed)
        }
    }
}

fn read_u16(bytes: &[u8]) -> u16 {
    u16::from_le_bytes([bytes[0], bytes[1]])
}

fn read_u32(bytes: &[u8]) -> u32 {
    u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
}

fn read_u64(bytes: &[u8]) -> u64 {
    u64::from_le_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ])
}

struct Hex<'a>(&'a [u8]);

impl fmt::Display for Hex<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::fs::File;
    use std::io::Cursor as IoCursor;

    use super::*;
    use crate::synthetic::{
        SYNTHETIC_STRIPPING_PROTECTION_ID, SYNTHETIC_V3_BLOCK_ID, SYNTHETIC_V31_BLOCK_ID,
        SyntheticArchive, SyntheticEntry, SyntheticSignature, synthetic_signer_policy,
    };

    fn verify(bytes: Vec<u8>) -> Result<ApkSignature, SignatureViolation> {
        verify_with_policy(
            &mut IoCursor::new(bytes),
            &Limits::DEFAULT,
            &synthetic_signer_policy(),
        )
    }

    fn signed(options: SyntheticSignature) -> Vec<u8> {
        SyntheticArchive::new()
            .with_entry(SyntheticEntry::stored("payload", b"synthetic".to_vec()))
            .with_comment(b"eocd-comment")
            .build_signed_with(&options)
    }

    fn eocd_offset(bytes: &[u8]) -> usize {
        bytes
            .windows(4)
            .rposition(|window| window == b"PK\x05\x06")
            .expect("end record")
    }

    fn central_directory_offset(bytes: &[u8]) -> usize {
        let eocd = eocd_offset(bytes);
        u32::from_le_bytes(bytes[eocd + 16..eocd + 20].try_into().expect("four bytes")) as usize
    }

    fn signing_block_offset(bytes: &[u8]) -> usize {
        let central = central_directory_offset(bytes);
        let size = u64::from_le_bytes(
            bytes[central - 24..central - 16]
                .try_into()
                .expect("eight bytes"),
        ) as usize;
        central - size - 8
    }

    #[test]
    fn valid_v2_signature_covers_all_regions_and_rewritten_central_offset() {
        let signature = verify(signed(SyntheticSignature::default())).expect("valid signature");
        assert_eq!(signature.scheme, SignatureScheme::V2);
        assert_eq!(signature.algorithm_id, RSA_PKCS1_SHA256_ALGORITHM_ID);
        assert_eq!(
            signature.signer_certificate_sha256,
            synthetic_signer_policy().certificate_sha256
        );
        assert_eq!(
            signature.signer_spki_sha256,
            synthetic_signer_policy().spki_sha256
        );
        assert_eq!(signature.content_chunk_count, 3);
    }

    #[test]
    fn wrong_digest_and_signature_bit_flip_are_rejected() {
        let options = SyntheticSignature {
            corrupt_content_digest: true,
            ..SyntheticSignature::default()
        };
        assert_eq!(
            verify(signed(options)),
            Err(SignatureViolation::ContentDigestMismatch)
        );

        let options = SyntheticSignature {
            corrupt_signature: true,
            ..SyntheticSignature::default()
        };
        assert_eq!(
            verify(signed(options)),
            Err(SignatureViolation::SignatureInvalid)
        );
    }

    #[test]
    fn both_certificate_and_spki_pins_are_enforced() {
        let options = SyntheticSignature {
            unpinned_certificate: true,
            ..SyntheticSignature::default()
        };
        assert!(matches!(
            verify(signed(options)),
            Err(SignatureViolation::SignerCertificateNotPinned { .. })
        ));

        let options = SyntheticSignature {
            unpinned_spki: true,
            ..SyntheticSignature::default()
        };
        assert!(matches!(
            verify(signed(options)),
            Err(SignatureViolation::SignerPublicKeyNotPinned { .. })
        ));
    }

    #[test]
    fn unsigned_and_v1_only_archives_are_rejected() {
        let unsigned = SyntheticArchive::new().build();
        assert_eq!(verify(unsigned), Err(SignatureViolation::SignatureMissing));
        let v1_only = SyntheticArchive::new()
            .with_entry(SyntheticEntry::stored(
                "META-INF/CERT.RSA",
                b"not a signature".to_vec(),
            ))
            .build();
        assert_eq!(verify(v1_only), Err(SignatureViolation::SignatureMissing));
    }

    #[test]
    fn malformed_truncated_and_oversized_blocks_are_rejected() {
        let mut malformed = signed(SyntheticSignature::default());
        let block = signing_block_offset(&malformed);
        malformed[block + 8..block + 16].copy_from_slice(&u64::MAX.to_le_bytes());
        assert_eq!(verify(malformed), Err(SignatureViolation::Malformed));

        let mut truncated = signed(SyntheticSignature::default());
        truncated.truncate(truncated.len() - 10);
        assert_eq!(
            verify(truncated),
            Err(SignatureViolation::EndOfCentralDirectoryNotFound)
        );

        let bytes = signed(SyntheticSignature::default());
        let mut limits = Limits::DEFAULT;
        limits.max_signing_block_bytes = 31;
        assert!(matches!(
            verify_with_policy(
                &mut IoCursor::new(bytes),
                &limits,
                &synthetic_signer_policy()
            ),
            Err(SignatureViolation::SigningBlockTooLarge { .. })
        ));
    }

    #[test]
    fn offset_overflow_bad_magic_and_size_mismatch_are_rejected() {
        let mut offset_overflow = signed(SyntheticSignature::default());
        let eocd = eocd_offset(&offset_overflow);
        offset_overflow[eocd + 16..eocd + 20].copy_from_slice(&u32::MAX.to_le_bytes());
        assert_eq!(
            verify(offset_overflow),
            Err(SignatureViolation::Zip64NotSupported)
        );

        let mut bad_magic = signed(SyntheticSignature::default());
        let central = central_directory_offset(&bad_magic);
        bad_magic[central - 1] ^= 1;
        assert_eq!(
            verify(bad_magic),
            Err(SignatureViolation::SigningBlockMagicMismatch)
        );

        let mut bad_size = signed(SyntheticSignature::default());
        let block = signing_block_offset(&bad_size);
        bad_size[block] ^= 1;
        assert_eq!(
            verify(bad_size),
            Err(SignatureViolation::SigningBlockSizeMismatch)
        );
    }

    #[test]
    fn duplicate_v2_is_rejected_and_unknown_pair_is_tolerated() {
        let options = SyntheticSignature {
            duplicate_v2: true,
            ..SyntheticSignature::default()
        };
        assert_eq!(
            verify(signed(options)),
            Err(SignatureViolation::DuplicateV2Block)
        );

        let options = SyntheticSignature {
            additional_pairs: vec![(0x1234_5678, b"opaque".to_vec())],
            ..SyntheticSignature::default()
        };
        let verified = verify(signed(options)).expect("unknown pair is allowed");
        assert_eq!(verified.other_block_ids, vec![0x1234_5678]);

        let options = SyntheticSignature {
            additional_pairs: (0..=MAX_OTHER_BLOCK_IDS)
                .map(|index| (0x1234_0000 + index as u32, Vec::new()))
                .collect(),
            ..SyntheticSignature::default()
        };
        assert_eq!(verify(signed(options)), Err(SignatureViolation::Malformed));
    }

    #[test]
    fn algorithm_and_record_disagreement_fail_closed() {
        let options = SyntheticSignature {
            signature_algorithm: 0x0104,
            ..SyntheticSignature::default()
        };
        assert_eq!(
            verify(signed(options)),
            Err(SignatureViolation::UnsupportedSignatureAlgorithm { id: 0x0104 })
        );

        let options = SyntheticSignature {
            digest_algorithm: 0x0104,
            ..SyntheticSignature::default()
        };
        assert_eq!(
            verify(signed(options)),
            Err(SignatureViolation::SignatureAlgorithmMismatch)
        );
    }

    #[test]
    fn exactly_one_signer_is_required() {
        for count in [0, 2] {
            let options = SyntheticSignature {
                signer_count: count,
                ..SyntheticSignature::default()
            };
            assert_eq!(
                verify(signed(options)),
                Err(SignatureViolation::UnexpectedSignerCount {
                    found: count as u32
                })
            );
        }
    }

    #[test]
    fn exactly_one_digest_signature_and_certificate_are_required() {
        for options in [
            SyntheticSignature {
                digest_count: 0,
                ..SyntheticSignature::default()
            },
            SyntheticSignature {
                digest_count: 2,
                ..SyntheticSignature::default()
            },
            SyntheticSignature {
                signature_count: 0,
                ..SyntheticSignature::default()
            },
            SyntheticSignature {
                signature_count: 2,
                ..SyntheticSignature::default()
            },
            SyntheticSignature {
                certificate_count: 0,
                ..SyntheticSignature::default()
            },
            SyntheticSignature {
                certificate_count: 2,
                ..SyntheticSignature::default()
            },
        ] {
            assert_eq!(
                verify(signed(options)),
                Err(SignatureViolation::UnexpectedRecordCount)
            );
        }
    }

    #[test]
    fn content_digest_length_and_chunk_count_are_bounded() {
        let options = SyntheticSignature {
            content_digest_length: 31,
            ..SyntheticSignature::default()
        };
        assert_eq!(
            verify(signed(options)),
            Err(SignatureViolation::ContentDigestLengthMismatch)
        );

        let bytes = signed(SyntheticSignature::default());
        let mut limits = Limits::DEFAULT;
        limits.max_signature_chunks = 2;
        assert_eq!(
            verify_with_policy(
                &mut IoCursor::new(bytes),
                &limits,
                &synthetic_signer_policy()
            ),
            Err(SignatureViolation::TooManyContentChunks {
                declared: 3,
                limit: 2,
            })
        );
    }

    #[test]
    fn spki_der_unwrap_rejects_non_rsa_and_unused_bits() {
        assert_eq!(
            spki_to_pkcs1(&[]),
            Err(SignatureViolation::SubjectPublicKeyMalformed)
        );
        let non_rsa = [0x30, 0x07, 0x30, 0x02, 0x05, 0x00, 0x03, 0x01, 0x00];
        assert_eq!(
            spki_to_pkcs1(&non_rsa),
            Err(SignatureViolation::SubjectPublicKeyMalformed)
        );
        let mut spki = crate::synthetic::rsa_spki_for_test();
        let (outer, _) = der_tlv(&spki, 0x30).expect("outer sequence");
        let outer_start = spki.len() - outer.len();
        let (_, algorithm_end) = der_tlv(outer, 0x30).expect("algorithm identifier");
        let bit_tlv = &outer[algorithm_end..];
        let (bits, _) = der_tlv(bit_tlv, 0x03).expect("bit string");
        let bits_start = outer_start + algorithm_end + bit_tlv.len() - bits.len();
        spki[bits_start] = 1;
        assert_eq!(
            spki_to_pkcs1(&spki),
            Err(SignatureViolation::SubjectPublicKeyMalformed)
        );
    }

    #[test]
    fn exact_four_zero_compatibility_tail_is_the_only_allowed_tail() {
        for tail in [Vec::new(), vec![0, 0, 0, 0]] {
            let options = SyntheticSignature {
                signed_data_tail: tail,
                ..SyntheticSignature::default()
            };
            verify(signed(options)).expect("reviewed compatibility tail");
        }
        for tail in [vec![0], vec![0, 0, 0, 0, 0], vec![0, 0, 0, 1]] {
            let options = SyntheticSignature {
                signed_data_tail: tail,
                ..SyntheticSignature::default()
            };
            assert_eq!(verify(signed(options)), Err(SignatureViolation::Malformed));
        }
    }

    #[test]
    fn newer_schemes_and_stripping_protection_are_rejected() {
        for (id, scheme) in [
            (SYNTHETIC_V3_BLOCK_ID, SignatureScheme::V3),
            (SYNTHETIC_V31_BLOCK_ID, SignatureScheme::V31),
        ] {
            let options = SyntheticSignature {
                additional_pairs: vec![(id, b"synthetic".to_vec())],
                ..SyntheticSignature::default()
            };
            assert_eq!(
                verify(signed(options)),
                Err(SignatureViolation::SignatureSchemeNotSupported { scheme })
            );
        }
        let options = SyntheticSignature {
            attributes: vec![(
                SYNTHETIC_STRIPPING_PROTECTION_ID,
                3u32.to_le_bytes().to_vec(),
            )],
            ..SyntheticSignature::default()
        };
        assert_eq!(
            verify(signed(options)),
            Err(SignatureViolation::StrippingProtectionNotSupported)
        );
    }

    #[test]
    fn mutations_in_each_content_region_are_detected() {
        let original = signed(SyntheticSignature::default());
        let central = central_directory_offset(&original);
        let block = signing_block_offset(&original);
        let eocd = eocd_offset(&original);
        for offset in [35usize, central + 46, eocd + 22] {
            assert!(offset < original.len());
            assert!(offset < block || offset >= central);
            let mut changed = original.clone();
            changed[offset] ^= 1;
            assert_eq!(
                verify(changed),
                Err(SignatureViolation::ContentDigestMismatch)
            );
        }
    }

    #[test]
    fn one_mib_chunk_boundary_is_counted_per_section() {
        let exact = SyntheticArchive::new()
            .with_entry(SyntheticEntry::stored("x", vec![0x55; (1 << 20) - 31]))
            .build_signed();
        assert_eq!(
            verify(exact).expect("exact boundary").content_chunk_count,
            3
        );

        let over = SyntheticArchive::new()
            .with_entry(SyntheticEntry::stored("x", vec![0x55; (1 << 20) - 30]))
            .build_signed();
        assert_eq!(verify(over).expect("over boundary").content_chunk_count, 4);
    }

    #[test]
    fn synthetic_signed_apk_is_byte_exact_and_deterministic() {
        let archive = SyntheticArchive::new()
            .with_entry(SyntheticEntry::stored("payload", b"synthetic".to_vec()));
        assert_eq!(archive.build_signed(), archive.build_signed());
    }

    #[test]
    fn independently_generated_1024_bit_golden_apk_verifies() {
        let bytes = crate::synthetic::decode_hex(include_str!(
            "../tests/fixtures/independent-v2-valid.apk.hex"
        ));
        assert_eq!(
            Hex(&Sha256::digest(&bytes)).to_string(),
            "226e762a935149fee428369eaeeb4623e784e19e1a7bb7085535da476167230c"
        );
        let policy = SignerPolicy {
            certificate_sha256: [
                0x54, 0x20, 0xfd, 0x31, 0xef, 0x0e, 0x12, 0x08, 0xc4, 0x92, 0x79, 0xc9, 0xee, 0xd3,
                0x71, 0x1b, 0x98, 0x94, 0xa4, 0x61, 0x4d, 0x7f, 0x99, 0x05, 0xf1, 0x50, 0x17, 0xbc,
                0x36, 0x76, 0xd5, 0x59,
            ],
            spki_sha256: [
                0x29, 0xa7, 0xb7, 0x9d, 0x63, 0xc1, 0x11, 0x64, 0xa2, 0x2e, 0xa8, 0x0d, 0xba, 0x41,
                0x6d, 0x65, 0x81, 0xa3, 0xad, 0xc6, 0x02, 0xef, 0x4d, 0xd4, 0x2c, 0x14, 0xce, 0x99,
                0x45, 0xf9, 0xde, 0x3b,
            ],
        };
        let signature = verify_with_policy(&mut IoCursor::new(bytes), &Limits::DEFAULT, &policy)
            .expect("independent 1024-bit v2 vector");
        assert_eq!(signature.algorithm_id, RSA_PKCS1_SHA256_ALGORITHM_ID);
    }

    #[test]
    fn production_pin_constants_match_the_reviewed_audit_values() {
        assert_eq!(
            Hex(&APPLE_MUSIC_SIGNER_CERTIFICATE_SHA256).to_string(),
            "88ba590ec2e1ea33c4458daf59489faee2cef297a9b4071e18cf82ef531100aa"
        );
        assert_eq!(
            Hex(&APPLE_MUSIC_SIGNER_SPKI_SHA256).to_string(),
            "53eca3353588f37c234f70d0535f7405f3e429915c84a13aca6d9dfdb5e4ea4c"
        );
    }

    #[test]
    #[ignore = "runs once manually only after synthetic tests, reviews, and full CI"]
    fn verifies_existing_real_apple_artifact_read_only() {
        let path = std::env::var_os("COFFER_APPLE_APK_PATH").expect("set existing artifact path");
        let mut file = File::open(path).expect("open existing artifact read-only");
        let signature =
            verify_apple_music_apk(&mut file, &Limits::DEFAULT).expect("Apple signature");
        assert_eq!(
            signature.content_digest_sha256,
            [
                0xec, 0x76, 0x2b, 0xf0, 0xb5, 0x47, 0x8a, 0x06, 0xa9, 0x9d, 0x40, 0xe4, 0xa4, 0x33,
                0x99, 0xaa, 0x2e, 0xa5, 0xd7, 0x44, 0xe6, 0x4a, 0xa0, 0xc5, 0xde, 0x12, 0x7b, 0xd8,
                0x40, 0x79, 0x79, 0x8d,
            ]
        );
    }
}
