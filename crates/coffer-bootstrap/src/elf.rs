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

//! Structural validation of an extracted ELF shared object.
//!
//! This is a header check, not a loader and not a parser of anything beyond the
//! fixed-size ELF identification and file header.  Its purpose is narrow: catch
//! the case where the archive layout changed under Coffer and an entry with the
//! expected name is no longer a shared object for the host architecture, before
//! that file is installed and later handed to a dynamic loader.
//!
//! Nothing here executes, maps, relocates or resolves symbols.  See the crate
//! documentation for what this validation does and does not guarantee.

use core::fmt;

use crate::arch::{Architecture, ElfClass};

/// `ET_DYN`, the ELF object type of a shared object.
const ET_DYN: u16 = 3;

/// `ELFDATA2LSB`, little-endian data encoding.
const ELFDATA2LSB: u8 = 1;

/// `EV_CURRENT`, the only ELF version ever defined.
const EV_CURRENT: u8 = 1;

/// The ELF file header size for `ELFCLASS32`.
const ELF32_HEADER_BYTES: usize = 52;

/// The ELF file header size for `ELFCLASS64`.
const ELF64_HEADER_BYTES: usize = 64;

/// The facts recorded about a shared object that passed validation.
///
/// These values are copied into install metadata so that a later archive whose
/// layout or ABI changed produces a visible difference rather than a silent
/// substitution.  None of them derives from user data.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ElfSummary {
    /// The declared `e_machine` value.
    pub machine: u16,
    /// The declared `EI_CLASS` value: 1 for `ELFCLASS32`, 2 for `ELFCLASS64`.
    pub class: u8,
}

/// A reason an extracted archive member is not an acceptable shared object.
///
/// Every variant describes the shape of the file, never its contents, so the
/// error is safe to log in full.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ElfViolation {
    /// The file is shorter than the ELF file header for its declared class.
    Truncated {
        /// The number of bytes actually present.
        length: usize,
        /// The number of bytes the header requires.
        required: usize,
    },
    /// The file does not start with the `\x7fELF` magic.
    NotAnElfObject,
    /// The `EI_CLASS` byte does not match the host architecture's word size.
    ClassMismatch {
        /// The class the file declares.
        found: u8,
        /// The class the host architecture requires.
        expected: u8,
    },
    /// The `EI_DATA` byte is not little-endian.
    ///
    /// All four Android ABIs Coffer supports are little-endian, so a big-endian
    /// object means the archive is not what this crate expects.
    EndiannessMismatch {
        /// The encoding the file declares.
        found: u8,
    },
    /// The `EI_VERSION` or `e_version` field is not `EV_CURRENT`.
    VersionMismatch {
        /// The version the file declares.
        found: u32,
    },
    /// The object is not `ET_DYN`.
    NotSharedObject {
        /// The object type the file declares.
        found: u16,
    },
    /// The `e_machine` value does not match the host architecture.
    MachineMismatch {
        /// The machine the file declares.
        found: u16,
        /// The machine the host architecture requires.
        expected: u16,
    },
}

impl fmt::Display for ElfViolation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ElfViolation::Truncated { length, required } => write!(
                f,
                "shared object is {length} bytes, shorter than its {required}-byte ELF header"
            ),
            ElfViolation::NotAnElfObject => f.write_str("file does not carry the ELF magic"),
            ElfViolation::ClassMismatch { found, expected } => {
                write!(
                    f,
                    "ELF class {found} does not match the expected {expected}"
                )
            }
            ElfViolation::EndiannessMismatch { found } => {
                write!(f, "ELF data encoding {found} is not little-endian")
            }
            ElfViolation::VersionMismatch { found } => {
                write!(f, "ELF version {found} is not EV_CURRENT")
            }
            ElfViolation::NotSharedObject { found } => {
                write!(f, "ELF type {found} is not ET_DYN")
            }
            ElfViolation::MachineMismatch { found, expected } => write!(
                f,
                "ELF machine {found} does not match the expected {expected} for this architecture"
            ),
        }
    }
}

impl std::error::Error for ElfViolation {}

/// Validates that `bytes` is a little-endian ELF shared object built for
/// `architecture`.
///
/// # Errors
///
/// Returns the first [`ElfViolation`] encountered.  Checks run in file order
/// (magic, class, encoding, version, type, machine) so that a completely
/// unrelated file reports `NotAnElfObject` rather than a confusing field
/// mismatch.
pub(crate) fn validate_shared_object(
    bytes: &[u8],
    architecture: Architecture,
) -> Result<ElfSummary, ElfViolation> {
    if bytes.len() < 6 {
        return Err(ElfViolation::Truncated {
            length: bytes.len(),
            required: ELF32_HEADER_BYTES,
        });
    }
    if bytes[..4] != [0x7f, b'E', b'L', b'F'] {
        return Err(ElfViolation::NotAnElfObject);
    }

    let expected_class = architecture.elf_class() as u8;
    let class = bytes[4];
    if class != expected_class {
        return Err(ElfViolation::ClassMismatch {
            found: class,
            expected: expected_class,
        });
    }

    let encoding = bytes[5];
    if encoding != ELFDATA2LSB {
        return Err(ElfViolation::EndiannessMismatch { found: encoding });
    }

    let required = match architecture.elf_class() {
        ElfClass::Elf32 => ELF32_HEADER_BYTES,
        ElfClass::Elf64 => ELF64_HEADER_BYTES,
    };
    if bytes.len() < required {
        return Err(ElfViolation::Truncated {
            length: bytes.len(),
            required,
        });
    }

    let identification_version = u32::from(bytes[6]);
    if identification_version != u32::from(EV_CURRENT) {
        return Err(ElfViolation::VersionMismatch {
            found: identification_version,
        });
    }

    let object_type = read_u16(bytes, 16);
    if object_type != ET_DYN {
        return Err(ElfViolation::NotSharedObject { found: object_type });
    }

    let machine = read_u16(bytes, 18);
    let expected_machine = architecture.elf_machine();
    if machine != expected_machine {
        return Err(ElfViolation::MachineMismatch {
            found: machine,
            expected: expected_machine,
        });
    }

    let file_version = read_u32(bytes, 20);
    if file_version != u32::from(EV_CURRENT) {
        return Err(ElfViolation::VersionMismatch {
            found: file_version,
        });
    }

    Ok(ElfSummary { machine, class })
}

/// Reads a little-endian `u16` at `offset`.
///
/// The caller has already established that the slice is at least as long as the
/// ELF header for its class, and every offset used here is inside that header.
fn read_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([bytes[offset], bytes[offset + 1]])
}

/// Reads a little-endian `u32` at `offset`, under the same precondition as
/// [`read_u16`].
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

    /// Builds a minimal but well-formed ELF file header.
    fn elf_header(architecture: Architecture) -> Vec<u8> {
        let class = architecture.elf_class() as u8;
        let size = match architecture.elf_class() {
            ElfClass::Elf32 => ELF32_HEADER_BYTES,
            ElfClass::Elf64 => ELF64_HEADER_BYTES,
        };
        let mut header = vec![0u8; size];
        header[..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
        header[4] = class;
        header[5] = ELFDATA2LSB;
        header[6] = EV_CURRENT;
        header[16..18].copy_from_slice(&ET_DYN.to_le_bytes());
        header[18..20].copy_from_slice(&architecture.elf_machine().to_le_bytes());
        header[20..24].copy_from_slice(&1u32.to_le_bytes());
        header
    }

    #[test]
    fn accepts_a_shared_object_for_every_supported_architecture() {
        for architecture in Architecture::ALL {
            let summary = validate_shared_object(&elf_header(architecture), architecture)
                .expect("a well-formed header must validate");
            assert_eq!(summary.machine, architecture.elf_machine());
            assert_eq!(summary.class, architecture.elf_class() as u8);
        }
    }

    #[test]
    fn rejects_a_file_without_elf_magic() {
        let mut header = elf_header(Architecture::X86_64);
        header[1] = b'X';
        assert_eq!(
            validate_shared_object(&header, Architecture::X86_64),
            Err(ElfViolation::NotAnElfObject)
        );
    }

    #[test]
    fn rejects_an_object_built_for_another_machine_of_the_same_width() {
        // Both are ELFCLASS64, so only `e_machine` distinguishes them.  This is
        // the case that matters most: an installation made on one 64-bit host
        // must never be loaded on the other.
        let header = elf_header(Architecture::Aarch64);
        assert_eq!(
            validate_shared_object(&header, Architecture::X86_64),
            Err(ElfViolation::MachineMismatch {
                found: 183,
                expected: 62,
            })
        );

        let header = elf_header(Architecture::X86_64);
        assert_eq!(
            validate_shared_object(&header, Architecture::Aarch64),
            Err(ElfViolation::MachineMismatch {
                found: 62,
                expected: 183,
            })
        );
    }

    #[test]
    fn rejects_a_32_bit_object_where_a_64_bit_one_is_expected() {
        let header = elf_header(Architecture::X86);
        assert_eq!(
            validate_shared_object(&header, Architecture::X86_64),
            Err(ElfViolation::ClassMismatch {
                found: 1,
                expected: 2
            })
        );
    }

    #[test]
    fn rejects_a_big_endian_object() {
        let mut header = elf_header(Architecture::X86_64);
        header[5] = 2;
        assert_eq!(
            validate_shared_object(&header, Architecture::X86_64),
            Err(ElfViolation::EndiannessMismatch { found: 2 })
        );
    }

    #[test]
    fn rejects_an_executable_rather_than_a_shared_object() {
        let mut header = elf_header(Architecture::X86_64);
        header[16..18].copy_from_slice(&2u16.to_le_bytes());
        assert_eq!(
            validate_shared_object(&header, Architecture::X86_64),
            Err(ElfViolation::NotSharedObject { found: 2 })
        );
    }

    #[test]
    fn rejects_an_unknown_elf_version() {
        let mut header = elf_header(Architecture::X86_64);
        header[6] = 2;
        assert_eq!(
            validate_shared_object(&header, Architecture::X86_64),
            Err(ElfViolation::VersionMismatch { found: 2 })
        );

        let mut header = elf_header(Architecture::X86_64);
        header[20..24].copy_from_slice(&7u32.to_le_bytes());
        assert_eq!(
            validate_shared_object(&header, Architecture::X86_64),
            Err(ElfViolation::VersionMismatch { found: 7 })
        );
    }

    #[test]
    fn rejects_a_header_truncated_before_the_machine_field() {
        let header = elf_header(Architecture::X86_64);
        for length in [0usize, 3, 5, 16, 20, ELF64_HEADER_BYTES - 1] {
            let error = validate_shared_object(&header[..length], Architecture::X86_64)
                .expect_err("a truncated header must be rejected");
            assert!(
                matches!(error, ElfViolation::Truncated { .. }),
                "unexpected violation for length {length}: {error:?}"
            );
        }
    }

    #[test]
    fn rejects_an_empty_file() {
        assert_eq!(
            validate_shared_object(&[], Architecture::X86_64),
            Err(ElfViolation::Truncated {
                length: 0,
                required: ELF32_HEADER_BYTES
            })
        );
    }
}
