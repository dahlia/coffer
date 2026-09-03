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

//! Fail-closed policy for the observed Apple Music Android ELF ABI.
//!
//! The policy describes Apple Music 4.9.6 (version code 1447), observed on
//! 2026-09-04.  It intentionally rejects a future image when any dependency,
//! import, export, version node, relocation count/type, initialization-array
//! size, TLS use, packed relocation, machine, class, endianness, or LOAD
//! alignment changes.  A new artifact therefore requires a reviewed policy
//! update instead of silently expanding executable behavior.
//!
//! The ADI declarations below come from SideStore's MPL-2.0
//! [`store_services_core.rs`](https://github.com/SideStore/apple-private-apis/blob/03beb1aa42991ccdad6214dee77e72282bef461f/omnisette/src/store_services_core.rs).

use std::collections::BTreeSet;

use coffer_bootstrap::Architecture;
use elf::ElfBytes;
use elf::abi;
use elf::endian::AnyEndian;
use elf::file::Class;
use sha2::{Digest, Sha256};

use crate::error::BridgeError;

/// Maximum accepted size of either proprietary library.
pub const MAX_LIBRARY_BYTES: usize = 64 * 1024 * 1024;

/// StoreServicesCore ADI loader entry point.
pub type AdiLoadLibraryWithPath = unsafe extern "C" fn(*const u8) -> i32;
/// Set the Android device identifier.
pub type AdiSetAndroidId = unsafe extern "C" fn(*const u8, u32) -> i32;
/// Set the ADI provisioning directory.
pub type AdiSetProvisioningPath = unsafe extern "C" fn(*const u8) -> i32;
/// Erase provisioning state for one directory-services identifier.
pub type AdiProvisioningErase = unsafe extern "C" fn(i64) -> i32;
/// Synchronize provisioning material and return ADI-owned MID/SRM buffers.
pub type AdiSynchronize = unsafe extern "C" fn(
    i64,
    *const u8,
    u32,
    *mut *const u8,
    *mut u32,
    *mut *const u8,
    *mut u32,
) -> i32;
/// Destroy a provisioning session.
pub type AdiProvisioningDestroy = unsafe extern "C" fn(u32) -> i32;
/// Finish a provisioning session.
pub type AdiProvisioningEnd = unsafe extern "C" fn(u32, *const u8, u32, *const u8, u32) -> i32;
/// Start provisioning and return an ADI-owned CPIM buffer and session.
pub type AdiProvisioningStart =
    unsafe extern "C" fn(i64, *const u8, u32, *mut *const u8, *mut u32, *mut u32) -> i32;
/// Query whether the machine is provisioned for a directory-services identifier.
pub type AdiGetLoginCode = unsafe extern "C" fn(i64) -> i32;
/// Dispose a buffer returned by ADI.
pub type AdiDispose = unsafe extern "C" fn(*const u8) -> i32;
/// Request ADI-owned MID and OTP buffers.
pub type AdiOtpRequest =
    unsafe extern "C" fn(i64, *mut *const u8, *mut u32, *mut *const u8, *mut u32) -> i32;

/// All StoreServicesCore ADI exports whose signatures are declared by the
/// MPL-2.0 SideStore revision named in the crate documentation.
pub const ADI_EXPORTS: [&str; 11] = [
    "kq56gsgHG6",
    "Sph98paBcz",
    "nf92ngaK92",
    "p435tmhbla",
    "tn46gtiuhw",
    "fy34trz2st",
    "uv5t6nhkui",
    "rsegvyrt87",
    "aslgmuibau",
    "jk24uiwqrg",
    "qi864985u0",
];

/// Proprietary image role selected for ABI validation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum LibraryKind {
    /// `libCoreADI.so`.
    CoreAdi,
    /// `libstoreservicescore.so`.
    StoreServicesCore,
}

const CORE_NEEDED: [&str; 3] = ["libc.so", "libdl.so", "liblog.so"];
const SSC_NEEDED: [&str; 9] = [
    "libCoreFoundation.so",
    "libandroid.so",
    "libc++_shared.so",
    "libc.so",
    "libdl.so",
    "liblog.so",
    "libm.so",
    "libmediaplatform.so",
    "libz.so",
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ImageKind {
    CoreAdi,
    StoreServicesCore,
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub(crate) struct Import {
    pub(crate) name: String,
    pub(crate) version: Option<String>,
}

#[derive(Debug)]
pub(crate) struct ImagePolicy {
    image_sha256: &'static str,
    needed: &'static [&'static str],
    import_count: usize,
    export_count: usize,
    import_sha256: &'static str,
    export_sha256: &'static str,
    versioned_import_count: usize,
    versioned_import_sha256: &'static str,
    relocations: &'static [(u32, usize)],
    init_array_bytes: usize,
}

/// Revalidates one image against the complete currently observed policy.
///
/// # Errors
///
/// Returns [`BridgeError::AbiMismatch`] for every parse error or policy drift.
pub fn validate_image(
    bytes: &[u8],
    architecture: Architecture,
    kind: LibraryKind,
) -> Result<(), BridgeError> {
    validate(
        bytes,
        architecture,
        match kind {
            LibraryKind::CoreAdi => ImageKind::CoreAdi,
            LibraryKind::StoreServicesCore => ImageKind::StoreServicesCore,
        },
    )
    .map(|_| ())
}

pub(crate) fn validate(
    bytes: &[u8],
    architecture: Architecture,
    kind: ImageKind,
) -> Result<Vec<Import>, BridgeError> {
    if bytes.len() > MAX_LIBRARY_BYTES {
        return Err(BridgeError::AbiMismatch);
    }
    let file = ElfBytes::<AnyEndian>::minimal_parse(bytes).map_err(|_| BridgeError::AbiMismatch)?;
    let machine = match architecture {
        Architecture::X86_64 => abi::EM_X86_64,
        Architecture::Aarch64 => abi::EM_AARCH64,
        _ => return Err(BridgeError::UnsupportedArchitecture),
    };
    if file.ehdr.class != Class::ELF64
        || file.ehdr.endianness != AnyEndian::Little
        || file.ehdr.e_type != abi::ET_DYN
        || file.ehdr.e_machine != machine
    {
        return Err(BridgeError::AbiMismatch);
    }
    let policy = policy(architecture, kind)?;
    if bytes_digest(bytes) != policy.image_sha256 {
        return Err(BridgeError::AbiMismatch);
    }
    validate_segments(&file)?;
    let common = file
        .find_common_data()
        .map_err(|_| BridgeError::AbiMismatch)?;
    let dynamic = common.dynamic.ok_or(BridgeError::AbiMismatch)?;
    let dynstr = common.dynsyms_strs.ok_or(BridgeError::AbiMismatch)?;
    let mut needed = BTreeSet::new();
    let mut init_array_bytes = 0usize;
    for entry in dynamic.iter() {
        match entry.d_tag {
            abi::DT_NEEDED => {
                needed.insert(
                    dynstr
                        .get(entry.d_val() as usize)
                        .map_err(|_| BridgeError::AbiMismatch)?,
                );
            }
            abi::DT_INIT_ARRAYSZ => {
                init_array_bytes =
                    usize::try_from(entry.d_val()).map_err(|_| BridgeError::AbiMismatch)?;
            }
            // GNU RELR and Android APS2 packed relocations are intentionally
            // outside the current policy.
            35..=37 | 0x6000_000f..=0x6000_0014 => return Err(BridgeError::AbiMismatch),
            _ => {}
        }
    }
    if needed != policy.needed.iter().copied().collect()
        || init_array_bytes != policy.init_array_bytes
    {
        return Err(BridgeError::AbiMismatch);
    }

    let dynsyms = common.dynsyms.ok_or(BridgeError::AbiMismatch)?;
    let versions = file
        .symbol_version_table()
        .map_err(|_| BridgeError::AbiMismatch)?;
    let mut imports = BTreeSet::new();
    let mut exports = BTreeSet::new();
    for index in 0..dynsyms.len() {
        let symbol = dynsyms.get(index).map_err(|_| BridgeError::AbiMismatch)?;
        let name = dynstr
            .get(symbol.st_name as usize)
            .map_err(|_| BridgeError::AbiMismatch)?;
        if name.is_empty() {
            continue;
        }
        if symbol.is_undefined() {
            let version = versions
                .as_ref()
                .map(|table| table.get_requirement(index))
                .transpose()
                .map_err(|_| BridgeError::AbiMismatch)?
                .flatten()
                .map(|requirement| {
                    if requirement.name != "LIBC"
                        || !matches!(requirement.file, "libc.so" | "libdl.so")
                    {
                        return Err(BridgeError::AbiMismatch);
                    }
                    Ok(requirement.name.to_owned())
                })
                .transpose()?;
            imports.insert(Import {
                name: name.to_owned(),
                version,
            });
        } else {
            if versions
                .as_ref()
                .map(|table| table.get_definition(index))
                .transpose()
                .map_err(|_| BridgeError::AbiMismatch)?
                .flatten()
                .is_some()
            {
                return Err(BridgeError::AbiMismatch);
            }
            exports.insert(name.to_owned());
        }
    }
    if imports.len() != policy.import_count
        || exports.len() != policy.export_count
        || names_digest(imports.iter().map(|entry| entry.name.as_str())) != policy.import_sha256
        || names_digest(exports.iter().map(String::as_str)) != policy.export_sha256
        || versioned_names_digest(imports.iter()).0 != policy.versioned_import_count
        || versioned_names_digest(imports.iter()).1 != policy.versioned_import_sha256
    {
        return Err(BridgeError::AbiMismatch);
    }
    if kind == ImageKind::StoreServicesCore
        && !ADI_EXPORTS.iter().all(|name| exports.contains(*name))
    {
        return Err(BridgeError::AbiMismatch);
    }
    validate_relocations(&file, policy.relocations)?;
    Ok(imports.into_iter().collect())
}

fn validate_segments(file: &ElfBytes<'_, AnyEndian>) -> Result<(), BridgeError> {
    let segments = file.segments().ok_or(BridgeError::AbiMismatch)?;
    let mut saw_load = false;
    for segment in segments.iter() {
        if segment.p_type == abi::PT_TLS {
            return Err(BridgeError::AbiMismatch);
        }
        if segment.p_type == abi::PT_LOAD {
            saw_load = true;
            if segment.p_align != 0x1000
                || segment.p_offset % segment.p_align != segment.p_vaddr % segment.p_align
            {
                return Err(BridgeError::AbiMismatch);
            }
        }
    }
    saw_load.then_some(()).ok_or(BridgeError::AbiMismatch)
}

fn validate_relocations(
    file: &ElfBytes<'_, AnyEndian>,
    expected: &[(u32, usize)],
) -> Result<(), BridgeError> {
    let sections = file.section_headers().ok_or(BridgeError::AbiMismatch)?;
    let mut counts = std::collections::BTreeMap::<u32, usize>::new();
    for section in sections.iter() {
        match section.sh_type {
            abi::SHT_REL => {
                for relocation in file
                    .section_data_as_rels(&section)
                    .map_err(|_| BridgeError::AbiMismatch)?
                {
                    *counts.entry(relocation.r_type).or_default() += 1;
                }
            }
            abi::SHT_RELA => {
                for relocation in file
                    .section_data_as_relas(&section)
                    .map_err(|_| BridgeError::AbiMismatch)?
                {
                    *counts.entry(relocation.r_type).or_default() += 1;
                }
            }
            _ => {}
        }
    }
    let observed: Vec<_> = counts.into_iter().collect();
    (observed == expected)
        .then_some(())
        .ok_or(BridgeError::AbiMismatch)
}

fn names_digest<'a>(names: impl Iterator<Item = &'a str>) -> String {
    let mut hasher = Sha256::new();
    for name in names {
        hasher.update(name.as_bytes());
        hasher.update(b"\n");
    }
    encode_digest(hasher.finalize())
}

fn bytes_digest(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    encode_digest(hasher.finalize())
}

fn encode_digest(digest: impl AsRef<[u8]>) -> String {
    let mut out = String::with_capacity(64);
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for byte in digest.as_ref() {
        out.push(char::from(HEX[usize::from(byte >> 4)]));
        out.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    out
}

fn versioned_names_digest<'a>(imports: impl Iterator<Item = &'a Import>) -> (usize, String) {
    let versioned: Vec<_> = imports
        .filter_map(|import| {
            import
                .version
                .as_ref()
                .map(|version| format!("{}@{version}", import.name))
        })
        .collect();
    let count = versioned.len();
    (count, names_digest(versioned.iter().map(String::as_str)))
}

fn policy(
    architecture: Architecture,
    kind: ImageKind,
) -> Result<&'static ImagePolicy, BridgeError> {
    match (architecture, kind) {
        (Architecture::X86_64, ImageKind::CoreAdi) => Ok(&X86_CORE),
        (Architecture::X86_64, ImageKind::StoreServicesCore) => Ok(&X86_SSC),
        (Architecture::Aarch64, ImageKind::CoreAdi) => Ok(&ARM64_CORE),
        (Architecture::Aarch64, ImageKind::StoreServicesCore) => Ok(&ARM64_SSC),
        _ => Err(BridgeError::UnsupportedArchitecture),
    }
}

const X86_CORE_RELOCS: &[(u32, usize)] = &[
    (abi::R_X86_64_64, 22),
    (abi::R_X86_64_JUMP_SLOT, 2),
    (abi::R_X86_64_RELATIVE, 529),
];
const X86_SSC_RELOCS: &[(u32, usize)] = &[
    (abi::R_X86_64_64, 1815),
    (abi::R_X86_64_GLOB_DAT, 347),
    (abi::R_X86_64_JUMP_SLOT, 1081),
    (abi::R_X86_64_RELATIVE, 3089),
];
const ARM64_CORE_RELOCS: &[(u32, usize)] = &[
    (abi::R_AARCH64_ABS64, 22),
    (abi::R_AARCH64_JUMP_SLOT, 2),
    (abi::R_AARCH64_RELATIVE, 530),
];
const ARM64_SSC_RELOCS: &[(u32, usize)] = &[
    (abi::R_AARCH64_ABS64, 1815),
    (abi::R_AARCH64_GLOB_DAT, 347),
    (abi::R_AARCH64_JUMP_SLOT, 1083),
    (abi::R_AARCH64_RELATIVE, 3102),
];

const X86_CORE: ImagePolicy = ImagePolicy {
    image_sha256: "ece4ffa6bbe4239e8f0d4714da57e62ce5e3c581d19553a83d78ac897783b905",
    needed: &CORE_NEEDED,
    import_count: 24,
    export_count: 22,
    import_sha256: "24ce6d839dc4b38eea3baddeca0760e3e34d1fcf39e98e5e03d1396d20681cf5",
    export_sha256: "2201f77d23e8ca069093ae9286d1a4cf578362df3d73d12a40f88b1dc2c00f75",
    versioned_import_count: 24,
    versioned_import_sha256: "4eb5d797a1548741abc2f38e804dc7e860540572107a95de5944d6eff4fe7b1c",
    relocations: X86_CORE_RELOCS,
    init_array_bytes: 0,
};
const X86_SSC: ImagePolicy = ImagePolicy {
    image_sha256: "d8be230df34c0044758d43e33a8dabd3236b9a4258c4d48cb366911224d52f68",
    needed: &SSC_NEEDED,
    import_count: 403,
    export_count: 2053,
    import_sha256: "088d8ca818ff91ea04e7f9cdab6d4841d4f10e0ca4ef6b4a10886e5f3b1cfb8e",
    export_sha256: "7261ed6458596035a4dcc83994917cd45f025df748570d2e476ce16c7aef6696",
    versioned_import_count: 41,
    versioned_import_sha256: "0b6cb1273fe81c84743db9e31b8588548b5aa034b55a60ca8c6f32a99f04634f",
    relocations: X86_SSC_RELOCS,
    init_array_bytes: 512,
};
const ARM64_CORE: ImagePolicy = ImagePolicy {
    image_sha256: "9d5b557cf3faf88c34c394ab2cd7fc1a3b4acf3aed51f28cd0bc093858107c22",
    needed: &CORE_NEEDED,
    import_count: 24,
    export_count: 3,
    import_sha256: "24ce6d839dc4b38eea3baddeca0760e3e34d1fcf39e98e5e03d1396d20681cf5",
    export_sha256: "90f1ab764878f3e88c52e1ec8ee3ad5cd74cca4ebace2fbfe38bb8550999935a",
    versioned_import_count: 24,
    versioned_import_sha256: "4eb5d797a1548741abc2f38e804dc7e860540572107a95de5944d6eff4fe7b1c",
    relocations: ARM64_CORE_RELOCS,
    init_array_bytes: 0,
};
const ARM64_SSC: ImagePolicy = ImagePolicy {
    image_sha256: "bd335e6963ba5ae2f5babca613435ad56d2660a9aee37df35f876c458d105ce4",
    needed: &SSC_NEEDED,
    import_count: 405,
    export_count: 2053,
    import_sha256: "a91b31fb2d9a5d8bc22f1df51535bd6365a7ff4100268d23604001a868847265",
    export_sha256: "7261ed6458596035a4dcc83994917cd45f025df748570d2e476ce16c7aef6696",
    versioned_import_count: 43,
    versioned_import_sha256: "fa2a1a7741a093ec180d7db5a04540c8f143fe1d5edc07480cfd285577d31c9d",
    relocations: ARM64_SSC_RELOCS,
    init_array_bytes: 520,
};

#[cfg(test)]
mod tests {
    use elf_loader::arch::x86_64::X86_64Arch;
    use elf_loader::elf::write::DsoBuilder;

    use super::*;

    fn synthetic_dso() -> Vec<u8> {
        DsoBuilder::<X86_64Arch>::new("synthetic.so")
            .with_text(vec![0xc3])
            .build()
            .expect("build synthetic DSO")
            .bytes
    }

    #[test]
    fn malformed_truncated_and_oversized_images_fail_closed() {
        for bytes in [
            Vec::new(),
            b"not ELF".to_vec(),
            synthetic_dso()[..31].to_vec(),
        ] {
            assert_eq!(
                validate_image(&bytes, Architecture::X86_64, LibraryKind::CoreAdi),
                Err(BridgeError::AbiMismatch)
            );
        }
        assert_eq!(
            validate_image(
                &vec![0; MAX_LIBRARY_BYTES + 1],
                Architecture::X86_64,
                LibraryKind::CoreAdi
            ),
            Err(BridgeError::AbiMismatch)
        );
    }

    #[test]
    fn a_synthetic_image_with_wrong_dependencies_imports_and_exports_is_rejected() {
        assert_eq!(
            validate_image(&synthetic_dso(), Architecture::X86_64, LibraryKind::CoreAdi),
            Err(BridgeError::AbiMismatch)
        );
    }

    #[test]
    fn policy_hash_distinguishes_missing_extra_and_renamed_symbols() {
        let exact = names_digest(["a", "b"].into_iter());
        assert_ne!(exact, names_digest(["a"].into_iter()));
        assert_ne!(exact, names_digest(["a", "b", "c"].into_iter()));
        assert_ne!(exact, names_digest(["a", "c"].into_iter()));
    }
}
