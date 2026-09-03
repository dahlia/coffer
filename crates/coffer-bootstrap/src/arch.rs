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

//! Host CPU architecture to Android ABI mapping.
//!
//! The Apple support libraries Coffer needs are published only inside an
//! Android application archive, so every path in this crate is parameterized
//! by an Android ABI directory name rather than by a Rust target triple.  This
//! module is the single place that translates between the two, and the single
//! place that decides an architecture is unsupported.

use core::fmt;

/// A CPU architecture for which the Apple Music Android archive is known to
/// ship the support libraries Coffer needs.
///
/// The mapping to an Android ABI directory name is fixed by the Android NDK
/// ABI documentation, not by Coffer, and Coffer records the resolved ABI in
/// install metadata so that an installation made for one architecture can
/// never be loaded on another.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum Architecture {
    /// 64-bit x86, Android ABI `x86_64`.
    X86_64,
    /// 64-bit Arm, Android ABI `arm64-v8a`.
    Aarch64,
    /// 32-bit x86, Android ABI `x86`.
    X86,
    /// 32-bit Arm with hardware floating point, Android ABI `armeabi-v7a`.
    Arm,
}

/// The ELF identification class expected for an architecture.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ElfClass {
    /// `ELFCLASS32`.
    Elf32 = 1,
    /// `ELFCLASS64`.
    Elf64 = 2,
}

impl Architecture {
    /// Every architecture Coffer can bootstrap, in a stable order.
    pub const ALL: [Architecture; 4] = [
        Architecture::X86_64,
        Architecture::Aarch64,
        Architecture::X86,
        Architecture::Arm,
    ];

    /// Resolves the architecture of the process running this code.
    ///
    /// # Errors
    ///
    /// Returns [`UnsupportedArchitecture`] when the host is not one of the four
    /// architectures the archive publishes.  Bootstrap must not be attempted at
    /// all in that case: there is no artifact to download and no fallback, so
    /// failing here keeps the caller from making a pointless network request.
    pub fn host() -> Result<Self, UnsupportedArchitecture> {
        Self::from_rust_target_arch(std::env::consts::ARCH)
    }

    /// Resolves an architecture from a Rust `target_arch` value such as
    /// `"x86_64"` or `"aarch64"`.
    ///
    /// # Errors
    ///
    /// Returns [`UnsupportedArchitecture`] for every other value, including
    /// architectures such as `riscv64` for which the archive ships nothing.
    pub fn from_rust_target_arch(target_arch: &str) -> Result<Self, UnsupportedArchitecture> {
        match target_arch {
            "x86_64" => Ok(Architecture::X86_64),
            "aarch64" => Ok(Architecture::Aarch64),
            "x86" => Ok(Architecture::X86),
            "arm" => Ok(Architecture::Arm),
            other => Err(UnsupportedArchitecture::new(other)),
        }
    }

    /// The Rust `target_arch` value this architecture corresponds to.
    #[must_use]
    pub const fn rust_target_arch(self) -> &'static str {
        match self {
            Architecture::X86_64 => "x86_64",
            Architecture::Aarch64 => "aarch64",
            Architecture::X86 => "x86",
            Architecture::Arm => "arm",
        }
    }

    /// The Android ABI directory name used inside the archive's `lib/`
    /// hierarchy.
    #[must_use]
    pub const fn android_abi(self) -> &'static str {
        match self {
            Architecture::X86_64 => "x86_64",
            Architecture::Aarch64 => "arm64-v8a",
            Architecture::X86 => "x86",
            Architecture::Arm => "armeabi-v7a",
        }
    }

    /// The ELF class every support library for this architecture must declare.
    pub(crate) const fn elf_class(self) -> ElfClass {
        match self {
            Architecture::X86_64 | Architecture::Aarch64 => ElfClass::Elf64,
            Architecture::X86 | Architecture::Arm => ElfClass::Elf32,
        }
    }

    /// The ELF `e_machine` value every support library for this architecture
    /// must declare.
    ///
    /// The constants are `EM_386`, `EM_ARM`, `EM_X86_64` and `EM_AARCH64` from
    /// the System V ABI machine registry.
    pub(crate) const fn elf_machine(self) -> u16 {
        match self {
            Architecture::X86_64 => 62,
            Architecture::Aarch64 => 183,
            Architecture::X86 => 3,
            Architecture::Arm => 40,
        }
    }
}

impl fmt::Display for Architecture {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.android_abi())
    }
}

/// The host CPU architecture has no Apple support libraries published for it.
///
/// The recorded architecture name is a CPU architecture identifier, never
/// account or path data, so it is safe to log and to render in a user-facing
/// message.  It is sanitized on construction anyway, because
/// [`Architecture::from_rust_target_arch`] accepts an arbitrary caller-supplied
/// string.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UnsupportedArchitecture {
    rust_target_arch: Box<str>,
}

impl UnsupportedArchitecture {
    /// The longest architecture name retained in the error.
    const MAX_NAME_BYTES: usize = 32;

    fn new(target_arch: &str) -> Self {
        let sanitized: String = target_arch
            .chars()
            .take(Self::MAX_NAME_BYTES)
            .map(|c| {
                if c.is_ascii_alphanumeric() || c == '_' || c == '-' {
                    c
                } else {
                    '?'
                }
            })
            .collect();
        Self {
            rust_target_arch: sanitized.into_boxed_str(),
        }
    }

    /// The sanitized architecture name that was rejected.
    #[must_use]
    pub fn rust_target_arch(&self) -> &str {
        &self.rust_target_arch
    }
}

impl fmt::Display for UnsupportedArchitecture {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "no Apple support libraries are published for CPU architecture `{}`",
            self.rust_target_arch
        )
    }
}

impl std::error::Error for UnsupportedArchitecture {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_every_supported_target_arch_to_its_android_abi() {
        let pairs = [
            ("x86_64", Architecture::X86_64, "x86_64"),
            ("aarch64", Architecture::Aarch64, "arm64-v8a"),
            ("x86", Architecture::X86, "x86"),
            ("arm", Architecture::Arm, "armeabi-v7a"),
        ];
        for (target_arch, expected, abi) in pairs {
            let resolved = Architecture::from_rust_target_arch(target_arch)
                .expect("architecture should be supported");
            assert_eq!(resolved, expected);
            assert_eq!(resolved.android_abi(), abi);
            assert_eq!(resolved.rust_target_arch(), target_arch);
        }
    }

    #[test]
    fn all_lists_every_variant_exactly_once() {
        let mut abis: Vec<&str> = Architecture::ALL.iter().map(|a| a.android_abi()).collect();
        abis.sort_unstable();
        abis.dedup();
        assert_eq!(abis.len(), Architecture::ALL.len());
    }

    #[test]
    fn rejects_architectures_the_archive_does_not_publish() {
        for target_arch in ["riscv64", "powerpc64", "s390x", "mips", "", "X86_64"] {
            let error = Architecture::from_rust_target_arch(target_arch)
                .expect_err("architecture should be unsupported");
            assert_eq!(error.rust_target_arch(), target_arch);
        }
    }

    #[test]
    fn sanitizes_and_truncates_the_rejected_architecture_name() {
        let error = Architecture::from_rust_target_arch("../../etc/shadow\0")
            .expect_err("architecture should be unsupported");
        assert_eq!(error.rust_target_arch(), "??????etc?shadow?");

        let long = "a".repeat(UnsupportedArchitecture::MAX_NAME_BYTES + 10);
        let error =
            Architecture::from_rust_target_arch(&long).expect_err("architecture is unsupported");
        assert_eq!(
            error.rust_target_arch().len(),
            UnsupportedArchitecture::MAX_NAME_BYTES
        );
    }

    #[test]
    fn host_architecture_resolves_on_every_architecture_the_test_suite_runs_on() {
        // The test suite only runs on architectures Coffer supports, so a
        // failure here means the mapping lost an entry rather than that the
        // host is exotic.
        let host = Architecture::host().expect("the test host must be a supported architecture");
        assert_eq!(host.rust_target_arch(), std::env::consts::ARCH);
    }

    #[test]
    fn elf_expectations_match_the_architecture_width() {
        assert_eq!(Architecture::X86_64.elf_class(), ElfClass::Elf64);
        assert_eq!(Architecture::Aarch64.elf_class(), ElfClass::Elf64);
        assert_eq!(Architecture::X86.elf_class(), ElfClass::Elf32);
        assert_eq!(Architecture::Arm.elf_class(), ElfClass::Elf32);
        assert_eq!(Architecture::X86_64.elf_machine(), 62);
        assert_eq!(Architecture::Aarch64.elf_machine(), 183);
        assert_eq!(Architecture::X86.elf_machine(), 3);
        assert_eq!(Architecture::Arm.elf_machine(), 40);
    }
}
