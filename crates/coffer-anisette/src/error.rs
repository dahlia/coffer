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

//! Secret-free failure classification for the helper boundary.

use core::fmt;

/// The stage at which one non-retried helper invocation stopped.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Stage {
    /// Request/response framing.
    Ipc,
    /// Resolving the already verified installation.
    Paths,
    /// Revalidating the current ELF ABI policy.
    Abi,
    /// Applying resource limits, `no_new_privs`, and seccomp.
    Sandbox,
    /// Mapping or relocating an image with constructors deferred.
    Loader,
    /// Binding the typed ADI entry points.
    Bind,
    /// Loading CoreADI through the StoreServicesCore entry point.
    LoadCoreAdi,
    /// Setting the disposable provisioning directory.
    SetProvisioningPath,
    /// Querying provisioned state.
    QueryProvisioned,
    /// Waiting for the helper process.
    Process,
}

/// A bounded, secret-free bridge error.
///
/// No variant contains a filesystem path, Apple diagnostic string, account
/// identifier, provisioning bytes, or other caller-controlled text.  `Debug`
/// and `Display` are therefore safe for ordinary diagnostics.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum BridgeError {
    /// The message was malformed, truncated, trailing, or oversized.
    InvalidMessage,
    /// A path was not absolute, canonical, or within the verified root.
    InvalidPath,
    /// A file was absent, too large, malformed, or outside the observed ABI.
    AbiMismatch,
    /// The host architecture is not supported by this executable bridge.
    UnsupportedArchitecture,
    /// Mandatory sandboxing could not be installed or verified.
    SandboxUnavailable,
    /// `elf_loader` refused to map or relocate an image.
    LoaderRejected,
    /// A required typed export could not be bound.
    MissingExport,
    /// The Apple loader export returned a nonzero status.
    CoreAdiLoadFailed,
    /// The provisioning-path setter returned a nonzero status.
    ProvisioningPathFailed,
    /// The helper exceeded its single invocation deadline.
    TimedOut,
    /// The helper terminated by signal, abort, or an abort-only shim.
    HelperCrashed,
    /// The helper exited unsuccessfully without a classifiable response.
    HelperFailed,
    /// Local process creation or pipe I/O failed.
    ProcessIo,
}

impl BridgeError {
    /// Returns the stage callers can present without inspecting error text.
    #[must_use]
    pub const fn stage(self) -> Stage {
        match self {
            Self::InvalidMessage => Stage::Ipc,
            Self::InvalidPath => Stage::Paths,
            Self::AbiMismatch | Self::UnsupportedArchitecture => Stage::Abi,
            Self::SandboxUnavailable => Stage::Sandbox,
            Self::LoaderRejected => Stage::Loader,
            Self::MissingExport => Stage::Bind,
            Self::CoreAdiLoadFailed => Stage::LoadCoreAdi,
            Self::ProvisioningPathFailed => Stage::SetProvisioningPath,
            Self::TimedOut | Self::HelperCrashed | Self::HelperFailed | Self::ProcessIo => {
                Stage::Process
            }
        }
    }

    pub(crate) const fn code(self) -> u8 {
        match self {
            Self::InvalidMessage => 1,
            Self::InvalidPath => 2,
            Self::AbiMismatch => 3,
            Self::UnsupportedArchitecture => 4,
            Self::SandboxUnavailable => 5,
            Self::LoaderRejected => 6,
            Self::MissingExport => 7,
            Self::CoreAdiLoadFailed => 8,
            Self::ProvisioningPathFailed => 9,
            Self::TimedOut => 10,
            Self::HelperCrashed => 11,
            Self::HelperFailed => 12,
            Self::ProcessIo => 13,
        }
    }

    pub(crate) const fn from_code(code: u8) -> Option<Self> {
        Some(match code {
            1 => Self::InvalidMessage,
            2 => Self::InvalidPath,
            3 => Self::AbiMismatch,
            4 => Self::UnsupportedArchitecture,
            5 => Self::SandboxUnavailable,
            6 => Self::LoaderRejected,
            7 => Self::MissingExport,
            8 => Self::CoreAdiLoadFailed,
            9 => Self::ProvisioningPathFailed,
            10 => Self::TimedOut,
            11 => Self::HelperCrashed,
            12 => Self::HelperFailed,
            13 => Self::ProcessIo,
            _ => return None,
        })
    }
}

impl fmt::Display for BridgeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "anisette helper failed during {:?}", self.stage())
    }
}

impl std::error::Error for BridgeError {}
