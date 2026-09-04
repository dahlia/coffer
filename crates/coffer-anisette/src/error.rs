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
    /// Setting ADI's fixed-width Android identifier.
    SetAndroidId,
    /// Querying provisioned state.
    QueryProvisioned,
    /// Starting a native provisioning session.
    StartProvisioning,
    /// Ending a native provisioning session.
    EndProvisioning,
    /// Destroying a native provisioning session.
    DestroyProvisioning,
    /// Requesting a native one-time password.
    Otp,
    /// Synchronizing native provisioning material.
    Synchronize,
    /// Erasing native provisioning state.
    EraseProvisioning,
    /// Validating, staging, or publishing durable provisioning state.
    State,
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
    /// The Android-identifier setter returned a nonzero status.
    SetAndroidIdFailed,
    /// Native provisioning start returned a nonzero status.
    StartProvisioningFailed,
    /// Native provisioning end returned a nonzero status.
    EndProvisioningFailed,
    /// Native provisioning-session destruction returned a nonzero status.
    DestroyProvisioningFailed,
    /// Native OTP generation returned a nonzero status.
    OtpFailed,
    /// Native synchronization returned a nonzero status.
    SynchronizeFailed,
    /// Native provisioning erasure returned a nonzero status.
    EraseProvisioningFailed,
    /// Durable provisioning state is absent.
    StateMissing,
    /// Durable provisioning state is malformed or violates its bounds.
    StateCorrupt,
    /// Durable provisioning state could not be staged or published.
    StateFailed,
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
            Self::SetAndroidIdFailed => Stage::SetAndroidId,
            Self::StartProvisioningFailed => Stage::StartProvisioning,
            Self::EndProvisioningFailed => Stage::EndProvisioning,
            Self::DestroyProvisioningFailed => Stage::DestroyProvisioning,
            Self::OtpFailed => Stage::Otp,
            Self::SynchronizeFailed => Stage::Synchronize,
            Self::EraseProvisioningFailed => Stage::EraseProvisioning,
            Self::StateMissing | Self::StateCorrupt | Self::StateFailed => Stage::State,
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
            Self::SetAndroidIdFailed => 14,
            Self::StartProvisioningFailed => 15,
            Self::EndProvisioningFailed => 16,
            Self::DestroyProvisioningFailed => 17,
            Self::OtpFailed => 18,
            Self::SynchronizeFailed => 19,
            Self::EraseProvisioningFailed => 20,
            Self::StateMissing => 21,
            Self::StateCorrupt => 22,
            Self::StateFailed => 23,
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
            14 => Self::SetAndroidIdFailed,
            15 => Self::StartProvisioningFailed,
            16 => Self::EndProvisioningFailed,
            17 => Self::DestroyProvisioningFailed,
            18 => Self::OtpFailed,
            19 => Self::SynchronizeFailed,
            20 => Self::EraseProvisioningFailed,
            21 => Self::StateMissing,
            22 => Self::StateCorrupt,
            23 => Self::StateFailed,
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
