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

//! Sandboxed local loader and ABI bridge for Apple's anisette libraries.
//!
//! The main Coffer process never maps proprietary Apple code.  It supplies an
//! [`InstalledLibraries`](coffer_bootstrap::InstalledLibraries) capability to
//! [`HelperClient`], which starts the dedicated `coffer-anisette-helper`
//! process and exchanges bounded, byte-exact frames.  The
//! helper revalidates the complete observed ELF ABI policy before mapping the
//! images with `elf_loader` 0.17.0 and constructors deferred.
//!
//! No API in this crate performs provisioning HTTP, Apple Account
//! authentication, or two-factor authentication.  Typed operations cover the
//! complete declared ADI surface.  Each ordinary operation uses one helper;
//! provisioning start and exactly one finish/cancel frame stay in one helper
//! so the opaque native session handle never crosses IPC.  Failures are
//! terminal and are never retried.
//!
//! [`ProvisioningStore`] binds the helper to
//! [`BootstrapPaths::provisioning_directory`](coffer_bootstrap::BootstrapPaths::provisioning_directory).
//! The parent passes a pre-opened private staging descriptor, and successful
//! state is fsynced and atomically published as a new immutable generation.
//!
//! # Provenance
//!
//! The eleven ADI export names and function declarations in [`abi`] are taken
//! from SideStore's MPL-2.0 `apple-private-apis` revision
//! `03beb1aa42991ccdad6214dee77e72282bef461f`.  ELF structure and relocation
//! rules come from the System V ABI, x86-64 psABI, and AArch64 ELF ABI.  Bionic
//! layouts and shim declarations come from public AOSP Bionic headers.  No
//! source from `android-loader`, `sysv64`, rustpush, or Sank6 is used.

pub mod abi;
mod bridge;
mod client;
mod error;
mod ipc;
mod sandbox;
mod state;
mod types;

pub use bridge::{AdiOwnedBuffer, PropertyKey};
pub use client::{HelperClient, ProvisioningSession, SmokeResult, VerifiedLibraryPaths};
pub use error::{BridgeError, Stage};
pub use state::{DeviceIdentifiers, ProvisioningStore};
pub use types::{
    AndroidId, DirectoryServiceId, OtpMaterial, SecretBytes, SecretString, SynchronizeMaterial,
};

/// Runs one helper invocation on stdin/stdout.
///
/// This is public only so the package's dedicated helper binary can stay a
/// very small wrapper.  Application code should use [`HelperClient`].
///
/// # Errors
///
/// Returns a stage-safe error response when framing, validation, sandboxing,
/// mapping, or the offline ADI call fails.
#[doc(hidden)]
pub fn helper_main() -> Result<(), BridgeError> {
    bridge::serve_one()
}
