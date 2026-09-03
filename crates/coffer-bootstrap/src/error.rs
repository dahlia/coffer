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

//! The error type bootstrap reports, and the stage vocabulary it uses.
//!
//! # What an error may say
//!
//! An error names the [`Stage`] that failed and a cause that is safe to show
//! anywhere: a size, a limit, an HTTP status, an ELF field, an
//! [`io::ErrorKind`].  That is enough for a user to know what to do and for a
//! maintainer to know where to look.
//!
//! # What an error may not say
//!
//! No variant carries a filesystem path, a home directory, an Apple Account
//! identifier, a token, provisioning material or a fragment of the downloaded
//! archive.  I/O failures are reduced to their [`io::ErrorKind`] precisely
//! because [`io::Error`]'s own `Display` includes the path it failed on, and
//! those paths contain the user's home directory.  This is a deliberate loss of
//! diagnostic detail in exchange for an error that is safe to put in a log, a
//! bug report or a graphical dialog without review.

use core::fmt;
use std::io;

use crate::arch::UnsupportedArchitecture;
use crate::archive::{ArchiveViolation, SupportLibrary};
use crate::elf::ElfViolation;
use crate::paths::{LayoutViolation, PathResolutionError};
use crate::signature::SignatureViolation;
use crate::source::FetchError;

/// The stage of bootstrap an error came from.
///
/// Stages are ordered as bootstrap runs them, so a caller can report progress
/// and a maintainer can tell how far a failing run got.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[non_exhaustive]
pub enum Stage {
    /// Resolving the host architecture and the XDG directories.
    Preparing,
    /// Taking the cross-process bootstrap lock.
    Locking,
    /// Reading an existing installation and its metadata.
    LoadingInstallation,
    /// Fetching the archive from Apple.
    Downloading,
    /// Verifying the APK signature and pinned Apple signer.
    VerifyingSignature,
    /// Reading and validating the archive.
    ReadingArchive,
    /// Writing the staged installation.
    Staging,
    /// Publishing the staged installation and updating the active pointer.
    Publishing,
}

impl fmt::Display for Stage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Stage::Preparing => "preparing",
            Stage::Locking => "locking",
            Stage::LoadingInstallation => "loading the installed libraries",
            Stage::Downloading => "downloading the archive",
            Stage::VerifyingSignature => "verifying the APK signature",
            Stage::ReadingArchive => "reading the archive",
            Stage::Staging => "staging the installation",
            Stage::Publishing => "publishing the installation",
        };
        f.write_str(name)
    }
}

/// Why bootstrap could not produce a usable installation.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum BootstrapError {
    /// The host CPU architecture has no published support libraries.
    UnsupportedArchitecture(UnsupportedArchitecture),
    /// The XDG base directories could not be resolved.
    PathResolution(PathResolutionError),
    /// Another process holds the bootstrap lock, and the caller asked not to
    /// wait.
    Busy,
    /// Fetching the archive failed.
    Fetch(FetchError),
    /// The response body exceeded [`Limits::max_archive_bytes`].
    ///
    /// [`Limits::max_archive_bytes`]: crate::limits::Limits::max_archive_bytes
    ArchiveTooLarge {
        /// The configured ceiling.
        limit: u64,
    },
    /// The response body length disagreed with the declared `Content-Length`.
    ArchiveLengthMismatch {
        /// The length the server declared.
        declared: u64,
        /// The length actually received.
        received: u64,
    },
    /// The APK signature or pinned signer verification failed.
    Signature(SignatureViolation),
    /// The archive is not the artifact Coffer expects.
    Archive(ArchiveViolation),
    /// An extracted library is not an acceptable shared object.
    Library {
        /// Which library failed.
        library: SupportLibrary,
        /// How it failed.
        violation: ElfViolation,
    },
    /// There is no usable installation and the archive could not be fetched.
    ///
    /// This is the offline case: bootstrap will not loop, will not retry on its
    /// own initiative, and will not fall back to another source.  The caller
    /// decides whether and when to try again.
    NoInstallationAvailable {
        /// Why the fetch that would have produced one failed.
        cause: FetchError,
    },
    /// The filesystem layout is one bootstrap refuses to manage.
    ///
    /// Raised before any directory is created or removed, so a layout Coffer
    /// will not work in costs nothing rather than causing damage.
    UnsafeLayout {
        /// The stage the layout was checked in.
        stage: Stage,
        /// What is wrong with the layout.
        violation: LayoutViolation,
    },
    /// An I/O operation failed.
    Io {
        /// The stage the failure happened in.
        stage: Stage,
        /// The kind of failure, without the path it happened on.
        kind: io::ErrorKind,
    },
}

impl BootstrapError {
    /// The stage this error came from.
    #[must_use]
    pub fn stage(&self) -> Stage {
        match self {
            BootstrapError::UnsupportedArchitecture(_) | BootstrapError::PathResolution(_) => {
                Stage::Preparing
            }
            BootstrapError::Busy => Stage::Locking,
            BootstrapError::Fetch(_)
            | BootstrapError::ArchiveTooLarge { .. }
            | BootstrapError::ArchiveLengthMismatch { .. }
            | BootstrapError::NoInstallationAvailable { .. } => Stage::Downloading,
            BootstrapError::Signature(_) => Stage::VerifyingSignature,
            BootstrapError::Archive(_) | BootstrapError::Library { .. } => Stage::ReadingArchive,
            BootstrapError::UnsafeLayout { stage, .. } | BootstrapError::Io { stage, .. } => *stage,
        }
    }

    /// Builds an I/O error for a stage without carrying the failing path.
    pub(crate) fn io(stage: Stage, error: &io::Error) -> Self {
        BootstrapError::Io {
            stage,
            kind: error.kind(),
        }
    }
}

impl fmt::Display for BootstrapError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Apple support library bootstrap failed while {}: ",
            self.stage()
        )?;
        match self {
            BootstrapError::UnsupportedArchitecture(error) => write!(f, "{error}"),
            BootstrapError::PathResolution(error) => write!(f, "{error}"),
            BootstrapError::Busy => f.write_str("another process is already running bootstrap"),
            BootstrapError::Fetch(error) => write!(f, "{error}"),
            BootstrapError::ArchiveTooLarge { limit } => write!(
                f,
                "the archive exceeded the {limit}-byte limit while being received"
            ),
            BootstrapError::ArchiveLengthMismatch { declared, received } => write!(
                f,
                "the archive declared {declared} bytes but {received} arrived"
            ),
            BootstrapError::Signature(violation) => write!(f, "{violation}"),
            BootstrapError::Archive(violation) => write!(f, "{violation}"),
            BootstrapError::Library { library, violation } => {
                write!(f, "{} is unusable: {violation}", library.file_name())
            }
            BootstrapError::NoInstallationAvailable { cause } => write!(
                f,
                "no support libraries are installed and none could be fetched: {cause}"
            ),
            BootstrapError::UnsafeLayout { violation, .. } => write!(f, "{violation}"),
            BootstrapError::Io { kind, .. } => write!(f, "{kind}"),
        }
    }
}

impl std::error::Error for BootstrapError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            BootstrapError::UnsupportedArchitecture(error) => Some(error),
            BootstrapError::PathResolution(error) => Some(error),
            BootstrapError::Fetch(error)
            | BootstrapError::NoInstallationAvailable { cause: error } => Some(error),
            BootstrapError::Signature(violation) => Some(violation),
            BootstrapError::Archive(violation) => Some(violation),
            BootstrapError::Library { violation, .. } => Some(violation),
            BootstrapError::UnsafeLayout { violation, .. } => Some(violation),
            BootstrapError::Busy
            | BootstrapError::ArchiveTooLarge { .. }
            | BootstrapError::ArchiveLengthMismatch { .. }
            | BootstrapError::Io { .. } => None,
        }
    }
}

impl From<UnsupportedArchitecture> for BootstrapError {
    fn from(error: UnsupportedArchitecture) -> Self {
        BootstrapError::UnsupportedArchitecture(error)
    }
}

impl From<PathResolutionError> for BootstrapError {
    fn from(error: PathResolutionError) -> Self {
        BootstrapError::PathResolution(error)
    }
}

impl From<ArchiveViolation> for BootstrapError {
    fn from(violation: ArchiveViolation) -> Self {
        BootstrapError::Archive(violation)
    }
}

impl From<SignatureViolation> for BootstrapError {
    fn from(violation: SignatureViolation) -> Self {
        BootstrapError::Signature(violation)
    }
}

impl From<FetchError> for BootstrapError {
    fn from(error: FetchError) -> Self {
        BootstrapError::Fetch(error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arch::Architecture;

    /// Renders every variant, so a new one cannot be added without a decision
    /// about what it is allowed to say.
    fn every_variant() -> Vec<BootstrapError> {
        vec![
            BootstrapError::UnsupportedArchitecture(
                Architecture::from_rust_target_arch("riscv64").unwrap_err(),
            ),
            BootstrapError::PathResolution(PathResolutionError::NoHomeDirectory),
            BootstrapError::Busy,
            BootstrapError::Fetch(FetchError::Redirected),
            BootstrapError::ArchiveTooLarge { limit: 1024 },
            BootstrapError::ArchiveLengthMismatch {
                declared: 10,
                received: 9,
            },
            BootstrapError::Signature(SignatureViolation::SignatureInvalid),
            BootstrapError::Archive(ArchiveViolation::DuplicateEntry),
            BootstrapError::Library {
                library: SupportLibrary::CoreAdi,
                violation: ElfViolation::NotAnElfObject,
            },
            BootstrapError::NoInstallationAvailable {
                cause: FetchError::Unreachable,
            },
            BootstrapError::Io {
                stage: Stage::Publishing,
                kind: io::ErrorKind::PermissionDenied,
            },
            BootstrapError::Io {
                stage: Stage::LoadingInstallation,
                kind: io::ErrorKind::InvalidData,
            },
            BootstrapError::UnsafeLayout {
                stage: Stage::Preparing,
                violation: LayoutViolation::ProvisioningOverlap,
            },
            BootstrapError::UnsafeLayout {
                stage: Stage::Staging,
                violation: LayoutViolation::SymbolicLink,
            },
            BootstrapError::Archive(ArchiveViolation::MissingRequiredEntry {
                name: SupportLibrary::StoreServicesCore.archive_entry_name(Architecture::X86_64),
            }),
        ]
    }

    #[test]
    fn no_error_message_leaks_a_filesystem_path_or_a_secret() {
        for error in every_variant() {
            let rendered = format!("{error}");
            let debug = format!("{error:?}");
            for text in [&rendered, &debug] {
                // An archive-relative entry name Coffer itself constructed is
                // allowed; anything that looks like a location on this machine
                // is not.
                for forbidden in [
                    "/home/",
                    "/root/",
                    "/.cache",
                    "/.local",
                    "/tmp/",
                    "/var/",
                    "$HOME",
                    "token",
                    "password",
                    "passcode",
                    "adi.pb",
                    "identifier",
                ] {
                    assert!(
                        !text.contains(forbidden),
                        "error text must not mention {forbidden}: {text}"
                    );
                }
                assert!(
                    !text.starts_with('/'),
                    "error text must not start with an absolute path: {text}"
                );
            }
        }
    }

    #[test]
    fn every_error_names_the_stage_it_came_from() {
        for error in every_variant() {
            let rendered = format!("{error}");
            assert!(
                rendered.contains(&error.stage().to_string()),
                "error text must name its stage: {rendered}"
            );
        }
    }

    #[test]
    fn an_io_error_keeps_its_kind_but_drops_its_path() {
        let underlying = io::Error::new(
            io::ErrorKind::PermissionDenied,
            "/home/example/.cache/coffer/apple-support-libraries/versions",
        );
        let error = BootstrapError::io(Stage::Staging, &underlying);
        assert_eq!(
            error,
            BootstrapError::Io {
                stage: Stage::Staging,
                kind: io::ErrorKind::PermissionDenied,
            }
        );
        assert!(!format!("{error}").contains("/home/example"));
        assert!(!format!("{error:?}").contains("/home/example"));
    }

    #[test]
    fn stages_are_ordered_as_bootstrap_runs_them() {
        assert!(Stage::Preparing < Stage::Locking);
        assert!(Stage::Locking < Stage::Downloading);
        assert!(Stage::Downloading < Stage::VerifyingSignature);
        assert!(Stage::VerifyingSignature < Stage::ReadingArchive);
        assert!(Stage::ReadingArchive < Stage::Staging);
        assert!(Stage::Staging < Stage::Publishing);
    }
}
