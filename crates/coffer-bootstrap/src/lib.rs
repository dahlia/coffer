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

//! Runtime acquisition of the Apple support libraries local anisette
//! generation needs on Linux.
//!
//! Generating anisette data locally, rather than asking a third-party anisette
//! server for it, requires two proprietary Apple shared objects.  Apple
//! publishes them only inside the Apple Music Android application archive.
//! They are not free software, Coffer must not commit or redistribute them, and
//! they are therefore fetched from Apple at runtime, once, and cached.
//!
//! This crate does that fetch and nothing else.  It does not load the
//! libraries, does not call into them, does not provision anisette and does not
//! touch an Apple Account.  It hands a caller a directory containing two files
//! that have passed every check described below.
//!
//! # Flow
//!
//! [`Bootstrap::ensure`] resolves the host architecture, takes a cross-process
//! lock, and returns an existing verified installation if there is one.  When
//! there is not, it downloads the archive from the single pinned Apple URL,
//! validates its structure, extracts exactly two entries, checks them, writes
//! them to a staging directory and publishes that directory with one rename.
//!
//! # What is verified, and what is not
//!
//! This matters more than the rest of this document, so it is stated plainly.
//!
//! **What Coffer checks.**
//!
//! - The archive is retrieved over HTTPS from
//!   [`APPLE_MUSIC_APK_URL`], an Apple-owned host,
//!   with the server certificate verified against Mozilla's root bundle rather
//!   than the system trust store, and with redirects refused outright.
//! - Every remote-controlled size is bounded before anything is allocated: the
//!   response body, the central directory, the entry count, each entry's
//!   compressed and uncompressed size, the sum of those, and the expansion
//!   ratio of anything inflated.
//! - The ZIP structure is validated, and encrypted, duplicate, symbolic-link,
//!   special (neither a regular file nor a directory) and path-traversing
//!   entries are refused for the whole archive, not just for the two entries
//!   extracted.
//! - Exactly two entries are extracted, named by an allowlist that no
//!   configuration can widen, and each is checked against the CRC-32 the
//!   archive declares.
//! - Each extracted file is an ELF shared object whose class, byte order and
//!   `e_machine` match the host architecture.
//! - The SHA-256 of the archive and of each installed file is recorded.  Each
//!   installed file's digest is recomputed every time the installation is
//!   loaded; the archive's is only compared against the recorded value, since
//!   the archive itself is a temporary file that is deleted once the two
//!   libraries have been extracted from it.
//!
//! **What Coffer does not check.**
//!
//! Coffer does **not** verify the archive's own APK signature, and therefore
//! does not verify that Apple signed the payload.  Implementing APK Signature
//! Scheme v2 verification with a pinned Apple signing certificate is the check
//! that would establish that, and it is not implemented here.
//!
//! The practical consequence: the trust anchor for these binaries is the TLS
//! connection to `apps.mzstatic.com` and the integrity of Apple's content
//! delivery network, plus everything structural in the list above.  An attacker
//! who could serve a different archive from that origin under a certificate a
//! Mozilla-trusted CA issued for that host would not be caught by this crate.
//! The recorded digests make such a substitution *visible* after the fact —
//! they do not prevent it, because Coffer has no pinned expected digest to
//! compare against on a first install.
//!
//! The structural checks are not nothing: they bound every allocation, keep
//! every byte outside the two allowlisted entries unread, and refuse anything
//! that is not a shared object for this machine.  But they are integrity and
//! shape checks, not an authenticity proof, and this crate does not claim
//! otherwise.
//!
//! # Where things live
//!
//! Three XDG base directories, for three different lifecycles.  The reasoning
//! is in the [`paths`] module documentation; the short version is that the
//! library payload is redownloadable and lives in `XDG_CACHE_HOME`, the pointer
//! to the active installation is small and durable and lives in
//! `XDG_STATE_HOME`, and anisette provisioning state is irreplaceable and lives
//! in `XDG_DATA_HOME` — where **this crate only reports the path and never
//! writes, reads or removes anything**, so that replacing the libraries can
//! never destroy an identity that cannot be regenerated offline.
//!
//! Because bootstrap removes its own staging directories recursively, two
//! layouts are refused outright rather than navigated carefully: one in which
//! the provisioning directory and a bootstrap-owned root contain one another,
//! and one in which a bootstrap-owned directory turns out to be a symbolic
//! link.
//!
//! # Concurrency, atomicity and failure
//!
//! Bootstrap is serialized across processes by an `flock` in `XDG_STATE_HOME`.
//! An installation becomes visible in one rename after every check has passed,
//! and the active pointer is updated after that.  A failed or interrupted
//! update therefore leaves any previous installation, and the pointer naming
//! it, exactly as they were.
//!
//! An install directory is named by the digest of the archive it came from, so
//! a directory that already carries the right name is reused rather than
//! rewritten — but only after its contents have been verified against their
//! recorded digests.  One whose files were damaged after they were written is
//! replaced instead of adopted.
//!
//! Offline, an existing verified installation is reused with no network access
//! at all.  With nothing to reuse and no network,
//! [`BootstrapError::NoInstallationAvailable`] is returned once: this crate
//! never loops, never sleeps and never retries on its own initiative.
//!
//! # Blocking, not asynchronous
//!
//! The downloader is blocking.  Bootstrap is one large, rare, sequential
//! download with no concurrency to exploit, and making it asynchronous would
//! impose an executor on every consumer.  A command-line tool calls
//! [`Bootstrap::ensure`] directly; a GTK application calls it on a worker
//! thread, which it must do for the filesystem work regardless.
//!
//! # Secrets
//!
//! Nothing here handles a secret.  There is no password, token, passcode or key
//! anywhere in this crate, and the metadata it writes contains only the
//! artifact URL, sanitized HTTP response headers, sizes, digests and the
//! resolved architecture.  Errors carry a stage and a safe cause and never a
//! filesystem path; see the [`error`] module documentation for why.

#![forbid(unsafe_code)]

pub mod arch;
pub mod archive;
mod bootstrap;
pub mod elf;
pub mod error;
pub mod http;
pub mod install;
pub mod limits;
pub mod metadata;
pub mod paths;
pub mod source;

#[cfg(test)]
mod synthetic;

pub use crate::arch::{Architecture, UnsupportedArchitecture};
pub use crate::archive::{ArchiveViolation, SupportLibrary};
pub use crate::bootstrap::{Bootstrap, InstalledLibraries};
pub use crate::elf::{ElfSummary, ElfViolation};
pub use crate::error::{BootstrapError, Stage};
pub use crate::http::AppleCdnSource;
pub use crate::install::LockMode;
pub use crate::limits::Limits;
pub use crate::metadata::{ActiveInstall, InstallMetadata};
pub use crate::paths::{BootstrapPaths, PathResolutionError};
pub use crate::source::{APPLE_MUSIC_APK_URL, ArtifactSource, FetchError, SourceUrl};
