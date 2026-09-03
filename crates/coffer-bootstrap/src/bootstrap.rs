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

//! The orchestration: reuse, download, verify, install, publish.
//!
//! [`Bootstrap`] is the only type in this crate that combines the network, the
//! filesystem and the archive reader, and it does so through
//! [`ArtifactSource`], so every path through it is reachable in a test with a
//! deterministic fake and a temporary directory.

use std::fs::{File, Permissions};
use std::io::{self, Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use sha2::{Digest, Sha256};

use crate::arch::Architecture;
use crate::archive::{Archive, SupportLibrary};
use crate::elf::{ElfSummary, validate_shared_object};
use crate::error::{BootstrapError, Stage};
use crate::install::{
    BootstrapLock, ExistingInstall, LockMode, StagedInstall, write_file_atomically,
};
use crate::limits::Limits;
use crate::metadata::{
    ACTIVE_INSTALL_SCHEMA, ActiveInstall, FileRecord, INSTALL_METADATA_FILE,
    INSTALL_METADATA_SCHEMA, InstallMetadata, PerformedCheck, SourceRecord,
};
use crate::paths::BootstrapPaths;
use crate::source::{ArtifactSource, ObservedArtifact, SourceUrl};

/// The number of leading hexadecimal digits of the archive digest that name an
/// install directory.
///
/// Sixty-four bits of a SHA-256 prefix: long enough that two artifacts will not
/// collide in practice, short enough that the directory name stays readable.
/// The full digest is recorded in the metadata and is what verification uses.
const INSTALL_ID_HEX_DIGITS: usize = 16;

/// The buffer size used while streaming the archive to disk.
const DOWNLOAD_CHUNK_BYTES: usize = 64 * 1024;

/// An installation of the Apple support libraries that has been verified.
///
/// Holding one of these means, at the moment it was produced: the install
/// directory exists, its metadata parsed at a schema this Coffer understands,
/// it is for this host's architecture, and both libraries are present with the
/// recorded length, the recorded SHA-256 and an ELF header for this
/// architecture.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InstalledLibraries {
    architecture: Architecture,
    directory: PathBuf,
    metadata: InstallMetadata,
}

impl InstalledLibraries {
    /// The directory to hand a loader as the library root.
    ///
    /// The two libraries sit under `lib/<abi>/` inside it, which is the layout
    /// the archive uses and the layout the Apple loader entry point expects.
    #[must_use]
    pub fn library_root(&self) -> &Path {
        &self.directory
    }

    /// The path of one of the two libraries.
    #[must_use]
    pub fn library_path(&self, library: SupportLibrary) -> PathBuf {
        self.directory
            .join(library.install_relative_path(self.architecture))
    }

    /// The architecture this installation is for.
    #[must_use]
    pub fn architecture(&self) -> Architecture {
        self.architecture
    }

    /// The installation's identifier, which is also its directory name.
    #[must_use]
    pub fn install_id(&self) -> &str {
        &self.metadata.install_id
    }

    /// The recorded provenance and verification metadata.
    #[must_use]
    pub fn metadata(&self) -> &InstallMetadata {
        &self.metadata
    }
}

/// Acquires, verifies and installs the Apple support libraries.
///
/// # Ownership and lifecycle
///
/// A `Bootstrap` owns nothing on disk.  It resolves paths, takes a lock for the
/// duration of a call, and releases it before returning.  Two `Bootstrap`
/// values in the same process, or in different processes, can be used
/// concurrently; the lock serializes the parts that must not overlap.
///
/// # What it never does
///
/// It never creates, reads or removes anything under
/// [`BootstrapPaths::provisioning_directory`], never contacts an Apple Account,
/// never provisions anisette, and never falls back to a source other than the
/// pinned artifact URL.
#[derive(Debug)]
pub struct Bootstrap<S> {
    paths: BootstrapPaths,
    source: S,
    limits: Limits,
    architecture: Architecture,
    lock_mode: LockMode,
}

impl<S: ArtifactSource> Bootstrap<S> {
    /// Builds a bootstrap for the host architecture.
    ///
    /// # Errors
    ///
    /// Returns [`BootstrapError::UnsupportedArchitecture`] when the host is not
    /// one of the architectures the artifact publishes libraries for.  Failing
    /// here rather than at download time means no request is made that could
    /// not have succeeded.
    pub fn new(paths: BootstrapPaths, source: S) -> Result<Self, BootstrapError> {
        Ok(Self::for_architecture(paths, source, Architecture::host()?))
    }

    /// Builds a bootstrap for an explicit architecture.
    ///
    /// Useful for tests and for tooling that inspects an installation made on
    /// another machine.  The resulting installation is still only usable on a
    /// host of that architecture; nothing here cross-compiles.
    #[must_use]
    pub fn for_architecture(paths: BootstrapPaths, source: S, architecture: Architecture) -> Self {
        Self {
            paths,
            source,
            limits: Limits::DEFAULT,
            architecture,
            lock_mode: LockMode::Wait,
        }
    }

    /// Replaces the bounds applied to the artifact.
    #[must_use]
    pub fn with_limits(mut self, limits: Limits) -> Self {
        self.limits = limits;
        self
    }

    /// Chooses what to do when another process holds the bootstrap lock.
    #[must_use]
    pub fn with_lock_mode(mut self, lock_mode: LockMode) -> Self {
        self.lock_mode = lock_mode;
        self
    }

    /// The architecture this bootstrap installs for.
    #[must_use]
    pub fn architecture(&self) -> Architecture {
        self.architecture
    }

    /// The resolved filesystem locations.
    #[must_use]
    pub fn paths(&self) -> &BootstrapPaths {
        &self.paths
    }

    /// The durable location for anisette provisioning state.
    ///
    /// Reported for the benefit of the component that owns provisioning.  This
    /// crate does not create it, write to it, read it or remove it, so calling
    /// this has no side effects and a library update can never disturb what
    /// lives there.
    #[must_use]
    pub fn provisioning_directory(&self) -> &Path {
        self.paths.provisioning_directory()
    }

    /// Returns the verified installation, if there is one.
    ///
    /// Performs no network access and takes no lock, so it is safe to call on a
    /// user interface thread that must not block on another process.
    ///
    /// # Errors
    ///
    /// Returns an I/O error when the cache or state directory exists but cannot
    /// be read.  An installation that is absent, stale, written at an unknown
    /// schema, or whose payload no longer matches its recorded digests is
    /// reported as `Ok(None)`: Coffer refuses to use it, but the payload is
    /// redownloadable, so the correct response is to bootstrap again rather
    /// than to fail.
    pub fn installed(&self) -> Result<Option<InstalledLibraries>, BootstrapError> {
        self.check_layout()?;
        self.load_installation()
    }

    /// Returns a verified installation, downloading one if there is none.
    ///
    /// An existing valid installation is reused without any network access, so
    /// an offline machine that has bootstrapped once keeps working.  When there
    /// is nothing to reuse and the artifact cannot be fetched, this returns
    /// [`BootstrapError::NoInstallationAvailable`] once.  It does not loop, does
    /// not sleep and does not retry; deciding when to try again is the caller's.
    ///
    /// # Errors
    ///
    /// See [`BootstrapError`].  Every failure leaves any pre-existing
    /// installation, and the pointer naming it, exactly as they were.
    pub fn ensure(&self) -> Result<InstalledLibraries, BootstrapError> {
        self.check_layout()?;
        let lock = BootstrapLock::acquire(&self.paths, self.lock_mode)?;
        lock.clean_staging(&self.paths)?;

        // Re-checked under the lock: another process may have installed the
        // libraries between the caller's decision to bootstrap and this point.
        if let Some(installed) = self.load_installation()? {
            return Ok(installed);
        }
        match self.install_under_lock() {
            Err(BootstrapError::Fetch(cause)) => {
                Err(BootstrapError::NoInstallationAvailable { cause })
            }
            other => other,
        }
    }

    /// Downloads and installs the artifact even when an installation exists.
    ///
    /// Used to pick up a new build of the artifact.  On failure the previous
    /// installation and the pointer naming it are untouched, so a failed update
    /// is a no-op rather than a regression: the payload is only renamed into
    /// place after every check has passed, and the pointer is only rewritten
    /// after that rename succeeded.
    ///
    /// Updating the libraries does not touch anisette provisioning state.  The
    /// new libraries are installed in their own directory beside the old ones,
    /// and nothing under [`Bootstrap::provisioning_directory`] is read or
    /// written.
    ///
    /// # Errors
    ///
    /// See [`BootstrapError`].
    pub fn install_latest(&self) -> Result<InstalledLibraries, BootstrapError> {
        self.check_layout()?;
        let lock = BootstrapLock::acquire(&self.paths, self.lock_mode)?;
        lock.clean_staging(&self.paths)?;
        self.install_under_lock()
    }

    /// Refuses a filesystem layout in which bootstrap's own cleanup could
    /// reach anisette provisioning state.
    ///
    /// Checked at the start of every entry point, before any directory is
    /// created, so an unusable configuration costs nothing rather than causing
    /// damage.
    fn check_layout(&self) -> Result<(), BootstrapError> {
        self.paths
            .check_separation()
            .map_err(|violation| BootstrapError::UnsafeLayout {
                stage: Stage::Preparing,
                violation,
            })
    }

    /// The download, verify, stage and publish sequence, with the lock held.
    fn install_under_lock(&self) -> Result<InstalledLibraries, BootstrapError> {
        let url = SourceUrl::apple_music_apk();
        let fetched = self.source.fetch(&url, &self.limits)?;
        let observed = fetched.observed;

        let staged_archive = self.stage_archive(fetched.body, &observed)?;
        let install_id = staged_archive.digest[..INSTALL_ID_HEX_DIGITS].to_owned();

        let mut archive = Archive::open(staged_archive.file, &self.limits)?;
        let mut payload = Vec::with_capacity(SupportLibrary::ALL.len());
        for library in SupportLibrary::ALL {
            let name = library.archive_entry_name(self.architecture);
            let bytes = archive.extract(&name, &self.limits)?;
            let summary = validate_shared_object(&bytes, self.architecture)
                .map_err(|violation| BootstrapError::Library { library, violation })?;
            // The archive reader already checked this against the value the
            // central directory declared; recording it makes a later change in
            // the artifact visible in a diff of two metadata documents.
            let crc32 = crc32fast::hash(&bytes);
            payload.push((library, name, bytes, summary, crc32));
        }

        let metadata = self.build_metadata(
            &install_id,
            &observed,
            &staged_archive.digest,
            staged_archive.received_length,
            &payload,
        );
        let encoded = serde_json::to_vec_pretty(&metadata).map_err(|_| BootstrapError::Io {
            stage: Stage::Staging,
            kind: io::ErrorKind::InvalidData,
        })?;

        let staged = StagedInstall::create(&self.paths)?;
        for (library, _, bytes, _, _) in &payload {
            staged.write(&library.install_relative_path(self.architecture), bytes)?;
        }
        staged.write(INSTALL_METADATA_FILE, &encoded)?;

        let target = self.paths.install_directory(self.architecture, &install_id);
        // A directory already carrying this name should hold the same payload,
        // because the name is a digest of the archive.  Trust that only after
        // checking it: an installation whose files were damaged after they were
        // written would otherwise be kept, and then returned as verified.
        let retained = if target.exists() {
            self.verify_install_directory(&target, &install_id, &staged_archive.digest)?
        } else {
            None
        };
        let existing = if retained.is_some() {
            ExistingInstall::Keep
        } else {
            ExistingInstall::Replace
        };
        let directory = staged.publish(&target, existing)?;
        // When the existing directory was kept, the metadata that describes
        // what is on disk is the one just read back from it, not the one built
        // from this fetch and then discarded with the staging directory.
        // Returning the latter would report a fetch time and response headers
        // that no file records.
        let metadata = retained.unwrap_or(metadata);

        self.publish_active_pointer(&install_id, &directory, &staged_archive.digest)?;

        Ok(InstalledLibraries {
            architecture: self.architecture,
            directory,
            metadata,
        })
    }

    /// Streams the response body into a temporary file beside the install root.
    ///
    /// The file is in the staging area rather than in memory: the artifact is
    /// over a hundred mebibytes and the archive reader needs random access.  It
    /// is removed when the returned value is dropped, so an interrupted
    /// download leaves nothing behind.
    fn stage_archive(
        &self,
        mut body: Box<dyn Read + Send>,
        observed: &ObservedArtifact,
    ) -> Result<StagedArchive, BootstrapError> {
        crate::install::create_directory(self.paths.cache_root(), Stage::Downloading)?;
        let staging_root = self.paths.staging_root();
        crate::install::create_directory(&staging_root, Stage::Downloading)?;
        let mut temporary = tempfile::Builder::new()
            .prefix("archive-")
            .permissions(Permissions::from_mode(0o600))
            .tempfile_in(&staging_root)
            .map_err(|error| BootstrapError::io(Stage::Downloading, &error))?;

        let mut hasher = Sha256::new();
        let mut received: u64 = 0;
        let mut buffer = vec![0u8; DOWNLOAD_CHUNK_BYTES];
        loop {
            let read = body
                .read(&mut buffer)
                .map_err(|error| BootstrapError::io(Stage::Downloading, &error))?;
            if read == 0 {
                break;
            }
            received += read as u64;
            if received > self.limits.max_archive_bytes {
                return Err(BootstrapError::ArchiveTooLarge {
                    limit: self.limits.max_archive_bytes,
                });
            }
            if received > observed.declared_length {
                return Err(BootstrapError::ArchiveLengthMismatch {
                    declared: observed.declared_length,
                    received,
                });
            }
            hasher.update(&buffer[..read]);
            temporary
                .write_all(&buffer[..read])
                .map_err(|error| BootstrapError::io(Stage::Downloading, &error))?;
        }
        if received != observed.declared_length {
            return Err(BootstrapError::ArchiveLengthMismatch {
                declared: observed.declared_length,
                received,
            });
        }
        temporary
            .flush()
            .map_err(|error| BootstrapError::io(Stage::Downloading, &error))?;

        let file = temporary
            .reopen()
            .map_err(|error| BootstrapError::io(Stage::Downloading, &error))?;
        Ok(StagedArchive {
            _temporary: temporary,
            file,
            digest: to_hex(&hasher.finalize()),
            received_length: received,
        })
    }

    /// Assembles the metadata document for a verified payload.
    fn build_metadata(
        &self,
        install_id: &str,
        observed: &ObservedArtifact,
        archive_digest: &str,
        received_length: u64,
        payload: &[(SupportLibrary, String, Vec<u8>, ElfSummary, u32)],
    ) -> InstallMetadata {
        let files = payload
            .iter()
            .map(|(library, _, bytes, summary, crc32)| {
                (
                    library.install_relative_path(self.architecture),
                    FileRecord {
                        length: bytes.len() as u64,
                        sha256: to_hex(&Sha256::digest(bytes)),
                        crc32: format!("{crc32:08x}"),
                        elf_machine: summary.machine,
                        elf_class: summary.class,
                    },
                )
            })
            .collect();
        InstallMetadata {
            schema: INSTALL_METADATA_SCHEMA,
            install_id: install_id.to_owned(),
            rust_target_arch: self.architecture.rust_target_arch().to_owned(),
            android_abi: self.architecture.android_abi().to_owned(),
            source: SourceRecord {
                url: SourceUrl::apple_music_apk().as_str().to_owned(),
                declared_length: observed.declared_length,
                received_length,
                archive_sha256: archive_digest.to_owned(),
                last_modified: observed.last_modified.clone(),
                etag: observed.etag.clone(),
                apple_version_number: observed.apple_version_number.clone(),
                content_type: observed.content_type.clone(),
                fetched_at_unix_seconds: unix_seconds(),
            },
            files,
            performed_checks: vec![
                PerformedCheck::HttpsPinnedEndpoint,
                PerformedCheck::ArchiveStructure,
                PerformedCheck::EntryChecksum,
                PerformedCheck::ElfHeader,
            ],
        }
    }

    /// Points the active install file at a published installation.
    fn publish_active_pointer(
        &self,
        install_id: &str,
        directory: &Path,
        archive_digest: &str,
    ) -> Result<(), BootstrapError> {
        let active = ActiveInstall {
            schema: ACTIVE_INSTALL_SCHEMA,
            install_id: install_id.to_owned(),
            rust_target_arch: self.architecture.rust_target_arch().to_owned(),
            android_abi: self.architecture.android_abi().to_owned(),
            install_directory: directory.to_path_buf(),
            archive_sha256: archive_digest.to_owned(),
            activated_at_unix_seconds: unix_seconds(),
        };
        let encoded = serde_json::to_vec_pretty(&active).map_err(|_| BootstrapError::Io {
            stage: Stage::Publishing,
            kind: io::ErrorKind::InvalidData,
        })?;
        crate::install::create_directory(self.paths.state_root(), Stage::Publishing)?;
        write_file_atomically(
            &self.paths.active_install_file(),
            &encoded,
            Stage::Publishing,
        )
    }

    /// Reads and revalidates the active installation.
    fn load_installation(&self) -> Result<Option<InstalledLibraries>, BootstrapError> {
        let Some(active) = read_document::<ActiveInstall>(
            &self.paths.active_install_file(),
            self.limits.max_metadata_bytes,
        )?
        else {
            return Ok(None);
        };
        if active.schema != ACTIVE_INSTALL_SCHEMA
            || active.rust_target_arch != self.architecture.rust_target_arch()
            || active.android_abi != self.architecture.android_abi()
        {
            return Ok(None);
        }

        let directory = active.install_directory;
        let Some(metadata) =
            self.verify_install_directory(&directory, &active.install_id, &active.archive_sha256)?
        else {
            return Ok(None);
        };

        Ok(Some(InstalledLibraries {
            architecture: self.architecture,
            directory,
            metadata,
        }))
    }

    /// Revalidates an install directory against what it claims to be.
    ///
    /// Returns `Ok(None)` for anything Coffer will not use: missing or
    /// unparsable metadata, a schema this Coffer does not know, metadata for
    /// another architecture, another install identifier or another archive, a
    /// missing library, a library whose length or SHA-256 no longer matches the
    /// record, or a library that is no longer an ELF shared object for this
    /// architecture.
    ///
    /// The digests are recomputed on every call rather than trusted from a
    /// previous one, which is what makes an installation damaged after it was
    /// written visible instead of silently reused.
    ///
    /// # Errors
    ///
    /// Returns an I/O error when the directory exists but cannot be read.
    fn verify_install_directory(
        &self,
        directory: &Path,
        expected_install_id: &str,
        expected_archive_sha256: &str,
    ) -> Result<Option<InstallMetadata>, BootstrapError> {
        let Some(metadata) = read_document::<InstallMetadata>(
            &directory.join(INSTALL_METADATA_FILE),
            self.limits.max_metadata_bytes,
        )?
        else {
            return Ok(None);
        };
        if metadata.schema != INSTALL_METADATA_SCHEMA
            || metadata.install_id != expected_install_id
            || metadata.rust_target_arch != self.architecture.rust_target_arch()
            || metadata.android_abi != self.architecture.android_abi()
            || metadata.source.archive_sha256 != expected_archive_sha256
        {
            return Ok(None);
        }

        for library in SupportLibrary::ALL {
            let relative = library.install_relative_path(self.architecture);
            let Some(record) = metadata.files.get(&relative) else {
                return Ok(None);
            };
            // The recorded length is read from a file that may be damaged or
            // written by someone else, so it bounds nothing on its own.  Refuse
            // a record that claims more than a library could ever be before
            // using it as an allocation limit.
            if record.length > self.limits.max_entry_uncompressed_bytes {
                return Ok(None);
            }
            let Some(bytes) = read_bounded(&directory.join(&relative), record.length)? else {
                return Ok(None);
            };
            if bytes.len() as u64 != record.length
                || to_hex(&Sha256::digest(&bytes)) != record.sha256
            {
                return Ok(None);
            }
            if validate_shared_object(&bytes, self.architecture).is_err() {
                return Ok(None);
            }
        }
        Ok(Some(metadata))
    }
}

/// The downloaded archive, in a temporary file that is removed on drop.
struct StagedArchive {
    /// Kept alive so that the file is removed when this value is dropped.
    _temporary: tempfile::NamedTempFile,
    /// A separate handle used for the random access the archive reader needs.
    file: File,
    /// The archive's SHA-256, lowercase hexadecimal.
    digest: String,
    /// The number of bytes received.
    received_length: u64,
}

/// Reads and parses a JSON document, bounded by `limit`.
///
/// A missing document, a document over the limit, and a document that does not
/// parse are all reported as `Ok(None)`: Coffer will not use what it cannot
/// verify, and every document this reads describes a payload that can be
/// downloaded again.  A genuine I/O failure is reported as an error.
fn read_document<T: serde::de::DeserializeOwned>(
    path: &Path,
    limit: u64,
) -> Result<Option<T>, BootstrapError> {
    let Some(bytes) = read_bounded(path, limit)? else {
        return Ok(None);
    };
    Ok(serde_json::from_slice(&bytes).ok())
}

/// Reads a file, refusing to allocate more than `limit` bytes for it.
fn read_bounded(path: &Path, limit: u64) -> Result<Option<Vec<u8>>, BootstrapError> {
    let mut file = match File::open(path) {
        Ok(file) => file,
        // `NotADirectory` is the damaged-cache case: something that is not a
        // directory occupies the install directory's name, so the file inside
        // it cannot exist.  Reporting it as absent lets the next bootstrap
        // replace the damage instead of failing on it forever.
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::NotFound | io::ErrorKind::NotADirectory
            ) =>
        {
            return Ok(None);
        }
        Err(error) => return Err(BootstrapError::io(Stage::LoadingInstallation, &error)),
    };
    let mut bytes = Vec::new();
    // One byte over the limit, so an oversized file is detected rather than
    // silently truncated into something that might still parse.
    let read = Read::by_ref(&mut file)
        .take(limit.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|error| BootstrapError::io(Stage::LoadingInstallation, &error))?;
    if read as u64 > limit {
        return Ok(None);
    }
    Ok(Some(bytes))
}

/// Renders bytes as lowercase hexadecimal.
fn to_hex(bytes: &[u8]) -> String {
    let mut hex = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use core::fmt::Write as _;
        // Writing to a `String` cannot fail; the result is discarded rather
        // than unwrapped so that this helper cannot panic.
        let _ = write!(hex, "{byte:02x}");
    }
    hex
}

/// The current time in seconds since the Unix epoch, or zero if the clock is
/// before it.
///
/// A wrong timestamp is a cosmetic problem in a provenance record, so this
/// records zero rather than failing a bootstrap over a misconfigured clock.
fn unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::archive::ArchiveViolation;
    use crate::source::FetchError;
    use crate::synthetic::{
        FakeResponse, FakeSource, SyntheticArchive, SyntheticEntry, synthetic_shared_object,
    };
    use std::fs;
    use tempfile::TempDir;

    /// The architecture every test bootstraps for, so that the suite behaves
    /// the same on an x86-64 and an AArch64 developer machine.
    const TEST_ARCHITECTURE: Architecture = Architecture::X86_64;

    fn good_archive() -> Vec<u8> {
        SyntheticArchive::apple_music_like(TEST_ARCHITECTURE).build()
    }

    fn bootstrap_with(root: &TempDir, source: FakeSource) -> Bootstrap<FakeSource> {
        Bootstrap::for_architecture(
            BootstrapPaths::rooted_at(root.path()),
            source,
            TEST_ARCHITECTURE,
        )
    }

    #[test]
    fn installs_both_libraries_from_a_well_formed_archive() {
        let root = TempDir::new().expect("temporary root");
        let bootstrap = bootstrap_with(&root, FakeSource::serving(good_archive()));

        let installed = bootstrap.ensure().expect("bootstrap must succeed");

        for library in SupportLibrary::ALL {
            let path = installed.library_path(library);
            let bytes = fs::read(&path).expect("installed library must be readable");
            assert_eq!(&bytes[..4], &[0x7f, b'E', b'L', b'F']);
            assert!(
                path.starts_with(installed.library_root()),
                "libraries must live inside the install root"
            );
        }
        assert_eq!(installed.architecture(), TEST_ARCHITECTURE);
        assert_eq!(installed.install_id().len(), INSTALL_ID_HEX_DIGITS);
        assert!(
            installed
                .library_root()
                .starts_with(bootstrap.paths().versions_root()),
            "the install must be published under the versions root"
        );
    }

    #[test]
    fn records_provenance_without_recording_a_secret() {
        let root = TempDir::new().expect("temporary root");
        let archive = good_archive();
        let bootstrap = bootstrap_with(&root, FakeSource::serving(archive.clone()));
        let installed = bootstrap.ensure().expect("bootstrap");

        let metadata = installed.metadata();
        assert_eq!(metadata.schema, INSTALL_METADATA_SCHEMA);
        assert_eq!(metadata.source.url, crate::source::APPLE_MUSIC_APK_URL);
        assert_eq!(metadata.source.declared_length, archive.len() as u64);
        assert_eq!(metadata.source.received_length, archive.len() as u64);
        assert_eq!(metadata.source.archive_sha256.len(), 64);
        assert!(
            metadata
                .source
                .archive_sha256
                .starts_with(installed.install_id())
        );
        assert_eq!(metadata.android_abi, TEST_ARCHITECTURE.android_abi());
        assert_eq!(
            metadata.rust_target_arch,
            TEST_ARCHITECTURE.rust_target_arch()
        );
        assert_eq!(metadata.files.len(), SupportLibrary::ALL.len());
        for library in SupportLibrary::ALL {
            let record = metadata
                .files
                .get(&library.install_relative_path(TEST_ARCHITECTURE))
                .expect("both libraries must be recorded");
            assert_eq!(record.sha256.len(), 64);
            assert_eq!(record.crc32.len(), 8);
            assert_eq!(record.elf_machine, TEST_ARCHITECTURE.elf_machine());
        }
        for check in [
            PerformedCheck::HttpsPinnedEndpoint,
            PerformedCheck::ArchiveStructure,
            PerformedCheck::EntryChecksum,
            PerformedCheck::ElfHeader,
        ] {
            assert!(metadata.performed_checks.contains(&check));
        }
    }

    #[test]
    fn install_metadata_survives_a_round_trip_through_disk() {
        let root = TempDir::new().expect("temporary root");
        let bootstrap = bootstrap_with(&root, FakeSource::serving(good_archive()));
        let installed = bootstrap.ensure().expect("bootstrap");

        let on_disk: InstallMetadata = serde_json::from_slice(
            &fs::read(installed.library_root().join(INSTALL_METADATA_FILE)).expect("read"),
        )
        .expect("parse");
        assert_eq!(&on_disk, installed.metadata());

        let active: ActiveInstall = serde_json::from_slice(
            &fs::read(bootstrap.paths().active_install_file()).expect("read"),
        )
        .expect("parse");
        assert_eq!(active.schema, ACTIVE_INSTALL_SCHEMA);
        assert_eq!(active.install_id, installed.install_id());
        assert_eq!(&active.install_directory, installed.library_root());

        // Reloading from disk must reproduce the same installation.
        let reloaded = bootstrap
            .installed()
            .expect("load")
            .expect("an installation must be found");
        assert_eq!(reloaded, installed);
    }

    #[test]
    fn reuses_an_existing_installation_without_touching_the_network() {
        let root = TempDir::new().expect("temporary root");
        let paths = BootstrapPaths::rooted_at(root.path());

        let first = Bootstrap::for_architecture(
            paths.clone(),
            FakeSource::serving(good_archive()),
            TEST_ARCHITECTURE,
        );
        let installed = first.ensure().expect("first bootstrap");
        assert_eq!(first.source.calls(), 1);

        // A second process, now offline.
        let offline = Bootstrap::for_architecture(paths, FakeSource::offline(), TEST_ARCHITECTURE);
        let reused = offline.ensure().expect("an offline reuse must succeed");
        assert_eq!(reused, installed);
        assert_eq!(
            offline.source.calls(),
            0,
            "reuse must not reach for the network at all"
        );
    }

    #[test]
    fn reports_the_offline_case_once_when_there_is_nothing_to_reuse() {
        let root = TempDir::new().expect("temporary root");
        let bootstrap = bootstrap_with(&root, FakeSource::offline());

        let error = bootstrap
            .ensure()
            .expect_err("no installation is available");
        assert_eq!(
            error,
            BootstrapError::NoInstallationAvailable {
                cause: FetchError::Unreachable
            }
        );
        assert_eq!(
            bootstrap.source.calls(),
            1,
            "bootstrap must not retry an unreachable endpoint on its own initiative"
        );
        assert!(bootstrap.installed().expect("load").is_none());
    }

    #[test]
    fn a_failed_update_leaves_the_existing_installation_and_pointer_untouched() {
        let root = TempDir::new().expect("temporary root");
        let paths = BootstrapPaths::rooted_at(root.path());

        let good = Bootstrap::for_architecture(
            paths.clone(),
            FakeSource::serving(good_archive()),
            TEST_ARCHITECTURE,
        );
        let installed = good.ensure().expect("first bootstrap");
        let pointer_before = fs::read(paths.active_install_file()).expect("read pointer");

        // Every way an update can fail after a valid install already exists.
        let failures: Vec<(FakeSource, &str)> = vec![
            (FakeSource::offline(), "unreachable endpoint"),
            (
                FakeSource::new(vec![FakeResponse::Interrupted {
                    prefix: good_archive()[..64].to_vec(),
                    declared: good_archive().len() as u64,
                }]),
                "interrupted transfer",
            ),
            (
                FakeSource::serving(
                    SyntheticArchive::apple_music_like(TEST_ARCHITECTURE)
                        .without_entry(
                            &SupportLibrary::CoreAdi.archive_entry_name(TEST_ARCHITECTURE),
                        )
                        .build(),
                ),
                "archive missing a required entry",
            ),
            (
                FakeSource::serving(
                    SyntheticArchive::apple_music_like(TEST_ARCHITECTURE)
                        .with_replaced_entry(
                            &SupportLibrary::CoreAdi.archive_entry_name(TEST_ARCHITECTURE),
                            b"not an ELF object".to_vec(),
                        )
                        .build(),
                ),
                "archive entry that is not a shared object",
            ),
        ];

        for (source, description) in failures {
            let updating = Bootstrap::for_architecture(paths.clone(), source, TEST_ARCHITECTURE);
            updating
                .install_latest()
                .expect_err(&format!("{description} must fail"));

            assert_eq!(
                fs::read(paths.active_install_file()).expect("read pointer"),
                pointer_before,
                "{description} rewrote the active pointer"
            );
            let still_there = updating
                .installed()
                .expect("load")
                .expect("the previous installation must survive");
            assert_eq!(still_there, installed, "{description} damaged the install");
            assert_no_staging_left(&paths);
        }
    }

    #[test]
    fn a_failure_at_the_publishing_stage_leaves_the_pointer_naming_the_old_install() {
        // Every other failure case aborts before anything is staged.  This one
        // fails at the rename itself, which is where the ordering guarantee
        // that matters lives: the payload is renamed into place before the
        // pointer is rewritten, so a failed rename must leave both untouched.
        let root = TempDir::new().expect("temporary root");
        let paths = BootstrapPaths::rooted_at(root.path());
        let first = Bootstrap::for_architecture(
            paths.clone(),
            FakeSource::serving(good_archive()),
            TEST_ARCHITECTURE,
        );
        let installed = first.ensure().expect("first bootstrap");
        let pointer_before = fs::read(paths.active_install_file()).expect("read pointer");

        // Make the architecture directory unwritable so the publish rename
        // fails.  `create_directory` only widens nothing and only tightens a
        // group- or other-accessible directory, so 0500 survives its check.
        let architecture_root = paths.architecture_root(TEST_ARCHITECTURE);
        let original = fs::metadata(&architecture_root)
            .expect("metadata")
            .permissions();
        fs::set_permissions(&architecture_root, fs::Permissions::from_mode(0o500))
            .expect("restrict");
        // Root ignores those permissions, and so does any environment that
        // grants `CAP_DAC_OVERRIDE`.  Probe rather than assume.
        if fs::create_dir(architecture_root.join(".probe")).is_ok() {
            fs::remove_dir(architecture_root.join(".probe")).expect("remove probe");
            fs::set_permissions(&architecture_root, original).expect("restore");
            return;
        }

        let updating = Bootstrap::for_architecture(
            paths.clone(),
            FakeSource::serving(
                SyntheticArchive::apple_music_like(TEST_ARCHITECTURE)
                    .with_replaced_entry(
                        &SupportLibrary::CoreAdi.archive_entry_name(TEST_ARCHITECTURE),
                        synthetic_shared_object(TEST_ARCHITECTURE, 3_333),
                    )
                    .build(),
            ),
            TEST_ARCHITECTURE,
        );
        let error = updating.install_latest().expect_err("the rename must fail");
        assert_eq!(error.stage(), Stage::Publishing);

        fs::set_permissions(&architecture_root, original).expect("restore");
        assert_eq!(
            fs::read(paths.active_install_file()).expect("read pointer"),
            pointer_before,
            "a failed publish must not rewrite the active pointer"
        );
        assert_eq!(
            updating
                .installed()
                .expect("load")
                .expect("the previous installation must survive"),
            installed
        );
        assert_no_staging_left(&paths);
    }

    #[test]
    fn an_interrupted_transfer_publishes_nothing_and_leaves_no_staging_behind() {
        let root = TempDir::new().expect("temporary root");
        let archive = good_archive();
        let bootstrap = bootstrap_with(
            &root,
            FakeSource::new(vec![FakeResponse::Interrupted {
                prefix: archive[..archive.len() / 2].to_vec(),
                declared: archive.len() as u64,
            }]),
        );

        let error = bootstrap
            .ensure()
            .expect_err("an interrupted transfer must fail");
        assert_eq!(error.stage(), Stage::Downloading);
        assert!(bootstrap.installed().expect("load").is_none());
        assert!(
            !bootstrap.paths().versions_root().exists(),
            "nothing may be published from an interrupted transfer"
        );
        assert_no_staging_left(bootstrap.paths());
    }

    #[test]
    fn refuses_a_body_that_disagrees_with_the_declared_length() {
        let root = TempDir::new().expect("temporary root");
        let archive = good_archive();
        let declared = archive.len() as u64;
        let bootstrap = bootstrap_with(
            &root,
            FakeSource::new(vec![FakeResponse::MisdeclaredLength {
                body: archive[..archive.len() - 10].to_vec(),
                declared,
            }]),
        );
        assert_eq!(
            bootstrap.ensure().expect_err("short body"),
            BootstrapError::ArchiveLengthMismatch {
                declared,
                received: declared - 10,
            }
        );
    }

    #[test]
    fn refuses_a_body_that_grows_past_the_archive_limit_while_streaming() {
        let root = TempDir::new().expect("temporary root");
        let limit = 1024u64;
        let bootstrap = bootstrap_with(
            &root,
            FakeSource::new(vec![FakeResponse::MisdeclaredLength {
                body: vec![0u8; usize::try_from(limit).unwrap() + 64],
                declared: limit,
            }]),
        )
        .with_limits(Limits {
            max_archive_bytes: limit,
            ..Limits::DEFAULT
        });
        assert_eq!(
            bootstrap.ensure().expect_err("oversized body"),
            BootstrapError::ArchiveTooLarge { limit }
        );
    }

    #[test]
    fn refuses_an_artifact_whose_declared_length_is_over_the_limit() {
        let root = TempDir::new().expect("temporary root");
        let bootstrap =
            bootstrap_with(&root, FakeSource::serving(good_archive())).with_limits(Limits {
                max_archive_bytes: 16,
                ..Limits::DEFAULT
            });
        let error = bootstrap.ensure().expect_err("oversized artifact");
        assert!(
            matches!(
                error,
                BootstrapError::NoInstallationAvailable {
                    cause: FetchError::DeclaredLengthTooLarge { limit: 16, .. }
                }
            ),
            "unexpected error: {error:?}"
        );
    }

    #[test]
    fn refuses_an_archive_that_is_missing_a_required_library() {
        for library in SupportLibrary::ALL {
            let root = TempDir::new().expect("temporary root");
            let name = library.archive_entry_name(TEST_ARCHITECTURE);
            let bootstrap = bootstrap_with(
                &root,
                FakeSource::serving(
                    SyntheticArchive::apple_music_like(TEST_ARCHITECTURE)
                        .without_entry(&name)
                        .build(),
                ),
            );
            assert_eq!(
                bootstrap.ensure().expect_err("missing library"),
                BootstrapError::Archive(ArchiveViolation::MissingRequiredEntry { name })
            );
        }
    }

    #[test]
    fn refuses_a_library_built_for_another_machine() {
        let root = TempDir::new().expect("temporary root");
        let other = Architecture::Aarch64;
        let bootstrap = bootstrap_with(
            &root,
            FakeSource::serving(
                SyntheticArchive::apple_music_like(TEST_ARCHITECTURE)
                    .with_replaced_entry(
                        &SupportLibrary::StoreServicesCore.archive_entry_name(TEST_ARCHITECTURE),
                        synthetic_shared_object(other, 256),
                    )
                    .build(),
            ),
        );
        assert_eq!(
            bootstrap.ensure().expect_err("wrong machine"),
            BootstrapError::Library {
                library: SupportLibrary::StoreServicesCore,
                violation: crate::elf::ElfViolation::MachineMismatch {
                    found: other.elf_machine(),
                    expected: TEST_ARCHITECTURE.elf_machine(),
                },
            }
        );
    }

    #[test]
    fn refuses_an_archive_whose_entry_data_was_corrupted_in_transit() {
        let root = TempDir::new().expect("temporary root");
        let mut archive = SyntheticArchive::new()
            .with_entry(SyntheticEntry::stored(
                &SupportLibrary::StoreServicesCore.archive_entry_name(TEST_ARCHITECTURE),
                synthetic_shared_object(TEST_ARCHITECTURE, 128),
            ))
            .with_entry(SyntheticEntry::stored(
                &SupportLibrary::CoreAdi.archive_entry_name(TEST_ARCHITECTURE),
                synthetic_shared_object(TEST_ARCHITECTURE, 128),
            ))
            .build();
        // Flip a byte in the first entry's stored data.
        let data_offset = 30
            + SupportLibrary::StoreServicesCore
                .archive_entry_name(TEST_ARCHITECTURE)
                .len()
            + 8;
        archive[data_offset] ^= 0xff;

        let bootstrap = bootstrap_with(&root, FakeSource::serving(archive));
        assert_eq!(
            bootstrap.ensure().expect_err("corrupt entry"),
            BootstrapError::Archive(ArchiveViolation::ChecksumMismatch)
        );
    }

    #[test]
    fn refuses_an_archive_carrying_a_hostile_entry_anywhere_in_it() {
        let hostile = [
            (
                SyntheticEntry::stored("../escape.so", b"x".to_vec()),
                ArchiveViolation::EntryNameRejected,
            ),
            (
                SyntheticEntry::stored("link.so", b"/etc/passwd".to_vec()).into_symlink(),
                ArchiveViolation::SymlinkEntry,
            ),
            (
                SyntheticEntry::stored("secret.bin", b"x".to_vec()).with_flags(1),
                ArchiveViolation::EncryptedEntry,
            ),
        ];
        for (entry, expected) in hostile {
            let root = TempDir::new().expect("temporary root");
            let bootstrap = bootstrap_with(
                &root,
                FakeSource::serving(
                    SyntheticArchive::apple_music_like(TEST_ARCHITECTURE)
                        .with_entry(entry)
                        .build(),
                ),
            );
            assert_eq!(
                bootstrap.ensure().expect_err("hostile entry"),
                BootstrapError::Archive(expected)
            );
            assert!(!bootstrap.paths().versions_root().exists());
        }
    }

    #[test]
    fn a_corrupted_installation_is_not_used_and_is_replaced_on_the_next_bootstrap() {
        let root = TempDir::new().expect("temporary root");
        let paths = BootstrapPaths::rooted_at(root.path());
        let bootstrap = Bootstrap::for_architecture(
            paths.clone(),
            FakeSource::serving(good_archive()),
            TEST_ARCHITECTURE,
        );
        let installed = bootstrap.ensure().expect("bootstrap");

        let victim = installed.library_path(SupportLibrary::CoreAdi);
        let mut bytes = fs::read(&victim).expect("read");
        bytes[64] ^= 0xff;
        fs::write(&victim, &bytes).expect("tamper");

        assert!(
            bootstrap.installed().expect("load").is_none(),
            "an installation whose payload no longer matches its digest must not be used"
        );

        // Bootstrapping again must repair the payload, not adopt the corrupt
        // directory merely because it carries the right content-addressed name.
        let repaired = bootstrap.ensure().expect("re-bootstrap");
        assert_eq!(repaired.install_id(), installed.install_id());
        assert_eq!(repaired.library_root(), installed.library_root());
        // The payload is byte-identical again; the provenance record is not,
        // because this installation really was fetched a second time.
        assert_eq!(repaired.metadata().files, installed.metadata().files);
        assert_ne!(
            fs::read(&victim).expect("read"),
            bytes,
            "a corrupt installation must be replaced, not kept"
        );
        assert_eq!(
            bootstrap
                .installed()
                .expect("load")
                .expect("the repaired installation must verify"),
            repaired,
            "what is on disk must match what the repair reported"
        );
        assert_no_staging_left(&paths);
    }

    #[test]
    fn reinstalling_the_same_archive_reports_the_metadata_that_is_on_disk() {
        let root = TempDir::new().expect("temporary root");
        let paths = BootstrapPaths::rooted_at(root.path());
        let first = Bootstrap::for_architecture(
            paths.clone(),
            FakeSource::serving(good_archive()),
            TEST_ARCHITECTURE,
        );
        let installed = first.ensure().expect("first bootstrap");

        // The same archive again: the existing directory is verified and kept,
        // so the metadata reported must be the one the kept directory holds,
        // not the one this fetch built and then discarded.
        let again = Bootstrap::for_architecture(
            paths.clone(),
            FakeSource::serving(good_archive()),
            TEST_ARCHITECTURE,
        );
        let reinstalled = again.install_latest().expect("reinstall");

        assert_eq!(reinstalled, installed);
        let on_disk: InstallMetadata = serde_json::from_slice(
            &fs::read(reinstalled.library_root().join(INSTALL_METADATA_FILE)).expect("read"),
        )
        .expect("parse");
        assert_eq!(
            reinstalled.metadata(),
            &on_disk,
            "the reported metadata must be what the install directory records"
        );
    }

    #[test]
    fn replacing_a_corrupt_install_never_leaves_the_target_absent() {
        let root = TempDir::new().expect("temporary root");
        let paths = BootstrapPaths::rooted_at(root.path());
        let bootstrap = Bootstrap::for_architecture(
            paths.clone(),
            FakeSource::serving(good_archive()),
            TEST_ARCHITECTURE,
        );
        let installed = bootstrap.ensure().expect("bootstrap");
        let target = installed.library_root().to_path_buf();

        // Damage the payload so the next run takes the replace path.
        let victim = installed.library_path(SupportLibrary::StoreServicesCore);
        let mut bytes = fs::read(&victim).expect("read");
        bytes[70] ^= 0xff;
        fs::write(&victim, &bytes).expect("tamper");

        let replaced = bootstrap.ensure().expect("replace");
        assert_eq!(replaced.install_id(), installed.install_id());
        assert_eq!(replaced.metadata().files, installed.metadata().files);
        assert!(target.exists(), "the target must exist after a replacement");
        assert_eq!(
            replaced.library_root(),
            target,
            "a replacement must publish to the same content-addressed path"
        );
        assert_no_staging_left(&paths);
    }

    #[test]
    fn refuses_a_layout_where_cleanup_could_reach_provisioning_state() {
        let root = TempDir::new().expect("temporary root");
        // The provisioning directory nested inside the staging root, which
        // `clean_staging` empties at the start of every run.
        let paths = BootstrapPaths::new(
            &root
                .path()
                .join(".cache")
                .join("coffer")
                .join("apple-support-libraries")
                .join("staging"),
            &root.path().join(".cache"),
            &root.path().join(".local").join("state"),
        );
        let bootstrap = Bootstrap::for_architecture(
            paths.clone(),
            FakeSource::serving(good_archive()),
            TEST_ARCHITECTURE,
        );
        let expected = BootstrapError::UnsafeLayout {
            stage: Stage::Preparing,
            violation: crate::paths::LayoutViolation::ProvisioningOverlap,
        };
        assert_eq!(bootstrap.installed().expect_err("unsafe layout"), expected);
        assert_eq!(bootstrap.ensure().expect_err("unsafe layout"), expected);
        assert_eq!(
            bootstrap.install_latest().expect_err("unsafe layout"),
            expected
        );
        assert_eq!(
            bootstrap.source.calls(),
            0,
            "an unusable layout must be refused before anything is fetched"
        );
        assert!(
            !paths.state_root().exists() && !paths.versions_root().exists(),
            "an unusable layout must be refused before anything is created"
        );
    }

    #[test]
    fn refuses_to_clean_a_staging_root_that_is_a_symbolic_link() {
        let root = TempDir::new().expect("temporary root");
        let paths = BootstrapPaths::rooted_at(root.path());

        // Stand in for provisioning state that a recursive clean must not reach.
        let decoy = root.path().join("decoy");
        fs::create_dir_all(decoy.join("anisette")).expect("create decoy");
        fs::write(decoy.join("anisette").join("identifier"), b"state").expect("write decoy");

        crate::install::create_directory(paths.cache_root(), Stage::Staging).expect("create cache");
        std::os::unix::fs::symlink(&decoy, paths.staging_root()).expect("symlink staging root");

        let bootstrap = Bootstrap::for_architecture(
            paths.clone(),
            FakeSource::serving(good_archive()),
            TEST_ARCHITECTURE,
        );
        assert_eq!(
            bootstrap.ensure().expect_err("symlinked staging root"),
            BootstrapError::UnsafeLayout {
                stage: Stage::Staging,
                violation: crate::paths::LayoutViolation::SymbolicLink,
            }
        );
        assert!(
            decoy.join("anisette").join("identifier").exists(),
            "cleanup must not follow a symbolic link out of the staging area"
        );
        assert_eq!(bootstrap.source.calls(), 0);
    }

    #[test]
    fn an_installation_for_another_architecture_is_not_used() {
        let root = TempDir::new().expect("temporary root");
        let paths = BootstrapPaths::rooted_at(root.path());
        Bootstrap::for_architecture(
            paths.clone(),
            FakeSource::serving(good_archive()),
            TEST_ARCHITECTURE,
        )
        .ensure()
        .expect("bootstrap");

        let other =
            Bootstrap::for_architecture(paths, FakeSource::offline(), Architecture::Aarch64);
        assert!(
            other.installed().expect("load").is_none(),
            "an installation made for another architecture must not be adopted"
        );
    }

    #[test]
    fn a_second_bootstrap_can_decline_to_wait_for_the_lock() {
        let root = TempDir::new().expect("temporary root");
        let paths = BootstrapPaths::rooted_at(root.path());
        let holder = crate::install::BootstrapLock::acquire(&paths, LockMode::Wait).expect("lock");

        let bootstrap = Bootstrap::for_architecture(
            paths.clone(),
            FakeSource::serving(good_archive()),
            TEST_ARCHITECTURE,
        )
        .with_lock_mode(LockMode::Fail);
        assert_eq!(bootstrap.ensure().expect_err("busy"), BootstrapError::Busy);
        assert_eq!(
            bootstrap.source.calls(),
            0,
            "a bootstrap that could not take the lock must not download"
        );

        drop(holder);
        bootstrap
            .ensure()
            .expect("bootstrap must succeed once the lock is free");
    }

    #[test]
    fn concurrent_bootstraps_produce_one_installation() {
        let root = TempDir::new().expect("temporary root");
        let paths = BootstrapPaths::rooted_at(root.path());
        let archive = good_archive();

        let results: Vec<_> = std::thread::scope(|scope| {
            let handles: Vec<_> = (0..4)
                .map(|_| {
                    let paths = paths.clone();
                    let archive = archive.clone();
                    scope.spawn(move || {
                        Bootstrap::for_architecture(
                            paths,
                            FakeSource::serving(archive),
                            TEST_ARCHITECTURE,
                        )
                        .ensure()
                    })
                })
                .collect();
            handles
                .into_iter()
                .map(|handle| handle.join().expect("thread"))
                .collect()
        });

        let installs: Vec<_> = results
            .into_iter()
            .map(|result| result.expect("every concurrent bootstrap must succeed"))
            .collect();
        let first = &installs[0];
        for install in &installs {
            assert_eq!(install, first, "concurrent bootstraps disagreed");
        }
        let published: Vec<_> = fs::read_dir(paths.architecture_root(TEST_ARCHITECTURE))
            .expect("read versions")
            .filter_map(Result::ok)
            .collect();
        assert_eq!(published.len(), 1, "exactly one installation must exist");
        assert_no_staging_left(&paths);
    }

    #[test]
    fn bootstrap_never_creates_or_removes_the_provisioning_directory() {
        let root = TempDir::new().expect("temporary root");
        let paths = BootstrapPaths::rooted_at(root.path());
        let bootstrap = Bootstrap::for_architecture(
            paths.clone(),
            FakeSource::serving(good_archive()),
            TEST_ARCHITECTURE,
        );
        assert!(!bootstrap.provisioning_directory().exists());
        let original = bootstrap.ensure().expect("bootstrap");
        assert!(
            !bootstrap.provisioning_directory().exists(),
            "bootstrap must not create the provisioning directory"
        );

        // Provisioning state written by another component must survive an
        // update of the libraries.
        fs::create_dir_all(paths.provisioning_directory()).expect("create provisioning directory");
        let sentinel = paths.provisioning_directory().join("identifier");
        fs::write(&sentinel, b"synthetic provisioning state").expect("write sentinel");

        let updating = Bootstrap::for_architecture(
            paths.clone(),
            FakeSource::serving(
                SyntheticArchive::apple_music_like(TEST_ARCHITECTURE)
                    .with_replaced_entry(
                        &SupportLibrary::CoreAdi.archive_entry_name(TEST_ARCHITECTURE),
                        synthetic_shared_object(TEST_ARCHITECTURE, 9_000),
                    )
                    .build(),
            ),
            TEST_ARCHITECTURE,
        );
        let updated = updating.install_latest().expect("update");
        assert_eq!(
            fs::read(&sentinel).expect("read sentinel"),
            b"synthetic provisioning state",
            "a library update must not disturb provisioning state"
        );
        assert_ne!(
            updated.install_id(),
            original.install_id(),
            "a different archive must produce a different installation"
        );
        assert!(
            fs::read_dir(paths.provisioning_directory())
                .expect("the provisioning directory must still exist")
                .count()
                == 1,
            "a library update must not add to or remove from the provisioning directory"
        );
    }

    #[test]
    fn an_update_installs_beside_the_previous_libraries_rather_than_over_them() {
        let root = TempDir::new().expect("temporary root");
        let paths = BootstrapPaths::rooted_at(root.path());
        let first = Bootstrap::for_architecture(
            paths.clone(),
            FakeSource::serving(good_archive()),
            TEST_ARCHITECTURE,
        );
        let old = first.ensure().expect("first bootstrap");

        let second = Bootstrap::for_architecture(
            paths.clone(),
            FakeSource::serving(
                SyntheticArchive::apple_music_like(TEST_ARCHITECTURE)
                    .with_replaced_entry(
                        &SupportLibrary::StoreServicesCore.archive_entry_name(TEST_ARCHITECTURE),
                        synthetic_shared_object(TEST_ARCHITECTURE, 7_777),
                    )
                    .build(),
            ),
            TEST_ARCHITECTURE,
        );
        let new = second.install_latest().expect("update");

        assert_ne!(new.install_id(), old.install_id());
        assert!(
            old.library_root().exists(),
            "the previous installation must remain on disk"
        );
        assert_eq!(
            second
                .installed()
                .expect("load")
                .expect("an installation must be active")
                .install_id(),
            new.install_id(),
            "the pointer must name the new installation"
        );
    }

    #[test]
    fn a_staging_directory_lives_beside_the_publish_target() {
        let root = TempDir::new().expect("temporary root");
        let paths = BootstrapPaths::rooted_at(root.path());
        let staged = StagedInstall::create(&paths).expect("stage");
        assert!(
            staged.path().starts_with(paths.staging_root()),
            "staging must happen inside the staging root so the publish is a rename"
        );
    }

    #[test]
    fn a_bootstrap_for_the_host_resolves_the_host_architecture() {
        let root = TempDir::new().expect("temporary root");
        let bootstrap = Bootstrap::new(
            BootstrapPaths::rooted_at(root.path()),
            FakeSource::offline(),
        )
        .expect("the test host must be a supported architecture");
        assert_eq!(
            bootstrap.architecture().rust_target_arch(),
            std::env::consts::ARCH
        );
    }

    fn assert_no_staging_left(paths: &BootstrapPaths) {
        let staging = paths.staging_root();
        if !staging.exists() {
            return;
        }
        let remaining: Vec<_> = fs::read_dir(&staging)
            .expect("read staging root")
            .filter_map(Result::ok)
            .map(|entry| entry.file_name())
            .collect();
        assert!(
            remaining.is_empty(),
            "staging directory was left behind: {remaining:?}"
        );
    }
}
