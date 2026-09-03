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

//! Locking, staging, and the atomic publish.
//!
//! # Concurrency
//!
//! Coffer runs as several processes on one machine: a graphical application, a
//! command-line tool, a browser native-messaging host.  Any of them may start
//! bootstrap.  An exclusive `flock` on a file in `XDG_STATE_HOME` serializes
//! them, so exactly one process downloads and publishes while the others wait
//! or are told the work is already under way.  The lock is taken before the
//! "is something already installed?" check, so the check is not a race.
//!
//! # Atomicity
//!
//! An install becomes visible in exactly one step.  Everything is written into
//! a staging directory on the same filesystem as the publish target, every file
//! and directory is flushed, and only then is the staging directory renamed
//! into place.  A crash at any earlier point leaves an orphan staging directory
//! and nothing else; the next lock holder removes it.
//!
//! The active pointer is updated after the payload is published, and by the
//! same write-then-rename dance.  The ordering matters: if publishing the
//! payload fails, the pointer still names the previous installation, and if
//! updating the pointer fails, the previous installation is still named.  A
//! failed update therefore never leaves Coffer worse off than before it
//! started.
//!
//! # Permissions
//!
//! Directories are created 0700 and files 0600, from creation rather than by
//! adjusting them afterwards, so there is no window in which another user on
//! the machine can read or replace a partially written library.
//!
//! # What is never touched
//!
//! Nothing in this module writes to, reads from, or removes
//! [`BootstrapPaths::provisioning_directory`].  Replacing the support libraries
//! must not be able to destroy provisioning state.
//!
//! Two guards keep that true even under a hostile or misconfigured filesystem
//! layout, because this module removes directories recursively.  A
//! bootstrap-owned directory that is a symbolic link is refused rather than
//! followed, and the caller checks with
//! [`BootstrapPaths::check_separation`] that no bootstrap-owned root and the
//! provisioning directory contain one another.

use std::fs::{self, File, Permissions};
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use rustix::fs::{CWD, FlockOperation, RenameFlags, flock, renameat_with};
use rustix::io::Errno;

use crate::error::{BootstrapError, Stage};
use crate::paths::{BootstrapPaths, LayoutViolation};

/// The mode bootstrap-owned directories are created with.
const DIRECTORY_MODE: u32 = 0o700;

/// The mode bootstrap-owned files are created with.
const FILE_MODE: u32 = 0o600;

/// How to behave when another process already holds the bootstrap lock.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum LockMode {
    /// Wait for the other process to finish.
    ///
    /// The right choice for a user-initiated bootstrap: the other process is
    /// almost certainly downloading the same archive, and waiting for it is
    /// cheaper and safer than downloading it twice.
    #[default]
    Wait,
    /// Report [`BootstrapError::Busy`] immediately.
    ///
    /// The right choice for a background check that must not block.
    Fail,
}

/// An exclusive, cross-process lock over the bootstrap state.
///
/// Held for the whole of a bootstrap run and released when dropped, including
/// on unwind and on process exit, because the lock lives on the open file
/// description rather than in the file's contents.
#[derive(Debug)]
pub(crate) struct BootstrapLock {
    /// Kept open for as long as the lock is held; closing it releases the lock.
    file: File,
}

impl BootstrapLock {
    /// Takes the lock, creating the lock file and its directory if needed.
    ///
    /// # Errors
    ///
    /// Returns [`BootstrapError::Busy`] when `mode` is [`LockMode::Fail`] and
    /// another process holds the lock, and an I/O error when the lock file
    /// cannot be created or locked.
    pub(crate) fn acquire(paths: &BootstrapPaths, mode: LockMode) -> Result<Self, BootstrapError> {
        create_directory(paths.state_root(), Stage::Locking)?;
        let path = paths.lock_file();
        let file = fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .mode(FILE_MODE)
            .open(&path)
            .map_err(|error| BootstrapError::io(Stage::Locking, &error))?;
        let operation = match mode {
            LockMode::Wait => FlockOperation::LockExclusive,
            LockMode::Fail => FlockOperation::NonBlockingLockExclusive,
        };
        match flock(&file, operation) {
            Ok(()) => Ok(Self { file }),
            Err(errno) if mode == LockMode::Fail && errno == rustix::io::Errno::WOULDBLOCK => {
                Err(BootstrapError::Busy)
            }
            Err(errno) => Err(BootstrapError::Io {
                stage: Stage::Locking,
                kind: std::io::Error::from(errno).kind(),
            }),
        }
    }

    /// Removes staging directories left behind by an interrupted run.
    ///
    /// Safe only while the lock is held, which is why it is a method here: no
    /// other process can be writing into the staging area at the time.
    pub(crate) fn clean_staging(&self, paths: &BootstrapPaths) -> Result<(), BootstrapError> {
        let staging = paths.staging_root();
        // `read_dir` follows a symbolic link, so a link standing in for the
        // staging root would send the recursive removal below into whatever it
        // points at.  Refuse before enumerating anything.
        match fs::symlink_metadata(&staging) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(BootstrapError::UnsafeLayout {
                    stage: Stage::Staging,
                    violation: LayoutViolation::SymbolicLink,
                });
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(BootstrapError::io(Stage::Staging, &error)),
        }
        // `DirEntry::file_type` does not follow symbolic links, so an entry
        // that is one is unlinked rather than followed.
        match fs::read_dir(&staging) {
            Ok(entries) => {
                for entry in entries {
                    let entry =
                        entry.map_err(|error| BootstrapError::io(Stage::Staging, &error))?;
                    let path = entry.path();
                    let removed = if entry
                        .file_type()
                        .map_err(|error| BootstrapError::io(Stage::Staging, &error))?
                        .is_dir()
                    {
                        fs::remove_dir_all(&path)
                    } else {
                        fs::remove_file(&path)
                    };
                    removed.map_err(|error| BootstrapError::io(Stage::Staging, &error))?;
                }
                Ok(())
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(BootstrapError::io(Stage::Staging, &error)),
        }
    }
}

impl Drop for BootstrapLock {
    fn drop(&mut self) {
        // Closing the file releases the lock, so an explicit unlock is not
        // required.  Doing it anyway makes the release point obvious and does
        // not change behavior if it fails.
        let _ = flock(&self.file, FlockOperation::Unlock);
    }
}

/// Creates a directory and every missing parent with restrictive permissions.
///
/// The mode is given to [`fs::DirBuilder`] rather than applied afterwards, so
/// it covers every directory the call creates, not just the leaf.  That matters
/// under a permissive umask: `create_dir_all` would otherwise leave an
/// intermediate directory world-writable, and another local user who can write
/// there can rename the cache or state root aside and substitute a
/// self-consistent installation of their own.
///
/// A directory that already exists is tightened if it is group- or
/// other-accessible, for the same reason: these are directories Coffer owns,
/// and one left permissive by an older version or by something else is a way
/// in.  Files under them are 0600, but the directory permissions are what stop
/// an entry being replaced wholesale.
///
/// # Errors
///
/// Returns [`LayoutViolation::SymbolicLink`] when the path already exists as a
/// symbolic link.  Bootstrap recursively removes staging directories, so a
/// symbolic link standing in for one of its own directories would redirect
/// that removal outside the tree Coffer owns.  Refusing is cheap and the
/// failure it prevents is not recoverable.
pub(crate) fn create_directory(path: &Path, stage: Stage) -> Result<(), BootstrapError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            return Err(BootstrapError::UnsafeLayout {
                stage,
                violation: LayoutViolation::SymbolicLink,
            });
        }
        Ok(metadata) if metadata.is_dir() => {
            if metadata.permissions().mode() & 0o077 != 0 {
                fs::set_permissions(path, Permissions::from_mode(DIRECTORY_MODE))
                    .map_err(|error| BootstrapError::io(stage, &error))?;
            }
            return Ok(());
        }
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(BootstrapError::io(stage, &error)),
    }
    fs::DirBuilder::new()
        .recursive(true)
        .mode(DIRECTORY_MODE)
        .create(path)
        .map_err(|error| BootstrapError::io(stage, &error))?;
    // `recursive(true)` succeeds if the leaf already existed, in which case the
    // mode above was not applied to it.
    fs::set_permissions(path, Permissions::from_mode(DIRECTORY_MODE))
        .map_err(|error| BootstrapError::io(stage, &error))
}

/// Flushes a directory entry so that a rename into it survives a crash.
pub(crate) fn sync_directory(path: &Path, stage: Stage) -> Result<(), BootstrapError> {
    let directory = File::open(path).map_err(|error| BootstrapError::io(stage, &error))?;
    directory
        .sync_all()
        .map_err(|error| BootstrapError::io(stage, &error))
}

/// Flushes `leaf` and every directory between it and `root`, inclusive.
///
/// Creating `a/b/c` writes an entry into `a` and into `a/b` as well as creating
/// `a/b/c`.  Flushing only the deepest directory leaves those entries in the
/// page cache, so a crash can leave a published tree missing an intermediate
/// level.  `leaf` must be `root` or below it; a `leaf` outside `root` flushes
/// `leaf` alone rather than walking to the filesystem root.
pub(crate) fn sync_directory_chain(
    root: &Path,
    leaf: &Path,
    stage: Stage,
) -> Result<(), BootstrapError> {
    let mut current = leaf;
    loop {
        sync_directory(current, stage)?;
        if current == root {
            return Ok(());
        }
        match current.parent() {
            Some(parent) if parent.starts_with(root) => current = parent,
            _ => return Ok(()),
        }
    }
}

/// Writes `contents` to `path` by writing a temporary file beside it and
/// renaming it into place.
///
/// The temporary file is created in the destination directory so the rename
/// never crosses a filesystem, is created with [`FILE_MODE`] rather than being
/// chmodded afterwards, and is flushed before the rename.  The directory is
/// flushed after it.
pub(crate) fn write_file_atomically(
    path: &Path,
    contents: &[u8],
    stage: Stage,
) -> Result<(), BootstrapError> {
    let directory = path.parent().ok_or(BootstrapError::Io {
        stage,
        kind: std::io::ErrorKind::InvalidInput,
    })?;
    let mut temporary = tempfile::Builder::new()
        .prefix(".partial-")
        .permissions(Permissions::from_mode(FILE_MODE))
        .tempfile_in(directory)
        .map_err(|error| BootstrapError::io(stage, &error))?;
    temporary
        .write_all(contents)
        .map_err(|error| BootstrapError::io(stage, &error))?;
    temporary
        .as_file()
        .sync_all()
        .map_err(|error| BootstrapError::io(stage, &error))?;
    temporary
        .persist(path)
        .map_err(|error| BootstrapError::io(stage, &error.error))?;
    sync_directory(directory, stage)
}

/// A staging directory that is removed unless it is published.
#[derive(Debug)]
pub(crate) struct StagedInstall {
    directory: tempfile::TempDir,
    /// The outermost directory bootstrap owns, and therefore how far up the
    /// tree a durability flush has to walk.
    cache_root: PathBuf,
}

impl StagedInstall {
    /// Creates a staging directory beside the publish target.
    pub(crate) fn create(paths: &BootstrapPaths) -> Result<Self, BootstrapError> {
        create_directory(paths.cache_root(), Stage::Staging)?;
        let staging_root = paths.staging_root();
        create_directory(&staging_root, Stage::Staging)?;
        let directory = tempfile::Builder::new()
            .prefix("install-")
            .permissions(Permissions::from_mode(DIRECTORY_MODE))
            .tempdir_in(&staging_root)
            .map_err(|error| BootstrapError::io(Stage::Staging, &error))?;
        Ok(Self {
            directory,
            cache_root: paths.cache_root().to_path_buf(),
        })
    }

    /// The staging directory's path.
    #[cfg(test)]
    pub(crate) fn path(&self) -> &Path {
        self.directory.path()
    }

    /// Writes one file into the staging directory at a relative path.
    ///
    /// The relative path is produced by Coffer, never taken from the archive.
    pub(crate) fn write(&self, relative: &str, contents: &[u8]) -> Result<(), BootstrapError> {
        let destination = self.directory.path().join(relative);
        let parent = destination.parent().ok_or(BootstrapError::Io {
            stage: Stage::Staging,
            kind: std::io::ErrorKind::InvalidInput,
        })?;
        create_directory(parent, Stage::Staging)?;
        let mut file = fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(FILE_MODE)
            .open(&destination)
            .map_err(|error| BootstrapError::io(Stage::Staging, &error))?;
        file.write_all(contents)
            .map_err(|error| BootstrapError::io(Stage::Staging, &error))?;
        file.sync_all()
            .map_err(|error| BootstrapError::io(Stage::Staging, &error))?;
        // Flush every level, not just the file's own directory.  `lib/<abi>/`
        // is two levels deep, and flushing only the deepest one leaves the
        // entry naming it inside `lib/` unflushed, so a crash could publish an
        // install whose library directory is missing.
        sync_directory_chain(self.directory.path(), parent, Stage::Staging)
    }

    /// Renames the staging directory into its final location.
    ///
    /// An install directory is named by the digest of the archive it came from,
    /// so a directory that already carries the target's name should hold the
    /// same payload.  `existing` says what to do when it nonetheless must not
    /// be trusted:
    ///
    /// - [`ExistingInstall::Keep`] discards the staged copy and returns the
    ///   existing path.  Use it only when the existing directory has just been
    ///   verified; not replacing it keeps the window in which the libraries are
    ///   absent at zero.
    /// - [`ExistingInstall::Replace`] swaps the freshly verified payload in.
    ///   Where the kernel and filesystem support it, this is a single
    ///   `RENAME_EXCHANGE`, so the target holds either the old or the new
    ///   installation at every instant and never nothing.  Where they do not,
    ///   it falls back to moving the old directory aside and moving it back if
    ///   the replacement rename fails; that fallback has a brief window in
    ///   which the target is absent, which costs a re-download rather than
    ///   anything irreplaceable.
    ///
    /// # Errors
    ///
    /// On failure the staged copy is removed and the publish target is left
    /// exactly as it was, including in the replace case.
    pub(crate) fn publish(
        self,
        target: &Path,
        existing: ExistingInstall,
    ) -> Result<PathBuf, BootstrapError> {
        let parent = target.parent().ok_or(BootstrapError::Io {
            stage: Stage::Publishing,
            kind: std::io::ErrorKind::InvalidInput,
        })?;
        // Check the versions root before the architecture directory inside it.
        // `create_directory` only inspects the leaf it is given, and
        // `symlink_metadata` follows every component but the last, so creating
        // `versions/<abi>` straight away would let a symbolic link at
        // `versions` stand unexamined — and then be recursed into by a later
        // replacement.
        if let Some(versions) = parent.parent() {
            create_directory(versions, Stage::Publishing)?;
        }
        create_directory(parent, Stage::Publishing)?;
        sync_directory(self.directory.path(), Stage::Publishing)?;

        // `symlink_metadata` rather than `exists`, so a dangling symbolic link
        // standing where the install directory belongs is seen as occupying
        // the name.  `exists` reports it as absent, and the rename below would
        // then fail with `AlreadyExists` on every attempt, leaving a damaged
        // cache that can never repair itself.
        if fs::symlink_metadata(target).is_ok() {
            match existing {
                ExistingInstall::Keep => return Ok(target.to_path_buf()),
                ExistingInstall::Replace => return self.replace(target, parent),
            }
        }

        let cache_root = self.cache_root.clone();
        let staged = self.directory.keep();
        match fs::rename(&staged, target) {
            Ok(()) => {
                // Flush the whole destination chain, not just the immediate
                // parent: this call may have created both the versions root and
                // the architecture directory, and the entry naming one inside
                // the other has to be durable too.
                sync_directory_chain(&cache_root, parent, Stage::Publishing)?;
                Ok(target.to_path_buf())
            }
            Err(error) => {
                let _ = fs::remove_dir_all(&staged);
                Err(BootstrapError::io(Stage::Publishing, &error))
            }
        }
    }

    /// Puts the staged copy where something already occupies the target name.
    fn replace(self, target: &Path, parent: &Path) -> Result<PathBuf, BootstrapError> {
        let cache_root = self.cache_root.clone();
        let staged = self.directory.keep();

        // A target that is not a directory cannot be exchanged or renamed over,
        // so unlink it first.  This is cache damage, not a valid installation:
        // an install directory is only ever created here, as a directory.
        match fs::symlink_metadata(target) {
            Ok(metadata) if !metadata.is_dir() || metadata.file_type().is_symlink() => {
                if let Err(error) = fs::remove_file(target) {
                    let _ = fs::remove_dir_all(&staged);
                    return Err(BootstrapError::io(Stage::Publishing, &error));
                }
                return match fs::rename(&staged, target) {
                    Ok(()) => {
                        sync_directory_chain(&cache_root, parent, Stage::Publishing)?;
                        Ok(target.to_path_buf())
                    }
                    Err(error) => {
                        let _ = fs::remove_dir_all(&staged);
                        Err(BootstrapError::io(Stage::Publishing, &error))
                    }
                };
            }
            Ok(_) => {}
            Err(error) => {
                let _ = fs::remove_dir_all(&staged);
                return Err(BootstrapError::io(Stage::Publishing, &error));
            }
        }

        // `RENAME_EXCHANGE` swaps the two directories in one step, so the
        // target is never absent.  It needs Linux 3.15 and filesystem support,
        // and reports its absence as `ENOSYS`, `EINVAL` or `EOPNOTSUPP`; those
        // fall through to the two-rename path below rather than failing.
        match renameat_with(CWD, &staged, CWD, target, RenameFlags::EXCHANGE) {
            Ok(()) => {
                // `staged` now holds the previous installation.  Removing it is
                // best-effort: an orphan is cleaned up by the next lock holder,
                // whereas failing here would report an error for a replacement
                // that already succeeded.
                let _ = fs::remove_dir_all(&staged);
                sync_directory_chain(&cache_root, parent, Stage::Publishing)?;
                return Ok(target.to_path_buf());
            }
            // `EOPNOTSUPP` and `ENOTSUP` are the same value on Linux.
            Err(Errno::NOSYS | Errno::INVAL | Errno::OPNOTSUPP) => {}
            Err(errno) => {
                let _ = fs::remove_dir_all(&staged);
                return Err(BootstrapError::Io {
                    stage: Stage::Publishing,
                    kind: std::io::Error::from(errno).kind(),
                });
            }
        }

        let displaced = match displace(&staged, target) {
            Ok(displaced) => displaced,
            Err(error) => {
                let _ = fs::remove_dir_all(&staged);
                return Err(error);
            }
        };
        match fs::rename(&staged, target) {
            Ok(()) => {
                let _ = fs::remove_dir_all(&displaced);
                sync_directory_chain(&cache_root, parent, Stage::Publishing)?;
                Ok(target.to_path_buf())
            }
            Err(error) => {
                let _ = fs::remove_dir_all(&staged);
                // Put the previous installation back.  If even this fails the
                // target is left absent, which the next bootstrap repairs by
                // downloading again; nothing irreplaceable lives here.
                let _ = fs::rename(&displaced, target);
                Err(BootstrapError::io(Stage::Publishing, &error))
            }
        }
    }
}

/// Moves an existing install directory aside, beside the staged copy.
///
/// Returns where it went, so the caller can put it back if the replacement
/// rename fails.  The staging area is on the same filesystem as the publish
/// target, so this is a rename rather than a copy.
fn displace(staged: &Path, target: &Path) -> Result<PathBuf, BootstrapError> {
    let staging_root = staged.parent().ok_or(BootstrapError::Io {
        stage: Stage::Publishing,
        kind: std::io::ErrorKind::InvalidInput,
    })?;
    // Borrow the temporary-directory machinery purely for a name nothing else
    // holds, then free the name so the rename can take it.
    let reserved = tempfile::Builder::new()
        .prefix("replaced-")
        .permissions(Permissions::from_mode(DIRECTORY_MODE))
        .tempdir_in(staging_root)
        .map_err(|error| BootstrapError::io(Stage::Publishing, &error))?
        .keep();
    fs::remove_dir(&reserved).map_err(|error| BootstrapError::io(Stage::Publishing, &error))?;
    fs::rename(target, &reserved).map_err(|error| BootstrapError::io(Stage::Publishing, &error))?;
    Ok(reserved)
}

/// What [`StagedInstall::publish`] should do about a directory that already
/// carries the target's name.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ExistingInstall {
    /// Discard the staged copy and keep what is already there.
    Keep,
    /// Replace it with the staged copy.
    Replace,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::MetadataExt;
    use std::sync::mpsc;
    use std::thread;

    fn paths_in(root: &Path) -> BootstrapPaths {
        BootstrapPaths::rooted_at(root)
    }

    #[test]
    fn creates_bootstrap_directories_with_restrictive_permissions() {
        let root = tempfile::tempdir().expect("temporary root");
        let paths = paths_in(root.path());
        create_directory(paths.cache_root(), Stage::Staging).expect("create");
        let mode = fs::metadata(paths.cache_root()).expect("metadata").mode() & 0o777;
        assert_eq!(mode, DIRECTORY_MODE);
    }

    #[test]
    fn creates_every_intermediate_directory_restrictively_under_a_permissive_umask() {
        let root = tempfile::tempdir().expect("temporary root");
        let paths = paths_in(root.path());
        // `create_dir_all` would apply the umask to the intermediate levels and
        // chmod only the leaf, leaving a world-writable directory another local
        // user could rename the cache root out of.
        create_directory(&paths.staging_root(), Stage::Staging).expect("create");

        let mut current = paths.staging_root();
        while current.starts_with(root.path()) && current != root.path() {
            let mode = fs::metadata(&current).expect("metadata").mode() & 0o777;
            assert_eq!(
                mode,
                DIRECTORY_MODE,
                "{} was created with mode {mode:o}",
                current.display()
            );
            current = current.parent().expect("parent").to_path_buf();
        }
    }

    #[test]
    fn tightens_a_bootstrap_directory_that_is_already_permissive() {
        let root = tempfile::tempdir().expect("temporary root");
        let paths = paths_in(root.path());
        fs::create_dir_all(paths.cache_root()).expect("create");
        fs::set_permissions(paths.cache_root(), Permissions::from_mode(0o777)).expect("widen");

        create_directory(paths.cache_root(), Stage::Staging).expect("create");
        assert_eq!(
            fs::metadata(paths.cache_root()).expect("metadata").mode() & 0o777,
            DIRECTORY_MODE,
            "an existing world-writable bootstrap directory must be tightened"
        );
    }

    #[test]
    fn refuses_to_publish_through_a_versions_root_that_is_a_symbolic_link() {
        let root = tempfile::tempdir().expect("temporary root");
        let paths = paths_in(root.path());
        create_directory(paths.cache_root(), Stage::Publishing).expect("create cache root");

        // Stand in for something outside the tree bootstrap owns.
        let elsewhere = root.path().join("elsewhere");
        fs::create_dir_all(&elsewhere).expect("create elsewhere");
        std::os::unix::fs::symlink(&elsewhere, paths.versions_root()).expect("symlink versions");

        let staged = StagedInstall::create(&paths).expect("stage");
        staged.write("lib/x86_64/a.so", b"payload").expect("write");
        let error = staged
            .publish(
                &paths.install_directory(crate::arch::Architecture::X86_64, "abc"),
                ExistingInstall::Keep,
            )
            .expect_err("a symlinked versions root must be refused");
        assert_eq!(
            error,
            BootstrapError::UnsafeLayout {
                stage: Stage::Publishing,
                violation: LayoutViolation::SymbolicLink,
            }
        );
        assert!(
            fs::read_dir(&elsewhere)
                .expect("read elsewhere")
                .next()
                .is_none(),
            "nothing may be written through the symbolic link"
        );
    }

    #[test]
    fn replaces_a_target_name_occupied_by_something_that_is_not_a_directory() {
        let root = tempfile::tempdir().expect("temporary root");
        let paths = paths_in(root.path());
        let target = paths.install_directory(crate::arch::Architecture::X86_64, "abc");
        create_directory(target.parent().expect("parent"), Stage::Publishing).expect("create");

        // A regular file, and then a dangling symbolic link, standing where the
        // install directory belongs.  Both are cache damage that must be
        // repaired rather than reported forever.
        fs::write(&target, b"not a directory").expect("write file");
        let staged = StagedInstall::create(&paths).expect("stage");
        staged.write("lib/x86_64/a.so", b"payload").expect("write");
        staged
            .publish(&target, ExistingInstall::Replace)
            .expect("publish over a regular file");
        assert!(target.is_dir());
        assert_eq!(
            fs::read(target.join("lib/x86_64/a.so")).expect("read"),
            b"payload"
        );

        fs::remove_dir_all(&target).expect("remove");
        std::os::unix::fs::symlink(root.path().join("nowhere"), &target).expect("symlink");
        let staged = StagedInstall::create(&paths).expect("stage");
        staged.write("lib/x86_64/a.so", b"payload").expect("write");
        staged
            .publish(&target, ExistingInstall::Replace)
            .expect("publish over a dangling symbolic link");
        assert!(target.is_dir());
    }

    #[test]
    fn writes_files_atomically_with_restrictive_permissions() {
        let root = tempfile::tempdir().expect("temporary root");
        let paths = paths_in(root.path());
        create_directory(paths.state_root(), Stage::Publishing).expect("create");
        let target = paths.active_install_file();

        write_file_atomically(&target, b"first", Stage::Publishing).expect("write");
        assert_eq!(fs::read(&target).expect("read"), b"first");
        let mode = fs::metadata(&target).expect("metadata").mode() & 0o777;
        assert_eq!(mode, FILE_MODE);

        write_file_atomically(&target, b"second", Stage::Publishing).expect("rewrite");
        assert_eq!(fs::read(&target).expect("read"), b"second");

        // No temporary file survives a successful write.
        let leftovers: Vec<_> = fs::read_dir(paths.state_root())
            .expect("read state root")
            .filter_map(Result::ok)
            .filter(|entry| entry.file_name().to_string_lossy().starts_with(".partial-"))
            .collect();
        assert!(leftovers.is_empty(), "a temporary file survived the write");
    }

    #[test]
    fn publishes_a_staged_install_atomically() {
        let root = tempfile::tempdir().expect("temporary root");
        let paths = paths_in(root.path());
        let target = paths.install_directory(crate::arch::Architecture::X86_64, "abc");

        let staged = StagedInstall::create(&paths).expect("stage");
        staged.write("lib/x86_64/a.so", b"payload").expect("write");
        let published = staged
            .publish(&target, ExistingInstall::Keep)
            .expect("publish");

        assert_eq!(published, target);
        assert_eq!(
            fs::read(target.join("lib/x86_64/a.so")).expect("read"),
            b"payload"
        );
        let mode = fs::metadata(target.join("lib/x86_64/a.so"))
            .expect("metadata")
            .mode()
            & 0o777;
        assert_eq!(mode, FILE_MODE);
    }

    #[test]
    fn a_staged_install_that_is_never_published_leaves_nothing_behind() {
        let root = tempfile::tempdir().expect("temporary root");
        let paths = paths_in(root.path());
        {
            let staged = StagedInstall::create(&paths).expect("stage");
            staged.write("lib/x86_64/a.so", b"payload").expect("write");
            // Dropped without publishing, as an interrupted run would.
        }
        let remaining: Vec<_> = fs::read_dir(paths.staging_root())
            .expect("read staging root")
            .filter_map(Result::ok)
            .collect();
        assert!(
            remaining.is_empty(),
            "an unpublished staging directory survived"
        );
        assert!(!paths.versions_root().exists());
    }

    #[test]
    fn publishing_over_an_existing_install_keeps_the_existing_one() {
        let root = tempfile::tempdir().expect("temporary root");
        let paths = paths_in(root.path());
        let target = paths.install_directory(crate::arch::Architecture::X86_64, "abc");

        let first = StagedInstall::create(&paths).expect("stage");
        first.write("lib/x86_64/a.so", b"original").expect("write");
        first
            .publish(&target, ExistingInstall::Keep)
            .expect("publish");

        let second = StagedInstall::create(&paths).expect("stage");
        second
            .write("lib/x86_64/a.so", b"replacement")
            .expect("write");
        second
            .publish(&target, ExistingInstall::Keep)
            .expect("publish");

        assert_eq!(
            fs::read(target.join("lib/x86_64/a.so")).expect("read"),
            b"original",
            "an install directory named by content digest must not be rewritten"
        );
    }

    #[test]
    fn the_lock_serializes_concurrent_bootstrap_attempts() {
        let root = tempfile::tempdir().expect("temporary root");
        let paths = paths_in(root.path());

        let held = BootstrapLock::acquire(&paths, LockMode::Wait).expect("first acquire");
        assert_eq!(
            BootstrapLock::acquire(&paths, LockMode::Fail).err(),
            Some(BootstrapError::Busy),
            "a second non-blocking acquire must report the lock as busy"
        );

        // A waiting acquire must not proceed until the first is released.  The
        // lock is per open file description, so this uses a separate process
        // rather than a thread.
        let (ready, released) = mpsc::channel();
        let waiter_paths = paths.clone();
        let waiter = thread::spawn(move || {
            // `flock` is per open file description, and this thread opens its
            // own, so it genuinely blocks on the lock held above.
            let lock = BootstrapLock::acquire(&waiter_paths, LockMode::Wait).expect("acquire");
            ready.send(()).expect("report acquisition");
            drop(lock);
        });

        assert!(
            released
                .recv_timeout(std::time::Duration::from_millis(200))
                .is_err(),
            "the waiter acquired the lock while it was still held"
        );
        drop(held);
        released
            .recv_timeout(std::time::Duration::from_secs(10))
            .expect("the waiter must acquire the lock once it is released");
        waiter.join().expect("waiter thread");
    }

    #[test]
    fn cleaning_staging_removes_orphans_from_an_interrupted_run() {
        let root = tempfile::tempdir().expect("temporary root");
        let paths = paths_in(root.path());
        create_directory(&paths.staging_root(), Stage::Staging).expect("create");
        let orphan = paths.staging_root().join("install-orphan");
        fs::create_dir(&orphan).expect("create orphan");
        fs::write(orphan.join("half-written.so"), b"partial").expect("write orphan");
        fs::write(paths.staging_root().join("stray"), b"stray").expect("write stray");

        let lock = BootstrapLock::acquire(&paths, LockMode::Wait).expect("acquire");
        lock.clean_staging(&paths).expect("clean");

        let remaining: Vec<_> = fs::read_dir(paths.staging_root())
            .expect("read staging root")
            .filter_map(Result::ok)
            .collect();
        assert!(remaining.is_empty());
    }

    #[test]
    fn cleaning_staging_is_fine_when_nothing_was_ever_staged() {
        let root = tempfile::tempdir().expect("temporary root");
        let paths = paths_in(root.path());
        let lock = BootstrapLock::acquire(&paths, LockMode::Wait).expect("acquire");
        lock.clean_staging(&paths).expect("clean");
    }

    #[test]
    fn locking_never_creates_the_provisioning_directory() {
        let root = tempfile::tempdir().expect("temporary root");
        let paths = paths_in(root.path());
        let lock = BootstrapLock::acquire(&paths, LockMode::Wait).expect("acquire");
        let staged = StagedInstall::create(&paths).expect("stage");
        staged.write("lib/x86_64/a.so", b"payload").expect("write");
        staged
            .publish(
                &paths.install_directory(crate::arch::Architecture::X86_64, "abc"),
                ExistingInstall::Keep,
            )
            .expect("publish");
        drop(lock);
        assert!(
            !paths.provisioning_directory().exists(),
            "bootstrap must not create the provisioning directory"
        );
    }
}
