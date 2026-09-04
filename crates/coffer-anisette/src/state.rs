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

//! Crash-safe ownership of the opaque native provisioning directory.

use std::ffi::CString;
use std::fs::{self, File, Permissions};
use std::io::{Read as _, Write as _};
use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd};
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::{
    DirBuilderExt as _, MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _,
};
use std::path::{Component, Path, PathBuf};
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, Instant};

use coffer_bootstrap::BootstrapPaths;
use sha2::{Digest as _, Sha256};
use tempfile::TempDir;
use zeroize::Zeroizing;

use crate::{AndroidId, BridgeError, SecretString};

const DIRECTORY_MODE: u32 = 0o700;
const FILE_MODE: u32 = 0o600;
const IDENTIFIER_BYTES: usize = 16;
const MAX_STATE_FILE_BYTES: u64 = 16 * 1024 * 1024;
const MAX_STATE_TOTAL_BYTES: u64 = 64 * 1024 * 1024;
const MAX_STATE_ENTRIES: usize = 1024;
const MAX_STATE_DEPTH: usize = 16;
const MAX_GENERATION_NAME_BYTES: usize = 80;
const ACTIVE_FILE: &str = "active";
const IDENTIFIER_FILE: &str = "identifier";
const LOCK_FILE: &str = "provisioning.lock";
const GENERATIONS_DIRECTORY: &str = "generations";
const STAGING_DIRECTORY: &str = "staging";

/// XDG-bound storage for native provisioning generations.
pub struct ProvisioningStore {
    root: PathBuf,
}

impl ProvisioningStore {
    /// Binds storage to [`BootstrapPaths::provisioning_directory`].
    ///
    /// The configured bootstrap layout is checked before any directory is
    /// created.  There is no constructor that accepts a bare state path.
    ///
    /// # Errors
    ///
    /// Returns [`BridgeError::InvalidPath`] for an overlapping bootstrap
    /// layout.
    pub fn from_paths(paths: &BootstrapPaths) -> Result<Self, BridgeError> {
        paths
            .check_separation()
            .map_err(|_| BridgeError::InvalidPath)?;
        let root = effective_path(paths.provisioning_directory());
        if !root.is_absolute() {
            return Err(BridgeError::InvalidPath);
        }
        Ok(Self { root })
    }

    /// Loads or atomically creates the installation's 16-byte identifier.
    ///
    /// # Errors
    ///
    /// Returns a stage-safe state error for unsafe paths, permissions,
    /// ownership, malformed identifier data, locking, or local I/O failure.
    pub fn identifiers(&self) -> Result<DeviceIdentifiers, BridgeError> {
        if let Some(bytes) = read_identifier(&self.root)? {
            return DeviceIdentifiers::from_bytes(bytes);
        }
        let _lock = self.lock_until(None)?;
        let bytes = match read_identifier(&self.root)? {
            Some(bytes) => bytes,
            None => {
                let mut bytes = Zeroizing::new(vec![0u8; IDENTIFIER_BYTES]);
                fill_random(&mut bytes)?;
                write_atomic(&self.root, IDENTIFIER_FILE, &bytes)?;
                bytes
            }
        };
        DeviceIdentifiers::from_bytes(bytes)
    }

    pub(crate) fn prepare(&self, deadline: Instant) -> Result<PreparedGeneration, BridgeError> {
        check_deadline(deadline)?;
        let lock = self.lock_until(Some(deadline))?;
        let staging_root = self.root.join(STAGING_DIRECTORY);
        let generations_root = self.root.join(GENERATIONS_DIRECTORY);
        create_private_directory(&staging_root)?;
        create_private_directory(&generations_root)?;
        check_deadline(deadline)?;
        clean_staging(&staging_root, deadline)?;
        let active = active_generation(&self.root, Some(deadline))?;
        let active_name = active
            .as_ref()
            .and_then(|path| path.file_name())
            .map(std::ffi::OsStr::to_owned);
        prune_generations(&self.root, active_name.as_deref(), None, Some(deadline))?;
        check_deadline(deadline)?;
        let directory = tempfile::Builder::new()
            .prefix(".generation-")
            .permissions(Permissions::from_mode(DIRECTORY_MODE))
            .tempdir_in(&staging_root)
            .map_err(|_| BridgeError::StateFailed)?;
        fs::set_permissions(directory.path(), Permissions::from_mode(DIRECTORY_MODE))
            .map_err(|_| BridgeError::StateFailed)?;
        let path = directory.path().to_owned();
        validate_staging_path(&self.root, &path)?;
        if let Some(active) = active {
            copy_tree(&active, &path, deadline)?;
        }
        check_deadline(deadline)?;
        let capability = open_directory(&path)?;
        let lease = Arc::new(Mutex::new(GenerationLease {
            directory: Some(directory),
            lock: Some(lock),
            expired: false,
        }));
        Ok(PreparedGeneration {
            root: self.root.clone(),
            path,
            capability,
            deadline,
            lease,
        })
    }

    #[allow(unsafe_code)]
    fn lock_until(&self, deadline: Option<Instant>) -> Result<StateLock, BridgeError> {
        create_private_directory(&self.root)?;
        validate_private_directory(&self.root)?;
        let path = self.root.join(LOCK_FILE);
        let mut options = fs::OpenOptions::new();
        options
            .read(true)
            .write(true)
            .mode(FILE_MODE)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
        let file = match options.create_new(true).open(&path) {
            Ok(file) => {
                file.set_permissions(Permissions::from_mode(FILE_MODE))
                    .map_err(|_| BridgeError::StateFailed)?;
                file
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => options
                .create_new(false)
                .open(&path)
                .map_err(|_| BridgeError::StateFailed)?,
            Err(_) => return Err(BridgeError::StateFailed),
        };
        validate_regular_metadata(&file.metadata().map_err(|_| BridgeError::StateFailed)?)?;
        loop {
            if let Some(deadline) = deadline {
                check_deadline(deadline)?;
            }
            let operation = if deadline.is_some() {
                libc::LOCK_EX | libc::LOCK_NB
            } else {
                libc::LOCK_EX
            };
            // SAFETY: `file` is an owned descriptor for the private lock file.
            if unsafe { libc::flock(file.as_raw_fd(), operation) } == 0 {
                break;
            }
            // SAFETY: errno is read immediately after the failed `flock`.
            let errno = unsafe { *libc::__errno_location() };
            if deadline.is_none() || errno != libc::EWOULDBLOCK {
                return Err(BridgeError::StateFailed);
            }
            check_deadline(deadline.ok_or(BridgeError::StateFailed)?)?;
            std::thread::sleep(Duration::from_millis(2));
        }
        if let Some(deadline) = deadline {
            check_deadline(deadline)?;
        }
        validate_private_directory(&self.root)?;
        Ok(StateLock(file))
    }
}

fn read_identifier(root: &Path) -> Result<Option<Zeroizing<Vec<u8>>>, BridgeError> {
    let directory = match open_existing_private_directory(root) {
        Ok(directory) => directory,
        Err(BridgeError::StateMissing) => return Ok(None),
        Err(error) => return Err(error),
    };
    let file = match open_regular_file_at(&directory, IDENTIFIER_FILE) {
        Ok(file) => file,
        Err(BridgeError::StateMissing) => return Ok(None),
        Err(error) => return Err(error),
    };
    let mut bytes = Zeroizing::new(Vec::with_capacity(IDENTIFIER_BYTES + 1));
    file.take((IDENTIFIER_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| BridgeError::StateFailed)?;
    if bytes.len() != IDENTIFIER_BYTES {
        return Err(BridgeError::StateCorrupt);
    }
    Ok(Some(bytes))
}

impl core::fmt::Debug for ProvisioningStore {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("ProvisioningStore(<redacted-path>)")
    }
}

/// Stable identifiers derived from the separately persisted random seed.
pub struct DeviceIdentifiers {
    android_id: AndroidId,
    device_identifier: String,
    local_user_id: SecretString,
}

impl DeviceIdentifiers {
    fn from_bytes(bytes: Zeroizing<Vec<u8>>) -> Result<Self, BridgeError> {
        let array: [u8; 16] = bytes
            .as_slice()
            .try_into()
            .map_err(|_| BridgeError::StateCorrupt)?;
        let device_identifier = format_uuid(array);
        let android: [u8; 16] = device_identifier.as_bytes()[..16]
            .try_into()
            .map_err(|_| BridgeError::StateCorrupt)?;
        let local_user_id = encode_hex_upper(Sha256::digest(array));
        Ok(Self {
            android_id: AndroidId::new(android)?,
            device_identifier,
            local_user_id: SecretString::new(local_user_id)?,
        })
    }

    /// The exact Android identifier configured before every native operation.
    #[must_use]
    pub fn android_id(&self) -> &AndroidId {
        &self.android_id
    }

    /// The uppercase UUID sent as the device identifier.
    #[must_use]
    pub fn device_identifier(&self) -> &str {
        &self.device_identifier
    }

    /// The uppercase SHA-256 local-user identifier.
    #[must_use]
    pub fn local_user_id(&self) -> &SecretString {
        &self.local_user_id
    }

    /// SideStore's local composition constant for routing information.
    #[must_use]
    pub const fn routing_info(&self) -> &'static str {
        "17106176"
    }

    /// SideStore's local composition serial-number placeholder.
    #[must_use]
    pub const fn serial_number(&self) -> &'static str {
        "0"
    }
}

impl core::fmt::Debug for DeviceIdentifiers {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("DeviceIdentifiers(<redacted>)")
    }
}

pub(crate) struct PreparedGeneration {
    root: PathBuf,
    path: PathBuf,
    capability: OwnedFd,
    deadline: Instant,
    lease: Arc<Mutex<GenerationLease>>,
}

pub(crate) struct GenerationLease {
    directory: Option<TempDir>,
    lock: Option<StateLock>,
    expired: bool,
}

pub(crate) type GenerationLeaseHandle = Weak<Mutex<GenerationLease>>;

pub(crate) fn expire_generation(handle: &GenerationLeaseHandle) {
    let Some(lease) = handle.upgrade() else {
        return;
    };
    let Ok(mut lease) = lease.lock() else {
        return;
    };
    lease.expired = true;
    lease.lock.take();
    // Leave the bounded, private staging tree for the next lock holder to
    // clean. Recursive deletion in this watchdog would extend the lock past
    // the absolute deadline or race the next writer after releasing it.
    if let Some(directory) = lease.directory.take() {
        let _ = directory.keep();
    }
}

impl PreparedGeneration {
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    pub(crate) fn capability(&self) -> &OwnedFd {
        &self.capability
    }

    pub(crate) fn root(&self) -> &Path {
        &self.root
    }

    pub(crate) fn lease_handle(&self) -> GenerationLeaseHandle {
        Arc::downgrade(&self.lease)
    }

    pub(crate) fn publish(mut self) -> Result<(), BridgeError> {
        self.publish_inner(true)
    }

    pub(crate) fn publish_erasing(mut self) -> Result<(), BridgeError> {
        self.publish_inner(false)
    }

    fn publish_inner(&mut self, retain_previous: bool) -> Result<(), BridgeError> {
        check_deadline(self.deadline)?;
        let mut lease = self.lease.lock().map_err(|_| BridgeError::StateFailed)?;
        if lease.expired || lease.directory.is_none() || lease.lock.is_none() {
            return Err(BridgeError::TimedOut);
        }
        validate_staging_path(&self.root, self.path())?;
        let descriptor_metadata = File::from(
            self.capability
                .try_clone()
                .map_err(|_| BridgeError::StateFailed)?,
        )
        .metadata()
        .map_err(|_| BridgeError::StateFailed)?;
        let path_metadata = fs::metadata(self.path()).map_err(|_| BridgeError::StateFailed)?;
        if descriptor_metadata.dev() != path_metadata.dev()
            || descriptor_metadata.ino() != path_metadata.ino()
        {
            return Err(BridgeError::InvalidPath);
        }
        sync_tree_until(self.path(), Some(self.deadline))?;
        let basename = self
            .path()
            .file_name()
            .and_then(|name| name.to_str())
            .filter(|name| is_generation_name(name))
            .ok_or(BridgeError::StateCorrupt)?
            .to_owned();
        let target = self.root.join(GENERATIONS_DIRECTORY).join(&basename);
        if fs::symlink_metadata(&target).is_ok() {
            return Err(BridgeError::StateCorrupt);
        }
        let previous = active_generation(&self.root, Some(self.deadline))?
            .and_then(|path| path.file_name().map(|name| name.to_owned()));
        check_deadline(self.deadline)?;
        fs::rename(self.path(), &target).map_err(|_| BridgeError::StateFailed)?;
        // The path move succeeded, so dropping the owner can only attempt to
        // clean the now-absent staging name.  On rename failure it remains
        // armed and removes the secret-bearing staging tree automatically.
        lease.directory.take();
        sync_directory(target.parent().ok_or(BridgeError::StateFailed)?)?;
        validate_generation_set(&self.root, Some(self.deadline))?;
        check_deadline(self.deadline)?;
        write_atomic(&self.root, ACTIVE_FILE, basename.as_bytes())?;
        // Publication is committed once the active pointer is durable.  Any
        // cleanup interruption is retried strictly under the lock by the next
        // `prepare`, rather than reporting failure after durable state changed.
        let _ = prune_generations(
            &self.root,
            Some(std::ffi::OsStr::new(&basename)),
            retain_previous.then_some(previous).flatten().as_deref(),
            None,
        );
        Ok(())
    }
}

struct StateLock(File);

impl Drop for StateLock {
    #[allow(unsafe_code)]
    fn drop(&mut self) {
        // SAFETY: the descriptor stays live for this call.  Closing it would
        // release the same open-file-description lock as a fallback.
        let _ = unsafe { libc::flock(self.0.as_raw_fd(), libc::LOCK_UN) };
    }
}

fn create_private_directory(path: &Path) -> Result<(), BridgeError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
            return Err(BridgeError::InvalidPath);
        }
        Ok(_) => return validate_private_directory(path),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => secure_create_chain(path)?,
        Err(_) => return Err(BridgeError::InvalidPath),
    }
    validate_private_directory(path)
}

#[allow(unsafe_code)]
fn secure_create_chain(path: &Path) -> Result<(), BridgeError> {
    if !path.is_absolute() {
        return Err(BridgeError::InvalidPath);
    }
    // SAFETY: the static path opens a fresh directory descriptor owned here.
    let root = unsafe {
        libc::open(
            c"/".as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    if root < 0 {
        return Err(BridgeError::StateFailed);
    }
    // SAFETY: `root` is the fresh successful descriptor above.
    let mut directory = unsafe { OwnedFd::from_raw_fd(root) };
    for component in path.components() {
        let Component::Normal(name) = component else {
            if matches!(component, Component::RootDir) {
                continue;
            }
            return Err(BridgeError::InvalidPath);
        };
        let name = CString::new(name.as_bytes()).map_err(|_| BridgeError::InvalidPath)?;
        // SAFETY: the live parent descriptor and bounded single component
        // ensure creation cannot traverse a symbolic link or `..` component.
        let created =
            unsafe { libc::mkdirat(directory.as_raw_fd(), name.as_ptr(), DIRECTORY_MODE) };
        if created != 0 {
            // SAFETY: errno is thread-local and immediately follows mkdirat.
            let errno = unsafe { *libc::__errno_location() };
            if errno != libc::EEXIST {
                return Err(BridgeError::StateFailed);
            }
        } else {
            // A caller may inherit a mask stricter than 0077. Normalize the
            // newly created inode through its parent capability before exact
            // mode validation or descent.
            // SAFETY: this is the same live parent descriptor and single
            // component used for the successful mkdirat above.
            if unsafe { libc::fchmodat(directory.as_raw_fd(), name.as_ptr(), DIRECTORY_MODE, 0) }
                != 0
            {
                return Err(BridgeError::StateFailed);
            }
            // Persist the new name in its parent before descending.  Without
            // this, a successful publication could be lost with an unflushed
            // intermediate XDG directory after a crash.
            File::from(
                directory
                    .try_clone()
                    .map_err(|_| BridgeError::StateFailed)?,
            )
            .sync_all()
            .map_err(|_| BridgeError::StateFailed)?;
        }
        // SAFETY: O_NOFOLLOW and a single component refuse symbolic links;
        // the successful result transfers to the next owned descriptor.
        let next = unsafe {
            libc::openat(
                directory.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if next < 0 {
            return Err(BridgeError::InvalidPath);
        }
        // SAFETY: `next` is a fresh successful open result.
        directory = unsafe { OwnedFd::from_raw_fd(next) };
    }
    Ok(())
}

fn validate_private_directory(path: &Path) -> Result<(), BridgeError> {
    validate_private_directory_for_uid(path, current_uid())
}

fn validate_private_directory_for_uid(path: &Path, expected_uid: u32) -> Result<(), BridgeError> {
    let link = fs::symlink_metadata(path).map_err(|_| BridgeError::InvalidPath)?;
    if link.file_type().is_symlink() || !link.is_dir() {
        return Err(BridgeError::InvalidPath);
    }
    let canonical = path.canonicalize().map_err(|_| BridgeError::InvalidPath)?;
    if canonical != path || link.uid() != expected_uid || link.mode() & 0o777 != DIRECTORY_MODE {
        return Err(BridgeError::InvalidPath);
    }
    Ok(())
}

pub(crate) fn validate_staging_path(root: &Path, path: &Path) -> Result<(), BridgeError> {
    validate_private_directory(root)?;
    validate_private_directory(path)?;
    let expected_parent = root.join(STAGING_DIRECTORY);
    validate_private_directory(&expected_parent)?;
    if path.parent() != Some(expected_parent.as_path())
        || !path
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(is_generation_name)
    {
        return Err(BridgeError::InvalidPath);
    }
    Ok(())
}

#[allow(unsafe_code)]
fn current_uid() -> u32 {
    // SAFETY: `geteuid` has no pointer arguments or preconditions.
    unsafe { libc::geteuid() }
}

fn validate_regular_metadata(metadata: &fs::Metadata) -> Result<(), BridgeError> {
    if !metadata.is_file()
        || metadata.uid() != current_uid()
        || metadata.mode() & 0o777 != FILE_MODE
        || metadata.nlink() != 1
    {
        return Err(BridgeError::InvalidPath);
    }
    Ok(())
}

fn open_regular_file(path: &Path) -> Result<File, BridgeError> {
    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                BridgeError::StateMissing
            } else {
                BridgeError::InvalidPath
            }
        })?;
    validate_regular_metadata(&file.metadata().map_err(|_| BridgeError::StateFailed)?)?;
    Ok(file)
}

#[allow(unsafe_code)]
fn open_regular_file_at(directory: &OwnedFd, name: &str) -> Result<File, BridgeError> {
    let name = CString::new(name).map_err(|_| BridgeError::InvalidPath)?;
    // SAFETY: `directory` is a live directory capability, the C string has no
    // interior NUL, and a successful result is transferred into `File` once.
    let raw = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if raw < 0 {
        // SAFETY: errno is read immediately after the failed `openat`.
        let errno = unsafe { *libc::__errno_location() };
        return Err(if errno == libc::ENOENT {
            BridgeError::StateMissing
        } else {
            BridgeError::InvalidPath
        });
    }
    // SAFETY: `raw` is a fresh successful open result owned here.
    let file = unsafe { File::from_raw_fd(raw) };
    validate_regular_metadata(&file.metadata().map_err(|_| BridgeError::StateFailed)?)?;
    Ok(file)
}

fn open_existing_private_directory(path: &Path) -> Result<OwnedFd, BridgeError> {
    match fs::symlink_metadata(path) {
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Err(BridgeError::StateMissing);
        }
        Err(_) => return Err(BridgeError::InvalidPath),
    }
    let directory = open_directory(path)?;
    validate_private_directory(path)?;
    let opened = File::from(
        directory
            .try_clone()
            .map_err(|_| BridgeError::StateFailed)?,
    );
    let opened = opened.metadata().map_err(|_| BridgeError::StateFailed)?;
    let current = fs::symlink_metadata(path).map_err(|_| BridgeError::InvalidPath)?;
    if opened.dev() != current.dev() || opened.ino() != current.ino() {
        return Err(BridgeError::InvalidPath);
    }
    Ok(directory)
}

#[allow(unsafe_code)]
fn open_directory(path: &Path) -> Result<OwnedFd, BridgeError> {
    let path = CString::new(path.as_os_str().as_bytes()).map_err(|_| BridgeError::InvalidPath)?;
    // SAFETY: the live C string is bounded by the platform path limit.  A
    // successful open returns a fresh descriptor transferred to `OwnedFd`.
    let raw = unsafe {
        libc::open(
            path.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if raw < 0 {
        return Err(BridgeError::InvalidPath);
    }
    // SAFETY: `raw` is a fresh successful open result owned here.
    Ok(unsafe { OwnedFd::from_raw_fd(raw) })
}

#[allow(unsafe_code)]
fn fill_random(bytes: &mut [u8]) -> Result<(), BridgeError> {
    let mut offset = 0usize;
    while offset < bytes.len() {
        // SAFETY: the remaining slice is writable for its reported length.
        let count = unsafe {
            libc::getrandom(bytes[offset..].as_mut_ptr().cast(), bytes.len() - offset, 0)
        };
        if count <= 0 {
            return Err(BridgeError::StateFailed);
        }
        offset = offset
            .checked_add(usize::try_from(count).map_err(|_| BridgeError::StateFailed)?)
            .ok_or(BridgeError::StateFailed)?;
    }
    Ok(())
}

fn write_atomic(directory: &Path, basename: &str, contents: &[u8]) -> Result<(), BridgeError> {
    validate_atomic_target(&directory.join(basename))?;
    let mut temporary = tempfile::Builder::new()
        .prefix(".partial-")
        .permissions(Permissions::from_mode(FILE_MODE))
        .tempfile_in(directory)
        .map_err(|_| BridgeError::StateFailed)?;
    temporary
        .as_file()
        .set_permissions(Permissions::from_mode(FILE_MODE))
        .map_err(|_| BridgeError::StateFailed)?;
    temporary
        .write_all(contents)
        .map_err(|_| BridgeError::StateFailed)?;
    temporary
        .as_file()
        .sync_all()
        .map_err(|_| BridgeError::StateFailed)?;
    temporary
        .persist(directory.join(basename))
        .map_err(|_| BridgeError::StateFailed)?;
    sync_directory(directory)
}

fn validate_atomic_target(path: &Path) -> Result<(), BridgeError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => validate_regular_metadata(&metadata),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(BridgeError::InvalidPath),
    }
}

fn active_generation(
    root: &Path,
    deadline: Option<Instant>,
) -> Result<Option<PathBuf>, BridgeError> {
    check_optional_deadline(deadline)?;
    let file = match open_regular_file(&root.join(ACTIVE_FILE)) {
        Ok(file) => file,
        Err(BridgeError::StateMissing) => return Ok(None),
        Err(error) => return Err(error),
    };
    let mut name = Vec::with_capacity(MAX_GENERATION_NAME_BYTES + 1);
    file.take((MAX_GENERATION_NAME_BYTES + 1) as u64)
        .read_to_end(&mut name)
        .map_err(|_| BridgeError::StateFailed)?;
    if name.len() > MAX_GENERATION_NAME_BYTES {
        return Err(BridgeError::StateCorrupt);
    }
    let name = std::str::from_utf8(&name).map_err(|_| BridgeError::StateCorrupt)?;
    if !is_generation_name(name) {
        return Err(BridgeError::StateCorrupt);
    }
    let path = root.join(GENERATIONS_DIRECTORY).join(name);
    validate_generation_tree_until(&path, deadline)?;
    Ok(Some(path))
}

fn is_generation_name(name: &str) -> bool {
    name.starts_with(".generation-")
        && name.len() <= MAX_GENERATION_NAME_BYTES
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
}

fn prune_generations(
    root: &Path,
    active: Option<&std::ffi::OsStr>,
    retained_previous: Option<&std::ffi::OsStr>,
    deadline: Option<Instant>,
) -> Result<(), BridgeError> {
    let generations = root.join(GENERATIONS_DIRECTORY);
    for (name, path) in validate_generation_set(root, deadline)? {
        check_optional_deadline(deadline)?;
        if active.is_some_and(|current| current == name)
            || retained_previous.is_some_and(|previous| previous == name)
        {
            continue;
        }
        fs::remove_dir_all(path).map_err(|_| BridgeError::StateFailed)?;
    }
    sync_directory(&generations)
}

fn validate_generation_set(
    root: &Path,
    deadline: Option<Instant>,
) -> Result<Vec<(std::ffi::OsString, PathBuf)>, BridgeError> {
    let generations = root.join(GENERATIONS_DIRECTORY);
    let mut validated = Vec::new();
    for entry in fs::read_dir(generations).map_err(|_| BridgeError::StateFailed)? {
        check_optional_deadline(deadline)?;
        let entry = entry.map_err(|_| BridgeError::StateFailed)?;
        let name = entry.file_name();
        let name_text = name.to_str().ok_or(BridgeError::StateCorrupt)?;
        let file_type = entry.file_type().map_err(|_| BridgeError::StateFailed)?;
        if !is_generation_name(name_text) || file_type.is_symlink() || !file_type.is_dir() {
            return Err(BridgeError::InvalidPath);
        }
        validate_generation_tree_until(&entry.path(), deadline)?;
        validated.push((name, entry.path()));
    }
    Ok(validated)
}

fn clean_staging(staging: &Path, deadline: Instant) -> Result<(), BridgeError> {
    let mut count = 0usize;
    for entry in fs::read_dir(staging).map_err(|_| BridgeError::StateFailed)? {
        check_deadline(deadline)?;
        let entry = entry.map_err(|_| BridgeError::StateFailed)?;
        count = count.checked_add(1).ok_or(BridgeError::StateCorrupt)?;
        if count > MAX_STATE_ENTRIES {
            return Err(BridgeError::StateCorrupt);
        }
        let metadata = entry.file_type().map_err(|_| BridgeError::StateFailed)?;
        if metadata.is_dir() {
            validate_stale_tree_for_cleanup(&entry.path(), 0, &mut count, deadline)?;
            fs::remove_dir_all(entry.path()).map_err(|_| BridgeError::StateFailed)?;
        } else {
            fs::remove_file(entry.path()).map_err(|_| BridgeError::StateFailed)?;
        }
    }
    Ok(())
}

fn validate_stale_tree_for_cleanup(
    directory: &Path,
    depth: usize,
    count: &mut usize,
    deadline: Instant,
) -> Result<(), BridgeError> {
    if depth > MAX_STATE_DEPTH {
        return Err(BridgeError::StateCorrupt);
    }
    for entry in fs::read_dir(directory).map_err(|_| BridgeError::StateCorrupt)? {
        check_deadline(deadline)?;
        let entry = entry.map_err(|_| BridgeError::StateCorrupt)?;
        *count = count.checked_add(1).ok_or(BridgeError::StateCorrupt)?;
        if *count > MAX_STATE_ENTRIES {
            return Err(BridgeError::StateCorrupt);
        }
        let file_type = entry.file_type().map_err(|_| BridgeError::StateCorrupt)?;
        if file_type.is_dir() {
            validate_stale_tree_for_cleanup(&entry.path(), depth + 1, count, deadline)?;
        }
    }
    Ok(())
}

fn copy_tree(source: &Path, destination: &Path, deadline: Instant) -> Result<(), BridgeError> {
    validate_generation_tree_until(source, Some(deadline))?;
    let mut count = 0usize;
    let mut total = 0u64;
    copy_directory(source, destination, &mut count, &mut total, 0, deadline)
}

fn copy_directory(
    source: &Path,
    destination: &Path,
    count: &mut usize,
    total: &mut u64,
    depth: usize,
    deadline: Instant,
) -> Result<(), BridgeError> {
    if depth > MAX_STATE_DEPTH {
        return Err(BridgeError::StateCorrupt);
    }
    for entry in fs::read_dir(source).map_err(|_| BridgeError::StateCorrupt)? {
        check_deadline(deadline)?;
        let entry = entry.map_err(|_| BridgeError::StateCorrupt)?;
        *count = count.checked_add(1).ok_or(BridgeError::StateCorrupt)?;
        if *count > MAX_STATE_ENTRIES {
            return Err(BridgeError::StateCorrupt);
        }
        let metadata = entry.metadata().map_err(|_| BridgeError::StateCorrupt)?;
        let file_type = entry.file_type().map_err(|_| BridgeError::StateCorrupt)?;
        let target = destination.join(entry.file_name());
        if file_type.is_symlink() || metadata.uid() != current_uid() {
            return Err(BridgeError::InvalidPath);
        }
        if file_type.is_dir() {
            fs::DirBuilder::new()
                .mode(DIRECTORY_MODE)
                .create(&target)
                .map_err(|_| BridgeError::StateFailed)?;
            fs::set_permissions(&target, Permissions::from_mode(DIRECTORY_MODE))
                .map_err(|_| BridgeError::StateFailed)?;
            copy_directory(&entry.path(), &target, count, total, depth + 1, deadline)?;
        } else if file_type.is_file()
            && metadata.nlink() == 1
            && metadata.len() <= MAX_STATE_FILE_BYTES
        {
            let mut input = open_regular_file(&entry.path())?;
            let mut output = fs::OpenOptions::new()
                .create_new(true)
                .write(true)
                .mode(FILE_MODE)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(&target)
                .map_err(|_| BridgeError::StateFailed)?;
            output
                .set_permissions(Permissions::from_mode(FILE_MODE))
                .map_err(|_| BridgeError::StateFailed)?;
            let remaining = MAX_STATE_TOTAL_BYTES
                .checked_sub(*total)
                .ok_or(BridgeError::StateCorrupt)?
                .min(MAX_STATE_FILE_BYTES);
            let copied = copy_bounded(&mut input, &mut output, remaining)?;
            *total = total.checked_add(copied).ok_or(BridgeError::StateCorrupt)?;
            output.sync_all().map_err(|_| BridgeError::StateFailed)?;
        } else {
            return Err(BridgeError::StateCorrupt);
        }
    }
    Ok(())
}

fn copy_bounded(
    input: &mut impl std::io::Read,
    output: &mut impl std::io::Write,
    maximum: u64,
) -> Result<u64, BridgeError> {
    let limit = maximum.saturating_add(1);
    let mut copied = 0u64;
    let mut buffer = Zeroizing::new([0u8; 8192]);
    while copied < limit {
        let remaining = usize::try_from((limit - copied).min(buffer.len() as u64))
            .map_err(|_| BridgeError::StateFailed)?;
        let count = input
            .read(&mut buffer[..remaining])
            .map_err(|_| BridgeError::StateFailed)?;
        if count == 0 {
            break;
        }
        output
            .write_all(&buffer[..count])
            .map_err(|_| BridgeError::StateFailed)?;
        copied = copied
            .checked_add(u64::try_from(count).map_err(|_| BridgeError::StateFailed)?)
            .ok_or(BridgeError::StateCorrupt)?;
    }
    if copied > maximum {
        return Err(BridgeError::StateCorrupt);
    }
    Ok(copied)
}

fn validate_generation_tree_until(
    root: &Path,
    deadline: Option<Instant>,
) -> Result<(), BridgeError> {
    check_optional_deadline(deadline)?;
    validate_private_directory(root)?;
    let mut count = 0usize;
    let mut total = 0u64;
    validate_directory_entries(root, &mut count, &mut total, 0, deadline)
}

fn validate_directory_entries(
    directory: &Path,
    count: &mut usize,
    total: &mut u64,
    depth: usize,
    deadline: Option<Instant>,
) -> Result<(), BridgeError> {
    if depth > MAX_STATE_DEPTH {
        return Err(BridgeError::StateCorrupt);
    }
    for entry in fs::read_dir(directory).map_err(|_| BridgeError::StateCorrupt)? {
        check_optional_deadline(deadline)?;
        let entry = entry.map_err(|_| BridgeError::StateCorrupt)?;
        *count += 1;
        if *count > MAX_STATE_ENTRIES {
            return Err(BridgeError::StateCorrupt);
        }
        let file_type = entry.file_type().map_err(|_| BridgeError::StateCorrupt)?;
        let metadata = entry.metadata().map_err(|_| BridgeError::StateCorrupt)?;
        if file_type.is_symlink() || metadata.uid() != current_uid() {
            return Err(BridgeError::InvalidPath);
        }
        if file_type.is_dir() {
            if metadata.mode() & 0o777 != DIRECTORY_MODE {
                return Err(BridgeError::InvalidPath);
            }
            validate_directory_entries(&entry.path(), count, total, depth + 1, deadline)?;
        } else if file_type.is_file()
            && metadata.mode() & 0o777 == FILE_MODE
            && metadata.nlink() == 1
            && metadata.len() <= MAX_STATE_FILE_BYTES
        {
            *total = total
                .checked_add(metadata.len())
                .ok_or(BridgeError::StateCorrupt)?;
            if *total > MAX_STATE_TOTAL_BYTES {
                return Err(BridgeError::StateCorrupt);
            }
        } else {
            return Err(BridgeError::InvalidPath);
        }
    }
    Ok(())
}

fn sync_tree_until(root: &Path, deadline: Option<Instant>) -> Result<(), BridgeError> {
    validate_generation_tree_until(root, deadline)?;
    for entry in fs::read_dir(root).map_err(|_| BridgeError::StateFailed)? {
        check_optional_deadline(deadline)?;
        let entry = entry.map_err(|_| BridgeError::StateFailed)?;
        if entry
            .file_type()
            .map_err(|_| BridgeError::StateFailed)?
            .is_dir()
        {
            sync_tree_until(&entry.path(), deadline)?;
        } else {
            File::open(entry.path())
                .and_then(|file| file.sync_all())
                .map_err(|_| BridgeError::StateFailed)?;
        }
    }
    sync_directory(root)
}

fn check_deadline(deadline: Instant) -> Result<(), BridgeError> {
    if Instant::now() >= deadline {
        Err(BridgeError::TimedOut)
    } else {
        Ok(())
    }
}

fn check_optional_deadline(deadline: Option<Instant>) -> Result<(), BridgeError> {
    deadline.map_or(Ok(()), check_deadline)
}

fn sync_directory(path: &Path) -> Result<(), BridgeError> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| BridgeError::StateFailed)
}

fn format_uuid(bytes: [u8; 16]) -> String {
    let hex = encode_hex_upper(bytes);
    format!(
        "{}-{}-{}-{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    )
}

/// Resolves every existing ancestor and normalizes the not-yet-created tail.
///
/// This preserves ordinary XDG layouts whose existing base is a symbolic link
/// while `secure_create_chain` still rejects any replacement introduced after
/// construction.
fn effective_path(path: &Path) -> PathBuf {
    let components: Vec<Component<'_>> = path.components().collect();
    for split in (1..=components.len()).rev() {
        let prefix: PathBuf = components[..split].iter().collect();
        if let Ok(resolved) = prefix.canonicalize() {
            return extend_lexically(resolved, &components[split..]);
        }
    }
    extend_lexically(PathBuf::new(), &components)
}

fn extend_lexically(mut base: PathBuf, components: &[Component<'_>]) -> PathBuf {
    for component in components {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                base.pop();
            }
            other => base.push(other.as_os_str()),
        }
    }
    base
}

fn encode_hex_upper(bytes: impl AsRef<[u8]>) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let bytes = bytes.as_ref();
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

#[cfg(test)]
#[allow(unsafe_code)]
mod tests {
    use super::*;

    fn store(root: &tempfile::TempDir) -> ProvisioningStore {
        ProvisioningStore::from_paths(&BootstrapPaths::rooted_at(root.path())).expect("store")
    }

    fn prepare(store: &ProvisioningStore) -> Result<PreparedGeneration, BridgeError> {
        store.prepare(Instant::now() + Duration::from_secs(5))
    }

    #[test]
    fn identifiers_use_the_upstream_byte_exact_convention() {
        let bytes = Zeroizing::new((0u8..16).collect());
        let identity = DeviceIdentifiers::from_bytes(bytes).expect("identity");
        assert_eq!(
            identity.device_identifier(),
            "00010203-0405-0607-0809-0A0B0C0D0E0F"
        );
        assert_eq!(identity.android_id().expose(), b"00010203-0405-06");
        assert_eq!(
            identity.local_user_id().expose(),
            "BE45CB2605BF36BEBDE684841A28F0FD43C69850A3DCE5FEDBA69928EE3A8991"
        );
        assert_eq!(identity.routing_info(), "17106176");
        assert_eq!(identity.serial_number(), "0");
        assert_eq!(format!("{identity:?}"), "DeviceIdentifiers(<redacted>)");
    }

    #[test]
    fn state_copy_stops_after_one_byte_beyond_its_actual_limit() {
        let mut input = std::io::Cursor::new(b"growing-state".to_vec());
        let mut output = Vec::new();
        assert_eq!(
            copy_bounded(&mut input, &mut output, 3),
            Err(BridgeError::StateCorrupt)
        );
        assert_eq!(output, b"grow");
    }

    #[test]
    fn generation_validation_rejects_aggregate_state_over_sixty_four_mib() {
        let generation = tempfile::tempdir().expect("generation");
        fs::set_permissions(generation.path(), Permissions::from_mode(DIRECTORY_MODE))
            .expect("generation mode");
        for index in 0..5 {
            let file = File::create(generation.path().join(format!("state-{index}")))
                .expect("sparse state");
            file.set_len(MAX_STATE_FILE_BYTES).expect("sparse length");
            file.set_permissions(Permissions::from_mode(FILE_MODE))
                .expect("state mode");
        }
        assert_eq!(
            validate_generation_tree_until(generation.path(), None),
            Err(BridgeError::StateCorrupt)
        );
    }

    #[test]
    fn root_and_generation_reject_symlink_file_public_mode_and_arbitrary_root() {
        let root = tempfile::tempdir().expect("root");
        let store = store(&root);
        let prepared = prepare(&store).expect("prepare");
        let arbitrary = root.path().join("arbitrary");
        fs::create_dir(&arbitrary).expect("arbitrary");
        fs::set_permissions(&arbitrary, Permissions::from_mode(0o700)).expect("mode");
        assert_eq!(
            validate_staging_path(&store.root, &arbitrary),
            Err(BridgeError::InvalidPath)
        );
        drop(prepared);

        fs::set_permissions(&store.root, Permissions::from_mode(0o750)).expect("public root");
        assert_eq!(prepare(&store).err(), Some(BridgeError::InvalidPath));
        fs::set_permissions(&store.root, Permissions::from_mode(0o700)).expect("private root");
        fs::remove_dir_all(&store.root).expect("remove root");
        fs::write(&store.root, b"file").expect("replace with file");
        assert_eq!(prepare(&store).err(), Some(BridgeError::InvalidPath));
        fs::remove_file(&store.root).expect("remove file");
        let target = root.path().join("target");
        fs::create_dir(&target).expect("target");
        std::os::unix::fs::symlink(&target, &store.root).expect("symlink root");
        assert_eq!(prepare(&store).err(), Some(BridgeError::InvalidPath));
    }

    #[test]
    fn existing_xdg_symlink_is_resolved_before_the_store_is_bound() {
        let root = tempfile::tempdir().expect("root");
        let outside = tempfile::tempdir().expect("outside");
        let linked_parent = root.path().join("linked");
        std::os::unix::fs::symlink(outside.path(), &linked_parent).expect("symlink parent");
        let paths = BootstrapPaths::rooted_at(&linked_parent.join("layout"));
        let store = ProvisioningStore::from_paths(&paths).expect("store");
        assert!(
            store
                .root
                .starts_with(outside.path().canonicalize().expect("outside"))
        );
        drop(prepare(&store).expect("resolved XDG base"));
    }

    #[test]
    fn missing_parent_replaced_by_a_symlink_after_binding_is_rejected() {
        let root = tempfile::tempdir().expect("root");
        let outside = tempfile::tempdir().expect("outside");
        let linked_parent = root.path().join("linked");
        let paths = BootstrapPaths::rooted_at(&linked_parent.join("layout"));
        let store = ProvisioningStore::from_paths(&paths).expect("store");
        std::os::unix::fs::symlink(outside.path(), &linked_parent).expect("symlink parent");
        assert_eq!(prepare(&store).err(), Some(BridgeError::InvalidPath));
        assert!(!outside.path().join("layout").exists());
    }

    #[test]
    fn ownership_check_rejects_a_uid_other_than_the_current_user() {
        let root = tempfile::tempdir().expect("root");
        let store = store(&root);
        let prepared = prepare(&store).expect("prepare");
        let metadata = fs::metadata(prepared.path()).expect("metadata");
        assert_eq!(
            validate_private_directory_for_uid(prepared.path(), metadata.uid().wrapping_add(1)),
            Err(BridgeError::InvalidPath)
        );
    }

    #[test]
    fn open_capability_detects_path_replacement() {
        let root = tempfile::tempdir().expect("root");
        let store = store(&root);
        let prepared = prepare(&store).expect("prepare");
        let original = prepared.path().to_owned();
        let displaced = original.with_extension("displaced");
        fs::rename(&original, &displaced).expect("displace");
        fs::create_dir(&original).expect("replacement");
        fs::set_permissions(&original, Permissions::from_mode(0o700)).expect("mode");
        assert_eq!(prepared.publish(), Err(BridgeError::InvalidPath));
    }

    #[test]
    fn successful_publication_is_atomic_and_preserves_previous_generation() {
        let root = tempfile::tempdir().expect("root");
        let store = store(&root);
        let first = prepare(&store).expect("first");
        fs::write(first.path().join("adi.pb"), b"old").expect("old state");
        fs::set_permissions(first.path().join("adi.pb"), Permissions::from_mode(0o600))
            .expect("mode");
        first.publish().expect("publish first");
        let old = fs::read_to_string(store.root.join(ACTIVE_FILE)).expect("old pointer");

        let second = prepare(&store).expect("second");
        assert_eq!(
            fs::read(second.path().join("adi.pb")).expect("copied"),
            b"old"
        );
        fs::write(second.path().join("adi.pb"), b"new").expect("new state");
        fs::set_permissions(second.path().join("adi.pb"), Permissions::from_mode(0o600))
            .expect("mode");
        second.publish().expect("publish second");
        let new = fs::read_to_string(store.root.join(ACTIVE_FILE)).expect("new pointer");
        assert_ne!(old, new);
        assert_eq!(
            fs::read(
                store
                    .root
                    .join(GENERATIONS_DIRECTORY)
                    .join(old)
                    .join("adi.pb")
            )
            .expect("old generation"),
            b"old"
        );
    }

    #[test]
    fn publication_retains_one_rollback_and_erasure_prunes_every_predecessor() {
        let root = tempfile::tempdir().expect("root");
        let store = store(&root);
        let mut published = Vec::new();
        for contents in [b"first".as_slice(), b"second", b"third"] {
            let generation = prepare(&store).expect("prepare");
            fs::write(generation.path().join("adi.pb"), contents).expect("state");
            fs::set_permissions(
                generation.path().join("adi.pb"),
                Permissions::from_mode(FILE_MODE),
            )
            .expect("mode");
            generation.publish().expect("publish");
            published.push(fs::read_to_string(store.root.join(ACTIVE_FILE)).expect("active"));
        }
        let generation_names = fs::read_dir(store.root.join(GENERATIONS_DIRECTORY))
            .expect("generations")
            .map(|entry| {
                entry
                    .expect("entry")
                    .file_name()
                    .into_string()
                    .expect("UTF-8 name")
            })
            .collect::<Vec<_>>();
        assert_eq!(generation_names.len(), 2);
        assert!(!generation_names.contains(&published[0]));
        assert!(generation_names.contains(&published[1]));
        assert!(generation_names.contains(&published[2]));

        let erased = prepare(&store).expect("erase staging");
        fs::remove_file(erased.path().join("adi.pb")).expect("erase state");
        erased.publish_erasing().expect("publish erasure");
        assert_eq!(
            fs::read_dir(store.root.join(GENERATIONS_DIRECTORY))
                .expect("generations")
                .count(),
            1
        );
    }

    #[test]
    fn active_pointer_accepts_the_documented_maximum_name_without_truncation() {
        let root = tempfile::tempdir().expect("root");
        let store = store(&root);
        drop(prepare(&store).expect("initialize"));
        let name = format!(".generation-{}", "a".repeat(68));
        assert_eq!(name.len(), MAX_GENERATION_NAME_BYTES);
        let generation = store.root.join(GENERATIONS_DIRECTORY).join(&name);
        fs::create_dir(&generation).expect("generation");
        fs::set_permissions(&generation, Permissions::from_mode(0o700)).expect("mode");
        fs::write(store.root.join(ACTIVE_FILE), name).expect("active");
        fs::set_permissions(
            store.root.join(ACTIVE_FILE),
            Permissions::from_mode(FILE_MODE),
        )
        .expect("active mode");
        drop(prepare(&store).expect("maximum-length active generation"));
    }

    #[test]
    fn active_pointer_rejects_a_name_past_the_documented_bound() {
        let root = tempfile::tempdir().expect("root");
        let store = store(&root);
        drop(prepare(&store).expect("initialize"));
        fs::write(
            store.root.join(ACTIVE_FILE),
            format!(".generation-{}", "a".repeat(69)),
        )
        .expect("active");
        fs::set_permissions(
            store.root.join(ACTIVE_FILE),
            Permissions::from_mode(FILE_MODE),
        )
        .expect("active mode");
        assert_eq!(prepare(&store).err(), Some(BridgeError::StateCorrupt));
    }

    #[test]
    fn publication_rejects_non_private_and_hard_linked_files() {
        let root = tempfile::tempdir().expect("root");
        let store = store(&root);
        let public = prepare(&store).expect("public");
        fs::write(public.path().join("state"), b"public").expect("state");
        assert_eq!(public.publish(), Err(BridgeError::InvalidPath));

        let linked = prepare(&store).expect("linked");
        let first = linked.path().join("first");
        fs::write(&first, b"linked").expect("first");
        fs::set_permissions(&first, Permissions::from_mode(0o600)).expect("mode");
        fs::hard_link(&first, linked.path().join("second")).expect("hard link");
        assert_eq!(linked.publish(), Err(BridgeError::InvalidPath));
    }

    #[test]
    fn normalized_native_modes_remain_copyable_and_prunable() {
        let root = tempfile::tempdir().expect("root");
        let store = store(&root);
        let prepared = prepare(&store).expect("prepared");
        let directory = prepared.path().join("native");
        fs::create_dir(&directory).expect("directory");
        fs::set_permissions(&directory, Permissions::from_mode(DIRECTORY_MODE))
            .expect("directory mode");
        let file = directory.join("state");
        fs::write(&file, b"private").expect("state");
        fs::set_permissions(&file, Permissions::from_mode(FILE_MODE)).expect("file mode");
        prepared.publish().expect("publish normalized modes");

        let second = prepare(&store).expect("copy normalized state");
        assert_eq!(
            fs::read(second.path().join("native/state")).expect("copied"),
            b"private"
        );
        second.publish().expect("publish second");
        let third = prepare(&store).expect("prune oldest generation");
        third.publish().expect("publish third");
        assert_eq!(
            fs::read_dir(store.root.join(GENERATIONS_DIRECTORY))
                .expect("generations")
                .count(),
            2
        );
    }

    #[test]
    fn active_pointer_symlink_is_rejected_without_touching_its_target() {
        let root = tempfile::tempdir().expect("root");
        let store = store(&root);
        let prepared = prepare(&store).expect("prepared");
        let target = root.path().join("outside");
        fs::write(&target, b"unchanged").expect("target");
        std::os::unix::fs::symlink(&target, store.root.join(ACTIVE_FILE)).expect("active link");
        assert_eq!(prepared.publish(), Err(BridgeError::InvalidPath));
        assert_eq!(fs::read(target).expect("target"), b"unchanged");
    }

    #[test]
    fn dropped_or_failed_staging_never_replaces_active_state() {
        let root = tempfile::tempdir().expect("root");
        let store = store(&root);
        let first = prepare(&store).expect("first");
        fs::write(first.path().join("adi.pb"), b"good").expect("state");
        fs::set_permissions(first.path().join("adi.pb"), Permissions::from_mode(0o600))
            .expect("mode");
        first.publish().expect("publish");
        let active = fs::read(store.root.join(ACTIVE_FILE)).expect("active");
        {
            let interrupted = prepare(&store).expect("interrupted");
            fs::write(interrupted.path().join("partial"), b"partial").expect("partial");
        }
        assert_eq!(
            fs::read(store.root.join(ACTIVE_FILE)).expect("active"),
            active
        );
    }

    #[test]
    fn rename_failure_removes_the_secret_bearing_staging_tree() {
        let root = tempfile::tempdir().expect("root");
        let store = store(&root);
        let prepared = prepare(&store).expect("prepared");
        let staging = prepared.path().to_owned();
        let state = staging.join("state");
        fs::write(&state, b"secret-state").expect("state");
        fs::set_permissions(&state, Permissions::from_mode(FILE_MODE)).expect("state mode");
        let generations = store.root.join(GENERATIONS_DIRECTORY);
        fs::set_permissions(&generations, Permissions::from_mode(0o500)).expect("block rename");
        assert_eq!(prepared.publish(), Err(BridgeError::StateFailed));
        assert!(!staging.exists());
        fs::set_permissions(&generations, Permissions::from_mode(DIRECTORY_MODE))
            .expect("restore mode");
    }

    #[test]
    fn lock_wait_obeys_the_same_absolute_deadline() {
        let root = tempfile::tempdir().expect("root");
        let store = store(&root);
        let first = prepare(&store).expect("first");
        let started = Instant::now();
        assert_eq!(
            store.prepare(started + Duration::from_millis(50)).err(),
            Some(BridgeError::TimedOut)
        );
        assert!(started.elapsed() < Duration::from_secs(1));
        drop(first);
    }

    #[test]
    fn existing_identifier_is_read_without_waiting_for_a_generation_lock() {
        let root = tempfile::tempdir().expect("root");
        let store = Arc::new(store(&root));
        drop(store.identifiers().expect("initialize identifier"));
        let prepared = prepare(&store).expect("hold generation lock");
        let reader = Arc::clone(&store);
        let (send, receive) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || {
            send.send(reader.identifiers().is_ok()).expect("result");
        });
        let result = receive.recv_timeout(Duration::from_millis(250));
        drop(prepared);
        worker.join().expect("reader");
        assert_eq!(result, Ok(true));
    }

    #[test]
    fn existing_identifier_rejects_a_replaced_root_while_the_lock_is_held() {
        let root = tempfile::tempdir().expect("root");
        let store = store(&root);
        drop(store.identifiers().expect("initialize identifier"));
        let prepared = prepare(&store).expect("hold generation lock");
        let original = root.path().join("original-provisioning");
        fs::rename(&store.root, &original).expect("move bound root");
        let replacement = root.path().join("replacement-provisioning");
        fs::create_dir(&replacement).expect("replacement root");
        fs::set_permissions(&replacement, Permissions::from_mode(DIRECTORY_MODE))
            .expect("replacement root mode");
        let replacement_identifier = replacement.join(IDENTIFIER_FILE);
        fs::write(&replacement_identifier, [0x5au8; IDENTIFIER_BYTES])
            .expect("replacement identifier");
        fs::set_permissions(&replacement_identifier, Permissions::from_mode(FILE_MODE))
            .expect("replacement identifier mode");
        std::os::unix::fs::symlink(&replacement, &store.root).expect("replace root with symlink");

        let started = Instant::now();
        assert_eq!(store.identifiers().err(), Some(BridgeError::InvalidPath));
        assert!(started.elapsed() < Duration::from_millis(250));
        assert_eq!(
            fs::read(&replacement_identifier).expect("replacement remains untouched"),
            [0x5au8; IDENTIFIER_BYTES]
        );

        fs::remove_file(&store.root).expect("remove replacement symlink");
        fs::rename(&original, &store.root).expect("restore bound root");
        drop(prepared);
    }

    #[test]
    fn restrictive_inherited_umask_still_produces_canonical_directories() {
        const CHILD: &str = "COFFER_RESTRICTIVE_UMASK_CHILD";
        if std::env::var_os(CHILD).is_some() {
            let root = tempfile::tempdir().expect("root");
            // SAFETY: this test runs alone in a dedicated child process and
            // restores the process mask before returning.
            let previous = unsafe { libc::umask(0o777) };
            let store = store(&root);
            drop(store.identifiers().expect("identifier under strict mask"));
            let prepared = prepare(&store).expect("prepare under strict mask");
            assert_eq!(
                fs::metadata(&store.root).expect("root mode").mode() & 0o777,
                DIRECTORY_MODE
            );
            for basename in [LOCK_FILE, IDENTIFIER_FILE] {
                assert_eq!(
                    fs::metadata(store.root.join(basename))
                        .expect("private file mode")
                        .mode()
                        & 0o777,
                    FILE_MODE
                );
            }
            assert_eq!(
                fs::metadata(prepared.path()).expect("staging mode").mode() & 0o777,
                DIRECTORY_MODE
            );
            prepared.publish().expect("publish under strict mask");
            assert_eq!(
                fs::metadata(store.root.join(ACTIVE_FILE))
                    .expect("active mode")
                    .mode()
                    & 0o777,
                FILE_MODE
            );
            // SAFETY: restore the mask captured above before normal teardown.
            unsafe { libc::umask(previous) };
            return;
        }
        let status = std::process::Command::new(std::env::current_exe().expect("test executable"))
            .args([
                "--exact",
                "state::tests::restrictive_inherited_umask_still_produces_canonical_directories",
            ])
            .env(CHILD, "1")
            .status()
            .expect("child test");
        assert!(status.success());
    }

    #[test]
    fn lock_serializes_concurrent_writers() {
        let root = tempfile::tempdir().expect("root");
        let store = std::sync::Arc::new(store(&root));
        let first = prepare(&store).expect("first");
        let second_store = std::sync::Arc::clone(&store);
        let (send, receive) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || {
            let second = prepare(&second_store).expect("second");
            send.send(()).expect("signal");
            drop(second);
        });
        assert!(
            receive
                .recv_timeout(std::time::Duration::from_millis(100))
                .is_err()
        );
        drop(first);
        receive
            .recv_timeout(std::time::Duration::from_secs(2))
            .expect("released");
        worker.join().expect("join");
    }
}
