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

//! Durable, non-secret profile-slot metadata under `XDG_STATE_HOME`.
//!
//! A [`SessionSlot`] is sixteen random bytes that
//! name the Secret Service item holding a reusable session.  The service crate
//! deliberately does not export the bytes of a slot, so this module owns them
//! instead: the harness draws the bytes from the OS CSPRNG, writes them to a
//! small file of fixed shape, and rebuilds the slot from that file on the
//! next run.  The slot is opaque metadata: it is unrelated to the Apple
//! Account, and neither the account name nor any hash of it appears in the
//! file name or contents.
//!
//! # File format, version 1
//!
//! ```text
//! coffer-live-auth-profile-slot/1\n
//! <32 lowercase hexadecimal digits>\n
//! ```
//!
//! Exactly 65 bytes.  Any other length or content is corrupt and the harness
//! stops; it never replaces existing state on its own, because a slot that is
//! silently regenerated would strand the Secret Service item the old one
//! named.
//!
//! # Filesystem policy
//!
//! - The directory `$XDG_STATE_HOME/coffer/live-auth` is created with mode
//!   `0700` and must stay a real directory with exactly that mode.
//! - The file `profile-slot` must be a regular file with mode `0600`.
//! - Every step after the XDG state home itself works on file descriptors:
//!   the two directories Coffer owns are opened with `O_DIRECTORY |
//!   O_NOFOLLOW` and kept open, the file is opened relative to that directory
//!   with `O_NOFOLLOW`, and the same descriptor is `fstat`ed and read through
//!   a hard byte ceiling.  A symbolic link at any of those components is
//!   refused, and a swap between the check and the read is impossible because
//!   no path is resolved twice.
//! - Creation is atomic and race-safe: the bytes go to a private temporary
//!   file that is fsynced, then published with `linkat(2)`, which fails if
//!   another process published first, in which case that process's slot is
//!   adopted.  The directory is fsynced after publication.

use core::fmt;
use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::{AsFd, OwnedFd};
use std::path::{Path, PathBuf};

use coffer_protocol::entropy::Entropy;
use coffer_service::{SESSION_SLOT_LEN, SessionSlot};
use rustix::fs::{
    AtFlags, CWD, FileType, Mode, OFlags, fstat, fsync, linkat, mkdirat, openat, unlinkat,
};
use rustix::io::Errno;

use crate::entropy::random_array;

/// Version tag on the first line of the state file.
const HEADER: &str = "coffer-live-auth-profile-slot/1";
/// Exact size of a valid state file in bytes.
const FILE_LEN: usize = HEADER.len() + 1 + SESSION_SLOT_LEN * 2 + 1;
/// Application directory under the XDG state home.
const APPLICATION_DIRECTORY: &str = "coffer";
/// Harness directory under the application directory.
const HARNESS_DIRECTORY: &str = "live-auth";
/// Name of the state file.
const FILE_NAME: &str = "profile-slot";
/// Prefix of the private temporary file used during creation.
const TEMP_PREFIX: &str = ".profile-slot.tmp-";
/// Required mode of the state directory.
const DIRECTORY_MODE: u32 = 0o700;
/// Required mode of the state file.
const FILE_MODE: u32 = 0o600;
/// Largest file the loader will read; anything past this is corrupt anyway.
const READ_CEILING: u64 = 4096;

/// Why the slot state could not be used.
///
/// No variant carries a path or file contents.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SlotStateError {
    /// Neither `XDG_STATE_HOME` nor `HOME` yields an absolute base directory.
    NoStateHome,
    /// The state directory or a parent is a symbolic link or not a directory.
    DirectoryNotPlain,
    /// The state directory does not have mode `0700`.
    DirectoryMode,
    /// The state file is a symbolic link or not a regular file.
    FileNotPlain,
    /// The state file does not have mode `0600`.
    FileMode,
    /// The state file exists but does not have the exact version-1 shape.
    Corrupt,
    /// Existing profile state is absent; load-only mode never creates it.
    Missing,
    /// The selected new profile already exists; it is never adopted.
    Occupied,
    /// A new profile label is missing or invalid.
    InvalidProfile,
    /// The random source failed.
    Entropy,
    /// A filesystem operation failed for another reason.
    Io,
}

impl SlotStateError {
    /// A fixed description; every variant maps to a string literal.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::NoStateHome => "no XDG state home could be resolved",
            Self::DirectoryNotPlain => "profile state directory is not a plain directory",
            Self::DirectoryMode => "profile state directory is not mode 0700",
            Self::FileNotPlain => "profile slot file is not a regular file",
            Self::FileMode => "profile slot file is not mode 0600",
            Self::Corrupt => "profile slot file is corrupt; it is not replaced automatically",
            Self::Missing => "existing profile state is missing",
            Self::Occupied => "new profile already exists; no retry or replacement",
            Self::InvalidProfile => "new profile label rejected",
            Self::Entropy => "profile slot could not be generated",
            Self::Io => "profile slot state I/O failed",
        }
    }
}

impl fmt::Display for SlotStateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

impl std::error::Error for SlotStateError {}

/// Whether the slot was found or freshly created.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlotOrigin {
    /// A valid existing file was reused.
    Reused,
    /// A new slot was generated and published by this call.
    Created,
    /// This call generated a slot but another process published first; the
    /// other process's slot was adopted.
    AdoptedFromRace,
}

/// The slot state directory for one harness profile.
#[derive(Clone, PartialEq, Eq)]
pub struct SlotState {
    state_home: PathBuf,
    profile: Option<String>,
}

impl fmt::Debug for SlotState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SlotState(<path redacted>)")
    }
}

impl SlotState {
    /// Resolves `$XDG_STATE_HOME/coffer/live-auth` from the environment.
    ///
    /// `XDG_STATE_HOME` is honored when absolute; otherwise
    /// `$HOME/.local/state` is used, as the XDG Base Directory Specification
    /// requires.
    ///
    /// # Errors
    ///
    /// Returns [`SlotStateError::NoStateHome`] when no absolute base exists.
    pub fn from_environment() -> Result<Self, SlotStateError> {
        let base = resolve_state_home(
            std::env::var_os("XDG_STATE_HOME").as_deref(),
            std::env::var_os("HOME").as_deref(),
        )?;
        Ok(Self::under_state_home(&base))
    }

    /// Places the state directory under an explicit XDG state home.
    #[must_use]
    pub fn under_state_home(state_home: &Path) -> Self {
        Self {
            state_home: state_home.to_path_buf(),
            profile: None,
        }
    }

    /// Selects a separate developer profile without changing anisette's XDG home.
    ///
    /// The label must be non-secret, 1..=32 lowercase ASCII letters, digits or
    /// hyphens. It is local metadata, never an Apple Account identifier.
    /// Construction performs no I/O. Call [`Self::create_new`] to reserve it.
    ///
    /// # Errors
    /// Returns [`SlotStateError::InvalidProfile`] for any other label.
    pub fn new_profile(mut self, label: &str) -> Result<Self, SlotStateError> {
        if label.is_empty()
            || label.len() > 32
            || !label
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        {
            return Err(SlotStateError::InvalidProfile);
        }
        self.profile = Some(label.to_owned());
        Ok(self)
    }

    /// Exclusively reserves a new profile before credential input or authentication.
    ///
    /// Creates a mode-0700 directory and publishes one random mode-0600 slot.
    /// An existing directory, even empty or corrupt, is never adopted. The
    /// reservation remains after any later failure or declined confirmation;
    /// there is no automatic cleanup, new slot, or alternate profile attempt.
    ///
    /// # Errors
    /// Returns [`SlotStateError::Occupied`] if another invocation reserved the
    /// label first. Other failures preserve all existing state and may leave
    /// an empty reservation. The default profile cannot be reserved this way.
    pub fn create_new(&self, entropy: &impl Entropy) -> Result<SessionSlot, SlotStateError> {
        let label = self
            .profile
            .as_deref()
            .ok_or(SlotStateError::InvalidProfile)?;
        let directory = self.open_directory()?;
        let profiles = create_and_open_plain_directory(&directory, "profiles")?;
        mkdirat(&profiles, label, Mode::from_raw_mode(DIRECTORY_MODE)).map_err(|error| {
            if error == Errno::EXIST {
                SlotStateError::Occupied
            } else {
                SlotStateError::Io
            }
        })?;
        fsync(&profiles).map_err(|_| SlotStateError::Io)?;
        let reserved = open_plain_directory(&profiles, label)?;
        let bytes = random_array(entropy).map_err(|_| SlotStateError::Entropy)?;
        if !publish(&reserved, &bytes)? {
            return Err(SlotStateError::Occupied);
        }
        load_existing(&reserved)?.ok_or(SlotStateError::Io)
    }

    /// Loads an existing slot without creating directories or drawing entropy.
    ///
    /// # Errors
    /// Returns [`SlotStateError::Missing`] when any component is absent, or the
    /// same path/mode/format errors as `load_or_create`. Nothing is repaired.
    pub fn load(&self) -> Result<SessionSlot, SlotStateError> {
        let base = openat(
            CWD,
            &self.state_home,
            OFlags::DIRECTORY | OFlags::RDONLY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|e| {
            if e == Errno::NOENT {
                SlotStateError::Missing
            } else {
                SlotStateError::Io
            }
        })?;
        let application = open_plain_directory(&base, APPLICATION_DIRECTORY)?;
        let directory = open_plain_directory(&application, HARNESS_DIRECTORY)?;
        let directory = if let Some(label) = &self.profile {
            let profiles = open_plain_directory(&directory, "profiles")?;
            open_plain_directory(&profiles, label)?
        } else {
            directory
        };
        load_existing(&directory)?.ok_or(SlotStateError::Missing)
    }

    /// Returns the existing default slot or creates one.
    ///
    /// Explicit named profiles must use [`Self::create_new`]; this method
    /// rejects them with [`SlotStateError::InvalidProfile`].
    ///
    /// # Errors
    ///
    /// Fails closed on any policy violation: a symbolic link, a wrong mode, a
    /// corrupt file, or an entropy failure.  Nothing is deleted or rewritten
    /// on an error path.
    pub fn load_or_create(
        &self,
        entropy: &impl Entropy,
    ) -> Result<(SessionSlot, SlotOrigin), SlotStateError> {
        if self.profile.is_some() {
            return Err(SlotStateError::InvalidProfile);
        }
        let directory = self.open_directory()?;
        if let Some(slot) = load_existing(&directory)? {
            return Ok((slot, SlotOrigin::Reused));
        }
        let bytes: [u8; SESSION_SLOT_LEN] =
            random_array(entropy).map_err(|_| SlotStateError::Entropy)?;
        let published = publish(&directory, &bytes)?;
        // Read back through the same validating path and the same directory
        // descriptor, so that what the harness uses is exactly what is on
        // disk.
        let slot = load_existing(&directory)?.ok_or(SlotStateError::Io)?;
        Ok((
            slot,
            if published {
                SlotOrigin::Created
            } else {
                SlotOrigin::AdoptedFromRace
            },
        ))
    }

    /// Opens the state directory, creating it when absent, and verifies it.
    ///
    /// The XDG state home is opened by path once; from there every component
    /// Coffer owns is created and opened relative to its parent descriptor
    /// with `O_NOFOLLOW`, so an intermediate symbolic link is refused rather
    /// than followed.
    fn open_directory(&self) -> Result<OwnedFd, SlotStateError> {
        let base = openat(
            CWD,
            &self.state_home,
            OFlags::DIRECTORY | OFlags::RDONLY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| SlotStateError::Io)?;
        let application = create_and_open_plain_directory(&base, APPLICATION_DIRECTORY)?;
        let directory = create_and_open_plain_directory(&application, HARNESS_DIRECTORY)?;
        Ok(directory)
    }
}

/// Creates `name` under `parent` if absent, opens it without following a
/// symbolic link in its place, and verifies on the opened descriptor that it
/// is a directory with exactly [`DIRECTORY_MODE`].
///
/// Both components Coffer owns (`coffer` and `live-auth`) go through this,
/// so a loosened intermediate directory is refused just like a loosened
/// final one.  The XDG state home itself is platform-owned and not checked.
fn create_and_open_plain_directory(
    parent: &OwnedFd,
    name: &str,
) -> Result<OwnedFd, SlotStateError> {
    match mkdirat(parent, name, Mode::from_raw_mode(DIRECTORY_MODE)) {
        Ok(()) | Err(Errno::EXIST) => {}
        Err(_) => return Err(SlotStateError::Io),
    }
    open_plain_directory(parent, name)
}

fn open_plain_directory(parent: &OwnedFd, name: &str) -> Result<OwnedFd, SlotStateError> {
    let directory = openat(
        parent,
        name,
        OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::RDONLY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|error| match error {
        Errno::LOOP | Errno::NOTDIR => SlotStateError::DirectoryNotPlain,
        Errno::NOENT => SlotStateError::Missing,
        _ => SlotStateError::Io,
    })?;
    let stat = fstat(&directory).map_err(|_| SlotStateError::Io)?;
    if !FileType::from_raw_mode(stat.st_mode).is_dir() {
        return Err(SlotStateError::DirectoryNotPlain);
    }
    if stat.st_mode & 0o777 != DIRECTORY_MODE {
        return Err(SlotStateError::DirectoryMode);
    }
    Ok(directory)
}

/// Loads and validates the slot file through one descriptor.
fn load_existing(directory: &OwnedFd) -> Result<Option<SessionSlot>, SlotStateError> {
    let fd = match openat(
        directory,
        FILE_NAME,
        // `NONBLOCK` keeps the open from blocking on a FIFO placed here; it
        // has no effect on reads from the regular file that is then
        // required by the `fstat` below.
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(fd) => fd,
        Err(Errno::NOENT) => return Ok(None),
        Err(Errno::LOOP) => return Err(SlotStateError::FileNotPlain),
        Err(_) => return Err(SlotStateError::Io),
    };
    let stat = fstat(&fd).map_err(|_| SlotStateError::Io)?;
    if !FileType::from_raw_mode(stat.st_mode).is_file() {
        return Err(SlotStateError::FileNotPlain);
    }
    if stat.st_mode & 0o777 != FILE_MODE {
        return Err(SlotStateError::FileMode);
    }
    if u64::try_from(stat.st_size).map_or(true, |size| size > READ_CEILING) {
        return Err(SlotStateError::Corrupt);
    }
    // Bounded read from the descriptor that was just checked, never from a
    // path resolved a second time.
    let mut contents = Vec::with_capacity(FILE_LEN);
    File::from(fd)
        .take(READ_CEILING + 1)
        .read_to_end(&mut contents)
        .map_err(|_| SlotStateError::Io)?;
    if contents.len() as u64 > READ_CEILING {
        return Err(SlotStateError::Corrupt);
    }
    parse(&contents).map(Some)
}

/// Writes the bytes to a private temporary file and links it into place.
///
/// Returns `Ok(true)` when this call published the file and `Ok(false)`
/// when another process did so first.
fn publish(directory: &OwnedFd, bytes: &[u8; SESSION_SLOT_LEN]) -> Result<bool, SlotStateError> {
    let temp_name = format!("{TEMP_PREFIX}{}", std::process::id());
    let result = publish_named(directory, &temp_name, bytes);
    // The temporary name is private to this process; remove it on every
    // path.  A leftover from a crash is never adopted, because only the
    // final name is ever read.
    let _ = unlinkat(directory, &temp_name, AtFlags::empty());
    result
}

fn publish_named(
    directory: &OwnedFd,
    temp_name: &str,
    bytes: &[u8; SESSION_SLOT_LEN],
) -> Result<bool, SlotStateError> {
    let temp = openat(
        directory,
        temp_name,
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::from_raw_mode(FILE_MODE),
    )
    .map_err(|_| SlotStateError::Io)?;
    let mut temp = File::from(temp);
    temp.write_all(&render(bytes))
        .and_then(|()| temp.sync_all())
        .map_err(|_| SlotStateError::Io)?;
    drop(temp);
    let published = match linkat(directory, temp_name, directory, FILE_NAME, AtFlags::empty()) {
        Ok(()) => true,
        Err(Errno::EXIST) => false,
        Err(_) => return Err(SlotStateError::Io),
    };
    fsync(directory.as_fd()).map_err(|_| SlotStateError::Io)?;
    Ok(published)
}

/// Resolves the XDG state home from the two relevant variables.
fn resolve_state_home(
    xdg_state_home: Option<&std::ffi::OsStr>,
    home: Option<&std::ffi::OsStr>,
) -> Result<PathBuf, SlotStateError> {
    if let Some(value) = xdg_state_home {
        let path = Path::new(value);
        if path.is_absolute() {
            return Ok(path.to_path_buf());
        }
    }
    match home {
        Some(value) if !value.is_empty() && Path::new(value).is_absolute() => {
            Ok(Path::new(value).join(".local").join("state"))
        }
        _ => Err(SlotStateError::NoStateHome),
    }
}

/// Serializes the exact version-1 file.
fn render(bytes: &[u8; SESSION_SLOT_LEN]) -> Vec<u8> {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = Vec::with_capacity(FILE_LEN);
    out.extend_from_slice(HEADER.as_bytes());
    out.push(b'\n');
    for byte in bytes {
        out.push(HEX[usize::from(byte >> 4)]);
        out.push(HEX[usize::from(byte & 0x0f)]);
    }
    out.push(b'\n');
    debug_assert_eq!(out.len(), FILE_LEN);
    out
}

/// Parses the exact version-1 file.
fn parse(contents: &[u8]) -> Result<SessionSlot, SlotStateError> {
    if contents.len() != FILE_LEN {
        return Err(SlotStateError::Corrupt);
    }
    let (head, rest) = contents.split_at(HEADER.len() + 1);
    if head[..HEADER.len()] != *HEADER.as_bytes() || head[HEADER.len()] != b'\n' {
        return Err(SlotStateError::Corrupt);
    }
    let (hex, newline) = rest.split_at(SESSION_SLOT_LEN * 2);
    if newline != b"\n" {
        return Err(SlotStateError::Corrupt);
    }
    let mut bytes = [0u8; SESSION_SLOT_LEN];
    for (index, pair) in hex.as_chunks::<2>().0.iter().enumerate() {
        let nibble = |digit: u8| match digit {
            b'0'..=b'9' => Ok(digit - b'0'),
            b'a'..=b'f' => Ok(digit - b'a' + 10),
            _ => Err(SlotStateError::Corrupt),
        };
        bytes[index] = nibble(pair[0])? << 4 | nibble(pair[1])?;
    }
    Ok(SessionSlot::from_random_bytes(bytes))
}

#[cfg(test)]
mod tests {
    use std::ffi::OsStr;
    use std::fs;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    use std::sync::{Arc, Barrier};

    use coffer_protocol::entropy::EntropyError;

    use super::*;

    struct Fixed([u8; SESSION_SLOT_LEN]);

    impl Entropy for Fixed {
        fn fill(&self, dest: &mut [u8]) -> Result<(), EntropyError> {
            dest.copy_from_slice(&self.0[..dest.len()]);
            Ok(())
        }
    }

    struct Broken;

    impl Entropy for Broken {
        fn fill(&self, _: &mut [u8]) -> Result<(), EntropyError> {
            Err(EntropyError::new("broken"))
        }
    }

    const BYTES: [u8; SESSION_SLOT_LEN] = [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
        0xff,
    ];

    fn state() -> (tempfile::TempDir, SlotState) {
        let root = tempfile::tempdir().unwrap();
        let state = SlotState::under_state_home(root.path());
        (root, state)
    }

    /// Creates the two owned directories with the production mode so a test
    /// can pre-populate the file.
    fn prepared_dir(root: &Path) -> PathBuf {
        let dir = root.join("coffer/live-auth");
        fs::create_dir_all(&dir).unwrap();
        fs::set_permissions(root.join("coffer"), fs::Permissions::from_mode(0o700)).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
        dir
    }

    fn write_slot_file(path: &Path, contents: &[u8]) {
        fs::write(path, contents).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }

    #[test]
    fn render_and_parse_round_trip_the_exact_shape() {
        let rendered = render(&BYTES);
        assert_eq!(rendered.len(), 65);
        assert_eq!(
            rendered,
            b"coffer-live-auth-profile-slot/1\n00112233445566778899aabbccddeeff\n"
        );
        assert_eq!(
            parse(&rendered).unwrap(),
            SessionSlot::from_random_bytes(BYTES)
        );
    }

    #[test]
    fn parse_rejects_every_deviation() {
        let good = render(&BYTES);
        let mut short = good.clone();
        short.pop();
        assert_eq!(parse(&short).unwrap_err(), SlotStateError::Corrupt);
        let mut long = good.clone();
        long.push(b'\n');
        assert_eq!(parse(&long).unwrap_err(), SlotStateError::Corrupt);
        let mut upper = good.clone();
        upper[HEADER.len() + 1 + 10] = b'A';
        assert_eq!(parse(&upper).unwrap_err(), SlotStateError::Corrupt);
        let mut header = good.clone();
        header[0] = b'C';
        assert_eq!(parse(&header).unwrap_err(), SlotStateError::Corrupt);
        let mut version = good.clone();
        version[HEADER.len() - 1] = b'2';
        assert_eq!(parse(&version).unwrap_err(), SlotStateError::Corrupt);
        let mut crlf = good;
        crlf[HEADER.len()] = b'\r';
        assert_eq!(parse(&crlf).unwrap_err(), SlotStateError::Corrupt);
        assert_eq!(parse(b"").unwrap_err(), SlotStateError::Corrupt);
    }

    #[test]
    fn first_run_creates_directory_and_file_with_strict_modes() {
        let (root, state) = state();
        let (slot, origin) = state.load_or_create(&Fixed(BYTES)).unwrap();
        assert_eq!(origin, SlotOrigin::Created);
        assert_eq!(slot, SessionSlot::from_random_bytes(BYTES));
        let dir = fs::symlink_metadata(root.path().join("coffer/live-auth")).unwrap();
        assert!(dir.is_dir());
        assert_eq!(dir.mode() & 0o777, 0o700);
        let file = fs::symlink_metadata(root.path().join("coffer/live-auth/profile-slot")).unwrap();
        assert!(file.is_file());
        assert_eq!(file.mode() & 0o777, 0o600);
        assert_eq!(file.len(), 65);
        let entries: Vec<_> = fs::read_dir(root.path().join("coffer/live-auth"))
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(entries, vec![OsStr::new("profile-slot")]);
    }

    #[test]
    fn second_run_reuses_the_existing_slot_without_touching_entropy() {
        let (_root, state) = state();
        let (first, _) = state.load_or_create(&Fixed(BYTES)).unwrap();
        let (second, origin) = state.load_or_create(&Broken).unwrap();
        assert_eq!(origin, SlotOrigin::Reused);
        assert_eq!(first, second);
    }

    #[test]
    fn entropy_failure_creates_nothing() {
        let (root, state) = state();
        assert_eq!(
            state.load_or_create(&Broken).unwrap_err(),
            SlotStateError::Entropy
        );
        assert!(!root.path().join("coffer/live-auth/profile-slot").exists());
    }

    #[test]
    fn a_missing_state_home_is_an_error_not_a_creation() {
        let root = tempfile::tempdir().unwrap();
        let state = SlotState::under_state_home(&root.path().join("absent"));
        assert_eq!(
            state.load_or_create(&Fixed(BYTES)).unwrap_err(),
            SlotStateError::Io
        );
    }

    #[test]
    fn corrupt_state_fails_closed_and_is_preserved() {
        let (root, state) = state();
        let path = prepared_dir(root.path()).join("profile-slot");
        write_slot_file(&path, b"garbage");
        assert_eq!(
            state.load_or_create(&Fixed(BYTES)).unwrap_err(),
            SlotStateError::Corrupt
        );
        assert_eq!(fs::read(&path).unwrap(), b"garbage");
    }

    #[test]
    fn an_oversized_file_is_refused_without_reading_it_all() {
        let (root, state) = state();
        let path = prepared_dir(root.path()).join("profile-slot");
        let mut big = render(&BYTES);
        big.resize(usize::try_from(READ_CEILING).unwrap() + 1, b'\n');
        write_slot_file(&path, &big);
        assert_eq!(
            state.load_or_create(&Fixed(BYTES)).unwrap_err(),
            SlotStateError::Corrupt
        );
        assert_eq!(fs::metadata(&path).unwrap().len(), READ_CEILING + 1);
    }

    #[test]
    fn symlinked_file_and_directory_are_refused() {
        let (root, file_state) = state();
        let dir = prepared_dir(root.path());
        let target = root.path().join("elsewhere");
        write_slot_file(&target, &render(&BYTES));
        std::os::unix::fs::symlink(&target, dir.join("profile-slot")).unwrap();
        assert_eq!(
            file_state.load_or_create(&Fixed(BYTES)).unwrap_err(),
            SlotStateError::FileNotPlain
        );

        let (root, dir_state) = state();
        fs::create_dir_all(root.path().join("coffer")).unwrap();
        fs::set_permissions(
            root.path().join("coffer"),
            fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        let real = root.path().join("real-dir");
        fs::create_dir(&real).unwrap();
        fs::set_permissions(&real, fs::Permissions::from_mode(0o700)).unwrap();
        std::os::unix::fs::symlink(&real, root.path().join("coffer/live-auth")).unwrap();
        assert_eq!(
            dir_state.load_or_create(&Fixed(BYTES)).unwrap_err(),
            SlotStateError::DirectoryNotPlain
        );
    }

    #[test]
    fn an_intermediate_symlink_is_refused_even_when_its_target_is_valid() {
        let (root, state) = state();
        let real = root.path().join("real-coffer");
        fs::create_dir(&real).unwrap();
        fs::set_permissions(&real, fs::Permissions::from_mode(0o700)).unwrap();
        let inner = real.join("live-auth");
        fs::create_dir(&inner).unwrap();
        fs::set_permissions(&inner, fs::Permissions::from_mode(0o700)).unwrap();
        write_slot_file(&inner.join("profile-slot"), &render(&BYTES));
        std::os::unix::fs::symlink(&real, root.path().join("coffer")).unwrap();
        assert_eq!(
            state.load_or_create(&Fixed(BYTES)).unwrap_err(),
            SlotStateError::DirectoryNotPlain
        );
    }

    #[test]
    fn a_regular_file_where_a_directory_belongs_is_refused() {
        let (root, state) = state();
        fs::write(root.path().join("coffer"), b"not a directory").unwrap();
        assert_eq!(
            state.load_or_create(&Fixed(BYTES)).unwrap_err(),
            SlotStateError::DirectoryNotPlain
        );
    }

    #[test]
    fn a_non_regular_file_is_refused() {
        let (root, state) = state();
        let dir = prepared_dir(root.path());
        // A directory in the file's place is opened (O_NOFOLLOW allows it)
        // and then rejected by the fstat on that very descriptor.
        fs::create_dir(dir.join("profile-slot")).unwrap();
        fs::set_permissions(dir.join("profile-slot"), fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(
            state.load_or_create(&Fixed(BYTES)).unwrap_err(),
            SlotStateError::FileNotPlain
        );
    }

    #[test]
    fn loose_permissions_are_refused() {
        let (root, state) = state();
        state.load_or_create(&Fixed(BYTES)).unwrap();
        let dir = root.path().join("coffer/live-auth");
        let file = dir.join("profile-slot");
        fs::set_permissions(&file, fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(
            state.load_or_create(&Fixed(BYTES)).unwrap_err(),
            SlotStateError::FileMode
        );
        fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(
            state.load_or_create(&Fixed(BYTES)).unwrap_err(),
            SlotStateError::DirectoryMode
        );
    }

    #[test]
    fn a_fifo_in_the_file_position_is_refused_without_blocking() {
        use std::sync::mpsc;
        use std::time::Duration;

        let (root, state) = state();
        let dir = prepared_dir(root.path());
        rustix::fs::mkfifoat(CWD, dir.join("profile-slot"), Mode::from_raw_mode(0o600))
            .expect("mkfifo");
        // Without a writer an ordinary open would block forever; the
        // bounded wait turns a regression into a failure, not a hang.
        let (sender, receiver) = mpsc::channel();
        std::thread::spawn(move || {
            let _ = sender.send(
                state
                    .load_or_create(&Fixed(BYTES))
                    .map(|(_, origin)| origin),
            );
        });
        let outcome = receiver
            .recv_timeout(Duration::from_secs(10))
            .expect("the FIFO open must not block");
        assert_eq!(outcome.unwrap_err(), SlotStateError::FileNotPlain);
    }

    #[test]
    fn a_loose_intermediate_directory_is_refused() {
        let (root, state) = state();
        state.load_or_create(&Fixed(BYTES)).unwrap();
        let application = root.path().join("coffer");
        assert_eq!(fs::metadata(&application).unwrap().mode() & 0o777, 0o700);
        fs::set_permissions(&application, fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(
            state.load_or_create(&Fixed(BYTES)).unwrap_err(),
            SlotStateError::DirectoryMode
        );
        fs::set_permissions(&application, fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(
            state.load_or_create(&Fixed(BYTES)).unwrap().1,
            SlotOrigin::Reused
        );
    }

    #[test]
    fn a_stale_temporary_file_is_never_adopted() {
        let (root, state) = state();
        let dir = prepared_dir(root.path());
        let other = [0x42u8; SESSION_SLOT_LEN];
        fs::write(dir.join(".profile-slot.tmp-999999"), render(&other)).unwrap();
        let (slot, origin) = state.load_or_create(&Fixed(BYTES)).unwrap();
        assert_eq!(origin, SlotOrigin::Created);
        assert_eq!(slot, SessionSlot::from_random_bytes(BYTES));
    }

    #[test]
    fn the_process_temporary_name_is_cleaned_up_after_publication() {
        let (root, state) = state();
        state.load_or_create(&Fixed(BYTES)).unwrap();
        let leftovers: Vec<_> = fs::read_dir(root.path().join("coffer/live-auth"))
            .unwrap()
            .filter(|e| e.as_ref().unwrap().file_name() != "profile-slot")
            .collect();
        assert!(leftovers.is_empty());
    }

    #[test]
    fn a_lost_publication_race_adopts_the_winner() {
        let (_root, state) = state();
        let directory = state.open_directory().unwrap();
        let winner = [0x7fu8; SESSION_SLOT_LEN];
        // Simulate the window between the temporary write and the link by
        // publishing the winner first through the same primitive.
        assert!(publish_named(&directory, ".profile-slot.tmp-winner", &winner).unwrap());
        unlinkat(&directory, ".profile-slot.tmp-winner", AtFlags::empty()).unwrap();
        assert!(!publish(&directory, &BYTES).unwrap());
        let (slot, _) = state.load_or_create(&Fixed(BYTES)).unwrap();
        assert_eq!(slot, SessionSlot::from_random_bytes(winner));
    }

    #[test]
    fn concurrent_first_runs_agree_on_one_slot() {
        let (_root, state) = state();
        let barrier = Arc::new(Barrier::new(4));
        let handles: Vec<_> = (0u8..4)
            .map(|i| {
                let state = state.clone();
                let barrier = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    barrier.wait();
                    // Distinct temporary names per thread stand in for the
                    // per-process names used in production.
                    let temp = format!(".profile-slot.tmp-t{i}");
                    let directory = state.open_directory().unwrap();
                    if load_existing(&directory).unwrap().is_none() {
                        let _ = publish_named(&directory, &temp, &[i + 1; SESSION_SLOT_LEN]);
                        let _ = unlinkat(&directory, &temp, AtFlags::empty());
                    }
                    load_existing(&directory).unwrap().unwrap()
                })
            })
            .collect();
        let slots: Vec<SessionSlot> = handles.into_iter().map(|h| h.join().unwrap()).collect();
        assert!(slots.windows(2).all(|pair| pair[0] == pair[1]));
    }

    #[test]
    fn state_home_resolution_follows_the_specification() {
        assert_eq!(
            resolve_state_home(Some(OsStr::new("/var/state")), Some(OsStr::new("/home/x")))
                .unwrap(),
            PathBuf::from("/var/state")
        );
        assert_eq!(
            resolve_state_home(Some(OsStr::new("relative")), Some(OsStr::new("/home/x"))).unwrap(),
            PathBuf::from("/home/x/.local/state")
        );
        assert_eq!(
            resolve_state_home(None, Some(OsStr::new("/home/x"))).unwrap(),
            PathBuf::from("/home/x/.local/state")
        );
        assert_eq!(
            resolve_state_home(None, Some(OsStr::new(""))).unwrap_err(),
            SlotStateError::NoStateHome
        );
        assert_eq!(
            resolve_state_home(None, None).unwrap_err(),
            SlotStateError::NoStateHome
        );
    }

    #[test]
    fn debug_and_errors_reveal_no_path() {
        let (root, state) = state();
        let rendered = format!("{state:?}");
        assert!(!rendered.contains(root.path().to_str().unwrap()));
        assert_eq!(rendered, "SlotState(<path redacted>)");
        assert!(!SlotStateError::Corrupt.to_string().contains('/'));
    }
}

#[cfg(test)]
mod new_profile_tests {
    use super::*;
    use coffer_protocol::entropy::EntropyError;
    use std::os::unix::fs::{PermissionsExt, symlink};
    struct Fixed;
    impl Entropy for Fixed {
        fn fill(&self, bytes: &mut [u8]) -> Result<(), EntropyError> {
            bytes.fill(42);
            Ok(())
        }
    }
    #[test]
    fn labels_are_bounded_single_components_and_debug_is_redacted() {
        let state = SlotState::under_state_home(Path::new("/synthetic-path"));
        for label in [
            "",
            ".",
            "..",
            "a/b",
            "A",
            "a_b",
            "a@example.invalid",
            "a\n",
            &"a".repeat(33),
        ] {
            assert_eq!(
                state.clone().new_profile(label),
                Err(SlotStateError::InvalidProfile)
            );
        }
        let selected = state.new_profile("synthetic-label").unwrap();
        assert!(!format!("{selected:?}").contains("synthetic"));
    }
    #[test]
    fn reservation_never_adopts_existing_empty_corrupt_or_valid_profiles() {
        for contents in [
            None,
            Some(b"corrupt".as_slice()),
            Some(render(&[1; 16]).as_slice()),
        ] {
            let root = tempfile::tempdir().unwrap();
            let state = SlotState::under_state_home(root.path())
                .new_profile("example")
                .unwrap();
            state.create_new(&Fixed).unwrap();
            let path = root
                .path()
                .join("coffer/live-auth/profiles/example/profile-slot");
            if let Some(bytes) = contents {
                std::fs::write(&path, bytes).unwrap();
            } else {
                std::fs::remove_file(&path).unwrap();
            }
            assert_eq!(state.create_new(&Fixed), Err(SlotStateError::Occupied));
            assert_eq!(
                state.load_or_create(&Fixed),
                Err(SlotStateError::InvalidProfile)
            );
            if let Some(bytes) = contents {
                assert_eq!(std::fs::read(&path).unwrap(), bytes);
            } else {
                assert!(!path.exists());
            }
        }
    }
    #[test]
    fn profiles_directory_symlink_and_wrong_mode_fail_closed() {
        for symbolic in [false, true] {
            let root = tempfile::tempdir().unwrap();
            let state = SlotState::under_state_home(root.path());
            state.load_or_create(&Fixed).unwrap();
            let profiles = root.path().join("coffer/live-auth/profiles");
            let target = root.path().join("outside");
            std::fs::create_dir(&target).unwrap();
            if symbolic {
                symlink(&target, &profiles).unwrap();
            } else {
                std::fs::create_dir(&profiles).unwrap();
                std::fs::set_permissions(&profiles, std::fs::Permissions::from_mode(0o755))
                    .unwrap();
            }
            assert!(
                state
                    .new_profile("example")
                    .unwrap()
                    .create_new(&Fixed)
                    .is_err()
            );
            assert_eq!(std::fs::read_dir(target).unwrap().count(), 0);
        }
    }
    #[test]
    fn concurrent_reservations_have_exactly_one_winner_and_no_adoption() {
        let root = tempfile::tempdir().unwrap();
        let state = SlotState::under_state_home(root.path())
            .new_profile("example")
            .unwrap();
        let barrier = std::sync::Barrier::new(2);
        let outcomes = std::thread::scope(|scope| {
            let worker = || {
                barrier.wait();
                state.create_new(&Fixed)
            };
            let first = scope.spawn(worker);
            let second = scope.spawn(worker);
            [first.join().unwrap(), second.join().unwrap()]
        });
        assert_eq!(outcomes.iter().filter(|r| r.is_ok()).count(), 1);
        assert_eq!(
            outcomes
                .iter()
                .filter(|r| **r == Err(SlotStateError::Occupied))
                .count(),
            1
        );
        assert!(state.load().is_ok());
    }
}
