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

//! Explicit disposable-account file input for the developer first-login harness.
//!
//! Construction performs no I/O. Only the exact first-login confirmation unlocks
//! a single file read. OTP stays on the controlling terminal. No secret-bearing
//! type implements `Debug`; all failures have fixed labels.

use crate::terminal::{MAX_INPUT_LEN, SecureTerminal, TerminalError};
use rustix::fs::{CWD, FileType, Mode, OFlags, fstat, openat};
use std::{
    fs::File,
    io::Read,
    path::{Component, Path, PathBuf},
};
use zeroize::Zeroizing;

const MAX_FILE_LEN: usize = 2 * MAX_INPUT_LEN + 17;
const ACCOUNT: &str = "Apple Account (e-mail address or phone number, not echoed): ";
const PASSWORD: &str = "Password (not echoed): ";
const OTP: &str = "Verification code (6 digits, not echoed): ";
const REAUTH: &str = "Password again, for post-2FA re-authentication (not echoed): ";
const ACCOUNT_NOTICE: &str = "[auth] the account name is an identifier Coffer treats as private: it is typed without echo, kept in memory only, and never printed";
const REAUTH_NOTICE: &str = "[auth] code accepted; Apple requires the password exchange again after a second factor, and the earlier password was not kept";
const STORE_NOTICE: &str =
    "[store] writing the reusable session to Secret Service under the profile slot";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FileInputError {
    Open,
    Metadata,
    Read,
    Size,
    Format,
}
impl FileInputError {
    fn label(self) -> &'static str {
        match self {
            Self::Open => "credential file open rejected",
            Self::Metadata => {
                "credential file must be a current-user regular file with exact mode 0600"
            }
            Self::Read => "credential file read failed",
            Self::Size => "credential file size rejected",
            Self::Format => "credential file format rejected",
        }
    }
}
struct Credentials {
    email: Zeroizing<String>,
    password: Zeroizing<String>,
}

// Walk each component through held directory descriptors. NOFOLLOW on only
// the leaf would still permit an ancestor symlink. Parent traversal is refused.
fn open_file(path: &Path) -> Result<File, FileInputError> {
    let flags = OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK;
    let mut directory = openat(
        CWD,
        if path.is_absolute() { "/" } else { "." },
        flags | OFlags::DIRECTORY,
        Mode::empty(),
    )
    .map_err(|_| FileInputError::Open)?;
    let mut components = path.components().peekable();
    while let Some(component) = components.next() {
        match component {
            Component::RootDir | Component::CurDir => continue,
            Component::Normal(name) => {
                let last = components.peek().is_none();
                let fd = openat(
                    &directory,
                    name,
                    if last {
                        flags
                    } else {
                        flags | OFlags::DIRECTORY
                    },
                    Mode::empty(),
                )
                .map_err(|_| FileInputError::Open)?;
                if last {
                    return Ok(File::from(fd));
                }
                directory = fd;
            }
            _ => return Err(FileInputError::Open),
        }
    }
    Err(FileInputError::Open)
}
fn validate_metadata(stat: &rustix::fs::Stat, uid: u32) -> Result<(), FileInputError> {
    if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile
        || stat.st_uid != uid
        || stat.st_mode & 0o7777 != 0o600
    {
        return Err(FileInputError::Metadata);
    }
    if stat.st_size < 0 || stat.st_size as u64 > MAX_FILE_LEN as u64 {
        return Err(FileInputError::Size);
    }
    Ok(())
}
fn read_credentials(path: &Path) -> Result<Credentials, FileInputError> {
    let mut file = open_file(path)?;
    let stat = fstat(&file).map_err(|_| FileInputError::Metadata)?;
    validate_metadata(&stat, rustix::process::geteuid().as_raw())?;
    // Allocate and initialize the full bound before reading any secret. The
    // extra byte detects growth/overflow without reallocating a secret buffer.
    let mut bytes = Zeroizing::new(vec![0; MAX_FILE_LEN + 1]);
    let mut length = 0;
    loop {
        let count = file
            .read(&mut bytes[length..])
            .map_err(|_| FileInputError::Read)?;
        if count == 0 {
            break;
        }
        length += count;
        if length > MAX_FILE_LEN {
            return Err(FileInputError::Size);
        }
    }
    // Recheck mode/owner after the read as well; no pathname is reopened.
    validate_metadata(
        &fstat(&file).map_err(|_| FileInputError::Metadata)?,
        rustix::process::geteuid().as_raw(),
    )?;
    parse(&bytes[..length])
}
fn parse(bytes: &[u8]) -> Result<Credentials, FileInputError> {
    if bytes.len() > MAX_FILE_LEN {
        return Err(FileInputError::Size);
    }
    let text = std::str::from_utf8(bytes).map_err(|_| FileInputError::Format)?;
    let text = text.strip_suffix('\n').unwrap_or(text);
    let mut email = None;
    let mut password = None;
    for line in text.split('\n') {
        let (key, value) = line.split_once('=').ok_or(FileInputError::Format)?;
        if value.is_empty() || value.len() > MAX_INPUT_LEN || value.chars().any(char::is_control) {
            return Err(FileInputError::Format);
        }
        let slot = match key {
            "EMAIL" => &mut email,
            "PASSWORD" => &mut password,
            _ => return Err(FileInputError::Format),
        };
        if slot.is_some() {
            return Err(FileInputError::Format);
        }
        *slot = Some(value);
    }
    // Validate both borrowed fields before allocating either returned secret.
    let email = email.ok_or(FileInputError::Format)?;
    let password = password.ok_or(FileInputError::Format)?;
    Ok(Credentials {
        email: Zeroizing::new(email.to_owned()),
        password: Zeroizing::new(password.to_owned()),
    })
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum State {
    Confirmation,
    Account,
    Password,
    Otp,
    Reauth,
    Finished,
}

/// File-backed input for exactly one [`crate::first_login::run`] invocation.
///
/// Requires an explicitly selected disposable-account file outside the repository.
/// The path is never printed. Confirmation and OTP use the wrapped secure TTY;
/// each credential prompt is accepted once, with one optional post-2FA password
/// handoff. Unknown, repeated, or out-of-order prompts wipe input and fail closed.
/// Buffers are zeroized on normal drop, not guaranteed after abrupt termination.
/// No `Debug` implementation is provided.
pub struct FileTerminal<T> {
    terminal: T,
    path: Option<PathBuf>,
    password: Option<Zeroizing<String>>,
    state: State,
}
impl<T: SecureTerminal> FileTerminal<T> {
    /// Retains the explicit path without opening or reading it.
    ///
    /// Use only with [`crate::first_login::run`], which owns preflight and the
    /// confirmation. The caller must call [`Self::finish`] on every return path
    /// before reporting the result. Dropping also wipes retained passwords.
    #[must_use]
    pub fn new(terminal: T, path: PathBuf) -> Self {
        Self {
            terminal,
            path: Some(path),
            password: None,
            state: State::Confirmation,
        }
    }
    /// Wipes retained input and permanently rejects further prompts.
    /// Fixed result notices remain available after this call.
    pub fn finish(&mut self) {
        self.path = None;
        self.password = None;
        self.state = State::Finished;
    }
    fn fail(&mut self) -> TerminalError {
        self.finish();
        TerminalError::Io
    }
}
impl<T: SecureTerminal> SecureTerminal for FileTerminal<T> {
    fn notice(&mut self, text: &'static str) -> Result<(), TerminalError> {
        if text == STORE_NOTICE {
            self.finish();
        }
        let text = match text {
            ACCOUNT_NOTICE => {
                "[auth] account and password come from the explicitly selected developer file; neither is printed"
            }
            REAUTH_NOTICE => {
                "[auth] code accepted; reusing the in-memory file password once for post-2FA authentication"
            }
            other => other,
        };
        self.terminal.notice(text).inspect_err(|_| {
            self.fail();
        })
    }
    fn prompt_visible(&mut self, label: &'static str) -> Result<Zeroizing<String>, TerminalError> {
        if self.state != State::Confirmation || label != crate::first_login::CONFIRM {
            return Err(self.fail());
        }
        self.state = State::Finished;
        let answer = self.terminal.prompt_visible(label).inspect_err(|_| {
            self.fail();
        })?;
        if answer.as_str() == "LOGIN AND STORE" {
            self.state = State::Account;
        } else {
            self.finish();
        }
        Ok(answer)
    }
    fn prompt_hidden(&mut self, label: &'static str) -> Result<Zeroizing<String>, TerminalError> {
        match (self.state, label) {
            (State::Account, ACCOUNT) => {
                self.state = State::Finished;
                let path = self.path.take().ok_or_else(|| self.fail())?;
                let credentials = read_credentials(&path).map_err(|error| {
                    self.fail();
                    let _ = self.terminal.notice(error.label());
                    TerminalError::Io
                })?;
                self.password = Some(credentials.password);
                self.state = State::Password;
                Ok(credentials.email)
            }
            (State::Password, PASSWORD) => {
                let password = self.password.clone().ok_or_else(|| self.fail())?;
                self.state = State::Otp;
                Ok(password)
            }
            (State::Otp, OTP) => {
                self.state = State::Finished;
                let code = self.terminal.prompt_hidden(label).inspect_err(|_| {
                    self.fail();
                })?;
                self.state = State::Reauth;
                Ok(code)
            }
            (State::Reauth, REAUTH) => {
                self.state = State::Finished;
                self.password.take().ok_or_else(|| self.fail())
            }
            _ => Err(self.fail()),
        }
    }
}

#[cfg(test)]
#[path = "../tests/file_input/mod.rs"]
mod tests;
