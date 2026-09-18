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

//! Bounded 1Password input for separately authorized developer login entry points.
//!
//! Only [`ItemSelector::from_stdin_pipe`] accepts standard input: an opaque
//! item ID and the user-approved expected account, never a password. [`OpTerminal`] defers its one child process until
//! the harness has completed preflight and the exact TTY confirmation. The
//! selected harness owns preflight and login; `delegate_harness` also owns its
//! stored ADSID binding. First login requires a separate create-only profile.

use crate::terminal::{ChildSignalDeferral, MAX_INPUT_LEN, SecureTerminal, TerminalError};
use core::fmt;
use rustix::fs::{FileType, OFlags, fcntl_getfl, fcntl_setfl, fstat};
use std::fs::File;
use std::io::{self, Read, Write};
use std::os::fd::{AsFd, AsRawFd};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

const SELECTOR_LEN: usize = 26;
const MAX_EXPECTED_ACCOUNT_LEN: usize = 256;
const MAX_FRAME_LEN: usize = SELECTOR_LEN + 1 + MAX_EXPECTED_ACCOUNT_LEN + 1;
// Two maximally quoted/escaped fields, comma, and one optional LF.
const MAX_OUTPUT_LEN: usize = 4 * MAX_INPUT_LEN + 6;
const SELECTOR_TIMEOUT: Duration = Duration::from_secs(5);
const OP_TIMEOUT: Duration = Duration::from_secs(120);
const POLL_INTERVAL: Duration = Duration::from_millis(10);
const CONFIRM: &str =
    "Type LOGIN AND ISSUE to authorize this single fresh-login/delegate/store flow: ";
const ACCOUNT: &str = "Apple Account (e-mail address or phone number, not echoed): ";
const PASSWORD: &str = "Password (not echoed): ";
const OTP: &str = "Verification code (6 digits, not echoed): ";
const REAUTH: &str = "Password again, for post-2FA re-authentication (not echoed): ";
const ACCOUNT_NOTICE: &str = "[auth] the account name is an identifier Coffer treats as private: it is typed without echo, kept in memory only, and never printed";
const REAUTH_NOTICE: &str = "[auth] code accepted; Apple requires the password exchange again after a second factor, and the earlier password was not kept";
const STORE_NOTICE: &str =
    "[store] writing the reusable session to Secret Service under the profile slot";

/// Fixed failures; neither source errors nor input/output bytes are retained.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpInputError {
    /// Standard input source, frame, nonblocking setup, read or deadline failed.
    Selector,
    /// A pipe or child operation failed.
    Process,
    /// A termination signal cancelled the child operation.
    Interrupted,
    /// The bounded operation exceeded its wall-clock budget.
    Timeout,
    /// Child output exceeded the encoded size bound.
    TooLarge,
    /// The child returned a non-success exit status.
    Exit,
    /// Output was not one supported CSV row containing two acceptable fields.
    Malformed,
    /// The decoded first field did not byte-exactly match the approved account.
    AccountMismatch,
}
impl OpInputError {
    /// Returns only a fixed, secret-free description.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Selector => "1Password selector pipe rejected; no credential fetch",
            Self::Process => "1Password process or pipe failed; no retry",
            Self::Interrupted => "1Password input interrupted; no retry",
            Self::Timeout => "1Password input deadline exceeded; no retry",
            Self::TooLarge => "1Password output exceeded the bound; no retry",
            Self::Exit => {
                "1Password process failed; unlock may require human interaction; no retry"
            }
            Self::Malformed => "1Password output rejected; no retry",
            Self::AccountMismatch => "1Password account binding rejected; no retry",
        }
    }
}
impl fmt::Display for OpInputError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}
impl std::error::Error for OpInputError {}

/// Opaque item selector and approved account in zeroizing memory, without `Debug`.
///
/// It cannot be constructed from arguments, environment, or a file. It is
/// consumed by [`OpTerminal`] and wiped after the one credential fetch.
pub struct ItemSelector {
    frame: Zeroizing<Vec<u8>>,
}
impl ItemSelector {
    /// Reads exactly an item ID, LF, expected account, LF, and EOF from the
    /// inherited anonymous standard-input pipe. The ID is 26 lowercase ASCII
    /// letters/digits; the account is 1..=256 UTF-8 bytes without controls.
    /// The launcher must obtain the expected account independently from the
    /// same user approval that selected the item, never from fetched fields.
    ///
    /// Linux `/proc/self/fd` and `fstat` verify the pinned descriptor before
    /// reading; named FIFOs, files, terminals and sockets are refused. Reading
    /// uses a nonblocking duplicate, 284 bytes plus one overflow probe, and a
    /// five-second budget. No password or alternate input source is accepted.
    ///
    /// # Errors
    /// Every source, framing, nonblocking, I/O or timeout failure is mapped to
    /// the fixed [`OpInputError::Selector`] error, without retaining input.
    pub fn from_stdin_pipe() -> Result<Self, OpInputError> {
        let stdin = io::stdin();
        // A CLOEXEC duplicate pins the checked descriptor without owning fd 0.
        let owned = stdin
            .as_fd()
            .try_clone_to_owned()
            .map_err(|_| OpInputError::Selector)?;
        read_selector_pipe(&mut File::from(owned), Instant::now() + SELECTOR_TIMEOUT)
    }

    fn expected_account(&self) -> &[u8] {
        &self.frame[SELECTOR_LEN + 1..self.frame.len() - 1]
    }
}

fn read_selector_pipe(pipe: &mut File, deadline: Instant) -> Result<ItemSelector, OpInputError> {
    verify_anonymous_pipe(pipe)?;
    let mode = Nonblocking::new(pipe).map_err(|_| OpInputError::Selector)?;
    let result = read_bounded(pipe, MAX_FRAME_LEN, deadline, None)
        .and_then(parse_selector)
        .map_err(|_| OpInputError::Selector);
    drop(mode);
    result
}

fn verify_anonymous_pipe(pipe: &File) -> Result<(), OpInputError> {
    let stat = fstat(pipe).map_err(|_| OpInputError::Selector)?;
    if !FileType::from_raw_mode(stat.st_mode).is_fifo() {
        return Err(OpInputError::Selector);
    }
    let target = std::fs::read_link(format!("/proc/self/fd/{}", pipe.as_raw_fd()))
        .map_err(|_| OpInputError::Selector)?;
    let target = target.to_str().ok_or(OpInputError::Selector)?;
    let inode = target
        .strip_prefix("pipe:[")
        .and_then(|s| s.strip_suffix(']'))
        .ok_or(OpInputError::Selector)?;
    if inode.is_empty() || !inode.bytes().all(|b| b.is_ascii_digit()) {
        return Err(OpInputError::Selector);
    }
    Ok(())
}
fn parse_selector(bytes: Zeroizing<Vec<u8>>) -> Result<ItemSelector, OpInputError> {
    if !(SELECTOR_LEN + 3..=MAX_FRAME_LEN).contains(&bytes.len())
        || bytes[SELECTOR_LEN] != b'\n'
        || bytes.last() != Some(&b'\n')
        || !bytes[..SELECTOR_LEN]
            .iter()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
    {
        return Err(OpInputError::Selector);
    }
    let account = std::str::from_utf8(&bytes[SELECTOR_LEN + 1..bytes.len() - 1])
        .map_err(|_| OpInputError::Selector)?;
    if account.chars().any(char::is_control) {
        return Err(OpInputError::Selector);
    }
    Ok(ItemSelector { frame: bytes })
}

// This guard owns a duplicate of the same open-file description so no mutable
// borrow of the reader is held. Restore flags before either duplicate closes.
struct Nonblocking {
    fd: std::os::fd::OwnedFd,
    flags: OFlags,
}
impl Nonblocking {
    fn new(fd: &impl AsFd) -> Result<Self, OpInputError> {
        let fd = fd
            .as_fd()
            .try_clone_to_owned()
            .map_err(|_| OpInputError::Process)?;
        let flags = fcntl_getfl(&fd).map_err(|_| OpInputError::Process)?;
        fcntl_setfl(&fd, flags | OFlags::NONBLOCK).map_err(|_| OpInputError::Process)?;
        Ok(Self { fd, flags })
    }
}
impl Drop for Nonblocking {
    fn drop(&mut self) {
        let _ = fcntl_setfl(&self.fd, self.flags);
    }
}

fn read_bounded(
    reader: &mut impl Read,
    limit: usize,
    deadline: Instant,
    signals: Option<&ChildSignalDeferral>,
) -> Result<Zeroizing<Vec<u8>>, OpInputError> {
    // One allocation including the over-limit probe. Never grow a secret Vec.
    let mut bytes = Zeroizing::new(vec![0u8; limit + 1]);
    let mut used = 0;
    loop {
        check_deadline(deadline, signals)?;
        let read = reader.read(&mut bytes[used..]);
        check_deadline(deadline, signals)?;
        match read {
            Ok(0) => {
                bytes.truncate(used);
                return Ok(bytes);
            }
            Ok(n) => {
                used += n;
                if used > limit {
                    return Err(OpInputError::TooLarge);
                }
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => std::thread::sleep(POLL_INTERVAL),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(_) => return Err(OpInputError::Process),
        }
    }
}

struct Credentials {
    username: Zeroizing<String>,
    password: Zeroizing<String>,
}

fn decode_csv(bytes: &[u8]) -> Result<Credentials, OpInputError> {
    let bytes = bytes.strip_suffix(b"\n").unwrap_or(bytes);
    let mut offset = 0;
    let username = csv_field(bytes, &mut offset)?;
    if bytes.get(offset) != Some(&b',') {
        return Err(OpInputError::Malformed);
    }
    offset += 1;
    let password = csv_field(bytes, &mut offset)?;
    if offset != bytes.len() {
        return Err(OpInputError::Malformed);
    }
    Ok(Credentials { username, password })
}
fn csv_field(bytes: &[u8], offset: &mut usize) -> Result<Zeroizing<String>, OpInputError> {
    let mut decoded = Zeroizing::new(Vec::with_capacity(MAX_INPUT_LEN));
    let quoted = bytes.get(*offset) == Some(&b'"');
    if quoted {
        *offset += 1;
    }
    loop {
        let Some(&byte) = bytes.get(*offset) else {
            if quoted {
                return Err(OpInputError::Malformed);
            }
            break;
        };
        if quoted && byte == b'"' {
            *offset += 1;
            if bytes.get(*offset) != Some(&b'"') {
                break;
            }
        } else if !quoted && byte == b',' {
            break;
        } else if !quoted && byte == b'"' {
            return Err(OpInputError::Malformed);
        }
        if decoded.len() == MAX_INPUT_LEN {
            return Err(OpInputError::Malformed);
        }
        decoded.push(byte);
        *offset += 1;
    }
    let text = std::str::from_utf8(&decoded).map_err(|_| OpInputError::Malformed)?;
    if text.is_empty() || text.chars().any(char::is_control) {
        return Err(OpInputError::Malformed);
    }
    Ok(Zeroizing::new(text.to_owned()))
}

fn op_command() -> Command {
    let mut command = Command::new("/usr/bin/op");
    command.args([
        "item",
        "get",
        "-",
        "--fields",
        "label=username,label=password",
        "--reveal",
        "--debug=false",
        "--cache=false",
        "--format",
        "human-readable",
        "--no-color",
    ]);
    // UTF-8 is the CLI default. op 2.39.0 rejects an explicit UTF-8 encoding
    // override before command execution; only legacy encodings use that flag.
    // Keep GUI integration variables inherited without reading their values or
    // creating any secret environment. Explicit flags pin output/debug/cache.
    command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    command
}

// std::process::Child does not kill/reap on Drop. Own that duty immediately
// after spawn, including all setup/read/validation/deadline failures.
struct ChildOwner(Child);
impl Drop for ChildOwner {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
fn fetch(selector: &ItemSelector) -> Result<Credentials, OpInputError> {
    let output = run_child(&mut op_command(), selector, OP_TIMEOUT)?;
    decode_csv(&output)
}
fn run_child(
    command: &mut Command,
    selector: &ItemSelector,
    timeout: Duration,
) -> Result<Zeroizing<Vec<u8>>, OpInputError> {
    let deadline = Instant::now()
        .checked_add(timeout)
        .ok_or(OpInputError::Timeout)?;
    if Instant::now() >= deadline {
        return Err(OpInputError::Timeout);
    }
    // Declaration order also protects early returns and unwinding: child
    // cleanup runs before the signal guard emulates the default action.
    let signals = ChildSignalDeferral::begin().map_err(|_| OpInputError::Process)?;
    check_deadline(deadline, Some(&signals))?;
    let mut child = ChildOwner(command.spawn().map_err(|_| OpInputError::Process)?);
    let result = read_child(&mut child.0, selector, deadline, Some(&signals));
    drop(child);
    // A signal can arrive during cleanup or alongside successful output.
    // Wipe any output before honoring it and never return credentials then.
    let result = if signals.cancelled() {
        drop(result);
        Err(OpInputError::Interrupted)
    } else {
        result
    };
    drop(signals);
    result
}
fn read_child(
    child: &mut Child,
    selector: &ItemSelector,
    deadline: Instant,
    signals: Option<&ChildSignalDeferral>,
) -> Result<Zeroizing<Vec<u8>>, OpInputError> {
    let mut input = child.stdin.take().ok_or(OpInputError::Process)?;
    let input_mode = Nonblocking::new(&input)?;
    write_selection(&mut input, selector, deadline, signals)?;
    drop(input_mode);
    drop(input); // EOF is mandatory; op must never ask this pipe for a password.
    let mut output = child.stdout.take().ok_or(OpInputError::Process)?;
    let _output_mode = Nonblocking::new(&output)?;
    let bytes = read_bounded(&mut output, MAX_OUTPUT_LEN, deadline, signals)?;
    loop {
        check_deadline(deadline, signals)?;
        match child.try_wait().map_err(|_| OpInputError::Process)? {
            Some(status) if status.success() => return Ok(bytes),
            Some(_) => return Err(OpInputError::Exit),
            None => std::thread::sleep(POLL_INTERVAL),
        }
    }
}

fn write_selection(
    writer: &mut impl Write,
    selector: &ItemSelector,
    deadline: Instant,
    signals: Option<&ChildSignalDeferral>,
) -> Result<(), OpInputError> {
    let mut input = Zeroizing::new([0u8; SELECTOR_LEN + 1]);
    input[..SELECTOR_LEN].copy_from_slice(&selector.frame[..SELECTOR_LEN]);
    input[SELECTOR_LEN] = b'\n';
    let mut written = 0;
    while written < input.len() {
        check_deadline(deadline, signals)?;
        match writer.write(&input[written..]) {
            Ok(0) => return Err(OpInputError::Process),
            Ok(n) => written += n,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(_) => return Err(OpInputError::Process),
        }
    }
    Ok(())
}

fn check_deadline(
    deadline: Instant,
    signals: Option<&ChildSignalDeferral>,
) -> Result<(), OpInputError> {
    if signals.is_some_and(ChildSignalDeferral::cancelled) {
        return Err(OpInputError::Interrupted);
    }
    if Instant::now() >= deadline {
        return Err(OpInputError::Timeout);
    }
    Ok(())
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum State {
    Confirmation,
    Account,
    Password,
    Otp,
    Reauth,
    Finished,
    Failed,
}
type Loader = Box<dyn FnOnce(&ItemSelector) -> Result<Credentials, OpInputError>>;

/// Narrow terminal wrapper for exactly one selected developer harness invocation.
///
/// It forwards the exact visible confirmation and OTP to the original terminal.
/// Only after an accepted confirmation does the first exact account prompt run
/// `/usr/bin/op` once. Both fields must validate and the decoded username must
/// byte-exactly match the independently approved account before either is returned.
/// The password stays in a zeroizing owner for the optional post-2FA prompt,
/// then moves out; without 2FA it is wiped at the first persistence notice.
/// Unknown/repeated/out-of-order prompts permanently fail closed and wipe all
/// retained input. Dropping the wrapper wipes remaining material after errors.
/// It deliberately does not implement `Debug`.
pub struct OpTerminal<T> {
    terminal: T,
    selector: Option<ItemSelector>,
    password: Option<Zeroizing<String>>,
    loader: Option<Loader>,
    state: State,
    login_only: bool,
}
impl<T: SecureTerminal> OpTerminal<T> {
    /// Wraps the controlling terminal and selector without fetching credentials.
    ///
    /// Call only as the terminal passed to `delegate_harness::run`; that harness
    /// owns local preflight and stored-ADSID binding; this wrapper owns the
    /// pre-authentication expected-account binding. Construction performs
    /// no process, store, provisioning, or network operation.
    #[must_use]
    pub fn new(terminal: T, selector: ItemSelector) -> Self {
        Self {
            terminal,
            selector: Some(selector),
            password: None,
            loader: Some(Box::new(fetch)),
            state: State::Confirmation,
            login_only: false,
        }
    }
    /// Wraps input for [`crate::first_login::run`] with `LOGIN AND STORE`.
    ///
    /// This mode permits only the first-login confirmation, then the same
    /// bounded account/password/optional-2FA sequence as [`Self::new`]. It
    /// performs no fetch until that harness completes preflight and confirmation.
    #[must_use]
    pub fn for_first_login(terminal: T, selector: ItemSelector) -> Self {
        let mut input = Self::new(terminal, selector);
        input.login_only = true;
        input
    }

    #[cfg(test)]
    pub(crate) fn test_first_login(
        terminal: T,
        loader: impl FnOnce() -> Result<Zeroizing<Vec<u8>>, OpInputError> + 'static,
    ) -> Self {
        let selector = parse_selector(Zeroizing::new(
            b"abcdefghijklmnopqrstuvwxyz\nsynthetic@example.invalid\n".to_vec(),
        ))
        .ok()
        .unwrap();
        let mut input = Self::for_first_login(terminal, selector);
        input.loader = Some(Box::new(move |_| decode_csv(&loader()?)));
        input
    }

    /// Wipes retained input after the harness returns, before result reporting.
    /// Subsequent credential prompts fail; fixed notices can still be printed.
    pub fn finish(&mut self) {
        self.selector = None;
        self.password = None;
        self.loader = None;
        self.state = State::Finished;
    }
    fn fail(&mut self) -> TerminalError {
        self.finish();
        self.state = State::Failed;
        TerminalError::Io
    }
}
impl<T: SecureTerminal> SecureTerminal for OpTerminal<T> {
    fn notice(&mut self, text: &'static str) -> Result<(), TerminalError> {
        if text == STORE_NOTICE {
            self.finish();
        }
        let text = match text {
            ACCOUNT_NOTICE => {
                "[auth] account and password come from the selected 1Password item; neither is printed"
            }
            REAUTH_NOTICE => {
                "[auth] code accepted; reusing the in-memory 1Password password once for post-2FA authentication"
            }
            other => other,
        };
        self.terminal.notice(text).inspect_err(|_| {
            self.fail();
        })
    }
    fn prompt_visible(&mut self, label: &'static str) -> Result<Zeroizing<String>, TerminalError> {
        let (prompt, accepted) = if self.login_only {
            (crate::first_login::CONFIRM, "LOGIN AND STORE")
        } else {
            (CONFIRM, "LOGIN AND ISSUE")
        };
        if self.state != State::Confirmation || label != prompt {
            return Err(self.fail());
        }
        // Poison before delegating; failure/decline must never permit a fetch.
        self.state = State::Failed;
        let answer = self.terminal.prompt_visible(label).inspect_err(|_| {
            self.fail();
        })?;
        if answer.as_str() == accepted {
            self.state = State::Account;
        } else {
            self.fail();
        }
        Ok(answer)
    }
    fn prompt_hidden(&mut self, label: &'static str) -> Result<Zeroizing<String>, TerminalError> {
        match (self.state, label) {
            (State::Account, ACCOUNT) => {
                self.state = State::Failed;
                self.terminal.notice("[1Password] fetching the selected username and password once; unlock or approval may require human interaction in the 1Password application")
                    .inspect_err(|_| { self.fail(); })?;
                let selector = self.selector.take().ok_or_else(|| self.fail())?;
                let loader = self.loader.take().ok_or_else(|| self.fail())?;
                let credentials = loader(&selector)
                    .and_then(|credentials| {
                        if credentials.username.as_bytes() != selector.expected_account() {
                            return Err(OpInputError::AccountMismatch);
                        }
                        Ok(credentials)
                    })
                    .map_err(|error| {
                        self.fail();
                        let _ = self.terminal.notice(error.label());
                        TerminalError::Io
                    })?;
                self.password = Some(credentials.password);
                self.state = State::Password;
                Ok(credentials.username)
            }
            (State::Password, PASSWORD) => {
                let password = self.password.clone().ok_or_else(|| self.fail())?;
                self.state = State::Otp;
                Ok(password)
            }
            (State::Otp, OTP) => {
                self.state = State::Failed;
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
#[path = "../tests/op_input/mod.rs"]
mod tests;
