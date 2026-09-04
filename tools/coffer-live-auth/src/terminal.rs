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

//! Interactive input from the controlling terminal only.
//!
//! The account name, the password, and the trusted-device verification code
//! reach the harness through exactly one path: a line read from `/dev/tty`.
//! There is no command-line, environment, standard-input, or file path, so a
//! shell history, a process listing, or a CI log can never carry one of them.
//! All three are read with terminal echo off: the account name is an
//! identifier Coffer treats as private, so it does not belong in terminal
//! scrollback either.  The only echoed prompt is the one-word provisioning
//! confirmation.
//!
//! Everything the harness prints goes through [`SecureTerminal::notice`],
//! which accepts only `&'static str`.  That restriction is the mechanism that
//! keeps a runtime value, secret or merely correlatable, out of the output.
//!
//! # Leaving the terminal as it was found
//!
//! A hidden prompt changes the terminal's mode, and a process that dies with
//! echo off leaves the user typing blind.  Two mechanisms cover the two ways
//! that can happen:
//!
//! - Keyboard interrupts.  While a hidden prompt is active the terminal's
//!   `ISIG` flag is cleared together with `ECHO`, so Ctrl-C, Ctrl-\ and
//!   Ctrl-Z arrive as ordinary bytes instead of signals.  The line reader
//!   turns such a byte into [`TerminalError::Interrupted`], the guard
//!   restores the mode, and the run stops normally.
//! - Signals from elsewhere (`kill`, a closing terminal).  `SIGINT`,
//!   `SIGTERM`, and `SIGHUP` are registered once, at open time, through the
//!   `signal-hook` crate.  Outside a hidden prompt they keep their default
//!   action.  During one, the signal is only recorded; once the prompt has
//!   restored the terminal the default action is emulated, so the process
//!   still terminates the way it would have, but with the terminal intact.
//!   The prompt's blocking read itself is not interrupted (the handlers are
//!   installed with `SA_RESTART`), so termination happens when the line ends.

use core::fmt;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock};

use rustix::termios::{LocalModes, OptionalActions, Termios, isatty, tcgetattr, tcsetattr};
use signal_hook::consts::signal::{SIGHUP, SIGINT, SIGTERM};
use zeroize::Zeroizing;

/// Longest line accepted from the terminal, in bytes, excluding the newline.
///
/// Larger than any account name, password, or code Apple accepts; a longer
/// line is refused before it is parsed.
pub const MAX_INPUT_LEN: usize = 1024;

/// Path of the controlling terminal on Linux.
const TTY_PATH: &str = "/dev/tty";

/// Signals whose default action is deferred while a hidden prompt is active.
const DEFERRED_SIGNALS: [i32; 3] = [SIGINT, SIGTERM, SIGHUP];

/// The user-facing terminal.
///
/// Implementations must own the only copy of what the user types until it is
/// handed to the caller inside a [`Zeroizing`] buffer, and must never echo a
/// hidden line back.  The harness is generic over this trait so that the
/// prompt sequence can be tested with a scripted implementation.
pub trait SecureTerminal {
    /// Prints a fixed, secret-free line for the user.
    ///
    /// # Errors
    ///
    /// Returns [`TerminalError::Io`] when the terminal cannot be written.
    fn notice(&mut self, text: &'static str) -> Result<(), TerminalError>;

    /// Prompts for one line with echo left on.
    ///
    /// # Errors
    ///
    /// Returns a [`TerminalError`] when no well-formed line was read.
    fn prompt_visible(&mut self, label: &'static str) -> Result<Zeroizing<String>, TerminalError>;

    /// Prompts for one line with echo turned off for the duration of the read.
    ///
    /// Echo is turned off before the label is written, so nothing typed
    /// ahead of the prompt is echoed, and it is restored before this returns,
    /// whether or not the read succeeded.
    ///
    /// # Errors
    ///
    /// Returns [`TerminalError::EchoControlFailed`] before writing or reading
    /// anything when echo cannot be turned off, and otherwise the same errors
    /// as [`SecureTerminal::prompt_visible`].
    fn prompt_hidden(&mut self, label: &'static str) -> Result<Zeroizing<String>, TerminalError>;
}

/// Why the terminal could not supply a line.
///
/// No variant carries any of the bytes that were read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum TerminalError {
    /// `/dev/tty` could not be opened: the process has no controlling
    /// terminal, so secrets cannot be entered safely.
    NoControllingTerminal,
    /// The device that was opened is not a terminal.
    NotATerminal,
    /// The termination-signal deferral could not be installed.
    SignalControlFailed,
    /// Terminal echo could not be turned off or read back.
    EchoControlFailed,
    /// The user interrupted the prompt, or a termination signal arrived
    /// while it was active.
    Interrupted,
    /// The terminal reached end of input before a newline.
    Closed,
    /// The line is longer than [`MAX_INPUT_LEN`] bytes.
    TooLong,
    /// The line is empty.
    Empty,
    /// The line contains an ASCII control character.
    ControlCharacter,
    /// The line is not valid UTF-8.
    InvalidEncoding,
    /// Another read or write failure.
    Io,
}

impl TerminalError {
    /// A fixed description; every variant maps to a string literal.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::NoControllingTerminal => {
                "no controlling terminal: secrets can only be entered on /dev/tty"
            }
            Self::NotATerminal => "the controlling terminal device is not a terminal",
            Self::SignalControlFailed => "termination-signal handling could not be installed",
            Self::EchoControlFailed => "terminal echo could not be controlled",
            Self::Interrupted => "the prompt was interrupted",
            Self::Closed => "terminal input ended before a complete line",
            Self::TooLong => "terminal input line is too long",
            Self::Empty => "terminal input line is empty",
            Self::ControlCharacter => "terminal input contains a control character",
            Self::InvalidEncoding => "terminal input is not valid UTF-8",
            Self::Io => "terminal I/O failed",
        }
    }
}

impl fmt::Display for TerminalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

impl std::error::Error for TerminalError {}

/// The raw device a [`LineTerminal`] talks to.
///
/// Production uses the `/dev/tty` file; tests use an in-memory script.
pub trait TerminalDevice: Read + Write {
    /// Turns input echo off, remembering the previous state.
    ///
    /// # Errors
    ///
    /// Returns [`TerminalError::EchoControlFailed`] when the state cannot be
    /// read or changed.
    fn disable_echo(&mut self) -> Result<(), TerminalError>;

    /// Restores the state saved by [`TerminalDevice::disable_echo`].
    ///
    /// The saved state must be kept until restoration succeeds, so that a
    /// failed attempt can be repeated.
    ///
    /// # Errors
    ///
    /// Returns [`TerminalError::EchoControlFailed`] when the state cannot be
    /// restored, or [`TerminalError::Interrupted`] when a deferred
    /// termination signal was recorded while echo was off and the process
    /// unexpectedly survived re-raising it.
    fn restore_echo(&mut self) -> Result<(), TerminalError>;
}

/// A [`SecureTerminal`] built on any [`TerminalDevice`].
///
/// [`LineTerminal::open_controlling_tty`] is the production constructor.
pub struct LineTerminal<D> {
    device: D,
}

impl LineTerminal<TtyDevice> {
    /// Opens `/dev/tty` read-write, confirms it is a terminal, and installs
    /// the termination-signal deferral.
    ///
    /// This is the only way the production harness obtains input.  Failure
    /// here is fatal on purpose: without a controlling terminal there is no
    /// safe place to type a password.
    ///
    /// # Errors
    ///
    /// Returns [`TerminalError::NoControllingTerminal`] when the device cannot
    /// be opened, [`TerminalError::NotATerminal`] when it can but is not a
    /// terminal, and [`TerminalError::SignalControlFailed`] when the signal
    /// deferral cannot be registered.
    pub fn open_controlling_tty() -> Result<Self, TerminalError> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(TTY_PATH)
            .map_err(|_| TerminalError::NoControllingTerminal)?;
        if !isatty(&file) {
            return Err(TerminalError::NotATerminal);
        }
        SignalDeferral::install()?;
        Ok(Self {
            device: TtyDevice { file, saved: None },
        })
    }
}

impl<D: TerminalDevice> LineTerminal<D> {
    /// Wraps a device.  Exposed for tests and alternative front ends.
    #[must_use]
    pub fn new(device: D) -> Self {
        Self { device }
    }

    fn write_all(&mut self, bytes: &[u8]) -> Result<(), TerminalError> {
        write_flush(&mut self.device, bytes)
    }

    /// Borrows the device so tests can inspect what was written.
    #[cfg(test)]
    pub(crate) fn device(&self) -> &D {
        &self.device
    }
}

fn write_flush(device: &mut impl Write, bytes: &[u8]) -> Result<(), TerminalError> {
    device
        .write_all(bytes)
        .and_then(|()| device.flush())
        .map_err(|_| TerminalError::Io)
}

impl<D: TerminalDevice> SecureTerminal for LineTerminal<D> {
    fn notice(&mut self, text: &'static str) -> Result<(), TerminalError> {
        self.write_all(text.as_bytes())?;
        self.write_all(b"\n")
    }

    fn prompt_visible(&mut self, label: &'static str) -> Result<Zeroizing<String>, TerminalError> {
        self.write_all(label.as_bytes())?;
        read_line(&mut self.device)
    }

    fn prompt_hidden(&mut self, label: &'static str) -> Result<Zeroizing<String>, TerminalError> {
        let line = {
            // Echo goes off before the label appears, so a user who starts
            // typing as soon as they see the prompt cannot be echoed.
            let mut guard = EchoGuard::disable(&mut self.device)?;
            let line = write_flush(guard.device(), label.as_bytes())
                .and_then(|()| read_line(guard.device()));
            guard.restore()?;
            line
        };
        // The user's newline was swallowed with echo off.
        self.write_all(b"\n")?;
        line
    }
}

/// Keeps echo off for a scope and restores it on every exit path.
///
/// [`EchoGuard::restore`] reports a restoration failure and leaves the guard
/// unrestored, so that `Drop` tries again on the way out; `Drop` itself
/// cannot report, which is why callers restore explicitly first.
struct EchoGuard<'a, D: TerminalDevice> {
    device: &'a mut D,
    restored: bool,
}

impl<'a, D: TerminalDevice> EchoGuard<'a, D> {
    fn disable(device: &'a mut D) -> Result<Self, TerminalError> {
        device.disable_echo()?;
        Ok(Self {
            device,
            restored: false,
        })
    }

    fn device(&mut self) -> &mut D {
        self.device
    }

    fn restore(&mut self) -> Result<(), TerminalError> {
        if self.restored {
            return Ok(());
        }
        let result = self.device.restore_echo();
        // Only a confirmed restoration ends the guard's responsibility; any
        // other outcome, including a deferred signal that unexpectedly did
        // not terminate the process, leaves the `Drop` retry in place.
        if result.is_ok() {
            self.restored = true;
        }
        result
    }
}

impl<D: TerminalDevice> Drop for EchoGuard<'_, D> {
    fn drop(&mut self) {
        if !self.restored {
            // Last attempt; nothing sensible can be done with a failure here.
            let _ = self.device.restore_echo();
        }
    }
}

/// Bytes that a terminal with `ISIG` on would have turned into signals.
///
/// `ETX` (Ctrl-C, `SIGINT`), `FS` (Ctrl-\, `SIGQUIT`) and `SUB` (Ctrl-Z,
/// `SIGTSTP`).  With `ISIG` off during a hidden prompt they reach the line
/// reader as bytes and abort the prompt.
const INTERRUPT_BYTES: [u8; 3] = [0x03, 0x1c, 0x1a];

/// Upper bound on bytes discarded while draining a rejected line.
///
/// In canonical mode the newline that ends the current line is already
/// queued when the first byte is read, so draining normally stops there;
/// the bound only guards a device that never delivers one.
const DRAIN_CEILING: usize = 64 * 1024;

/// Reads one line, byte by byte, into zeroizing storage.
///
/// Reading a byte at a time means no bytes past the newline are consumed and
/// no oversized buffer is ever allocated.  The trailing newline and an
/// optional carriage return before it are removed.  A line rejected before
/// its end (an interrupt byte, or one byte past [`MAX_INPUT_LEN`]) is drained
/// to its newline first, so no suffix of it remains queued for the next
/// reader, which after the harness exits is the invoking shell.
fn read_line(reader: &mut impl Read) -> Result<Zeroizing<String>, TerminalError> {
    let mut bytes = line_buffer();
    let mut byte = Zeroizing::new([0u8; 1]);
    loop {
        match reader.read(&mut *byte) {
            Ok(0) => return Err(TerminalError::Closed),
            Ok(_) if byte[0] == b'\n' => break,
            Ok(_) if INTERRUPT_BYTES.contains(&byte[0]) => {
                return Err(drain_line(reader, TerminalError::Interrupted));
            }
            Ok(_) => {
                if bytes.len() == MAX_INPUT_LEN {
                    return Err(drain_line(reader, TerminalError::TooLong));
                }
                bytes.push(byte[0]);
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(_) => return Err(TerminalError::Io),
        }
    }
    if bytes.last() == Some(&b'\r') {
        bytes.pop();
    }
    // The buffer never grew, so no earlier allocation holds a prefix of
    // the line; `Zeroizing` wipes this one on drop.
    debug_assert_eq!(bytes.capacity(), MAX_INPUT_LEN);
    if bytes.is_empty() {
        return Err(TerminalError::Empty);
    }
    let text = std::str::from_utf8(&bytes).map_err(|_| TerminalError::InvalidEncoding)?;
    if text.chars().any(char::is_control) {
        return Err(TerminalError::ControlCharacter);
    }
    Ok(Zeroizing::new(text.to_owned()))
}

/// The single allocation a hidden line is accumulated into.
///
/// It is sized for the longest accepted line from the start, so pushing up
/// to [`MAX_INPUT_LEN`] bytes never reallocates.  A growing `Vec` would
/// copy the partial secret into a new allocation and free the old one
/// without wiping it; a fixed-capacity one leaves exactly one buffer, and
/// [`Zeroizing`] wipes that buffer on drop.
fn line_buffer() -> Zeroizing<Vec<u8>> {
    Zeroizing::new(Vec::with_capacity(MAX_INPUT_LEN))
}

/// Discards the rest of the current line, up to and including its newline.
///
/// Runs while the caller still holds echo off.  The discarded bytes pass
/// through one zeroized byte buffer and are never accumulated.
fn drain_line(reader: &mut impl Read, error: TerminalError) -> TerminalError {
    let mut byte = Zeroizing::new([0u8; 1]);
    let mut discarded = 0usize;
    while discarded < DRAIN_CEILING {
        match reader.read(&mut *byte) {
            Ok(0) => break,
            Ok(_) if byte[0] == b'\n' => break,
            Ok(_) => discarded += 1,
            Err(failure) if failure.kind() == io::ErrorKind::Interrupted => {}
            Err(_) => break,
        }
    }
    error
}

/// Process-wide deferral of termination signals during hidden prompts.
///
/// Installed once.  `armed` true means the default action runs immediately
/// when a signal arrives, exactly as if nothing were installed.  While a
/// hidden prompt holds the terminal in its modified mode `armed` is false and
/// an arriving signal only records its number in `pending`; the prompt
/// re-arms after restoring the terminal and then emulates the default action
/// for the recorded signal.
struct SignalDeferral {
    armed: Arc<AtomicBool>,
    pending: Arc<AtomicUsize>,
}

static SIGNAL_DEFERRAL: OnceLock<Result<SignalDeferral, TerminalError>> = OnceLock::new();

impl SignalDeferral {
    /// Registers the complete handler set exactly once for the whole process.
    ///
    /// The registration runs inside the `OnceLock` initializer, so a second
    /// caller, on any thread, observes the same result and never registers a
    /// duplicate handler or a second `armed` flag.
    fn install() -> Result<&'static Self, TerminalError> {
        SIGNAL_DEFERRAL
            .get_or_init(Self::register)
            .as_ref()
            .map_err(|error| *error)
    }

    fn register() -> Result<Self, TerminalError> {
        let deferral = Self {
            armed: Arc::new(AtomicBool::new(true)),
            pending: Arc::new(AtomicUsize::new(0)),
        };
        for signal in DEFERRED_SIGNALS {
            // Both actions are pure flag stores, which is what makes them
            // safe to run in signal context; `signal-hook` wraps the
            // registration.  The conditional default is registered first:
            // `armed` starts true, so a signal that arrives while setup is
            // still in progress keeps terminating the process instead of
            // being recorded by a handler whose counterpart does not exist
            // yet.
            signal_hook::flag::register_conditional_default(signal, Arc::clone(&deferral.armed))
                .map_err(|_| TerminalError::SignalControlFailed)?;
            signal_hook::flag::register_usize(
                signal,
                Arc::clone(&deferral.pending),
                usize::try_from(signal).map_err(|_| TerminalError::SignalControlFailed)?,
            )
            .map_err(|_| TerminalError::SignalControlFailed)?;
        }
        Ok(deferral)
    }

    fn disarm(&self) {
        self.armed.store(false, Ordering::SeqCst);
    }

    /// Re-arms and returns the signal recorded while disarmed, if any.
    fn rearm(&self) -> Option<i32> {
        self.armed.store(true, Ordering::SeqCst);
        let pending = self.pending.swap(0, Ordering::SeqCst);
        i32::try_from(pending).ok().filter(|signal| *signal != 0)
    }
}

/// Runs the default action of a signal that was deferred during a prompt.
///
/// For the deferred signals the default action terminates the process, so
/// this normally does not return.
fn terminate_by(signal: i32) -> TerminalError {
    let _ = signal_hook::low_level::emulate_default_handler(signal);
    TerminalError::Interrupted
}

/// Decides what a restoration attempt returns once the deferral is re-armed.
///
/// A signal recorded while the prompt held the terminal always gets its
/// default action now, whether or not the restoration succeeded: the
/// restoration was attempted first, which is the most that can be done, and
/// swallowing the signal would turn `kill` into a no-op.  Without a pending
/// signal the restoration result stands on its own.
fn finish_restore(
    restored: Result<(), TerminalError>,
    pending: Option<i32>,
    terminate: impl FnOnce(i32) -> TerminalError,
) -> Result<(), TerminalError> {
    match pending {
        Some(signal) => Err(terminate(signal)),
        None => restored,
    }
}

/// Decides what a failed attempt to *enter* hidden mode returns.
///
/// The deferral was disarmed before the mode change was tried, so a signal
/// that arrived in that window has been recorded rather than acted on.  The
/// terminal is still in its original mode, so there is nothing to restore;
/// the recorded signal must get its default action now.
fn abandon_hidden_mode(
    pending: Option<i32>,
    terminate: impl FnOnce(i32) -> TerminalError,
) -> TerminalError {
    finish_restore(Err(TerminalError::EchoControlFailed), pending, terminate)
        .err()
        .unwrap_or(TerminalError::EchoControlFailed)
}

/// The `/dev/tty` device with termios-based echo control.
pub struct TtyDevice {
    file: File,
    saved: Option<Termios>,
}

impl TtyDevice {
    /// Wraps an already opened terminal file.  Used by the PTY tests.
    #[cfg(test)]
    pub(crate) fn from_file(file: File) -> Self {
        Self { file, saved: None }
    }
}

/// The terminal mode used while a hidden prompt is active.
fn hidden_mode(saved: &Termios) -> Termios {
    let mut quiet = saved.clone();
    // ECHO off hides the secret.  ISIG off turns Ctrl-C, Ctrl-\ and Ctrl-Z
    // into ordinary bytes for the duration of the read, so a keyboard
    // interrupt cannot end the process before the mode is restored; the
    // byte is rejected by the line reader and the prompt fails cleanly.
    quiet
        .local_modes
        .remove(LocalModes::ECHO | LocalModes::ISIG);
    quiet
}

impl Read for TtyDevice {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.file.read(buf)
    }
}

impl Write for TtyDevice {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.file.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.file.flush()
    }
}

impl TerminalDevice for TtyDevice {
    fn disable_echo(&mut self) -> Result<(), TerminalError> {
        let deferral = SignalDeferral::install()?;
        let saved = tcgetattr(&self.file).map_err(|_| TerminalError::EchoControlFailed)?;
        let quiet = hidden_mode(&saved);
        // Disarm before the mode changes, so there is no window in which a
        // signal can terminate the process with the mode already modified.
        deferral.disarm();
        // `Flush` discards typed-ahead input so a password typed before the
        // prompt appeared is not echoed by the previous mode.
        if tcsetattr(&self.file, OptionalActions::Flush, &quiet).is_err() {
            // Re-arm and do not swallow a signal recorded in the window.
            return Err(abandon_hidden_mode(deferral.rearm(), terminate_by));
        }
        self.saved = Some(saved);
        Ok(())
    }

    fn restore_echo(&mut self) -> Result<(), TerminalError> {
        let deferral = SignalDeferral::install()?;
        // Protect the attempt, and any retry the guard's `Drop` makes, the
        // same way the hidden window itself is protected.
        deferral.disarm();
        let restored = match &self.saved {
            Some(saved) => tcsetattr(&self.file, OptionalActions::Now, saved)
                .map_err(|_| TerminalError::EchoControlFailed),
            None => Ok(()),
        };
        if restored.is_ok() {
            self.saved = None;
        }
        // Re-arm only after the restoration attempt; a signal that arrived
        // meanwhile now gets its default action even if the attempt failed.
        finish_restore(restored, deferral.rearm(), terminate_by)
    }
}

impl fmt::Debug for TtyDevice {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("TtyDevice")
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use std::io::Cursor;
    use std::sync::Mutex;

    use super::*;

    /// Scripted device recording echo transitions, writes, and reads.
    pub(crate) struct FakeDevice {
        input: Cursor<Vec<u8>>,
        pub(crate) output: Vec<u8>,
        pub(crate) events: Vec<&'static str>,
        pub(crate) echo_off: bool,
        pub(crate) fail_disable: bool,
        pub(crate) fail_restore_times: usize,
        pub(crate) pending_signal: Option<i32>,
        pub(crate) terminated: Vec<i32>,
    }

    impl FakeDevice {
        pub(crate) fn new(input: &[u8]) -> Self {
            Self {
                input: Cursor::new(input.to_vec()),
                output: Vec::new(),
                events: Vec::new(),
                echo_off: false,
                fail_disable: false,
                fail_restore_times: 0,
                pending_signal: None,
                terminated: Vec::new(),
            }
        }
    }

    impl Read for FakeDevice {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let n = self.input.read(buf)?;
            if n > 0 {
                self.events.push(if self.echo_off {
                    "read-hidden"
                } else {
                    "read-visible"
                });
            }
            Ok(n)
        }
    }

    impl Write for FakeDevice {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.output.extend_from_slice(buf);
            self.events.push(if self.echo_off {
                "write-hidden"
            } else {
                "write-visible"
            });
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl TerminalDevice for FakeDevice {
        fn disable_echo(&mut self) -> Result<(), TerminalError> {
            if self.fail_disable {
                return Err(TerminalError::EchoControlFailed);
            }
            self.echo_off = true;
            self.events.push("echo-off");
            Ok(())
        }

        fn restore_echo(&mut self) -> Result<(), TerminalError> {
            let restored = if self.fail_restore_times > 0 {
                self.fail_restore_times -= 1;
                self.events.push("echo-restore-failed");
                Err(TerminalError::EchoControlFailed)
            } else {
                self.echo_off = false;
                self.events.push("echo-restored");
                Ok(())
            };
            // Mirrors the production decision: a signal deferred during the
            // prompt wins over the restoration result.
            let pending = self.pending_signal.take();
            let terminated = &mut self.terminated;
            finish_restore(restored, pending, |signal| {
                terminated.push(signal);
                TerminalError::Interrupted
            })
        }
    }

    #[test]
    fn hidden_prompt_disables_echo_before_the_label_and_restores_after_the_read() {
        let mut terminal = LineTerminal::new(FakeDevice::new(b"hunter2\n"));
        let line = terminal.prompt_hidden("Password: ").unwrap();
        assert_eq!(line.as_str(), "hunter2");
        let device = &terminal.device;
        assert!(!device.echo_off);
        // Order: echo off, label written with echo off, hidden reads, echo
        // restored, then the newline written with echo on.
        assert_eq!(device.events[0], "echo-off");
        assert_eq!(device.events[1], "write-hidden");
        let restored = device
            .events
            .iter()
            .position(|e| *e == "echo-restored")
            .unwrap();
        assert!(
            device.events[2..restored]
                .iter()
                .all(|event| *event == "read-hidden")
        );
        assert_eq!(&device.events[restored + 1..], ["write-visible"]);
        let output = String::from_utf8(device.output.clone()).unwrap();
        assert_eq!(output, "Password: \n");
        assert!(!output.contains("hunter2"));
    }

    #[test]
    fn echo_is_restored_when_the_read_fails() {
        let mut terminal = LineTerminal::new(FakeDevice::new(b"no newline"));
        assert_eq!(
            terminal.prompt_hidden("Code: ").unwrap_err(),
            TerminalError::Closed
        );
        assert!(!terminal.device.echo_off);
        let last_echo_event = terminal
            .device
            .events
            .iter()
            .rev()
            .find(|e| e.starts_with("echo"));
        assert_eq!(last_echo_event, Some(&"echo-restored"));
    }

    #[test]
    fn hidden_prompt_writes_and_reads_nothing_when_echo_cannot_be_disabled() {
        let mut device = FakeDevice::new(b"secret\n");
        device.fail_disable = true;
        let mut terminal = LineTerminal::new(device);
        assert_eq!(
            terminal.prompt_hidden("Password: ").unwrap_err(),
            TerminalError::EchoControlFailed
        );
        assert!(terminal.device.events.is_empty());
        assert!(terminal.device.output.is_empty());
    }

    #[test]
    fn a_failed_restoration_is_reported_and_retried_on_drop() {
        let mut device = FakeDevice::new(b"secret\n");
        device.fail_restore_times = 1;
        let mut terminal = LineTerminal::new(device);
        assert_eq!(
            terminal.prompt_hidden("Password: ").unwrap_err(),
            TerminalError::EchoControlFailed
        );
        let events = &terminal.device.events;
        let failed = events
            .iter()
            .position(|e| *e == "echo-restore-failed")
            .unwrap();
        assert_eq!(events[failed + 1], "echo-restored");
        assert!(!terminal.device.echo_off);
    }

    #[test]
    fn a_restoration_that_keeps_failing_is_attempted_exactly_twice() {
        let mut device = FakeDevice::new(b"secret\n");
        device.fail_restore_times = 5;
        let mut terminal = LineTerminal::new(device);
        assert!(terminal.prompt_hidden("Password: ").is_err());
        let attempts = terminal
            .device
            .events
            .iter()
            .filter(|e| **e == "echo-restore-failed")
            .count();
        assert_eq!(attempts, 2);
    }

    #[test]
    fn a_failed_restoration_with_a_surviving_signal_still_retries_on_drop() {
        let mut device = FakeDevice::new(b"secret\n");
        device.fail_restore_times = 1;
        device.pending_signal = Some(SIGTERM);
        let mut terminal = LineTerminal::new(device);
        // The emulated default action "returned", so the prompt reports the
        // interruption instead of terminating.
        assert_eq!(
            terminal.prompt_hidden("Password: ").unwrap_err(),
            TerminalError::Interrupted
        );
        let device = &terminal.device;
        assert_eq!(device.terminated, vec![SIGTERM]);
        let failed = device
            .events
            .iter()
            .position(|e| *e == "echo-restore-failed")
            .unwrap();
        assert_eq!(device.events[failed + 1], "echo-restored");
        assert!(!device.echo_off);
    }

    #[test]
    fn visible_prompt_never_touches_echo() {
        let mut terminal = LineTerminal::new(FakeDevice::new(b"provision\r\n"));
        let line = terminal.prompt_visible("Confirm: ").unwrap();
        assert_eq!(line.as_str(), "provision");
        assert!(
            terminal
                .device
                .events
                .iter()
                .all(|e| *e == "read-visible" || *e == "write-visible")
        );
    }

    #[test]
    fn line_shape_is_enforced() {
        let read = |bytes: &[u8]| read_line(&mut Cursor::new(bytes.to_vec()));
        assert_eq!(read(b"").unwrap_err(), TerminalError::Closed);
        assert_eq!(read(b"\n").unwrap_err(), TerminalError::Empty);
        assert_eq!(read(b"\r\n").unwrap_err(), TerminalError::Empty);
        assert_eq!(
            read(b"a\tb\n").unwrap_err(),
            TerminalError::ControlCharacter
        );
        assert_eq!(read(b"\xff\n").unwrap_err(), TerminalError::InvalidEncoding);
        let mut long = vec![b'a'; MAX_INPUT_LEN + 1];
        long.push(b'\n');
        assert_eq!(read(&long).unwrap_err(), TerminalError::TooLong);
        let mut exact = vec![b'a'; MAX_INPUT_LEN];
        exact.push(b'\n');
        assert_eq!(read(&exact).unwrap().len(), MAX_INPUT_LEN);
        assert_eq!(read("p\u{e9}\n".as_bytes()).unwrap().as_str(), "p\u{e9}");
    }

    #[test]
    fn keyboard_interrupt_bytes_abort_the_prompt_and_restore_echo() {
        for byte in INTERRUPT_BYTES {
            let mut input = b"partial".to_vec();
            input.push(byte);
            input.extend_from_slice(b"rest\n");
            input.extend_from_slice(b"next\n");
            let mut terminal = LineTerminal::new(FakeDevice::new(&input));
            assert_eq!(
                terminal.prompt_hidden("Password: ").unwrap_err(),
                TerminalError::Interrupted
            );
            assert!(!terminal.device.echo_off);
            assert_eq!(
                terminal
                    .device
                    .events
                    .iter()
                    .filter(|e| **e == "echo-restored")
                    .count(),
                1
            );
            // The rest of the rejected line was drained while hidden; the
            // next prompt sees the following line, not the secret suffix.
            assert_eq!(terminal.prompt_visible("> ").unwrap().as_str(), "next");
        }
    }

    #[test]
    fn an_overlong_line_is_drained_to_its_end() {
        let mut input = vec![b'a'; MAX_INPUT_LEN + 1];
        input.extend_from_slice(b"SECRET-SUFFIX\nnext\n");
        let mut cursor = Cursor::new(input);
        assert_eq!(read_line(&mut cursor).unwrap_err(), TerminalError::TooLong);
        assert_eq!(read_line(&mut cursor).unwrap().as_str(), "next");
        let mut cursor = Cursor::new(vec![b'a'; MAX_INPUT_LEN + 1]);
        assert_eq!(read_line(&mut cursor).unwrap_err(), TerminalError::TooLong);
        assert_eq!(read_line(&mut cursor).unwrap_err(), TerminalError::Closed);
    }

    #[test]
    fn only_one_line_is_consumed() {
        let mut cursor = Cursor::new(b"first\nsecond\n".to_vec());
        assert_eq!(read_line(&mut cursor).unwrap().as_str(), "first");
        assert_eq!(read_line(&mut cursor).unwrap().as_str(), "second");
    }

    #[test]
    fn the_line_buffer_never_reallocates_while_accumulating_a_secret() {
        let mut buffer = line_buffer();
        let capacity = buffer.capacity();
        assert_eq!(capacity, MAX_INPUT_LEN);
        let before = buffer.as_ptr();
        for byte in 0..MAX_INPUT_LEN {
            buffer.push(u8::try_from(byte % 251).unwrap());
        }
        assert_eq!(buffer.len(), MAX_INPUT_LEN);
        assert_eq!(buffer.capacity(), capacity);
        assert_eq!(buffer.as_ptr(), before);
        // A full-length line goes through `read_line` without tripping the
        // structural assertion either.
        let mut exact = vec![b'a'; MAX_INPUT_LEN];
        exact.push(b'\n');
        assert_eq!(
            read_line(&mut Cursor::new(exact)).unwrap().len(),
            MAX_INPUT_LEN
        );
    }

    #[test]
    fn errors_are_static_text() {
        for error in [
            TerminalError::NoControllingTerminal,
            TerminalError::NotATerminal,
            TerminalError::SignalControlFailed,
            TerminalError::EchoControlFailed,
            TerminalError::Interrupted,
            TerminalError::Closed,
            TerminalError::TooLong,
            TerminalError::Empty,
            TerminalError::ControlCharacter,
            TerminalError::InvalidEncoding,
            TerminalError::Io,
        ] {
            assert_eq!(error.to_string(), error.label());
            assert!(!format!("{error:?}").is_empty());
        }
    }

    /// Serializes the tests that touch the process-wide signal deferral or
    /// send a signal to the test process.
    static SIGNAL_TESTS: Mutex<()> = Mutex::new(());

    #[test]
    fn a_signal_during_a_hidden_prompt_is_recorded_not_acted_on() {
        let _serial = SIGNAL_TESTS.lock().unwrap_or_else(|e| e.into_inner());
        let deferral = SignalDeferral::install().unwrap();
        deferral.disarm();
        // With the deferral disarmed this must not terminate the process.
        signal_hook::low_level::raise(SIGTERM).unwrap();
        assert_eq!(deferral.pending.load(Ordering::SeqCst), SIGTERM as usize);
        assert_eq!(deferral.rearm(), Some(SIGTERM));
        assert_eq!(deferral.rearm(), None);
        assert!(deferral.armed.load(Ordering::SeqCst));
    }

    /// Opens a pseudo-terminal pair and returns the slave side as a file.
    fn open_pty_slave() -> File {
        use std::os::unix::fs::OpenOptionsExt;

        use rustix::pty::{OpenptFlags, grantpt, openpt, ptsname, unlockpt};

        let master = openpt(OpenptFlags::RDWR | OpenptFlags::NOCTTY).expect("openpt");
        grantpt(&master).expect("grantpt");
        unlockpt(&master).expect("unlockpt");
        let name = ptsname(&master, Vec::new()).expect("ptsname");
        let path = name.to_str().expect("utf-8 pty name").to_owned();
        let slave = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(i32::try_from(rustix::fs::OFlags::NOCTTY.bits()).unwrap())
            .open(path)
            .expect("open pty slave");
        // Keep the master alive for the slave's lifetime by leaking it into
        // the test; the pair is torn down when the process exits.
        std::mem::forget(master);
        slave
    }

    #[test]
    fn a_real_pty_has_echo_and_isig_cleared_only_while_hidden() {
        let _serial = SIGNAL_TESTS.lock().unwrap_or_else(|e| e.into_inner());
        let slave = open_pty_slave();
        let original = tcgetattr(&slave).expect("tcgetattr");
        assert!(original.local_modes.contains(LocalModes::ECHO));
        assert!(original.local_modes.contains(LocalModes::ISIG));
        let mut device = TtyDevice::from_file(slave);

        device.disable_echo().unwrap();
        let hidden = tcgetattr(&device.file).expect("tcgetattr");
        assert!(!hidden.local_modes.contains(LocalModes::ECHO));
        assert!(!hidden.local_modes.contains(LocalModes::ISIG));
        assert!(hidden.local_modes.contains(LocalModes::ICANON));
        assert!(
            !SignalDeferral::install()
                .unwrap()
                .armed
                .load(Ordering::SeqCst)
        );

        device.restore_echo().unwrap();
        let restored = tcgetattr(&device.file).expect("tcgetattr");
        assert_eq!(restored.local_modes, original.local_modes);
        assert!(
            SignalDeferral::install()
                .unwrap()
                .armed
                .load(Ordering::SeqCst)
        );
        assert!(device.saved.is_none());
    }

    #[test]
    fn a_pending_signal_wins_over_the_restoration_result() {
        let mut terminated = Vec::new();
        let mut terminate = |signal: i32| {
            terminated.push(signal);
            TerminalError::Interrupted
        };
        assert_eq!(finish_restore(Ok(()), None, &mut terminate), Ok(()));
        assert_eq!(
            finish_restore(Err(TerminalError::EchoControlFailed), None, &mut terminate),
            Err(TerminalError::EchoControlFailed)
        );
        assert_eq!(
            finish_restore(Ok(()), Some(SIGTERM), &mut terminate),
            Err(TerminalError::Interrupted)
        );
        assert_eq!(
            finish_restore(
                Err(TerminalError::EchoControlFailed),
                Some(SIGHUP),
                &mut terminate
            ),
            Err(TerminalError::Interrupted)
        );
        assert_eq!(terminated, vec![SIGTERM, SIGHUP]);
    }

    #[test]
    fn a_failed_entry_into_hidden_mode_still_honors_a_pending_signal() {
        let mut terminated = Vec::new();
        let mut terminate = |signal: i32| {
            terminated.push(signal);
            TerminalError::Interrupted
        };
        assert_eq!(
            abandon_hidden_mode(None, &mut terminate),
            TerminalError::EchoControlFailed
        );
        assert_eq!(
            abandon_hidden_mode(Some(SIGTERM), &mut terminate),
            TerminalError::Interrupted
        );
        assert_eq!(terminated, vec![SIGTERM]);
    }

    #[test]
    fn the_deferral_is_installed_once_and_shared() {
        let _serial = SIGNAL_TESTS.lock().unwrap_or_else(|e| e.into_inner());
        let first = SignalDeferral::install().unwrap();
        let second = SignalDeferral::install().unwrap();
        assert!(std::ptr::eq(first, second));
        assert!(Arc::ptr_eq(&first.armed, &second.armed));
        assert!(Arc::ptr_eq(&first.pending, &second.pending));
    }

    /// Environment variable that turns a test process into the child of
    /// [`a_child_process_restores_the_terminal_before_a_deferred_signal_ends_it`].
    /// Test-only; it carries a pseudo-terminal path, never a credential.
    const PTY_CHILD_ENV: &str = "COFFER_LIVE_AUTH_TEST_PTY_CHILD";

    /// Child role of the process-level regression test.  A no-op unless the
    /// parent set [`PTY_CHILD_ENV`].
    #[test]
    fn pty_child_role() {
        let Some(path) = std::env::var_os(PTY_CHILD_ENV) else {
            return;
        };
        let slave = OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .expect("child opens the pty slave");
        let mut device = TtyDevice::from_file(slave);
        device.disable_echo().expect("child enters hidden mode");
        write_flush(&mut device, b"READY\n").expect("child signals readiness");
        // Blocks until the parent supplies a line; the parent sends the
        // signal first, so it is pending by the time this returns.
        let _ = read_line(&mut device);
        // Restores the mode, re-arms, and emulates the deferred default
        // action, which terminates this process.
        let _ = device.restore_echo();
        write_flush(&mut device, b"SURVIVED\n").expect("child reports survival");
    }

    #[test]
    fn a_child_process_restores_the_terminal_before_a_deferred_signal_ends_it() {
        use std::os::unix::process::ExitStatusExt;
        use std::process::{Command, Stdio};
        use std::sync::mpsc;
        use std::time::Duration;

        use rustix::process::{Pid, Signal, kill_process};
        use rustix::pty::{OpenptFlags, grantpt, openpt, ptsname, unlockpt};

        let _serial = SIGNAL_TESTS.lock().unwrap_or_else(|e| e.into_inner());
        let master = openpt(OpenptFlags::RDWR | OpenptFlags::NOCTTY).expect("openpt");
        grantpt(&master).expect("grantpt");
        unlockpt(&master).expect("unlockpt");
        let slave_path = ptsname(&master, Vec::new())
            .expect("ptsname")
            .to_str()
            .expect("utf-8 pty name")
            .to_owned();
        let mut master = File::from(master);

        /// Kills and reaps the child on every exit path, including a panic
        /// in an assertion below, so a failed run never leaves a process
        /// blocked on the pseudo-terminal.
        struct ChildGuard(std::process::Child);

        impl Drop for ChildGuard {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }

        let child = Command::new(std::env::current_exe().expect("test executable"))
            .args([
                "--exact",
                "terminal::tests::pty_child_role",
                "--test-threads",
                "1",
            ])
            .env(PTY_CHILD_ENV, &slave_path)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn child");
        let mut child = ChildGuard(child);

        // Wait for READY on the master side, with a deadline so a broken
        // child fails the test instead of hanging it.
        let (sender, receiver) = mpsc::channel();
        let mut reader = master.try_clone().expect("clone master");
        std::thread::spawn(move || {
            let mut seen = Vec::new();
            let mut byte = [0u8; 1];
            while let Ok(1) = reader.read(&mut byte) {
                seen.push(byte[0]);
                if seen.ends_with(b"READY") {
                    break;
                }
            }
            let _ = sender.send(seen);
        });
        let seen = receiver
            .recv_timeout(Duration::from_secs(30))
            .expect("child became ready");
        assert!(seen.ends_with(b"READY"));

        // The pty shares one termios between master and slave: the child
        // holds it in hidden mode now.
        let hidden = tcgetattr(&master).expect("tcgetattr");
        assert!(!hidden.local_modes.contains(LocalModes::ECHO));
        assert!(!hidden.local_modes.contains(LocalModes::ISIG));

        // Deliver the signal while the prompt is active, then end the line so
        // the child's read returns.
        let pid = Pid::from_child(&child.0);
        kill_process(pid, Signal::TERM).expect("kill");
        master.write_all(b"x\n").expect("end the line");
        master.flush().expect("flush");

        // Bounded reap: a child that neither restores nor dies within the
        // deadline fails the test instead of hanging the gate; the guard
        // then kills it.
        let deadline = std::time::Instant::now() + Duration::from_secs(30);
        let status = loop {
            if let Some(status) = child.0.try_wait().expect("try_wait") {
                break status;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "child did not exit within the deadline"
            );
            std::thread::sleep(Duration::from_millis(20));
        };
        assert_eq!(
            status.signal(),
            Some(SIGTERM),
            "child must die by the deferred SIGTERM"
        );
        let restored = tcgetattr(&master).expect("tcgetattr");
        assert!(restored.local_modes.contains(LocalModes::ECHO));
        assert!(restored.local_modes.contains(LocalModes::ISIG));
    }

    #[test]
    fn hidden_mode_changes_nothing_but_echo_and_isig() {
        let _serial = SIGNAL_TESTS.lock().unwrap_or_else(|e| e.into_inner());
        let slave = open_pty_slave();
        let original = tcgetattr(&slave).expect("tcgetattr");
        let hidden = hidden_mode(&original);
        assert_eq!(hidden.input_modes, original.input_modes);
        assert_eq!(hidden.output_modes, original.output_modes);
        assert_eq!(hidden.control_modes, original.control_modes);
        assert_eq!(
            hidden.local_modes | LocalModes::ECHO | LocalModes::ISIG,
            original.local_modes | LocalModes::ECHO | LocalModes::ISIG
        );
    }

    /// Opens a pseudo-terminal pair, returning the master and the slave.
    fn open_pty_pair() -> (File, File) {
        use std::os::unix::fs::OpenOptionsExt;

        use rustix::pty::{OpenptFlags, grantpt, openpt, ptsname, unlockpt};

        let master = openpt(OpenptFlags::RDWR | OpenptFlags::NOCTTY).expect("openpt");
        grantpt(&master).expect("grantpt");
        unlockpt(&master).expect("unlockpt");
        let name = ptsname(&master, Vec::new()).expect("ptsname");
        let path = name.to_str().expect("utf-8 pty name").to_owned();
        let slave = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(i32::try_from(rustix::fs::OFlags::NOCTTY.bits()).unwrap())
            .open(path)
            .expect("open pty slave");
        (File::from(master), slave)
    }

    #[test]
    fn a_real_pty_rejected_line_is_drained_before_the_next_reader() {
        let _serial = SIGNAL_TESTS.lock().unwrap_or_else(|e| e.into_inner());
        let (mut master, slave) = open_pty_pair();
        let mut device = TtyDevice::from_file(slave);
        // Hidden mode, exactly as in production: ECHO and ISIG off, ICANON
        // on, so the interrupt byte arrives as data within a queued line.
        device.disable_echo().expect("hidden mode");

        master
            .write_all(b"abc\x03SECRET-SUFFIX\nNEXT\n")
            .expect("queue lines");
        assert_eq!(
            read_line(&mut device).unwrap_err(),
            TerminalError::Interrupted
        );
        assert_eq!(read_line(&mut device).unwrap().as_str(), "NEXT");

        let mut long = vec![b'b'; MAX_INPUT_LEN + 1];
        long.extend_from_slice(b"SECRET-TAIL\nAFTER\n");
        master.write_all(&long).expect("queue long line");
        assert_eq!(read_line(&mut device).unwrap_err(), TerminalError::TooLong);
        assert_eq!(read_line(&mut device).unwrap().as_str(), "AFTER");

        device.restore_echo().expect("restore");
    }
}
