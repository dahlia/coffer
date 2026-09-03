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

//! Parent-side process and deadline boundary.

use std::io::{ErrorKind, Read, Write};
use std::os::fd::AsRawFd as _;
use std::os::unix::fs::PermissionsExt as _;
use std::os::unix::process::CommandExt as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use coffer_bootstrap::InstalledLibraries;

use crate::PropertyKey;
use crate::error::BridgeError;
use crate::ipc::{self, Operation, Request, Response};

/// A bootstrap-verified support-library installation passed as a capability.
#[derive(Clone, Eq, PartialEq)]
pub struct VerifiedLibraryPaths {
    root: PathBuf,
}

impl VerifiedLibraryPaths {
    /// Captures the immutable root of a successfully verified installation.
    #[must_use]
    pub fn from_installation(installation: &InstalledLibraries) -> Self {
        Self {
            root: installation.library_root().to_owned(),
        }
    }
}

impl core::fmt::Debug for VerifiedLibraryPaths {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("VerifiedLibraryPaths")
            .field("root", &"<redacted-path>")
            .finish()
    }
}

/// Result of the deliberately narrow local-only ADI smoke operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SmokeResult {
    /// Whether ADI reported the sentinel account as locally provisioned.
    pub provisioned: bool,
    /// Non-secret classifications of Android property lookups.
    pub property_queries: Vec<PropertyKey>,
}

/// Starts exactly one bounded helper process for each requested operation.
pub struct HelperClient {
    executable: PathBuf,
    timeout: Duration,
}

impl HelperClient {
    /// Creates a client for a dedicated helper executable and deadline.
    ///
    /// The executable is not invoked until an operation method is called.
    #[must_use]
    pub fn new(executable: impl Into<PathBuf>, timeout: Duration) -> Self {
        Self {
            executable: executable.into(),
            timeout,
        }
    }

    /// Executes the single offline smoke request without retrying failures.
    ///
    /// # Errors
    ///
    /// Returns a stage-safe error for process, framing, helper crash, timeout,
    /// ABI, loader, sandbox, or ADI status failure.  A failed call is never
    /// retried internally.
    pub fn offline_smoke(
        &self,
        libraries: &VerifiedLibraryPaths,
    ) -> Result<SmokeResult, BridgeError> {
        match self.invoke(Operation::OfflineSmoke, &libraries.root)? {
            Response::Smoke {
                provisioned,
                properties,
            } => Ok(SmokeResult {
                provisioned,
                property_queries: properties,
            }),
            Response::Error(error) => Err(error),
            Response::SandboxEnabled => Err(BridgeError::InvalidMessage),
        }
    }

    /// Verifies that the helper can install and test its mandatory sandbox.
    ///
    /// # Errors
    ///
    /// Returns [`BridgeError::SandboxUnavailable`] rather than running
    /// without protection when any confinement layer is unavailable.
    pub fn probe_sandbox(&self) -> Result<(), BridgeError> {
        match self.invoke(Operation::SandboxProbe, Path::new(""))? {
            Response::SandboxEnabled => Ok(()),
            Response::Error(error) => Err(error),
            Response::Smoke { .. } => Err(BridgeError::InvalidMessage),
        }
    }

    fn invoke(&self, operation: Operation, library_root: &Path) -> Result<Response, BridgeError> {
        let state = tempfile::Builder::new()
            .prefix("coffer-anisette-state-")
            .tempdir()
            .map_err(|_| BridgeError::ProcessIo)?;
        std::fs::set_permissions(state.path(), std::fs::Permissions::from_mode(0o700))
            .map_err(|_| BridgeError::ProcessIo)?;
        let state_path = std::fs::canonicalize(state.path()).map_err(|_| BridgeError::ProcessIo)?;
        let mut command = Command::new(&self.executable);
        let result = invoke_command(
            &mut command,
            &Request {
                operation,
                library_root: library_root.to_owned(),
                state_directory: state_path,
            },
            self.timeout,
        );
        state.close().map_err(|_| BridgeError::ProcessIo)?;
        result
    }
}

impl core::fmt::Debug for HelperClient {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("HelperClient")
            .field("executable", &"<redacted-path>")
            .field("timeout", &self.timeout)
            .finish()
    }
}

#[allow(unsafe_code)]
fn invoke_command(
    command: &mut Command,
    request: &Request,
    timeout: Duration,
) -> Result<Response, BridgeError> {
    let deadline = Instant::now()
        .checked_add(timeout)
        .ok_or(BridgeError::TimedOut)?;
    let mut child = command
        .process_group(0)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        // Proprietary diagnostics may contain sensitive material.  The helper
        // protocol is the only output accepted by the parent.
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| BridgeError::ProcessIo)?;

    let Some(mut stdin) = child.stdin.take() else {
        terminate(&mut child);
        return Err(BridgeError::ProcessIo);
    };
    if let Err(error) = ipc::write_request(&mut stdin, request)
        .and_then(|()| stdin.flush().map_err(|_| BridgeError::ProcessIo))
    {
        drop(stdin);
        terminate(&mut child);
        return Err(error);
    }
    drop(stdin);

    let Some(mut stdout) = child.stdout.take() else {
        terminate(&mut child);
        return Err(BridgeError::ProcessIo);
    };
    let descriptor = stdout.as_raw_fd();
    // SAFETY: `descriptor` is the live, uniquely owned child stdout pipe.  The
    // nonblocking flag lets this thread enforce one deadline over both process
    // exit and output EOF, including when a descendant inherited the pipe.
    let flags = unsafe { libc::fcntl(descriptor, libc::F_GETFL) };
    // SAFETY: same live descriptor; `flags` came from F_GETFL.
    if flags < 0 || unsafe { libc::fcntl(descriptor, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0
    {
        terminate(&mut child);
        return Err(BridgeError::ProcessIo);
    }

    let mut bytes = Vec::new();
    let mut buffer = [0u8; 4096];
    let mut status = None;
    let mut output_eof = false;
    loop {
        while !output_eof {
            match stdout.read(&mut buffer) {
                Ok(0) => output_eof = true,
                Ok(count) => {
                    if bytes.len().saturating_add(count) > ipc::MAX_FRAME_BYTES {
                        terminate(&mut child);
                        return Err(BridgeError::InvalidMessage);
                    }
                    bytes.extend_from_slice(&buffer[..count]);
                }
                Err(error) if error.kind() == ErrorKind::WouldBlock => break,
                Err(error) if error.kind() == ErrorKind::Interrupted => {}
                Err(_) => {
                    terminate(&mut child);
                    return Err(BridgeError::ProcessIo);
                }
            }
        }
        if status.is_none() {
            match child.try_wait() {
                Ok(Some(exit)) => status = Some(exit),
                Ok(None) => {}
                Err(_) => {
                    terminate(&mut child);
                    return Err(BridgeError::ProcessIo);
                }
            }
        }
        if status.is_some() && output_eof {
            break;
        }
        if Instant::now() >= deadline {
            terminate(&mut child);
            return Err(BridgeError::TimedOut);
        }
        std::thread::sleep(Duration::from_millis(2));
    }
    let status = status.ok_or(BridgeError::ProcessIo)?;
    if !status.success() {
        #[cfg(unix)]
        {
            use std::os::unix::process::ExitStatusExt as _;
            if status.signal().is_some() || matches!(status.code(), Some(126) | Some(134)) {
                return Err(BridgeError::HelperCrashed);
            }
        }
        return Err(BridgeError::HelperFailed);
    }
    ipc::read_response(std::io::Cursor::new(bytes)).and_then(|response| match response {
        Response::Error(error) => Err(error),
        response => Ok(response),
    })
}

#[allow(unsafe_code)]
fn terminate(child: &mut std::process::Child) {
    if let Ok(pid) = libc::pid_t::try_from(child.id()) {
        // SAFETY: every command launched by `invoke_command` starts a new
        // process group whose ID is the direct child's PID.  A negative PID
        // targets that group, including descendants that inherited stdout.
        let _ = unsafe { libc::kill(-pid, libc::SIGKILL) };
    }
    let _ = child.kill();
    let _ = child.wait();
}

#[cfg(test)]
mod tests {
    use super::*;

    fn probe_request() -> Request {
        Request {
            operation: Operation::SandboxProbe,
            library_root: PathBuf::new(),
            state_directory: PathBuf::from("/tmp/unused-test-state"),
        }
    }

    #[test]
    fn abort_is_a_stage_safe_crash_and_is_not_retried() {
        let mut command = Command::new("sh");
        command.args(["-c", "cat >/dev/null; kill -ABRT $$"]);
        assert_eq!(
            invoke_command(&mut command, &probe_request(), Duration::from_secs(1)),
            Err(BridgeError::HelperCrashed)
        );
    }

    #[test]
    fn abort_shim_exit_code_is_a_stage_safe_crash() {
        let mut command = Command::new("sh");
        command.args(["-c", "cat >/dev/null; exit 134"]);
        assert_eq!(
            invoke_command(&mut command, &probe_request(), Duration::from_secs(1)),
            Err(BridgeError::HelperCrashed)
        );
    }

    #[test]
    fn timeout_kills_the_single_helper_invocation() {
        let mut command = Command::new("sh");
        command.args(["-c", "cat >/dev/null; sleep 5"]);
        assert_eq!(
            invoke_command(&mut command, &probe_request(), Duration::from_millis(25)),
            Err(BridgeError::TimedOut)
        );
    }

    #[test]
    fn descendant_holding_stdout_cannot_extend_the_deadline() {
        let mut command = Command::new("sh");
        command.args(["-c", "cat >/dev/null; (sleep 5) & exit 0"]);
        let started = Instant::now();
        assert_eq!(
            invoke_command(&mut command, &probe_request(), Duration::from_millis(25)),
            Err(BridgeError::TimedOut)
        );
        assert!(started.elapsed() < Duration::from_secs(1));
    }

    #[test]
    fn malformed_helper_output_is_rejected() {
        let mut command = Command::new("sh");
        command.args(["-c", "cat >/dev/null; printf malformed"]);
        assert_eq!(
            invoke_command(&mut command, &probe_request(), Duration::from_secs(1)),
            Err(BridgeError::InvalidMessage)
        );
    }

    #[test]
    fn debug_output_redacts_executable_and_library_paths() {
        let client = HelperClient::new("/secret-looking-helper", Duration::from_secs(1));
        let libraries = VerifiedLibraryPaths {
            root: PathBuf::from("/secret-looking-library"),
        };
        assert!(!format!("{client:?}").contains("secret-looking"));
        assert!(!format!("{libraries:?}").contains("secret-looking"));
    }
}
