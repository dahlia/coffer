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

//! Parent-side capability, process, ownership, and deadline boundary.

use std::io::{ErrorKind, Read, Write};
use std::marker::PhantomData;
use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd};
use std::os::unix::process::CommandExt as _;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::rc::Rc;
use std::sync::mpsc::{self, RecvTimeoutError, Sender};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use coffer_bootstrap::InstalledLibraries;
use zeroize::Zeroizing;

use crate::PropertyKey;
use crate::error::BridgeError;
use crate::ipc::{self, Operation, Request, Response, TransactionCommand};
use crate::state::{
    GenerationLeaseHandle, PreparedGeneration, ProvisioningStore, expire_generation,
};
use crate::types::{AndroidId, DirectoryServiceId, OtpMaterial, SecretBytes, SynchronizeMaterial};

pub(crate) const STATE_CAPABILITY_FD: libc::c_int = 3;

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

/// Starts one bounded helper process for each one-shot operation.
pub struct HelperClient {
    executable: PathBuf,
    timeout: Duration,
}

struct Invocation<'a> {
    android_id: &'a [u8],
    secret: &'a [u8],
    publish: bool,
}

impl HelperClient {
    /// Creates a client for a dedicated helper executable and deadline.
    #[must_use]
    pub fn new(executable: impl Into<PathBuf>, timeout: Duration) -> Self {
        Self {
            executable: executable.into(),
            timeout,
        }
    }

    /// Executes the offline load/query smoke operation without retrying.
    ///
    /// # Errors
    ///
    /// Returns a stage-safe helper or state error.
    pub fn offline_smoke(
        &self,
        libraries: &VerifiedLibraryPaths,
        store: &ProvisioningStore,
    ) -> Result<SmokeResult, BridgeError> {
        match self.invoke(
            Operation::OfflineSmoke,
            libraries,
            store,
            DirectoryServiceId::LOCAL_MACHINE,
            Invocation {
                android_id: &[],
                secret: &[],
                publish: false,
            },
        )? {
            Response::Smoke {
                provisioned,
                properties,
            } => Ok(SmokeResult {
                provisioned,
                property_queries: properties,
            }),
            _ => Err(BridgeError::InvalidMessage),
        }
    }

    /// Verifies mandatory confinement using an XDG-bound state capability.
    ///
    /// # Errors
    ///
    /// Returns [`BridgeError::SandboxUnavailable`] if any layer is absent.
    pub fn probe_sandbox(&self, store: &ProvisioningStore) -> Result<(), BridgeError> {
        let libraries = VerifiedLibraryPaths {
            root: PathBuf::new(),
        };
        match self.invoke(
            Operation::SandboxProbe,
            &libraries,
            store,
            DirectoryServiceId::LOCAL_MACHINE,
            Invocation {
                android_id: &[],
                secret: &[],
                publish: false,
            },
        )? {
            Response::SandboxEnabled => Ok(()),
            _ => Err(BridgeError::InvalidMessage),
        }
    }

    /// Configures one helper process with the fixed Android identifier.
    ///
    /// # Errors
    ///
    /// Returns once on the first native or process failure; it never retries.
    pub fn set_android_id(
        &self,
        libraries: &VerifiedLibraryPaths,
        store: &ProvisioningStore,
        android_id: &AndroidId,
    ) -> Result<(), BridgeError> {
        match self.invoke(
            Operation::SetAndroidId,
            libraries,
            store,
            DirectoryServiceId::LOCAL_MACHINE,
            Invocation {
                android_id: android_id.expose(),
                secret: &[],
                publish: false,
            },
        )? {
            Response::Unit(Operation::SetAndroidId) => Ok(()),
            _ => Err(BridgeError::InvalidMessage),
        }
    }

    /// Queries provisioned state in one non-retried helper invocation.
    ///
    /// # Errors
    ///
    /// Returns a stage-safe helper or state error.
    pub fn is_machine_provisioned(
        &self,
        libraries: &VerifiedLibraryPaths,
        store: &ProvisioningStore,
        ds_id: DirectoryServiceId,
        android_id: &AndroidId,
    ) -> Result<bool, BridgeError> {
        match self.invoke(
            Operation::QueryProvisioned,
            libraries,
            store,
            ds_id,
            Invocation {
                android_id: android_id.expose(),
                secret: &[],
                publish: false,
            },
        )? {
            Response::Provisioned(value) => Ok(value),
            _ => Err(BridgeError::InvalidMessage),
        }
    }

    /// Requests MID/OTP material in one non-retried helper invocation.
    ///
    /// # Errors
    ///
    /// Returns a stage-safe helper, state, native, or framing error.
    pub fn request_otp(
        &self,
        libraries: &VerifiedLibraryPaths,
        store: &ProvisioningStore,
        ds_id: DirectoryServiceId,
        android_id: &AndroidId,
    ) -> Result<OtpMaterial, BridgeError> {
        match self.invoke(
            Operation::RequestOtp,
            libraries,
            store,
            ds_id,
            Invocation {
                android_id: android_id.expose(),
                secret: &[],
                publish: true,
            },
        )? {
            Response::SecretPair {
                operation: Operation::RequestOtp,
                first,
                second,
            } => Ok(OtpMaterial {
                machine_id: SecretBytes::from_zeroizing(first)?,
                one_time_password: SecretBytes::from_zeroizing(second)?,
            }),
            _ => Err(BridgeError::InvalidMessage),
        }
    }

    /// Runs native synchronization once and publishes its complete state.
    ///
    /// # Errors
    ///
    /// Returns a stage-safe helper, state, native, or framing error.
    pub fn synchronize(
        &self,
        libraries: &VerifiedLibraryPaths,
        store: &ProvisioningStore,
        ds_id: DirectoryServiceId,
        android_id: &AndroidId,
        sim: SecretBytes,
    ) -> Result<SynchronizeMaterial, BridgeError> {
        match self.invoke(
            Operation::Synchronize,
            libraries,
            store,
            ds_id,
            Invocation {
                android_id: android_id.expose(),
                secret: sim.expose(),
                publish: true,
            },
        )? {
            Response::SecretPair {
                operation: Operation::Synchronize,
                first,
                second,
            } => Ok(SynchronizeMaterial {
                machine_id: SecretBytes::from_zeroizing(first)?,
                srm: SecretBytes::from_zeroizing(second)?,
            }),
            _ => Err(BridgeError::InvalidMessage),
        }
    }

    /// Erases one staged native generation and publishes only on success.
    ///
    /// # Errors
    ///
    /// Returns once on the first failure and preserves the previous active
    /// generation.
    pub fn erase_provisioning(
        &self,
        libraries: &VerifiedLibraryPaths,
        store: &ProvisioningStore,
        ds_id: DirectoryServiceId,
        android_id: &AndroidId,
    ) -> Result<(), BridgeError> {
        match self.invoke(
            Operation::EraseProvisioning,
            libraries,
            store,
            ds_id,
            Invocation {
                android_id: android_id.expose(),
                secret: &[],
                publish: true,
            },
        )? {
            Response::Unit(Operation::EraseProvisioning) => Ok(()),
            _ => Err(BridgeError::InvalidMessage),
        }
    }

    /// Starts a same-process native provisioning transaction exactly once.
    ///
    /// The returned owner must be consumed by [`ProvisioningSession::finish`]
    /// or [`ProvisioningSession::cancel`].  Dropping it sends one cancellation
    /// command as a best-effort cleanup and then terminates the helper.
    ///
    /// # Errors
    ///
    /// Returns once on the first state, process, framing, or native failure.
    pub fn start_provisioning(
        &self,
        libraries: &VerifiedLibraryPaths,
        store: &ProvisioningStore,
        ds_id: DirectoryServiceId,
        android_id: &AndroidId,
        spim: SecretBytes,
    ) -> Result<ProvisioningSession, BridgeError> {
        let deadline = self.deadline()?;
        let prepared = store.prepare(deadline)?;
        let request = request(
            Operation::StartProvisioning,
            libraries,
            &prepared,
            ds_id,
            android_id.expose(),
            spim.expose(),
        );
        let mut process = HelperProcess::spawn(&self.executable, &prepared, deadline)?;
        process.send_request(&request, false)?;
        let response = process.read_response(false)?;
        match response {
            Response::ProvisioningStarted(cpim) => Ok(ProvisioningSession {
                cpim: Some(SecretBytes::from_zeroizing(cpim)?),
                process: Some(process),
                prepared: Some(prepared),
                thread_bound: PhantomData,
            }),
            Response::Error(error) => Err(error),
            _ => Err(BridgeError::InvalidMessage),
        }
    }

    fn invoke(
        &self,
        operation: Operation,
        libraries: &VerifiedLibraryPaths,
        store: &ProvisioningStore,
        ds_id: DirectoryServiceId,
        invocation: Invocation<'_>,
    ) -> Result<Response, BridgeError> {
        let deadline = self.deadline()?;
        let prepared = store.prepare(deadline)?;
        let request = request(
            operation,
            libraries,
            &prepared,
            ds_id,
            invocation.android_id,
            invocation.secret,
        );
        let mut process = HelperProcess::spawn(&self.executable, &prepared, deadline)?;
        process.send_request(&request, true)?;
        let response = process.read_response(true)?;
        match response {
            Response::Error(error) => Err(error),
            response => {
                if !response_matches_operation(&response, operation) {
                    return Err(BridgeError::InvalidMessage);
                }
                if invocation.publish {
                    if operation == Operation::EraseProvisioning {
                        prepared.publish_erasing()?;
                    } else {
                        prepared.publish()?;
                    }
                }
                Ok(response)
            }
        }
    }

    fn deadline(&self) -> Result<Instant, BridgeError> {
        Instant::now()
            .checked_add(self.timeout)
            .ok_or(BridgeError::TimedOut)
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

/// Move-only, thread-bound owner of one live native provisioning session.
///
/// The helper's Linux parent-death signal is tied to the thread that spawned
/// it.  This owner is therefore deliberately not [`Send`] or [`Sync`].  It
/// must be finished, cancelled, or dropped on the thread that called
/// [`HelperClient::start_provisioning`].
///
/// ```compile_fail
/// use coffer_anisette::ProvisioningSession;
///
/// fn move_to_another_thread(session: ProvisioningSession) {
///     std::thread::spawn(move || drop(session));
/// }
/// ```
pub struct ProvisioningSession {
    cpim: Option<SecretBytes>,
    process: Option<HelperProcess>,
    prepared: Option<PreparedGeneration>,
    thread_bound: PhantomData<Rc<()>>,
}

impl ProvisioningSession {
    /// Borrows CPIM for the caller's single finish-provisioning HTTP request.
    #[must_use]
    pub fn cpim(&self) -> &[u8] {
        self.cpim.as_ref().map_or(&[], SecretBytes::expose)
    }

    /// Ends the native session once and atomically publishes the generation.
    ///
    /// # Errors
    ///
    /// A failed end is terminal.  The helper performs one destroy cleanup and
    /// the previous active generation remains selected.
    pub fn finish(mut self, ptm: SecretBytes, tk: SecretBytes) -> Result<(), BridgeError> {
        let process = self.process.as_mut().ok_or(BridgeError::HelperFailed)?;
        process.send_command(
            &TransactionCommand::Finish {
                ptm: ptm.into_zeroizing(),
                tk: tk.into_zeroizing(),
            },
            true,
        )?;
        match process.read_response(true)? {
            Response::Unit(Operation::EndProvisioning) => {
                self.process.take();
                self.cpim.take();
                self.prepared
                    .take()
                    .ok_or(BridgeError::StateFailed)?
                    .publish()
            }
            Response::Error(error) => Err(error),
            _ => Err(BridgeError::InvalidMessage),
        }
    }

    /// Destroys the native session exactly once without publishing state.
    ///
    /// # Errors
    ///
    /// Returns the first cleanup, process, or framing failure without retrying.
    pub fn cancel(mut self) -> Result<(), BridgeError> {
        let result = self.cancel_inner();
        self.process.take();
        self.cpim.take();
        self.prepared.take();
        result
    }

    fn cancel_inner(&mut self) -> Result<(), BridgeError> {
        let process = self.process.as_mut().ok_or(BridgeError::HelperFailed)?;
        process.send_command(&TransactionCommand::Cancel, true)?;
        match process.read_response(true)? {
            Response::Unit(Operation::DestroyProvisioning) => Ok(()),
            Response::Error(error) => Err(error),
            _ => Err(BridgeError::InvalidMessage),
        }
    }
}

impl core::fmt::Debug for ProvisioningSession {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("ProvisioningSession(<redacted>)")
    }
}

impl Drop for ProvisioningSession {
    fn drop(&mut self) {
        if self.process.is_some() {
            let _ = self.cancel_inner();
        }
    }
}

fn request(
    operation: Operation,
    libraries: &VerifiedLibraryPaths,
    prepared: &PreparedGeneration,
    ds_id: DirectoryServiceId,
    android_id: &[u8],
    secret: &[u8],
) -> Request {
    Request {
        operation,
        library_root: libraries.root.clone(),
        provisioning_root: prepared.root().to_owned(),
        state_directory: prepared.path().to_owned(),
        ds_id: ds_id.get(),
        android_id: Zeroizing::new(android_id.to_vec()),
        secret: Zeroizing::new(secret.to_vec()),
    }
}

fn response_matches_operation(response: &Response, operation: Operation) -> bool {
    matches!(
        (response, operation),
        (Response::Smoke { .. }, Operation::OfflineSmoke)
            | (Response::SandboxEnabled, Operation::SandboxProbe)
            | (
                Response::Unit(Operation::SetAndroidId),
                Operation::SetAndroidId
            )
            | (Response::Provisioned(_), Operation::QueryProvisioned)
            | (
                Response::SecretPair {
                    operation: Operation::RequestOtp,
                    ..
                },
                Operation::RequestOtp
            )
            | (
                Response::SecretPair {
                    operation: Operation::Synchronize,
                    ..
                },
                Operation::Synchronize
            )
            | (
                Response::Unit(Operation::EraseProvisioning),
                Operation::EraseProvisioning
            )
    )
}

struct HelperProcess {
    child: Child,
    stdin: Option<ChildStdin>,
    stdout: ChildStdout,
    deadline: Instant,
    watchdog: DeadlineWatchdog,
}

impl HelperProcess {
    #[allow(unsafe_code)]
    fn spawn(
        executable: &Path,
        prepared: &PreparedGeneration,
        deadline: Instant,
    ) -> Result<Self, BridgeError> {
        if Instant::now() >= deadline {
            return Err(BridgeError::TimedOut);
        }
        let state_capability = reserve_state_capability(prepared.capability().as_raw_fd())?;
        let source_fd = state_capability.as_raw_fd();
        let mut command = Command::new(executable);
        // SAFETY: the closure uses only async-signal-safe `dup2`/`fcntl`
        // operations between fork and exec.  It duplicates the already-open,
        // validated staging capability into a fixed descriptor; no path is
        // reopened in the child.
        unsafe {
            command.pre_exec(move || {
                if source_fd != STATE_CAPABILITY_FD
                    && libc::dup2(source_fd, STATE_CAPABILITY_FD) < 0
                {
                    return Err(std::io::Error::last_os_error());
                }
                if libc::fcntl(STATE_CAPABILITY_FD, libc::F_SETFD, 0) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let child = command
            .process_group(0)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn();
        // Keep the reserved descriptor occupied until `Command` has allocated
        // and installed its three standard-I/O descriptors in the child.
        drop(state_capability);
        let mut child = child.map_err(|_| BridgeError::ProcessIo)?;
        let watchdog = match DeadlineWatchdog::arm(&child, deadline, prepared.lease_handle()) {
            Ok(watchdog) => watchdog,
            Err(error) => {
                terminate(&mut child);
                return Err(error);
            }
        };
        let stdin = child.stdin.take().ok_or(BridgeError::ProcessIo)?;
        let stdout = child.stdout.take().ok_or(BridgeError::ProcessIo)?;
        set_nonblocking(stdin.as_raw_fd())?;
        set_nonblocking(stdout.as_raw_fd())?;
        Ok(Self {
            child,
            stdin: Some(stdin),
            stdout,
            deadline,
            watchdog,
        })
    }

    fn send_request(&mut self, request: &Request, close: bool) -> Result<(), BridgeError> {
        let mut bytes = Zeroizing::new(Vec::new());
        ipc::write_request(&mut *bytes, request)?;
        self.write_frame(&bytes)?;
        if close {
            self.stdin.take();
        }
        Ok(())
    }

    fn send_command(
        &mut self,
        command: &TransactionCommand,
        close: bool,
    ) -> Result<(), BridgeError> {
        let mut bytes = Zeroizing::new(Vec::new());
        ipc::write_transaction_command(&mut *bytes, command)?;
        self.write_frame(&bytes)?;
        if close {
            self.stdin.take();
        }
        Ok(())
    }

    fn write_frame(&mut self, bytes: &[u8]) -> Result<(), BridgeError> {
        let writer = self.stdin.as_mut().ok_or(BridgeError::ProcessIo)?;
        if let Err(error) = write_until_deadline(&mut self.child, writer, bytes, self.deadline) {
            terminate(&mut self.child);
            return Err(error);
        }
        Ok(())
    }

    fn read_response(&mut self, wait_for_exit: bool) -> Result<Response, BridgeError> {
        let bytes = collect_frame(
            &mut self.child,
            &mut self.stdout,
            self.deadline,
            wait_for_exit,
        )?;
        ipc::read_response(std::io::Cursor::new(bytes))
    }
}

#[allow(unsafe_code)]
fn reserve_state_capability(source: libc::c_int) -> Result<OwnedFd, BridgeError> {
    // SAFETY: `source` is the live, validated staging-directory capability.
    // F_DUPFD_CLOEXEC creates a new owned descriptor numbered at least three,
    // reserving that slot before `Command` allocates its standard-I/O pipes.
    let descriptor = unsafe { libc::fcntl(source, libc::F_DUPFD_CLOEXEC, STATE_CAPABILITY_FD) };
    if descriptor < STATE_CAPABILITY_FD {
        return Err(BridgeError::ProcessIo);
    }
    // SAFETY: a successful F_DUPFD_CLOEXEC call returns a fresh descriptor
    // whose sole ownership transfers to this value.
    Ok(unsafe { OwnedFd::from_raw_fd(descriptor) })
}

impl Drop for HelperProcess {
    fn drop(&mut self) {
        self.watchdog.disarm();
        terminate(&mut self.child);
    }
}

struct DeadlineWatchdog {
    cancel: Option<Sender<()>>,
    worker: Option<JoinHandle<()>>,
}

impl DeadlineWatchdog {
    #[allow(unsafe_code)]
    fn arm(
        child: &Child,
        deadline: Instant,
        lease: GenerationLeaseHandle,
    ) -> Result<Self, BridgeError> {
        let pid = libc::pid_t::try_from(child.id()).map_err(|_| BridgeError::ProcessIo)?;
        // SAFETY: pidfd_open obtains a stable reference to this exact child,
        // avoiding PID reuse when the deadline fires after an early exit.
        let descriptor = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0u32) };
        let descriptor = i32::try_from(descriptor).map_err(|_| BridgeError::ProcessIo)?;
        if descriptor < 0 {
            return Err(BridgeError::ProcessIo);
        }
        // SAFETY: the successful syscall returned a fresh descriptor.
        let pidfd = unsafe { OwnedFd::from_raw_fd(descriptor) };
        let (cancel, receiver) = mpsc::channel();
        let worker = std::thread::Builder::new()
            .name("coffer-anisette-deadline".to_owned())
            .spawn(move || {
                let remaining = deadline.saturating_duration_since(Instant::now());
                if matches!(
                    receiver.recv_timeout(remaining),
                    Err(RecvTimeoutError::Timeout)
                ) {
                    // SAFETY: the pidfd names only the helper observed above.
                    // The sandbox never permits it to create descendants, so
                    // signaling that process is complete cleanup without a
                    // process-group PID-reuse hazard.
                    let _ = unsafe {
                        libc::syscall(
                            libc::SYS_pidfd_send_signal,
                            pidfd.as_raw_fd(),
                            libc::SIGKILL,
                            std::ptr::null::<libc::siginfo_t>(),
                            0u32,
                        )
                    };
                    expire_generation(&lease);
                }
            })
            .map_err(|_| BridgeError::ProcessIo)?;
        Ok(Self {
            cancel: Some(cancel),
            worker: Some(worker),
        })
    }

    fn disarm(&mut self) {
        if let Some(cancel) = self.cancel.take() {
            let _ = cancel.send(());
        }
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

impl Drop for DeadlineWatchdog {
    fn drop(&mut self) {
        self.disarm();
    }
}

#[allow(unsafe_code)]
fn set_nonblocking(descriptor: libc::c_int) -> Result<(), BridgeError> {
    // SAFETY: `descriptor` is a live, uniquely owned pipe descriptor.
    let flags = unsafe { libc::fcntl(descriptor, libc::F_GETFL) };
    // SAFETY: same live descriptor; `flags` came from F_GETFL.
    if flags < 0 || unsafe { libc::fcntl(descriptor, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0
    {
        Err(BridgeError::ProcessIo)
    } else {
        Ok(())
    }
}

fn collect_frame(
    child: &mut Child,
    stdout: &mut ChildStdout,
    deadline: Instant,
    wait_for_exit: bool,
) -> Result<Zeroizing<Vec<u8>>, BridgeError> {
    // Reserve the complete public frame bound before reading any secret bytes.
    // A later Vec growth would abandon an allocation containing a copied
    // prefix that `Zeroizing` can no longer wipe.
    let mut bytes = Zeroizing::new(Vec::with_capacity(ipc::MAX_FRAME_BYTES));
    let mut buffer = Zeroizing::new([0u8; 4096]);
    let mut expected = None;
    let mut status = None;
    let mut eof = false;
    loop {
        while !eof {
            match stdout.read(&mut *buffer) {
                Ok(0) => {
                    eof = true;
                    break;
                }
                Ok(count) => {
                    if bytes.len().saturating_add(count) > ipc::MAX_FRAME_BYTES {
                        terminate(child);
                        return Err(BridgeError::InvalidMessage);
                    }
                    bytes.extend_from_slice(&buffer[..count]);
                    if expected.is_none() && bytes.len() >= 16 {
                        let payload = u32::from_be_bytes(
                            bytes[12..16]
                                .try_into()
                                .map_err(|_| BridgeError::InvalidMessage)?,
                        ) as usize;
                        expected = Some(
                            16usize
                                .checked_add(payload)
                                .ok_or(BridgeError::InvalidMessage)?,
                        );
                    }
                    if expected.is_some_and(|length| bytes.len() > length) {
                        terminate(child);
                        return Err(BridgeError::InvalidMessage);
                    }
                }
                Err(error) if error.kind() == ErrorKind::WouldBlock => break,
                Err(error) if error.kind() == ErrorKind::Interrupted => {}
                Err(_) => {
                    terminate(child);
                    return Err(BridgeError::ProcessIo);
                }
            }
        }
        if status.is_none() {
            status = child.try_wait().map_err(|_| BridgeError::ProcessIo)?;
        }
        let frame_complete = expected.is_some_and(|length| bytes.len() == length);
        let completed_error = frame_complete && bytes.get(11).is_some_and(|status| *status != 0);
        if Instant::now() >= deadline {
            terminate(child);
            return Err(BridgeError::TimedOut);
        }
        if !wait_for_exit && status.is_some() && !completed_error {
            return Err(classify_exit(status));
        }
        if frame_complete && (!wait_for_exit || status.is_some() && eof) {
            break;
        }
        if status.is_some() && eof && !frame_complete {
            return Err(classify_exit(status));
        }
        std::thread::sleep(Duration::from_millis(2));
    }
    if wait_for_exit && !status.is_some_and(|exit| exit.success()) {
        return Err(classify_exit(status));
    }
    Ok(bytes)
}

fn write_until_deadline(
    child: &mut Child,
    writer: &mut ChildStdin,
    bytes: &[u8],
    deadline: Instant,
) -> Result<(), BridgeError> {
    let mut offset = 0usize;
    while offset < bytes.len() {
        if Instant::now() >= deadline {
            return Err(BridgeError::TimedOut);
        }
        match writer.write(&bytes[offset..]) {
            Ok(0) => return Err(BridgeError::ProcessIo),
            Ok(count) => {
                offset = offset
                    .checked_add(count)
                    .ok_or(BridgeError::InvalidMessage)?;
            }
            Err(error) if error.kind() == ErrorKind::WouldBlock => {
                if child
                    .try_wait()
                    .map_err(|_| BridgeError::ProcessIo)?
                    .is_some()
                {
                    return Err(BridgeError::HelperFailed);
                }
                if Instant::now() >= deadline {
                    return Err(BridgeError::TimedOut);
                }
                std::thread::sleep(Duration::from_millis(2));
            }
            Err(error) if error.kind() == ErrorKind::Interrupted => {}
            Err(_) => return Err(BridgeError::ProcessIo),
        }
    }
    Ok(())
}

fn classify_exit(status: Option<std::process::ExitStatus>) -> BridgeError {
    #[cfg(unix)]
    if let Some(status) = status {
        use std::os::unix::process::ExitStatusExt as _;
        if status.signal().is_some() || matches!(status.code(), Some(126) | Some(134)) {
            return BridgeError::HelperCrashed;
        }
    }
    BridgeError::HelperFailed
}

#[allow(unsafe_code)]
fn terminate(child: &mut Child) {
    if matches!(child.try_wait(), Ok(Some(_))) {
        return;
    }
    if let Ok(pid) = libc::pid_t::try_from(child.id()) {
        // SAFETY: every helper starts a fresh process group with the child PID.
        let _ = unsafe { libc::kill(-pid, libc::SIGKILL) };
    }
    let _ = child.kill();
    let _ = child.wait();
}

#[cfg(test)]
mod tests {
    use super::*;
    use coffer_bootstrap::BootstrapPaths;
    use std::fs::File;

    fn completed_response_process(response: &Response) -> (Child, ChildStdout) {
        let mut response_file = tempfile::NamedTempFile::new().expect("response file");
        ipc::write_response(&mut response_file, response).expect("response");
        response_file.flush().expect("flush response");
        let mut child = Command::new("sh")
            .args(["-c", "cat -- \"$1\"", "sh"])
            .arg(response_file.path())
            .process_group(0)
            .stdout(Stdio::piped())
            .spawn()
            .expect("spawn");
        let stdout = child.stdout.take().expect("stdout");
        assert!(child.wait().expect("wait").success());
        (child, stdout)
    }

    #[test]
    fn timeout_kills_one_process_group_without_retry() {
        let mut command = Command::new("sh");
        command.args(["-c", "sleep 5"]);
        let mut child = command
            .process_group(0)
            .stdout(Stdio::piped())
            .spawn()
            .expect("spawn");
        let mut stdout = child.stdout.take().expect("stdout");
        set_nonblocking(stdout.as_raw_fd()).expect("nonblocking");
        assert_eq!(
            collect_frame(
                &mut child,
                &mut stdout,
                Instant::now() + Duration::from_millis(25),
                true
            ),
            Err(BridgeError::TimedOut)
        );
    }

    #[test]
    fn blocked_request_write_obeys_the_global_deadline() {
        let mut child = Command::new("sh")
            .args(["-c", "sleep 5"])
            .process_group(0)
            .stdin(Stdio::piped())
            .spawn()
            .expect("spawn");
        let mut stdin = child.stdin.take().expect("stdin");
        set_nonblocking(stdin.as_raw_fd()).expect("nonblocking");
        let bytes = Zeroizing::new(vec![0x5a; ipc::MAX_FRAME_BYTES]);
        assert_eq!(
            write_until_deadline(
                &mut child,
                &mut stdin,
                &bytes,
                Instant::now() + Duration::from_millis(25),
            ),
            Err(BridgeError::TimedOut)
        );
        terminate(&mut child);
    }

    #[test]
    fn expired_deadline_writes_no_provisioning_command() {
        let mut child = Command::new("sh")
            .args(["-c", "sleep 5"])
            .process_group(0)
            .stdin(Stdio::piped())
            .spawn()
            .expect("spawn");
        let mut stdin = child.stdin.take().expect("stdin");
        set_nonblocking(stdin.as_raw_fd()).expect("nonblocking");
        assert_eq!(
            write_until_deadline(&mut child, &mut stdin, b"finish", Instant::now()),
            Err(BridgeError::TimedOut)
        );
        terminate(&mut child);
    }

    #[test]
    fn complete_response_after_deadline_is_never_accepted() {
        let (mut child, mut stdout) = completed_response_process(&Response::ProvisioningStarted(
            Zeroizing::new(b"cpim".to_vec()),
        ));
        set_nonblocking(stdout.as_raw_fd()).expect("nonblocking");
        assert_eq!(
            collect_frame(&mut child, &mut stdout, Instant::now(), false),
            Err(BridgeError::TimedOut)
        );
    }

    #[test]
    fn complete_provisioning_response_from_exited_helper_is_rejected() {
        let (mut child, mut stdout) = completed_response_process(&Response::ProvisioningStarted(
            Zeroizing::new(b"cpim".to_vec()),
        ));
        set_nonblocking(stdout.as_raw_fd()).expect("nonblocking");
        assert_eq!(
            collect_frame(
                &mut child,
                &mut stdout,
                Instant::now() + Duration::from_secs(1),
                false
            ),
            Err(BridgeError::HelperFailed)
        );
    }

    #[test]
    fn complete_error_response_from_exited_helper_preserves_the_stage() {
        let (mut child, mut stdout) =
            completed_response_process(&Response::Error(BridgeError::SandboxUnavailable));
        set_nonblocking(stdout.as_raw_fd()).expect("nonblocking");
        let bytes = collect_frame(
            &mut child,
            &mut stdout,
            Instant::now() + Duration::from_secs(1),
            false,
        )
        .expect("completed error frame");
        assert!(matches!(
            ipc::read_response(std::io::Cursor::new(bytes)),
            Ok(Response::Error(BridgeError::SandboxUnavailable))
        ));
    }

    #[test]
    fn live_helper_error_response_waits_for_normal_exit_and_preserves_the_stage() {
        let mut response_file = tempfile::NamedTempFile::new().expect("response file");
        ipc::write_response(&mut response_file, &Response::Error(BridgeError::OtpFailed))
            .expect("response");
        response_file.flush().expect("flush response");
        let mut child = Command::new("sh")
            .args(["-c", "cat -- \"$1\"; sleep 0.05", "sh"])
            .arg(response_file.path())
            .process_group(0)
            .stdout(Stdio::piped())
            .spawn()
            .expect("spawn");
        let mut stdout = child.stdout.take().expect("stdout");
        set_nonblocking(stdout.as_raw_fd()).expect("nonblocking");
        let bytes = collect_frame(
            &mut child,
            &mut stdout,
            Instant::now() + Duration::from_secs(1),
            true,
        )
        .expect("completed error frame after normal exit");
        assert!(matches!(
            ipc::read_response(std::io::Cursor::new(bytes)),
            Ok(Response::Error(BridgeError::OtpFailed))
        ));
    }

    #[test]
    fn state_capability_is_reserved_above_standard_io() {
        let source = File::open("/dev/null").expect("source");
        let reserved = reserve_state_capability(source.as_raw_fd()).expect("reserve");
        assert!(reserved.as_raw_fd() >= STATE_CAPABILITY_FD);
        assert_ne!(reserved.as_raw_fd(), source.as_raw_fd());
    }

    #[test]
    fn watchdog_expires_the_generation_lease_without_caller_polling() {
        let root = tempfile::tempdir().expect("root");
        let store =
            ProvisioningStore::from_paths(&BootstrapPaths::rooted_at(root.path())).expect("store");
        let deadline = Instant::now() + Duration::from_millis(250);
        let prepared = store.prepare(deadline).expect("prepared");
        let staging = prepared.path().to_owned();
        std::fs::write(staging.join("noncanonical"), b"stale").expect("stale state");
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(
            staging.join("noncanonical"),
            std::fs::Permissions::from_mode(0o000),
        )
        .expect("noncanonical mode");
        let mut child = Command::new("sh")
            .args(["-c", "sleep 5"])
            .process_group(0)
            .spawn()
            .expect("spawn");
        let mut watchdog =
            DeadlineWatchdog::arm(&child, deadline, prepared.lease_handle()).expect("watchdog");
        std::thread::sleep(Duration::from_millis(350));
        watchdog.disarm();
        assert_eq!(prepared.publish(), Err(BridgeError::TimedOut));
        assert!(!child.wait().expect("wait").success());
        assert!(staging.exists());
        drop(
            store
                .prepare(Instant::now() + Duration::from_secs(1))
                .expect("next preparation cleans stale staging"),
        );
        assert!(!staging.exists());
    }

    #[test]
    fn publication_requires_the_exact_operation_response() {
        assert!(response_matches_operation(
            &Response::SecretPair {
                operation: Operation::RequestOtp,
                first: Zeroizing::new(Vec::new()),
                second: Zeroizing::new(Vec::new()),
            },
            Operation::RequestOtp,
        ));
        assert!(!response_matches_operation(
            &Response::Unit(Operation::SetAndroidId),
            Operation::EraseProvisioning,
        ));
    }

    #[test]
    fn termination_does_not_signal_an_already_reaped_process_group() {
        let mut child = Command::new("sh")
            .args(["-c", "exit 0"])
            .process_group(0)
            .spawn()
            .expect("spawn");
        assert!(child.wait().expect("wait").success());
        terminate(&mut child);
        assert!(child.try_wait().expect("cached status").is_some());
    }

    #[test]
    fn debug_output_redacts_paths_and_sessions() {
        let client = HelperClient::new("/secret-looking-helper", Duration::from_secs(1));
        let libraries = VerifiedLibraryPaths {
            root: PathBuf::from("/secret-looking-library"),
        };
        assert!(!format!("{client:?}").contains("secret-looking"));
        assert!(!format!("{libraries:?}").contains("secret-looking"));
    }
}
