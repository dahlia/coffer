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

//! One initial SRP diagnostic, with no session or follow-up capability.
//!
//! Production preparation opens only existing local support state. Execution
//! needs separate live authorization; synthetic tests do not provide it.

use crate::{file_input::FileTerminal, terminal::SecureTerminal};
use coffer_protocol::{
    anisette::AnisetteProvider,
    auth::{Authenticator, GSA_ENDPOINT, diagnostic::InitialAuthReport},
    entropy::Entropy,
    secret::{AccountName, Password},
    transport::{Method, Request, Response, Transport, TransportError},
};
use futures_lite::future::block_on;
use std::{
    io::Write,
    sync::atomic::{AtomicU8, Ordering},
    time::Duration,
};

pub(crate) const CONFIRM: &str = "Type DIAGNOSE INITIAL AUTH for one initial SRP diagnostic: ";

/// Fixed local failure labels; raw errors and credential paths are discarded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiagnosticError {
    /// Existing local libraries or provisioning could not be opened.
    LocalState,
    /// Input mode, confirmation, or terminal failed before authentication.
    Input,
    /// Finite report output failed; authentication is never repeated.
    Output,
}
impl std::fmt::Display for DiagnosticError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::LocalState => "existing local diagnostic state unavailable",
            Self::Input => "initial diagnostic input stopped",
            Self::Output => "initial diagnostic output failed; do not retry",
        })
    }
}
impl std::error::Error for DiagnosticError {}

// Private to this runner: no caller can extract the underlying transport.
// State 0/1 means ready for first/second send; 2 is in flight, 3 is closed.
// Claim the state before polling a send. Failure, cancellation, or concurrency
// cannot restore it. Only successful completion of the first send enables #2.
struct InitialTransport<T> {
    inner: T,
    state: AtomicU8,
}
impl<T> InitialTransport<T> {
    fn new(inner: T) -> Self {
        Self {
            inner,
            state: AtomicU8::new(0),
        }
    }
}
impl<T: Transport> Transport for InitialTransport<T> {
    async fn send(&self, request: Request) -> Result<Response, TransportError> {
        let refuse = || TransportError::Other {
            detail: "initial diagnostic transport closed".into(),
        };
        let state = self
            .state
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |state| {
                Some(if state == 0 { 2 } else { 3 })
            })
            .unwrap_or(3);
        if state >= 2 || request.method != Method::Post || request.url != GSA_ENDPOINT {
            return Err(refuse());
        }
        let result = self.inner.send(request).await;
        if state == 0
            && result
                .as_ref()
                .is_ok_and(|response| (200..300).contains(&response.status()))
        {
            // Concurrent calls leave the transport closed, even if they fail.
            // The runner itself never sends concurrently.
            let _ = self
                .state
                .compare_exchange(2, 1, Ordering::SeqCst, Ordering::SeqCst);
        }
        result
    }
}

/// Runs one diagnostic using explicit file input and injected offline adapters.
///
/// `prepare` must open only existing local resources, with no provisioning or
/// download. It runs before confirmation; no credential read happens until
/// confirmation succeeds. The initial-only transport permits at most two POSTs
/// to the GSA password endpoint. The consumed protocol login enforces init then
/// complete. This function always finishes the input before returning, including
/// failures. It has no store, OTP, token, recovery, or trust callback.
///
/// # Errors
/// Local preparation/input failures return fixed labels. Protocol failures are
/// finite reports. Nothing is retried, including failures after transmission.
pub fn run_with<T: SecureTerminal, H: Transport, A: AnisetteProvider, E: Entropy>(
    terminal: &mut FileTerminal<T>,
    prepare: impl FnOnce() -> Result<(H, A, E), DiagnosticError>,
) -> Result<InitialAuthReport, DiagnosticError> {
    let result = (|| {
        if !terminal.is_initial_diagnostic() {
            return Err(DiagnosticError::Input);
        }
        let (transport, anisette, entropy) = prepare()?;
        terminal.notice("Initial authentication may affect account protection or send server notifications; no retry.").map_err(|_| DiagnosticError::Input)?;
        terminal.notice("At most init and complete; no code, session storage, token, recovery, or trust operation.").map_err(|_| DiagnosticError::Input)?;
        if terminal
            .prompt_visible(CONFIRM)
            .map_err(|_| DiagnosticError::Input)?
            .as_str()
            != "DIAGNOSE INITIAL AUTH"
        {
            return Err(DiagnosticError::Input);
        }
        let mut account = terminal
            .prompt_hidden("Apple Account (e-mail address or phone number, not echoed): ")
            .map_err(|_| DiagnosticError::Input)?;
        let account =
            AccountName::new(std::mem::take(&mut *account)).map_err(|_| DiagnosticError::Input)?;
        let mut password = terminal
            .prompt_hidden("Password (not echoed): ")
            .map_err(|_| DiagnosticError::Input)?;
        let password = Password::new(std::mem::take(&mut *password));
        let auth = Authenticator::new(InitialTransport::new(transport), anisette, entropy);
        Ok(block_on(auth.login(account, password).diagnose_initial()))
    })();
    terminal.finish();
    result
}

/// Runs the separately authorized live diagnostic with existing local state.
///
/// Preparation reuses `installed`/`open_existing` with downloads disabled. It
/// does not generate anisette as a preflight: only the SRP path generates once.
/// No profile, Secret Service, provisioning, OTP, or subsequent endpoint is used.
/// The HTTP budget is 60 seconds per exchange and 20 minutes from the first one.
///
/// # Errors
/// See [`run_with`]. A failed/unknown result is not permission for another run.
pub fn run<T: SecureTerminal>(
    terminal: &mut FileTerminal<T>,
) -> Result<InitialAuthReport, DiagnosticError> {
    run_with(terminal, || {
        let (_, anisette) =
            crate::reuse::prepare_local().map_err(|_| DiagnosticError::LocalState)?;
        let transport = crate::transport::GsaTransport::starting_on_first_exchange(
            crate::transport::UreqExchange::new(),
            Duration::from_secs(60),
            Duration::from_secs(1200),
        );
        Ok((transport, anisette, crate::entropy::OsEntropy))
    })
}

/// Writes only a finite report after the credential adapter has been finished.
///
/// Debug is safe here because every report field is a payload-free enum. No
/// arbitrary string, number, length, hash, URL, or underlying error is rendered.
/// The presentation is intended for human review, not a stable serialization.
///
/// # Errors
/// Returns only [`DiagnosticError::Output`] on a write failure; never retries.
pub fn write_report(
    writer: &mut impl Write,
    report: &InitialAuthReport,
) -> Result<(), DiagnosticError> {
    writeln!(writer, "{report:?}").map_err(|_| DiagnosticError::Output)
}

#[cfg(test)]
#[path = "../tests/initial_diagnostic/mod.rs"]
mod tests;
