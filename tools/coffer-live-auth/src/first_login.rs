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

//! One confirmed first GSA login into an exclusively reserved developer profile.
//!
//! Existing anisette is shared; only the local session slot is isolated. No
//! delegate, service-token, trust, escrow or CKKS operation belongs to this flow.

use crate::{
    entropy::OsEntropy,
    flow::run_login,
    harness::HarnessError,
    slot::SlotState,
    store::{SecretServiceConnector, StoreConnector, persist_and_reload},
    terminal::SecureTerminal,
    transport::{GsaTransport, UreqExchange},
};
use coffer_protocol::{auth::Authenticator, entropy::Entropy};
use coffer_service::{DeleteOutcome, ReusableSession, SessionSlot, SessionStore, StoreError};
use futures_lite::future::block_on;
use std::time::Duration;

pub(crate) const CONFIRM: &str =
    "Type LOGIN AND STORE to authorize this single first-login/store flow: ";

/// Fixed stage/cause labels and conservative storage status; no source data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FirstLoginError {
    stage: &'static str,
    cause: &'static str,
    persistence_started: bool,
}
impl FirstLoginError {
    fn at(stage: &'static str, cause: &'static str) -> Self {
        Self {
            stage,
            cause,
            persistence_started: false,
        }
    }
    /// Returns literal labels without account, path, slot, or upstream text.
    #[must_use]
    pub fn labels(&self) -> (&'static str, &'static str) {
        (self.stage, self.cause)
    }
    /// Explains retained local state after a failure; never promises rollback.
    #[must_use]
    pub fn retention_label(&self) -> &'static str {
        if self.persistence_started {
            "New profile reservation remains; its session storage may have changed; no rollback or retry."
        } else {
            "A new profile reservation may remain; no session was written by this run; no retry."
        }
    }
}
impl std::fmt::Display for FirstLoginError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.stage, self.cause)
    }
}
impl std::error::Error for FirstLoginError {}

// Reuse the existing persistence round trip, guarding its one replace call.
// SessionStore has no atomic insert API: an external same-user writer can race
// this final check. Exclusive profile reservation serializes this entry point.
struct EmptyConnector<'a, C>(&'a C);
struct EmptyStore<S>(S);
impl<C: StoreConnector> StoreConnector for EmptyConnector<'_, C> {
    type Store = EmptyStore<C::Store>;
    async fn connect(&self) -> Result<Self::Store, StoreError> {
        Ok(EmptyStore(self.0.connect().await?))
    }
}
impl<S: SessionStore> SessionStore for EmptyStore<S> {
    async fn check_available(&self) -> Result<(), StoreError> {
        self.0.check_available().await
    }
    async fn load(&self, slot: &SessionSlot) -> Result<Option<ReusableSession>, StoreError> {
        self.0.load(slot).await
    }
    async fn replace(
        &self,
        slot: &SessionSlot,
        session: &ReusableSession,
    ) -> Result<(), StoreError> {
        if self.0.load(slot).await?.is_some() {
            return Err(StoreError::Duplicate);
        }
        self.0.replace(slot, session).await
    }
    async fn delete(&self, _: &SessionSlot) -> Result<DeleteOutcome, StoreError> {
        Err(StoreError::Denied)
    }
}

fn run_with<C: StoreConnector, T: SecureTerminal, A>(
    terminal: &mut T,
    state: &SlotState,
    entropy: &impl Entropy,
    connector: &C,
    prepare: impl FnOnce() -> Result<A, FirstLoginError>,
    validate: impl FnOnce(&A) -> Result<(), FirstLoginError>,
    login: impl FnOnce(A, &mut T) -> Result<ReusableSession, FirstLoginError>,
) -> Result<(), FirstLoginError> {
    let slot = state
        .create_new(entropy)
        .map_err(|error| FirstLoginError::at("new profile reservation", error.label()))?;
    let store = block_on(connector.connect())
        .map_err(|_| FirstLoginError::at("session preflight", "connection failed"))?;
    block_on(store.check_available())
        .map_err(|_| FirstLoginError::at("session preflight", "store unavailable or locked"))?;
    if block_on(store.load(&slot))
        .map_err(|_| FirstLoginError::at("session preflight", "session lookup rejected"))?
        .is_some()
    {
        return Err(FirstLoginError::at(
            "session preflight",
            "slot already occupied",
        ));
    }
    drop(store);
    let local = prepare()?;
    validate(&local)?;
    let terminal_error = || FirstLoginError::at("confirmation", "declined or interrupted");
    terminal.notice("This starts one first GSA login and stores its reusable session in the reserved new developer profile.")
        .map_err(|_| terminal_error())?;
    terminal.notice("Authentication may consume attempts: at most two GSA requests, or six requests with trusted-device 2FA; no automatic retry.")
        .map_err(|_| terminal_error())?;
    terminal.notice("No delegate or service-token issuance, trust, recovery, or CKKS request is made. Existing anisette is reused without initial provisioning.")
        .map_err(|_| terminal_error())?;
    terminal.notice("The new profile reservation remains even if you decline or this run fails; there is no automatic replacement or alternate slot.")
        .map_err(|_| terminal_error())?;
    let answer = terminal
        .prompt_visible(CONFIRM)
        .map_err(|_| terminal_error())?;
    if answer.as_str() != "LOGIN AND STORE" {
        return Err(terminal_error());
    }
    drop(answer);
    let session = login(local, terminal)?;
    block_on(persist_and_reload(
        &EmptyConnector(connector),
        &slot,
        &session,
        terminal,
    ))
    .map_err(|_| FirstLoginError {
        stage: "session persistence",
        cause: "write or fresh-connection reload failed; no retry",
        persistence_started: true,
    })?;
    Ok(())
}

/// Authenticates once into an explicitly selected new developer profile.
///
/// `profile` is a non-secret local label accepted by [`SlotState::new_profile`].
/// The default profile and anisette XDG home are unchanged. A reservation is
/// created before store/local preflight and confirmation and retained on every
/// failure or decline. Existing reservations are rejected before input/auth.
/// Use [`crate::op_input::OpTerminal::for_first_login`] for 1Password input.
///
/// Requires independent review and separate live authorization; never run in
/// normal tests or CI. Existing anisette is opened and generated once before
/// confirmation or credential fetch. Local generation may update its state;
/// it makes no network request and never provisions a new device.
/// Successful persistence proves equality over a new connection, not token reuse.
///
/// # Errors
/// Stops on the first failure, with fixed stage labels and no retry, repair,
/// alternate slot or rollback. Storage may have changed after persistence starts.
/// SessionStore has no atomic create-if-absent, so external same-user writers
/// must not concurrently modify the reserved slot.
pub fn run(terminal: &mut impl SecureTerminal, profile: &str) -> Result<(), FirstLoginError> {
    let state = SlotState::from_environment()
        .and_then(|state| state.new_profile(profile))
        .map_err(|error| FirstLoginError::at("new profile selection", error.label()))?;
    run_with(
        terminal,
        &state,
        &OsEntropy,
        &SecretServiceConnector,
        || {
            crate::reuse::prepare_local()
                .map(|(_, provider)| provider)
                .map_err(|_| {
                    FirstLoginError::at(
                        "local preflight",
                        "existing libraries or provisioning unavailable",
                    )
                })
        },
        |provider| {
            // Opening the provider validates identity, but active provisioning
            // and its library binding are checked only on local generation.
            block_on(provider.generate()).map(drop).map_err(|_| {
                FirstLoginError::at("local preflight", "existing anisette generation failed")
            })
        },
        |provider, terminal| {
            let transport = GsaTransport::starting_on_first_exchange(
                UreqExchange::new(),
                Duration::from_secs(60),
                Duration::from_secs(20 * 60),
            );
            let auth = Authenticator::new(transport, provider, OsEntropy);
            block_on(run_login(&auth, terminal))
                .map(|outcome| ReusableSession::from_session(&outcome.session))
                .map_err(|error| {
                    let (stage, cause) = HarnessError::Flow(error).labels();
                    FirstLoginError::at(stage, cause)
                })
        },
    )
}

#[cfg(test)]
#[path = "../tests/first_login/mod.rs"]
mod tests;
