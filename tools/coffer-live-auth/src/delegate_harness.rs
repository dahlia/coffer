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

//! Developer-only fresh GSA login, one delegate issuance, and separate local stores.
//!
//! Existing state is mandatory. No download, provisioning, automatic retry,
//! credential cache, CloudKit initialization, trust, or recovery is performed.
//! The two local writes are not a transaction; errors describe retained state
//! conservatively and never include arbitrary backend or protocol error text.

use crate::{
    delegate_transport::DelegateTransport,
    entropy::OsEntropy,
    flow::run_login,
    harness::HarnessError,
    slot::SlotState,
    store::{SecretServiceConnector, StoreConnector, constant_time_eq, persist_and_reload},
    terminal::SecureTerminal,
    transport::{Deadlines, GsaTransport, UreqExchange},
};
use coffer_protocol::{
    anisette::{AnisetteData, AnisetteError, AnisetteProvider},
    auth::{Authenticator, Session},
    delegate::{ClientIdRef, DelegateClient, DelegateError, DelegateMaterialRef},
    transport::Transport,
};
use coffer_service::{
    DelegateBindingRef, DelegateStore, ReusableSession, SessionStore, StoredDelegateCredentials,
};
use core::fmt;
use futures_lite::future::block_on;
use std::time::Duration;
use zeroize::{Zeroize, Zeroizing};

const UNCHANGED: &str =
    "Local GSA/delegate items were not written by this run; server effects may be unknown.";
const GSA_UNCERTAIN: &str =
    "GSA storage may have changed; delegate issuance and delegate storage were not attempted.";
const GSA_STORED: &str = "Fresh GSA material remains stored; delegate issuance may have happened; no delegate item was written by this run.";
const BOTH_UNCERTAIN: &str = "Fresh GSA material remains stored; delegate storage may have changed; no rollback or retry is attempted.";

/// Fixed stage/cause and conservative local retention report, without sources.
///
/// Constructed only inside this module from literal labels. No secret or
/// arbitrary upstream error is retained, formatted, or exposed through `source`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DelegateHarnessError {
    stage: &'static str,
    cause: &'static str,
    retained: &'static str,
}
impl DelegateHarnessError {
    fn at(stage: &'static str, cause: &'static str, retained: &'static str) -> Self {
        Self {
            stage,
            cause,
            retained,
        }
    }
    /// Returns fixed stage/cause labels suitable for terminal output.
    #[must_use]
    pub fn labels(&self) -> (&'static str, &'static str) {
        (self.stage, self.cause)
    }
    /// Describes what may remain after a nontransactional partial failure.
    #[must_use]
    pub fn retention_label(&self) -> &'static str {
        self.retained
    }
}
impl fmt::Display for DelegateHarnessError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.stage, self.cause)
    }
}
impl std::error::Error for DelegateHarnessError {}

/// Local result only; neither variant proves current token validity or reuse.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DelegateOutcome {
    /// A bound item already exists; no password, login, issuance, or write occurred.
    AlreadyStored,
    /// One issuance and both independent storage round trips completed.
    Stored,
}
impl DelegateOutcome {
    /// Returns a fixed, secret-free terminal result.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::AlreadyStored => {
                "RESULT: delegate item already stored; no login or issuance; validity and live reuse unverified"
            }
            Self::Stored => {
                "RESULT: one delegate issuance and separate GSA/delegate round trips completed; CloudKit access and token reuse unverified"
            }
        }
    }
}

fn confirm(terminal: &mut impl SecureTerminal) -> Result<(), DelegateHarnessError> {
    let error =
        || DelegateHarnessError::at("confirmation", "terminal failed or interrupted", UNCHANGED);
    terminal
        .notice("This explicitly starts fresh GSA login, then at most one delegate token issuance.")
        .map_err(|_| error())?;
    terminal.notice("GSA and delegate material will be stored separately in Secret Service; these writes are not an atomic transaction.").map_err(|_| error())?;
    terminal.notice("Authentication/2FA may consume attempts; token rotation, registration, consent, and security notification effects are unknown.").map_err(|_| error())?;
    terminal.notice("Existing local device ID is the explicit client-id choice; Apple binding, token lifetime/reuse, and CloudKit access are unverified.").map_err(|_| error())?;
    terminal.notice("No automatic retry, download, provisioning, reset, trust, recovery, or CloudKit initialization follows any failure.").map_err(|_| error())?;
    let answer = terminal
        .prompt_visible(
            "Type LOGIN AND ISSUE to authorize this single fresh-login/delegate/store flow: ",
        )
        .map_err(|_| error())?;
    if answer.as_str() != "LOGIN AND ISSUE" {
        return Err(DelegateHarnessError::at(
            "confirmation",
            "fresh login and issuance were declined",
            UNCHANGED,
        ));
    }
    Ok(())
}

// The private seam substitutes only the fresh session in synthetic tests.
// Production uses the existing authenticated Session and its PET borrow.
trait FreshSession {
    fn adsid(&self) -> &str;
    fn material<'a>(
        &'a self,
        client: ClientIdRef<'a>,
    ) -> Result<DelegateMaterialRef<'a>, DelegateError>;
    fn reusable(&self) -> ReusableSession;
}
impl FreshSession for Session {
    fn adsid(&self) -> &str {
        self.account_id().as_str()
    }
    fn material<'a>(
        &'a self,
        client: ClientIdRef<'a>,
    ) -> Result<DelegateMaterialRef<'a>, DelegateError> {
        DelegateMaterialRef::from_session(self, client)
    }
    fn reusable(&self) -> ReusableSession {
        ReusableSession::from_session(self)
    }
}

// Borrow the one opened provider; never reopen/provision to get a login provider.
struct BorrowedProvider<'a, A>(&'a A);
impl<A: AnisetteProvider> AnisetteProvider for BorrowedProvider<'_, A> {
    async fn anisette(&self) -> Result<AnisetteData, AnisetteError> {
        self.0.anisette().await
    }
}

fn run_with<C, A, S, D, T>(
    terminal: &mut T,
    state: &SlotState,
    connector: &C,
    prepare: impl FnOnce() -> Result<A, DelegateHarnessError>,
    login: impl FnOnce(&A, &mut T) -> Result<S, DelegateHarnessError>,
    make_delegate_transport: impl FnOnce() -> D,
) -> Result<DelegateOutcome, DelegateHarnessError>
where
    C: StoreConnector,
    C::Store: DelegateStore,
    A: AnisetteProvider,
    S: FreshSession,
    D: Transport,
    T: SecureTerminal,
{
    let slot = state.load().map_err(|_| {
        DelegateHarnessError::at(
            "profile slot",
            "existing slot unavailable or corrupt",
            UNCHANGED,
        )
    })?;
    let store = block_on(connector.connect()).map_err(|_| {
        DelegateHarnessError::at(
            "GSA preflight",
            "Secret Service connection failed",
            UNCHANGED,
        )
    })?;
    block_on(store.check_available()).map_err(|_| {
        DelegateHarnessError::at(
            "GSA preflight",
            "Secret Service unavailable or locked",
            UNCHANGED,
        )
    })?;
    let stored = block_on(store.load(&slot))
        .map_err(|_| {
            DelegateHarnessError::at("GSA preflight", "stored session rejected", UNCHANGED)
        })?
        .ok_or(DelegateHarnessError::at(
            "GSA preflight",
            "stored session missing",
            UNCHANGED,
        ))?;
    // Only the ADSID is needed after preflight; release the old token/key/cookie.
    let mut adsid = Zeroizing::new(String::with_capacity(stored.expose_account_id().len()));
    adsid.push_str(stored.expose_account_id());
    drop(stored);
    let provider = prepare()?;
    let anisette = block_on(provider.anisette()).map_err(|mut error| {
        // Provider errors may own arbitrary backend text. Wipe before dropping.
        if let AnisetteError::Unavailable { detail: message } = &mut error {
            message.zeroize();
        }
        DelegateHarnessError::at("local anisette", "existing provider failed", UNCHANGED)
    })?;
    anisette.validate().map_err(|_| {
        DelegateHarnessError::at("local anisette", "generated values rejected", UNCHANGED)
    })?;
    let mut client_id = Zeroizing::new(String::with_capacity(anisette.device_id.len()));
    client_id.push_str(&anisette.device_id);
    drop(anisette);
    let client = ClientIdRef::new(&client_id).map_err(|_| {
        DelegateHarnessError::at(
            "client binding",
            "existing local device ID rejected",
            UNCHANGED,
        )
    })?;
    let expected = DelegateBindingRef::new(&adsid, &client_id).map_err(|_| {
        DelegateHarnessError::at(
            "client binding",
            "stored ADSID or client ID rejected",
            UNCHANGED,
        )
    })?;
    if block_on(store.load_delegate(&slot, expected))
        .map_err(|_| {
            DelegateHarnessError::at(
                "delegate preflight",
                "stored delegate unavailable, duplicate, corrupt, unsupported, or mismatched",
                UNCHANGED,
            )
        })?
        .is_some()
    {
        return Ok(DelegateOutcome::AlreadyStored);
    }
    drop(store);
    confirm(terminal)?;
    let fresh = login(&provider, terminal)?;
    if fresh.adsid() != adsid.as_str() {
        return Err(DelegateHarnessError::at(
            "fresh account binding",
            "account mismatch; existing items preserved; no delegate request",
            UNCHANGED,
        ));
    }
    let material = fresh.material(client).map_err(|error| {
        DelegateHarnessError::at(
            "delegate input",
            if error == DelegateError::MissingPet {
                "fresh GSA session has no PET; no delegate request"
            } else {
                "fresh delegate input rejected; no delegate request"
            },
            UNCHANGED,
        )
    })?;
    let reusable = fresh.reusable();
    block_on(persist_and_reload(connector, &slot, &reusable, terminal)).map_err(|_| {
        DelegateHarnessError::at(
            "GSA persistence",
            "GSA write/reload failed or interrupted; no delegate request",
            GSA_UNCERTAIN,
        )
    })?;
    drop(reusable);
    terminal
        .notice(
            "[delegate] issuing once; failure or interruption leaves issuance potentially unknown",
        )
        .map_err(|_| {
            DelegateHarnessError::at(
                "before delegate issuance",
                "terminal failed or interrupted; no delegate request",
                GSA_UNCERTAIN,
            )
        })?;
    // Factory starts a fresh deadline only here, after all login/TTY/store waits.
    let transport = make_delegate_transport();
    let issued =
        block_on(DelegateClient::new(&transport, &provider).issue(material)).map_err(|error| {
            DelegateHarnessError::at(
                "delegate issuance",
                match error {
                    DelegateError::MissingPet => "missing PET; no request or retry",
                    DelegateError::InvalidInput => "invalid input; no request or retry",
                    DelegateError::Anisette => "anisette failed; no request or retry",
                    DelegateError::Transport => "transport failed; issuance unknown; no retry",
                    DelegateError::Http => "HTTP response rejected; no retry",
                    DelegateError::Malformed => "malformed XML response; no retry",
                    DelegateError::Schema => "unsupported response schema; no retry",
                    DelegateError::TooLarge => "response exceeded a bound; no retry",
                    DelegateError::Unsupported => "unsupported response format; no retry",
                    DelegateError::RootRejected => "root protocol status rejected; no retry",
                    DelegateError::DelegateRejected => {
                        "delegate protocol status rejected; no retry"
                    }
                },
                GSA_STORED,
            )
        })?;
    drop(transport);
    drop(provider);
    let value = StoredDelegateCredentials::from_issued(&issued, expected).map_err(|_| {
        DelegateHarnessError::at(
            "delegate storage input",
            "issued storage material rejected",
            GSA_STORED,
        )
    })?;
    drop(issued);
    drop(fresh);
    terminal
        .notice("[delegate store] writing once, then comparing every field over a fresh connection")
        .map_err(|_| {
            DelegateHarnessError::at(
                "before delegate persistence",
                "terminal failed or interrupted",
                GSA_STORED,
            )
        })?;
    let writer = block_on(connector.connect()).map_err(|_| {
        DelegateHarnessError::at(
            "delegate persistence",
            "new writer connection failed",
            GSA_STORED,
        )
    })?;
    block_on(writer.replace_delegate(&slot, expected, &value)).map_err(|_| {
        DelegateHarnessError::at(
            "delegate persistence",
            "single write failed; no retry",
            BOTH_UNCERTAIN,
        )
    })?;
    drop(writer);
    let reader = block_on(connector.connect()).map_err(|_| {
        DelegateHarnessError::at(
            "delegate reload",
            "fresh reader connection failed",
            BOTH_UNCERTAIN,
        )
    })?;
    let reloaded = block_on(reader.load_delegate(&slot, expected))
        .map_err(|_| {
            DelegateHarnessError::at(
                "delegate reload",
                "fresh-connection load rejected",
                BOTH_UNCERTAIN,
            )
        })?
        .ok_or(DelegateHarnessError::at(
            "delegate reload",
            "item missing after write",
            BOTH_UNCERTAIN,
        ))?;
    if !delegates_equal(&value, &reloaded) {
        return Err(DelegateHarnessError::at(
            "delegate reload",
            "reloaded fields differ from issued material",
            BOTH_UNCERTAIN,
        ));
    }
    Ok(DelegateOutcome::Stored)
}

fn delegates_equal(left: &StoredDelegateCredentials, right: &StoredDelegateCredentials) -> bool {
    let adsid = constant_time_eq(
        left.expose_adsid().as_bytes(),
        right.expose_adsid().as_bytes(),
    );
    let client = constant_time_eq(
        left.expose_client_id().as_bytes(),
        right.expose_client_id().as_bytes(),
    );
    let dsid = constant_time_eq(
        left.expose_dsid().as_bytes(),
        right.expose_dsid().as_bytes(),
    );
    let mme = constant_time_eq(
        left.expose_mme_auth_token().as_bytes(),
        right.expose_mme_auth_token().as_bytes(),
    );
    let cloudkit = constant_time_eq(
        left.expose_cloudkit_token().as_bytes(),
        right.expose_cloudkit_token().as_bytes(),
    );
    adsid & client & dsid & mme & cloudkit
}

/// Runs this developer-only flow using the controlling-terminal abstraction.
///
/// Requires a preexisting profile, GSA session, verified installed support
/// libraries, and existing local provisioning. Missing or invalid state fails
/// before password input/network; a stored delegate exits without fresh login.
/// Otherwise visible confirmation precedes the existing hidden-TTY login flow.
/// All owners are dropped on return; only separately persisted subsets remain.
///
/// # Errors
/// Returns fixed stage/retention labels on the first failure; never retries or
/// rolls back either independent write. This function must not be invoked from
/// CI or before independent review and explicit live-account authorization.
pub fn run(terminal: &mut impl SecureTerminal) -> Result<DelegateOutcome, DelegateHarnessError> {
    let state = SlotState::from_environment().map_err(|_| {
        DelegateHarnessError::at(
            "profile slot",
            "existing state location unavailable",
            UNCHANGED,
        )
    })?;
    run_with(
        terminal,
        &state,
        &SecretServiceConnector,
        || {
            crate::reuse::prepare_local()
                .map(|(_, provider)| provider)
                .map_err(|_| {
                    DelegateHarnessError::at(
                        "local preflight",
                        "existing libraries or provisioning unavailable",
                        UNCHANGED,
                    )
                })
        },
        |provider, terminal| {
            let transport = GsaTransport::starting_on_first_exchange(
                UreqExchange::new(),
                Duration::from_secs(60),
                Duration::from_secs(20 * 60),
            );
            let authenticator =
                Authenticator::new(transport, BorrowedProvider(provider), OsEntropy);
            block_on(run_login(&authenticator, terminal))
                .map(|outcome| outcome.session)
                .map_err(|error| {
                    let (stage, cause) = HarnessError::Flow(error).labels();
                    DelegateHarnessError::at(stage, cause, UNCHANGED)
                })
        },
        || {
            DelegateTransport::production(Deadlines::starting_now(
                Duration::from_secs(60),
                Duration::from_secs(300),
            ))
        },
    )
}

#[cfg(test)]
#[path = "../tests/delegate_harness/mod.rs"]
mod tests;
