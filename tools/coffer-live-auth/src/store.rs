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

//! Persisting the reusable session and proving it reloads.
//!
//! What this verifies is deliberately narrow.  Milestone 1 has no
//! service-token refresh: the protocol crate does not yet build the
//! `apptokens` request, so nothing in Coffer can *use* a stored session to
//! talk to Apple again.  The harness therefore claims only what it checks:
//! the reusable subset of the session is written to Secret Service under the
//! profile slot, a second, independent connection to the same backend reads
//! it back, and the four retained fields compare equal.  No field is ever
//! printed.
//!
//! The backend is checked for availability before authentication starts, so
//! a missing or locked keyring is reported before a password is typed and
//! before any Apple attempt is consumed.  There is no plaintext or file
//! fallback of any kind.

use core::fmt;
use std::future::Future;

use coffer_service::{LinuxSecretService, ReusableSession, SessionSlot, SessionStore, StoreError};

use crate::terminal::{SecureTerminal, TerminalError};

/// Opens fresh connections to the session store.
///
/// Each call must produce an independent backend connection so that the
/// reload half of the round trip does not read from a cache the write half
/// populated.
pub trait StoreConnector {
    /// The store a connection yields.
    type Store: SessionStore;

    /// Opens one new connection.
    fn connect(&self) -> impl Future<Output = Result<Self::Store, StoreError>>;
}

/// The production connector over Linux Secret Service.
#[derive(Debug, Default, Clone, Copy)]
pub struct SecretServiceConnector;

impl StoreConnector for SecretServiceConnector {
    type Store = LinuxSecretService;

    async fn connect(&self) -> Result<LinuxSecretService, StoreError> {
        LinuxSecretService::connect().await
    }
}

/// Proof that the store round trip compared equal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PersistenceVerdict {
    _private: (),
}

/// Why the round trip failed.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum PersistError {
    /// The backend or the envelope codec failed; the operation is named.
    Store(StoreError),
    /// The write reported success but a new connection found no item.
    MissingAfterWrite,
    /// The reloaded session differs from the one written.
    Mismatch,
    /// The terminal failed while printing a stage label.
    Terminal(TerminalError),
}

impl fmt::Display for PersistError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Store(error) => write!(f, "{error}"),
            Self::MissingAfterWrite => {
                f.write_str("the session was written but a new connection could not find it")
            }
            Self::Mismatch => f.write_str("the reloaded session does not match what was written"),
            Self::Terminal(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for PersistError {}

impl From<StoreError> for PersistError {
    fn from(error: StoreError) -> Self {
        Self::Store(error)
    }
}

impl From<TerminalError> for PersistError {
    fn from(error: TerminalError) -> Self {
        Self::Terminal(error)
    }
}

/// Confirms the backend is reachable and unlocked without touching any item.
///
/// # Errors
///
/// Returns the store's own classification, for example
/// [`StoreError::Unavailable`] or [`StoreError::Locked`].
pub async fn check_keyring_available<C: StoreConnector>(connector: &C) -> Result<(), StoreError> {
    let store = connector.connect().await?;
    store.check_available().await
}

/// Writes `session` under `slot`, then reloads it over a new connection and
/// compares.
///
/// # Errors
///
/// See [`PersistError`].  A failure after the write leaves the written item
/// in place for inspection with desktop keyring tools.
pub async fn persist_and_reload<C: StoreConnector, T: SecureTerminal>(
    connector: &C,
    slot: &SessionSlot,
    session: &ReusableSession,
    terminal: &mut T,
) -> Result<PersistenceVerdict, PersistError> {
    terminal
        .notice("[store] writing the reusable session to Secret Service under the profile slot")?;
    let writer = connector.connect().await?;
    writer.check_available().await?;
    writer.replace(slot, session).await?;
    drop(writer);
    terminal.notice("[store] reloading it over a new Secret Service connection")?;
    let reader = connector.connect().await?;
    let reloaded = reader
        .load(slot)
        .await?
        .ok_or(PersistError::MissingAfterWrite)?;
    if !sessions_equal(session, &reloaded) {
        return Err(PersistError::Mismatch);
    }
    Ok(PersistenceVerdict { _private: () })
}

/// Compares every retained field without early exit on the secret ones.
fn sessions_equal(left: &ReusableSession, right: &ReusableSession) -> bool {
    let account = left.expose_account_id() == right.expose_account_id();
    let token = constant_time_eq(
        left.expose_idms_token().as_bytes(),
        right.expose_idms_token().as_bytes(),
    );
    let key = constant_time_eq(left.expose_session_key(), right.expose_session_key());
    let cookie = constant_time_eq(left.expose_cookie(), right.expose_cookie());
    account & token & key & cookie
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right)
        .fold(0u8, |acc, (a, b)| acc | (a ^ b))
        == 0
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use coffer_service::{
        BackendOperation, DeleteOutcome, FakeOperation, FakeSessionStore, UnavailableReason,
    };
    use futures_lite::future::block_on;

    use super::*;
    use crate::terminal::LineTerminal;
    use crate::terminal::tests::FakeDevice;

    /// A "connection" to a shared in-memory fake.
    struct Shared(Arc<FakeSessionStore>);

    impl SessionStore for Shared {
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
            self.0.replace(slot, session).await
        }

        async fn delete(&self, slot: &SessionSlot) -> Result<DeleteOutcome, StoreError> {
            self.0.delete(slot).await
        }
    }

    /// Hands out the scripted backends in order, one per connection.
    struct Connector {
        backends: Mutex<Vec<Result<Arc<FakeSessionStore>, StoreError>>>,
        connections: Mutex<usize>,
    }

    impl Connector {
        fn new(backends: Vec<Result<Arc<FakeSessionStore>, StoreError>>) -> Self {
            Self {
                backends: Mutex::new(backends),
                connections: Mutex::new(0),
            }
        }

        fn connections(&self) -> usize {
            *self.connections.lock().unwrap()
        }
    }

    impl StoreConnector for Connector {
        type Store = Shared;

        async fn connect(&self) -> Result<Shared, StoreError> {
            *self.connections.lock().unwrap() += 1;
            let mut backends = self.backends.lock().unwrap();
            assert!(
                !backends.is_empty(),
                "connect called more often than scripted"
            );
            backends.remove(0).map(Shared)
        }
    }

    const SLOT: SessionSlot = SessionSlot::from_random_bytes([0x5a; 16]);

    fn session(tag: u8) -> ReusableSession {
        ReusableSession::new(
            "000000000000000".to_owned(),
            format!("synthetic-idms-token-{tag}"),
            [tag; 32],
            vec![tag, 1, 2, 3],
        )
        .unwrap()
    }

    fn terminal() -> LineTerminal<FakeDevice> {
        LineTerminal::new(FakeDevice::new(b""))
    }

    #[test]
    fn round_trip_uses_two_connections_and_compares_equal() {
        let backend = Arc::new(FakeSessionStore::new());
        let connector = Connector::new(vec![Ok(Arc::clone(&backend)), Ok(Arc::clone(&backend))]);
        let mut terminal = terminal();
        block_on(persist_and_reload(
            &connector,
            &SLOT,
            &session(7),
            &mut terminal,
        ))
        .unwrap();
        assert_eq!(connector.connections(), 2);
        let operations: Vec<FakeOperation> =
            backend.operations().into_iter().map(|(op, _)| op).collect();
        let replace = operations
            .iter()
            .position(|op| *op == FakeOperation::Replace)
            .unwrap();
        let load = operations
            .iter()
            .position(|op| *op == FakeOperation::Load)
            .unwrap();
        assert!(replace < load);
        assert_eq!(
            operations
                .iter()
                .filter(|op| **op == FakeOperation::Replace)
                .count(),
            1
        );
        let output = String::from_utf8(terminal.device().output.clone()).unwrap();
        assert!(!output.contains("synthetic-idms-token"));
        assert!(!output.contains("000000000000000"));
    }

    #[test]
    fn keyring_unavailable_is_reported_before_anything_is_written() {
        let connector = Connector::new(vec![Err(StoreError::Unavailable(
            UnavailableReason::NoServiceOwner,
        ))]);
        assert_eq!(
            block_on(check_keyring_available(&connector)).unwrap_err(),
            StoreError::Unavailable(UnavailableReason::NoServiceOwner)
        );
        let backend = Arc::new(FakeSessionStore::new());
        backend.fail_next(FakeOperation::CheckAvailable, StoreError::Locked);
        let connector = Connector::new(vec![Ok(Arc::clone(&backend))]);
        assert_eq!(
            block_on(check_keyring_available(&connector)).unwrap_err(),
            StoreError::Locked
        );
        assert!(block_on(backend.load(&SLOT)).unwrap().is_none());
    }

    #[test]
    fn a_failed_write_stops_before_the_reload_connection() {
        let backend = Arc::new(FakeSessionStore::new());
        backend.fail_next(
            FakeOperation::Replace,
            StoreError::BackendFailure(BackendOperation::Write),
        );
        let connector = Connector::new(vec![Ok(Arc::clone(&backend))]);
        let error = block_on(persist_and_reload(
            &connector,
            &SLOT,
            &session(1),
            &mut terminal(),
        ))
        .unwrap_err();
        assert_eq!(
            error,
            PersistError::Store(StoreError::BackendFailure(BackendOperation::Write))
        );
        assert_eq!(connector.connections(), 1);
    }

    #[test]
    fn a_reload_that_finds_nothing_is_an_error() {
        let writer = Arc::new(FakeSessionStore::new());
        let reader = Arc::new(FakeSessionStore::new());
        let connector = Connector::new(vec![Ok(writer), Ok(reader)]);
        let error = block_on(persist_and_reload(
            &connector,
            &SLOT,
            &session(1),
            &mut terminal(),
        ))
        .unwrap_err();
        assert_eq!(error, PersistError::MissingAfterWrite);
    }

    #[test]
    fn a_reload_that_differs_is_an_error() {
        let writer = Arc::new(FakeSessionStore::new());
        let reader = Arc::new(FakeSessionStore::new());
        block_on(reader.replace(&SLOT, &session(2))).unwrap();
        let connector = Connector::new(vec![Ok(writer), Ok(reader)]);
        let error = block_on(persist_and_reload(
            &connector,
            &SLOT,
            &session(1),
            &mut terminal(),
        ))
        .unwrap_err();
        assert_eq!(error, PersistError::Mismatch);
    }

    #[test]
    fn a_reload_failure_is_reported_as_the_store_error() {
        let backend = Arc::new(FakeSessionStore::new());
        backend.fail_next(FakeOperation::Load, StoreError::Duplicate);
        let connector = Connector::new(vec![Ok(Arc::clone(&backend)), Ok(backend)]);
        let error = block_on(persist_and_reload(
            &connector,
            &SLOT,
            &session(1),
            &mut terminal(),
        ))
        .unwrap_err();
        assert_eq!(error, PersistError::Store(StoreError::Duplicate));
    }

    #[test]
    fn comparison_covers_every_field() {
        assert!(sessions_equal(&session(1), &session(1)));
        assert!(!sessions_equal(&session(1), &session(2)));
        let other = ReusableSession::new(
            "000000000000000".to_owned(),
            "synthetic-idms-token-1".to_owned(),
            [1; 32],
            vec![1, 1, 2, 3, 4],
        )
        .unwrap();
        assert!(!sessions_equal(&session(1), &other));
        assert!(constant_time_eq(b"", b""));
        assert!(!constant_time_eq(b"a", b"ab"));
    }

    #[test]
    fn errors_are_secret_free() {
        assert_eq!(
            PersistError::Mismatch.to_string(),
            "the reloaded session does not match what was written"
        );
        assert_eq!(
            format!("{:?}", PersistenceVerdict { _private: () }),
            "PersistenceVerdict { _private: () }"
        );
    }
}
