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

//! Deterministic in-memory implementation of the session-store port.

use core::fmt;
use std::collections::{BTreeMap, VecDeque};
use std::sync::Mutex;

use zeroize::Zeroizing;

use crate::codec;
use crate::store::{
    BackendOperation, DeleteOutcome, ReusableSession, SessionSlot, SessionStore, StoreError,
};

/// A fake-store operation that tests can fail or inspect.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum FakeOperation {
    /// [`SessionStore::check_available`].
    CheckAvailable,
    /// [`SessionStore::load`].
    Load,
    /// [`SessionStore::replace`].
    Replace,
    /// [`SessionStore::delete`].
    Delete,
}

/// Secret-free outcome recorded by [`FakeSessionStore`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FakeOutcome {
    /// The operation succeeded.
    Succeeded,
    /// The operation returned an injected or data-validation failure.
    Failed,
}

#[derive(Default)]
struct State {
    items: BTreeMap<SessionSlot, Vec<Zeroizing<Vec<u8>>>>,
    failures: BTreeMap<FakeOperation, VecDeque<StoreError>>,
    operations: Vec<(FakeOperation, FakeOutcome)>,
}

/// A deterministic, process-only [`SessionStore`] for tests.
///
/// The fake never reads the environment, filesystem, D-Bus, clock, or random
/// source.  It stores the exact same encoded bytes as the production adapter,
/// permits malformed and duplicate records to be injected, and records only
/// operation kinds and outcomes.  Its `Debug` output never contains slots or
/// secret bytes.
#[derive(Default)]
pub struct FakeSessionStore {
    state: Mutex<State>,
}

impl FakeSessionStore {
    /// Creates an empty, available fake.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Queues one error for the next matching operation.
    ///
    /// Failures are consumed in insertion order.  This makes unavailable,
    /// locked, denied, timeout, and generic backend paths reproducible.
    pub fn fail_next(&self, operation: FakeOperation, error: StoreError) {
        if let Ok(mut state) = self.state.lock() {
            state
                .failures
                .entry(operation)
                .or_default()
                .push_back(error);
        }
    }

    /// Adds one raw backend item for corruption, version, or duplicate tests.
    ///
    /// `bytes` are treated as a secret and zeroized when replaced, deleted, or
    /// when the fake is dropped.  Production code should use [`SessionStore`]
    /// instead of this test-support escape hatch.
    pub fn insert_raw(&self, slot: SessionSlot, bytes: Vec<u8>) {
        if let Ok(mut state) = self.state.lock() {
            state
                .items
                .entry(slot)
                .or_default()
                .push(Zeroizing::new(bytes));
        }
    }

    /// Returns the secret-free operation history.
    #[must_use]
    pub fn operations(&self) -> Vec<(FakeOperation, FakeOutcome)> {
        self.state
            .lock()
            .map(|state| state.operations.clone())
            .unwrap_or_default()
    }

    fn begin(
        &self,
        operation: FakeOperation,
    ) -> Result<std::sync::MutexGuard<'_, State>, StoreError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| StoreError::BackendFailure(backend_operation(operation)))?;
        if let Some(error) = state
            .failures
            .get_mut(&operation)
            .and_then(VecDeque::pop_front)
        {
            state.operations.push((operation, FakeOutcome::Failed));
            return Err(error);
        }
        Ok(state)
    }

    fn finish(state: &mut State, operation: FakeOperation, succeeded: bool) {
        state.operations.push((
            operation,
            if succeeded {
                FakeOutcome::Succeeded
            } else {
                FakeOutcome::Failed
            },
        ));
    }
}

impl fmt::Debug for FakeSessionStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("FakeSessionStore(<redacted>)")
    }
}

impl SessionStore for FakeSessionStore {
    async fn check_available(&self) -> Result<(), StoreError> {
        let mut state = self.begin(FakeOperation::CheckAvailable)?;
        state
            .operations
            .push((FakeOperation::CheckAvailable, FakeOutcome::Succeeded));
        Ok(())
    }

    async fn load(&self, slot: &SessionSlot) -> Result<Option<ReusableSession>, StoreError> {
        let mut state = self.begin(FakeOperation::Load)?;
        let result = match state.items.get(slot) {
            None => Ok(None),
            Some(items) if items.len() > 1 => Err(StoreError::Duplicate),
            Some(items) => codec::decode(slot, &items[0]).map(Some),
        };
        Self::finish(&mut state, FakeOperation::Load, result.is_ok());
        result
    }

    async fn replace(
        &self,
        slot: &SessionSlot,
        session: &ReusableSession,
    ) -> Result<(), StoreError> {
        let mut state = self.begin(FakeOperation::Replace)?;
        let result = (|| {
            if let Some(items) = state.items.get(slot) {
                if items.len() > 1 {
                    return Err(StoreError::Duplicate);
                }
                codec::decode(slot, &items[0])?;
            }
            let encoded = codec::encode(slot, session)?;
            state.items.insert(*slot, vec![encoded]);
            Ok(())
        })();
        Self::finish(&mut state, FakeOperation::Replace, result.is_ok());
        result
    }

    async fn delete(&self, slot: &SessionSlot) -> Result<DeleteOutcome, StoreError> {
        let mut state = self.begin(FakeOperation::Delete)?;
        let result = match state.items.remove(slot) {
            None => Ok(DeleteOutcome::NotFound),
            Some(items) => Ok(DeleteOutcome::Deleted { count: items.len() }),
        };
        Self::finish(&mut state, FakeOperation::Delete, result.is_ok());
        result
    }
}

const fn backend_operation(operation: FakeOperation) -> BackendOperation {
    match operation {
        FakeOperation::CheckAvailable => BackendOperation::Connect,
        FakeOperation::Load => BackendOperation::Read,
        FakeOperation::Replace => BackendOperation::Write,
        FakeOperation::Delete => BackendOperation::Delete,
    }
}

#[cfg(test)]
mod tests {
    use futures_lite::future::block_on;

    use super::*;
    use crate::UnavailableReason;
    use crate::codec::tests::{SLOT, session};

    #[test]
    fn store_load_replace_delete_and_missing_are_deterministic() {
        let store = FakeSessionStore::new();
        let session = ReusableSession::new(
            "public-test-account".to_owned(),
            "public-test-token".to_owned(),
            [0x24; 32],
            b"public-test-cookie".to_vec(),
        )
        .expect("valid public constructor inputs");
        block_on(store.check_available()).expect("available");
        assert!(block_on(store.load(&SLOT)).expect("missing load").is_none());

        block_on(store.replace(&SLOT, &session)).expect("store");
        let loaded = block_on(store.load(&SLOT))
            .expect("load")
            .expect("stored item");
        assert_eq!(loaded.expose_account_id(), "public-test-account");

        block_on(store.replace(&SLOT, &session)).expect("replace");
        assert_eq!(
            block_on(store.delete(&SLOT)).expect("delete"),
            DeleteOutcome::Deleted { count: 1 }
        );
        assert_eq!(
            block_on(store.delete(&SLOT)).expect("missing delete"),
            DeleteOutcome::NotFound
        );
    }

    #[test]
    fn unavailable_and_backend_failures_are_explicit() {
        let store = FakeSessionStore::new();
        store.fail_next(
            FakeOperation::CheckAvailable,
            StoreError::Unavailable(UnavailableReason::NoServiceOwner),
        );
        assert_eq!(
            block_on(store.check_available()).expect_err("unavailable"),
            StoreError::Unavailable(UnavailableReason::NoServiceOwner)
        );

        store.fail_next(
            FakeOperation::Load,
            StoreError::BackendFailure(BackendOperation::Read),
        );
        assert_eq!(
            block_on(store.load(&SLOT)).expect_err("backend failure"),
            StoreError::BackendFailure(BackendOperation::Read)
        );
    }

    #[test]
    fn duplicate_corrupt_and_newer_items_are_not_selected_or_overwritten() {
        let duplicate = FakeSessionStore::new();
        let encoded = codec::encode(&SLOT, &session()).expect("encode").to_vec();
        duplicate.insert_raw(SLOT, encoded.clone());
        duplicate.insert_raw(SLOT, encoded);
        assert_eq!(
            block_on(duplicate.load(&SLOT)).expect_err("duplicate"),
            StoreError::Duplicate
        );
        assert_eq!(
            block_on(duplicate.replace(&SLOT, &session())).expect_err("preserve duplicate"),
            StoreError::Duplicate
        );

        let corrupt = FakeSessionStore::new();
        corrupt.insert_raw(SLOT, b"not an envelope".to_vec());
        assert_eq!(
            block_on(corrupt.replace(&SLOT, &session())).expect_err("preserve corrupt"),
            StoreError::Corrupt
        );

        let newer = FakeSessionStore::new();
        let mut encoded = codec::encode(&SLOT, &session()).expect("encode").to_vec();
        encoded[8..10].copy_from_slice(&99u16.to_be_bytes());
        newer.insert_raw(SLOT, encoded);
        assert_eq!(
            block_on(newer.replace(&SLOT, &session())).expect_err("preserve newer"),
            StoreError::UnsupportedVersion(99)
        );
    }

    #[test]
    fn operation_history_and_debug_contain_no_slots_or_secrets() {
        let store = FakeSessionStore::new();
        block_on(store.replace(&SLOT, &session())).expect("store");
        let rendered = format!("{store:?} {:?}", store.operations());
        assert!(!rendered.contains("synthetic"));
        assert!(!rendered.contains("5a5a5a"));
        assert_eq!(format!("{store:?}"), "FakeSessionStore(<redacted>)");
    }
}
