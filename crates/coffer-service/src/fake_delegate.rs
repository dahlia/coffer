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

//! Synthetic connections sharing only in-memory delegate backend state.

use crate::delegate_store::{self, Backend};
use crate::{
    DelegateBindingRef, DelegateStore, DelegateStoreError as Error, MAX_STORED_DELEGATE_BYTES,
    SessionSlot, StoredDelegateCredentials,
};
use core::fmt;
use std::collections::VecDeque;
use std::sync::{Arc, Mutex, MutexGuard};
use zeroize::Zeroizing;

/// Secret-free backend attempt observed by the delegate fake.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FakeDelegateOperation {
    /// Checks availability.
    Available,
    /// Searches the delegate kind and opaque slot.
    Search,
    /// Reads one selected record.
    Read,
    /// Creates a record without implicit replacement.
    Create,
    /// Updates the exact selected record.
    Update,
}
struct Item {
    slot: SessionSlot,
    bytes: Zeroizing<Vec<u8>>,
}
#[derive(Default)]
struct State {
    items: Vec<Item>,
    operations: Vec<FakeDelegateOperation>,
    failures: VecDeque<(FakeDelegateOperation, Error)>,
    after_write: Option<Error>,
}

/// In-memory fake of the same delegate storage algorithm as Linux Secret Service.
///
/// Each [`Self::new_connection`] shares backend bytes, not decoded credentials.
/// No D-Bus, filesystem, environment, account, clock, or network access occurs.
/// All stored bytes are zeroized on final backend drop; diagnostics are redacted.
#[derive(Default)]
pub struct FakeDelegateStore {
    state: Arc<Mutex<State>>,
}
impl FakeDelegateStore {
    /// Creates an empty synthetic backend and its first connection.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
    /// Creates an independent client connection to the same synthetic backend.
    #[must_use]
    pub fn new_connection(&self) -> Self {
        Self {
            state: Arc::clone(&self.state),
        }
    }
    /// Adds an opaque synthetic delegate item, including corrupt or duplicate bytes.
    ///
    /// Takes zeroizing ownership immediately. Intended only for offline tests.
    /// Returns a static backend error if the synthetic state lock is poisoned.
    pub fn insert_raw(&self, slot: SessionSlot, bytes: Vec<u8>) -> Result<(), Error> {
        let bytes = Zeroizing::new(bytes);
        self.lock()?.items.push(Item { slot, bytes });
        Ok(())
    }
    /// Fails the next matching backend operation before it takes effect.
    ///
    /// Returns a static backend error if the synthetic state lock is poisoned.
    pub fn fail_next(&self, operation: FakeDelegateOperation, error: Error) -> Result<(), Error> {
        self.lock()?.failures.push_back((operation, error));
        Ok(())
    }
    /// Makes the next write take effect and then report an ambiguous failure.
    ///
    /// This models a lost create/update reply. No retry is performed.
    /// Returns a static backend error if the synthetic state lock is poisoned.
    pub fn fail_after_write(&self, error: Error) -> Result<(), Error> {
        self.lock()?.after_write = Some(error);
        Ok(())
    }
    /// Returns only backend attempt kinds, without paths, slots, or secret data.
    ///
    /// Returns a static backend error if the synthetic state lock is poisoned.
    pub fn operations(&self) -> Result<Vec<FakeDelegateOperation>, Error> {
        Ok(self.lock()?.operations.clone())
    }
    fn lock(&self) -> Result<MutexGuard<'_, State>, Error> {
        self.state.lock().map_err(|_| Error::BackendFailure)
    }
    fn begin(&self, operation: FakeDelegateOperation) -> Result<MutexGuard<'_, State>, Error> {
        let mut state = self.lock()?;
        state.operations.push(operation);
        if let Some(index) = state
            .failures
            .iter()
            .position(|(kind, _)| *kind == operation)
            && let Some((_, error)) = state.failures.remove(index)
        {
            return Err(error);
        }
        Ok(state)
    }
}
impl fmt::Debug for FakeDelegateStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("FakeDelegateStore(<redacted>)")
    }
}
impl Backend for FakeDelegateStore {
    type Item = usize;
    async fn available(&self) -> Result<(), Error> {
        drop(self.begin(FakeDelegateOperation::Available)?);
        Ok(())
    }
    async fn search(&self, slot: &SessionSlot) -> Result<Vec<usize>, Error> {
        let state = self.begin(FakeDelegateOperation::Search)?;
        Ok(state
            .items
            .iter()
            .enumerate()
            .filter_map(|(i, item)| (item.slot == *slot).then_some(i))
            .collect())
    }
    async fn read(&self, item: &usize) -> Result<Zeroizing<Vec<u8>>, Error> {
        let state = self.begin(FakeDelegateOperation::Read)?;
        let raw = &state.items.get(*item).ok_or(Error::BackendFailure)?.bytes;
        if raw.len() > MAX_STORED_DELEGATE_BYTES {
            return Err(Error::TooLarge);
        }
        let mut bytes = Zeroizing::new(Vec::with_capacity(raw.len()));
        bytes.extend_from_slice(raw);
        Ok(bytes)
    }
    async fn write(
        &self,
        slot: &SessionSlot,
        item: Option<&usize>,
        bytes: Zeroizing<Vec<u8>>,
    ) -> Result<(), Error> {
        let op = if item.is_some() {
            FakeDelegateOperation::Update
        } else {
            FakeDelegateOperation::Create
        };
        let mut state = self.begin(op)?;
        if let Some(index) = item {
            state
                .items
                .get_mut(*index)
                .ok_or(Error::BackendFailure)?
                .bytes = bytes;
        } else {
            state.items.push(Item { slot: *slot, bytes });
        }
        if let Some(error) = state.after_write.take() {
            return Err(error);
        }
        Ok(())
    }
}
impl DelegateStore for FakeDelegateStore {
    async fn load_delegate(
        &self,
        slot: &SessionSlot,
        expected: DelegateBindingRef<'_>,
    ) -> Result<Option<StoredDelegateCredentials>, Error> {
        delegate_store::load(self, slot, expected).await
    }
    async fn replace_delegate(
        &self,
        slot: &SessionSlot,
        expected: DelegateBindingRef<'_>,
        value: &StoredDelegateCredentials,
    ) -> Result<(), Error> {
        delegate_store::replace(self, slot, expected, value).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::delegate_codec::tests::{FIXTURE, SLOT, binding, material};
    use FakeDelegateOperation::*;
    use futures_lite::future::block_on;

    #[test]
    fn new_connection_reloads_and_replaces_encoded_material() {
        let first = FakeDelegateStore::new();
        assert!(
            block_on(first.load_delegate(&SLOT, binding()))
                .unwrap()
                .is_none()
        );
        let value = material();
        block_on(first.replace_delegate(&SLOT, binding(), &value)).unwrap();
        let second = first.new_connection();
        drop(value);
        drop(first);
        let loaded = block_on(second.load_delegate(&SLOT, binding()))
            .unwrap()
            .unwrap();
        assert_eq!(loaded.expose_mme_auth_token(), "M");
        assert_eq!(loaded.expose_cloudkit_token(), "K");
        assert_eq!(loaded.expose_dsid(), "D");
        let next =
            StoredDelegateCredentials::from_fields(["A", "C", "D", "new M", "new K"]).unwrap();
        block_on(second.replace_delegate(&SLOT, binding(), &next)).unwrap();
        let third = second.new_connection();
        drop(second);
        drop(next);
        let loaded = block_on(third.load_delegate(&SLOT, binding()))
            .unwrap()
            .unwrap();
        assert_eq!(loaded.expose_mme_auth_token(), "new M");
        assert_eq!(third.lock().unwrap().items.len(), 1);
    }
    #[test]
    fn rejected_records_are_byte_for_byte_preserved() {
        let mut newer = FIXTURE.to_vec();
        newer[9] = 99;
        let mut wrong_slot = FIXTURE.to_vec();
        wrong_slot[10] ^= 1;
        let mut wrong_account = FIXTURE.to_vec();
        wrong_account[29] = b'B';
        let mut wrong_client = FIXTURE.to_vec();
        wrong_client[33] = b'B';
        let mut trailing = FIXTURE.to_vec();
        trailing.push(0);
        for raw in [
            b"bad".to_vec(),
            newer,
            wrong_slot,
            wrong_account,
            wrong_client,
            trailing,
            vec![0; MAX_STORED_DELEGATE_BYTES + 1],
        ] {
            let store = FakeDelegateStore::new();
            store.insert_raw(SLOT, raw.clone()).unwrap();
            assert!(block_on(store.load_delegate(&SLOT, binding())).is_err());
            assert!(block_on(store.replace_delegate(&SLOT, binding(), &material())).is_err());
            assert_eq!(&*store.lock().unwrap().items[0].bytes, &raw);
            assert!(
                !store
                    .operations()
                    .unwrap()
                    .iter()
                    .any(|op| matches!(op, Create | Update))
            );
        }
        let store = FakeDelegateStore::new();
        for _ in 0..2 {
            store.insert_raw(SLOT, FIXTURE.to_vec()).unwrap();
        }
        assert_eq!(
            block_on(store.load_delegate(&SLOT, binding())).unwrap_err(),
            Error::Duplicate
        );
        assert_eq!(
            block_on(store.replace_delegate(&SLOT, binding(), &material())).unwrap_err(),
            Error::Duplicate
        );
        assert_eq!(
            store.operations().unwrap(),
            [Available, Search, Available, Search]
        );
        assert!(
            store
                .lock()
                .unwrap()
                .items
                .iter()
                .all(|item| item.bytes.as_slice() == FIXTURE)
        );
    }
    #[test]
    fn caller_mismatch_causes_no_backend_access_and_slot_isolation_holds() {
        let store = FakeDelegateStore::new();
        let wrong = DelegateBindingRef::new("other", "C").unwrap();
        assert_eq!(
            block_on(store.replace_delegate(&SLOT, wrong, &material())).unwrap_err(),
            Error::BindingMismatch
        );
        assert!(store.operations().unwrap().is_empty());
        block_on(store.replace_delegate(&SLOT, binding(), &material())).unwrap();
        let other = SessionSlot::from_random_bytes([0; 16]);
        assert!(
            block_on(store.load_delegate(&other, binding()))
                .unwrap()
                .is_none()
        );
    }
    #[test]
    fn failures_do_not_retry_or_fall_back_and_preserve_rejected_writes() {
        for error in [
            Error::Unavailable,
            Error::Locked,
            Error::Denied,
            Error::PromptDismissed,
            Error::TimedOut,
            Error::BackendFailure,
        ] {
            for operation in [Available, Search, Read, Update] {
                let store = FakeDelegateStore::new();
                store.insert_raw(SLOT, FIXTURE.to_vec()).unwrap();
                store.fail_next(operation, error).unwrap();
                assert_eq!(
                    block_on(store.replace_delegate(&SLOT, binding(), &material())).unwrap_err(),
                    error
                );
                let ops = store.operations().unwrap();
                assert_eq!(ops.last(), Some(&operation));
                assert_eq!(ops.iter().filter(|op| **op == operation).count(), 1);
                assert_eq!(&*store.lock().unwrap().items[0].bytes, FIXTURE);
            }
            let store = FakeDelegateStore::new();
            store.fail_next(Create, error).unwrap();
            assert_eq!(
                block_on(store.replace_delegate(&SLOT, binding(), &material())).unwrap_err(),
                error
            );
            assert!(store.lock().unwrap().items.is_empty());
            assert_eq!(store.operations().unwrap(), [Available, Search, Create]);
        }
    }
    #[test]
    fn ambiguous_create_and_update_fail_once_without_cleanup_or_second_item() {
        for existing in [false, true] {
            let store = FakeDelegateStore::new();
            if existing {
                store.insert_raw(SLOT, FIXTURE.to_vec()).unwrap();
            }
            store.fail_after_write(Error::TimedOut).unwrap();
            let next =
                StoredDelegateCredentials::from_fields(["A", "C", "D", "changed M", "changed K"])
                    .unwrap();
            assert_eq!(
                block_on(store.replace_delegate(&SLOT, binding(), &next)).unwrap_err(),
                Error::TimedOut
            );
            assert_eq!(store.lock().unwrap().items.len(), 1);
            let ops = store.operations().unwrap();
            assert_eq!(
                ops.iter()
                    .filter(|op| matches!(op, Create | Update))
                    .count(),
                1
            );
            let connection = store.new_connection();
            let loaded = block_on(connection.load_delegate(&SLOT, binding()))
                .unwrap()
                .unwrap();
            assert_eq!(loaded.expose_cloudkit_token(), "changed K");
        }
    }
    #[test]
    fn all_public_diagnostics_are_static_and_have_no_error_source() {
        use std::error::Error as _;
        let value = StoredDelegateCredentials::from_fields([
            "SYNTHETIC-ADSID",
            "SYNTHETIC-CLIENT",
            "SYNTHETIC-DSID",
            "SYNTHETIC-MME",
            "SYNTHETIC-CK",
        ])
        .unwrap();
        let binding =
            DelegateBindingRef::new(value.expose_adsid(), value.expose_client_id()).unwrap();
        let store = FakeDelegateStore::new();
        let rendered = format!("{value:?} {binding:?} {store:?} {SLOT:?}");
        assert!(!rendered.contains("SYNTHETIC"));
        for error in [
            Error::InvalidMaterial,
            Error::Corrupt,
            Error::UnsupportedVersion,
            Error::TooLarge,
            Error::BindingMismatch,
            Error::Duplicate,
            Error::Unavailable,
            Error::Locked,
            Error::Denied,
            Error::PromptDismissed,
            Error::TimedOut,
            Error::BackendFailure,
        ] {
            assert!(error.source().is_none());
            assert!(!format!("{error} {error:?}").contains("SYNTHETIC"));
        }
    }
}
