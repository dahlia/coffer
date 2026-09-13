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

//! Shared delegate-only backend operations, exercised by synthetic connections.

use crate::delegate_codec;
use crate::{
    DelegateBindingRef, DelegateStoreError as Error, SessionSlot, StoredDelegateCredentials,
};
use std::future::Future;
use zeroize::Zeroizing;

pub(crate) trait Backend: Send + Sync {
    type Item: Send + Sync;
    fn available(&self) -> impl Future<Output = Result<(), Error>> + Send;
    fn search(
        &self,
        slot: &SessionSlot,
    ) -> impl Future<Output = Result<Vec<Self::Item>, Error>> + Send;
    fn read(
        &self,
        item: &Self::Item,
    ) -> impl Future<Output = Result<Zeroizing<Vec<u8>>, Error>> + Send;
    fn write(
        &self,
        slot: &SessionSlot,
        item: Option<&Self::Item>,
        bytes: Zeroizing<Vec<u8>>,
    ) -> impl Future<Output = Result<(), Error>> + Send;
}

pub(crate) async fn load<B: Backend>(
    backend: &B,
    slot: &SessionSlot,
    expected: DelegateBindingRef<'_>,
) -> Result<Option<StoredDelegateCredentials>, Error> {
    backend.available().await?;
    let items = backend.search(slot).await?;
    match items.as_slice() {
        [] => Ok(None),
        [item] => {
            let bytes = backend.read(item).await?;
            delegate_codec::decode(slot, expected, &bytes).map(Some)
        }
        _ => Err(Error::Duplicate),
    }
}

pub(crate) async fn replace<B: Backend>(
    backend: &B,
    slot: &SessionSlot,
    expected: DelegateBindingRef<'_>,
    value: &StoredDelegateCredentials,
) -> Result<(), Error> {
    // A caller mistake cannot trigger any backend work.
    if !value.matches(expected) {
        return Err(Error::BindingMismatch);
    }
    backend.available().await?;
    let items = backend.search(slot).await?;
    let item = match items.as_slice() {
        [] => None,
        [item] => {
            let bytes = backend.read(item).await?;
            delegate_codec::decode(slot, expected, &bytes)?;
            Some(item)
        }
        _ => return Err(Error::Duplicate),
    };
    let bytes = delegate_codec::encode(slot, value)?;
    // Exactly one mutation. On an ambiguous failure, never try another item.
    backend.write(slot, item, bytes).await
}
