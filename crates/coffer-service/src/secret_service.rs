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

//! Linux Secret Service adapter implemented through oo7's explicit D-Bus API.

use core::fmt;
use std::collections::BTreeMap;

use oo7::dbus::{Collection, Error as Oo7Error, Service, ServiceError};

use crate::codec;
use crate::store::{
    BackendOperation, DeleteFailure, DeleteOutcome, ReusableSession, SessionSlot, SessionStore,
    StoreError, UnavailableReason,
};

/// Fixed Secret Service schema attribute.
pub const SCHEMA_ATTRIBUTE: &str = "org.dahlia.Coffer.Authentication";
/// Fixed application attribute.
pub const APPLICATION_ATTRIBUTE: &str = "org.dahlia.Coffer";
/// Fixed item-kind attribute.
pub const KIND_ATTRIBUTE: &str = "authentication-session";
/// Non-identifying label visible in desktop keyring tools.
pub const ITEM_LABEL: &str = "Coffer authentication session";

const DEFAULT_COLLECTION: &str = Service::DEFAULT_COLLECTION;

#[derive(Debug, Eq, PartialEq)]
enum ReplacementAction {
    Create,
    UpdateMatched,
}

const fn replacement_action(match_count: usize) -> Result<ReplacementAction, StoreError> {
    match match_count {
        0 => Ok(ReplacementAction::Create),
        1 => Ok(ReplacementAction::UpdateMatched),
        _ => Err(StoreError::Duplicate),
    }
}

/// The Linux Secret Service implementation of [`SessionStore`].
///
/// Construct it with [`LinuxSecretService::connect`].  That constructor calls
/// [`oo7::dbus::Service::encrypted`] directly, then selects an existing default
/// collection without creating one.  It never calls `oo7::Keyring::new`, never
/// permits oo7's plain D-Bus session fallback, and never falls back to a file or
/// portal backend when Secret Service is absent or denied.
pub struct LinuxSecretService {
    collection: Collection,
}

impl LinuxSecretService {
    /// Connects to an existing default Secret Service collection.
    ///
    /// # Errors
    ///
    /// Returns an explicit unavailable, denied, locked, timeout, prompt, or
    /// backend category.  Backend error strings and object paths are discarded
    /// so they cannot put account-correlated data into logs.
    pub async fn connect() -> Result<Self, StoreError> {
        let service = Service::encrypted()
            .await
            .map_err(|error| classify(error, BackendOperation::Connect))?;
        let collection = service
            .with_alias(DEFAULT_COLLECTION)
            .await
            .map_err(|error| classify(error, BackendOperation::Connect))?
            .ok_or(StoreError::Unavailable(
                UnavailableReason::NoDefaultCollection,
            ))?;
        let store = Self { collection };
        store.check_available().await?;
        Ok(store)
    }

    fn attributes(slot: &SessionSlot) -> BTreeMap<&'static str, String> {
        BTreeMap::from([
            (oo7::XDG_SCHEMA_ATTRIBUTE, SCHEMA_ATTRIBUTE.to_owned()),
            ("application", APPLICATION_ATTRIBUTE.to_owned()),
            ("kind", KIND_ATTRIBUTE.to_owned()),
            ("slot", slot.attribute_value()),
        ])
    }
}

impl fmt::Debug for LinuxSecretService {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("LinuxSecretService")
    }
}

impl SessionStore for LinuxSecretService {
    async fn check_available(&self) -> Result<(), StoreError> {
        match self.collection.is_locked().await {
            Ok(false) => Ok(()),
            Ok(true) => Err(StoreError::Locked),
            Err(error) => Err(classify(error, BackendOperation::Connect)),
        }
    }

    async fn load(&self, slot: &SessionSlot) -> Result<Option<ReusableSession>, StoreError> {
        self.check_available().await?;
        let items = self
            .collection
            .search_items(&Self::attributes(slot))
            .await
            .map_err(|error| classify(error, BackendOperation::Search))?;
        match items.len() {
            0 => Ok(None),
            1 => {
                let secret = items[0]
                    .secret()
                    .await
                    .map_err(|error| classify(error, BackendOperation::Read))?;
                codec::decode(slot, secret.as_bytes()).map(Some)
            }
            _ => Err(StoreError::Duplicate),
        }
    }

    async fn replace(
        &self,
        slot: &SessionSlot,
        session: &ReusableSession,
    ) -> Result<(), StoreError> {
        self.check_available().await?;
        let attributes = Self::attributes(slot);
        let existing = self
            .collection
            .search_items(&attributes)
            .await
            .map_err(|error| classify(error, BackendOperation::Search))?;
        let matched_item = match replacement_action(existing.len())? {
            ReplacementAction::Create => None,
            ReplacementAction::UpdateMatched => {
                let secret = existing[0]
                    .secret()
                    .await
                    .map_err(|error| classify(error, BackendOperation::Read))?;
                codec::decode(slot, secret.as_bytes())?;
                Some(&existing[0])
            }
        };

        let envelope = codec::encode(slot, session)?;
        if let Some(item) = matched_item {
            // Secret Service search semantics allow an item to carry extra
            // attributes.  Updating the matched object prevents a subsequent
            // exact-attribute CreateItem call from creating a duplicate.
            item.set_secret(envelope)
                .await
                .map_err(|error| classify(error, BackendOperation::Write))?;
        } else {
            self.collection
                .create_item(ITEM_LABEL, &attributes, envelope, true, None)
                .await
                .map_err(|error| classify(error, BackendOperation::Write))?;
        }
        Ok(())
    }

    async fn delete(&self, slot: &SessionSlot) -> Result<DeleteOutcome, StoreError> {
        self.check_available().await?;
        let items = self
            .collection
            .search_items(&Self::attributes(slot))
            .await
            .map_err(|error| classify(error, BackendOperation::Search))?;
        if items.is_empty() {
            return Ok(DeleteOutcome::NotFound);
        }

        let total = items.len();
        let mut deleted = 0usize;
        let mut failures = Vec::new();
        for item in items {
            match item.delete(None).await {
                Ok(()) => deleted += 1,
                Err(error) => failures.push(classify(error, BackendOperation::Delete)),
            }
        }
        if failures.is_empty() {
            Ok(DeleteOutcome::Deleted { count: deleted })
        } else if total == 1 {
            Err(failures.remove(0))
        } else {
            Err(StoreError::PartialDelete {
                deleted,
                failures: failures.iter().map(delete_failure).collect(),
            })
        }
    }
}

const fn delete_failure(error: &StoreError) -> DeleteFailure {
    match error {
        StoreError::Unavailable(_) => DeleteFailure::Unavailable,
        StoreError::Locked => DeleteFailure::Locked,
        StoreError::Denied => DeleteFailure::Denied,
        StoreError::PromptDismissed => DeleteFailure::PromptDismissed,
        StoreError::TimedOut => DeleteFailure::TimedOut,
        _ => DeleteFailure::Backend,
    }
}

fn classify(error: Oo7Error, operation: BackendOperation) -> StoreError {
    match error {
        Oo7Error::Dismissed => StoreError::PromptDismissed,
        Oo7Error::Service(ServiceError::IsLocked(_)) => StoreError::Locked,
        Oo7Error::Service(ServiceError::ZBus(error)) | Oo7Error::ZBus(error) => {
            classify_zbus(&error).unwrap_or(StoreError::BackendFailure(operation))
        }
        _ => StoreError::BackendFailure(operation),
    }
}

fn classify_zbus(error: &oo7::zbus::Error) -> Option<StoreError> {
    use oo7::zbus::Error;
    use oo7::zbus::fdo::Error as FdoError;

    match error {
        Error::InputOutput(error) | Error::Connection(error, _) => match error.kind() {
            std::io::ErrorKind::TimedOut => Some(StoreError::TimedOut),
            std::io::ErrorKind::PermissionDenied => Some(StoreError::Denied),
            _ => Some(StoreError::Unavailable(UnavailableReason::NoSessionBus)),
        },
        Error::FDO(error) => match error.as_ref() {
            FdoError::AccessDenied(_) | FdoError::AuthFailed(_) => Some(StoreError::Denied),
            FdoError::NoReply(_) | FdoError::Timeout(_) | FdoError::TimedOut(_) => {
                Some(StoreError::TimedOut)
            }
            FdoError::ServiceUnknown(_) | FdoError::NameHasNoOwner(_) => {
                Some(StoreError::Unavailable(UnavailableReason::NoServiceOwner))
            }
            FdoError::NoServer(_) | FdoError::Disconnected(_) | FdoError::BadAddress(_) => {
                Some(StoreError::Unavailable(UnavailableReason::NoSessionBus))
            }
            _ => None,
        },
        Error::MethodError(name, _, _) => match name.as_str() {
            "org.freedesktop.DBus.Error.AccessDenied" | "org.freedesktop.DBus.Error.AuthFailed" => {
                Some(StoreError::Denied)
            }
            "org.freedesktop.DBus.Error.NoReply"
            | "org.freedesktop.DBus.Error.Timeout"
            | "org.freedesktop.DBus.Error.TimedOut" => Some(StoreError::TimedOut),
            "org.freedesktop.DBus.Error.ServiceUnknown"
            | "org.freedesktop.DBus.Error.NameHasNoOwner" => {
                Some(StoreError::Unavailable(UnavailableReason::NoServiceOwner))
            }
            "org.freedesktop.DBus.Error.NoServer"
            | "org.freedesktop.DBus.Error.Disconnected"
            | "org.freedesktop.DBus.Error.BadAddress" => {
                Some(StoreError::Unavailable(UnavailableReason::NoSessionBus))
            }
            "org.freedesktop.Secret.Error.IsLocked" => Some(StoreError::Locked),
            _ => None,
        },
        Error::Address(_) | Error::Handshake(_) => {
            Some(StoreError::Unavailable(UnavailableReason::NoSessionBus))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attributes_are_stable_and_contain_only_constants_and_opaque_slot() {
        let slot = SessionSlot::from_random_bytes([0xa5; 16]);
        let attributes = LinuxSecretService::attributes(&slot);
        assert_eq!(attributes.len(), 4);
        assert_eq!(attributes[oo7::XDG_SCHEMA_ATTRIBUTE], SCHEMA_ATTRIBUTE);
        assert_eq!(attributes["application"], APPLICATION_ATTRIBUTE);
        assert_eq!(attributes["kind"], KIND_ATTRIBUTE);
        assert_eq!(attributes["slot"], "a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5");
        let rendered = format!("{attributes:?}");
        for forbidden in ["@", "apple", "token", "account-id", "email"] {
            assert!(!rendered.to_ascii_lowercase().contains(forbidden));
        }
    }

    #[test]
    fn adapter_debug_exposes_no_backend_objects() {
        assert_eq!(
            format!("{}", StoreError::Denied),
            "Secret Service access was denied"
        );
        assert_eq!(
            format!(
                "{:?}",
                StoreError::Unavailable(UnavailableReason::NoSessionBus)
            ),
            "Unavailable(NoSessionBus)"
        );
    }

    #[test]
    fn oo7_errors_map_to_secret_free_actionable_categories() {
        use oo7::zbus::Error as ZbusError;
        use oo7::zbus::fdo::Error as FdoError;

        assert_eq!(
            classify(Oo7Error::Dismissed, BackendOperation::Read),
            StoreError::PromptDismissed
        );
        assert_eq!(
            classify(
                Oo7Error::Service(ServiceError::IsLocked("sensitive path".to_owned())),
                BackendOperation::Read,
            ),
            StoreError::Locked
        );
        assert_eq!(
            classify(
                Oo7Error::ZBus(ZbusError::FDO(Box::new(FdoError::NameHasNoOwner(
                    "sensitive bus detail".to_owned(),
                )))),
                BackendOperation::Connect,
            ),
            StoreError::Unavailable(UnavailableReason::NoServiceOwner)
        );
        assert_eq!(
            classify(
                Oo7Error::Service(ServiceError::ZBus(ZbusError::FDO(Box::new(
                    FdoError::AccessDenied("sensitive policy detail".to_owned()),
                )))),
                BackendOperation::Read,
            ),
            StoreError::Denied
        );
        assert_eq!(
            classify(Oo7Error::Deleted, BackendOperation::Write),
            StoreError::BackendFailure(BackendOperation::Write)
        );
    }

    #[test]
    fn replacement_updates_the_single_search_match() {
        // SearchItems may return a credential carrying these query
        // attributes plus provider-specific extras.  The one-match branch
        // must update that exact item, while only zero matches may create.
        assert_eq!(replacement_action(0), Ok(ReplacementAction::Create));
        assert_eq!(replacement_action(1), Ok(ReplacementAction::UpdateMatched));
        assert_eq!(replacement_action(2), Err(StoreError::Duplicate));
    }
}
