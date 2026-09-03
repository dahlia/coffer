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

//! Application services and Linux platform integration for Coffer.
//!
//! This crate sits above `coffer-protocol`.  It owns platform facilities that
//! the protocol layer must not know about, beginning with durable storage of
//! reusable authentication material in Linux Secret Service.
//!
//! # Secret storage boundary
//!
//! [`SessionStore`] is the project-owned port.  [`LinuxSecretService`] is its
//! production adapter and connects only through `oo7::dbus::Service` using an
//! encrypted D-Bus session.  It never invokes oo7's automatic backend chooser
//! and has no plaintext, regular-file, or portal fallback.  Tests use
//! [`FakeSessionStore`], whose contents and failures are wholly deterministic.
//!
//! # Build requirement
//!
//! The Linux adapter uses oo7's OpenSSL crypto backend because oo7 0.6.0's
//! native backend releases an unwiped plaintext decrypt buffer.  Building this
//! crate therefore requires OpenSSL development headers discoverable through
//! `pkg-config` (for example, the `openssl-devel` or `libssl-dev` system
//! package).  This system library cannot be installed through mise.
#![forbid(unsafe_code)]

mod codec;
mod fake;
mod secret_service;
mod store;

pub use fake::{FakeOperation, FakeOutcome, FakeSessionStore};
pub use secret_service::LinuxSecretService;
pub use store::{
    BackendOperation, DeleteFailure, DeleteOutcome, MAX_STORED_SESSION_BYTES, ReusableSession,
    SESSION_SLOT_LEN, SessionSlot, SessionStore, StoreError, UnavailableReason,
};
