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

//! Apple protocol layer for Coffer.
//!
//! This crate is the home of everything that talks to Apple's services:
//! Apple Account authentication and anisette provisioning, the CloudKit
//! transport, Octagon trust, and CKKS key and record handling.  Higher layers
//! of Coffer (the application and service layer, the command-line interface,
//! the GNOME application, and browser integration) consume the typed API this
//! crate exposes; they never reach into protocol internals directly.
//!
//! # Invariants
//!
//! - This crate has no dependency on GTK, libadwaita, or any other graphical
//!   toolkit, and it must remain usable from a process without a graphical
//!   session.  A test harness or command-line tool has to be able to exercise
//!   every protocol path here headlessly.
//! - This crate never performs an operation that can consume an
//!   authentication, two-factor, or escrow-recovery attempt on its own
//!   initiative.  Such operations are driven by an explicit caller action and
//!   are never retried automatically.
//! - Secrets handled here (passwords, tokens, keys, passcodes, recovery
//!   material) must not appear in logs, panics, `Debug` output, or fixtures.
//!
//! # Status
//!
//! The crate is empty apart from this documentation.  Apple Account
//! authentication is the first capability scheduled for it; see the project
//! roadmap for the intended order of work.
#![forbid(unsafe_code)]
