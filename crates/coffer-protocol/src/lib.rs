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
//! This crate owns Coffer's runtime-neutral Apple protocol logic.  Higher
//! layers of Coffer (the application and service layer, the command-line
//! interface, the GNOME application, and browser integration) consume the
//! typed API this crate exposes; they never reach into protocol internals
//! directly.
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
//! - This crate performs no I/O of its own.  Network exchanges go through the
//!   [`transport::Transport`] trait, anisette data comes from an
//!   [`anisette::AnisetteProvider`], and randomness comes from an
//!   [`entropy::Entropy`] source.  All three are supplied by the caller, which
//!   keeps the protocol logic runtime-neutral and testable offline.
//!
//! # Status
//!
//! The crate currently implements the offline-verifiable core of Apple
//! Account authentication in the [`auth`] module: the GSA (GrandSlam
//! Authentication) SRP password exchange, trusted-device two-factor
//! submission, and the post-two-factor re-authentication that yields a
//! usable session.  Sibling crates provide local anisette generation, the
//! concrete developer-harness transport, and Linux Secret Service storage so
//! those platform concerns do not enter this runtime-neutral protocol layer.
//! Stored-session service-token issuance lives in [`tokens`]. Explicit legacy
//! PET-to-delegate token issuance lives in [`delegate`], with offline fixtures
//! and no live compatibility guarantee. The [`ckks`]
//! module provides offline key unwrapping and bounded key-hierarchy validation
//! using a caller-supplied anchor; it does not establish anchor trust. The
//! [`octagon`] module provides offline P-384 key encodings and ECDSA/SHA-384
//! verification. Its bounded bottle inspector checks embedded-key signature
//! self-consistency over original bytes, not trust, identity, entropy binding,
//! viability or recovery. CloudKit transport, Octagon peer identity and trust, and
//! credential retrieval remain later work.
#![forbid(unsafe_code)]

pub mod anisette;
pub mod auth;
pub mod ckks;
pub mod delegate;
pub mod entropy;
pub mod octagon;
pub mod pki;
pub mod secret;
pub mod transport;

pub mod tokens;
