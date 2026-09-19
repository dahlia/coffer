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

//! Offline Octagon serialization and signature-verification primitives.
//!
//! These types do not implement peer identity, trust, bottle recovery, or any
//! network/session/storage operation. Successful cryptographic verification
//! establishes no account or peer binding; callers must establish that separately.
//! See `OCTAGON_KEYS.md` and `OCTAGON_BOTTLE.md` at the crate root for provenance,
//! dependency rationale and the deliberate offline scope.

pub mod bottle;
pub mod keys;
