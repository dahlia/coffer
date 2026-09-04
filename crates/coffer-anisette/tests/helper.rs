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

//! Process-level confinement tests for the dedicated helper.

use std::time::Duration;

use coffer_anisette::{HelperClient, ProvisioningStore};
use coffer_bootstrap::BootstrapPaths;

#[test]
fn helper_refuses_to_run_without_verified_network_denial() {
    let client = HelperClient::new(
        env!("CARGO_BIN_EXE_coffer-anisette-helper"),
        Duration::from_secs(2),
    );
    let root = tempfile::tempdir().expect("root");
    let store = ProvisioningStore::from_paths(&BootstrapPaths::rooted_at(root.path()))
        .expect("provisioning store");
    client
        .probe_sandbox(&store)
        .expect("mandatory sandbox applies");
}
