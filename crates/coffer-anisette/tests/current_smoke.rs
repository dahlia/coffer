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

//! Explicit, ignored, one-shot smoke test for a locally installed image pair.

use std::time::Duration;

use coffer_anisette::{HelperClient, VerifiedLibraryPaths};
use coffer_bootstrap::{AppleCdnSource, Bootstrap, BootstrapPaths};

#[test]
#[ignore = "must be run explicitly exactly once after all offline gates pass"]
fn locally_installed_images_complete_the_sandboxed_offline_smoke() {
    let paths = BootstrapPaths::from_environment().expect("resolve XDG paths");
    let bootstrap = Bootstrap::new(paths, AppleCdnSource::new()).expect("supported host");
    let installed = bootstrap
        .installed()
        .expect("inspect installed libraries without network")
        .expect("verified installation required");
    let libraries = VerifiedLibraryPaths::from_installation(&installed);
    let client = HelperClient::new(
        env!("CARGO_BIN_EXE_coffer-anisette-helper"),
        Duration::from_secs(15),
    );
    let result = client
        .offline_smoke(&libraries)
        .expect("sandboxed offline smoke");
    eprintln!(
        "offline smoke succeeded: provisioned={}, property_classes={:?}",
        result.provisioned, result.property_queries
    );
}
