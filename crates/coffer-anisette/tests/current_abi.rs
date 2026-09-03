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

//! Explicit, ignored validation for locally installed proprietary images.

use std::path::PathBuf;

use coffer_anisette::abi::{LibraryKind, validate_image};
use coffer_bootstrap::Architecture;

#[test]
#[ignore = "requires an explicit local support-library root; never runs in CI"]
fn locally_installed_images_match_the_reviewed_policy() {
    let root = PathBuf::from(
        std::env::var_os("COFFER_ANISETTE_LIBRARY_ROOT").expect("explicit library root"),
    );
    let architecture = Architecture::host().expect("supported host");
    let directory = root.join("lib").join(architecture.android_abi());
    for (basename, kind) in [
        ("libCoreADI.so", LibraryKind::CoreAdi),
        ("libstoreservicescore.so", LibraryKind::StoreServicesCore),
    ] {
        let bytes = std::fs::read(directory.join(basename)).expect("read local image");
        validate_image(&bytes, architecture, kind)
            .unwrap_or_else(|error| panic!("{basename}: {error:?}"));
    }
}
