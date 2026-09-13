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

//! Entry-point rejection without TTY, selector, credential, or Apple access.
use std::process::{Command, Stdio};

#[test]
fn arguments_are_rejected_before_any_input_or_preflight() {
    let mut child = Command::new(env!("CARGO_BIN_EXE_coffer-live-delegate-op"))
        .arg("synthetic-not-a-selector")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    assert_eq!(child.wait().unwrap().code(), Some(2));
}
