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

#[test]
fn first_login_refuses_missing_extra_or_private_arguments_before_tty_or_state() {
    for args in [
        vec![],
        vec!["--new-profile"],
        vec!["--new-profile", "../escape"],
        vec!["--new-profile", "synthetic@example.invalid"],
        vec!["--new-profile", "UPPERCASE"],
        vec!["--new-profile", ""],
        vec!["--new-profile", "synthetic", "extra"],
        vec!["--profile", "synthetic"],
    ] {
        let root = tempfile::tempdir().unwrap();
        let output = Command::new(env!("CARGO_BIN_EXE_coffer-live-login-op"))
            .args(args)
            .env("XDG_STATE_HOME", root.path())
            .stdin(Stdio::null())
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(2));
        assert!(!String::from_utf8_lossy(&output.stderr).contains("synthetic"));
        assert_eq!(std::fs::read_dir(root.path()).unwrap().count(), 0);
    }
}
