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

#[test]
fn diagnostic_rejects_arguments_before_tty_or_credential_access() {
    let output = Command::new(env!("CARGO_BIN_EXE_coffer-op-diagnose"))
        .arg("synthetic-private")
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert_eq!(output.stderr, b"coffer-op-diagnose takes no arguments\n");
}

#[test]
fn diagnostic_entry_has_no_apple_storage_or_anisette_path() {
    // Pin the production composition alongside behavior tests of the generic
    // diagnostic function. No test invokes the real lookup or a real account.
    let source = include_str!("../src/op_diagnose_main.rs");
    assert!(source.contains("op_input::diagnose(&mut terminal, selector)"));
    for forbidden in [
        "run_login",
        "first_login",
        "delegate_harness",
        "SlotState",
        "SessionStore",
        "Anisette",
        "Bootstrap",
        "Transport",
        "Command::",
    ] {
        assert!(!source.contains(forbidden));
    }
    let input = include_str!("../src/op_input.rs");
    assert!(input.contains("diagnose_with_loader(terminal, selector, fetch)"));
    let body = input
        .split("fn diagnose_with_loader(")
        .nth(1)
        .unwrap()
        .split("fn validate_binding(")
        .next()
        .unwrap();
    for forbidden in [
        "run_login",
        "store::",
        "anisette::",
        "transport::",
        "harness::",
        "Command::",
        "fetch(",
    ] {
        assert!(!body.contains(forbidden));
    }
}
