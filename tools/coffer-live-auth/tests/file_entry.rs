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

//! CLI rejection tests use only synthetic selectors and never reach preflight.
use std::process::{Command, Stdio};
#[test]
fn rejects_missing_duplicate_unknown_private_and_invalid_arguments() {
    for args in [
        vec![],
        vec!["--credentials-file"],
        vec!["--new-profile", "test"],
        vec!["--credentials-file", "synthetic-file"],
        vec!["--credentials-file", "", "--new-profile", "test"],
        vec![
            "--credentials-file",
            "synthetic-file",
            "--new-profile",
            "../escape",
        ],
        vec![
            "--credentials-file",
            "synthetic-file",
            "--new-profile",
            "synthetic@example.invalid",
        ],
        vec![
            "--credentials-file",
            "synthetic-file",
            "--new-profile",
            "test",
            "extra",
        ],
        vec![
            "--credentials-file",
            "synthetic-file",
            "--new-profile",
            "test",
            "--new-profile",
            "other",
        ],
        vec![
            "--credentials-file",
            "one",
            "--credentials-file",
            "two",
            "--new-profile",
            "test",
        ],
        vec!["--password", "synthetic-secret", "--new-profile", "test"],
        vec!["--credentials-file", "--new-profile", "test"],
    ] {
        let dir = tempfile::tempdir().unwrap();
        let output = Command::new(env!("CARGO_BIN_EXE_coffer-live-login-file"))
            .args(args)
            .env("XDG_STATE_HOME", dir.path())
            .stdin(Stdio::null())
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stdout.is_empty());
        assert!(!String::from_utf8_lossy(&output.stderr).contains("synthetic"));
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
    }
}
#[test]
fn existing_entries_still_reject_file_option() {
    for binary in [
        env!("CARGO_BIN_EXE_coffer-live-auth"),
        env!("CARGO_BIN_EXE_coffer-live-token"),
        env!("CARGO_BIN_EXE_coffer-live-delegate"),
        env!("CARGO_BIN_EXE_coffer-live-login-op"),
    ] {
        let output = Command::new(binary)
            .args(["--credentials-file", "synthetic-file"])
            .stdin(Stdio::null())
            .output()
            .unwrap();
        assert!(!output.status.success());
        assert!(!String::from_utf8_lossy(&output.stderr).contains("synthetic-file"));
    }
}
