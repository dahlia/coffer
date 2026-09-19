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

//! Invalid CLI invocations stop before opening a terminal or credential file.
#[test]
fn invalid_arguments_never_echo_input_or_start_the_runner() {
    for args in [
        vec![],
        vec!["--password", "SyntheticPrivateSentinel"],
        vec!["--credentials-file"],
        vec![
            "--credentials-file",
            "synthetic-path",
            "--new-profile",
            "SyntheticPrivateSentinel",
        ],
    ] {
        let result =
            std::process::Command::new(env!("CARGO_BIN_EXE_coffer-live-auth-initial-file"))
                .args(args)
                .stdin(std::process::Stdio::null())
                .output()
                .unwrap();
        assert_eq!(result.status.code(), Some(2));
        assert!(result.stdout.is_empty());
        assert_eq!(
            String::from_utf8(result.stderr).unwrap(),
            "coffer-live-auth-initial-file requires only --credentials-file PATH\n"
        );
    }
}
