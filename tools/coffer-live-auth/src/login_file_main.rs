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

//! Developer-only file-input first-login entry point; never invoked by CI.
use coffer_live_auth::{
    file_input::FileTerminal,
    first_login,
    slot::SlotState,
    terminal::{LineTerminal, SecureTerminal},
};
use std::process::ExitCode;

fn main() -> ExitCode {
    let Some((path, profile)) = parse_arguments(std::env::args_os().skip(1)) else {
        eprintln!(
            "coffer-live-login-file requires --credentials-file PATH and --new-profile LABEL"
        );
        return ExitCode::from(2);
    };
    let Some(profile) = profile.to_str() else {
        eprintln!("new profile label rejected");
        return ExitCode::from(2);
    };
    if SlotState::under_state_home(std::path::Path::new("/"))
        .new_profile(profile)
        .is_err()
    {
        eprintln!("new profile label rejected");
        return ExitCode::from(2);
    }
    let terminal = match LineTerminal::open_controlling_tty() {
        Ok(terminal) => terminal,
        Err(_) => {
            eprintln!("coffer-live-login-file requires a controlling terminal");
            return ExitCode::from(2);
        }
    };
    let mut terminal = FileTerminal::new(terminal, path.into());
    let result = first_login::run(&mut terminal, profile);
    terminal.finish();
    match result {
        Ok(()) => {
            if terminal.notice("RESULT: first GSA login and new-profile session round trip completed; token reuse unverified").is_err() {
                eprintln!("result output interrupted; session storage is not rolled back");
                return ExitCode::FAILURE;
            }
            ExitCode::SUCCESS
        }
        Err(error) => {
            let _ = terminal.notice("RESULT: first login stopped; no automatic retry");
            let (stage, cause) = error.labels();
            let _ = terminal.notice(stage);
            let _ = terminal.notice(cause);
            let _ = terminal.notice(error.retention_label());
            ExitCode::FAILURE
        }
    }
}

// Paths and labels are non-secret selectors; values never enter diagnostics.
fn parse_arguments(
    args: impl Iterator<Item = std::ffi::OsString>,
) -> Option<(std::ffi::OsString, std::ffi::OsString)> {
    let mut path = None;
    let mut profile = None;
    let mut args = args;
    while let Some(flag) = args.next() {
        let target = if flag == "--credentials-file" {
            &mut path
        } else if flag == "--new-profile" {
            &mut profile
        } else {
            return None;
        };
        if target.is_some() {
            return None;
        }
        let value = args.next()?;
        if value.is_empty() || value.as_encoded_bytes().starts_with(b"--") {
            return None;
        }
        *target = Some(value);
    }
    Some((path?, profile?))
}
