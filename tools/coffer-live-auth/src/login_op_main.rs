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

//! Developer-only 1Password first-login entry point; never invoked by CI.
use coffer_live_auth::{
    first_login,
    op_input::{ItemSelector, OpTerminal},
    slot::SlotState,
    terminal::{LineTerminal, SecureTerminal},
};
use std::process::ExitCode;

fn main() -> ExitCode {
    // The sole argv exception is a non-secret local profile label. Credentials
    // and selector/account frames keep the existing bounded private pipe path.
    let mut args = std::env::args_os().skip(1);
    let profile = match (args.next(), args.next(), args.next()) {
        (Some(flag), Some(label), None) if flag == "--new-profile" => label,
        _ => {
            eprintln!("coffer-live-login-op requires --new-profile and one non-secret local label");
            return ExitCode::from(2);
        }
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
            eprintln!("coffer-live-login-op requires a controlling terminal");
            return ExitCode::from(2);
        }
    };
    let selector = match ItemSelector::from_stdin_pipe() {
        Ok(selector) => selector,
        Err(error) => {
            eprintln!("{}", error.label());
            return ExitCode::from(2);
        }
    };
    let mut terminal = OpTerminal::for_first_login(terminal, selector);
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
