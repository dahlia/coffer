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

//! Explicit developer-only fresh-login delegate issuance, without arguments.
use coffer_live_auth::{
    delegate_harness,
    terminal::{LineTerminal, SecureTerminal},
};
use std::process::ExitCode;
fn main() -> ExitCode {
    if std::env::args_os().count() != 1 {
        eprintln!("coffer-live-delegate takes no arguments");
        return ExitCode::from(2);
    }
    let mut terminal = match LineTerminal::open_controlling_tty() {
        Ok(terminal) => terminal,
        Err(_) => {
            eprintln!("coffer-live-delegate requires a controlling terminal");
            return ExitCode::from(2);
        }
    };
    match delegate_harness::run(&mut terminal) {
        Ok(outcome) => {
            if terminal.notice(outcome.label()).is_err() {
                eprintln!(
                    "coffer-live-delegate result output interrupted; completed local operations are not rolled back"
                );
                return ExitCode::FAILURE;
            }
            ExitCode::SUCCESS
        }
        Err(error) => {
            // Only fixed stage labels are printed; error sources are never rendered.
            let _ = terminal.notice("RESULT: delegate harness stopped; no automatic retry");
            let (stage, reason) = error.labels();
            let _ = terminal.notice(stage);
            let _ = terminal.notice(reason);
            let _ = terminal.notice(error.retention_label());
            ExitCode::FAILURE
        }
    }
}
