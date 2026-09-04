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

//! Entry point: no arguments, a controlling terminal, one run.

use std::process::ExitCode;

use coffer_live_auth::harness;
use coffer_live_auth::terminal::{LineTerminal, SecureTerminal};

fn main() -> ExitCode {
    if let Err(message) = coffer_live_auth::reject_arguments(std::env::args_os().count()) {
        eprintln!("{message}");
        return ExitCode::from(2);
    }
    let mut terminal = match LineTerminal::open_controlling_tty() {
        Ok(terminal) => terminal,
        Err(error) => {
            eprintln!("coffer-live-auth: {}", error.label());
            return ExitCode::from(2);
        }
    };
    match harness::run(&mut terminal) {
        Ok(report) => {
            let _ = terminal.notice("");
            let _ = terminal.notice("RESULT: live authentication harness succeeded");
            for line in report.lines() {
                let _ = terminal.notice(line);
            }
            ExitCode::SUCCESS
        }
        Err(error) => {
            // Both labels are string literals selected by variant; see
            // `HarnessError::labels`.  Nothing formatted at runtime is printed.
            let (stage, kind) = error.labels();
            let _ = terminal.notice("");
            let _ = terminal.notice("RESULT: live authentication harness stopped");
            let _ = terminal.notice("stage:");
            let _ = terminal.notice(stage);
            let _ = terminal.notice("cause:");
            let _ = terminal.notice(kind);
            ExitCode::FAILURE
        }
    }
}
