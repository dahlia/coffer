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

//! Developer-only selector-pipe entry point for one confirmed delegate run.
use coffer_live_auth::{
    delegate_harness,
    op_input::{ItemSelector, OpTerminal},
    terminal::{LineTerminal, SecureTerminal},
};
use std::process::ExitCode;

fn main() -> ExitCode {
    if std::env::args_os().count() != 1 {
        eprintln!("coffer-live-delegate-op takes no arguments");
        return ExitCode::from(2);
    }
    let terminal = match LineTerminal::open_controlling_tty() {
        Ok(terminal) => terminal,
        Err(_) => {
            eprintln!("coffer-live-delegate-op requires a controlling terminal");
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
    let mut terminal = OpTerminal::new(terminal, selector);
    let result = delegate_harness::run(&mut terminal);
    terminal.finish();
    match result {
        Ok(outcome) => {
            if terminal.notice(outcome.label()).is_err() {
                eprintln!(
                    "coffer-live-delegate-op result output interrupted; completed local operations are not rolled back"
                );
                return ExitCode::FAILURE;
            }
            ExitCode::SUCCESS
        }
        Err(error) => {
            let _ = terminal.notice("RESULT: delegate harness stopped; no automatic retry");
            let (stage, reason) = error.labels();
            let _ = terminal.notice(stage);
            let _ = terminal.notice(reason);
            let _ = terminal.notice(error.retention_label());
            ExitCode::FAILURE
        }
    }
}
