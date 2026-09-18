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

//! Developer-only one-shot 1Password validation, with no Apple or storage calls.
use coffer_live_auth::{
    op_input::{self, ItemSelector},
    terminal::LineTerminal,
};
use std::process::ExitCode;

fn main() -> ExitCode {
    if std::env::args_os().count() != 1 {
        eprintln!("coffer-op-diagnose takes no arguments");
        return ExitCode::from(2);
    }
    let mut terminal = match LineTerminal::open_controlling_tty() {
        Ok(terminal) => terminal,
        Err(_) => {
            eprintln!("coffer-op-diagnose requires a controlling terminal");
            return ExitCode::from(2);
        }
    };
    let selector = match ItemSelector::from_stdin_pipe() {
        Ok(selector) => selector,
        Err(error) => {
            eprintln!("{error}");
            return ExitCode::from(2);
        }
    };
    match op_input::diagnose(&mut terminal, selector) {
        Ok(()) => {
            eprintln!(
                "RESULT: one 1Password fetch passed CSV and account binding validation; credentials discarded; no Apple or storage access"
            );
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!(
                "RESULT: 1Password diagnostic stopped; no automatic retry; no Apple or storage access"
            );
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}
