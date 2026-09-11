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

//! Explicit developer-only existing-session token issuance, without arguments.
use coffer_live_auth::{
    reuse,
    terminal::{LineTerminal, SecureTerminal},
};
use std::process::ExitCode;
fn main() -> ExitCode {
    if std::env::args_os().count() != 1 {
        eprintln!("coffer-live-token takes no arguments");
        return ExitCode::from(2);
    }
    let mut terminal = match LineTerminal::open_controlling_tty() {
        Ok(terminal) => terminal,
        Err(_) => {
            eprintln!("coffer-live-token requires a controlling terminal");
            return ExitCode::from(2);
        }
    };
    match reuse::run(&mut terminal) {
        Ok(()) => {
            let _ = terminal.notice("RESULT: stored GSA session issued one authenticated, unexpired Xcode token; token discarded");
            ExitCode::SUCCESS
        }
        Err(error) => {
            // ReuseError contains fixed classifications only, no backend text.
            eprintln!("coffer-live-token stopped: {error}");
            ExitCode::FAILURE
        }
    }
}
