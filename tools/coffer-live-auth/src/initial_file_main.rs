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

//! Explicit initial-only file diagnostic; live execution is never part of CI.
use coffer_live_auth::{
    file_input::FileTerminal,
    initial_diagnostic::{self, DiagnosticError},
    terminal::LineTerminal,
};
use coffer_protocol::auth::diagnostic::InitialOutcome;
use std::{ffi::OsString, path::PathBuf, process::ExitCode};

fn main() -> ExitCode {
    let Some(path) = parse_arguments(std::env::args_os().skip(1)) else {
        eprintln!("coffer-live-auth-initial-file requires only --credentials-file PATH");
        return ExitCode::from(2);
    };
    let terminal = match LineTerminal::open_controlling_tty() {
        Ok(terminal) => terminal,
        Err(_) => {
            eprintln!("initial diagnostic requires a controlling terminal");
            return ExitCode::from(2);
        }
    };
    let mut terminal = FileTerminal::for_initial_diagnostic(terminal, path);
    let result = initial_diagnostic::run(&mut terminal);
    terminal.finish();
    match result {
        Ok(report) => {
            if initial_diagnostic::write_report(&mut std::io::stdout().lock(), &report).is_err() {
                eprintln!("{}", DiagnosticError::Output);
                return ExitCode::FAILURE;
            }
            if report.outcome == InitialOutcome::Failed {
                ExitCode::FAILURE
            } else {
                ExitCode::SUCCESS
            }
        }
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}

fn parse_arguments(mut args: impl Iterator<Item = OsString>) -> Option<PathBuf> {
    if args.next()? != "--credentials-file" {
        return None;
    }
    let path = args.next()?;
    if path.is_empty() || path.as_encoded_bytes().starts_with(b"--") || args.next().is_some() {
        return None;
    }
    Some(path.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn only_one_nonsecret_file_selector_is_accepted() {
        for args in [
            vec![],
            vec!["--password", "sentinel"],
            vec!["--credentials-file"],
            vec!["--credentials-file", ""],
            vec!["--credentials-file", "--password"],
            vec!["--credentials-file", "x", "--new-profile", "y"],
            vec!["--credentials-file", "x", "--credentials-file", "y"],
        ] {
            assert!(parse_arguments(args.into_iter().map(OsString::from)).is_none());
        }
        assert_eq!(
            parse_arguments(
                ["--credentials-file", "synthetic-path"]
                    .into_iter()
                    .map(OsString::from)
            ),
            Some(PathBuf::from("synthetic-path"))
        );
    }
}
