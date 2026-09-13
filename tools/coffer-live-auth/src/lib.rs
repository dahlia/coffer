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

//! Developer-only harness for one live Apple Account authentication.
//!
//! This crate is the Milestone 1 integration check.  It is not part of the
//! Coffer application and never will be: it exists so that a developer can
//! run, on a machine and account they control, the whole authentication path
//! that the workspace otherwise exercises only against fixtures:
//!
//! 1. runtime bootstrap of the Apple support libraries (`coffer-bootstrap`);
//! 2. local anisette generation with at most one explicit provisioning
//!    attempt (`coffer-anisette`);
//! 3. the GSA SRP password exchange, trusted-device two-factor
//!    verification, and post-two-factor re-authentication
//!    (`coffer-protocol`), over the HTTPS transport in [`transport`];
//! 4. persistence of the reusable session in Linux Secret Service and a
//!    reload over a new connection (`coffer-service`).
//!
//! # Rules the harness enforces
//!
//! - Input comes only from `/dev/tty` ([`terminal`]).  There is no argument,
//!   environment variable, or file that carries the account name, password,
//!   or verification code, and the binary refuses to start with any
//!   argument at all.
//! - Every network step runs once.  A failure ends the run with a static,
//!   stage-labelled error; the user decides whether to run again.
//! - Output consists of string literals.  No account, token, code, header,
//!   body, slot, or path is ever printed.
//! - Nothing here falls back: no remote anisette provider, no plaintext
//!   session file, no proxy, no redirect.
//!
//! The library exists so the pieces are unit-testable with scripted
//! terminals, exchanges, and stores; `src/main.rs` is a few lines over
//! [`harness::run`].  The interactive entry point is `mise run test-live-auth`,
//! which is deliberately absent from `mise run test` and `mise run ci`.
//!
//! # What the success report does and does not claim
//!
//! The M1 Secret Service line reports only that the reusable session
//! round-tripped through the keyring. The separate [`reuse`] harness exercises
//! a stored-session Xcode token exchange after explicit confirmation.  The two-factor lines are reported as verified only
//! on an account that actually required a trusted-device code during the run.

#![forbid(unsafe_code)]

pub mod anisette;
pub mod delegate_transport;
pub mod entropy;
pub mod flow;
pub mod harness;
pub mod reuse;
pub mod slot;
pub mod store;
pub mod terminal;
pub mod transport;

/// Refuses to run when any command-line argument is present.
///
/// The harness has no options.  Rejecting arguments outright makes it
/// impossible for a secret to arrive through the command line by mistake, and
/// keeps it out of shell history.  `argument_count` is the length of
/// `std::env::args_os()`, which includes the program name.
pub fn reject_arguments(argument_count: usize) -> Result<(), &'static str> {
    if argument_count > 1 {
        Err(
            "coffer-live-auth takes no arguments; the account name, password, and code are \
             read from the terminal only",
        )
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn any_argument_is_refused() {
        assert!(reject_arguments(0).is_ok());
        assert!(reject_arguments(1).is_ok());
        assert!(reject_arguments(2).is_err());
        assert!(reject_arguments(9).is_err());
    }

    /// No production module may read the process arguments or a variable
    /// that could carry a credential.  The XDG variables are the only ones the
    /// harness consults, through `slot` and `coffer-bootstrap`; the one
    /// `COFFER_LIVE_AUTH_TEST_`-prefixed variable is read by a test-only child
    /// role and carries a pseudo-terminal path.
    #[test]
    fn no_secret_reaches_the_process_from_arguments_or_environment() {
        let sources = [
            ("anisette.rs", include_str!("anisette.rs")),
            ("entropy.rs", include_str!("entropy.rs")),
            ("flow.rs", include_str!("flow.rs")),
            ("harness.rs", include_str!("harness.rs")),
            ("main.rs", include_str!("main.rs")),
            ("token_main.rs", include_str!("token_main.rs")),
            ("reuse.rs", include_str!("reuse.rs")),
            ("slot.rs", include_str!("slot.rs")),
            ("store.rs", include_str!("store.rs")),
            ("terminal.rs", include_str!("terminal.rs")),
            ("transport.rs", include_str!("transport.rs")),
        ];
        for (name, source) in sources {
            for forbidden in [
                "env::args(",
                "args_os().nth",
                "env::var(\"",
                "var_os(\"PASS",
                "io::stdin(",
            ] {
                assert!(
                    !source.contains(forbidden),
                    "{name} must not contain {forbidden:?}"
                );
            }
            let env_reads: Vec<&str> = source
                .match_indices("var_os(\"")
                .map(|(index, _)| &source[index + 8..index + 8 + 20])
                .collect();
            for read in env_reads {
                assert!(
                    read.starts_with("XDG_STATE_HOME")
                        || read.starts_with("HOME\"")
                        || read.starts_with("COFFER_LIVE_AUTH_TEST_"),
                    "{name} reads an unexpected environment variable"
                );
            }
        }
    }
}
