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

//! Bringing local anisette to a usable state, once.
//!
//! The sequence is fixed and every step runs at most once:
//!
//! 1. Ask the provider for one set of headers.  Success means the machine is
//!    already provisioned and nothing else happens.
//! 2. If, and only if, the provider reports
//!    [`CofferAnisetteError::NotProvisioned`], tell the user and ask for an
//!    explicit confirmation typed at the terminal.
//! 3. Run exactly one provisioning attempt through
//!    [`ProvisioningCoordinator::begin`](coffer_anisette::ProvisioningCoordinator::begin)
//!    and
//!    [`provision_once`](coffer_anisette::ProvisioningCoordinator::provision_once).
//! 4. Ask for headers once more to confirm the new generation works.
//!
//! Any other generation failure stops the harness without provisioning, and a
//! provisioning failure stops it without authenticating.  There is no remote
//! anisette provider anywhere in the graph to fall back to.

use core::fmt;
use std::time::Duration;

use coffer_anisette::{
    CofferAnisetteError, CofferAnisetteProvider, ProvisioningErrorKind, ProvisioningStage,
};

use crate::terminal::{SecureTerminal, TerminalError};

/// The word the user must type to authorize the single provisioning attempt.
pub const PROVISION_CONFIRMATION: &str = "provision";

/// What the harness may ask local anisette to do.
pub trait AnisetteReadiness {
    /// Generates one set of headers and discards it.
    ///
    /// # Errors
    ///
    /// Returns the provider's classification; [`CofferAnisetteError::NotProvisioned`]
    /// is the only value that leads to provisioning.
    fn generate_once(&self) -> Result<(), CofferAnisetteError>;

    /// Performs exactly one provisioning attempt.
    ///
    /// # Errors
    ///
    /// Returns the stage and kind of the first failure.
    fn provision_once(&self) -> Result<(), ProvisioningFailure>;
}

/// A provisioning failure reduced to its public, secret-free classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProvisioningFailure {
    /// Stage of the first failure.
    pub stage: ProvisioningStage,
    /// Kind of the first failure.
    pub kind: ProvisioningErrorKind,
}

impl fmt::Display for ProvisioningFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "anisette provisioning failed during {:?} ({:?})",
            self.stage, self.kind
        )
    }
}

/// How local anisette became usable during this run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnisetteVerdict {
    /// Headers were generated from existing provisioning state.
    AlreadyProvisioned,
    /// One explicit provisioning attempt succeeded and headers were then
    /// generated from the new state.
    ProvisionedNow,
}

/// Why local anisette could not be made usable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum AnisetteStageError {
    /// Header generation failed for a reason other than missing provisioning.
    Generate(CofferAnisetteError),
    /// The user did not authorize the provisioning attempt.
    Declined,
    /// The single provisioning attempt failed.
    Provisioning(ProvisioningFailure),
    /// Provisioning reported success but header generation still failed.
    VerificationAfterProvisioning(CofferAnisetteError),
    /// The terminal failed while asking for authorization.
    Terminal(TerminalError),
}

impl fmt::Display for AnisetteStageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Generate(error) => write!(f, "local anisette generation failed: {error}"),
            Self::Declined => f.write_str("provisioning was not authorized; nothing was sent"),
            Self::Provisioning(failure) => write!(f, "{failure}"),
            Self::VerificationAfterProvisioning(error) => write!(
                f,
                "anisette generation still failed after the provisioning attempt: {error}"
            ),
            Self::Terminal(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for AnisetteStageError {}

/// Drives the fixed readiness sequence described in the module docs.
///
/// # Errors
///
/// See [`AnisetteStageError`].  Every failure is terminal for the run.
pub fn ensure_local_anisette<R: AnisetteReadiness, T: SecureTerminal>(
    readiness: &R,
    terminal: &mut T,
) -> Result<AnisetteVerdict, AnisetteStageError> {
    terminal
        .notice("[anisette] generating local anisette headers from existing state")
        .map_err(AnisetteStageError::Terminal)?;
    match readiness.generate_once() {
        Ok(()) => return Ok(AnisetteVerdict::AlreadyProvisioned),
        Err(CofferAnisetteError::NotProvisioned) => {}
        Err(error) => return Err(AnisetteStageError::Generate(error)),
    }
    terminal
        .notice("[anisette] this machine is not provisioned for local anisette")
        .map_err(AnisetteStageError::Terminal)?;
    terminal
        .notice(
            "[anisette] one provisioning attempt would contact Apple's provisioning endpoints \
             and publish a new local generation; it is never retried automatically",
        )
        .map_err(AnisetteStageError::Terminal)?;
    let answer = terminal
        .prompt_visible("Type 'provision' to run exactly one attempt, anything else to stop: ")
        .map_err(AnisetteStageError::Terminal)?;
    if answer.as_str() != PROVISION_CONFIRMATION {
        return Err(AnisetteStageError::Declined);
    }
    terminal
        .notice("[anisette] running the single provisioning attempt")
        .map_err(AnisetteStageError::Terminal)?;
    readiness
        .provision_once()
        .map_err(AnisetteStageError::Provisioning)?;
    terminal
        .notice("[anisette] provisioning published; generating headers once to verify")
        .map_err(AnisetteStageError::Terminal)?;
    readiness
        .generate_once()
        .map_err(AnisetteStageError::VerificationAfterProvisioning)?;
    Ok(AnisetteVerdict::ProvisionedNow)
}

/// The production [`AnisetteReadiness`] over a [`CofferAnisetteProvider`].
///
/// It borrows the provider so that the same instance can later be moved into
/// the authenticator.
pub struct LocalAnisette<'a> {
    provider: &'a CofferAnisetteProvider,
    attempt_deadline: Duration,
}

impl<'a> LocalAnisette<'a> {
    /// Binds a provider and the absolute deadline for one provisioning
    /// attempt.
    #[must_use]
    pub fn new(provider: &'a CofferAnisetteProvider, attempt_deadline: Duration) -> Self {
        Self {
            provider,
            attempt_deadline,
        }
    }
}

impl AnisetteReadiness for LocalAnisette<'_> {
    fn generate_once(&self) -> Result<(), CofferAnisetteError> {
        // The data is dropped, and therefore zeroized, immediately: this
        // call only establishes that generation works.
        futures_lite::future::block_on(self.provider.generate()).map(drop)
    }

    fn provision_once(&self) -> Result<(), ProvisioningFailure> {
        let coordinator = self
            .provider
            .provisioning_coordinator(self.attempt_deadline);
        let request = coordinator.begin();
        futures_lite::future::block_on(coordinator.provision_once(request))
            .map(drop)
            .map_err(|error| ProvisioningFailure {
                stage: error.stage(),
                kind: error.kind(),
            })
    }
}

impl fmt::Debug for LocalAnisette<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("LocalAnisette")
    }
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;

    use coffer_anisette::BridgeError;

    use super::*;
    use crate::terminal::LineTerminal;
    use crate::terminal::tests::FakeDevice;

    struct Scripted {
        generate: RefCell<Vec<Result<(), CofferAnisetteError>>>,
        provision: RefCell<Vec<Result<(), ProvisioningFailure>>>,
        calls: RefCell<Vec<&'static str>>,
    }

    impl Scripted {
        fn new(
            generate: Vec<Result<(), CofferAnisetteError>>,
            provision: Vec<Result<(), ProvisioningFailure>>,
        ) -> Self {
            Self {
                generate: RefCell::new(generate),
                provision: RefCell::new(provision),
                calls: RefCell::new(Vec::new()),
            }
        }

        fn calls(&self) -> Vec<&'static str> {
            self.calls.borrow().clone()
        }
    }

    impl AnisetteReadiness for Scripted {
        fn generate_once(&self) -> Result<(), CofferAnisetteError> {
            self.calls.borrow_mut().push("generate");
            let mut script = self.generate.borrow_mut();
            assert!(
                !script.is_empty(),
                "generate called more often than scripted"
            );
            script.remove(0)
        }

        fn provision_once(&self) -> Result<(), ProvisioningFailure> {
            self.calls.borrow_mut().push("provision");
            let mut script = self.provision.borrow_mut();
            assert!(
                !script.is_empty(),
                "provision called more often than scripted"
            );
            script.remove(0)
        }
    }

    fn failure() -> ProvisioningFailure {
        ProvisioningFailure {
            stage: ProvisioningStage::StartRequest,
            kind: ProvisioningErrorKind::HttpStatus(503),
        }
    }

    #[test]
    fn already_provisioned_needs_no_prompt_and_no_provisioning() {
        let readiness = Scripted::new(vec![Ok(())], vec![]);
        let mut terminal = LineTerminal::new(FakeDevice::new(b""));
        let verdict = ensure_local_anisette(&readiness, &mut terminal).unwrap();
        assert_eq!(verdict, AnisetteVerdict::AlreadyProvisioned);
        assert_eq!(readiness.calls(), vec!["generate"]);
    }

    #[test]
    fn explicit_confirmation_runs_exactly_one_attempt_then_verifies() {
        let readiness = Scripted::new(
            vec![Err(CofferAnisetteError::NotProvisioned), Ok(())],
            vec![Ok(())],
        );
        let mut terminal = LineTerminal::new(FakeDevice::new(b"provision\n"));
        let verdict = ensure_local_anisette(&readiness, &mut terminal).unwrap();
        assert_eq!(verdict, AnisetteVerdict::ProvisionedNow);
        assert_eq!(readiness.calls(), vec!["generate", "provision", "generate"]);
    }

    #[test]
    fn anything_but_the_confirmation_word_stops_before_provisioning() {
        for answer in [&b"yes\n"[..], b"Provision\n", b"provision \n", b"n\n"] {
            let readiness = Scripted::new(vec![Err(CofferAnisetteError::NotProvisioned)], vec![]);
            let mut terminal = LineTerminal::new(FakeDevice::new(answer));
            assert_eq!(
                ensure_local_anisette(&readiness, &mut terminal).unwrap_err(),
                AnisetteStageError::Declined
            );
            assert_eq!(readiness.calls(), vec!["generate"]);
        }
    }

    #[test]
    fn a_closed_terminal_stops_before_provisioning() {
        let readiness = Scripted::new(vec![Err(CofferAnisetteError::NotProvisioned)], vec![]);
        let mut terminal = LineTerminal::new(FakeDevice::new(b""));
        assert_eq!(
            ensure_local_anisette(&readiness, &mut terminal).unwrap_err(),
            AnisetteStageError::Terminal(TerminalError::Closed)
        );
        assert_eq!(readiness.calls(), vec!["generate"]);
    }

    #[test]
    fn a_failed_attempt_is_not_repeated_and_blocks_authentication() {
        let readiness = Scripted::new(
            vec![Err(CofferAnisetteError::NotProvisioned)],
            vec![Err(failure())],
        );
        let mut terminal = LineTerminal::new(FakeDevice::new(b"provision\n"));
        assert_eq!(
            ensure_local_anisette(&readiness, &mut terminal).unwrap_err(),
            AnisetteStageError::Provisioning(failure())
        );
        assert_eq!(readiness.calls(), vec!["generate", "provision"]);
    }

    #[test]
    fn still_unprovisioned_after_success_is_an_error_not_a_second_attempt() {
        let readiness = Scripted::new(
            vec![
                Err(CofferAnisetteError::NotProvisioned),
                Err(CofferAnisetteError::NotProvisioned),
            ],
            vec![Ok(())],
        );
        let mut terminal = LineTerminal::new(FakeDevice::new(b"provision\n"));
        assert_eq!(
            ensure_local_anisette(&readiness, &mut terminal).unwrap_err(),
            AnisetteStageError::VerificationAfterProvisioning(CofferAnisetteError::NotProvisioned)
        );
        assert_eq!(readiness.calls(), vec!["generate", "provision", "generate"]);
    }

    #[test]
    fn other_generation_failures_never_lead_to_provisioning() {
        for error in [
            CofferAnisetteError::IncompatibleState,
            CofferAnisetteError::InvalidIdentifier,
            CofferAnisetteError::Bridge(BridgeError::SandboxUnavailable),
            CofferAnisetteError::WorkerUnavailable,
        ] {
            let readiness = Scripted::new(vec![Err(error)], vec![]);
            let mut terminal = LineTerminal::new(FakeDevice::new(b"provision\n"));
            assert_eq!(
                ensure_local_anisette(&readiness, &mut terminal).unwrap_err(),
                AnisetteStageError::Generate(error)
            );
            assert_eq!(readiness.calls(), vec!["generate"]);
            let output = String::from_utf8(terminal.device().output.clone()).unwrap();
            assert!(!output.contains("Type"));
        }
    }

    #[test]
    fn errors_print_only_classifications() {
        let text = AnisetteStageError::Provisioning(failure()).to_string();
        assert_eq!(
            text,
            "anisette provisioning failed during StartRequest (HttpStatus(503))"
        );
        assert!(
            AnisetteStageError::Declined
                .to_string()
                .contains("nothing was sent")
        );
    }
}
