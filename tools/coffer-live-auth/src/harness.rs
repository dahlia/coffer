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

//! The end-to-end run: wiring the production adapters together in a fixed
//! order and rendering the static report.
//!
//! # Order of stages
//!
//! 1. Profile slot state under `XDG_STATE_HOME` (fails closed on corruption).
//! 2. Secret Service availability, checked before any Apple attempt so that
//!    a missing keyring never costs an authentication.
//! 3. Runtime bootstrap of the Apple support libraries through
//!    [`Bootstrap::ensure`], reusing a verified install or downloading once
//!    from Apple's pinned URL.
//! 4. Local anisette readiness, with at most one explicit provisioning
//!    attempt.
//! 5. The authentication flow, one attempt per step.
//! 6. Secret Service write and reload over a new connection.
//!
//! Every stage label printed along the way is a string literal; the final
//! report is a fixed set of lines chosen by the verdicts.

use core::fmt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use coffer_anisette::{
    AnisetteContext, BridgeError, CofferAnisetteError, CofferAnisetteProvider,
    MalformedResponseReason, ProvisioningErrorKind, ProvisioningStage, Stage as BridgeStage,
};
use coffer_bootstrap::{
    AppleCdnSource, Bootstrap, BootstrapError, BootstrapPaths, Stage as BootstrapStage,
};
use coffer_protocol::auth::{AuthError, AuthErrorKind, AuthStage, Authenticator};
use coffer_protocol::transport::TransportError;
use coffer_service::{BackendOperation, ReusableSession, StoreError, UnavailableReason};
use futures_lite::future::block_on;

use crate::anisette::{AnisetteStageError, AnisetteVerdict, LocalAnisette, ensure_local_anisette};
use crate::entropy::OsEntropy;
use crate::flow::{FlowError, SecondFactorPath, run_login};
use crate::slot::{SlotOrigin, SlotState, SlotStateError};
use crate::store::{
    PersistError, SecretServiceConnector, check_keyring_available, persist_and_reload,
};
use crate::terminal::{SecureTerminal, TerminalError};
use crate::transport::{Deadlines, GsaTransport};

/// File name of the sandboxed helper built from `coffer-anisette`.
pub const HELPER_EXECUTABLE: &str = "coffer-anisette-helper";

/// Upper bound on one helper invocation.
const HELPER_TIMEOUT: Duration = Duration::from_secs(60);
/// Absolute deadline for the single provisioning attempt.
const PROVISIONING_DEADLINE: Duration = Duration::from_secs(180);
/// Upper bound on one GSA exchange.
const EXCHANGE_TIMEOUT: Duration = Duration::from_secs(60);
/// Budget for every GSA exchange of the run, including the time the user
/// spends typing between them.
const RUN_DEADLINE: Duration = Duration::from_secs(20 * 60);
/// Public anisette context.  Both values are plain and consistent between
/// the header and the `cpd` dictionary.
const TIME_ZONE: &str = "UTC";
const LOCALE: &str = "en_US";

/// Why the run stopped, with the stage it stopped in.
#[derive(Debug)]
#[non_exhaustive]
pub enum HarnessError {
    /// The terminal failed.
    Terminal(TerminalError),
    /// The profile slot state was unusable.
    SlotState(SlotStateError),
    /// Secret Service was unavailable before authentication started.
    KeyringUnavailable(StoreError),
    /// The support-library bootstrap failed.
    Bootstrap(BootstrapError),
    /// The helper executable was not found beside the harness.
    HelperMissing,
    /// The local anisette provider could not be opened.
    AnisetteOpen(CofferAnisetteError),
    /// Local anisette could not be made ready.
    Anisette(AnisetteStageError),
    /// The authentication flow stopped.
    Flow(FlowError<AuthError>),
    /// The Secret Service round trip failed after authentication.
    Persist(PersistError),
}

impl fmt::Display for HarnessError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Terminal(error) => write!(f, "terminal: {error}"),
            Self::SlotState(error) => write!(f, "profile slot state: {error}"),
            Self::KeyringUnavailable(error) => {
                write!(
                    f,
                    "Secret Service is not usable, nothing was attempted: {error}"
                )
            }
            Self::Bootstrap(error) => write!(f, "support-library bootstrap: {error}"),
            Self::HelperMissing => write!(
                f,
                "the {HELPER_EXECUTABLE} executable is not beside the harness; \
                 run through `mise run test-live-auth` so both are built together"
            ),
            Self::AnisetteOpen(error) => write!(f, "opening local anisette: {error}"),
            Self::Anisette(error) => write!(f, "local anisette: {error}"),
            Self::Flow(error) => write!(f, "authentication: {error}"),
            Self::Persist(error) => write!(f, "session persistence: {error}"),
        }
    }
}

impl std::error::Error for HarnessError {}

impl HarnessError {
    /// The stage and the kind of the failure as two string literals.
    ///
    /// This is what the binary prints.  Every arm below is a literal chosen
    /// by matching on enum variants; no number, server-supplied text, path,
    /// or other runtime value is ever interpolated, so the output cannot
    /// carry an account, token, code, header, body, slot, or path.
    #[must_use]
    pub fn labels(&self) -> (&'static str, &'static str) {
        match self {
            Self::Terminal(error) => ("terminal", error.label()),
            Self::SlotState(error) => ("profile slot state", error.label()),
            Self::KeyringUnavailable(error) => (
                "Secret Service availability (nothing was attempted)",
                store_label(error),
            ),
            Self::Bootstrap(error) => {
                (bootstrap_stage_label(error.stage()), bootstrap_label(error))
            }
            Self::HelperMissing => (
                "locating the anisette helper",
                "coffer-anisette-helper is not beside the harness; run through `mise run \
                 test-live-auth` so both are built together",
            ),
            Self::AnisetteOpen(error) => ("opening local anisette", anisette_label(*error)),
            Self::Anisette(stage) => match stage {
                AnisetteStageError::Generate(error) => {
                    ("local anisette generation", anisette_label(*error))
                }
                AnisetteStageError::Declined => (
                    "local anisette provisioning",
                    "not authorized at the prompt; nothing was sent",
                ),
                AnisetteStageError::Provisioning(failure) => (
                    provisioning_stage_label(failure.stage),
                    provisioning_kind_label(failure.kind),
                ),
                AnisetteStageError::VerificationAfterProvisioning(error) => (
                    "anisette generation after the provisioning attempt",
                    anisette_label(*error),
                ),
                AnisetteStageError::Terminal(error) => ("terminal", error.label()),
            },
            Self::Flow(flow) => match flow {
                FlowError::Terminal(error) => ("terminal", error.label()),
                FlowError::InvalidAccountName(_) => {
                    ("account name", "rejected locally; nothing was sent")
                }
                FlowError::InvalidCode(_) => (
                    "verification code",
                    "not six ASCII digits; the code was not submitted",
                ),
                FlowError::Auth(error) => (
                    auth_stage_label(error.stage()),
                    auth_kind_label(error.kind()),
                ),
                FlowError::UnsupportedStep => (
                    "secondary authentication",
                    "the server requires a step other than a trusted-device code; stopped",
                ),
            },
            Self::Persist(persist) => match persist {
                PersistError::Store(error) => ("session persistence", store_label(error)),
                PersistError::MissingAfterWrite => (
                    "session persistence",
                    "written, but a new connection could not find the item",
                ),
                PersistError::Mismatch => (
                    "session persistence",
                    "the reloaded session does not match what was written",
                ),
                PersistError::Terminal(error) => ("terminal", error.label()),
            },
        }
    }
}

fn store_label(error: &StoreError) -> &'static str {
    match error {
        StoreError::Unavailable(reason) => match reason {
            UnavailableReason::NoSessionBus => "Secret Service unavailable: no session bus",
            UnavailableReason::NoServiceOwner => "Secret Service unavailable: no service owner",
            UnavailableReason::NoDefaultCollection => {
                "Secret Service unavailable: no default collection"
            }
            _ => "Secret Service unavailable",
        },
        StoreError::Locked => "Secret Service collection is locked",
        StoreError::Denied => "Secret Service access was denied",
        StoreError::PromptDismissed => "the Secret Service prompt was dismissed",
        StoreError::TimedOut => "the Secret Service operation timed out",
        StoreError::Duplicate => "more than one Secret Service item matches the slot",
        StoreError::Corrupt => "the stored session is corrupt",
        StoreError::TooLarge => "the stored session exceeds the size limit",
        StoreError::UnsupportedVersion(_) => "the stored session uses an unsupported version",
        StoreError::EncodingFailed => "the session could not be encoded",
        StoreError::BackendFailure(operation) => match operation {
            BackendOperation::Connect => "Secret Service failed during connection",
            BackendOperation::Search => "Secret Service failed during lookup",
            BackendOperation::Read => "Secret Service failed during read",
            BackendOperation::Write => "Secret Service failed during write",
            BackendOperation::Delete => "Secret Service failed during delete",
            _ => "Secret Service failed",
        },
        StoreError::PartialDelete { .. } => "Secret Service deleted only some matching items",
        _ => "Secret Service failed",
    }
}

fn bootstrap_stage_label(stage: BootstrapStage) -> &'static str {
    match stage {
        BootstrapStage::Preparing => "support-library bootstrap: preparing",
        BootstrapStage::Locking => "support-library bootstrap: locking",
        BootstrapStage::LoadingInstallation => "support-library bootstrap: loading installation",
        BootstrapStage::Downloading => "support-library bootstrap: downloading",
        BootstrapStage::VerifyingSignature => "support-library bootstrap: verifying signature",
        BootstrapStage::ReadingArchive => "support-library bootstrap: reading archive",
        BootstrapStage::Staging => "support-library bootstrap: staging",
        BootstrapStage::Publishing => "support-library bootstrap: publishing",
        _ => "support-library bootstrap",
    }
}

fn bootstrap_label(error: &BootstrapError) -> &'static str {
    match error {
        BootstrapError::UnsupportedArchitecture(_) => "the host architecture is unsupported",
        BootstrapError::PathResolution(_) => "the XDG directories could not be resolved",
        BootstrapError::Busy => "another process holds the bootstrap lock",
        BootstrapError::Fetch(_) => "the archive could not be fetched from Apple",
        BootstrapError::ArchiveTooLarge { .. } => "the archive exceeds the size bound",
        BootstrapError::ArchiveLengthMismatch { .. } => {
            "the archive length did not match the declared length"
        }
        BootstrapError::Signature(_) => "the APK signature or pinned signer did not verify",
        BootstrapError::Archive(_) => "the archive structure was rejected",
        BootstrapError::Library { .. } => "an extracted library was rejected",
        BootstrapError::NoInstallationAvailable { .. } => {
            "no verified installation exists and none could be fetched"
        }
        BootstrapError::UnsafeLayout { .. } => "the XDG layout is unsafe for bootstrap",
        BootstrapError::Io { .. } => "a filesystem operation failed",
        _ => "bootstrap failed",
    }
}

fn anisette_label(error: CofferAnisetteError) -> &'static str {
    match error {
        CofferAnisetteError::NotProvisioned => "local anisette is not provisioned",
        CofferAnisetteError::InvalidContext => "the public anisette context is invalid",
        CofferAnisetteError::InvalidTime => "the client time is invalid",
        CofferAnisetteError::InvalidIdentifier => "the persisted identifier is invalid",
        CofferAnisetteError::IncompatibleState => {
            "anisette state needs an explicit migration or reprovisioning decision"
        }
        CofferAnisetteError::Bridge(error) => bridge_label(error),
        CofferAnisetteError::WorkerUnavailable => "the anisette worker is unavailable",
        _ => "local anisette failed",
    }
}

fn bridge_label(error: BridgeError) -> &'static str {
    match error.stage() {
        BridgeStage::Ipc => "anisette helper failed during framing",
        BridgeStage::Paths => "anisette helper failed while resolving the installation",
        BridgeStage::Abi => "anisette helper rejected the library ABI",
        BridgeStage::Sandbox => "anisette helper could not install its sandbox",
        BridgeStage::Loader => "anisette helper could not map a library",
        BridgeStage::Bind => "anisette helper could not bind an export",
        BridgeStage::LoadCoreAdi => "anisette helper could not load CoreADI",
        BridgeStage::SetProvisioningPath => "anisette helper could not set the provisioning path",
        BridgeStage::SetAndroidId => "anisette helper could not set the Android identifier",
        BridgeStage::QueryProvisioned => "anisette helper could not query provisioned state",
        BridgeStage::StartProvisioning => "anisette helper could not start provisioning",
        BridgeStage::EndProvisioning => "anisette helper could not end provisioning",
        BridgeStage::DestroyProvisioning => "anisette helper could not destroy a session",
        BridgeStage::Otp => "anisette helper could not generate a one-time password",
        BridgeStage::Synchronize => "anisette helper could not synchronize",
        BridgeStage::EraseProvisioning => "anisette helper could not erase provisioning",
        BridgeStage::State => "anisette provisioning state is missing, corrupt, or incompatible",
        BridgeStage::Process => "anisette helper process failed, crashed, or timed out",
        _ => "anisette helper failed",
    }
}

fn provisioning_stage_label(stage: ProvisioningStage) -> &'static str {
    match stage {
        ProvisioningStage::Lookup => "anisette provisioning: lookup",
        ProvisioningStage::StartRequest => "anisette provisioning: start request",
        ProvisioningStage::NativeStart => "anisette provisioning: native start",
        ProvisioningStage::FinishRequest => "anisette provisioning: finish request",
        ProvisioningStage::NativeEnd => "anisette provisioning: native end",
        ProvisioningStage::Cleanup => "anisette provisioning: cleanup",
        ProvisioningStage::Cancelled => "anisette provisioning: cancelled",
        _ => "anisette provisioning",
    }
}

fn provisioning_kind_label(kind: ProvisioningErrorKind) -> &'static str {
    match kind {
        ProvisioningErrorKind::Transport => "transport failed or the deadline passed",
        ProvisioningErrorKind::Tls => "TLS handshake or certificate verification failed",
        ProvisioningErrorKind::Redirect => "the endpoint answered with a redirect; refused",
        ProvisioningErrorKind::AuthenticationChallenge => {
            "the endpoint answered with an authentication challenge; refused"
        }
        ProvisioningErrorKind::HttpStatus(status) => http_status_label(status),
        ProvisioningErrorKind::ContentType => "the response content type was wrong",
        ProvisioningErrorKind::MalformedResponse(reason) => malformed_response_label(reason),
        ProvisioningErrorKind::ProtocolStatus(_) => "the server reported a protocol error",
        ProvisioningErrorKind::Native(error) => bridge_label(error),
        ProvisioningErrorKind::Cancelled => "the attempt was cancelled",
        ProvisioningErrorKind::WorkerUnavailable => "the worker could not be started",
        ProvisioningErrorKind::InvalidContext => "the provisioning header context is invalid",
        _ => "provisioning failed",
    }
}

fn malformed_response_label(reason: MalformedResponseReason) -> &'static str {
    match reason {
        MalformedResponseReason::Endpoint => "the response endpoint was not allowlisted",
        MalformedResponseReason::BodySize => "the response body was empty or oversized",
        MalformedResponseReason::XmlSyntax => "the response XML syntax was invalid",
        MalformedResponseReason::XmlDeclaration => {
            "the response XML declaration was duplicated or misplaced"
        }
        MalformedResponseReason::XmlDoctype => "the response plist doctype was not canonical",
        MalformedResponseReason::XmlMarkup => "the response XML markup was unsupported",
        MalformedResponseReason::XmlAttribute => "the response plist attributes were unsupported",
        MalformedResponseReason::XmlDepth => "the response XML was nested too deeply",
        MalformedResponseReason::XmlFieldLimit => "the response exceeded the plist field bound",
        MalformedResponseReason::XmlNodeLimit => "the response exceeded the plist node bound",
        MalformedResponseReason::DictionaryKey => {
            "the response contained an invalid dictionary key"
        }
        MalformedResponseReason::DictionaryType => "the response required a dictionary value",
        MalformedResponseReason::MissingField => "the response omitted a required field",
        MalformedResponseReason::FieldType => "the response field had the wrong type",
        MalformedResponseReason::MissingStatus => "the response omitted protocol status",
        MalformedResponseReason::StatusType => "the response protocol status was malformed",
        MalformedResponseReason::MissingSecret => "the response omitted a required secret",
        MalformedResponseReason::SecretType => "the response secret had the wrong type",
        MalformedResponseReason::SecretEncoding => "the response secret encoding was invalid",
        MalformedResponseReason::SecretSize => "the response secret exceeded its size bound",
        _ => "the response was malformed or oversized",
    }
}

fn http_status_label(status: u16) -> &'static str {
    match status {
        100..=199 => "the server answered with a 1xx status",
        200..=299 => "the server answered with an unexpected 2xx status",
        300..=399 => "the server answered with a 3xx status; refused",
        400..=499 => "the server answered with a 4xx status",
        500..=599 => "the server answered with a 5xx status",
        _ => "the server answered with a non-standard status",
    }
}

fn auth_stage_label(stage: AuthStage) -> &'static str {
    match stage {
        AuthStage::SrpInit => "initial SRP init",
        AuthStage::SrpComplete => "initial SRP complete",
        AuthStage::TrustedDevicePush => "trusted-device code request",
        AuthStage::CodeValidation => "verification code submission",
        AuthStage::ReauthSrpInit => "post-2FA SRP init",
        AuthStage::ReauthSrpComplete => "post-2FA SRP complete",
    }
}

fn auth_kind_label(kind: &AuthErrorKind) -> &'static str {
    match kind {
        AuthErrorKind::Transport(error) => transport_label(error),
        AuthErrorKind::Anisette(_) => "no usable anisette data was available",
        AuthErrorKind::Entropy(_) => "the entropy source failed",
        AuthErrorKind::HttpStatus(status) => http_status_label(*status),
        AuthErrorKind::Protocol(_) => {
            "the server reported a protocol error (HTTP 200 with a nonzero status code)"
        }
        AuthErrorKind::Malformed(_) => "the response was malformed or exceeded a bound",
        AuthErrorKind::UnsupportedProtocol { .. } => {
            "the server selected an SRP password protocol this client does not implement"
        }
        AuthErrorKind::ServerProofMismatch => {
            "the server proof did not verify (wrong password or untrusted peer)"
        }
        AuthErrorKind::SecondFactorStillRequired => {
            "a second factor was still required after verification; not repeated"
        }
        AuthErrorKind::UnsupportedStep { .. } => {
            "the server requires an unsupported secondary authentication step"
        }
        AuthErrorKind::Internal { .. } => "an internal request-building invariant failed",
        _ => "authentication failed",
    }
}

fn transport_label(error: &TransportError) -> &'static str {
    match error {
        TransportError::Connect { .. } => "the connection could not be established",
        TransportError::Tls { .. } => "TLS negotiation or certificate verification failed",
        TransportError::Timeout => "the exchange timed out",
        TransportError::ResponseTooLarge { .. } => "the response exceeded the size bound",
        TransportError::Other { .. } => {
            "the transport refused the exchange (allowlist, redirect, or challenge policy)"
        }
        _ => "the transport failed",
    }
}

impl From<TerminalError> for HarnessError {
    fn from(error: TerminalError) -> Self {
        Self::Terminal(error)
    }
}

/// The verdicts a successful run reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Report {
    /// How local anisette became usable.
    pub anisette: AnisetteVerdict,
    /// Which authentication branch ran.
    pub path: SecondFactorPath,
    /// Whether the profile slot pre-existed.
    pub slot: SlotOrigin,
}

impl Report {
    /// The fixed lines of the success report.
    #[must_use]
    pub fn lines(&self) -> [&'static str; 7] {
        [
            match self.anisette {
                AnisetteVerdict::AlreadyProvisioned => {
                    "local anisette: verified (existing provisioning reused)"
                }
                AnisetteVerdict::ProvisionedNow => {
                    "local anisette: verified (provisioned once during this run)"
                }
            },
            "initial SRP password exchange: verified",
            match self.path {
                SecondFactorPath::TrustedDeviceVerified => "trusted-device 2FA: verified",
                SecondFactorPath::NotRequired => {
                    "trusted-device 2FA: not exercised (the account did not require it)"
                }
            },
            match self.path {
                SecondFactorPath::TrustedDeviceVerified => "post-2FA re-authentication: verified",
                SecondFactorPath::NotRequired => {
                    "post-2FA re-authentication: not exercised (no second factor)"
                }
            },
            match self.slot {
                SlotOrigin::Reused => {
                    "Secret Service store and reload over a new connection: verified \
                     (existing profile slot reused)"
                }
                SlotOrigin::Created | SlotOrigin::AdoptedFromRace => {
                    "Secret Service store and reload over a new connection: verified \
                     (new profile slot)"
                }
            },
            "stored material: persistence only; this M1 flow performs no token issuance, so no \
             authenticated network session was resumed",
            "remote anisette fallback: absent by construction",
        ]
    }
}

/// Returns the helper's expected location beside `harness_executable`.
#[must_use]
pub fn helper_beside(harness_executable: &Path) -> Option<PathBuf> {
    harness_executable
        .parent()
        .map(|dir| dir.join(HELPER_EXECUTABLE))
}

/// Checks that the helper is a regular, executable file.
#[must_use]
pub fn helper_is_usable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path)
        .map(|metadata| metadata.is_file() && metadata.permissions().mode() & 0o111 != 0)
        .unwrap_or(false)
}

fn locate_helper() -> Result<PathBuf, HarnessError> {
    let exe = std::env::current_exe().map_err(|_| HarnessError::HelperMissing)?;
    let helper = helper_beside(&exe).ok_or(HarnessError::HelperMissing)?;
    if helper_is_usable(&helper) {
        Ok(helper)
    } else {
        Err(HarnessError::HelperMissing)
    }
}

/// Runs the whole harness against the production adapters.
///
/// # Errors
///
/// Returns the first failure; nothing is retried.
pub fn run<T: SecureTerminal>(terminal: &mut T) -> Result<Report, HarnessError> {
    terminal.notice("coffer-live-auth: one live Apple Account authentication, no retries")?;

    terminal.notice("[state] resolving the profile slot under XDG_STATE_HOME")?;
    let entropy = OsEntropy;
    let (slot, slot_origin) = SlotState::from_environment()
        .and_then(|state| state.load_or_create(&entropy))
        .map_err(HarnessError::SlotState)?;

    terminal.notice("[store] checking that Secret Service is reachable and unlocked")?;
    let connector = SecretServiceConnector;
    block_on(check_keyring_available(&connector)).map_err(HarnessError::KeyringUnavailable)?;

    terminal.notice(
        "[bootstrap] verifying the Apple support libraries (downloads once from Apple if absent)",
    )?;
    let paths = BootstrapPaths::from_environment()
        .map_err(|error| HarnessError::Bootstrap(BootstrapError::from(error)))?;
    let installation = Bootstrap::new(paths.clone(), AppleCdnSource::new())
        .and_then(|bootstrap| bootstrap.ensure())
        .map_err(HarnessError::Bootstrap)?;

    terminal.notice("[anisette] opening the local provider with the sandboxed helper")?;
    let helper = locate_helper()?;
    let context = AnisetteContext::new(TIME_ZONE.to_owned(), LOCALE.to_owned())
        .map_err(HarnessError::AnisetteOpen)?;
    let provider =
        CofferAnisetteProvider::open(&installation, &paths, helper, HELPER_TIMEOUT, context)
            .map_err(HarnessError::AnisetteOpen)?;
    let anisette = ensure_local_anisette(
        &LocalAnisette::new(&provider, PROVISIONING_DEADLINE),
        terminal,
    )
    .map_err(HarnessError::Anisette)?;

    let transport =
        GsaTransport::production(Deadlines::starting_now(EXCHANGE_TIMEOUT, RUN_DEADLINE));
    let authenticator = Authenticator::new(transport, provider, entropy);
    let outcome = block_on(run_login(&authenticator, terminal)).map_err(HarnessError::Flow)?;

    let reusable = ReusableSession::from_session(&outcome.session);
    drop(outcome.session);
    block_on(persist_and_reload(&connector, &slot, &reusable, terminal))
        .map_err(HarnessError::Persist)?;
    drop(reusable);

    Ok(Report {
        anisette,
        path: outcome.path,
        slot: slot_origin,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn report_lines_never_claim_an_unexercised_branch() {
        let report = Report {
            anisette: AnisetteVerdict::AlreadyProvisioned,
            path: SecondFactorPath::NotRequired,
            slot: SlotOrigin::Reused,
        };
        let lines = report.lines();
        assert!(lines[2].contains("not exercised"));
        assert!(lines[3].contains("not exercised"));
        assert!(!lines.iter().any(|line| line.contains("2FA: verified")));
        let report = Report {
            anisette: AnisetteVerdict::ProvisionedNow,
            path: SecondFactorPath::TrustedDeviceVerified,
            slot: SlotOrigin::Created,
        };
        let lines = report.lines();
        assert_eq!(lines[2], "trusted-device 2FA: verified");
        assert_eq!(lines[3], "post-2FA re-authentication: verified");
        assert!(lines[0].contains("provisioned once"));
        assert!(lines[5].contains("no authenticated network session was resumed"));
        assert!(lines[6].contains("absent by construction"));
    }

    #[test]
    fn helper_is_looked_for_beside_the_harness_only() {
        assert_eq!(
            helper_beside(Path::new("/x/target/debug/coffer-live-auth")).unwrap(),
            PathBuf::from("/x/target/debug/coffer-anisette-helper")
        );
        assert!(helper_beside(Path::new("/")).is_none());
        let dir = tempfile::tempdir().unwrap();
        let helper = dir.path().join(HELPER_EXECUTABLE);
        assert!(!helper_is_usable(&helper));
        std::fs::write(&helper, b"#!/bin/sh\n").unwrap();
        assert!(!helper_is_usable(&helper));
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&helper, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(helper_is_usable(&helper));
        assert!(!helper_is_usable(dir.path()));
    }

    #[test]
    fn errors_name_the_stage_without_values() {
        let text = HarnessError::HelperMissing.to_string();
        assert!(text.contains("mise run test-live-auth"));
        let text = HarnessError::KeyringUnavailable(StoreError::Locked).to_string();
        assert!(text.starts_with("Secret Service is not usable, nothing was attempted"));
        let text = HarnessError::SlotState(SlotStateError::Corrupt).to_string();
        assert!(!text.contains('/'));
        let (_, kind) = HarnessError::Anisette(AnisetteStageError::Provisioning(
            crate::anisette::ProvisioningFailure {
                stage: ProvisioningStage::Lookup,
                kind: ProvisioningErrorKind::Tls,
            },
        ))
        .labels();
        assert_eq!(kind, "TLS handshake or certificate verification failed");
    }

    #[test]
    fn labels_never_carry_server_controlled_values() {
        use std::time::Duration;

        use coffer_protocol::anisette::{AnisetteData, AnisetteError};
        use coffer_protocol::entropy::{Entropy, EntropyError};
        use coffer_protocol::secret::{AccountName, Password};
        use futures_lite::future::block_on;

        use crate::transport::tests::FakeExchange;

        struct FixedEntropy;
        impl Entropy for FixedEntropy {
            fn fill(&self, dest: &mut [u8]) -> Result<(), EntropyError> {
                dest.fill(0x42);
                Ok(())
            }
        }
        struct FixedAnisette;
        impl coffer_protocol::anisette::AnisetteProvider for FixedAnisette {
            async fn anisette(&self) -> Result<AnisetteData, AnisetteError> {
                Ok(AnisetteData {
                    one_time_password: "otp".to_owned(),
                    machine_id: "mid".to_owned(),
                    routing_info: "17106176".to_owned(),
                    local_user_id: "LU".to_owned(),
                    serial_number: "0".to_owned(),
                    client_info: "<Model> <macOS;13.1;22C65> <com.apple.AuthKit/1 (x)>".to_owned(),
                    device_id: "DEVICE".to_owned(),
                    client_time: "2026-01-01T00:00:00Z".to_owned(),
                    time_zone: "UTC".to_owned(),
                    locale: "en_US".to_owned(),
                })
            }
        }

        // A protocol error whose numeric code and message must not surface.
        let body = concat!(
            "<?xml version=\"1.0\"?><plist version=\"1.0\"><dict><key>Response</key><dict>",
            "<key>Status</key><dict><key>ec</key><integer>-20101</integer>",
            "<key>em</key><string>MARKER-SERVER-TEXT</string></dict></dict></dict></plist>"
        );
        let scripted = [
            Ok((200, body.as_bytes().to_vec())),
            Ok((503, b"MARKER-BODY".to_vec())),
            Ok((302, b"Location: https://marker.example/".to_vec())),
        ];
        for outcome in scripted {
            let transport = GsaTransport::new(
                FakeExchange::new(vec![outcome]),
                Deadlines::starting_now(Duration::from_secs(5), Duration::from_secs(5)),
            );
            let authenticator = Authenticator::new(transport, FixedAnisette, FixedEntropy);
            let login = authenticator.login(
                AccountName::new("someone@example.com".to_owned()).unwrap(),
                Password::new("hunter2".to_owned()),
            );
            let error = block_on(login.authenticate()).expect_err("scripted failure");
            let harness_error = HarnessError::Flow(FlowError::Auth(error));
            let (stage, kind) = harness_error.labels();
            assert_eq!(stage, "initial SRP init");
            for forbidden in [
                "20101", "503", "302", "MARKER", "someone", "hunter2", "marker",
            ] {
                assert!(!kind.contains(forbidden), "{kind} leaks {forbidden}");
                assert!(!stage.contains(forbidden));
            }
        }

        let (stage, kind) =
            HarnessError::Persist(PersistError::Store(StoreError::UnsupportedVersion(77))).labels();
        assert!(!kind.contains("77"));
        assert_eq!(stage, "session persistence");
        let (_, kind) = HarnessError::Anisette(AnisetteStageError::Provisioning(
            crate::anisette::ProvisioningFailure {
                stage: ProvisioningStage::FinishRequest,
                kind: ProvisioningErrorKind::ProtocolStatus(-45054),
            },
        ))
        .labels();
        assert!(!kind.contains("45054"));

        for reason in [
            MalformedResponseReason::Endpoint,
            MalformedResponseReason::BodySize,
            MalformedResponseReason::XmlSyntax,
            MalformedResponseReason::XmlDeclaration,
            MalformedResponseReason::XmlDoctype,
            MalformedResponseReason::XmlMarkup,
            MalformedResponseReason::XmlAttribute,
            MalformedResponseReason::XmlDepth,
            MalformedResponseReason::XmlFieldLimit,
            MalformedResponseReason::XmlNodeLimit,
            MalformedResponseReason::DictionaryKey,
            MalformedResponseReason::DictionaryType,
            MalformedResponseReason::MissingField,
            MalformedResponseReason::FieldType,
            MalformedResponseReason::MissingStatus,
            MalformedResponseReason::StatusType,
            MalformedResponseReason::MissingSecret,
            MalformedResponseReason::SecretType,
            MalformedResponseReason::SecretEncoding,
            MalformedResponseReason::SecretSize,
        ] {
            let (_, kind) = HarnessError::Anisette(AnisetteStageError::Provisioning(
                crate::anisette::ProvisioningFailure {
                    stage: ProvisioningStage::StartRequest,
                    kind: ProvisioningErrorKind::MalformedResponse(reason),
                },
            ))
            .labels();
            for forbidden in ["MARKER", "spim", "ptm", "tk", "cpim", "?secret="] {
                assert!(!kind.contains(forbidden));
            }
        }
    }
}
