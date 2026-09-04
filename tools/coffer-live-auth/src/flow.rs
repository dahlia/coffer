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

//! Driving the authentication typestate from the terminal, one step each.
//!
//! [`run_login`] is the whole interactive flow:
//!
//! ```text
//! hidden account prompt ─▶ hidden password prompt ─▶ authenticate (once)
//!   ├─ Authenticated ──────────────────────────────────────────▶ session
//!   ├─ SecondFactorRequired ─▶ request code (once) ─▶ hidden code prompt
//!   │     ─▶ submit code (once) ─▶ NEW hidden password prompt
//!   │     ─▶ reauthenticate (once) ────────────────────────────▶ session
//!   └─ Unsupported ─────────────────────────────────────────────▶ stop
//! ```
//!
//! Every failure ends the flow.  Nothing is retried, no prompt is repeated,
//! and the first password is gone before the code prompt appears: the
//! post-two-factor re-authentication takes a password typed fresh.
//!
//! The flow is written against the four small step traits below rather than
//! the protocol types directly, so that the prompt sequence and the
//! once-only discipline are testable with scripted steps.  The production
//! implementations, at the bottom of this module, are one-line adapters over
//! [`coffer_protocol::auth`].

use core::fmt;
use std::future::Future;

use coffer_protocol::anisette::AnisetteProvider;
use coffer_protocol::auth::{
    AuthError, Authenticator, CodeRequested, LoginOutcome, SecondFactorRequired,
    SecondFactorVerified, Session,
};
use coffer_protocol::entropy::Entropy;
use coffer_protocol::secret::{
    AccountName, InvalidAccountName, InvalidVerificationCode, Password, VerificationCode,
};
use coffer_protocol::transport::Transport;
use zeroize::Zeroizing;

use crate::terminal::{SecureTerminal, TerminalError};

/// The initial password exchange.
pub trait LoginStep: Sized {
    /// What a successful flow yields.
    type Session;
    /// The stage reached when a trusted-device code is required.
    type SecondFactor: SecondFactorStep<Session = Self::Session, Error = Self::Error>;
    /// The step failure type; [`AuthError`] in production.
    type Error: std::error::Error;

    /// Runs the initial SRP exchange exactly once.
    fn authenticate(
        self,
        account: AccountName,
        password: Password,
    ) -> impl Future<Output = Result<LoginResult<Self>, Self::Error>>;
}

/// Outcome of [`LoginStep::authenticate`].
pub enum LoginResult<L: LoginStep> {
    /// No second factor is required.
    Authenticated(L::Session),
    /// A trusted-device code is required.
    SecondFactorRequired(L::SecondFactor),
    /// The server asked for a step this harness does not perform.
    Unsupported,
}

/// The stage that can ask for a code push.
pub trait SecondFactorStep: Sized {
    /// What a successful flow yields.
    type Session;
    /// The step failure type.
    type Error: std::error::Error;
    /// The stage reached after the push request.
    type CodeRequested: CodeStep<Session = Self::Session, Error = Self::Error>;

    /// Requests one code push to the trusted devices.
    fn request_trusted_device_code(
        self,
    ) -> impl Future<Output = Result<Self::CodeRequested, Self::Error>>;
}

/// The stage that can submit a code.
pub trait CodeStep: Sized {
    /// What a successful flow yields.
    type Session;
    /// The step failure type.
    type Error: std::error::Error;
    /// The stage reached after the code is accepted.
    type Verified: ReauthStep<Session = Self::Session, Error = Self::Error>;

    /// Submits the code exactly once.
    fn submit_code(
        self,
        code: VerificationCode,
    ) -> impl Future<Output = Result<Self::Verified, Self::Error>>;
}

/// The stage that runs the post-two-factor password exchange.
pub trait ReauthStep: Sized {
    /// What a successful flow yields.
    type Session;
    /// The step failure type.
    type Error: std::error::Error;

    /// Runs the post-two-factor SRP exchange exactly once.
    fn reauthenticate(
        self,
        password: Password,
    ) -> impl Future<Output = Result<Self::Session, Self::Error>>;
}

/// Which branch the flow took.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecondFactorPath {
    /// The account did not require a second factor; the trusted-device and
    /// post-two-factor steps were not exercised.
    NotRequired,
    /// A trusted-device code was requested, submitted, and accepted, and the
    /// post-two-factor re-authentication produced the session.
    TrustedDeviceVerified,
}

/// A completed flow.
pub struct FlowOutcome<S> {
    /// The authenticated session.
    pub session: S,
    /// Which branch produced it.
    pub path: SecondFactorPath,
}

impl<S> fmt::Debug for FlowOutcome<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FlowOutcome")
            .field("path", &self.path)
            .finish_non_exhaustive()
    }
}

/// Why the flow stopped.
#[derive(Debug)]
#[non_exhaustive]
pub enum FlowError<E> {
    /// The terminal could not supply input.
    Terminal(TerminalError),
    /// The typed account name is not acceptable; nothing was sent.
    InvalidAccountName(InvalidAccountName),
    /// The typed code is not six digits; nothing was sent.
    InvalidCode(InvalidVerificationCode),
    /// A protocol step failed.  In production the [`AuthError`] names the
    /// stage, which distinguishes an initial failure from a post-two-factor
    /// one.
    Auth(E),
    /// The server requires a secondary authentication step other than a
    /// trusted-device code.  The harness does not guess at it.
    UnsupportedStep,
}

impl<E: fmt::Display> fmt::Display for FlowError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Terminal(error) => write!(f, "{error}"),
            Self::InvalidAccountName(error) => write!(f, "{error}; nothing was sent"),
            Self::InvalidCode(error) => write!(f, "{error}; the code was not submitted"),
            Self::Auth(error) => write!(f, "{error}"),
            Self::UnsupportedStep => f.write_str(
                "the server requires a secondary authentication step other than a \
                 trusted-device code; the harness stops here",
            ),
        }
    }
}

impl<E: std::error::Error> std::error::Error for FlowError<E> {}

impl<E> From<TerminalError> for FlowError<E> {
    fn from(error: TerminalError) -> Self {
        Self::Terminal(error)
    }
}

/// Moves the text out of a zeroizing buffer, leaving it empty.
fn take(mut line: Zeroizing<String>) -> String {
    std::mem::take(&mut *line)
}

/// Runs the interactive flow described in the module docs.
///
/// # Errors
///
/// See [`FlowError`].  Every error is terminal; the caller must not call this
/// again without a new, deliberate user action.
pub async fn run_login<L: LoginStep, T: SecureTerminal>(
    login: L,
    terminal: &mut T,
) -> Result<FlowOutcome<L::Session>, FlowError<L::Error>> {
    terminal.notice(
        "[auth] the account name is an identifier Coffer treats as private: it is typed \
         without echo, kept in memory only, and never printed",
    )?;
    let account =
        terminal.prompt_hidden("Apple Account (e-mail address or phone number, not echoed): ")?;
    let account = AccountName::new(take(account)).map_err(FlowError::InvalidAccountName)?;
    let password = terminal.prompt_hidden("Password (not echoed): ")?;
    let password = Password::new(take(password));
    terminal.notice("[auth] initial SRP password exchange (one attempt)")?;
    let second_factor = match login
        .authenticate(account, password)
        .await
        .map_err(FlowError::Auth)?
    {
        LoginResult::Authenticated(session) => {
            return Ok(FlowOutcome {
                session,
                path: SecondFactorPath::NotRequired,
            });
        }
        LoginResult::SecondFactorRequired(second_factor) => second_factor,
        LoginResult::Unsupported => return Err(FlowError::UnsupportedStep),
    };
    terminal.notice("[auth] trusted-device verification required; requesting one code push")?;
    let requested = second_factor
        .request_trusted_device_code()
        .await
        .map_err(FlowError::Auth)?;
    terminal.notice("[auth] a code should appear on your trusted devices; it is submitted once")?;
    let code = terminal.prompt_hidden("Verification code (6 digits, not echoed): ")?;
    let code = VerificationCode::parse(take(code)).map_err(FlowError::InvalidCode)?;
    let verified = requested.submit_code(code).await.map_err(FlowError::Auth)?;
    terminal.notice(
        "[auth] code accepted; Apple requires the password exchange again after a second \
         factor, and the earlier password was not kept",
    )?;
    let password =
        terminal.prompt_hidden("Password again, for post-2FA re-authentication (not echoed): ")?;
    let password = Password::new(take(password));
    terminal.notice("[auth] post-2FA SRP password exchange (one attempt)")?;
    let session = verified
        .reauthenticate(password)
        .await
        .map_err(FlowError::Auth)?;
    Ok(FlowOutcome {
        session,
        path: SecondFactorPath::TrustedDeviceVerified,
    })
}

// Production adapters ---------------------------------------------------------

impl<'a, T: Transport, A: AnisetteProvider, E: Entropy> LoginStep for &'a Authenticator<T, A, E> {
    type Session = Session;
    type SecondFactor = SecondFactorRequired<'a, T, A, E>;
    type Error = AuthError;

    async fn authenticate(
        self,
        account: AccountName,
        password: Password,
    ) -> Result<LoginResult<Self>, AuthError> {
        Ok(match self.login(account, password).authenticate().await? {
            LoginOutcome::Authenticated(session) => LoginResult::Authenticated(session),
            LoginOutcome::SecondFactorRequired(stage) => LoginResult::SecondFactorRequired(stage),
            _ => LoginResult::Unsupported,
        })
    }
}

impl<'a, T: Transport, A: AnisetteProvider, E: Entropy> SecondFactorStep
    for SecondFactorRequired<'a, T, A, E>
{
    type Session = Session;
    type Error = AuthError;
    type CodeRequested = CodeRequested<'a, T, A, E>;

    async fn request_trusted_device_code(self) -> Result<Self::CodeRequested, AuthError> {
        Self::request_trusted_device_code(self).await
    }
}

impl<'a, T: Transport, A: AnisetteProvider, E: Entropy> CodeStep for CodeRequested<'a, T, A, E> {
    type Session = Session;
    type Error = AuthError;
    type Verified = SecondFactorVerified<'a, T, A, E>;

    async fn submit_code(self, code: VerificationCode) -> Result<Self::Verified, AuthError> {
        Self::submit_code(self, code).await
    }
}

impl<T: Transport, A: AnisetteProvider, E: Entropy> ReauthStep
    for SecondFactorVerified<'_, T, A, E>
{
    type Session = Session;
    type Error = AuthError;

    async fn reauthenticate(self, password: Password) -> Result<Session, AuthError> {
        Self::reauthenticate(self, password).await
    }
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::rc::Rc;
    use std::time::Duration;

    use coffer_protocol::anisette::{AnisetteData, AnisetteError};
    use coffer_protocol::auth::{AuthErrorKind, AuthStage};
    use coffer_protocol::entropy::EntropyError;
    use coffer_protocol::transport::TransportError;
    use futures_lite::future::block_on;

    use super::*;
    use crate::terminal::LineTerminal;
    use crate::terminal::tests::FakeDevice;
    use crate::transport::tests::FakeExchange;
    use crate::transport::{Deadlines, GsaTransport};

    // Scripted steps ---------------------------------------------------------

    type Log = Rc<RefCell<Vec<&'static str>>>;

    #[derive(Debug)]
    struct StepFailure(&'static str);

    impl fmt::Display for StepFailure {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str(self.0)
        }
    }

    impl std::error::Error for StepFailure {}

    #[derive(Clone, Copy)]
    enum Plan {
        NoSecondFactor,
        Unsupported,
        FailAuthenticate,
        SecondFactor {
            request: bool,
            submit: bool,
            reauth: bool,
        },
    }

    struct FakeLogin {
        log: Log,
        plan: Plan,
    }
    struct FakeSecondFactor {
        log: Log,
        plan: Plan,
    }
    struct FakeCode {
        log: Log,
        plan: Plan,
    }
    struct FakeVerified {
        log: Log,
        plan: Plan,
    }

    impl LoginStep for FakeLogin {
        type Session = &'static str;
        type SecondFactor = FakeSecondFactor;
        type Error = StepFailure;

        async fn authenticate(
            self,
            _: AccountName,
            _: Password,
        ) -> Result<LoginResult<Self>, StepFailure> {
            self.log.borrow_mut().push("authenticate");
            match self.plan {
                Plan::NoSecondFactor => Ok(LoginResult::Authenticated("session")),
                Plan::Unsupported => Ok(LoginResult::Unsupported),
                Plan::FailAuthenticate => Err(StepFailure("initial exchange failed")),
                Plan::SecondFactor { .. } => {
                    Ok(LoginResult::SecondFactorRequired(FakeSecondFactor {
                        log: self.log,
                        plan: self.plan,
                    }))
                }
            }
        }
    }

    impl SecondFactorStep for FakeSecondFactor {
        type Session = &'static str;
        type Error = StepFailure;
        type CodeRequested = FakeCode;

        async fn request_trusted_device_code(self) -> Result<FakeCode, StepFailure> {
            self.log.borrow_mut().push("request-code");
            match self.plan {
                Plan::SecondFactor { request: true, .. } => Ok(FakeCode {
                    log: self.log,
                    plan: self.plan,
                }),
                _ => Err(StepFailure("push failed")),
            }
        }
    }

    impl CodeStep for FakeCode {
        type Session = &'static str;
        type Error = StepFailure;
        type Verified = FakeVerified;

        async fn submit_code(self, _: VerificationCode) -> Result<FakeVerified, StepFailure> {
            self.log.borrow_mut().push("submit-code");
            match self.plan {
                Plan::SecondFactor { submit: true, .. } => Ok(FakeVerified {
                    log: self.log,
                    plan: self.plan,
                }),
                _ => Err(StepFailure("code rejected")),
            }
        }
    }

    impl ReauthStep for FakeVerified {
        type Session = &'static str;
        type Error = StepFailure;

        async fn reauthenticate(self, _: Password) -> Result<&'static str, StepFailure> {
            self.log.borrow_mut().push("reauthenticate");
            match self.plan {
                Plan::SecondFactor { reauth: true, .. } => Ok("session-after-2fa"),
                _ => Err(StepFailure("post-2FA exchange failed")),
            }
        }
    }

    /// A terminal that records every prompt into the shared log, so the
    /// interleaving of prompts and protocol steps is asserted exactly.
    struct LoggingTerminal {
        inner: LineTerminal<FakeDevice>,
        log: Log,
    }

    impl LoggingTerminal {
        fn new(input: &[u8], log: &Log) -> Self {
            Self {
                inner: LineTerminal::new(FakeDevice::new(input)),
                log: Rc::clone(log),
            }
        }

        fn output(&self) -> String {
            String::from_utf8(self.inner.device().output.clone()).unwrap()
        }
    }

    impl SecureTerminal for LoggingTerminal {
        fn notice(&mut self, text: &'static str) -> Result<(), TerminalError> {
            self.inner.notice(text)
        }

        fn prompt_visible(
            &mut self,
            label: &'static str,
        ) -> Result<Zeroizing<String>, TerminalError> {
            self.log.borrow_mut().push("prompt-hidden");
            self.inner.prompt_visible(label)
        }

        fn prompt_hidden(
            &mut self,
            label: &'static str,
        ) -> Result<Zeroizing<String>, TerminalError> {
            self.log.borrow_mut().push("prompt-hidden");
            self.inner.prompt_hidden(label)
        }
    }

    fn run(
        plan: Plan,
        input: &[u8],
    ) -> (
        Result<FlowOutcome<&'static str>, FlowError<StepFailure>>,
        Vec<&'static str>,
        String,
    ) {
        let log: Log = Rc::new(RefCell::new(Vec::new()));
        let mut terminal = LoggingTerminal::new(input, &log);
        let login = FakeLogin {
            log: Rc::clone(&log),
            plan,
        };
        let result = block_on(run_login(login, &mut terminal));
        let events = log.borrow().clone();
        (result, events, terminal.output())
    }

    const ACCOUNT: &[u8] = b"someone@example.com\n";

    #[test]
    fn no_second_factor_flow_prompts_twice_and_authenticates_once() {
        let (result, events, output) = run(Plan::NoSecondFactor, b"someone@example.com\nhunter2\n");
        let outcome = result.unwrap();
        assert_eq!(outcome.session, "session");
        assert_eq!(outcome.path, SecondFactorPath::NotRequired);
        assert_eq!(
            events,
            vec!["prompt-hidden", "prompt-hidden", "authenticate"]
        );
        assert!(!output.contains("hunter2"));
        assert!(!output.contains("someone"));
    }

    #[test]
    fn second_factor_flow_takes_a_fresh_password_after_the_code() {
        let plan = Plan::SecondFactor {
            request: true,
            submit: true,
            reauth: true,
        };
        let (result, events, output) =
            run(plan, b"someone@example.com\nfirst-pw\n123456\nsecond-pw\n");
        let outcome = result.unwrap();
        assert_eq!(outcome.session, "session-after-2fa");
        assert_eq!(outcome.path, SecondFactorPath::TrustedDeviceVerified);
        assert_eq!(
            events,
            vec![
                "prompt-hidden",
                "prompt-hidden",
                "authenticate",
                "request-code",
                "prompt-hidden",
                "submit-code",
                "prompt-hidden",
                "reauthenticate",
            ]
        );
        for secret in ["first-pw", "123456", "second-pw", "someone"] {
            assert!(!output.contains(secret));
        }
    }

    #[test]
    fn a_rejected_code_stops_without_reauthentication() {
        let plan = Plan::SecondFactor {
            request: true,
            submit: false,
            reauth: true,
        };
        let (result, events, _) = run(plan, b"someone@example.com\npw\n123456\nnever-read\n");
        assert!(matches!(
            result.unwrap_err(),
            FlowError::Auth(StepFailure("code rejected"))
        ));
        assert_eq!(
            events,
            vec![
                "prompt-hidden",
                "prompt-hidden",
                "authenticate",
                "request-code",
                "prompt-hidden",
                "submit-code",
            ]
        );
    }

    #[test]
    fn a_malformed_code_is_never_submitted() {
        let plan = Plan::SecondFactor {
            request: true,
            submit: true,
            reauth: true,
        };
        for bad in [&b"12345\n"[..], b"12345a\n", b"1234567\n"] {
            let mut input = b"someone@example.com\npw\n".to_vec();
            input.extend_from_slice(bad);
            let (result, events, _) = run(plan, &input);
            assert!(matches!(result.unwrap_err(), FlowError::InvalidCode(_)));
            assert_eq!(events.last(), Some(&"prompt-hidden"));
            assert!(!events.contains(&"submit-code"));
        }
    }

    #[test]
    fn a_failed_push_request_stops_before_the_code_prompt() {
        let plan = Plan::SecondFactor {
            request: false,
            submit: true,
            reauth: true,
        };
        let (result, events, _) = run(plan, b"someone@example.com\npw\n123456\n");
        assert!(matches!(
            result.unwrap_err(),
            FlowError::Auth(StepFailure("push failed"))
        ));
        assert_eq!(
            events,
            vec![
                "prompt-hidden",
                "prompt-hidden",
                "authenticate",
                "request-code"
            ]
        );
    }

    #[test]
    fn a_failed_reauthentication_is_not_retried() {
        let plan = Plan::SecondFactor {
            request: true,
            submit: true,
            reauth: false,
        };
        let (result, events, _) = run(plan, b"someone@example.com\npw\n123456\npw\nextra\n");
        assert!(matches!(
            result.unwrap_err(),
            FlowError::Auth(StepFailure("post-2FA exchange failed"))
        ));
        assert_eq!(events.iter().filter(|e| **e == "reauthenticate").count(), 1);
        assert_eq!(events.last(), Some(&"reauthenticate"));
    }

    #[test]
    fn an_initial_failure_is_not_retried_and_asks_nothing_more() {
        let (result, events, _) = run(Plan::FailAuthenticate, b"someone@example.com\npw\npw\n");
        assert!(matches!(
            result.unwrap_err(),
            FlowError::Auth(StepFailure("initial exchange failed"))
        ));
        assert_eq!(
            events,
            vec!["prompt-hidden", "prompt-hidden", "authenticate"]
        );
    }

    #[test]
    fn an_unsupported_step_stops_without_guessing() {
        let (result, events, _) = run(Plan::Unsupported, b"someone@example.com\npw\n");
        assert!(matches!(result.unwrap_err(), FlowError::UnsupportedStep));
        assert_eq!(
            events,
            vec!["prompt-hidden", "prompt-hidden", "authenticate"]
        );
    }

    #[test]
    fn terminal_failures_stop_before_any_network_step() {
        let (result, events, _) = run(Plan::NoSecondFactor, ACCOUNT);
        assert!(matches!(
            result.unwrap_err(),
            FlowError::Terminal(TerminalError::Closed)
        ));
        assert_eq!(events, vec!["prompt-hidden", "prompt-hidden"]);
        let (result, events, _) = run(Plan::NoSecondFactor, b"\n");
        assert!(matches!(
            result.unwrap_err(),
            FlowError::Terminal(TerminalError::Empty)
        ));
        assert_eq!(events, vec!["prompt-hidden"]);
    }

    #[test]
    fn an_invalid_account_name_is_rejected_locally() {
        let mut input = vec![b'a'; 300];
        input.extend_from_slice(b"\npw\n");
        let (result, events, _) = run(Plan::NoSecondFactor, &input);
        assert!(matches!(
            result.unwrap_err(),
            FlowError::InvalidAccountName(_)
        ));
        assert_eq!(events, vec!["prompt-hidden"]);
    }

    // The real protocol over a scripted exchange -----------------------------

    struct FixedEntropy;

    impl Entropy for FixedEntropy {
        fn fill(&self, dest: &mut [u8]) -> Result<(), EntropyError> {
            for (i, byte) in dest.iter_mut().enumerate() {
                *byte = (i as u8).wrapping_mul(37).wrapping_add(11);
            }
            Ok(())
        }
    }

    struct FixedAnisette;

    impl AnisetteProvider for FixedAnisette {
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

    fn status_body(ec: i64) -> Vec<u8> {
        let mut status = plist::Dictionary::new();
        status.insert("ec".to_owned(), plist::Value::Integer(ec.into()));
        status.insert(
            "em".to_owned(),
            plist::Value::String("synthetic".to_owned()),
        );
        let mut response = plist::Dictionary::new();
        response.insert("Status".to_owned(), plist::Value::Dictionary(status));
        let mut root = plist::Dictionary::new();
        root.insert("Response".to_owned(), plist::Value::Dictionary(response));
        let mut out = Vec::new();
        plist::Value::Dictionary(root)
            .to_writer_xml(&mut out)
            .unwrap();
        out
    }

    fn real_login(
        outcome: Result<(u16, Vec<u8>), TransportError>,
    ) -> (AuthStage, AuthErrorKind, usize) {
        let exchange = FakeExchange::new(vec![outcome]);
        let transport = GsaTransport::new(
            exchange,
            Deadlines::starting_now(Duration::from_secs(5), Duration::from_secs(5)),
        );
        let authenticator = Authenticator::new(transport, FixedAnisette, FixedEntropy);
        let log: Log = Rc::new(RefCell::new(Vec::new()));
        let mut terminal = LoggingTerminal::new(b"someone@example.com\nhunter2\n", &log);
        let result = block_on(run_login(&authenticator, &mut terminal));
        let error = match result {
            Err(FlowError::Auth(error)) => error,
            Err(other) => panic!("unexpected flow error: {other}"),
            Ok(_) => panic!("scripted failure produced a session"),
        };
        let calls = authenticator.transport().exchange_ref().calls();
        let (stage, kind) = error.into_parts();
        (stage, kind, calls)
    }

    #[test]
    fn transport_failure_at_srp_init_sends_exactly_one_exchange() {
        let (stage, kind, calls) = real_login(Err(TransportError::Timeout));
        assert_eq!(stage, AuthStage::SrpInit);
        assert!(matches!(
            kind,
            AuthErrorKind::Transport(TransportError::Timeout)
        ));
        assert_eq!(calls, 1);
    }

    #[test]
    fn http_200_protocol_error_is_terminal_at_srp_init() {
        let (stage, kind, calls) = real_login(Ok((200, status_body(-20101))));
        assert_eq!(stage, AuthStage::SrpInit);
        match kind {
            AuthErrorKind::Protocol(status) => assert_eq!(status.code(), -20101),
            other => panic!("unexpected kind: {other:?}"),
        }
        assert_eq!(calls, 1);
    }

    #[test]
    fn malformed_http_200_body_is_terminal_at_srp_init() {
        let (stage, kind, calls) = real_login(Ok((200, b"this is not a property list".to_vec())));
        assert_eq!(stage, AuthStage::SrpInit);
        assert!(matches!(kind, AuthErrorKind::Malformed(_)));
        assert_eq!(calls, 1);
    }

    #[test]
    fn server_error_status_is_terminal_at_srp_init() {
        let (stage, kind, calls) = real_login(Ok((503, b"unavailable".to_vec())));
        assert_eq!(stage, AuthStage::SrpInit);
        assert!(matches!(kind, AuthErrorKind::HttpStatus(503)));
        assert_eq!(calls, 1);
    }

    #[test]
    fn a_redirect_never_reaches_the_protocol_layer() {
        let (stage, kind, calls) =
            real_login(Ok((302, b"Location: https://evil.example/".to_vec())));
        assert_eq!(stage, AuthStage::SrpInit);
        match kind {
            AuthErrorKind::Transport(TransportError::Other { detail }) => {
                assert_eq!(detail, "redirect refused");
            }
            other => panic!("unexpected kind: {other:?}"),
        }
        assert_eq!(calls, 1);
    }

    #[test]
    fn flow_errors_do_not_echo_input() {
        let text =
            FlowError::<StepFailure>::InvalidCode(InvalidVerificationCode::Length).to_string();
        assert!(text.contains("not submitted"));
        let text = FlowError::<StepFailure>::UnsupportedStep.to_string();
        assert!(text.contains("stops here"));
    }
}
