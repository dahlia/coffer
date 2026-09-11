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

//! Developer-only stored-session issuance, with load-only preflight.
//!
//! Missing or invalid state stops before preparing anisette or HTTP adapters.
//! Only existing libraries/provisioning are used. Normal OTP generation may
//! update existing local anisette state; no provisioning or keyring write occurs.

use crate::{
    harness::{helper_beside, helper_is_usable},
    slot::{SlotState, SlotStateError},
    store::{SecretServiceConnector, StoreConnector},
    terminal::SecureTerminal,
    transport::{Deadlines, GsaTransport},
};
use coffer_anisette::{AnisetteContext, CofferAnisetteProvider};
use coffer_bootstrap::{ArtifactSource, Bootstrap, BootstrapPaths, FetchError, Limits, SourceUrl};
use coffer_protocol::{
    anisette::AnisetteProvider,
    tokens::{EpochMillis, Service, TokenClient, TokenError},
    transport::Transport,
};
use coffer_service::SessionStore;
use core::fmt;
use futures_lite::future::block_on;
use std::time::Duration;

/// Fixed, secret-free failure from the stored-session harness.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReuseError {
    /// No valid existing profile slot was found.
    Slot,
    /// The selected session is absent.
    MissingSession,
    /// Secret Service load/connect failed; no item is changed.
    Store,
    /// Existing support libraries or provisioning could not be opened.
    LocalState,
    /// The terminal failed or the explicit issuance confirmation was declined.
    Declined,
    /// The single token operation failed.
    Token(TokenError),
}
impl fmt::Display for ReuseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Slot => f.write_str("existing profile slot is unavailable"),
            Self::MissingSession => f.write_str("stored GSA session is missing"),
            Self::Store => f.write_str("stored GSA session could not be loaded"),
            Self::LocalState => {
                f.write_str("existing local libraries or provisioning are unavailable")
            }
            Self::Declined => f.write_str("service-token issuance was not confirmed"),
            Self::Token(error) => fmt::Display::fmt(error, f),
        }
    }
}
impl std::error::Error for ReuseError {}

/// Offline-testable orchestration with no login/provision/store-write callbacks.
///
/// `prepare` must open only existing local resources, without downloading or
/// provisioning. It runs after successful slot/session validation and returns a
/// transport factory whose deadline starts only when called after confirmation.
/// The terminal asks for exactly one issuance before anisette generation and HTTP.
/// The authenticated token is checked and dropped, never returned or printed.
///
/// # Errors
/// Returns the first [`ReuseError`]; no retry, repair, or persistence occurs.
pub fn run_with<C: StoreConnector, T: Transport, A: AnisetteProvider, F: FnOnce() -> T>(
    terminal: &mut impl SecureTerminal,
    state: &SlotState,
    connector: &C,
    prepare: impl FnOnce() -> Result<(F, A), ReuseError>,
    clock: &(impl Fn() -> Result<EpochMillis, TokenError> + Sync),
) -> Result<(), ReuseError> {
    let slot = state.load().map_err(|_: SlotStateError| ReuseError::Slot)?;
    let session = block_on(async {
        let store = connector.connect().await.map_err(|_| ReuseError::Store)?;
        store
            .load(&slot)
            .await
            .map_err(|_| ReuseError::Store)?
            .ok_or(ReuseError::MissingSession)
    })?;
    let input = session.token_input().map_err(ReuseError::Token)?;
    let (make_transport, anisette) = prepare()?;
    terminal
        .notice("One Xcode authentication token will be issued using the stored GSA session.")
        .map_err(|_| ReuseError::Declined)?;
    terminal
        .notice("This does not access CloudKit. Effects on previously issued tokens are unknown.")
        .map_err(|_| ReuseError::Declined)?;
    terminal.notice("No login, 2FA, downloads, provisioning, or keyring writes; failures stop without retry.").map_err(|_| ReuseError::Declined)?;
    let answer = terminal
        .prompt_visible("Type ISSUE to make this one token request: ")
        .map_err(|_| ReuseError::Declined)?;
    if answer.as_str() != "ISSUE" {
        return Err(ReuseError::Declined);
    }
    drop(answer);
    let transport = make_transport();
    let token = block_on(TokenClient::new(&transport, &anisette).issue(
        input,
        Service::XcodeAuthentication,
        clock,
    ))
    .map_err(ReuseError::Token)?;
    drop(token);
    Ok(())
}

struct NoDownloads;
impl ArtifactSource for NoDownloads {
    fn fetch(
        &self,
        _: &SourceUrl,
        _: &Limits,
    ) -> Result<coffer_bootstrap::source::FetchedArtifact, FetchError> {
        Err(FetchError::Unreachable)
    }
}
type TransportFactory = fn() -> GsaTransport<crate::transport::UreqExchange>;

fn prepare_local() -> Result<(TransportFactory, CofferAnisetteProvider), ReuseError> {
    let paths = BootstrapPaths::from_environment().map_err(|_| ReuseError::LocalState)?;
    let installation = Bootstrap::new(paths.clone(), NoDownloads)
        .and_then(|b| b.installed())
        .map_err(|_| ReuseError::LocalState)?
        .ok_or(ReuseError::LocalState)?;
    let executable = std::env::current_exe().map_err(|_| ReuseError::LocalState)?;
    let helper = helper_beside(&executable)
        .filter(|path| helper_is_usable(path))
        .ok_or(ReuseError::LocalState)?;
    let context = AnisetteContext::new("UTC".to_owned(), "en_US".to_owned())
        .map_err(|_| ReuseError::LocalState)?;
    let provider = CofferAnisetteProvider::open_existing(
        &installation,
        &paths,
        helper,
        Duration::from_secs(60),
        context,
    )
    .map_err(|_| ReuseError::LocalState)?;
    Ok((start_transport, provider))
}

fn start_transport() -> GsaTransport<crate::transport::UreqExchange> {
    GsaTransport::production(Deadlines::starting_now(
        Duration::from_secs(60),
        Duration::from_secs(300),
    ))
}

/// Runs one interactive developer-only token issuance with production adapters.
///
/// Never invoke from CI or without separate live-account authorization. This
/// function does not create missing state or obtain passwords/2FA credentials.
///
/// # Errors
/// See [`ReuseError`]. Failure preserves the session and never triggers fallback.
pub fn run(terminal: &mut impl SecureTerminal) -> Result<(), ReuseError> {
    let state = SlotState::from_environment().map_err(|_| ReuseError::Slot)?;
    run_with(
        terminal,
        &state,
        &SecretServiceConnector,
        prepare_local,
        &EpochMillis::now,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::terminal::TerminalError;
    use coffer_protocol::{
        anisette::{AnisetteData, AnisetteError},
        entropy::{Entropy, EntropyError},
        transport::{Request, Response, TransportError},
    };
    use coffer_service::{
        DeleteOutcome, FakeOperation, FakeSessionStore, ReusableSession, SessionSlot, StoreError,
    };
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    use zeroize::Zeroizing;

    struct Shared(Arc<FakeSessionStore>);
    impl SessionStore for Shared {
        async fn check_available(&self) -> Result<(), StoreError> {
            self.0.check_available().await
        }
        async fn load(&self, slot: &SessionSlot) -> Result<Option<ReusableSession>, StoreError> {
            self.0.load(slot).await
        }
        async fn replace(&self, _: &SessionSlot, _: &ReusableSession) -> Result<(), StoreError> {
            panic!("reuse must never write")
        }
        async fn delete(&self, _: &SessionSlot) -> Result<DeleteOutcome, StoreError> {
            panic!("reuse must never delete")
        }
    }
    struct Connector {
        backend: Arc<FakeSessionStore>,
        calls: AtomicUsize,
    }
    impl StoreConnector for Connector {
        type Store = Shared;
        async fn connect(&self) -> Result<Shared, StoreError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(Shared(Arc::clone(&self.backend)))
        }
    }
    struct Fixed;
    impl Entropy for Fixed {
        fn fill(&self, bytes: &mut [u8]) -> Result<(), EntropyError> {
            bytes.fill(0x42);
            Ok(())
        }
    }
    impl AnisetteProvider for Fixed {
        async fn anisette(&self) -> Result<AnisetteData, AnisetteError> {
            Ok(AnisetteData {
                one_time_password: "SYNTHETIC".into(),
                machine_id: "SYNTHETIC".into(),
                routing_info: "1".into(),
                local_user_id: "SYNTHETIC".into(),
                serial_number: "0".into(),
                client_info: "SYNTHETIC".into(),
                device_id: "SYNTHETIC".into(),
                client_time: "2026-09-11T00:00:00Z".into(),
                time_zone: "UTC".into(),
                locale: "en_US".into(),
            })
        }
    }
    struct Http {
        calls: Arc<AtomicUsize>,
        status: u16,
    }
    impl Transport for Http {
        async fn send(&self, request: Request) -> Result<Response, TransportError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let parsed = plist::Value::from_reader_xml(std::io::Cursor::new(
                request.body.as_ref().unwrap().as_slice(),
            ))
            .unwrap();
            let body = parsed.as_dictionary().unwrap()["Request"]
                .as_dictionary()
                .unwrap();
            assert_eq!(body["o"].as_string(), Some("apptokens"));
            assert_eq!(body["u"].as_string(), Some("SYNTHETIC-ADSID"));
            assert_eq!(body["t"].as_string(), Some("SYNTHETIC-IDMS"));
            assert_eq!(body["c"].as_data(), Some([0, 255, 128, 1].as_slice()));
            Ok(Response::new(
                self.status,
                include_bytes!("../tests/fixtures/apptokens-response.plist").to_vec(),
            ))
        }
    }
    struct Terminal {
        answer: &'static str,
        output: String,
        prompts: usize,
        simulated_confirmation_time: Option<Arc<AtomicUsize>>,
    }
    impl SecureTerminal for Terminal {
        fn notice(&mut self, text: &'static str) -> Result<(), TerminalError> {
            self.output.push_str(text);
            Ok(())
        }
        fn prompt_visible(&mut self, _: &'static str) -> Result<Zeroizing<String>, TerminalError> {
            self.prompts += 1;
            if let Some(clock) = &self.simulated_confirmation_time {
                clock.store(301, Ordering::SeqCst);
            }
            Ok(Zeroizing::new(self.answer.to_owned()))
        }
        fn prompt_hidden(&mut self, _: &'static str) -> Result<Zeroizing<String>, TerminalError> {
            panic!("reuse must never ask for a password or code")
        }
    }
    fn terminal(answer: &'static str) -> Terminal {
        Terminal {
            answer,
            output: String::new(),
            prompts: 0,
            simulated_confirmation_time: None,
        }
    }
    fn connector() -> Connector {
        Connector {
            backend: Arc::new(FakeSessionStore::new()),
            calls: AtomicUsize::new(0),
        }
    }
    fn session() -> ReusableSession {
        ReusableSession::new(
            "SYNTHETIC-ADSID".into(),
            "SYNTHETIC-IDMS".into(),
            core::array::from_fn(|i| i as u8),
            vec![0, 255, 128, 1],
        )
        .unwrap()
    }
    type HttpFactory = fn() -> Http;

    fn no_prepare() -> Result<(HttpFactory, Fixed), ReuseError> {
        panic!("invalid state must stop before local/HTTP adapters")
    }

    #[test]
    fn missing_slot_at_each_level_creates_nothing_and_never_connects() {
        for level in 0..4 {
            let root = tempfile::tempdir().unwrap();
            let home = root.path().join("state");
            if level >= 1 {
                std::fs::create_dir(&home).unwrap();
            }
            if level >= 2 {
                std::fs::create_dir(home.join("coffer")).unwrap();
            }
            if level >= 3 {
                std::fs::create_dir(home.join("coffer/live-auth")).unwrap();
            }
            use std::os::unix::fs::PermissionsExt;
            for dir in [home.join("coffer"), home.join("coffer/live-auth")] {
                if dir.exists() {
                    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).unwrap();
                }
            }
            let state = SlotState::under_state_home(&home);
            let connector = connector();
            let mut terminal = terminal("ISSUE");
            assert_eq!(
                run_with(&mut terminal, &state, &connector, no_prepare, &|| {
                    EpochMillis::new(1)
                }),
                Err(ReuseError::Slot)
            );
            assert_eq!(connector.calls.load(Ordering::SeqCst), 0);
            assert_eq!(terminal.prompts, 0);
            assert_eq!(home.exists(), level >= 1);
            assert_eq!(home.join("coffer").exists(), level >= 2);
            assert_eq!(home.join("coffer/live-auth").exists(), level >= 3);
            assert!(!home.join("coffer/live-auth/profile-slot").exists());
            assert!(connector.backend.operations().is_empty());
        }
    }

    #[test]
    fn missing_locked_duplicate_corrupt_and_invalid_session_stop_before_prepare() {
        for error in [
            None,
            Some(StoreError::Locked),
            Some(StoreError::Duplicate),
            Some(StoreError::Corrupt),
        ] {
            let root = tempfile::tempdir().unwrap();
            let state = SlotState::under_state_home(root.path());
            state.load_or_create(&Fixed).unwrap();
            let connector = connector();
            if let Some(e) = &error {
                connector.backend.fail_next(FakeOperation::Load, e.clone());
            }
            assert_eq!(
                run_with(
                    &mut terminal("ISSUE"),
                    &state,
                    &connector,
                    no_prepare,
                    &|| EpochMillis::new(1)
                ),
                Err(if error.is_none() {
                    ReuseError::MissingSession
                } else {
                    ReuseError::Store
                })
            );
            assert_eq!(connector.calls.load(Ordering::SeqCst), 1);
            assert!(
                connector
                    .backend
                    .operations()
                    .iter()
                    .all(|(op, _)| *op == FakeOperation::Load)
            );
        }
        let root = tempfile::tempdir().unwrap();
        let state = SlotState::under_state_home(root.path());
        let (slot, _) = state.load_or_create(&Fixed).unwrap();
        let connector = connector();
        let invalid =
            ReusableSession::new("bad\naccount".into(), "idms".into(), [0; 32], vec![1]).unwrap();
        block_on(connector.backend.replace(&slot, &invalid)).unwrap();
        assert_eq!(
            run_with(
                &mut terminal("ISSUE"),
                &state,
                &connector,
                no_prepare,
                &|| EpochMillis::new(1)
            ),
            Err(ReuseError::Token(TokenError::InvalidSession))
        );
    }

    #[test]
    fn stored_v1_roundtrip_new_connections_and_clients_issue_once_without_writing() {
        let root = tempfile::tempdir().unwrap();
        let state = SlotState::under_state_home(root.path());
        let (slot, _) = state.load_or_create(&Fixed).unwrap();
        let writer = connector();
        block_on(writer.backend.replace(&slot, &session())).unwrap();
        let reader = Connector {
            backend: Arc::clone(&writer.backend),
            calls: AtomicUsize::new(0),
        };
        drop(writer);
        let slot_path = root.path().join("coffer/live-auth/profile-slot");
        let initial = std::fs::read(&slot_path).unwrap();
        for (status, now, expected) in [
            (200, 1, Ok(())),
            (401, 1, Err(ReuseError::Token(TokenError::Rejected))),
            (
                200,
                2_000_000_000_000,
                Err(ReuseError::Token(TokenError::Expired)),
            ),
        ] {
            let calls = Arc::new(AtomicUsize::new(0));
            let mut terminal = terminal("ISSUE");
            assert_eq!(
                run_with(
                    &mut terminal,
                    &state,
                    &reader,
                    || Ok((
                        || Http {
                            calls: Arc::clone(&calls),
                            status
                        },
                        Fixed
                    )),
                    &|| EpochMillis::new(now)
                ),
                expected
            );
            assert_eq!(calls.load(Ordering::SeqCst), 1);
            assert_eq!(terminal.prompts, 1);
            assert!(!terminal.output.contains("SYNTHETIC"));
        }
        assert_eq!(reader.calls.load(Ordering::SeqCst), 3);
        assert_eq!(std::fs::read(slot_path).unwrap(), initial);
        let operations = reader.backend.operations();
        assert_eq!(
            operations
                .iter()
                .filter(|(op, _)| *op == FakeOperation::Replace)
                .count(),
            1
        );
        assert_eq!(
            operations
                .iter()
                .filter(|(op, _)| *op == FakeOperation::Delete)
                .count(),
            0
        );
        assert_eq!(
            operations
                .iter()
                .filter(|(op, _)| *op == FakeOperation::Load)
                .count(),
            3
        );
        assert_eq!(
            block_on(reader.backend.load(&slot))
                .unwrap()
                .unwrap()
                .expose_idms_token(),
            "SYNTHETIC-IDMS"
        );
    }

    #[test]
    fn declined_or_missing_local_resources_do_not_send() {
        let root = tempfile::tempdir().unwrap();
        let state = SlotState::under_state_home(root.path());
        let (slot, _) = state.load_or_create(&Fixed).unwrap();
        let connector = connector();
        block_on(connector.backend.replace(&slot, &session())).unwrap();
        let calls = Arc::new(AtomicUsize::new(0));
        assert_eq!(
            run_with(
                &mut terminal("NO"),
                &state,
                &connector,
                || Ok((
                    || Http {
                        calls: Arc::clone(&calls),
                        status: 200
                    },
                    Fixed
                )),
                &|| EpochMillis::new(1)
            ),
            Err(ReuseError::Declined)
        );
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        let mut terminal = terminal("ISSUE");
        assert_eq!(
            run_with(
                &mut terminal,
                &state,
                &connector,
                || -> Result<(HttpFactory, Fixed), _> { Err(ReuseError::LocalState) },
                &|| EpochMillis::new(1)
            ),
            Err(ReuseError::LocalState)
        );
        assert_eq!(terminal.prompts, 0);
    }
    #[test]
    fn confirmation_wait_does_not_consume_the_http_deadline() {
        struct TimedHttp {
            clock: Arc<AtomicUsize>,
            deadline: usize,
            inner: Http,
        }
        impl Transport for TimedHttp {
            async fn send(&self, request: Request) -> Result<Response, TransportError> {
                if self.clock.load(Ordering::SeqCst) >= self.deadline {
                    return Err(TransportError::Timeout);
                }
                self.inner.send(request).await
            }
        }
        let root = tempfile::tempdir().unwrap();
        let state = SlotState::under_state_home(root.path());
        let (slot, _) = state.load_or_create(&Fixed).unwrap();
        let connector = connector();
        block_on(connector.backend.replace(&slot, &session())).unwrap();
        let clock = Arc::new(AtomicUsize::new(0));
        let calls = Arc::new(AtomicUsize::new(0));
        let mut terminal = terminal("ISSUE");
        terminal.simulated_confirmation_time = Some(Arc::clone(&clock));
        assert_eq!(
            run_with(
                &mut terminal,
                &state,
                &connector,
                || {
                    assert_eq!(
                        clock.load(Ordering::SeqCst),
                        0,
                        "preflight precedes confirmation"
                    );
                    Ok((
                        || TimedHttp {
                            clock: Arc::clone(&clock),
                            deadline: clock.load(Ordering::SeqCst) + 300,
                            inner: Http {
                                calls: Arc::clone(&calls),
                                status: 200,
                            },
                        },
                        Fixed,
                    ))
                },
                &|| EpochMillis::new(1),
            ),
            Ok(())
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn m1_login_preserves_unauthorized_stage_without_answering_a_challenge() {
        use coffer_protocol::{
            auth::{AuthErrorKind, AuthStage, Authenticator},
            secret::{AccountName, Password},
        };
        let transport = GsaTransport::new(
            crate::transport::tests::FakeExchange::new(vec![Ok((
                401,
                b"SYNTHETIC-UNAUTHORIZED".to_vec(),
            ))]),
            Deadlines::starting_now(Duration::from_secs(5), Duration::from_secs(5)),
        );
        let auth = Authenticator::new(transport, Fixed, Fixed);
        let error = block_on(
            auth.login(
                AccountName::new("synthetic@example.invalid".into()).unwrap(),
                Password::new("SYNTHETIC-PASSWORD".into()),
            )
            .authenticate(),
        )
        .unwrap_err();
        assert_eq!(error.stage(), AuthStage::SrpInit);
        assert!(matches!(error.kind(), AuthErrorKind::HttpStatus(401)));
        assert_eq!(auth.transport().exchange_ref().calls(), 1);
        assert!(!format!("{error:?} {error}").contains("SYNTHETIC"));
    }
}
