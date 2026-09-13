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

//! Synthetic harness tests; no real session constructor, network, or keyring.
use super::*;
use crate::{
    flow::{CodeStep, LoginResult, LoginStep, ReauthStep, SecondFactorStep},
    terminal::TerminalError,
};
use coffer_protocol::{
    entropy::{Entropy, EntropyError},
    secret::{AccountName, Password, VerificationCode},
    transport::{Request, Response, TransportError},
};
use coffer_service::{
    DelegateStoreError, DeleteOutcome, FakeDelegateOperation, FakeDelegateStore, FakeOperation,
    FakeSessionStore, SessionSlot, StoreError,
};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};

const ADSID: &str = "SYNTHETIC-ADSID";
const CLIENT: &str = "SYNTHETIC-CLIENT";
fn session(adsid: &str) -> ReusableSession {
    ReusableSession::new(adsid.into(), "SYNTHETIC-IDMS".into(), [42; 32], vec![42]).unwrap()
}
struct Fixed;
impl Entropy for Fixed {
    fn fill(&self, out: &mut [u8]) -> Result<(), EntropyError> {
        out.fill(42);
        Ok(())
    }
}
impl AnisetteProvider for Fixed {
    async fn anisette(&self) -> Result<AnisetteData, AnisetteError> {
        Ok(AnisetteData {
            one_time_password: "SYNTHETIC-OTP".into(),
            machine_id: "SYNTHETIC-MACHINE".into(),
            routing_info: "1".into(),
            local_user_id: "SYNTHETIC-LOCAL".into(),
            serial_number: "0".into(),
            client_info: "SYNTHETIC-INFO".into(),
            device_id: CLIENT.into(),
            client_time: "2026-09-13T00:00:00Z".into(),
            time_zone: "UTC".into(),
            locale: "en_US".into(),
        })
    }
}
struct Http {
    calls: Arc<AtomicUsize>,
    fail: bool,
    rejection: bool,
}
impl Transport for Http {
    async fn send(&self, request: Request) -> Result<Response, TransportError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        crate::delegate_transport::validate_request(&request)?;
        let parsed =
            plist::Value::from_reader_xml(std::io::Cursor::new(request.body.as_ref().unwrap()))
                .unwrap();
        assert_eq!(
            parsed.as_dictionary().unwrap()["client-id"].as_string(),
            Some(CLIENT)
        );
        if self.fail {
            return Err(TransportError::Other {
                detail: "SYNTHETIC-SECRET-ERROR".into(),
            });
        }
        if self.rejection {
            return Ok(Response::new(
                200,
                b"<plist><dict><key>status</key><integer>1</integer></dict></plist>".to_vec(),
            ));
        }
        Ok(Response::new(
            200,
            include_bytes!(
                "../../../../crates/coffer-protocol/tests/fixtures/delegate/success.plist"
            )
            .to_vec(),
        ))
    }
}
fn value(adsid: &str, client: &str, changed: Option<usize>) -> StoredDelegateCredentials {
    struct ResponseOnly(Option<usize>);
    impl Transport for ResponseOnly {
        async fn send(&self, _: Request) -> Result<Response, TransportError> {
            let mut xml = include_str!(
                "../../../../crates/coffer-protocol/tests/fixtures/delegate/success.plist"
            )
            .to_owned();
            if let Some(field) = self.0 {
                let original = [
                    "000123-synthetic-dsid",
                    "SYNTHETIC-MME-TOKEN",
                    "SYNTHETIC-CLOUDKIT-TOKEN",
                ][field];
                xml = xml.replace(original, "SYNTHETIC-CHANGED");
            }
            Ok(Response::new(200, xml.into_bytes()))
        }
    }
    let input = DelegateMaterialRef::new(
        "synthetic@example.invalid",
        adsid,
        Some("SYNTHETIC-PET"),
        ClientIdRef::new(client).unwrap(),
    )
    .unwrap();
    let issued =
        block_on(DelegateClient::new(&ResponseOnly(changed), &Fixed).issue(input)).unwrap();
    StoredDelegateCredentials::from_issued(&issued, DelegateBindingRef::new(adsid, client).unwrap())
        .unwrap()
}

#[derive(Default)]
struct Backend {
    gsa: FakeSessionStore,
    delegate: FakeDelegateStore,
    connections: AtomicUsize,
    events: Mutex<Vec<&'static str>>,
    reload: Mutex<Option<usize>>,
    gsa_reload: Mutex<Option<bool>>,
    fail_connect: AtomicUsize,
}
struct Connector(Arc<Backend>);
struct Connection {
    backend: Arc<Backend>,
    id: usize,
}
impl StoreConnector for Connector {
    type Store = Connection;
    async fn connect(&self) -> Result<Connection, StoreError> {
        let id = self.0.connections.fetch_add(1, Ordering::SeqCst) + 1;
        if id == self.0.fail_connect.load(Ordering::SeqCst) {
            return Err(StoreError::Locked);
        }
        Ok(Connection {
            backend: self.0.clone(),
            id,
        })
    }
}
impl SessionStore for Connection {
    async fn check_available(&self) -> Result<(), StoreError> {
        self.backend.gsa.check_available().await
    }
    async fn load(&self, slot: &SessionSlot) -> Result<Option<ReusableSession>, StoreError> {
        self.backend.events.lock().unwrap().push("gsa load");
        if self.id == 3 {
            match *self.backend.gsa_reload.lock().unwrap() {
                Some(true) => return Ok(Some(session("SYNTHETIC-OTHER"))),
                Some(false) => return Ok(None),
                None => (),
            }
        }
        self.backend.gsa.load(slot).await
    }
    async fn replace(&self, slot: &SessionSlot, value: &ReusableSession) -> Result<(), StoreError> {
        self.backend.events.lock().unwrap().push("gsa write");
        self.backend.gsa.replace(slot, value).await
    }
    async fn delete(&self, _: &SessionSlot) -> Result<DeleteOutcome, StoreError> {
        panic!("no deletes")
    }
}
impl DelegateStore for Connection {
    async fn load_delegate(
        &self,
        slot: &SessionSlot,
        expected: DelegateBindingRef<'_>,
    ) -> Result<Option<StoredDelegateCredentials>, DelegateStoreError> {
        self.backend.events.lock().unwrap().push("delegate load");
        if self.id == 5 {
            let changed = *self.backend.reload.lock().unwrap();
            match changed {
                Some(0..=2) => return Ok(Some(value(ADSID, CLIENT, changed))),
                Some(3) => return Ok(None),
                Some(4) => return Err(DelegateStoreError::Corrupt),
                _ => (),
            }
        }
        self.backend
            .delegate
            .new_connection()
            .load_delegate(slot, expected)
            .await
    }
    async fn replace_delegate(
        &self,
        slot: &SessionSlot,
        expected: DelegateBindingRef<'_>,
        value: &StoredDelegateCredentials,
    ) -> Result<(), DelegateStoreError> {
        self.backend.events.lock().unwrap().push("delegate write");
        self.backend
            .delegate
            .new_connection()
            .replace_delegate(slot, expected, value)
            .await
    }
}
struct Terminal {
    answer: &'static str,
    hidden: usize,
    visible: usize,
    notices: usize,
    interrupt_notice: Option<usize>,
    interrupt_hidden: Option<usize>,
    interrupt_visible: bool,
    output: String,
}
impl Default for Terminal {
    fn default() -> Self {
        Self {
            answer: "LOGIN AND ISSUE",
            hidden: 0,
            visible: 0,
            notices: 0,
            interrupt_notice: None,
            interrupt_hidden: None,
            interrupt_visible: false,
            output: String::new(),
        }
    }
}
impl SecureTerminal for Terminal {
    fn notice(&mut self, line: &'static str) -> Result<(), TerminalError> {
        self.notices += 1;
        if self.interrupt_notice == Some(self.notices) {
            return Err(TerminalError::Interrupted);
        }
        self.output.push_str(line);
        Ok(())
    }
    fn prompt_visible(&mut self, _: &'static str) -> Result<Zeroizing<String>, TerminalError> {
        self.visible += 1;
        if self.interrupt_visible {
            return Err(TerminalError::Interrupted);
        }
        Ok(Zeroizing::new(self.answer.into()))
    }
    fn prompt_hidden(&mut self, _: &'static str) -> Result<Zeroizing<String>, TerminalError> {
        self.hidden += 1;
        if self.interrupt_hidden == Some(self.hidden) {
            return Err(TerminalError::Interrupted);
        }
        Ok(Zeroizing::new(
            if self.hidden == 1 {
                "synthetic@example.invalid"
            } else {
                "SYNTHETIC-PASSWORD"
            }
            .into(),
        ))
    }
}
struct Fresh {
    adsid: Zeroizing<String>,
    pet: Option<Zeroizing<String>>,
}
impl FreshSession for Fresh {
    fn adsid(&self) -> &str {
        &self.adsid
    }
    fn material<'a>(
        &'a self,
        client: ClientIdRef<'a>,
    ) -> Result<DelegateMaterialRef<'a>, DelegateError> {
        DelegateMaterialRef::new(
            "synthetic@example.invalid",
            &self.adsid,
            self.pet.as_deref().map(String::as_str),
            client,
        )
    }
    fn reusable(&self) -> ReusableSession {
        session(&self.adsid)
    }
}
struct Login {
    fresh: Fresh,
    backend: Arc<Backend>,
    fail: bool,
}
impl LoginStep for Login {
    type Session = Fresh;
    type SecondFactor = NoSecondFactor;
    type Error = std::io::Error;
    async fn authenticate(
        self,
        _: AccountName,
        _: Password,
    ) -> Result<LoginResult<Self>, Self::Error> {
        self.backend.events.lock().unwrap().push("login");
        if self.fail {
            return Err(std::io::Error::other("SYNTHETIC-SECRET-ERROR"));
        }
        Ok(LoginResult::Authenticated(self.fresh))
    }
}
struct NoSecondFactor;
impl SecondFactorStep for NoSecondFactor {
    type Session = Fresh;
    type Error = std::io::Error;
    type CodeRequested = Self;
    async fn request_trusted_device_code(self) -> Result<Self, Self::Error> {
        panic!("synthetic flow requires no 2FA")
    }
}
impl CodeStep for NoSecondFactor {
    type Session = Fresh;
    type Error = std::io::Error;
    type Verified = Self;
    async fn submit_code(self, _: VerificationCode) -> Result<Self, Self::Error> {
        panic!("synthetic flow requires no code")
    }
}
impl ReauthStep for NoSecondFactor {
    type Session = Fresh;
    type Error = std::io::Error;
    async fn reauthenticate(self, _: Password) -> Result<Fresh, Self::Error> {
        panic!("synthetic flow requires no reauth")
    }
}
struct Case {
    root: tempfile::TempDir,
    connector: Connector,
    terminal: Terminal,
    calls: Arc<AtomicUsize>,
    mismatch: bool,
    no_pet: bool,
    login_failure: bool,
    delegate_failure: bool,
    delegate_rejection: bool,
}
impl Case {
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        let state = SlotState::under_state_home(root.path());
        let (slot, _) = state.load_or_create(&Fixed).unwrap();
        let backend = Arc::new(Backend::default());
        block_on(backend.gsa.replace(&slot, &session(ADSID))).unwrap();
        Self {
            root,
            connector: Connector(backend),
            terminal: Terminal::default(),
            calls: Arc::new(AtomicUsize::new(0)),
            mismatch: false,
            no_pet: false,
            login_failure: false,
            delegate_failure: false,
            delegate_rejection: false,
        }
    }
    fn slot(&self) -> SessionSlot {
        SlotState::under_state_home(self.root.path())
            .load()
            .unwrap()
    }
    fn run(&mut self) -> Result<DelegateOutcome, DelegateHarnessError> {
        let backend = self.connector.0.clone();
        run_with(
            &mut self.terminal,
            &SlotState::under_state_home(self.root.path()),
            &self.connector,
            || {
                backend.events.lock().unwrap().push("prepare");
                Ok(Fixed)
            },
            |_, terminal| {
                block_on(run_login(
                    Login {
                        fresh: Fresh {
                            adsid: Zeroizing::new(
                                if self.mismatch {
                                    "SYNTHETIC-OTHER"
                                } else {
                                    ADSID
                                }
                                .into(),
                            ),
                            pet: if self.no_pet {
                                None
                            } else {
                                Some(Zeroizing::new("SYNTHETIC-PET".into()))
                            },
                        },
                        backend: backend.clone(),
                        fail: self.login_failure,
                    },
                    terminal,
                ))
                .map(|outcome| outcome.session)
                .map_err(|_| {
                    DelegateHarnessError::at("synthetic login", "failed or interrupted", UNCHANGED)
                })
            },
            || {
                backend
                    .events
                    .lock()
                    .unwrap()
                    .push("delegate transport starts");
                Http {
                    calls: self.calls.clone(),
                    fail: self.delegate_failure,
                    rejection: self.delegate_rejection,
                }
            },
        )
    }
    fn events(&self) -> Vec<&'static str> {
        self.connector.0.events.lock().unwrap().clone()
    }
    fn no_login_or_write(&self) {
        assert_eq!(self.terminal.hidden, 0);
        assert_eq!(self.calls.load(Ordering::SeqCst), 0);
        assert!(
            !self
                .events()
                .iter()
                .any(|e| matches!(*e, "login" | "gsa write" | "delegate write"))
        );
    }
}

#[test]
fn declined_confirmation_cannot_authorize_fresh_login() {
    for answer in ["NO", "", "login and issue", "LOGIN AND ISSUE "] {
        let mut case = Case::new();
        case.terminal.answer = answer;
        assert_eq!(case.run().unwrap_err().labels().0, "confirmation");
        assert_eq!(case.terminal.visible, 1);
        case.no_login_or_write();
    }
}
#[test]
fn missing_corrupt_slot_never_connects_or_prompts() {
    for corrupt in [false, true] {
        let mut case = Case::new();
        let path = case.root.path().join("coffer/live-auth/profile-slot");
        if corrupt {
            std::fs::write(path, b"SYNTHETIC-CORRUPT").unwrap();
        } else {
            std::fs::remove_file(path).unwrap();
        }
        assert_eq!(case.run().unwrap_err().labels().0, "profile slot");
        assert_eq!(case.connector.0.connections.load(Ordering::SeqCst), 0);
        case.no_login_or_write();
    }
}
#[test]
fn missing_locked_duplicate_corrupt_unknown_gsa_stops_before_prepare() {
    for failure in [
        None,
        Some(StoreError::Locked),
        Some(StoreError::Duplicate),
        Some(StoreError::Corrupt),
        Some(StoreError::UnsupportedVersion(99)),
    ] {
        let mut case = Case::new();
        if let Some(error) = failure {
            case.connector.0.gsa.fail_next(FakeOperation::Load, error);
        } else {
            block_on(case.connector.0.gsa.delete(&case.slot())).unwrap();
        }
        assert_eq!(case.run().unwrap_err().labels().0, "GSA preflight");
        assert!(!case.events().contains(&"prepare"));
        case.no_login_or_write();
    }
}
#[test]
fn existing_delegate_stops_without_confirmation_login_or_write() {
    let mut case = Case::new();
    block_on(case.connector.0.delegate.replace_delegate(
        &case.slot(),
        DelegateBindingRef::new(ADSID, CLIENT).unwrap(),
        &value(ADSID, CLIENT, None),
    ))
    .unwrap();
    assert_eq!(case.run(), Ok(DelegateOutcome::AlreadyStored));
    assert_eq!(case.terminal.visible, 0);
    case.no_login_or_write();
}
#[test]
fn delegate_preflight_failures_never_prompt_or_login() {
    for error in [
        DelegateStoreError::Locked,
        DelegateStoreError::Duplicate,
        DelegateStoreError::Corrupt,
        DelegateStoreError::UnsupportedVersion,
        DelegateStoreError::BindingMismatch,
        DelegateStoreError::Unavailable,
    ] {
        let mut case = Case::new();
        case.connector
            .0
            .delegate
            .fail_next(FakeDelegateOperation::Search, error)
            .unwrap();
        assert_eq!(case.run().unwrap_err().labels().0, "delegate preflight");
        assert_eq!(case.terminal.visible, 0);
        case.no_login_or_write();
    }
}
#[test]
fn mismatch_missing_pet_and_login_failure_preserve_both_items() {
    for (mismatch, no_pet, login_failure, stage) in [
        (true, false, false, "fresh account binding"),
        (false, true, false, "delegate input"),
        (false, false, true, "synthetic login"),
    ] {
        let mut case = Case::new();
        case.mismatch = mismatch;
        case.no_pet = no_pet;
        case.login_failure = login_failure;
        let error = case.run().unwrap_err();
        assert_eq!(error.labels().0, stage);
        if no_pet {
            assert!(error.labels().1.contains("PET"));
        }
        assert_eq!(error.retention_label(), UNCHANGED);
        assert_eq!(case.calls.load(Ordering::SeqCst), 0);
        assert!(!case.events().contains(&"gsa write"));
        assert!(!case.events().contains(&"delegate write"));
        assert_eq!(case.events().iter().filter(|e| **e == "login").count(), 1);
    }
}
#[test]
fn gsa_store_failure_never_starts_delegate_deadline_or_issuance() {
    let mut case = Case::new();
    case.connector
        .0
        .gsa
        .fail_next(FakeOperation::Replace, StoreError::Locked);
    assert_eq!(case.run().unwrap_err().retention_label(), GSA_UNCERTAIN);
    assert_eq!(case.calls.load(Ordering::SeqCst), 0);
    assert!(!case.events().contains(&"delegate transport starts"));
}
#[test]
fn delegate_failure_stops_once_after_gsa_roundtrip() {
    let mut case = Case::new();
    case.delegate_failure = true;
    let error = case.run().unwrap_err();
    assert_eq!(error.labels().0, "delegate issuance");
    assert_eq!(error.retention_label(), GSA_STORED);
    assert_eq!(case.calls.load(Ordering::SeqCst), 1);
    assert!(!case.events().contains(&"delegate write"));
    assert!(!format!("{error:?} {error}").contains("SYNTHETIC"));
}
#[test]
fn delegate_protocol_rejection_is_distinct_from_transport_failure() {
    let mut transport = Case::new();
    transport.delegate_failure = true;
    let transport_error = transport.run().unwrap_err();
    let mut rejected = Case::new();
    rejected.delegate_rejection = true;
    let rejected_error = rejected.run().unwrap_err();
    assert_ne!(transport_error.labels().1, rejected_error.labels().1);
    for (case, error) in [(&transport, &transport_error), (&rejected, &rejected_error)] {
        assert_eq!(error.retention_label(), GSA_STORED);
        assert_eq!(case.calls.load(Ordering::SeqCst), 1);
        assert!(!case.events().contains(&"delegate write"));
        assert!(!format!("{error:?} {error}").contains("SYNTHETIC"));
    }
}
#[test]
fn delegate_store_failure_is_not_retried() {
    let mut case = Case::new();
    case.connector
        .0
        .delegate
        .fail_after_write(DelegateStoreError::TimedOut)
        .unwrap();
    let error = case.run().unwrap_err();
    assert_eq!(error.labels().0, "delegate persistence");
    assert_eq!(error.retention_label(), BOTH_UNCERTAIN);
    assert_eq!(case.calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        case.events()
            .iter()
            .filter(|e| **e == "delegate write")
            .count(),
        1
    );
    assert_eq!(case.connector.0.connections.load(Ordering::SeqCst), 4);
}
#[test]
fn success_uses_five_connections_and_starts_delegate_after_gsa_reload() {
    let mut case = Case::new();
    assert_eq!(case.run(), Ok(DelegateOutcome::Stored));
    assert_eq!(case.connector.0.connections.load(Ordering::SeqCst), 5);
    assert_eq!(case.calls.load(Ordering::SeqCst), 1);
    assert_eq!(case.terminal.hidden, 2);
    assert_eq!(
        case.events(),
        [
            "gsa load",
            "prepare",
            "delegate load",
            "login",
            "gsa write",
            "gsa load",
            "delegate transport starts",
            "delegate write",
            "delegate load"
        ]
    );
    assert!(!case.terminal.output.contains("SYNTHETIC"));
}
#[test]
fn fresh_connection_missing_corrupt_or_different_fields_fail_without_retry() {
    for changed in 0..5 {
        let mut case = Case::new();
        *case.connector.0.reload.lock().unwrap() = Some(changed);
        let error = case.run().unwrap_err();
        assert_eq!(error.labels().0, "delegate reload");
        assert_eq!(case.calls.load(Ordering::SeqCst), 1);
        assert_eq!(case.connector.0.connections.load(Ordering::SeqCst), 5);
    }
}
#[test]
fn equality_covers_all_five_fields() {
    let original = value(ADSID, CLIENT, None);
    assert!(delegates_equal(&original, &value(ADSID, CLIENT, None)));
    assert!(!delegates_equal(
        &original,
        &value("SYNTHETIC-OTHER", CLIENT, None)
    ));
    assert!(!delegates_equal(
        &original,
        &value(ADSID, "SYNTHETIC-OTHER", None)
    ));
    for field in 0..3 {
        assert!(!delegates_equal(
            &original,
            &value(ADSID, CLIENT, Some(field))
        ));
    }
}
#[test]
fn all_terminal_interruptions_stop_at_the_current_stage() {
    let mut success = Case::new();
    success.run().unwrap();
    assert_eq!(success.terminal.notices, 11);
    for index in 1..=success.terminal.notices {
        let mut case = Case::new();
        case.terminal.interrupt_notice = Some(index);
        let error = case.run().unwrap_err();
        assert!(!format!("{error:?} {error}").contains("SYNTHETIC"));
        assert_eq!(case.calls.load(Ordering::SeqCst), usize::from(index == 11));
        assert!(!case.events().contains(&"delegate write"));
        if index <= 10 {
            assert!(!case.events().contains(&"delegate transport starts"));
        }
        if index <= 5 {
            assert_eq!(case.terminal.hidden, 0);
            case.no_login_or_write();
        }
        if index == 10 {
            assert_eq!(error.retention_label(), GSA_UNCERTAIN);
        } else if index == 11 {
            assert_eq!(error.retention_label(), GSA_STORED);
        }
        assert!(case.events().iter().filter(|e| **e == "login").count() <= 1);
    }
    for hidden in 1..=2 {
        let mut case = Case::new();
        case.terminal.interrupt_hidden = Some(hidden);
        assert!(case.run().is_err());
        assert_eq!(case.calls.load(Ordering::SeqCst), 0);
        assert!(!case.events().contains(&"login"));
    }
    let mut case = Case::new();
    case.terminal.interrupt_visible = true;
    assert!(case.run().is_err());
    case.no_login_or_write();
}
#[test]
fn connection_failures_stop_without_fallback() {
    for connection in 1..=5 {
        let mut case = Case::new();
        case.connector
            .0
            .fail_connect
            .store(connection, Ordering::SeqCst);
        assert!(case.run().is_err());
        assert_eq!(
            case.connector.0.connections.load(Ordering::SeqCst),
            connection
        );
        assert_eq!(
            case.calls.load(Ordering::SeqCst),
            usize::from(connection >= 4)
        );
    }
}

#[test]
fn gsa_reload_missing_or_mismatched_prevents_delegate() {
    for mismatch in [false, true] {
        let mut case = Case::new();
        *case.connector.0.gsa_reload.lock().unwrap() = Some(mismatch);
        assert_eq!(case.run().unwrap_err().labels().0, "GSA persistence");
        assert_eq!(case.calls.load(Ordering::SeqCst), 0);
        assert!(!case.events().contains(&"delegate transport starts"));
    }
}

#[test]
fn unavailable_or_locked_keyring_never_reads_items_or_prompts() {
    for error in [
        StoreError::Locked,
        StoreError::Unavailable(coffer_service::UnavailableReason::NoSessionBus),
    ] {
        let mut case = Case::new();
        case.connector
            .0
            .gsa
            .fail_next(FakeOperation::CheckAvailable, error);
        assert_eq!(case.run().unwrap_err().labels().0, "GSA preflight");
        assert!(case.events().is_empty());
        case.no_login_or_write();
    }
}

#[test]
fn missing_local_state_or_invalid_anisette_stops_before_confirmation() {
    struct Provider(bool);
    impl AnisetteProvider for Provider {
        async fn anisette(&self) -> Result<AnisetteData, AnisetteError> {
            if self.0 {
                return Err(AnisetteError::Unavailable {
                    detail: "SYNTHETIC-SECRET-ERROR".into(),
                });
            }
            let mut data = Fixed.anisette().await?;
            data.device_id = "SYNTHETIC\nINVALID".into();
            Ok(data)
        }
    }
    for mode in 0..3 {
        let mut case = Case::new();
        let result = run_with(
            &mut case.terminal,
            &SlotState::under_state_home(case.root.path()),
            &case.connector,
            || {
                if mode == 0 {
                    Err(DelegateHarnessError::at(
                        "local preflight",
                        "unavailable",
                        UNCHANGED,
                    ))
                } else {
                    Ok(Provider(mode == 1))
                }
            },
            |_, _| -> Result<Fresh, DelegateHarnessError> {
                panic!("local preflight must stop before login")
            },
            || -> Http { panic!("local preflight must stop before transport") },
        );
        let error = result.unwrap_err();
        assert!(!format!("{error:?} {error}").contains("SYNTHETIC"));
        assert!(std::error::Error::source(&error).is_none());
        assert_eq!(case.terminal.visible, 0);
        case.no_login_or_write();
    }
}
