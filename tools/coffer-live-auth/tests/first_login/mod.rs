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

//! Synthetic first-login tests: no op process, Apple or desktop keyring.
use super::*;
use crate::{
    flow::{CodeStep, LoginResult, LoginStep, ReauthStep, SecondFactorStep},
    op_input::{OpInputError, OpTerminal},
    terminal::TerminalError,
};
use coffer_protocol::{
    entropy::EntropyError,
    secret::{AccountName, Password, VerificationCode},
};
use coffer_service::{FakeOperation, FakeSessionStore};
use std::sync::{Arc, Mutex};
use zeroize::Zeroizing;

#[derive(Default)]
struct Cell<T>(Mutex<T>);
impl<T: Copy> Cell<T> {
    fn get(&self) -> T {
        *self.0.lock().unwrap()
    }
    fn set(&self, value: T) {
        *self.0.lock().unwrap() = value;
    }
}

#[derive(Default)]
struct Observations {
    events: Mutex<Vec<&'static str>>,
    fetched: Cell<usize>,
    connections: Cell<usize>,
    writes: Cell<usize>,
    backend: FakeSessionStore,
    fail_at: Cell<Option<&'static str>>,
    two_factor: Cell<bool>,
    csv_wrong: Cell<bool>,
    fetch_error: Cell<bool>,
    decline: Cell<bool>,
    cancel: Cell<bool>,
    cancel_otp: Cell<bool>,
    occupied_at_write: Cell<bool>,
    fail_reload: Cell<bool>,
    validation_error: Cell<Option<&'static str>>,
}
struct Fixed(u8);
impl Entropy for Fixed {
    fn fill(&self, bytes: &mut [u8]) -> Result<(), EntropyError> {
        bytes.fill(self.0);
        Ok(())
    }
}
struct Connector(Arc<Observations>);
struct Connection(Arc<Observations>, usize);
impl StoreConnector for Connector {
    type Store = Connection;
    async fn connect(&self) -> Result<Self::Store, StoreError> {
        let id = self.0.connections.get() + 1;
        self.0.connections.set(id);
        Ok(Connection(self.0.clone(), id))
    }
}
impl SessionStore for Connection {
    async fn check_available(&self) -> Result<(), StoreError> {
        self.0.backend.check_available().await
    }
    async fn load(&self, slot: &SessionSlot) -> Result<Option<ReusableSession>, StoreError> {
        match self.1 {
            1 => self.0.events.lock().unwrap().push("preflight"),
            2 => {
                self.0.events.lock().unwrap().push("recheck");
                if self.0.occupied_at_write.get() {
                    self.0
                        .backend
                        .replace(slot, &session("SYNTHETIC-OTHER"))
                        .await?;
                }
            }
            3 => {
                self.0.events.lock().unwrap().push("reload");
                if self.0.fail_reload.get() {
                    return Err(StoreError::Corrupt);
                }
            }
            _ => panic!("unexpected connection"),
        }
        self.0.backend.load(slot).await
    }
    async fn replace(
        &self,
        slot: &SessionSlot,
        session: &ReusableSession,
    ) -> Result<(), StoreError> {
        assert_eq!(self.1, 2, "only writer connection can write");
        self.0.writes.set(self.0.writes.get() + 1);
        self.0.events.lock().unwrap().push("write");
        self.0.backend.replace(slot, session).await
    }
    async fn delete(&self, _: &SessionSlot) -> Result<DeleteOutcome, StoreError> {
        panic!("no cleanup or rollback")
    }
}
fn session(id: &str) -> ReusableSession {
    ReusableSession::new(id.into(), "SYNTHETIC-TOKEN".into(), [42; 32], vec![42]).unwrap()
}
struct Terminal(Arc<Observations>);
impl SecureTerminal for Terminal {
    fn notice(&mut self, text: &'static str) -> Result<(), TerminalError> {
        assert!(!text.contains("synthetic@example.invalid"));
        assert!(!text.contains("synthetic-password"));
        Ok(())
    }
    fn prompt_visible(&mut self, label: &'static str) -> Result<Zeroizing<String>, TerminalError> {
        assert_eq!(label, CONFIRM);
        assert_eq!(self.0.fetched.get(), 0);
        self.0.events.lock().unwrap().push("confirm");
        if self.0.cancel.get() {
            return Err(TerminalError::Interrupted);
        }
        Ok(Zeroizing::new(
            if self.0.decline.get() {
                "NO"
            } else {
                "LOGIN AND STORE"
            }
            .into(),
        ))
    }
    fn prompt_hidden(&mut self, label: &'static str) -> Result<Zeroizing<String>, TerminalError> {
        assert_eq!(label, "Verification code (6 digits, not echoed): ");
        self.0.events.lock().unwrap().push("otp");
        if self.0.cancel_otp.get() {
            return Err(TerminalError::Interrupted);
        }
        Ok(Zeroizing::new("123456".into()))
    }
}
struct Steps(Arc<Observations>);
impl Steps {
    fn visit(&self, stage: &'static str) -> Result<(), std::io::Error> {
        self.0.events.lock().unwrap().push(stage);
        if self.0.fail_at.get() == Some(stage) {
            Err(std::io::Error::other("SYNTHETIC-PRIVATE-SOURCE"))
        } else {
            Ok(())
        }
    }
}
impl LoginStep for Steps {
    type Session = ReusableSession;
    type SecondFactor = Self;
    type Error = std::io::Error;
    async fn authenticate(
        self,
        account: AccountName,
        password: Password,
    ) -> Result<LoginResult<Self>, Self::Error> {
        assert_eq!(account.as_str(), "synthetic@example.invalid");
        drop(password);
        self.visit("auth")?;
        if self.0.two_factor.get() {
            Ok(LoginResult::SecondFactorRequired(self))
        } else {
            Ok(LoginResult::Authenticated(session("SYNTHETIC-NEW")))
        }
    }
}
impl SecondFactorStep for Steps {
    type Session = ReusableSession;
    type Error = std::io::Error;
    type CodeRequested = Self;
    async fn request_trusted_device_code(self) -> Result<Self, Self::Error> {
        self.visit("push")?;
        Ok(self)
    }
}
impl CodeStep for Steps {
    type Session = ReusableSession;
    type Error = std::io::Error;
    type Verified = Self;
    async fn submit_code(self, _: VerificationCode) -> Result<Self, Self::Error> {
        self.visit("submit")?;
        Ok(self)
    }
}
impl ReauthStep for Steps {
    type Session = ReusableSession;
    type Error = std::io::Error;
    async fn reauthenticate(self, password: Password) -> Result<Self::Session, Self::Error> {
        drop(password);
        self.visit("reauth")?;
        Ok(session("SYNTHETIC-NEW"))
    }
}
fn execute(
    state: &SlotState,
    seen: Arc<Observations>,
    fail_prepare: bool,
) -> Result<(), FirstLoginError> {
    let loader_seen = seen.clone();
    let mut input = OpTerminal::test_first_login(Terminal(seen.clone()), move || {
        assert_eq!(
            loader_seen.events.lock().unwrap().as_slice(),
            ["preflight", "prepare", "validate", "confirm"]
        );
        loader_seen.fetched.set(loader_seen.fetched.get() + 1);
        loader_seen.events.lock().unwrap().push("fetch");
        if loader_seen.fetch_error.get() {
            return Err(OpInputError::Interrupted);
        }
        Ok(Zeroizing::new(if loader_seen.csv_wrong.get() {
            b"wrong@example.invalid,synthetic-password".to_vec()
        } else {
            b"synthetic@example.invalid,synthetic-password".to_vec()
        }))
    });
    let result = run_with(
        &mut input,
        state,
        &Fixed(42),
        &Connector(seen.clone()),
        || {
            seen.events.lock().unwrap().push("prepare");
            if fail_prepare {
                Err(FirstLoginError::at("local preflight", "missing"))
            } else {
                Ok(())
            }
        },
        |()| {
            seen.events.lock().unwrap().push("validate");
            match seen.validation_error.get() {
                Some(cause) => Err(FirstLoginError::at("local preflight", cause)),
                None => Ok(()),
            }
        },
        |(), terminal| {
            block_on(run_login(Steps(seen.clone()), terminal))
                .map(|result| result.session)
                .map_err(|_| FirstLoginError::at("synthetic login", "stopped without retry"))
        },
    );
    input.finish();
    assert!(input.prompt_hidden("Password (not echoed): ").is_err());
    result
}
fn profile(root: &std::path::Path) -> SlotState {
    SlotState::under_state_home(root)
        .new_profile("test-profile")
        .unwrap()
}

#[test]
fn successful_branches_preserve_old_slot_and_reload_new_connection() {
    for two_factor in [false, true] {
        let root = tempfile::tempdir().unwrap();
        let old = SlotState::under_state_home(root.path());
        let (old_slot, _) = old.load_or_create(&Fixed(7)).unwrap();
        let old_path = root.path().join("coffer/live-auth/profile-slot");
        let before = std::fs::read(&old_path).unwrap();
        let seen = Arc::new(Observations::default());
        block_on(seen.backend.replace(&old_slot, &session("SYNTHETIC-OLD"))).unwrap();
        seen.two_factor.set(two_factor);
        let state = profile(root.path());
        assert_eq!(execute(&state, seen.clone(), false), Ok(()));
        assert_eq!(seen.fetched.get(), 1);
        assert_eq!(seen.connections.get(), 3);
        assert_eq!(seen.writes.get(), 1);
        let mut expected = vec![
            "preflight",
            "prepare",
            "validate",
            "confirm",
            "fetch",
            "auth",
        ];
        if two_factor {
            expected.extend(["push", "otp", "submit", "reauth"]);
        }
        expected.extend(["recheck", "write", "reload"]);
        assert_eq!(*seen.events.lock().unwrap(), expected);
        assert_eq!(std::fs::read(old_path).unwrap(), before);
        assert_eq!(
            block_on(seen.backend.load(&old_slot))
                .unwrap()
                .unwrap()
                .expose_account_id(),
            "SYNTHETIC-OLD"
        );
        let new_slot = state.load().unwrap();
        assert_ne!(old_slot, new_slot);
        assert_eq!(
            block_on(seen.backend.load(&new_slot))
                .unwrap()
                .unwrap()
                .expose_account_id(),
            "SYNTHETIC-NEW"
        );
        let again = Arc::new(Observations::default());
        assert!(execute(&state, again.clone(), false).is_err());
        assert!(again.events.lock().unwrap().is_empty());
        assert_eq!(again.connections.get(), 0);
    }
}

#[test]
fn preflight_decline_cancel_wrong_account_and_fetch_failure_never_authenticate() {
    for scenario in 0..9 {
        let root = tempfile::tempdir().unwrap();
        let state = profile(root.path());
        let seen = Arc::new(Observations::default());
        match scenario {
            0 => seen
                .backend
                .fail_next(FakeOperation::CheckAvailable, StoreError::Locked),
            1 => seen
                .backend
                .fail_next(FakeOperation::Load, StoreError::Corrupt),
            2 => {
                block_on(seen.backend.replace(
                    &SessionSlot::from_random_bytes([42; 16]),
                    &session("SYNTHETIC-OTHER"),
                ))
                .unwrap();
            }
            3 => {} // missing local state
            4 => seen.decline.set(true),
            5 => seen.cancel.set(true),
            6 => seen.csv_wrong.set(true),
            7 => seen.fetch_error.set(true),
            8 => seen
                .backend
                .fail_next(FakeOperation::Load, StoreError::Duplicate),
            _ => unreachable!(),
        }
        let error = execute(&state, seen.clone(), scenario == 3).unwrap_err();
        assert!(!format!("{error:?} {error}").contains("SYNTHETIC"));
        assert!(!seen.events.lock().unwrap().contains(&"auth"));
        assert_eq!(seen.writes.get(), 0);
        assert_eq!(
            seen.fetched.get(),
            usize::from(scenario == 6 || scenario == 7)
        );
        assert!(
            state.load().is_ok(),
            "reservation remains after failure/decline"
        );
        assert!(state.create_new(&Fixed(99)).is_err());
    }
}

#[test]
fn every_auth_failure_stops_at_that_stage_without_retry_or_write() {
    for stage in ["auth", "push", "submit", "reauth"] {
        let root = tempfile::tempdir().unwrap();
        let seen = Arc::new(Observations::default());
        seen.two_factor.set(true);
        seen.fail_at.set(Some(stage));
        assert!(execute(&profile(root.path()), seen.clone(), false).is_err());
        assert_eq!(seen.fetched.get(), 1);
        assert_eq!(seen.writes.get(), 0);
        assert_eq!(seen.events.lock().unwrap().last(), Some(&stage));
        assert_eq!(
            seen.events
                .lock()
                .unwrap()
                .iter()
                .filter(|&&event| event == stage)
                .count(),
            1
        );
    }
}

#[test]
fn persistence_rechecks_occupancy_and_never_retries_write_or_reload() {
    for scenario in 0..3 {
        let root = tempfile::tempdir().unwrap();
        let state = profile(root.path());
        let seen = Arc::new(Observations::default());
        match scenario {
            0 => seen.occupied_at_write.set(true),
            1 => seen
                .backend
                .fail_next(FakeOperation::Replace, StoreError::TimedOut),
            2 => seen.fail_reload.set(true),
            _ => unreachable!(),
        }
        let error = execute(&state, seen.clone(), false).unwrap_err();
        assert!(error.persistence_started);
        assert_eq!(seen.fetched.get(), 1);
        assert_eq!(seen.writes.get(), usize::from(scenario != 0));
        assert_eq!(seen.connections.get(), if scenario == 2 { 3 } else { 2 });
        if scenario == 0 {
            assert_eq!(
                block_on(seen.backend.load(&state.load().unwrap()))
                    .unwrap()
                    .unwrap()
                    .expose_account_id(),
                "SYNTHETIC-OTHER"
            );
        }
    }
}

#[test]
fn interrupted_otp_stops_before_submission_and_never_fetches_again() {
    let root = tempfile::tempdir().unwrap();
    let seen = Arc::new(Observations::default());
    seen.two_factor.set(true);
    seen.cancel_otp.set(true);
    assert!(execute(&profile(root.path()), seen.clone(), false).is_err());
    assert_eq!(seen.fetched.get(), 1);
    assert_eq!(seen.writes.get(), 0);
    assert_eq!(seen.events.lock().unwrap().last(), Some(&"otp"));
}

#[test]
fn occupied_corrupt_or_symlink_profile_stops_before_store_prepare_and_fetch() {
    for scenario in 0..4 {
        let root = tempfile::tempdir().unwrap();
        let state = profile(root.path());
        state.create_new(&Fixed(7)).unwrap();
        let directory = root.path().join("coffer/live-auth/profiles/test-profile");
        let file = directory.join("profile-slot");
        match scenario {
            0 => {}
            1 => std::fs::write(&file, b"synthetic-corruption").unwrap(),
            2 => std::fs::remove_file(&file).unwrap(),
            3 => {
                std::fs::remove_file(&file).unwrap();
                std::fs::remove_dir(&directory).unwrap();
                std::os::unix::fs::symlink(root.path(), &directory).unwrap();
            }
            _ => unreachable!(),
        }
        let seen = Arc::new(Observations::default());
        assert!(execute(&state, seen.clone(), false).is_err());
        assert!(seen.events.lock().unwrap().is_empty());
        assert_eq!(seen.connections.get(), 0);
        assert_eq!(seen.fetched.get(), 0);
    }
}

#[test]
fn invalid_active_provisioning_stops_before_confirmation_and_fetch() {
    // open_existing can succeed for these states; generation must still run
    // during preflight before any private input or authentication operation.
    for cause in ["not provisioned", "incompatible active binding"] {
        let root = tempfile::tempdir().unwrap();
        let state = profile(root.path());
        let seen = Arc::new(Observations::default());
        seen.validation_error.set(Some(cause));
        let error = execute(&state, seen.clone(), false).unwrap_err();
        assert_eq!(error.labels(), ("local preflight", cause));
        assert_eq!(
            *seen.events.lock().unwrap(),
            ["preflight", "prepare", "validate"]
        );
        assert_eq!(seen.fetched.get(), 0);
        assert_eq!(seen.writes.get(), 0);
        assert!(state.load().is_ok());
        assert!(state.create_new(&Fixed(99)).is_err());
    }
}
