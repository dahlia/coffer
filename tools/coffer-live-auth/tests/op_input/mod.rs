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

//! Synthetic CSV, child-process, and prompt-routing regression tests.
use super::*;

#[test]
fn csv_decodes_exactly_two_fields_and_preserves_whitespace() {
    let value = decode_csv(b"synthetic@example.invalid,  synthetic password  \n")
        .ok()
        .unwrap();
    assert_eq!(value.username.as_str(), "synthetic@example.invalid");
    assert_eq!(value.password.as_str(), "  synthetic password  ");
    let value = decode_csv(b"\"synthetic,account\",\"a\"\"b,c\"\n")
        .ok()
        .unwrap();
    assert_eq!(value.username.as_str(), "synthetic,account");
    assert_eq!(value.password.as_str(), "a\"b,c");
}

#[test]
fn csv_rejects_missing_extra_malformed_and_control_fields() {
    for bytes in [
        b"".as_slice(),
        b"a",
        b"a,",
        b",b",
        b"a,b,c",
        b"a,b\na,b\n",
        b"a,b\n\n",
        b"a,b\r\n",
        b"a,\"b",
        b"a,\"b\"suffix",
        b"a,b\"c",
        b"a,\"b\nc\"",
        b"a,b\0c",
        b"a,b\tc",
        b"a,\xff",
        "a,b\u{85}c".as_bytes(),
    ] {
        assert!(decode_csv(bytes).is_err());
    }
}

#[test]
fn csv_enforces_decoded_byte_limits() {
    let exact = format!(
        "{},{}\n",
        "a".repeat(MAX_INPUT_LEN),
        "b".repeat(MAX_INPUT_LEN)
    );
    assert!(decode_csv(exact.as_bytes()).is_ok());
    let long = format!("a,{}\n", "b".repeat(MAX_INPUT_LEN + 1));
    assert!(decode_csv(long.as_bytes()).is_err());
    let escaped = format!("a,\"{}\"\n", "\"\"".repeat(MAX_INPUT_LEN));
    assert_eq!(
        decode_csv(escaped.as_bytes()).ok().unwrap().password.len(),
        MAX_INPUT_LEN
    );
}

use std::cell::Cell;
use std::io::Cursor;
use std::rc::Rc;

fn selector() -> ItemSelector {
    parse_selector(Zeroizing::new(
        b"abcdefghijklmnopqrstuvwxyz\nsynthetic@example.invalid\n".to_vec(),
    ))
    .ok()
    .unwrap()
}
fn fake_command(script: &str) -> Command {
    let mut command = Command::new("/bin/sh");
    command
        .args(["-c", script])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    command
}

#[test]
fn selector_requires_exact_frame_and_bounded_control_free_utf8_account() {
    for account in [
        "a".to_owned(),
        "é".repeat(128),
        "a".repeat(256),
        " synthetic ".to_owned(),
    ] {
        let frame = format!("abcdefghijklmnopqrstuvwxyz\n{account}\n");
        let selector = parse_selector(Zeroizing::new(frame.into_bytes()))
            .ok()
            .unwrap();
        assert_eq!(selector.expected_account(), account.as_bytes());
    }
    for bytes in [
        b"".as_slice(),
        b"abcdefghijklmnopqrstuvwxyz",
        b"abcdefghijklmnopqrstuvwxyz\n",
        b"abcdefghijklmnopqrstuvwxyz\n\n",
        b"abcdefghijklmnopqrstuvwxy\na\n",
        b"abcdefghijklmnopqrstuvwxyzx\na\n",
        b"Abcdefghijklmnopqrstuvwxyz\na\n",
        b"abcdefghijklmnopqrstuvwx/z\na\n",
        b"abcdefghijklmnopqrstuvwxyz\r\na\n",
        b"abcdefghijklmnopqrstuvwxyz\na",
        b"abcdefghijklmnopqrstuvwxyz\na\n\n",
        b"abcdefghijklmnopqrstuvwxyz\na\r\n",
        b"abcdefghijklmnopqrstuvwxyz\na\0b\n",
        b"abcdefghijklmnopqrstuvwxyz\na\tb\n",
        b"abcdefghijklmnopqrstuvwxyz\n\xff\n",
        "abcdefghijklmnopqrstuvwxyz\na\u{85}b\n".as_bytes(),
    ] {
        assert_eq!(
            parse_selector(Zeroizing::new(bytes.to_vec())).err(),
            Some(OpInputError::Selector)
        );
    }
    for account in ["a".repeat(257), "é".repeat(129)] {
        let frame = format!("abcdefghijklmnopqrstuvwxyz\n{account}\n");
        assert_eq!(
            parse_selector(Zeroizing::new(frame.into_bytes())).err(),
            Some(OpInputError::Selector)
        );
    }
}

#[test]
fn anonymous_pipe_check_refuses_files_and_named_fifos() {
    let regular = tempfile::tempfile().unwrap();
    assert_eq!(verify_anonymous_pipe(&regular), Err(OpInputError::Selector));
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("synthetic-fifo");
    rustix::fs::mknodat(
        rustix::fs::CWD,
        &path,
        FileType::Fifo,
        rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
        0,
    )
    .unwrap();
    let fifo = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .unwrap();
    assert_eq!(verify_anonymous_pipe(&fifo), Err(OpInputError::Selector));
    // The shell only emits a synthetic selector; no op/secret-store execution.
    let mut child = ChildOwner(
        fake_command("printf 'abcdefghijklmnopqrstuvwxyz\nsynthetic@example.invalid\n'")
            .spawn()
            .unwrap(),
    );
    let stdout = child.0.stdout.take().unwrap();
    let mut pipe = File::from(stdout.as_fd().try_clone_to_owned().unwrap());
    assert!(verify_anonymous_pipe(&pipe).is_ok());
    assert!(read_selector_pipe(&mut pipe, Instant::now() + Duration::from_secs(2)).is_ok());
}

#[test]
fn reader_stops_at_one_over_limit_and_never_reads_the_suffix() {
    let mut reader = Cursor::new(vec![b'x'; 1000]);
    assert_eq!(
        read_bounded(
            &mut reader,
            MAX_FRAME_LEN,
            Instant::now() + Duration::from_secs(1),
            None
        )
        .unwrap_err(),
        OpInputError::TooLarge
    );
    assert_eq!(reader.position(), 285);
    let mut exact = Cursor::new(vec![b'x'; MAX_OUTPUT_LEN]);
    let value = read_bounded(
        &mut exact,
        MAX_OUTPUT_LEN,
        Instant::now() + Duration::from_secs(1),
        None,
    )
    .unwrap();
    assert_eq!(value.len(), MAX_OUTPUT_LEN);
    assert_eq!(value.capacity(), MAX_OUTPUT_LEN + 1);
}

#[test]
fn reader_checks_deadline_before_read_and_sanitizes_io_errors() {
    struct NeverRead;
    impl Read for NeverRead {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            panic!("deadline must precede read")
        }
    }
    assert_eq!(
        read_bounded(&mut NeverRead, 10, Instant::now(), None).unwrap_err(),
        OpInputError::Timeout
    );
    struct Failed;
    impl Read for Failed {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::other("synthetic-sensitive-upstream"))
        }
    }
    let error = read_bounded(
        &mut Failed,
        10,
        Instant::now() + Duration::from_secs(1),
        None,
    )
    .unwrap_err();
    assert_eq!(error, OpInputError::Process);
    assert!(!format!("{error:?} {error}").contains("synthetic-sensitive-upstream"));
}

#[test]
fn production_command_has_only_fixed_nonsecret_arguments_and_no_env_assignments() {
    let command = op_command();
    assert_eq!(command.get_program(), "/usr/bin/op");
    assert_eq!(
        command.get_args().collect::<Vec<_>>(),
        [
            "item",
            "get",
            "-",
            "--fields",
            "label=username,label=password",
            "--reveal",
            "--debug=false",
            "--cache=false",
            "--format",
            "human-readable",
            "--no-color",
        ]
    );
    assert_eq!(command.get_envs().count(), 0);
}

#[test]
fn child_receives_selection_only_via_stdin_then_eof_and_stderr_is_discarded() {
    let _serial = crate::terminal::tests::SIGNAL_TESTS
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let mut command = fake_command(
        r#"
        IFS= read -r selected || exit 2
        [ "$selected" = abcdefghijklmnopqrstuvwxyz ] || exit 3
        if IFS= read -r extra; then exit 4; fi
        printf 'synthetic-sensitive-stderr' >&2
        printf 'synthetic@example.invalid,"p,a"\n'
    "#,
    );
    let output = run_child(&mut command, &selector(), Duration::from_secs(2)).unwrap();
    let value = decode_csv(&output).unwrap();
    assert_eq!(value.username.as_str(), "synthetic@example.invalid");
    assert_eq!(value.password.as_str(), "p,a");
    assert!(!std::str::from_utf8(&output).unwrap().contains("stderr"));
}

#[test]
fn valid_output_with_nonzero_exit_is_rejected() {
    let _serial = crate::terminal::tests::SIGNAL_TESTS
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let mut command = fake_command("read selected; printf 'synthetic,password\\n'; exit 7");
    assert_eq!(
        run_child(&mut command, &selector(), Duration::from_secs(2)).unwrap_err(),
        OpInputError::Exit
    );
}

const CANCELLATION_CHILD_ENV: &str = "COFFER_TEST_OP_CANCELLATION";

#[test]
fn cancellation_child_role() {
    use crate::terminal::{TerminalDevice, TtyDevice};

    let Some(pid_path) = std::env::var_os(CANCELLATION_CHILD_ENV) else {
        return;
    };
    let tty_path = std::env::var_os("COFFER_TEST_OP_TTY").unwrap();
    let tty = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(tty_path)
        .unwrap();
    let mut device = TtyDevice::from_file(tty);
    // Install the real terminal handlers and finish hidden mode before op.
    device.disable_echo().unwrap();
    device.restore_echo().unwrap();
    let mut command = fake_command(
        "read selected; if [ \"$2\" = closed ]; then exec 1>&-; fi; printf '%s' \"$$\" > \"$1\"; exec /bin/sleep 60",
    );
    command
        .arg("synthetic-op")
        .arg(pid_path)
        .arg(std::env::var_os("COFFER_TEST_OP_STDOUT").unwrap());
    let _ = run_child(&mut command, &selector(), Duration::from_secs(30));
    panic!("the deferred termination signal must end the subprocess");
}

#[test]
fn parent_only_sigterm_kills_and_reaps_op_before_default_termination() {
    use rustix::process::{Pid, Signal, kill_process, test_kill_process};
    use rustix::pty::{OpenptFlags, grantpt, openpt, ptsname, unlockpt};
    use std::os::unix::process::ExitStatusExt;

    // Exercise both polling phases: reading stdout and waiting after EOF.
    for stdout in ["open", "closed"] {
        let directory = tempfile::tempdir().unwrap();
        let pid_path = directory.path().join("synthetic-child-pid");
        let master = openpt(OpenptFlags::RDWR | OpenptFlags::NOCTTY).unwrap();
        grantpt(&master).unwrap();
        unlockpt(&master).unwrap();
        let slave = ptsname(&master, Vec::new()).unwrap();
        let mut parent = ChildOwner(
            Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "op_input::tests::cancellation_child_role",
                    "--test-threads",
                    "1",
                ])
                .env(CANCELLATION_CHILD_ENV, &pid_path)
                .env("COFFER_TEST_OP_TTY", slave.to_str().unwrap())
                .env("COFFER_TEST_OP_STDOUT", stdout)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap(),
        );
        let deadline = Instant::now() + Duration::from_secs(5);
        let child_pid = loop {
            if let Ok(text) = std::fs::read_to_string(&pid_path)
                && let Ok(raw) = text.parse::<i32>()
            {
                break Pid::from_raw(raw).unwrap();
            }
            assert!(
                parent.0.try_wait().unwrap().is_none(),
                "parent exited before readiness"
            );
            assert!(
                Instant::now() < deadline,
                "synthetic child readiness timed out"
            );
            std::thread::sleep(POLL_INTERVAL);
        };
        // Also clean the synthetic descendant if the regression fails.
        struct Descendant(Pid);
        impl Drop for Descendant {
            fn drop(&mut self) {
                let _ = kill_process(self.0, Signal::KILL);
            }
        }
        let _descendant = Descendant(child_pid);
        assert_eq!(test_kill_process(child_pid), Ok(()));
        kill_process(Pid::from_child(&parent.0), Signal::TERM).unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        let status = loop {
            if let Some(status) = parent.0.try_wait().unwrap() {
                break status;
            }
            assert!(Instant::now() < deadline, "parent ignored cancellation");
            std::thread::sleep(POLL_INTERVAL);
        };
        assert_eq!(status.signal(), Some(signal_hook::consts::SIGTERM));
        // ESRCH excludes both a live child and an unreaped zombie: cleanup
        // must finish before the parent takes the signal's default action.
        assert_eq!(test_kill_process(child_pid), Err(rustix::io::Errno::SRCH));
    }
}

#[test]
fn timeout_and_oversize_kill_and_reap_the_owned_child() {
    for (script, expected) in [
        ("read selected; exec /bin/sleep 60", OpInputError::Timeout),
        (
            "read selected; while :; do printf xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx; done",
            OpInputError::TooLarge,
        ),
        (
            "read selected; exec 1>&-; exec /bin/sleep 60",
            OpInputError::Timeout,
        ),
    ] {
        let mut child = ChildOwner(fake_command(script).spawn().unwrap());
        let pid = rustix::process::Pid::from_raw(i32::try_from(child.0.id()).unwrap()).unwrap();
        let budget = if expected == OpInputError::TooLarge {
            Duration::from_secs(2)
        } else {
            Duration::from_millis(100)
        };
        assert_eq!(
            read_child(&mut child.0, &selector(), Instant::now() + budget, None).unwrap_err(),
            expected
        );
        drop(child);
        assert_eq!(
            rustix::process::test_kill_process(pid),
            Err(rustix::io::Errno::SRCH)
        );
    }
}

#[derive(Default)]
struct ScriptTerminal {
    notices: Vec<&'static str>,
    hidden: Vec<&'static str>,
    visible: Vec<&'static str>,
    decline: bool,
    fail_visible: bool,
    fail_hidden: bool,
    login_only: bool,
}
impl SecureTerminal for ScriptTerminal {
    fn notice(&mut self, text: &'static str) -> Result<(), TerminalError> {
        self.notices.push(text);
        Ok(())
    }
    fn prompt_visible(&mut self, label: &'static str) -> Result<Zeroizing<String>, TerminalError> {
        self.visible.push(label);
        if self.fail_visible {
            return Err(TerminalError::Interrupted);
        }
        Ok(Zeroizing::new(
            if self.decline {
                "DECLINE"
            } else if self.login_only {
                "LOGIN AND STORE"
            } else {
                "LOGIN AND ISSUE"
            }
            .to_owned(),
        ))
    }
    fn prompt_hidden(&mut self, label: &'static str) -> Result<Zeroizing<String>, TerminalError> {
        self.hidden.push(label);
        if self.fail_hidden {
            return Err(TerminalError::Interrupted);
        }
        assert_eq!(label, OTP);
        Ok(Zeroizing::new("123456".to_owned()))
    }
}
fn terminal(fail_fetch: bool) -> (OpTerminal<ScriptTerminal>, Rc<Cell<usize>>) {
    let count = Rc::new(Cell::new(0));
    let called = count.clone();
    let mut terminal = OpTerminal::new(ScriptTerminal::default(), selector());
    terminal.loader = Some(Box::new(move |_| {
        called.set(called.get() + 1);
        if fail_fetch {
            return Err(OpInputError::Exit);
        }
        decode_csv(b"synthetic@example.invalid,synthetic-password\n")
    }));
    (terminal, count)
}
fn confirm(terminal: &mut OpTerminal<ScriptTerminal>) {
    terminal.prompt_visible(CONFIRM).unwrap();
}
fn initial_inputs(terminal: &mut OpTerminal<ScriptTerminal>) {
    confirm(terminal);
    assert_eq!(
        terminal.prompt_hidden(ACCOUNT).unwrap().as_str(),
        "synthetic@example.invalid"
    );
    assert_eq!(
        terminal.prompt_hidden(PASSWORD).unwrap().as_str(),
        "synthetic-password"
    );
}

#[test]
fn no_fetch_during_construction_preflight_notices_or_confirmation() {
    let (mut terminal, count) = terminal(false);
    terminal.notice("synthetic preflight").unwrap();
    assert_eq!(count.get(), 0);
    confirm(&mut terminal);
    assert_eq!(count.get(), 0);
    terminal.prompt_hidden(ACCOUNT).unwrap();
    assert_eq!(count.get(), 1);
}

#[test]
fn declined_interrupted_or_absent_confirmation_prevents_fetch_permanently() {
    for kind in 0..3 {
        let (mut terminal, count) = terminal(false);
        terminal.terminal.decline = kind == 0;
        terminal.terminal.fail_visible = kind == 1;
        if kind != 2 {
            let _ = terminal.prompt_visible(CONFIRM);
        }
        assert!(terminal.prompt_hidden(ACCOUNT).is_err());
        assert!(terminal.prompt_visible(CONFIRM).is_err());
        assert!(terminal.prompt_hidden(ACCOUNT).is_err());
        assert_eq!(count.get(), 0);
        assert!(terminal.selector.is_none());
    }
}

#[test]
fn exact_routes_and_post_2fa_password_reuse_fetch_once() {
    let (mut terminal, count) = terminal(false);
    initial_inputs(&mut terminal);
    assert!(terminal.selector.is_none());
    assert_eq!(terminal.prompt_hidden(OTP).unwrap().as_str(), "123456");
    assert_eq!(
        terminal.prompt_hidden(REAUTH).unwrap().as_str(),
        "synthetic-password"
    );
    assert!(terminal.password.is_none());
    assert_eq!(count.get(), 1);
    assert_eq!(terminal.terminal.hidden, [OTP]);
    assert_eq!(terminal.terminal.visible, [CONFIRM]);
    assert!(terminal.prompt_hidden(REAUTH).is_err());
    assert_eq!(count.get(), 1);
}

#[test]
fn no_2fa_path_wipes_password_before_storage_and_notice_text_matches_caching() {
    let (mut terminal, fetched) = terminal(false);
    confirm(&mut terminal);
    let calls = Rc::new(Cell::new(0));
    assert!(block_on(run_login(CountAnyLogin(calls.clone()), &mut terminal)).is_ok());
    assert_eq!(calls.get(), 1);
    assert_eq!(fetched.get(), 1);
    assert!(terminal.password.is_some());
    terminal.notice(ACCOUNT_NOTICE).unwrap();
    terminal.notice(REAUTH_NOTICE).unwrap();
    assert!(
        terminal
            .terminal
            .notices
            .iter()
            .all(|s| !s.contains("was not kept") && !s.contains("is typed"))
    );
    // Pin both the real persistence notice and its placement before any
    // connector/write: a changed store contract must not silently retain input.
    let source = include_str!("../../src/store.rs");
    let body = source
        .split("pub async fn persist_and_reload")
        .nth(1)
        .unwrap();
    let notice_start = body.find(".notice(\"").unwrap() + ".notice(\"".len();
    let notice_end = notice_start + body[notice_start..].find("\")?").unwrap();
    let actual_store_notice = &body[notice_start..notice_end];
    assert_eq!(actual_store_notice, STORE_NOTICE);
    assert!(notice_end < body.find("connector.connect()").unwrap());
    assert!(notice_end < body.find("writer.replace(").unwrap());
    terminal.notice(actual_store_notice).unwrap();
    assert!(terminal.password.is_none());
    assert!(terminal.prompt_hidden(OTP).is_err());
}

#[test]
fn unknown_duplicate_out_of_order_and_failed_otp_poison_and_wipe() {
    for (prefix, wrong) in [
        (vec![], PASSWORD),
        (vec![ACCOUNT], OTP),
        (vec![ACCOUNT], ACCOUNT),
        (vec![ACCOUNT, PASSWORD], REAUTH),
        (vec![ACCOUNT, PASSWORD], PASSWORD),
        (vec![ACCOUNT, PASSWORD, OTP], OTP),
        (vec![ACCOUNT, PASSWORD], "Unknown: "),
    ] {
        let (mut terminal, count) = terminal(false);
        confirm(&mut terminal);
        for label in prefix {
            terminal.prompt_hidden(label).unwrap();
        }
        assert!(terminal.prompt_hidden(wrong).is_err());
        assert!(terminal.password.is_none());
        assert!(terminal.selector.is_none());
        assert!(terminal.prompt_hidden(ACCOUNT).is_err());
        assert!(count.get() <= 1);
    }
    let (mut terminal, count) = terminal(false);
    initial_inputs(&mut terminal);
    terminal.terminal.fail_hidden = true;
    assert_eq!(
        terminal.prompt_hidden(OTP).unwrap_err(),
        TerminalError::Interrupted
    );
    assert!(terminal.password.is_none());
    assert!(terminal.prompt_hidden(REAUTH).is_err());
    assert_eq!(count.get(), 1);
}

#[test]
fn failed_fetch_never_supplies_an_account_and_cannot_retry() {
    let (mut terminal, count) = terminal(true);
    confirm(&mut terminal);
    assert!(terminal.prompt_hidden(ACCOUNT).is_err());
    assert!(terminal.prompt_hidden(PASSWORD).is_err());
    assert!(terminal.prompt_hidden(ACCOUNT).is_err());
    assert_eq!(count.get(), 1);
    assert!(terminal.password.is_none());
    assert!(terminal.selector.is_none());
    assert!(terminal.terminal.hidden.is_empty());
}

use crate::flow::{CodeStep, LoginResult, LoginStep, ReauthStep, SecondFactorStep, run_login};
use coffer_protocol::secret::{AccountName, Password, VerificationCode};
use futures_lite::future::block_on;

struct LoginScript {
    calls: Rc<Cell<usize>>,
    second_factor: bool,
}
impl LoginStep for LoginScript {
    type Session = ();
    type Error = io::Error;
    type SecondFactor = Self;
    async fn authenticate(
        self,
        account: AccountName,
        _password: Password,
    ) -> Result<LoginResult<Self>, io::Error> {
        assert_eq!(account.as_str(), "synthetic@example.invalid");
        self.calls.set(self.calls.get() + 1);
        if self.second_factor {
            Ok(LoginResult::SecondFactorRequired(self))
        } else {
            Ok(LoginResult::Authenticated(()))
        }
    }
}
impl SecondFactorStep for LoginScript {
    type Session = ();
    type Error = io::Error;
    type CodeRequested = Self;
    async fn request_trusted_device_code(self) -> Result<Self, io::Error> {
        self.calls.set(self.calls.get() + 1);
        Ok(self)
    }
}
impl CodeStep for LoginScript {
    type Session = ();
    type Error = io::Error;
    type Verified = Self;
    async fn submit_code(self, _code: VerificationCode) -> Result<Self, io::Error> {
        self.calls.set(self.calls.get() + 1);
        Ok(self)
    }
}
impl ReauthStep for LoginScript {
    type Session = ();
    type Error = io::Error;
    async fn reauthenticate(self, _password: Password) -> Result<(), io::Error> {
        self.calls.set(self.calls.get() + 1);
        Ok(())
    }
}

#[test]
fn existing_login_flow_uses_one_fetch_and_only_tty_otp_in_both_branches() {
    for second_factor in [false, true] {
        let (mut terminal, fetched) = terminal(false);
        confirm(&mut terminal);
        let calls = Rc::new(Cell::new(0));
        let login = LoginScript {
            calls: calls.clone(),
            second_factor,
        };
        assert!(block_on(run_login(login, &mut terminal)).is_ok());
        assert_eq!(calls.get(), if second_factor { 4 } else { 1 });
        assert_eq!(fetched.get(), 1);
        assert_eq!(terminal.terminal.hidden.len(), usize::from(second_factor));
        assert!(!terminal.terminal.notices.contains(&ACCOUNT_NOTICE));
        assert!(!terminal.terminal.notices.contains(&REAUTH_NOTICE));
        terminal.finish();
        assert!(terminal.password.is_none());
    }
}

#[test]
fn malformed_username_or_password_and_process_failure_prevent_initial_login() {
    for output in [
        b",password\n".as_slice(),
        b"synthetic@example.invalid,\n",
        b"synthetic@example.invalid,\xff\n",
    ] {
        let (mut terminal, _) = terminal(false);
        terminal.loader = Some(Box::new(move |_| decode_csv(output)));
        confirm(&mut terminal);
        let calls = Rc::new(Cell::new(0));
        let login = LoginScript {
            calls: calls.clone(),
            second_factor: false,
        };
        assert!(block_on(run_login(login, &mut terminal)).is_err());
        assert_eq!(calls.get(), 0);
        assert!(terminal.password.is_none());
    }
    let (mut terminal, fetched) = terminal(true);
    confirm(&mut terminal);
    let calls = Rc::new(Cell::new(0));
    let login = LoginScript {
        calls: calls.clone(),
        second_factor: false,
    };
    assert!(block_on(run_login(login, &mut terminal)).is_err());
    assert_eq!(calls.get(), 0);
    assert_eq!(fetched.get(), 1);
}

#[test]
fn prompt_literals_still_match_the_existing_delegate_confirmation() {
    // A prompt-contract change must be reviewed explicitly; it must never
    // silently send a cached password into a newly named prompt.
    let source = include_str!("../../src/delegate_harness.rs");
    assert!(source.contains(CONFIRM));
}

#[test]
fn selector_write_is_bounded_and_late_eof_is_refused() {
    let mut sink = Vec::new();
    write_selection(
        &mut sink,
        &selector(),
        Instant::now() + Duration::from_secs(1),
        None,
    )
    .unwrap();
    assert_eq!(sink, b"abcdefghijklmnopqrstuvwxyz\n");
    assert_eq!(
        write_selection(&mut sink, &selector(), Instant::now(), None),
        Err(OpInputError::Timeout)
    );
    struct LateEof;
    impl Read for LateEof {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            std::thread::sleep(Duration::from_millis(10));
            Ok(0)
        }
    }
    assert_eq!(
        read_bounded(
            &mut LateEof,
            10,
            Instant::now() + Duration::from_millis(1),
            None
        )
        .unwrap_err(),
        OpInputError::Timeout
    );
}

struct CountAnyLogin(Rc<Cell<usize>>);
impl LoginStep for CountAnyLogin {
    type Session = ();
    type Error = io::Error;
    type SecondFactor = LoginScript;
    async fn authenticate(
        self,
        _account: AccountName,
        _password: Password,
    ) -> Result<LoginResult<Self>, io::Error> {
        self.0.set(self.0.get() + 1);
        Ok(LoginResult::Authenticated(()))
    }
}

#[test]
fn swapped_or_mismatched_fields_never_reach_authentication() {
    for output in [
        b"synthetic-password,synthetic@example.invalid\n".as_slice(),
        b"different@example.invalid,synthetic-password\n",
        b"Synthetic@example.invalid,synthetic-password\n",
        b" synthetic@example.invalid,synthetic-password\n",
    ] {
        let (mut terminal, _) = terminal(false);
        let fetched = Rc::new(Cell::new(0));
        let count = fetched.clone();
        terminal.loader = Some(Box::new(move |_| {
            count.set(count.get() + 1);
            decode_csv(output)
        }));
        confirm(&mut terminal);
        let calls = Rc::new(Cell::new(0));
        let result = block_on(run_login(CountAnyLogin(calls.clone()), &mut terminal));
        assert_eq!(
            calls.get(),
            0,
            "unbound fields must stop before authentication"
        );
        assert!(matches!(
            result,
            Err(crate::flow::FlowError::Terminal(TerminalError::Io))
        ));
        assert!(
            terminal
                .terminal
                .notices
                .contains(&OpInputError::AccountMismatch.label())
        );
        assert_eq!(fetched.get(), 1);
        assert!(terminal.password.is_none());
        assert!(terminal.selector.is_none());
        assert!(terminal.prompt_hidden(ACCOUNT).is_err());
        assert_eq!(fetched.get(), 1);
        assert!(terminal.terminal.hidden.is_empty());
    }
}

const SELECTOR_PIPE_CHILD_ENV: &str = "COFFER_TEST_SELECTOR_PIPE";

#[test]
fn selector_pipe_child_role() {
    let Some(mode) = std::env::var_os(SELECTOR_PIPE_CHILD_ENV) else {
        return;
    };
    let result = ItemSelector::from_stdin_pipe();
    if mode == "valid" {
        assert!(result.is_ok());
    } else {
        assert_eq!(result.err(), Some(OpInputError::Selector));
    }
}

fn selector_pipe_process(input: &[u8], keep_open: bool, mode: &str) {
    let mut child = ChildOwner(
        Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "op_input::tests::selector_pipe_child_role"])
            .env(SELECTOR_PIPE_CHILD_ENV, mode)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    let mut writer = child.0.stdin.take().unwrap();
    writer.write_all(input).unwrap();
    let _writer = if keep_open {
        Some(writer)
    } else {
        drop(writer);
        None
    };
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Some(status) = child.0.try_wait().unwrap() {
            assert!(status.success(), "selector reader contract failed: {mode}");
            break;
        }
        assert!(Instant::now() < deadline, "selector reader failed to stop");
        std::thread::sleep(POLL_INTERVAL);
    }
}

#[test]
fn actual_selector_pipe_oversize_is_selector_error() {
    selector_pipe_process(&[b'x'; 285], false, "oversize");
}

#[test]
fn actual_selector_pipe_timeout_is_selector_error() {
    selector_pipe_process(b"", true, "timeout");
}

#[test]
fn actual_selector_pipe_accepts_exact_frame_only_after_eof() {
    selector_pipe_process(
        b"abcdefghijklmnopqrstuvwxyz\nsynthetic@example.invalid\n",
        false,
        "valid",
    );
    let maximum = format!("abcdefghijklmnopqrstuvwxyz\n{}\n", "é".repeat(128));
    assert_eq!(maximum.len(), 284);
    selector_pipe_process(maximum.as_bytes(), false, "valid");
    selector_pipe_process(
        b"abcdefghijklmnopqrstuvwxyz\nsynthetic@example.invalid\n",
        true,
        "missing-eof",
    );
    for frame in [
        b"abcdefghijklmnopqrstuvwxyz\n".as_slice(),
        b"abcdefghijklmnopqrstuvwxyz\nsynthetic@example.invalid",
        b"abcdefghijklmnopqrstuvwxyz\nsynthetic@example.invalid\nextra",
        b"abcdefghijklmnopqrstuvwxyz\n\xff\n",
    ] {
        selector_pipe_process(frame, false, "malformed");
    }
}

#[test]
fn actual_selector_pipe_read_failure_is_selector_error_and_restores_flags() {
    // A child stdin is a real anonymous pipe, but its parent endpoint is
    // write-only: nonblocking setup succeeds and reading fails with EBADF.
    let mut child = ChildOwner(fake_command("read selected").spawn().unwrap());
    let input = child.0.stdin.take().unwrap();
    let mut pipe = File::from(input.as_fd().try_clone_to_owned().unwrap());
    let before = fcntl_getfl(&pipe).unwrap();
    assert_eq!(
        read_selector_pipe(&mut pipe, Instant::now() + Duration::from_secs(1)).err(),
        Some(OpInputError::Selector)
    );
    assert_eq!(fcntl_getfl(&pipe).unwrap(), before);
}

#[test]
fn first_login_confirmation_is_separate_and_reuses_password_then_wipes() {
    for two_factor in [false, true] {
        let (mut terminal, fetched) = terminal(false);
        terminal.login_only = true;
        terminal.terminal.login_only = true;
        terminal
            .prompt_visible(crate::first_login::CONFIRM)
            .unwrap();
        assert_eq!(fetched.get(), 0);
        terminal.prompt_hidden(ACCOUNT).unwrap();
        assert_eq!(
            terminal.prompt_hidden(PASSWORD).unwrap().as_str(),
            "synthetic-password"
        );
        if two_factor {
            terminal.prompt_hidden(OTP).unwrap();
            assert_eq!(
                terminal.prompt_hidden(REAUTH).unwrap().as_str(),
                "synthetic-password"
            );
        }
        terminal.notice(STORE_NOTICE).unwrap();
        assert!(terminal.password.is_none());
        assert_eq!(fetched.get(), 1);
    }
    for first_login in [false, true] {
        let (mut terminal, fetched) = terminal(false);
        terminal.login_only = first_login;
        let wrong = if first_login {
            CONFIRM
        } else {
            crate::first_login::CONFIRM
        };
        assert!(terminal.prompt_visible(wrong).is_err());
        assert!(terminal.prompt_hidden(ACCOUNT).is_err());
        assert_eq!(fetched.get(), 0);
    }
}
