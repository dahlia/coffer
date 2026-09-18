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

use super::*;
use std::{cell::RefCell, os::unix::fs::PermissionsExt, rc::Rc};

const INPUT: &[u8] = b"EMAIL=synthetic@example.invalid\nPASSWORD=synthetic-password\n";
fn fixture(bytes: &[u8]) -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("synthetic-input");
    std::fs::write(&path, bytes).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    (dir, path)
}
#[test]
fn byte_exact_literal_values_and_optional_final_lf() {
    for suffix in ["", "\n"] {
        let data = format!(
            "EMAIL=synthetic@example.invalid\nPASSWORD= 'x' \"y\" $HOME ${{X}} $(cmd) `cmd` #\\a=b 한글 {suffix}"
        );
        let c = parse(data.as_bytes()).ok().unwrap();
        assert_eq!(c.email.as_bytes(), b"synthetic@example.invalid");
        assert_eq!(
            c.password.as_str(),
            " 'x' \"y\" $HOME ${{X}} $(cmd) `cmd` #\\a=b 한글 ".replace("${{X}}", "${X}")
        );
    }
    let c = parse(b"PASSWORD= value = \nEMAIL= account ").ok().unwrap();
    assert_eq!(c.email.as_str(), " account ");
    assert_eq!(c.password.as_str(), " value = ");
}
#[test]
fn malformed_input_and_errors_never_retain_content() {
    let inputs: &[&[u8]] = &[
        b"",
        b"EMAIL=x",
        b"PASSWORD=x",
        b"EMAIL=\nPASSWORD=x",
        b"EMAIL=x\nPASSWORD=",
        b"EMAIL=x\nPASSWORD=y\nEMAIL=z",
        b"EMAIL=x\nPASSWORD=y\nPASSWORD=z",
        b"EMAIL=x\nSECRET=y",
        b"EMAIL=x\nPASSWORD=y\n", // valid; checked separately below
        b"EMAIL=x\r\nPASSWORD=y\r\n",
        b"EMAIL=x\nPASSWORD=y\r",
        b"EMAIL=x\nPASSWORD=\xff",
        b"EMAIL=x\nPASSWORD=a\0b",
        b"EMAIL=x\nPASSWORD=a\tb",
        b"EMAIL=x\nPASSWORD=y\n\n",
        b" EMAIL=x\nPASSWORD=y",
        b"EMAIL=x\nexport PASSWORD=y",
        b"EMAIL=x\nPASSWORD=y\n#comment",
        b"EMAIL=x\nPASSWORD=a\x7fb",
        "EMAIL=x\nPASSWORD=a\u{85}b".as_bytes(),
    ];
    for bytes in inputs {
        if *bytes == b"EMAIL=x\nPASSWORD=y\n" {
            assert!(parse(bytes).is_ok());
            continue;
        }
        let e = parse(bytes).err().unwrap();
        assert_eq!(e, FileInputError::Format);
        assert_eq!(e.label(), "credential file format rejected");
        assert_eq!(format!("{e:?}"), "Format");
    }
}
#[test]
fn exact_field_and_file_size_bounds() {
    let data = format!(
        "EMAIL={}\nPASSWORD={}\n",
        "a".repeat(MAX_INPUT_LEN),
        "b".repeat(MAX_INPUT_LEN)
    );
    assert_eq!(data.len(), MAX_FILE_LEN);
    assert!(parse(data.as_bytes()).is_ok());
    let (_dir, path) = fixture(data.as_bytes());
    assert!(read_credentials(&path).is_ok());
    let oversized = format!("EMAIL=x\nPASSWORD={}", "b".repeat(MAX_INPUT_LEN + 1));
    assert_eq!(
        parse(oversized.as_bytes()).err(),
        Some(FileInputError::Format)
    );
    let (_dir, path) = fixture(&vec![b'x'; MAX_FILE_LEN + 1]);
    assert_eq!(read_credentials(&path).err(), Some(FileInputError::Size));
}
#[test]
fn descriptor_metadata_rejects_wrong_owner_modes_and_nonregular_files() {
    let (_dir, path) = fixture(INPUT);
    assert!(read_credentials(&path).is_ok());
    let file = open_file(&path).unwrap();
    let stat = fstat(&file).unwrap();
    assert_eq!(
        validate_metadata(&stat, stat.st_uid.wrapping_add(1)),
        Err(FileInputError::Metadata)
    );
    for mode in [
        0o400, 0o000, 0o640, 0o644, 0o660, 0o700, 0o1600, 0o2600, 0o4600,
    ] {
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
        assert!(read_credentials(&path).is_err());
    }
    assert!(read_credentials(path.parent().unwrap()).is_err());
}
#[test]
fn leaf_and_parent_symlinks_and_parent_traversal_are_refused() {
    let (dir, path) = fixture(INPUT);
    let leaf = dir.path().join("link");
    std::os::unix::fs::symlink(&path, &leaf).unwrap();
    assert_eq!(read_credentials(&leaf).err(), Some(FileInputError::Open));
    let parent = dir.path().join("parent");
    std::os::unix::fs::symlink(dir.path(), &parent).unwrap();
    assert_eq!(
        read_credentials(&parent.join("synthetic-input")).err(),
        Some(FileInputError::Open)
    );
    assert!(read_credentials(&dir.path().join("../synthetic-input")).is_err());
}
#[test]
fn fifo_without_writer_is_nonblocking_and_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("fifo");
    rustix::fs::mkfifoat(CWD, &path, Mode::from_raw_mode(0o600)).unwrap();
    let start = std::time::Instant::now();
    assert_eq!(
        read_credentials(&path).err(),
        Some(FileInputError::Metadata)
    );
    assert!(start.elapsed() < std::time::Duration::from_secs(2));
}

#[derive(Default)]
struct Events {
    notices: Vec<&'static str>,
    prompts: Vec<&'static str>,
    decline: bool,
    cancel: bool,
    fail_notice: bool,
}
struct Terminal(Rc<RefCell<Events>>);
impl SecureTerminal for Terminal {
    fn notice(&mut self, text: &'static str) -> Result<(), TerminalError> {
        self.0.borrow_mut().notices.push(text);
        if self.0.borrow().fail_notice {
            Err(TerminalError::Io)
        } else {
            Ok(())
        }
    }
    fn prompt_visible(&mut self, label: &'static str) -> Result<Zeroizing<String>, TerminalError> {
        self.0.borrow_mut().prompts.push(label);
        if self.0.borrow().cancel {
            return Err(TerminalError::Interrupted);
        }
        Ok(Zeroizing::new(
            if self.0.borrow().decline {
                "NO"
            } else {
                "LOGIN AND STORE"
            }
            .into(),
        ))
    }
    fn prompt_hidden(&mut self, label: &'static str) -> Result<Zeroizing<String>, TerminalError> {
        assert_eq!(label, OTP);
        self.0.borrow_mut().prompts.push(label);
        if self.0.borrow().cancel {
            return Err(TerminalError::Interrupted);
        }
        Ok(Zeroizing::new("123456".into()))
    }
}
fn adapter(path: PathBuf) -> (FileTerminal<Terminal>, Rc<RefCell<Events>>) {
    let seen = Rc::new(RefCell::new(Events::default()));
    (FileTerminal::new(Terminal(seen.clone()), path), seen)
}
fn confirmed(input: &mut FileTerminal<Terminal>) {
    assert_eq!(
        input
            .prompt_visible(crate::first_login::CONFIRM)
            .unwrap()
            .as_str(),
        "LOGIN AND STORE"
    );
}
#[test]
fn construction_and_confirmation_do_not_open_file_and_decline_never_reads() {
    for cancel in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("does-not-exist");
        let (mut input, seen) = adapter(path);
        seen.borrow_mut().decline = true;
        seen.borrow_mut().cancel = cancel;
        let _ = input.prompt_visible(crate::first_login::CONFIRM);
        assert!(input.prompt_hidden(ACCOUNT).is_err());
        assert!(seen.borrow().notices.is_empty());
        assert!(input.path.is_none());
    }
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("created-after-confirmation");
    let (mut input, _) = adapter(path.clone());
    confirmed(&mut input);
    std::fs::write(&path, INPUT).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    assert!(input.prompt_hidden(ACCOUNT).is_ok());
}
#[test]
fn one_read_only_credentials_are_literal_and_only_otp_reaches_tty() {
    let (_dir, path) = fixture(INPUT);
    let (mut input, seen) = adapter(path.clone());
    confirmed(&mut input);
    assert_eq!(
        input.prompt_hidden(ACCOUNT).unwrap().as_str(),
        "synthetic@example.invalid"
    );
    std::fs::remove_file(path).unwrap();
    assert_eq!(
        input.prompt_hidden(PASSWORD).unwrap().as_str(),
        "synthetic-password"
    );
    assert_eq!(input.prompt_hidden(OTP).unwrap().as_str(), "123456");
    input.notice(ACCOUNT_NOTICE).unwrap();
    input.notice(REAUTH_NOTICE).unwrap();
    assert_eq!(
        input.prompt_hidden(REAUTH).unwrap().as_str(),
        "synthetic-password"
    );
    assert!(input.password.is_none());
    assert!(input.prompt_hidden(REAUTH).is_err());
    assert_eq!(seen.borrow().prompts, [crate::first_login::CONFIRM, OTP]);
    assert!(
        seen.borrow()
            .notices
            .iter()
            .all(|s| !s.contains("synthetic")
                && !s.contains("was not kept")
                && !s.contains("is typed"))
    );
}
#[test]
fn repeated_and_out_of_order_prompts_fail_closed() {
    for (steps, bad) in [
        (0, ACCOUNT),
        (0, PASSWORD),
        (1, PASSWORD),
        (1, OTP),
        (2, ACCOUNT),
        (2, OTP),
        (3, PASSWORD),
        (3, REAUTH),
        (4, OTP),
    ] {
        let (_dir, path) = fixture(INPUT);
        let (mut input, _) = adapter(path);
        if steps >= 1 {
            confirmed(&mut input);
        }
        if steps >= 2 {
            input.prompt_hidden(ACCOUNT).unwrap();
        }
        if steps >= 3 {
            input.prompt_hidden(PASSWORD).unwrap();
        }
        if steps >= 4 {
            input.prompt_hidden(OTP).unwrap();
        }
        assert!(input.prompt_hidden(bad).is_err());
        assert!(input.password.is_none());
        assert!(input.path.is_none());
        assert!(input.prompt_visible(crate::first_login::CONFIRM).is_err());
    }
}
#[test]
fn failures_persistence_and_finish_wipe_retained_password() {
    // Pin the cross-module notice contract before any store connection/write.
    // Rewording the actual store notice must not silently retain the password.
    let source = include_str!("../../src/store.rs");
    let body = source
        .split("pub async fn persist_and_reload")
        .nth(1)
        .unwrap();
    let start = body.find(".notice(\"").unwrap() + ".notice(\"".len();
    let end = start + body[start..].find("\")?").unwrap();
    let actual_notice = &body[start..end];
    assert_eq!(actual_notice, STORE_NOTICE);
    assert!(end < body.find("connector.connect()").unwrap());
    assert!(end < body.find("writer.replace(").unwrap());
    for scenario in 0..4 {
        let (_dir, path) = fixture(INPUT);
        let (mut input, seen) = adapter(path);
        confirmed(&mut input);
        input.prompt_hidden(ACCOUNT).unwrap();
        input.prompt_hidden(PASSWORD).unwrap();
        match scenario {
            0 => input.notice(actual_notice).unwrap(),
            1 => input.finish(),
            2 => {
                seen.borrow_mut().cancel = true;
                assert!(input.prompt_hidden(OTP).is_err());
            }
            _ => {
                seen.borrow_mut().fail_notice = true;
                assert!(input.notice("notice").is_err());
            }
        }
        assert!(input.password.is_none());
        assert!(input.prompt_hidden(REAUTH).is_err());
    }
}
#[test]
fn file_errors_are_redacted_and_never_fall_back_to_tty() {
    let (_dir, path) = fixture(b"EMAIL=synthetic-private\nPASSWORD=bad\0secret");
    let (mut input, seen) = adapter(path);
    confirmed(&mut input);
    assert!(input.prompt_hidden(ACCOUNT).is_err());
    assert!(input.prompt_hidden(ACCOUNT).is_err());
    assert_eq!(seen.borrow().notices, ["credential file format rejected"]);
    assert_eq!(seen.borrow().prompts, [crate::first_login::CONFIRM]);
}
