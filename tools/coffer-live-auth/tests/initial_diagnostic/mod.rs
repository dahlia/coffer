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
use crate::terminal::TerminalError;
use coffer_protocol::{
    anisette::{AnisetteData, AnisetteError},
    auth::diagnostic::{Au, InitialOutcome, Verification},
    entropy::EntropyError,
};
use std::{
    os::unix::fs::PermissionsExt,
    sync::{Arc, Mutex},
};
use zeroize::Zeroizing;

const INIT: &[u8] =
    include_bytes!("../../../../crates/coffer-protocol/tests/fixtures/gsa/init_response.plist");
const COMPLETE: &[u8] = include_bytes!(
    "../../../../crates/coffer-protocol/tests/fixtures/gsa/complete_response_authenticated.plist"
);
struct SyntheticAnisette(Arc<AtomicU8>);
impl AnisetteProvider for SyntheticAnisette {
    async fn anisette(&self) -> Result<AnisetteData, AnisetteError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(AnisetteData {
            one_time_password: "otp".into(),
            machine_id: "mid".into(),
            routing_info: "17106176".into(),
            local_user_id: "LU".into(),
            serial_number: "0".into(),
            client_info: "<Model> <macOS;13.1;22C65> <com.apple.AuthKit/1 (x)>".into(),
            device_id: "DEVICE".into(),
            client_time: "2026-01-01T00:00:00Z".into(),
            time_zone: "UTC".into(),
            locale: "en_US".into(),
        })
    }
}
struct SyntheticEntropy;
impl Entropy for SyntheticEntropy {
    fn fill(&self, dest: &mut [u8]) -> Result<(), EntropyError> {
        for (i, byte) in dest.iter_mut().enumerate() {
            *byte = (i * 7 + 3) as u8;
        }
        Ok(())
    }
}
struct Script {
    responses: Mutex<Vec<Vec<u8>>>,
    calls: Arc<AtomicU8>,
}
impl Transport for Script {
    async fn send(&self, request: Request) -> Result<Response, TransportError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        assert_eq!(request.method, Method::Post);
        assert_eq!(request.url, GSA_ENDPOINT);
        let mut responses = self.responses.lock().unwrap();
        if responses.is_empty() {
            return Err(TransportError::Timeout);
        }
        Ok(Response::new(200, responses.remove(0)))
    }
}
struct Terminal {
    decline: bool,
    fail_notice: bool,
}
impl SecureTerminal for Terminal {
    fn notice(&mut self, _: &'static str) -> Result<(), TerminalError> {
        if self.fail_notice {
            Err(TerminalError::Io)
        } else {
            Ok(())
        }
    }
    fn prompt_visible(&mut self, label: &'static str) -> Result<Zeroizing<String>, TerminalError> {
        assert_eq!(label, CONFIRM);
        Ok(Zeroizing::new(
            if self.decline {
                "no"
            } else {
                "DIAGNOSE INITIAL AUTH"
            }
            .into(),
        ))
    }
    fn prompt_hidden(&mut self, _: &'static str) -> Result<Zeroizing<String>, TerminalError> {
        panic!("hidden prompts must never reach the TTY");
    }
}
fn terminal(path: std::path::PathBuf) -> FileTerminal<Terminal> {
    FileTerminal::for_initial_diagnostic(
        Terminal {
            decline: false,
            fail_notice: false,
        },
        path,
    )
}
fn fixture() -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("synthetic-credentials");
    std::fs::write(&path, b"EMAIL=coffer-fixture@example.invalid\nPASSWORD=synthetic fixture password, not a real credential\n").unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    (dir, path)
}
fn responses(selector: Option<&str>) -> Vec<Vec<u8>> {
    let mut complete = plist::Value::from_reader_xml(COMPLETE).unwrap();
    let status = complete
        .as_dictionary_mut()
        .unwrap()
        .get_mut("Response")
        .unwrap()
        .as_dictionary_mut()
        .unwrap()
        .get_mut("Status")
        .unwrap()
        .as_dictionary_mut()
        .unwrap();
    if let Some(selector) = selector {
        status.insert("au".into(), plist::Value::String(selector.into()));
    }
    let mut body = Vec::new();
    complete.to_writer_xml(&mut body).unwrap();
    vec![INIT.to_vec(), body]
}

#[test]
fn protocol_to_file_runner_and_output_stop_for_every_successful_shape() {
    for (selector, au, outcome) in [
        (None, Au::Absent, InitialOutcome::CompleteWithoutSecondary),
        (Some(""), Au::Empty, InitialOutcome::Unsupported),
        (
            Some("trustedDeviceSecondaryAuth"),
            Au::TrustedDevice,
            InitialOutcome::TrustedDeviceRequired,
        ),
        (
            Some("secondaryAuth"),
            Au::Secondary,
            InitialOutcome::Unsupported,
        ),
        (Some("repair"), Au::Repair, InitialOutcome::Unsupported),
        (
            Some("HtTpS://synthetic.invalid/?secret=Sentinel123"),
            Au::HttpUrlLike,
            InitialOutcome::Unsupported,
        ),
        (
            Some("私\nSentinel123"),
            Au::OtherString,
            InitialOutcome::Unsupported,
        ),
    ] {
        let (_dir, path) = fixture();
        let mut terminal = terminal(path);
        let calls = Arc::new(AtomicU8::new(0));
        let generations = Arc::new(AtomicU8::new(0));
        let report = run_with(&mut terminal, || {
            Ok((
                Script {
                    responses: Mutex::new(responses(selector)),
                    calls: calls.clone(),
                },
                SyntheticAnisette(generations.clone()),
                SyntheticEntropy,
            ))
        })
        .unwrap();
        assert_eq!(report.outcome, outcome);
        assert_eq!(report.complete.au, au);
        assert_eq!(report.proof_verified, Verification::Passed);
        assert_eq!(report.spd_parsed, Verification::Passed);
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert_eq!(generations.load(Ordering::SeqCst), 1);
        assert!(terminal.prompt_hidden("Password (not echoed): ").is_err());
        assert!(terminal.prompt_visible(CONFIRM).is_err());
        let mut output = Vec::new();
        write_report(&mut output, &report).unwrap();
        let text = String::from_utf8(output).unwrap();
        for secret in [
            "Sentinel123",
            "synthetic",
            "example.invalid",
            "GSIDMS",
            "https://",
            "私",
        ] {
            assert!(!text.contains(secret));
        }
    }
}

#[test]
fn preflight_decline_and_output_failures_are_closed() {
    for scenario in 0..3 {
        let mut terminal = FileTerminal::for_initial_diagnostic(
            Terminal {
                decline: scenario == 0,
                fail_notice: scenario == 1,
            },
            "synthetic-nonexistent".into(),
        );
        let calls = Arc::new(AtomicU8::new(0));
        let generations = Arc::new(AtomicU8::new(0));
        let result = run_with(&mut terminal, || {
            if scenario == 2 {
                return Err(DiagnosticError::LocalState);
            }
            Ok((
                Script {
                    responses: Mutex::new(vec![]),
                    calls: calls.clone(),
                },
                SyntheticAnisette(generations.clone()),
                SyntheticEntropy,
            ))
        });
        assert!(result.is_err());
        assert!(terminal.prompt_visible(CONFIRM).is_err());
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert_eq!(generations.load(Ordering::SeqCst), 0);
    }
    struct BrokenWriter;
    impl Write for BrokenWriter {
        fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::other("synthetic-private-error"))
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    assert_eq!(
        write_report(&mut BrokenWriter, &InitialAuthReport::default()),
        Err(DiagnosticError::Output)
    );
}

#[test]
fn transport_budget_is_spent_before_failure_and_rejects_other_endpoints() {
    for bad_url in [
        None,
        Some(coffer_protocol::auth::TRUSTED_DEVICE_ENDPOINT),
        Some(coffer_protocol::auth::VALIDATE_ENDPOINT),
    ] {
        let calls = Arc::new(AtomicU8::new(0));
        let transport = InitialTransport::new(Script {
            responses: Mutex::new(vec![]),
            calls: calls.clone(),
        });
        let mut request = crate::transport::tests::post_request();
        if let Some(url) = bad_url {
            request.url = url.into();
        }
        assert!(block_on(transport.send(request)).is_err());
        assert!(block_on(transport.send(crate::transport::tests::post_request())).is_err());
        assert_eq!(calls.load(Ordering::SeqCst), u8::from(bad_url.is_none()));
    }
    let refused_calls = Arc::new(AtomicU8::new(0));
    let refused = InitialTransport::new(Script {
        responses: Mutex::new(vec![]),
        calls: refused_calls.clone(),
    });
    let mut get = crate::transport::tests::post_request();
    get.method = Method::Get;
    assert!(block_on(refused.send(get)).is_err());
    assert_eq!(refused_calls.load(Ordering::SeqCst), 0);
    let calls = Arc::new(AtomicU8::new(0));
    let transport = InitialTransport::new(Script {
        responses: Mutex::new(vec![vec![], vec![]]),
        calls: calls.clone(),
    });
    for _ in 0..2 {
        assert!(block_on(transport.send(crate::transport::tests::post_request())).is_ok());
    }
    assert!(block_on(transport.send(crate::transport::tests::post_request())).is_err());
    assert_eq!(calls.load(Ordering::SeqCst), 2);
}

#[test]
fn cancelling_or_concurrently_sending_never_restores_budget() {
    use std::{
        future::Future,
        pin::pin,
        task::{Context, Poll, Waker},
    };
    struct Pending(AtomicU8);
    impl Transport for Pending {
        async fn send(&self, _: Request) -> Result<Response, TransportError> {
            self.0.fetch_add(1, Ordering::SeqCst);
            std::future::pending().await
        }
    }
    let transport = InitialTransport::new(Pending(AtomicU8::new(0)));
    let mut context = Context::from_waker(Waker::noop());
    {
        let mut future = pin!(transport.send(crate::transport::tests::post_request()));
        assert!(matches!(future.as_mut().poll(&mut context), Poll::Pending));
        assert!(block_on(transport.send(crate::transport::tests::post_request())).is_err());
    }
    assert!(block_on(transport.send(crate::transport::tests::post_request())).is_err());
    assert_eq!(transport.inner.0.load(Ordering::SeqCst), 1);
}

#[test]
fn an_inflight_success_cannot_reopen_after_a_concurrent_refusal() {
    use std::{
        future::{Future, poll_fn},
        pin::pin,
        sync::atomic::AtomicBool,
        task::{Context, Poll, Waker},
    };
    struct Controlled {
        calls: AtomicU8,
        release: AtomicBool,
    }
    impl Transport for Controlled {
        async fn send(&self, _: Request) -> Result<Response, TransportError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            poll_fn(|_| {
                if self.release.load(Ordering::SeqCst) {
                    Poll::Ready(Ok(Response::new(200, vec![])))
                } else {
                    Poll::Pending
                }
            })
            .await
        }
    }
    let transport = InitialTransport::new(Controlled {
        calls: AtomicU8::new(0),
        release: AtomicBool::new(false),
    });
    let mut context = Context::from_waker(Waker::noop());
    let mut first = pin!(transport.send(crate::transport::tests::post_request()));
    assert!(matches!(first.as_mut().poll(&mut context), Poll::Pending));
    assert!(block_on(transport.send(crate::transport::tests::post_request())).is_err());
    transport.inner.release.store(true, Ordering::SeqCst);
    assert!(matches!(
        first.as_mut().poll(&mut context),
        Poll::Ready(Ok(_))
    ));
    assert!(block_on(transport.send(crate::transport::tests::post_request())).is_err());
    assert_eq!(transport.inner.calls.load(Ordering::SeqCst), 1);
}

#[test]
fn protocol_failure_finishes_input_before_any_report_can_be_written() {
    for scenario in 0..3 {
        let (_dir, path) = fixture();
        let mut terminal = terminal(path);
        let calls = Arc::new(AtomicU8::new(0));
        let mut replies = responses(Some("repair"));
        if scenario == 0 {
            replies[0] = b"truncated XML".to_vec();
        }
        if scenario == 1 {
            replies.clear();
        }
        if scenario == 2 {
            let mut complete = plist::Value::from_reader_xml(replies[1].as_slice()).unwrap();
            complete
                .as_dictionary_mut()
                .unwrap()
                .get_mut("Response")
                .unwrap()
                .as_dictionary_mut()
                .unwrap()
                .insert("M2".into(), plist::Value::Data(vec![0; 32]));
            replies[1].clear();
            complete.to_writer_xml(&mut replies[1]).unwrap();
        }
        let report = run_with(&mut terminal, || {
            Ok((
                Script {
                    responses: Mutex::new(replies),
                    calls: calls.clone(),
                },
                SyntheticAnisette(Arc::new(AtomicU8::new(0))),
                SyntheticEntropy,
            ))
        })
        .unwrap();
        assert_eq!(report.outcome, InitialOutcome::Failed);
        assert!(terminal.prompt_visible(CONFIRM).is_err());
        assert!(terminal.prompt_hidden("Password (not echoed): ").is_err());
        assert_eq!(
            calls.load(Ordering::SeqCst),
            if scenario == 2 { 2 } else { 1 }
        );
        let mut output = Vec::new();
        write_report(&mut output, &report).unwrap();
        assert!(!String::from_utf8(output).unwrap().contains("synthetic"));
    }
}
