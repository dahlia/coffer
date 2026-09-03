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

//! The authentication state machine exercised offline against a scripted
//! transport.  No test here contacts Apple or any other network service.

mod support;

use coffer_protocol::anisette::{AnisetteError, AnisetteProvider};
use coffer_protocol::auth::{
    AuthError, AuthErrorKind, AuthStage, Authenticator, LoginOutcome, MalformedReason,
    ResponseLimits, Session, TRUSTED_DEVICE_ENDPOINT, VALIDATE_ENDPOINT,
};
use coffer_protocol::entropy::Entropy;
use coffer_protocol::secret::{AccountName, Password, VerificationCode};
use coffer_protocol::transport::{Method, Transport, TransportError};
use plist::{Dictionary, Value};
use support::vector::{self, Vector};
use support::{
    BrokenAnisette, BrokenEntropy, FixedAnisette, FixedEntropy, InjectingAnisette,
    ScriptedTransport, Step, block_on, ok, reply,
};

type Auth = Authenticator<ScriptedTransport, FixedAnisette, FixedEntropy>;

const TRUSTED: &str = "trustedDeviceSecondaryAuth";

fn account() -> AccountName {
    AccountName::new(vector::ACCOUNT.to_owned()).unwrap()
}

fn password() -> Password {
    Password::new(vector::PASSWORD.to_owned())
}

fn code() -> VerificationCode {
    VerificationCode::parse("123456".to_owned()).unwrap()
}

fn authenticator(steps: Vec<Step>) -> Auth {
    Authenticator::new(
        ScriptedTransport::new(steps),
        FixedAnisette,
        FixedEntropy(vector::a_secret()),
    )
}

fn authenticate(
    auth: &Auth,
) -> Result<LoginOutcome<'_, ScriptedTransport, FixedAnisette, FixedEntropy>, AuthError> {
    block_on(auth.login(account(), password()).authenticate())
}

/// The six-response script of a complete trusted-device login.
fn two_factor_script(v: &Vector) -> Vec<Step> {
    vec![
        ok(vector::init_response(v)),
        ok(vector::complete_response(v, Some(TRUSTED))),
        reply(200, b"".to_vec()),
        ok(vector::validate_ok()),
        ok(vector::init_response(v)),
        ok(vector::complete_response(v, None)),
    ]
}

/// Runs the whole trusted-device flow.
fn run_two_factor(auth: &Auth) -> Result<Session, AuthError> {
    let LoginOutcome::SecondFactorRequired(required) = authenticate(auth)? else {
        panic!("expected a second-factor request");
    };
    let requested = block_on(required.request_trusted_device_code())?;
    let verified = block_on(requested.submit_code(code()))?;
    block_on(verified.reauthenticate(password()))
}

fn assert_session(session: &Session) {
    assert_eq!(session.account().as_str(), vector::ACCOUNT);
    assert_eq!(session.account_id().as_str(), vector::ADSID);
    assert_eq!(session.idms_token().expose_secret(), vector::IDMS_TOKEN);
    assert_eq!(
        session.session_key().expose_secret(),
        &vector::session_key_sk()
    );
    assert_eq!(session.cookie(), vector::SPD_COOKIE);
    assert_eq!(
        session.password_equivalent_token().unwrap().expose_secret(),
        vector::PET
    );
    assert_eq!(
        session.service_ids().collect::<Vec<_>>(),
        [vector::PET_SERVICE]
    );
    assert_eq!(session.given_name(), Some(vector::GIVEN_NAME));
    assert_eq!(session.family_name(), Some(vector::FAMILY_NAME));
}

/// Serializes a `Response` dictionary after `edit` has mutated it.
fn edited(mut dict: Dictionary, edit: impl FnOnce(&mut Dictionary)) -> Vec<u8> {
    edit(&mut dict);
    vector::plist_bytes(vector::envelope(dict))
}

fn assert_no_secrets(text: &str) {
    for secret in [
        vector::PASSWORD,
        vector::IDMS_TOKEN,
        vector::PET,
        "123456",
        vector::ACCOUNT,
        vector::ADSID,
    ] {
        assert!(!text.contains(secret), "{text:?} leaks {secret:?}");
    }
    let v = vector::compute();
    for bytes in [&v.a_pub, &v.m1, &v.k, &v.password_key.to_vec()] {
        assert!(!text.contains(&support::hex(bytes)));
    }
}

// Success paths --------------------------------------------------------------

#[test]
fn login_without_second_factor_succeeds_in_two_requests() {
    let v = vector::compute();
    let auth = authenticator(vec![
        ok(vector::init_response(&v)),
        ok(vector::complete_response(&v, None)),
    ]);
    let outcome = authenticate(&auth).unwrap();
    let LoginOutcome::Authenticated(session) = outcome else {
        panic!("expected Authenticated, got {outcome:?}");
    };
    assert_session(&session);
    let requests = auth.transport().requests();
    assert_eq!(requests.len(), 2);
    for request in &requests {
        assert_eq!(request.method, Method::Post);
        assert_eq!(request.url, coffer_protocol::auth::GSA_ENDPOINT);
        assert_eq!(request.header("Content-Type"), Some("text/x-xml-plist"));
        assert_eq!(request.header("Accept"), Some("*/*"));
        assert_eq!(
            request.header("User-Agent"),
            Some("akd/1.0 CFNetwork/978.0.7 Darwin/18.7.0")
        );
        assert_eq!(
            request.header("X-MMe-Client-Info"),
            Some(support::sample_anisette().client_info.as_str())
        );
        assert_eq!(request.headers.len(), 4);
    }
}

#[test]
fn login_with_trusted_device_second_factor_succeeds_in_six_requests() {
    let v = vector::compute();
    let auth = authenticator(two_factor_script(&v));
    let session = run_two_factor(&auth).unwrap();
    assert_session(&session);

    let requests = auth.transport().requests();
    assert_eq!(requests.len(), 6);
    assert_eq!(auth.transport().remaining(), 0);

    let push = &requests[2];
    assert_eq!(push.method, Method::Get);
    assert_eq!(push.url, TRUSTED_DEVICE_ENDPOINT);
    assert!(push.body.is_none());
    let expected_identity = {
        use base64::Engine as _;
        base64::engine::general_purpose::STANDARD.encode(format!(
            "{}:{}",
            vector::ADSID,
            vector::IDMS_TOKEN
        ))
    };
    assert_eq!(
        push.header("X-Apple-Identity-Token"),
        Some(expected_identity.as_str())
    );
    assert_eq!(push.header("User-Agent"), Some("Xcode"));
    assert_eq!(push.header("Accept-Language"), Some("en-us"));
    assert_eq!(push.header("Loc"), Some("en_US"));
    assert_eq!(
        push.header("X-Apple-App-Info"),
        Some("com.apple.gs.xcode.auth")
    );
    assert_eq!(push.header("X-Xcode-Version"), Some("11.2 (11B41)"));
    assert_eq!(push.header("Content-Type"), Some("text/x-xml-plist"));
    assert_eq!(push.header("Accept"), Some("text/x-xml-plist"));
    let anisette = support::sample_anisette();
    assert_eq!(
        push.header("X-Apple-I-MD"),
        Some(anisette.one_time_password.as_str())
    );
    assert_eq!(
        push.header("X-Apple-I-MD-M"),
        Some(anisette.machine_id.as_str())
    );
    assert_eq!(
        push.header("X-Mme-Client-Info"),
        Some(anisette.client_info.as_str())
    );
    assert_eq!(
        push.header("X-Mme-Device-Id"),
        Some(anisette.device_id.as_str())
    );
    assert!(push.header("security-code").is_none());
    assert_eq!(push.headers.len(), 18);

    let validate = &requests[3];
    assert_eq!(validate.method, Method::Get);
    assert_eq!(validate.url, VALIDATE_ENDPOINT);
    assert_eq!(validate.header("security-code"), Some("123456"));
    assert_eq!(
        validate.header("X-Apple-Identity-Token"),
        Some(expected_identity.as_str())
    );
    assert_eq!(validate.headers.len(), 19);

    // The re-authentication is a full, fresh SRP exchange.
    assert_eq!(requests[4].url, coffer_protocol::auth::GSA_ENDPOINT);
    assert_eq!(requests[4].body, requests[0].body);
    assert_eq!(requests[5].body, requests[1].body);
}

#[test]
fn unknown_secondary_auth_step_is_reported_not_guessed() {
    let v = vector::compute();
    let auth = authenticator(vec![
        ok(vector::init_response(&v)),
        ok(vector::complete_response(
            &v,
            Some("synthetic.unsupported.step"),
        )),
    ]);
    let outcome = authenticate(&auth).unwrap();
    let LoginOutcome::Unsupported(step) = outcome else {
        panic!("expected Unsupported, got {outcome:?}");
    };
    assert_eq!(step.step().as_str(), "synthetic.unsupported.step");
    assert_eq!(
        format!("{step:?}"),
        "UnsupportedStep { step: ServerSelector(synthetic.unsupported.step) }"
    );
    assert_eq!(auth.transport().count(), 2);
}

// Initial SRP failures -------------------------------------------------------

#[test]
fn protocol_error_with_http_200_fails_at_srp_init_with_one_request() {
    let auth = authenticator(vec![ok(vector::init_response_error())]);
    let err = authenticate(&auth).unwrap_err();
    assert_eq!(err.stage(), AuthStage::SrpInit);
    assert!(!err.stage().is_post_second_factor());
    let AuthErrorKind::Protocol(status) = err.kind() else {
        panic!("expected Protocol, got {err:?}");
    };
    assert_eq!(status.code(), -20101);
    assert!(status.message().starts_with("Synthetic:"));
    assert_eq!(auth.transport().count(), 1);
    assert_no_secrets(&err.to_string());
    assert_no_secrets(&format!("{err:?}"));
}

#[test]
fn wrong_server_proof_fails_at_srp_complete_without_retry() {
    let v = vector::compute();
    let mut wrong_m2 = v.m2.clone();
    wrong_m2[0] ^= 0x01;
    let complete = edited(vector::complete_response_dict(&v, None), |d| {
        d.insert("M2".to_owned(), Value::Data(wrong_m2));
    });
    let auth = authenticator(vec![ok(vector::init_response(&v)), ok(complete)]);
    let err = authenticate(&auth).unwrap_err();
    assert_eq!(err.stage(), AuthStage::SrpComplete);
    assert!(matches!(err.kind(), AuthErrorKind::ServerProofMismatch));
    assert_eq!(auth.transport().count(), 2);
}

#[test]
fn http_error_status_is_reported_before_parsing() {
    let auth = authenticator(vec![reply(503, b"<html>down</html>".to_vec())]);
    let err = authenticate(&auth).unwrap_err();
    assert_eq!(err.stage(), AuthStage::SrpInit);
    assert!(matches!(err.kind(), AuthErrorKind::HttpStatus(503)));
    assert_eq!(auth.transport().count(), 1);
}

#[test]
fn unsupported_password_protocol_stops_before_sending_a_proof() {
    let v = vector::compute();
    let init = edited(vector::init_response_dict(&v), |d| {
        d.insert("sp".to_owned(), Value::String("s2k_fo".to_owned()));
    });
    let auth = authenticator(vec![ok(init), ok(vector::complete_response(&v, None))]);
    let err = authenticate(&auth).unwrap_err();
    assert_eq!(err.stage(), AuthStage::SrpInit);
    assert!(matches!(
        err.kind(),
        AuthErrorKind::UnsupportedProtocol { protocol } if protocol.as_str() == "s2k_fo"
    ));
    assert_eq!(auth.transport().count(), 1);
}

#[test]
fn explicit_s2k_selection_is_accepted() {
    let v = vector::compute();
    let init = edited(vector::init_response_dict(&v), |d| {
        d.insert("sp".to_owned(), Value::String("s2k".to_owned()));
    });
    let auth = authenticator(vec![ok(init), ok(vector::complete_response(&v, None))]);
    assert!(matches!(
        authenticate(&auth).unwrap(),
        LoginOutcome::Authenticated(_)
    ));
}

// Malformed responses --------------------------------------------------------

fn expect_malformed(
    auth: &Auth,
    stage: AuthStage,
    field: &str,
    reason: MalformedReason,
    requests: usize,
) {
    let err = authenticate(auth).unwrap_err();
    assert_eq!(err.stage(), stage, "{err}");
    let AuthErrorKind::Malformed(m) = err.kind() else {
        panic!("expected Malformed, got {err:?}");
    };
    assert_eq!(m.field(), field, "{err}");
    assert_eq!(m.reason(), reason, "{err}");
    assert_eq!(auth.transport().count(), requests);
}

#[test]
fn init_body_that_is_not_a_plist_is_malformed() {
    let auth = authenticator(vec![ok(b"<html><body>not a plist</body></html>".to_vec())]);
    expect_malformed(
        &auth,
        AuthStage::SrpInit,
        "body",
        MalformedReason::NotPlist,
        1,
    );
}

#[test]
fn truncated_init_body_is_malformed() {
    let v = vector::compute();
    let mut body = vector::init_response(&v);
    body.truncate(body.len() / 2);
    let auth = authenticator(vec![ok(body)]);
    expect_malformed(
        &auth,
        AuthStage::SrpInit,
        "body",
        MalformedReason::NotPlist,
        1,
    );
}

#[test]
fn empty_init_body_is_malformed() {
    let auth = authenticator(vec![ok(Vec::new())]);
    expect_malformed(
        &auth,
        AuthStage::SrpInit,
        "body",
        MalformedReason::NotPlist,
        1,
    );
}

#[test]
fn plist_without_response_section_is_malformed() {
    let body = vector::plist_bytes(Value::Dictionary(Dictionary::new()));
    let auth = authenticator(vec![ok(body)]);
    expect_malformed(
        &auth,
        AuthStage::SrpInit,
        "Response",
        MalformedReason::Missing,
        1,
    );
}

#[test]
fn plist_whose_root_is_not_a_dictionary_is_malformed() {
    let body = vector::plist_bytes(Value::Array(vec![]));
    let auth = authenticator(vec![ok(body)]);
    expect_malformed(
        &auth,
        AuthStage::SrpInit,
        "body",
        MalformedReason::NotDictionary,
        1,
    );
}

#[test]
fn missing_status_is_not_treated_as_success() {
    let v = vector::compute();
    let init = edited(vector::init_response_dict(&v), |d| {
        d.remove("Status");
    });
    let auth = authenticator(vec![ok(init)]);
    expect_malformed(&auth, AuthStage::SrpInit, "ec", MalformedReason::Missing, 1);
}

#[test]
fn missing_salt_is_malformed() {
    let v = vector::compute();
    let init = edited(vector::init_response_dict(&v), |d| {
        d.remove("s");
    });
    let auth = authenticator(vec![ok(init)]);
    expect_malformed(&auth, AuthStage::SrpInit, "s", MalformedReason::Missing, 1);
}

#[test]
fn salt_with_wrong_type_is_malformed() {
    let v = vector::compute();
    let init = edited(vector::init_response_dict(&v), |d| {
        d.insert("s".to_owned(), Value::String("not data".to_owned()));
    });
    let auth = authenticator(vec![ok(init)]);
    expect_malformed(
        &auth,
        AuthStage::SrpInit,
        "s",
        MalformedReason::WrongType,
        1,
    );
}

#[test]
fn oversized_salt_is_malformed() {
    let v = vector::compute();
    let init = edited(vector::init_response_dict(&v), |d| {
        d.insert("s".to_owned(), Value::Data(vec![1; 65]));
    });
    let auth = authenticator(vec![ok(init)]);
    expect_malformed(
        &auth,
        AuthStage::SrpInit,
        "s",
        MalformedReason::TooLong { limit: 64 },
        1,
    );
}

#[test]
fn oversized_public_value_is_malformed() {
    let v = vector::compute();
    let init = edited(vector::init_response_dict(&v), |d| {
        d.insert("B".to_owned(), Value::Data(vec![1; 257]));
    });
    let auth = authenticator(vec![ok(init)]);
    expect_malformed(
        &auth,
        AuthStage::SrpInit,
        "B",
        MalformedReason::TooLong { limit: 256 },
        1,
    );
}

#[test]
fn zero_public_value_is_rejected_as_invalid_parameter() {
    let v = vector::compute();
    let init = edited(vector::init_response_dict(&v), |d| {
        d.insert("B".to_owned(), Value::Data(vec![0; 32]));
    });
    let auth = authenticator(vec![ok(init)]);
    expect_malformed(
        &auth,
        AuthStage::SrpInit,
        "B",
        MalformedReason::InvalidParameter,
        1,
    );
}

#[test]
fn iteration_count_bounds_are_enforced() {
    let v = vector::compute();
    for bad in [0i64, -1, 1 << 40, i64::MAX, i64::from(u32::MAX)] {
        let init = edited(vector::init_response_dict(&v), |d| {
            d.insert("i".to_owned(), Value::Integer(bad.into()));
        });
        let auth = authenticator(vec![ok(init)]);
        expect_malformed(
            &auth,
            AuthStage::SrpInit,
            "i",
            MalformedReason::OutOfRange,
            1,
        );
    }
    let init = edited(vector::init_response_dict(&v), |d| {
        d.insert("i".to_owned(), Value::Integer(u64::MAX.into()));
    });
    let auth = authenticator(vec![ok(init)]);
    expect_malformed(
        &auth,
        AuthStage::SrpInit,
        "i",
        MalformedReason::OutOfRange,
        1,
    );
}

#[test]
fn iteration_limit_is_configurable() {
    let v = vector::compute();
    let auth = authenticator(vec![ok(vector::init_response(&v))]).with_limits(ResponseLimits {
        max_iterations: vector::ITERATIONS - 1,
        ..ResponseLimits::default()
    });
    expect_malformed(
        &auth,
        AuthStage::SrpInit,
        "i",
        MalformedReason::OutOfRange,
        1,
    );
}

#[test]
fn oversized_cookie_is_malformed() {
    let v = vector::compute();
    let init = edited(vector::init_response_dict(&v), |d| {
        d.insert("c".to_owned(), Value::String("c".repeat(4097)));
    });
    let auth = authenticator(vec![ok(init)]);
    expect_malformed(
        &auth,
        AuthStage::SrpInit,
        "c",
        MalformedReason::TooLong { limit: 4096 },
        1,
    );
}

#[test]
fn oversized_body_is_rejected_by_the_protocol_layer() {
    let v = vector::compute();
    let body = vector::init_response(&v);
    let auth = authenticator(vec![ok(body.clone())]).with_limits(ResponseLimits {
        max_body: body.len() - 1,
        ..ResponseLimits::default()
    });
    // The scripted transport honours `max_response_body`, so the failure
    // surfaces as a transport error; a transport that does not honour it
    // would be caught by the protocol layer's own check instead.
    let err = authenticate(&auth).unwrap_err();
    assert_eq!(err.stage(), AuthStage::SrpInit);
    assert!(matches!(
        err.kind(),
        AuthErrorKind::Transport(TransportError::ResponseTooLarge { .. })
    ));
    assert_eq!(auth.transport().count(), 1);
}

#[test]
fn oversized_body_is_rejected_even_when_the_transport_ignores_the_cap() {
    let v = vector::compute();
    let body = vector::init_response(&v);
    let auth = authenticator(vec![Step::ReplyUncapped {
        status: 200,
        body: body.clone(),
    }])
    .with_limits(ResponseLimits {
        max_body: body.len() - 1,
        ..ResponseLimits::default()
    });
    let limit = body.len() - 1;
    expect_malformed(
        &auth,
        AuthStage::SrpInit,
        "body",
        MalformedReason::TooLong { limit },
        1,
    );
}

#[test]
fn short_server_proof_is_malformed() {
    let v = vector::compute();
    let complete = edited(vector::complete_response_dict(&v, None), |d| {
        d.insert("M2".to_owned(), Value::Data(v.m2[..31].to_vec()));
    });
    let auth = authenticator(vec![ok(vector::init_response(&v)), ok(complete)]);
    expect_malformed(
        &auth,
        AuthStage::SrpComplete,
        "M2",
        MalformedReason::WrongLength { expected: 32 },
        2,
    );
}

#[test]
fn long_server_proof_is_malformed() {
    let v = vector::compute();
    let complete = edited(vector::complete_response_dict(&v, None), |d| {
        let mut long = v.m2.clone();
        long.push(0);
        d.insert("M2".to_owned(), Value::Data(long));
    });
    let auth = authenticator(vec![ok(vector::init_response(&v)), ok(complete)]);
    expect_malformed(
        &auth,
        AuthStage::SrpComplete,
        "M2",
        MalformedReason::TooLong { limit: 32 },
        2,
    );
}

#[test]
fn missing_encrypted_data_is_malformed() {
    let v = vector::compute();
    let complete = edited(vector::complete_response_dict(&v, None), |d| {
        d.remove("spd");
    });
    let auth = authenticator(vec![ok(vector::init_response(&v)), ok(complete)]);
    expect_malformed(
        &auth,
        AuthStage::SrpComplete,
        "spd",
        MalformedReason::Missing,
        2,
    );
}

#[test]
fn encrypted_data_of_partial_block_is_malformed() {
    let v = vector::compute();
    let complete = edited(vector::complete_response_dict(&v, None), |d| {
        d.insert(
            "spd".to_owned(),
            Value::Data(v.spd_ciphertext[..17].to_vec()),
        );
    });
    let auth = authenticator(vec![ok(vector::init_response(&v)), ok(complete)]);
    expect_malformed(
        &auth,
        AuthStage::SrpComplete,
        "spd",
        MalformedReason::BadBlockLength,
        2,
    );
}

#[test]
fn encrypted_data_under_wrong_key_is_malformed() {
    let v = vector::compute();
    // Encrypt the real plaintext under a different key: padding or the
    // plist parse must fail, and either way the field is `spd`.
    let mut other_k = v.k.clone();
    other_k[0] ^= 0xff;
    let (_, _, ciphertext) = vector::encrypt_spd(&other_k, &v.spd_plaintext);
    let complete = edited(vector::complete_response_dict(&v, None), |d| {
        d.insert("spd".to_owned(), Value::Data(ciphertext));
    });
    let auth = authenticator(vec![ok(vector::init_response(&v)), ok(complete)]);
    let err = authenticate(&auth).unwrap_err();
    assert_eq!(err.stage(), AuthStage::SrpComplete);
    let AuthErrorKind::Malformed(m) = err.kind() else {
        panic!("expected Malformed, got {err:?}");
    };
    assert_eq!(m.field(), "spd");
    assert!(matches!(
        m.reason(),
        MalformedReason::BadPadding | MalformedReason::NotPlist | MalformedReason::NotDictionary
    ));
    assert_eq!(auth.transport().count(), 2);
}

#[test]
fn decrypted_data_missing_a_required_field_is_malformed() {
    let v = vector::compute();
    let mut plaintext = Value::from_reader(std::io::Cursor::new(&v.spd_plaintext))
        .unwrap()
        .into_dictionary()
        .unwrap();
    plaintext.remove("GsIdmsToken");
    let plaintext = vector::plist_bytes(Value::Dictionary(plaintext));
    let (_, _, ciphertext) = vector::encrypt_spd(&v.k, &plaintext);
    let complete = edited(vector::complete_response_dict(&v, None), |d| {
        d.insert("spd".to_owned(), Value::Data(ciphertext));
    });
    let auth = authenticator(vec![ok(vector::init_response(&v)), ok(complete)]);
    expect_malformed(
        &auth,
        AuthStage::SrpComplete,
        "GsIdmsToken",
        MalformedReason::Missing,
        2,
    );
}

#[test]
fn decrypted_session_key_of_wrong_length_is_malformed() {
    let v = vector::compute();
    let mut plaintext = Value::from_reader(std::io::Cursor::new(&v.spd_plaintext))
        .unwrap()
        .into_dictionary()
        .unwrap();
    plaintext.insert("sk".to_owned(), Value::Data(vec![1; 16]));
    let plaintext = vector::plist_bytes(Value::Dictionary(plaintext));
    let (_, _, ciphertext) = vector::encrypt_spd(&v.k, &plaintext);
    let complete = edited(vector::complete_response_dict(&v, None), |d| {
        d.insert("spd".to_owned(), Value::Data(ciphertext));
    });
    let auth = authenticator(vec![ok(vector::init_response(&v)), ok(complete)]);
    expect_malformed(
        &auth,
        AuthStage::SrpComplete,
        "sk",
        MalformedReason::WrongLength { expected: 32 },
        2,
    );
}

// Second-factor failures -----------------------------------------------------

#[test]
fn rejected_verification_code_fails_at_code_validation_without_further_requests() {
    let v = vector::compute();
    let auth = authenticator(vec![
        ok(vector::init_response(&v)),
        ok(vector::complete_response(&v, Some(TRUSTED))),
        reply(200, Vec::new()),
        ok(vector::validate_rejected()),
        // Never reached: a rejected code must not trigger re-authentication.
        ok(vector::init_response(&v)),
        ok(vector::complete_response(&v, None)),
    ]);
    let err = run_two_factor(&auth).unwrap_err();
    assert_eq!(err.stage(), AuthStage::CodeValidation);
    let AuthErrorKind::Protocol(status) = err.kind() else {
        panic!("expected Protocol, got {err:?}");
    };
    assert_eq!(status.code(), -21669);
    assert_eq!(auth.transport().count(), 4);
    assert_eq!(auth.transport().remaining(), 2);
    assert_no_secrets(&err.to_string());
}

#[test]
fn http_rejection_of_verification_code_is_reported_as_status() {
    let v = vector::compute();
    let auth = authenticator(vec![
        ok(vector::init_response(&v)),
        ok(vector::complete_response(&v, Some(TRUSTED))),
        reply(200, Vec::new()),
        reply(401, b"Unauthorized".to_vec()),
    ]);
    let err = run_two_factor(&auth).unwrap_err();
    assert_eq!(err.stage(), AuthStage::CodeValidation);
    assert!(matches!(err.kind(), AuthErrorKind::HttpStatus(401)));
    assert_eq!(auth.transport().count(), 4);
}

#[test]
fn empty_validate_body_is_not_treated_as_acceptance() {
    let v = vector::compute();
    let auth = authenticator(vec![
        ok(vector::init_response(&v)),
        ok(vector::complete_response(&v, Some(TRUSTED))),
        reply(200, Vec::new()),
        reply(200, Vec::new()),
    ]);
    let err = run_two_factor(&auth).unwrap_err();
    assert_eq!(err.stage(), AuthStage::CodeValidation);
    assert!(matches!(err.kind(), AuthErrorKind::Malformed(m) if m.field() == "body"));
    assert_eq!(auth.transport().count(), 4);
}

#[test]
fn failed_trusted_device_push_fails_at_that_stage() {
    let v = vector::compute();
    let auth = authenticator(vec![
        ok(vector::init_response(&v)),
        ok(vector::complete_response(&v, Some(TRUSTED))),
        reply(500, Vec::new()),
    ]);
    let err = run_two_factor(&auth).unwrap_err();
    assert_eq!(err.stage(), AuthStage::TrustedDevicePush);
    assert!(matches!(err.kind(), AuthErrorKind::HttpStatus(500)));
    assert_eq!(auth.transport().count(), 3);
}

#[test]
fn malformed_verification_code_never_reaches_the_wire() {
    assert!(VerificationCode::parse("12345".to_owned()).is_err());
    assert!(VerificationCode::parse("abcdef".to_owned()).is_err());
    assert!(VerificationCode::parse(String::new()).is_err());
}

// Post-second-factor failures -------------------------------------------------

#[test]
fn reauth_protocol_error_is_tagged_as_post_second_factor() {
    let v = vector::compute();
    let auth = authenticator(vec![
        ok(vector::init_response(&v)),
        ok(vector::complete_response(&v, Some(TRUSTED))),
        reply(200, Vec::new()),
        ok(vector::validate_ok()),
        ok(vector::init_response_error()),
    ]);
    let err = run_two_factor(&auth).unwrap_err();
    assert_eq!(err.stage(), AuthStage::ReauthSrpInit);
    assert!(err.stage().is_post_second_factor());
    assert!(matches!(err.kind(), AuthErrorKind::Protocol(s) if s.code() == -20101));
    assert_eq!(auth.transport().count(), 5);
    assert!(err.to_string().contains("post-2FA"));
}

#[test]
fn reauth_server_proof_mismatch_is_tagged_as_post_second_factor() {
    let v = vector::compute();
    let mut wrong_m2 = v.m2.clone();
    wrong_m2[31] ^= 0x80;
    let complete = edited(vector::complete_response_dict(&v, None), |d| {
        d.insert("M2".to_owned(), Value::Data(wrong_m2));
    });
    let auth = authenticator(vec![
        ok(vector::init_response(&v)),
        ok(vector::complete_response(&v, Some(TRUSTED))),
        reply(200, Vec::new()),
        ok(vector::validate_ok()),
        ok(vector::init_response(&v)),
        ok(complete),
    ]);
    let err = run_two_factor(&auth).unwrap_err();
    assert_eq!(err.stage(), AuthStage::ReauthSrpComplete);
    assert!(matches!(err.kind(), AuthErrorKind::ServerProofMismatch));
    assert_eq!(auth.transport().count(), 6);
}

#[test]
fn second_factor_still_required_after_reauth_is_an_error_not_a_loop() {
    let v = vector::compute();
    let auth = authenticator(vec![
        ok(vector::init_response(&v)),
        ok(vector::complete_response(&v, Some(TRUSTED))),
        reply(200, Vec::new()),
        ok(vector::validate_ok()),
        ok(vector::init_response(&v)),
        ok(vector::complete_response(&v, Some(TRUSTED))),
        // Never reached: no second push, no second code, no third SRP.
        reply(200, Vec::new()),
    ]);
    let err = run_two_factor(&auth).unwrap_err();
    assert_eq!(err.stage(), AuthStage::ReauthSrpComplete);
    assert!(matches!(
        err.kind(),
        AuthErrorKind::SecondFactorStillRequired
    ));
    assert_eq!(auth.transport().count(), 6);
    assert_eq!(auth.transport().remaining(), 1);
}

#[test]
fn unknown_step_after_reauth_is_an_error() {
    let v = vector::compute();
    let auth = authenticator(vec![
        ok(vector::init_response(&v)),
        ok(vector::complete_response(&v, Some(TRUSTED))),
        reply(200, Vec::new()),
        ok(vector::validate_ok()),
        ok(vector::init_response(&v)),
        ok(vector::complete_response(
            &v,
            Some("synthetic.unsupported.step"),
        )),
    ]);
    let err = run_two_factor(&auth).unwrap_err();
    assert_eq!(err.stage(), AuthStage::ReauthSrpComplete);
    assert!(matches!(
        err.kind(),
        AuthErrorKind::UnsupportedStep { step } if step.as_str() == "synthetic.unsupported.step"
    ));
    assert_eq!(auth.transport().count(), 6);
}

// Transport failures and the no-retry guarantee -------------------------------

#[test]
fn transport_failure_at_every_position_stops_the_flow_there() {
    let v = vector::compute();
    let expected = [
        AuthStage::SrpInit,
        AuthStage::SrpComplete,
        AuthStage::TrustedDevicePush,
        AuthStage::CodeValidation,
        AuthStage::ReauthSrpInit,
        AuthStage::ReauthSrpComplete,
    ];
    for (position, stage) in expected.into_iter().enumerate() {
        let mut script = two_factor_script(&v);
        script[position] = Step::Fail(TransportError::Timeout);
        let auth = authenticator(script);
        let err = run_two_factor(&auth).unwrap_err();
        assert_eq!(err.stage(), stage, "position {position}");
        assert!(
            matches!(
                err.kind(),
                AuthErrorKind::Transport(TransportError::Timeout)
            ),
            "position {position}: {err:?}"
        );
        assert_eq!(
            auth.transport().count(),
            position + 1,
            "position {position}"
        );
        assert_eq!(
            auth.transport().remaining(),
            5 - position,
            "position {position}"
        );
    }
}

#[test]
fn every_failure_leaves_no_extra_request_behind() {
    // Each script ends right after the failing response; an automatic retry
    // would show up as an "unscripted request" transport error instead of
    // the expected error kind, and as a higher count.
    let v = vector::compute();
    let cases: Vec<(Vec<Step>, AuthStage)> = vec![
        (vec![ok(vector::init_response_error())], AuthStage::SrpInit),
        (
            vec![
                ok(vector::init_response(&v)),
                ok(vector::complete_response(&v, Some(TRUSTED))),
                reply(429, Vec::new()),
            ],
            AuthStage::TrustedDevicePush,
        ),
        (
            vec![
                ok(vector::init_response(&v)),
                ok(vector::complete_response(&v, Some(TRUSTED))),
                reply(200, Vec::new()),
                ok(vector::validate_rejected()),
            ],
            AuthStage::CodeValidation,
        ),
    ];
    for (script, stage) in cases {
        let expected = script.len();
        let auth = authenticator(script);
        let err = run_two_factor(&auth).unwrap_err();
        assert_eq!(err.stage(), stage);
        assert!(!matches!(
            err.kind(),
            AuthErrorKind::Transport(TransportError::Other { .. })
        ));
        assert_eq!(auth.transport().count(), expected);
    }
}

// Provider failures before any request ---------------------------------------

#[test]
fn anisette_failure_sends_nothing() {
    let auth = Authenticator::new(
        ScriptedTransport::new(vec![]),
        BrokenAnisette,
        FixedEntropy(vector::a_secret()),
    );
    let err = block_on(auth.login(account(), password()).authenticate()).unwrap_err();
    assert_eq!(err.stage(), AuthStage::SrpInit);
    assert!(matches!(
        err.kind(),
        AuthErrorKind::Anisette(AnisetteError::Unavailable { .. })
    ));
    assert_eq!(auth.transport().count(), 0);
}

#[test]
fn anisette_header_injection_sends_nothing() {
    let auth = Authenticator::new(
        ScriptedTransport::new(vec![]),
        InjectingAnisette,
        FixedEntropy(vector::a_secret()),
    );
    let err = block_on(auth.login(account(), password()).authenticate()).unwrap_err();
    assert!(matches!(
        err.kind(),
        AuthErrorKind::Anisette(AnisetteError::InvalidValue {
            header: "X-Apple-I-SRL-NO"
        })
    ));
    assert_eq!(auth.transport().count(), 0);
}

#[test]
fn entropy_failure_sends_nothing() {
    let auth = Authenticator::new(ScriptedTransport::new(vec![]), FixedAnisette, BrokenEntropy);
    let err = block_on(auth.login(account(), password()).authenticate()).unwrap_err();
    assert_eq!(err.stage(), AuthStage::SrpInit);
    assert!(matches!(err.kind(), AuthErrorKind::Entropy(_)));
    assert_eq!(auth.transport().count(), 0);
}

#[test]
fn all_zero_entropy_is_refused() {
    let auth = Authenticator::new(
        ScriptedTransport::new(vec![]),
        FixedAnisette,
        FixedEntropy(vec![0; 64]),
    );
    let err = block_on(auth.login(account(), password()).authenticate()).unwrap_err();
    assert!(matches!(err.kind(), AuthErrorKind::Entropy(_)));
    assert_eq!(auth.transport().count(), 0);
}

// Redaction ------------------------------------------------------------------

#[test]
fn stage_values_and_session_debug_reveal_nothing() {
    let v = vector::compute();
    let auth = authenticator(two_factor_script(&v));
    let login = auth.login(account(), password());
    assert_eq!(format!("{login:?}"), "PasswordLogin");
    let outcome = block_on(login.authenticate()).unwrap();
    assert_eq!(format!("{outcome:?}"), "LoginOutcome::SecondFactorRequired");
    let LoginOutcome::SecondFactorRequired(required) = outcome else {
        unreachable!()
    };
    assert_eq!(format!("{required:?}"), "SecondFactorRequired");
    let requested = block_on(required.request_trusted_device_code()).unwrap();
    assert_eq!(format!("{requested:?}"), "CodeRequested");
    let verified = block_on(requested.submit_code(code())).unwrap();
    assert_eq!(format!("{verified:?}"), "SecondFactorVerified");
    let session = block_on(verified.reauthenticate(password())).unwrap();
    assert_eq!(format!("{session:?}"), "Session(<redacted>)");
    assert_eq!(
        format!("{:?}", session.account_id()),
        "AccountId(<redacted>)"
    );
    assert_eq!(
        format!("{:?}", session.idms_token()),
        "IdmsToken(<redacted>)"
    );
    assert_eq!(
        format!("{:?}", session.session_key()),
        "SessionKey(<redacted>)"
    );
    assert_eq!(
        format!("{:?}", session.password_equivalent_token().unwrap()),
        "ServiceToken(<redacted>)"
    );
}

#[test]
fn request_debug_hides_header_values_and_bodies() {
    let v = vector::compute();
    let auth = authenticator(two_factor_script(&v));
    run_two_factor(&auth).unwrap();
    for recorded in auth.transport().requests() {
        let request = coffer_protocol::transport::Request {
            method: recorded.method,
            url: recorded.url,
            headers: recorded.headers,
            body: recorded.body,
            max_response_body: 1,
        };
        let text = format!("{request:?}");
        assert_no_secrets(&text);
        assert!(text.contains("header_names"));
    }
}

#[test]
fn errors_never_mention_credentials() {
    let v = vector::compute();
    let scripts: Vec<Vec<Step>> = vec![
        vec![ok(vector::init_response_error())],
        vec![Step::Fail(TransportError::Other {
            detail: "synthetic".to_owned(),
        })],
        vec![
            ok(vector::init_response(&v)),
            ok(vector::complete_response(&v, Some(TRUSTED))),
            reply(200, Vec::new()),
            ok(vector::validate_rejected()),
        ],
        vec![
            ok(vector::init_response(&v)),
            ok(vector::complete_response(&v, Some(TRUSTED))),
            reply(200, Vec::new()),
            ok(vector::validate_ok()),
            ok(vector::init_response(&v)),
            ok(vector::complete_response(&v, Some(TRUSTED))),
        ],
    ];
    for script in scripts {
        let auth = authenticator(script);
        let err = run_two_factor(&auth).unwrap_err();
        assert_no_secrets(&err.to_string());
        assert_no_secrets(&format!("{err:?}"));
        assert_no_secrets(&format!("{:?}", err.kind()));
    }
}

// Hardening regressions ------------------------------------------------------

/// An XML plist envelope whose `Response` carries `depth` nested arrays under
/// an ignored key, plus the fields of a valid init response.
fn deeply_nested_body(depth: usize) -> Vec<u8> {
    let mut body = String::from(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<plist version=\"1.0\">\n<dict>\n<key>Response</key>\n<dict>\n<key>x</key>\n",
    );
    for _ in 0..depth {
        body.push_str("<array>");
    }
    for _ in 0..depth {
        body.push_str("</array>");
    }
    body.push_str("\n<key>Status</key><dict><key>ec</key><integer>0</integer></dict>\n</dict>\n</dict>\n</plist>\n");
    body.into_bytes()
}

#[test]
fn deeply_nested_response_is_rejected_before_it_can_exhaust_the_stack() {
    // About 975 KiB, under the 1 MiB body cap.  Dropping a 65 000-level
    // `plist::Value` tree would overflow the stack; the collection count
    // check rejects the body before it is parsed.
    let body = deeply_nested_body(65_000);
    assert!(body.len() < ResponseLimits::default().max_body);
    let auth = authenticator(vec![ok(body)]);
    expect_malformed(
        &auth,
        AuthStage::SrpInit,
        "body",
        MalformedReason::TooComplex { limit: 512 },
        1,
    );
}

#[test]
fn collection_limit_is_a_count_not_a_size() {
    // The envelope already contributes nine elements (plist, dict, key, dict,
    // key, key, dict, key, integer); 504 nested arrays make 513, one over
    // the default limit of 512, in a body of only a few kilobytes.
    let auth = authenticator(vec![ok(deeply_nested_body(504))]);
    expect_malformed(
        &auth,
        AuthStage::SrpInit,
        "body",
        MalformedReason::TooComplex { limit: 512 },
        1,
    );
}

#[test]
fn deeply_nested_decrypted_data_is_rejected() {
    let v = vector::compute();
    let mut plaintext = String::from(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<plist version=\"1.0\">\n<dict>\n<key>x</key>\n",
    );
    for _ in 0..600 {
        plaintext.push_str("<array>");
    }
    for _ in 0..600 {
        plaintext.push_str("</array>");
    }
    plaintext.push_str("\n</dict>\n</plist>\n");
    let (_, _, ciphertext) = vector::encrypt_spd(&v.k, plaintext.as_bytes());
    let complete = edited(vector::complete_response_dict(&v, None), |d| {
        d.insert("spd".to_owned(), Value::Data(ciphertext));
    });
    let auth = authenticator(vec![ok(vector::init_response(&v)), ok(complete)]);
    expect_malformed(
        &auth,
        AuthStage::SrpComplete,
        "spd",
        MalformedReason::TooComplex { limit: 512 },
        2,
    );
}

#[test]
fn binary_plist_body_is_rejected() {
    let v = vector::compute();
    let mut body = Vec::new();
    vector::envelope(vector::init_response_dict(&v))
        .to_writer_binary(&mut body)
        .unwrap();
    let auth = authenticator(vec![ok(body)]);
    expect_malformed(
        &auth,
        AuthStage::SrpInit,
        "body",
        MalformedReason::NotPlist,
        1,
    );
}

#[test]
fn public_value_wider_than_the_group_is_rejected_even_with_a_raised_limit() {
    let v = vector::compute();
    let init = edited(vector::init_response_dict(&v), |d| {
        d.insert("B".to_owned(), Value::Data(vec![1; 257]));
    });
    let auth = authenticator(vec![ok(init)]).with_limits(ResponseLimits {
        max_public_value: 4096,
        ..ResponseLimits::default()
    });
    expect_malformed(
        &auth,
        AuthStage::SrpInit,
        "B",
        MalformedReason::TooLong { limit: 256 },
        1,
    );
}

#[test]
fn server_message_is_sanitized_and_kept_out_of_error_text() {
    let mut response = Dictionary::new();
    response.insert(
        "Status".to_owned(),
        vector::status(
            -1,
            "line1\r\nInjected: someone@example.invalid\u{1b}[31m",
            None,
        ),
    );
    let body = vector::plist_bytes(vector::envelope(response));
    let auth = authenticator(vec![ok(body)]);
    let err = authenticate(&auth).unwrap_err();
    let AuthErrorKind::Protocol(status) = err.kind() else {
        panic!("expected Protocol, got {err:?}");
    };
    assert_eq!(status.code(), -1);
    assert_eq!(
        status.message(),
        "line1Injected: someone@example.invalid[31m"
    );
    for text in [err.to_string(), format!("{err:?}"), format!("{status}")] {
        assert!(!text.contains("line1"), "{text:?}");
        assert!(!text.contains("someone@example.invalid"), "{text:?}");
        assert!(!text.contains('\n'), "{text:?}");
        assert!(text.contains("-1"), "{text:?}");
    }
}

#[test]
fn empty_required_credentials_in_decrypted_data_are_rejected() {
    let v = vector::compute();
    for (key, field) in [("adsid", "adsid"), ("GsIdmsToken", "GsIdmsToken")] {
        let mut plaintext = Value::from_reader(std::io::Cursor::new(&v.spd_plaintext))
            .unwrap()
            .into_dictionary()
            .unwrap();
        plaintext.insert(key.to_owned(), Value::String(String::new()));
        let plaintext = vector::plist_bytes(Value::Dictionary(plaintext));
        let (_, _, ciphertext) = vector::encrypt_spd(&v.k, &plaintext);
        let complete = edited(vector::complete_response_dict(&v, None), |d| {
            d.insert("spd".to_owned(), Value::Data(ciphertext));
        });
        let auth = authenticator(vec![ok(vector::init_response(&v)), ok(complete)]);
        expect_malformed(
            &auth,
            AuthStage::SrpComplete,
            field,
            MalformedReason::TooShort { minimum: 1 },
            2,
        );
    }
}

#[test]
fn empty_reusable_cookie_in_decrypted_data_is_rejected() {
    let v = vector::compute();
    let mut plaintext = Value::from_reader(std::io::Cursor::new(&v.spd_plaintext))
        .unwrap()
        .into_dictionary()
        .unwrap();
    plaintext.insert("c".to_owned(), Value::Data(Vec::new()));
    let plaintext = vector::plist_bytes(Value::Dictionary(plaintext));
    let (_, _, ciphertext) = vector::encrypt_spd(&v.k, &plaintext);
    let complete = edited(vector::complete_response_dict(&v, None), |d| {
        d.insert("spd".to_owned(), Value::Data(ciphertext));
    });
    let auth = authenticator(vec![ok(vector::init_response(&v)), ok(complete)]);
    expect_malformed(
        &auth,
        AuthStage::SrpComplete,
        "c",
        MalformedReason::TooShort { minimum: 1 },
        2,
    );
}

#[test]
fn empty_service_token_is_rejected() {
    let v = vector::compute();
    let mut plaintext = Value::from_reader(std::io::Cursor::new(&v.spd_plaintext))
        .unwrap()
        .into_dictionary()
        .unwrap();
    let mut entry = Dictionary::new();
    entry.insert("token".to_owned(), Value::String(String::new()));
    let mut tokens = Dictionary::new();
    tokens.insert("synthetic.service".to_owned(), Value::Dictionary(entry));
    plaintext.insert("t".to_owned(), Value::Dictionary(tokens));
    let plaintext = vector::plist_bytes(Value::Dictionary(plaintext));
    let (_, _, ciphertext) = vector::encrypt_spd(&v.k, &plaintext);
    let complete = edited(vector::complete_response_dict(&v, None), |d| {
        d.insert("spd".to_owned(), Value::Data(ciphertext));
    });
    let auth = authenticator(vec![ok(vector::init_response(&v)), ok(complete)]);
    expect_malformed(
        &auth,
        AuthStage::SrpComplete,
        "token",
        MalformedReason::TooShort { minimum: 1 },
        2,
    );
}

#[test]
fn namespace_prefixed_nesting_is_rejected_too() {
    // `plist` resolves element names by local name, so `<p:array>` is a
    // collection to the parser.  The element counter must not depend on the
    // spelling of the tag.
    let mut body = String::from(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<plist version=\"1.0\">\n<dict>\n<key>Response</key>\n<dict>\n<key>x</key>\n",
    );
    for _ in 0..50_000 {
        body.push_str("<p:array>");
    }
    for _ in 0..50_000 {
        body.push_str("</p:array>");
    }
    body.push_str("\n<key>Status</key><dict><key>ec</key><integer>0</integer></dict>\n</dict>\n</dict>\n</plist>\n");
    let body = body.into_bytes();
    assert!(body.len() < ResponseLimits::default().max_body);
    let auth = authenticator(vec![ok(body)]);
    expect_malformed(
        &auth,
        AuthStage::SrpInit,
        "body",
        MalformedReason::TooComplex { limit: 512 },
        1,
    );
}

#[test]
fn non_ascii_and_digit_prefixed_nesting_is_rejected_too() {
    // Whatever the parser accepts as an element name, the counter must see
    // it; `<é:array>` starts with a non-ASCII byte and `<1:array>` with a
    // digit.
    for prefix in ["é", "1"] {
        let mut body = String::from(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<plist version=\"1.0\">\n<dict>\n<key>Response</key>\n<dict>\n<key>x</key>\n",
        );
        for _ in 0..40_000 {
            body.push_str(&format!("<{prefix}:array>"));
        }
        for _ in 0..40_000 {
            body.push_str(&format!("</{prefix}:array>"));
        }
        body.push_str("\n<key>Status</key><dict><key>ec</key><integer>0</integer></dict>\n</dict>\n</dict>\n</plist>\n");
        let body = body.into_bytes();
        assert!(body.len() < ResponseLimits::default().max_body);
        let auth = authenticator(vec![ok(body)]);
        expect_malformed(
            &auth,
            AuthStage::SrpInit,
            "body",
            MalformedReason::TooComplex { limit: 512 },
            1,
        );
    }
}

#[test]
fn unsupported_selectors_with_arbitrary_text_are_redacted_from_errors() {
    let v = vector::compute();
    let init = edited(vector::init_response_dict(&v), |d| {
        d.insert(
            "sp".to_owned(),
            Value::String("s2k\r\nInjected: someone@example.invalid".to_owned()),
        );
    });
    let auth = authenticator(vec![ok(init)]);
    let err = authenticate(&auth).unwrap_err();
    let AuthErrorKind::UnsupportedProtocol { protocol } = err.kind() else {
        panic!("expected UnsupportedProtocol, got {err:?}");
    };
    assert_eq!(
        protocol.as_str(),
        "s2k\r\nInjected: someone@example.invalid"
    );
    for text in [err.to_string(), format!("{err:?}"), format!("{protocol}")] {
        assert!(text.contains("<redacted>"), "{text:?}");
        assert!(!text.contains("Injected"), "{text:?}");
        assert!(!text.contains('\n'), "{text:?}");
    }

    let complete = vector::complete_response(&v, Some("step with spaces @ example"));
    let auth = authenticator(vec![ok(vector::init_response(&v)), ok(complete)]);
    let outcome = authenticate(&auth).unwrap();
    let text = format!("{outcome:?}");
    assert!(text.contains("<redacted>"), "{text:?}");
    assert!(!text.contains("example"), "{text:?}");
    let LoginOutcome::Unsupported(step) = outcome else {
        panic!("expected Unsupported");
    };
    assert_eq!(step.step().as_str(), "step with spaces @ example");
}

#[test]
fn plain_selectors_are_shown_in_errors() {
    let v = vector::compute();
    let init = edited(vector::init_response_dict(&v), |d| {
        d.insert("sp".to_owned(), Value::String("s2k_fo".to_owned()));
    });
    let auth = authenticator(vec![ok(init)]);
    let err = authenticate(&auth).unwrap_err();
    assert!(err.to_string().contains("`s2k_fo`"), "{err}");
}

// Trait object-safety shape: the traits are generic, never `dyn`.
fn _assert_send_sync<T: Transport + AnisetteProvider + Entropy>() {}
