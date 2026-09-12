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

//! Offline service-token protocol regressions using exclusively synthetic material.

mod support;

use coffer_protocol::tokens::{EpochMillis, Service, SessionMaterialRef, TokenClient, TokenError};
use support::{FixedAnisette, ScriptedTransport, block_on, fixture, ok};

#[test]
fn independent_openssl_token_from_stored_fields() {
    let transport = ScriptedTransport::new(vec![ok(fixture("apptokens/response.plist"))]);
    let key: [u8; 32] = core::array::from_fn(|i| i as u8);
    let input =
        SessionMaterialRef::new("SYNTHETIC-ADSID", "SYNTHETIC-IDMS", &key, &[0, 255, 128, 1])
            .unwrap();
    let client = TokenClient::new(&transport, &FixedAnisette);
    let token = block_on(client.issue(input, Service::XcodeAuthentication, &|| {
        EpochMillis::new(1_999_999_999_999)
    }))
    .unwrap();
    assert_eq!(token.service(), Service::XcodeAuthentication);
    assert_eq!(token.account_id(), "SYNTHETIC-ADSID");
    assert_eq!(token.expires_at().as_u64(), 2_000_000_000_000);
    assert_eq!(token.expose_secret(), "SYNTHETIC-SERVICE-TOKEN");
    assert_eq!(format!("{token:?}"), "IssuedToken(<redacted>)");
    assert_eq!(transport.count(), 1);
    let requests = transport.requests();
    assert_eq!(
        requests[0].body.as_ref().unwrap().as_slice(),
        fixture("apptokens/request.plist")
    );
    assert_eq!(requests[0].method, coffer_protocol::transport::Method::Post);
    assert_eq!(requests[0].url, coffer_protocol::auth::GSA_ENDPOINT);
    assert_eq!(requests[0].header("Content-Type"), Some("text/x-xml-plist"));
    assert_eq!(
        requests[0].header("User-Agent"),
        Some("AuthKit/1 (Macintosh; OS X 27.0) (com.apple.dt.Xcode/26.5)")
    );
}

#[test]
fn request_uses_typed_capabilities_and_canonical_plist_prologue() {
    let transport = ScriptedTransport::new(vec![ok(fixture("apptokens/response.plist"))]);
    let key = key();
    let input =
        SessionMaterialRef::new("SYNTHETIC-ADSID", "SYNTHETIC-IDMS", &key, &[0, 255, 128, 1])
            .unwrap();
    block_on(TokenClient::new(&transport, &FixedAnisette).issue(
        input,
        Service::XcodeAuthentication,
        &|| EpochMillis::new(1),
    ))
    .unwrap();
    assert_eq!(transport.count(), 1);
    let requests = transport.requests();
    let body = requests[0].body.as_ref().unwrap();
    // Independent plist decoding is used only on synthetic test data.
    let root = plist::Value::from_reader_xml(body.as_slice()).unwrap();
    let request = root.as_dictionary().unwrap()["Request"]
        .as_dictionary()
        .unwrap();
    let cpd = request["cpd"].as_dictionary().unwrap();
    for (name, value) in [
        ("bootstrap", true),
        ("icscrec", true),
        ("pbe", false),
        ("prkgen", true),
    ] {
        assert_eq!(cpd[name].as_boolean(), Some(value));
    }
    assert_eq!(cpd["svct"].as_string(), Some("iCloud"));
    assert_eq!(request["c"].as_data(), Some(&[0, 255, 128, 1][..]));
    let m1 = fixture("gsa/init_request.plist");
    let prefix = m1
        .split_inclusive(|b| *b == b'\n')
        .take(3)
        .flatten()
        .copied()
        .collect::<Vec<_>>();
    assert!(body.starts_with(&prefix));
}

#[test]
fn expiry_boundary_does_not_retry() {
    let transport = ScriptedTransport::new(vec![ok(fixture("apptokens/response.plist"))]);
    let key: [u8; 32] = core::array::from_fn(|i| i as u8);
    let input =
        SessionMaterialRef::new("SYNTHETIC-ADSID", "SYNTHETIC-IDMS", &key, &[0, 255]).unwrap();
    assert_eq!(
        block_on(TokenClient::new(&transport, &FixedAnisette).issue(
            input,
            Service::XcodeAuthentication,
            &|| EpochMillis::new(2_000_000_000_000)
        ))
        .unwrap_err(),
        TokenError::Expired
    );
    assert_eq!(transport.count(), 1);
}

fn key() -> [u8; 32] {
    core::array::from_fn(|i| i as u8)
}
fn envelope(et: &[u8]) -> Vec<u8> {
    use base64::Engine as _;
    format!("<plist version=\"1.0\"><dict><key>Response</key><dict><key>Status</key><dict><key>ec</key><integer>0</integer></dict><key>et</key><data>{}</data></dict></dict></plist>", base64::engine::general_purpose::STANDARD.encode(et)).into_bytes()
}
fn encrypt(plaintext: &[u8]) -> Vec<u8> {
    use aes_gcm::{AeadInOut, AesGcm, KeyInit, aead::consts::U16, aes::Aes256};
    let cipher = AesGcm::<Aes256, U16>::new_from_slice(&key()).unwrap();
    let nonce = aes_gcm::Nonce::<U16>::from([0x42; 16]);
    let mut ciphertext = plaintext.to_vec();
    let tag = cipher
        .encrypt_inout_detached(&nonce, b"XYZ", ciphertext.as_mut_slice().into())
        .unwrap();
    [
        b"XYZ".as_slice(),
        nonce.as_slice(),
        &ciphertext,
        tag.as_slice(),
    ]
    .concat()
}
fn outcome(
    step: support::Step,
    key: &[u8],
) -> Result<coffer_protocol::tokens::IssuedToken, TokenError> {
    let transport = ScriptedTransport::new(vec![step]);
    let input =
        SessionMaterialRef::new("SYNTHETIC-ADSID", "SYNTHETIC-IDMS", key, &[0, 255]).unwrap();
    let out = block_on(TokenClient::new(&transport, &FixedAnisette).issue(
        input,
        Service::XcodeAuthentication,
        &|| EpochMillis::new(1),
    ));
    assert_eq!(transport.count(), 1);
    if let Err(e) = out {
        assert!(!format!("{e:?} {e}").contains("SYNTHETIC"));
        assert!(std::error::Error::source(&e).is_none());
    }
    out
}
fn failure(body: Vec<u8>) -> TokenError {
    outcome(ok(body), &key()).unwrap_err()
}
fn inner() -> String {
    String::from_utf8(fixture("apptokens/plaintext.plist")).unwrap()
}

#[test]
fn independent_hmac_and_gcm_oracles() {
    use hmac::{Hmac, Mac};
    // RFC 4231 test case 1 checks the primitive separately from composition.
    let mut hmac = <Hmac<sha2::Sha256> as hmac::KeyInit>::new_from_slice(&[0x0b; 20]).unwrap();
    hmac.update(b"Hi There");
    assert_eq!(
        support::hex(&hmac.finalize().into_bytes()),
        "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
    );
    // The production request is byte-exact against the independently generated
    // Python HMAC vector, while the valid decrypt oracle is OpenSSL, not encrypt().
    let request =
        plist::Value::from_reader_xml(std::io::Cursor::new(fixture("apptokens/request.plist")))
            .unwrap();
    let checksum = request.as_dictionary().unwrap()["Request"]
        .as_dictionary()
        .unwrap()["checksum"]
        .as_data()
        .unwrap();
    assert_eq!(
        support::hex(checksum),
        "570ac6bc93250e307355eb4fb4fdc2b897e015d6d01b07765cae57c93296a9dd"
    );
}

#[test]
fn every_envelope_truncation_and_authenticated_component_fails_closed() {
    let et = support::unhex(
        std::str::from_utf8(&fixture("apptokens/et.hex"))
            .unwrap()
            .trim(),
    );
    for n in 0..et.len() {
        assert!(
            outcome(ok(envelope(&et[..n])), &key()).is_err(),
            "truncation {n}"
        );
    }
    for index in [3, 18, 19, et.len() - 17, et.len() - 1] {
        let mut bad = et.clone();
        bad[index] ^= 1;
        assert_eq!(failure(envelope(&bad)), TokenError::AuthenticationTag);
    }
    let mut bad = et.clone();
    bad[0] ^= 1;
    assert_eq!(failure(envelope(&bad)), TokenError::Unsupported);
    assert_eq!(
        outcome(ok(envelope(&et)), &[0; 32]).unwrap_err(),
        TokenError::AuthenticationTag
    );
    assert_eq!(failure(envelope(&vec![0; 65537])), TokenError::TooLarge);
    assert_eq!(
        failure(envelope(&encrypt(b""))),
        TokenError::MalformedPlist {
            stage: coffer_protocol::tokens::ResponseStage::AuthenticatedPlist,
            problem: coffer_protocol::tokens::PlistProblem::Structure,
        }
    );
    assert_eq!(
        failure(envelope(&encrypt(b"bplist00synthetic"))),
        TokenError::Unsupported
    );
}

#[test]
fn strict_outer_grammar_rejects_ambiguous_and_bounded_inputs() {
    let good = String::from_utf8(fixture("apptokens/response.plist")).unwrap();
    for bad in [
        good.replace("<key>ec</key>", "<key>ec</key><integer>0</integer><key>ec</key>"),
        good.replace("<key>ec</key>", "<key>ec</key><integer>0</integer><key>&#101;c</key>"),
        good.replace("<key>et</key>", "<key>et</key><data/><key>et</key>"),
        good.replace("<key>Status</key>", "<key>Status</key><dict/><key>Status</key>"),
        good.replace("<key>Response</key>", "<key>Response</key><dict/><key>Response</key>"),
        good.replace("<key>ec</key>", "<key>SYNTHETIC-UNKNOWN</key><string>x</string><key>SYNTHETIC-UNKNOWN</key><string>y</string><key>ec</key>"),
        good.replace("<integer>0</integer>", "<string>0</string>"),
        good.replace("<integer>0</integer>", "<integer>9223372036854775808</integer>"),
        good.replace("<integer>0</integer>", "<integer>+0</integer>"),
        good.replace("<integer>0</integer>", "<integer> 0 </integer>"),
        good.replace("<integer>0</integer>", "<integer>&bogus;</integer>"),
        good.replace("<integer>0</integer>", "<integer>&#0;</integer>"),
        good.replace("<integer>0</integer>", "<integer>&#xD800;</integer>"),
        good.replace("<integer>0</integer>", "<integer>&#999999999999999999999999;</integer>"),
        good.replace("<data>", "<data>!"),
        good.replace("<dict>", "<x:dict>"),
        good.replace("<dict>", "<dict attr=\"SYNTHETIC\">"),
        good.replace("<key>et</key>", "<key>et</key><key>extra</key>"),
        good.replace("<key>et</key>", "<string>et</string>"),
        good.replace("<dict>", "<array>"),
        format!("{good}{good}"), format!("{good}<plist version=\"1.0\"><dict/></plist>"),
        format!("{good}junk"), format!("{good}<![CDATA[SYNTHETIC]]>"),
        format!("{good}<!--SYNTHETIC-->"),
        good.replace("<plist", "<!DOCTYPE plist [<!ENTITY secret SYSTEM \"file:///synthetic\">]><plist"),
        good.replace("<plist", "<!DOCTYPE plist SYSTEM \"https://synthetic.invalid/\"><plist"),
    ] {
        if bad == good { continue; }
        assert!(outcome(ok(bad.into_bytes()), &key()).is_err());
    }
    for n in 0..good.len() {
        assert!(outcome(ok(good.as_bytes()[..n].to_vec()), &key()).is_err());
    }
    assert_eq!(failure(vec![b' '; 128 * 1024 + 1]), TokenError::TooLarge);
    for field in [
        format!("<key>{}</key><string>x</string>", "x".repeat(257)),
        format!("<key>x</key><string>{}</string>", "x".repeat(4097)),
        format!(
            "<key>x</key>{}<string>x</string>{}",
            "<array>".repeat(9),
            "</array>".repeat(9)
        ),
        "<key>x</key><array/>".repeat(260),
    ] {
        assert!(
            outcome(
                ok(good
                    .replace("<key>Response</key>", &(field + "<key>Response</key>"))
                    .into_bytes()),
                &key()
            )
            .is_err()
        );
    }
    // The exact standard declaration is inert: no DTD/entity is resolved.
    let dtd = "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">";
    assert!(
        outcome(
            ok(good
                .replace("<plist", &(dtd.to_owned() + "<plist"))
                .into_bytes()),
            &key()
        )
        .is_ok()
    );
    assert!(outcome(ok(format!("{good}\r\n\t ").into_bytes()), &key()).is_ok());
}

#[test]
fn inner_fields_types_duplicates_expiry_and_service_are_validated() {
    let good = inner();
    for bad in [
        good.replace("<key>t</key>", "<key>t</key><dict/><key>t</key>"),
        good.replace(
            "<key>token</key>",
            "<key>token</key><string>x</string><key>token</key>",
        ),
        good.replace(
            "<key>expiry</key>",
            "<key>expiry</key><integer>1</integer><key>expiry</key>",
        ),
        good.replace("<key>token</key>", "<key>missing</key>"),
        good.replace("<key>expiry</key>", "<key>missing</key>"),
        good.replace("SYNTHETIC-SERVICE-TOKEN", ""),
        good.replace("SYNTHETIC-SERVICE-TOKEN", "x&#10;y"),
        good.replace("2000000000000", "-1"),
        good.replace("2000000000000", "18446744073709551616"),
        good.replace(
            "<integer>2000000000000</integer>",
            "<string>2000000000000</string>",
        ),
        good.replace("SYNTHETIC-SERVICE-TOKEN", &"x".repeat(4097)),
    ] {
        assert!(outcome(ok(envelope(&encrypt(bad.as_bytes()))), &key()).is_err());
    }
    let wrong_service = good.replace("com.apple.gs.xcode.auth", "SYNTHETIC-OTHER-SERVICE");
    assert_eq!(
        failure(envelope(&encrypt(wrong_service.as_bytes()))),
        TokenError::Unsupported
    );
    let duplicate_service = good.replace(
        "<key>com.apple.gs.xcode.auth</key>",
        "<key>com.apple.gs.xcode.auth</key><dict/><key>com.apple.gs.xcode.auth</key>",
    );
    assert_eq!(
        failure(envelope(&encrypt(duplicate_service.as_bytes()))),
        TokenError::MalformedPlist {
            stage: coffer_protocol::tokens::ResponseStage::AuthenticatedPlist,
            problem: coffer_protocol::tokens::PlistProblem::DuplicateKey,
        }
    );
    let multiple_service = good.replace(
        "<key>com.apple.gs.xcode.auth</key>",
        "<key>other</key><dict/><key>com.apple.gs.xcode.auth</key>",
    );
    assert_eq!(
        failure(envelope(&encrypt(multiple_service.as_bytes()))),
        TokenError::Unsupported
    );
    let escaped = good.replace(
        "SYNTHETIC-SERVICE-TOKEN",
        "x&amp;&lt;&gt;&quot;&apos;&#65;&#x42;",
    );
    assert_eq!(
        outcome(ok(envelope(&encrypt(escaped.as_bytes()))), &key())
            .unwrap()
            .expose_secret(),
        "x&<>\"'AB"
    );
}

#[test]
fn http_status_diagnostics_exclude_response_material() {
    for status in [400, 401, 403, 429, 500, 503] {
        let error = outcome(support::reply(status, b"SYNTHETIC-SECRET-BODY"), &key()).unwrap_err();
        assert_eq!(
            error.to_string(),
            format!("service-token request returned HTTP {status}")
        );
        assert_eq!(format!("{error:?}"), format!("Http {{ status: {status} }}"));
    }
}

#[test]
fn rejection_diagnostics_distinguish_http_and_embedded_status() {
    assert_eq!(
        outcome(support::reply(401, b"SYNTHETIC-SECRET-BODY"), &key())
            .unwrap_err()
            .to_string(),
        "service-token request returned HTTP 401"
    );
    for (code, auth) in [(-999999, false), (0, true), (-999999, true)] {
        let selector = if auth {
            "<key>au</key><string>SYNTHETIC-SELECTOR</string>"
        } else {
            ""
        };
        let body = format!(
            "<plist version=\"1.0\"><dict><key>Response</key><dict><key>Status</key><dict><key>ec</key><integer>{code}</integer><key>em</key><string>SYNTHETIC-ERROR</string>{selector}</dict></dict></dict></plist>"
        );
        let error = failure(body.into_bytes());
        assert_eq!(
            error.to_string(),
            format!(
                "service-token protocol rejection: code {code}; additional authentication: {auth}"
            )
        );
        assert!(!format!("{error:?}").contains("SYNTHETIC"));
    }
}

#[test]
fn rejection_http_transport_and_custom_adapter_errors_never_retry_or_leak() {
    use coffer_protocol::{
        anisette::{AnisetteData, AnisetteError, AnisetteProvider},
        transport::TransportError,
    };
    let good = String::from_utf8(fixture("apptokens/response.plist")).unwrap();
    for (body, code, additional_authentication) in [
        (
            good.replace("<integer>0</integer>", "<integer>-999999</integer>"),
            -999999,
            false,
        ),
        (
            good.replace(
                "<key>ec</key>",
                "<key>au</key><string>SYNTHETIC-REMOTE</string><key>ec</key>",
            ),
            0,
            true,
        ),
    ] {
        assert_eq!(
            failure(body.into_bytes()),
            TokenError::Rejected {
                code,
                additional_authentication
            }
        );
    }
    assert_eq!(
        outcome(support::reply(401, b"SYNTHETIC-BODY"), &key()).unwrap_err(),
        TokenError::Http { status: 401 }
    );
    for status in [201, 204, 301, 302, 403, 407, 429, 500, 503] {
        assert_eq!(
            outcome(support::reply(status, b"SYNTHETIC-BODY"), &key()).unwrap_err(),
            TokenError::Http { status }
        );
    }
    for error in [
        TransportError::Timeout,
        TransportError::Connect {
            detail: "SYNTHETIC-CONNECT".into(),
        },
        TransportError::Tls {
            detail: "SYNTHETIC-TLS".into(),
        },
        TransportError::Other {
            detail: "SYNTHETIC-OTHER".into(),
        },
    ] {
        assert_eq!(
            outcome(support::Step::Fail(error), &key()).unwrap_err(),
            TokenError::Transport
        );
    }
    struct Broken;
    impl AnisetteProvider for Broken {
        async fn anisette(&self) -> Result<AnisetteData, AnisetteError> {
            Err(AnisetteError::Unavailable {
                detail: "SYNTHETIC-PROVIDER".into(),
            })
        }
    }
    let transport = ScriptedTransport::new(vec![]);
    let k = key();
    let input =
        || SessionMaterialRef::new("SYNTHETIC-ADSID", "SYNTHETIC-IDMS", &k, b"cookie").unwrap();
    let error = block_on(TokenClient::new(&transport, &Broken).issue(
        input(),
        Service::XcodeAuthentication,
        &|| EpochMillis::new(1),
    ))
    .unwrap_err();
    assert_eq!(error, TokenError::Anisette);
    assert!(!format!("{error:?} {error}").contains("SYNTHETIC"));
    assert_eq!(
        block_on(
            TokenClient::new(&transport, &support::InjectingAnisette).issue(
                input(),
                Service::XcodeAuthentication,
                &|| EpochMillis::new(1)
            )
        )
        .unwrap_err(),
        TokenError::Anisette
    );
    assert_eq!(transport.count(), 0);
}

#[test]
fn session_validation_and_clock_fail_before_network() {
    for (account, idms, key, cookie) in [
        ("", "idms", vec![0; 32], vec![1]),
        ("account", "", vec![0; 32], vec![1]),
        ("x\n", "idms", vec![0; 32], vec![1]),
        ("x", "idms", vec![0; 31], vec![1]),
        ("x", "idms", vec![0; 33], vec![1]),
        ("x", "idms", vec![0; 32], vec![]),
        ("x", "idms", vec![0; 32], vec![1; 4097]),
    ] {
        assert_eq!(
            SessionMaterialRef::new(account, idms, &key, &cookie).unwrap_err(),
            TokenError::InvalidSession
        );
    }
    assert!(SessionMaterialRef::new(&"x".repeat(1025), "idms", &key(), b"c").is_err());
    assert!(EpochMillis::new(u64::MAX).is_err());
    let transport = ScriptedTransport::new(vec![]);
    let k = key();
    let input = SessionMaterialRef::new("x", "idms", &k, b"c").unwrap();
    assert_eq!(
        block_on(TokenClient::new(&transport, &FixedAnisette).issue(
            input,
            Service::XcodeAuthentication,
            &|| Err(TokenError::Clock)
        ))
        .unwrap_err(),
        TokenError::Clock
    );
    assert_eq!(transport.count(), 0);
}

#[test]
fn non_string_scalars_cannot_be_used_as_tokens() {
    for value in ["<real>1.5</real>", "<date>2026-09-11T00:00:00Z</date>"] {
        let bad = inner().replace("<string>SYNTHETIC-SERVICE-TOKEN</string>", value);
        assert_eq!(
            failure(envelope(&encrypt(bad.as_bytes()))),
            TokenError::MalformedResponse {
                stage: coffer_protocol::tokens::ResponseStage::Token
            }
        );
    }
}

#[test]
fn untrusted_transport_cap_and_clock_rollback_are_rechecked() {
    assert_eq!(
        outcome(
            support::Step::ReplyUncapped {
                status: 200,
                body: vec![b' '; 128 * 1024 + 1]
            },
            &key()
        )
        .unwrap_err(),
        TokenError::TooLarge
    );
    let transport = ScriptedTransport::new(vec![ok(fixture("apptokens/response.plist"))]);
    let clock = std::sync::atomic::AtomicU64::new(10);
    let key = key();
    let input = SessionMaterialRef::new("SYNTHETIC-ADSID", "SYNTHETIC-IDMS", &key, b"c").unwrap();
    let result = block_on(TokenClient::new(&transport, &FixedAnisette).issue(
        input,
        Service::XcodeAuthentication,
        &|| EpochMillis::new(clock.fetch_sub(1, std::sync::atomic::Ordering::SeqCst)),
    ));
    assert_eq!(result.unwrap_err(), TokenError::Clock);
    assert_eq!(transport.count(), 1);
}

#[test]
fn malformed_response_locations_are_static_and_stop_after_one_exchange() {
    use coffer_protocol::tokens::ResponseStage as Stage;
    let plist = |value: &str| format!("<plist version=\"1.0\">{value}</plist>").into_bytes();
    let response = |value: &str| plist(&format!("<dict><key>Response</key>{value}</dict>"));
    let status = |value: &str| {
        response(&format!(
            "<dict><key>Status</key><dict>{value}</dict></dict>"
        ))
    };
    for (body, stage) in [
        (b"SYNTHETIC-SECRET-NOT-XML".to_vec(), Stage::OuterPlist),
        (plist("<dict/>"), Stage::Response),
        (
            response("<string>SYNTHETIC-SECRET</string>"),
            Stage::Response,
        ),
        (response("<dict/>"), Stage::Status),
        (
            response("<dict><key>Status</key><string>SYNTHETIC-SECRET</string></dict>"),
            Stage::Status,
        ),
        (status(""), Stage::StatusCode),
        (
            status("<key>ec</key><string>SYNTHETIC-SECRET</string>"),
            Stage::StatusCode,
        ),
        (
            status("<key>ec</key><integer>0</integer><key>em</key><data/>"),
            Stage::StatusMessage,
        ),
        (
            status("<key>ec</key><integer>0</integer><key>au</key><data/>"),
            Stage::AdditionalAuthentication,
        ),
        (status("<key>ec</key><integer>0</integer>"), Stage::Envelope),
        (envelope(&[]), Stage::Envelope),
        (
            envelope(&encrypt(b"SYNTHETIC-SECRET-NOT-XML")),
            Stage::AuthenticatedPlist,
        ),
        (envelope(&encrypt(&plist("<dict/>"))), Stage::Services),
        (
            envelope(&encrypt(&plist(
                "<dict><key>t</key><string>SYNTHETIC-SECRET</string></dict>",
            ))),
            Stage::Services,
        ),
        (
            envelope(&encrypt(
                inner()
                    .replace("<key>token</key>", "<key>SYNTHETIC-MISSING</key>")
                    .as_bytes(),
            )),
            Stage::Token,
        ),
        (
            envelope(&encrypt(
                inner()
                    .replace("<key>expiry</key>", "<key>SYNTHETIC-MISSING</key>")
                    .as_bytes(),
            )),
            Stage::Expiry,
        ),
        (
            envelope(&encrypt(inner().replace("2000000000000", "-1").as_bytes())),
            Stage::Expiry,
        ),
    ] {
        let error = failure(body);
        let expected = if matches!(stage, Stage::OuterPlist | Stage::AuthenticatedPlist) {
            TokenError::MalformedPlist {
                stage,
                problem: coffer_protocol::tokens::PlistProblem::Structure,
            }
        } else {
            TokenError::MalformedResponse { stage }
        };
        assert_eq!(error, expected);
        assert!(error.to_string().contains(&stage.to_string()));
        assert!(!format!("{error:?} {error}").contains("SYNTHETIC"));
    }
}

#[test]
fn plist_problem_categories_never_retain_remote_material() {
    use coffer_protocol::tokens::{PlistProblem as Problem, ResponseStage as Stage};
    let wrap = |value: &str| {
        format!("<plist version=\"1.0\"><dict><key>x</key>{value}</dict></plist>").into_bytes()
    };
    for (plaintext, problem) in [
        (vec![0xff], Problem::Encoding),
        (b"SYNTHETIC\0SECRET".to_vec(), Problem::Character),
        (wrap("<SYNTHETIC-SECRET/>"), Problem::Markup),
        (wrap("<dict></array>"), Problem::XmlSyntax),
        (b"SYNTHETIC-SECRET".to_vec(), Problem::Structure),
        (
            wrap("<dict><key>SYNTHETIC</key><true/><key>SYNTHETIC</key><false/></dict>"),
            Problem::DuplicateKey,
        ),
        (wrap("<string>&SYNTHETIC;</string>"), Problem::Entity),
        (wrap("<string><true/></string>"), Problem::Scalar),
        (
            wrap("<integer>18446744073709551615</integer>"),
            Problem::Integer,
        ),
        (wrap("<data>SYNTHETIC!</data>"), Problem::Base64),
        (wrap("<real>nan</real>"), Problem::Real),
        (wrap("<date>2026-02-30T00:00:00Z</date>"), Problem::Date),
    ] {
        for (body, stage) in [
            (plaintext.clone(), Stage::OuterPlist),
            (envelope(&encrypt(&plaintext)), Stage::AuthenticatedPlist),
        ] {
            let error = failure(body);
            assert_eq!(error, TokenError::MalformedPlist { stage, problem });
            assert!(error.to_string().contains(&problem.to_string()));
            assert!(!format!("{error:?} {error}").contains("SYNTHETIC"));
        }
    }
}
