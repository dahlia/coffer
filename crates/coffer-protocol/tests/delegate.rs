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

//! Independent synthetic tests of the explicit delegate API; no live adapters.
mod support;

use coffer_protocol::anisette::{AnisetteData, AnisetteError, AnisetteProvider};
use coffer_protocol::delegate::{
    ClientIdRef, DelegateClient, DelegateCredentials, DelegateError as E, DelegateMaterialRef,
    MAX_CLIENT_ID_LEN, MAX_IDENTIFIER_LEN, MAX_RESPONSE_BODY, MAX_TOKEN_LEN,
};
use coffer_protocol::transport::{Method, TransportError};
use std::sync::atomic::{AtomicUsize, Ordering};
use support::{ScriptedTransport, Step, block_on, ok, sample_anisette};

const SUCCESS: &str = include_str!("fixtures/delegate/success.plist");
const ACCOUNT: &str = "synthetic&<\"'>@example.invalid";
const PET: &str = "SYNTHETIC:PET<&\"'>";
const CLIENT: &str = "synthetic<&\"'>-client";
const ADSID: &str = "synthetic-separate-adsid";

struct Provider {
    calls: AtomicUsize,
    change: fn(&mut AnisetteData),
    fail: bool,
}
impl Default for Provider {
    fn default() -> Self {
        Self {
            calls: AtomicUsize::new(0),
            change: |_| {},
            fail: false,
        }
    }
}
impl AnisetteProvider for Provider {
    async fn anisette(&self) -> Result<AnisetteData, AnisetteError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if self.fail {
            return Err(AnisetteError::Unavailable {
                detail: "SYNTHETIC-SECRET-ERROR".into(),
            });
        }
        let mut data = sample_anisette();
        (self.change)(&mut data);
        Ok(data)
    }
}
fn material() -> DelegateMaterialRef<'static> {
    DelegateMaterialRef::new(ACCOUNT, ADSID, Some(PET), ClientIdRef::new(CLIENT).unwrap()).unwrap()
}
fn run(step: Step) -> Result<DelegateCredentials, E> {
    let transport = ScriptedTransport::new(vec![step, ok(SUCCESS)]);
    let provider = Provider::default();
    let result = block_on(DelegateClient::new(&transport, &provider).issue(material()));
    assert_eq!(provider.calls.load(Ordering::SeqCst), 1);
    assert_eq!(transport.count(), 1);
    assert_eq!(transport.remaining(), 1);
    result
}
fn reject(xml: impl Into<Vec<u8>>, expected: E) {
    let error = run(ok(xml)).unwrap_err();
    assert_eq!(error, expected);
    assert!(std::error::Error::source(&error).is_none());
}
fn unknown(value: &str) -> String {
    SUCCESS.replace(
        "<key>ignoredURL</key>",
        &format!("<key>unknown</key>{value}<key>ignoredURL</key>"),
    )
}

#[test]
fn exact_request_and_distinct_owners() {
    let transport = ScriptedTransport::new(vec![ok(SUCCESS)]);
    let provider = Provider::default();
    let client = DelegateClient::new(&transport, &provider);
    assert_eq!(format!("{client:?}"), "DelegateClient(<redacted>)");
    let credentials = block_on(client.issue(material())).unwrap();
    assert_eq!(credentials.dsid(), "000123-synthetic-dsid");
    assert_eq!(
        credentials.mme_auth_token().expose_secret(),
        "SYNTHETIC-MME-TOKEN"
    );
    assert_eq!(
        credentials.cloudkit_token().expose_secret(),
        "SYNTHETIC-CLOUDKIT-TOKEN"
    );
    assert_eq!(
        format!("{credentials:?}"),
        "DelegateCredentials(<redacted>)"
    );
    assert_eq!(
        format!("{:?}", credentials.mme_auth_token()),
        "MmeAuthToken(<redacted>)"
    );
    assert_eq!(
        format!("{:?}", credentials.cloudkit_token()),
        "CloudKitToken(<redacted>)"
    );
    assert_eq!(
        format!("{:?}", material()),
        "DelegateMaterialRef(<redacted>)"
    );
    assert_eq!(
        format!("{:?}", ClientIdRef::new(CLIENT).unwrap()),
        "ClientIdRef(<redacted>)"
    );
    assert_eq!(transport.count(), 1);
    assert_eq!(provider.calls.load(Ordering::SeqCst), 1);
    let requests = transport.requests();
    let request = &requests[0];
    assert_eq!(request.method, Method::Post);
    assert_eq!(
        request.url,
        "https://setup.icloud.com/setup/iosbuddy/loginDelegates"
    );
    assert_eq!(
        request.body.as_ref().unwrap().as_slice(),
        include_bytes!("fixtures/delegate/request.plist")
    );
    assert_eq!(
        request.header("Authorization"),
        Some(include_str!("fixtures/delegate/basic.txt").trim_end())
    );
    // The oracle file was generated with Python's standard-library Base64,
    // independently of the production Rust base64 crate and request encoder.
    let data = sample_anisette();
    let expected = [
        ("Content-Type", "text/xml"),
        (
            "User-Agent",
            "com.apple.iCloudHelper/282 CFNetwork/1408.0.4 Darwin/22.5.0",
        ),
        (
            "X-Mme-Client-Info",
            "<MacBookPro18,3> <Mac OS X;13.4.1;22F8> <com.apple.AOSKit/282 (com.apple.accountsd/113)>",
        ),
        ("X-Apple-ADSID", ADSID),
        ("X-Apple-I-Client-Time", data.client_time.as_str()),
        ("X-Apple-I-TimeZone", data.time_zone.as_str()),
        ("loc", data.locale.as_str()),
        ("X-Apple-Locale", data.locale.as_str()),
        ("X-Apple-I-MD", data.one_time_password.as_str()),
        ("X-Apple-I-MD-LU", data.local_user_id.as_str()),
        ("X-Apple-I-MD-M", data.machine_id.as_str()),
        ("X-Apple-I-MD-RINFO", data.routing_info.as_str()),
        ("X-Mme-Device-Id", data.device_id.as_str()),
        ("X-Apple-I-SRL-NO", data.serial_number.as_str()),
    ];
    assert_eq!(request.headers.len(), expected.len() + 1);
    for (key, value) in expected {
        assert_eq!(request.header(key), Some(value));
    }
}

#[test]
fn rfc7617_basic_oracle() {
    let t = ScriptedTransport::new(vec![ok(SUCCESS)]);
    let p = Provider::default();
    let input = DelegateMaterialRef::new(
        "Aladdin",
        ADSID,
        Some("open sesame"),
        ClientIdRef::new(CLIENT).unwrap(),
    )
    .unwrap();
    block_on(DelegateClient::new(&t, &p).issue(input)).unwrap();
    assert_eq!(
        t.requests()[0].header("Authorization"),
        Some("Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==")
    );
}

#[test]
fn status_types_and_each_rejection_are_fail_closed() {
    for (root, delegate, expected) in [
        (0, 0, None),
        (7, 0, Some(E::RootRejected)),
        (0, -8, Some(E::DelegateRejected)),
        (7, -8, Some(E::RootRejected)),
    ] {
        let xml = SUCCESS.replacen(
            "<integer>0</integer>",
            &format!("<integer>{root}</integer>"),
            1,
        );
        let needle = "<key>status</key><integer>0</integer>\n<key>service-data</key>";
        let xml = xml.replace(
            needle,
            &format!("<key>status</key><integer>{delegate}</integer>\n<key>service-data</key>"),
        );
        match expected {
            Some(e) => reject(xml, e),
            None => {
                run(ok(xml)).unwrap();
            }
        }
    }
    for value in [
        "<true/>",
        "<false/>",
        "<string>0</string>",
        "<real>0.0</real>",
        "<data>AA==</data>",
        "<dict/>",
    ] {
        reject(
            SUCCESS.replacen("<integer>0</integer>", value, 1),
            E::Schema,
        );
        reject(
            SUCCESS.replace(
                "<key>status</key><integer>0</integer>\n<key>service-data</key>",
                &format!("<key>status</key>{value}\n<key>service-data</key>"),
            ),
            E::Schema,
        );
    }
    for key in [
        "<key>status</key><integer>0</integer>\n",
        "<key>status</key><integer>0</integer>\n<key>service-data</key>",
    ] {
        reject(
            SUCCESS.replacen(key, "", 1),
            if key.ends_with("<key>service-data</key>") {
                E::Malformed
            } else {
                E::Schema
            },
        );
    }
    reject(
        SUCCESS.replace(
            "<key>status</key><integer>0</integer>\n<key>service-data</key>",
            "<key>service-data</key>",
        ),
        E::Schema,
    );
}

#[test]
fn required_paths_types_empty_ascii_and_bounds() {
    for (key, value) in [
        ("dsid", "000123-synthetic-dsid"),
        ("mmeAuthToken", "SYNTHETIC-MME-TOKEN"),
        ("cloudKitToken", "SYNTHETIC-CLOUDKIT-TOKEN"),
    ] {
        let field = format!("<key>{key}</key><string>{value}</string>");
        reject(SUCCESS.replace(&field, ""), E::Schema);
        for replacement in [
            "<integer>123</integer>",
            "<true/>",
            "<real>1.0</real>",
            "<data>AA==</data>",
            "<dict/>",
            "<string/>",
            "<string>é</string>",
            "<string>&#10;</string>",
        ] {
            reject(
                SUCCESS.replace(&field, &format!("<key>{key}</key>{replacement}")),
                E::Schema,
            );
        }
        let max = if key == "dsid" {
            MAX_IDENTIFIER_LEN
        } else {
            MAX_TOKEN_LEN
        };
        run(ok(SUCCESS.replace(value, &"x".repeat(max)))).unwrap();
        reject(
            SUCCESS.replace(value, &"x".repeat(max + 1)),
            if key == "dsid" {
                E::Schema
            } else {
                E::TooLarge
            },
        );
    }
    for key in ["delegates", "com.apple.mobileme", "service-data", "tokens"] {
        reject(
            SUCCESS.replace(&format!("<key>{key}</key>"), "<key>different</key>"),
            E::Schema,
        );
    }
    let result = run(ok(SUCCESS.replace("000123-synthetic-dsid", "0000123"))).unwrap();
    assert_eq!(result.dsid(), "0000123");
}

#[test]
fn whole_document_validation_precedes_status_and_extraction() {
    for value in [
        "<dict><key>secret</key><string>a</string><key>secret</key><string>b</string></dict>",
        "<dict><key>secret</key><string>a</string><key>secr&#101;t</key><string>b</string></dict>",
        "<string>&unknown;</string>",
        "<string>]]></string>",
        "<data>Zh==</data>",
        "<real>NaN</real>",
        "<date>2026-02-30T00:00:00Z</date>",
        "<string>unterminated",
        "<dict><key>unpaired</key></dict>",
        "<SYNTHETIC-SECRET/>",
        "<string><![CDATA[secret]]></string>",
    ] {
        reject(unknown(value), E::Malformed);
        reject(
            unknown(value).replacen("<integer>0</integer>", "<integer>9</integer>", 1),
            E::Malformed,
        );
    }
    for key in [
        "status",
        "dsid",
        "delegates",
        "com.apple.mobileme",
        "service-data",
        "tokens",
        "mmeAuthToken",
        "cloudKitToken",
    ] {
        reject(
            SUCCESS.replace(
                &format!("<key>{key}</key>"),
                &format!("<key>{key}</key><string>duplicate</string><key>{key}</key>"),
            ),
            E::Malformed,
        );
    }
    for suffix in ["<dict/>", "trailing", "<!--comment-->"] {
        reject(format!("{SUCCESS}{suffix}"), E::Malformed);
    }
    for n in 0..SUCCESS.len() {
        if SUCCESS[..n].trim_end().ends_with("</plist>") {
            continue;
        }
        reject(SUCCESS.as_bytes()[..n].to_vec(), E::Malformed);
    }
    reject(b"bplist00synthetic".to_vec(), E::Unsupported);
    reject(vec![0xff], E::Malformed);
    reject(
        SUCCESS.replace(
            "<integer>0</integer>",
            "<integer>9223372036854775808</integer>",
        ),
        E::Malformed,
    );
}

#[test]
fn limits_apply_to_unknown_fields_and_uncooperative_transports() {
    reject(
        unknown(&format!("<string>{}</string>", "x".repeat(4097))),
        E::TooLarge,
    );
    reject(
        unknown(&format!(
            "{}<true/>{}",
            "<array>".repeat(7),
            "</array>".repeat(7)
        )),
        E::TooLarge,
    );
    run(ok(unknown(&format!(
        "{}<true/>{}",
        "<array>".repeat(6),
        "</array>".repeat(6)
    ))))
    .unwrap();
    reject(
        unknown(&format!("<array>{}</array>", "<true/>".repeat(512))),
        E::TooLarge,
    );
    reject(unknown("<string>&#x0;</string>"), E::Malformed);
    reject(
        unknown(&format!(
            "<dict><key>{}</key><true/></dict>",
            "k".repeat(257)
        )),
        E::TooLarge,
    );
    let padded = format!("{SUCCESS}{}", " ".repeat(MAX_RESPONSE_BODY - SUCCESS.len()));
    run(ok(padded.clone())).unwrap();
    assert_eq!(
        run(Step::ReplyUncapped {
            status: 200,
            body: format!("{padded} ").into_bytes()
        })
        .unwrap_err(),
        E::TooLarge
    );
    assert_eq!(run(ok(format!("{padded} "))).unwrap_err(), E::TooLarge);
}

#[test]
fn input_validation_happens_before_any_adapter() {
    let t = ScriptedTransport::new(vec![ok(SUCCESS)]);
    let p = Provider::default();
    let client = DelegateClient::new(&t, &p);
    let attempt = |account: &str, adsid: &str, pet: Option<&str>, id: &str| {
        let result =
            ClientIdRef::new(id).and_then(|id| DelegateMaterialRef::new(account, adsid, pet, id));
        match result {
            Ok(input) => block_on(client.issue(input)),
            Err(e) => Err(e),
        }
    };
    assert_eq!(
        attempt(ACCOUNT, ADSID, None, CLIENT).unwrap_err(),
        E::MissingPet
    );
    for bad in [
        "",
        "colon:name",
        "nonascii-é",
        "injected\r\nHeader: secret",
        "tab\t",
        "del\u{7f}",
        &"a".repeat(257),
    ] {
        assert_eq!(
            attempt(bad, ADSID, Some(PET), CLIENT).unwrap_err(),
            E::InvalidInput
        );
    }
    for bad in ["", "é", "\r\n", "\0", &"x".repeat(MAX_IDENTIFIER_LEN + 1)] {
        assert_eq!(
            attempt(ACCOUNT, bad, Some(PET), CLIENT).unwrap_err(),
            E::InvalidInput
        );
    }
    for bad in ["", "é", "\r\n", "\0", &"x".repeat(MAX_TOKEN_LEN + 1)] {
        assert_eq!(
            attempt(ACCOUNT, ADSID, Some(bad), CLIENT).unwrap_err(),
            E::InvalidInput
        );
    }
    for bad in ["", "é", "\r\n", "\0", &"x".repeat(MAX_CLIENT_ID_LEN + 1)] {
        assert_eq!(
            attempt(ACCOUNT, ADSID, Some(PET), bad).unwrap_err(),
            E::InvalidInput
        );
    }
    assert_eq!(t.count(), 0);
    assert_eq!(p.calls.load(Ordering::SeqCst), 0);
    // All local maxima accepted without any network/provisioning work.
    DelegateMaterialRef::new(
        &"a".repeat(256),
        &"a".repeat(MAX_IDENTIFIER_LEN),
        Some(&"p".repeat(MAX_TOKEN_LEN)),
        ClientIdRef::new(&"c".repeat(MAX_CLIENT_ID_LEN)).unwrap(),
    )
    .unwrap();
}

#[test]
fn provider_errors_and_injection_are_redacted_without_sending() {
    let modifications: [fn(&mut AnisetteData); 11] = [
        |d| d.one_time_password = "\r\nSYNTHETIC-SECRET".into(),
        |d| d.machine_id = "".into(),
        |d| d.routing_info = "é".into(),
        |d| d.local_user_id = "\0".into(),
        |d| d.serial_number = "x".repeat(1025),
        |d| d.client_info = "\r\n".into(),
        |d| d.device_id = "\n".into(),
        |d| d.client_time = "\r".into(),
        |d| d.time_zone = "\t".into(),
        |d| d.locale = "\u{7f}".into(),
        |_| {},
    ];
    for (i, change) in modifications.into_iter().enumerate() {
        let p = Provider {
            change,
            fail: i == 10,
            ..Provider::default()
        };
        let t = ScriptedTransport::new(vec![ok(SUCCESS)]);
        let error = block_on(DelegateClient::new(&t, &p).issue(material())).unwrap_err();
        assert_eq!(error, E::Anisette);
        assert_eq!(
            format!("{error:?}: {error}"),
            "Anisette: delegate anisette failed"
        );
        assert!(std::error::Error::source(&error).is_none());
        assert_eq!(t.count(), 0);
        assert_eq!(p.calls.load(Ordering::SeqCst), 1);
    }
}

#[test]
fn transport_http_and_status_failures_never_retry_or_leak_details() {
    for error in [
        TransportError::Timeout,
        TransportError::Connect {
            detail: "SYNTHETIC-SECRET".into(),
        },
        TransportError::Tls {
            detail: "SYNTHETIC-SECRET".into(),
        },
        TransportError::Other {
            detail: "SYNTHETIC-SECRET".into(),
        },
    ] {
        let error = run(Step::Fail(error)).unwrap_err();
        assert_eq!(error, E::Transport);
        assert_eq!(
            format!("{error:?}: {error}"),
            "Transport: delegate transport failed; issuance outcome may be unknown"
        );
        assert!(std::error::Error::source(&error).is_none());
    }
    for status in [0, 199, 201, 204, 301, 302, 307, 308, 401, 403, 429, 500] {
        // Even malformed bodies must not be parsed on non-200 HTTP responses.
        assert_eq!(
            run(Step::ReplyUncapped {
                status,
                body: b"SYNTHETIC-SECRET".to_vec()
            })
            .unwrap_err(),
            E::Http
        );
    }
}

#[test]
fn session_borrow_uses_account_adsid_and_pet_without_substitution() {
    use coffer_protocol::auth::{Authenticator, LoginOutcome};
    use coffer_protocol::secret::{AccountName, Password};
    use support::{FixedAnisette, FixedEntropy, vector};
    let v = vector::compute();
    for with_pet in [true, false] {
        let mut complete = vector::complete_response_dict(&v, None);
        if !with_pet {
            let mut spd = plist::Value::from_reader_xml(v.spd_plaintext.as_slice()).unwrap();
            spd.as_dictionary_mut().unwrap().remove("t");
            let (_, _, encrypted) = vector::encrypt_spd(&v.k, &vector::plist_bytes(spd));
            complete.insert("spd".into(), plist::Value::Data(encrypted));
        }
        let auth = Authenticator::new(
            ScriptedTransport::new(vec![
                ok(vector::init_response(&v)),
                ok(vector::plist_bytes(vector::envelope(complete))),
            ]),
            FixedAnisette,
            FixedEntropy(vector::a_secret()),
        );
        let outcome = block_on(
            auth.login(
                AccountName::new(vector::ACCOUNT.into()).unwrap(),
                Password::new(vector::PASSWORD.into()),
            )
            .authenticate(),
        )
        .unwrap();
        let LoginOutcome::Authenticated(session) = outcome else {
            panic!("expected synthetic session");
        };
        let t = ScriptedTransport::new(vec![ok(SUCCESS)]);
        let p = Provider::default();
        let input = DelegateMaterialRef::from_session(&session, ClientIdRef::new(CLIENT).unwrap());
        if with_pet {
            block_on(DelegateClient::new(&t, &p).issue(input.unwrap())).unwrap();
            let requests = t.requests();
            let request = &requests[0];
            assert_eq!(request.header("X-Apple-ADSID"), Some(vector::ADSID));
            let xml =
                plist::Value::from_reader_xml(request.body.as_ref().unwrap().as_slice()).unwrap();
            let root = xml.as_dictionary().unwrap();
            assert_eq!(root["apple-id"].as_string(), Some(vector::ACCOUNT));
            assert_eq!(root["password"].as_string(), Some(vector::PET));
            // Independent literal oracle generated by Python, using the
            // existing Coffer synthetic session account and PET.
            assert_eq!(
                request.header("Authorization"),
                Some(
                    "Basic Y29mZmVyLWZpeHR1cmVAZXhhbXBsZS5pbnZhbGlkOlNZTlRIRVRJQy1QRVQtVE9LRU4tTk9ULVJFQUw="
                )
            );
            assert_eq!(p.calls.load(Ordering::SeqCst), 1);
        } else {
            assert_eq!(input.unwrap_err(), E::MissingPet);
            assert_eq!(t.count(), 0);
            assert_eq!(p.calls.load(Ordering::SeqCst), 0);
        }
    }
}
