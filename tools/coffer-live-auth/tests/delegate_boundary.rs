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

//! Offline protocol-to-adapter integration; no production exchange is created.
use coffer_live_auth::delegate_transport::{DelegateTransport, validate_request};
use coffer_live_auth::transport::{Deadlines, Exchange};
use coffer_protocol::anisette::{AnisetteData, AnisetteError, AnisetteProvider};
use coffer_protocol::delegate::{ClientIdRef, DelegateClient, DelegateMaterialRef};
use coffer_protocol::transport::{Request, Response, TransportError};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

struct SyntheticAnisette;
impl AnisetteProvider for SyntheticAnisette {
    async fn anisette(&self) -> Result<AnisetteData, AnisetteError> {
        Ok(sample_anisette())
    }
}
fn sample_anisette() -> AnisetteData {
    AnisetteData {
        one_time_password: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_owned(),
        machine_id: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
            .to_owned(),
        routing_info: "17106176".to_owned(),
        local_user_id: "SYNTHETICLOCALUSERID000000000000".to_owned(),
        serial_number: "0".to_owned(),
        client_info: "<Mac14,2> <macOS;27.0;26A5378j> <com.apple.AuthKit/1 (com.apple.akd/1.0)>"
            .to_owned(),
        device_id: "00000000-0000-4000-8000-000000000000".to_owned(),
        client_time: "2026-09-04T00:00:00Z".to_owned(),
        time_zone: "UTC".to_owned(),
        locale: "en_US".to_owned(),
    }
}
struct SyntheticExchange(Arc<AtomicUsize>);
impl Exchange for SyntheticExchange {
    fn exchange(&self, request: &Request, _timeout: Duration) -> Result<Response, TransportError> {
        validate_request(request)?;
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(Response::new(
            200,
            include_bytes!("../../../crates/coffer-protocol/tests/fixtures/delegate/success.plist")
                .to_vec(),
        ))
    }
}
#[test]
fn protocol_request_crosses_adapter_boundary_once() {
    let calls = Arc::new(AtomicUsize::new(0));
    let transport = DelegateTransport::new(
        SyntheticExchange(calls.clone()),
        Deadlines::starting_now(Duration::from_secs(5), Duration::from_secs(5)),
    );
    let provider = SyntheticAnisette;
    let input = DelegateMaterialRef::new(
        "synthetic@example.invalid",
        "synthetic-adsid",
        Some("SYNTHETIC-PET"),
        ClientIdRef::new("synthetic-client").unwrap(),
    )
    .unwrap();
    let credentials =
        futures_lite::future::block_on(DelegateClient::new(&transport, &provider).issue(input))
            .unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(credentials.dsid(), "000123-synthetic-dsid");
    assert_eq!(
        credentials.cloudkit_token().expose_secret(),
        "SYNTHETIC-CLOUDKIT-TOKEN"
    );
}

struct MaximumAnisette;
impl AnisetteProvider for MaximumAnisette {
    async fn anisette(&self) -> Result<AnisetteData, AnisetteError> {
        let mut data = sample_anisette();
        for value in [
            &mut data.one_time_password,
            &mut data.machine_id,
            &mut data.routing_info,
            &mut data.local_user_id,
            &mut data.serial_number,
            &mut data.client_info,
            &mut data.device_id,
            &mut data.client_time,
            &mut data.time_zone,
            &mut data.locale,
        ] {
            *value = "X".repeat(coffer_protocol::anisette::MAX_ANISETTE_VALUE_LEN);
        }
        Ok(data)
    }
}
#[test]
fn maximum_protocol_inputs_fit_adapter_budget() {
    let calls = Arc::new(AtomicUsize::new(0));
    let transport = DelegateTransport::new(
        SyntheticExchange(calls.clone()),
        Deadlines::starting_now(Duration::from_secs(5), Duration::from_secs(5)),
    );
    let account = "a".repeat(256);
    let adsid = "A".repeat(coffer_protocol::delegate::MAX_IDENTIFIER_LEN);
    let pet = "&".repeat(coffer_protocol::delegate::MAX_TOKEN_LEN);
    let client_id = "&".repeat(coffer_protocol::delegate::MAX_CLIENT_ID_LEN);
    let input = DelegateMaterialRef::new(
        &account,
        &adsid,
        Some(&pet),
        ClientIdRef::new(&client_id).unwrap(),
    )
    .unwrap();
    let result = futures_lite::future::block_on(
        DelegateClient::new(&transport, &MaximumAnisette).issue(input),
    );
    assert!(
        result.is_ok(),
        "maximum validated inputs must cross the adapter"
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}
