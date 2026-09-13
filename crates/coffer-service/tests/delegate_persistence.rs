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

//! Public API round trip with synthetic issuance and independent fake connections.
use coffer_protocol::anisette::{AnisetteData, AnisetteError, AnisetteProvider};
use coffer_protocol::delegate::{ClientIdRef, DelegateClient, DelegateMaterialRef};
use coffer_protocol::transport::{Request, Response, Transport, TransportError};
use coffer_service::{
    DelegateBindingRef, DelegateStore, FakeDelegateStore, SessionSlot, StoredDelegateCredentials,
};
use futures_lite::future::block_on;
use std::sync::atomic::{AtomicUsize, Ordering};

struct SyntheticTransport(AtomicUsize);
impl Transport for SyntheticTransport {
    async fn send(&self, _request: Request) -> Result<Response, TransportError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(Response::new(
            200,
            include_bytes!("fixtures/delegate/issued.plist").to_vec(),
        ))
    }
}
struct SyntheticAnisette(AtomicUsize);
impl AnisetteProvider for SyntheticAnisette {
    async fn anisette(&self) -> Result<AnisetteData, AnisetteError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(AnisetteData {
            one_time_password: "SYNTHETIC-OTP".into(),
            machine_id: "SYNTHETIC-MACHINE".into(),
            routing_info: "SYNTHETIC-ROUTING".into(),
            local_user_id: "SYNTHETIC-LOCAL".into(),
            serial_number: "0".into(),
            client_info: "SYNTHETIC-INFO".into(),
            device_id: "SYNTHETIC-DEVICE".into(),
            client_time: "2026-09-13T00:00:00Z".into(),
            time_zone: "UTC".into(),
            locale: "en_US".into(),
        })
    }
}
#[test]
fn issued_material_survives_source_drop_and_new_connection_without_reissuance() {
    let transport = SyntheticTransport(AtomicUsize::new(0));
    let anisette = SyntheticAnisette(AtomicUsize::new(0));
    let client = DelegateClient::new(&transport, &anisette);
    let input = DelegateMaterialRef::new(
        "synthetic@example.invalid",
        "synthetic-adsid",
        Some("SYNTHETIC-PET-NEVER-STORED"),
        ClientIdRef::new("synthetic-client").unwrap(),
    )
    .unwrap();
    let issued = block_on(client.issue(input)).unwrap();
    let expected = DelegateBindingRef::new("synthetic-adsid", "synthetic-client").unwrap();
    let stored = StoredDelegateCredentials::from_issued(&issued, expected).unwrap();
    drop(issued);
    let first = FakeDelegateStore::new();
    let slot = SessionSlot::from_random_bytes([0x53; 16]);
    block_on(first.replace_delegate(&slot, expected, &stored)).unwrap();
    drop(stored);
    let second = first.new_connection();
    drop(first);
    let loaded = block_on(second.load_delegate(&slot, expected))
        .unwrap()
        .unwrap();
    assert_eq!(loaded.expose_adsid(), "synthetic-adsid");
    assert_eq!(loaded.expose_client_id(), "synthetic-client");
    assert_eq!(loaded.expose_dsid(), "000-synthetic-dsid");
    assert_eq!(loaded.expose_mme_auth_token(), "SYNTHETIC-STORED-MME");
    assert_eq!(loaded.expose_cloudkit_token(), "SYNTHETIC-STORED-CLOUDKIT");
    assert_eq!(transport.0.load(Ordering::SeqCst), 1);
    assert_eq!(anisette.0.load(Ordering::SeqCst), 1);
}
