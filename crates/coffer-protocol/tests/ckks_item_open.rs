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

//! Public offline composition with independently generated OpenSSL fixtures.
use coffer_protocol::ckks::{
    UnwrappingKey,
    hierarchy::{
        AnchorInput, Database, Environment, HierarchyLimits, InputCompleteness, KeyClass, KeyGraph,
        KeyId, KeyRecord, KeyScope,
    },
    item::{self, Field, FieldCompleteness, FieldValue, ItemId},
    plaintext::parse_ckks_plaintext,
};
use zeroize::Zeroizing;

fn decode_fixture(hex: &str) -> Vec<u8> {
    let hex = hex.trim();
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect()
}

#[test]
fn explicit_graph_to_item_to_borrowed_website_candidate() {
    let scope = KeyScope {
        account: "synthetic-account",
        container: "synthetic-container",
        environment: Environment::Production,
        database: Database::Private,
        zone_owner: "synthetic-owner",
        zone_name: "synthetic-zone",
    };
    let root = KeyId {
        scope,
        name: "root",
    };
    let parent = KeyId {
        scope,
        name: "class-a",
    };
    let self_wrap = decode_fixture(include_str!("fixtures/ckks-wrap/self.hex"));
    let class_wrap = decode_fixture(include_str!("fixtures/ckks-wrap/child.hex"));
    let item_wrap = decode_fixture(include_str!("fixtures/ckks-wrap/grandchild.hex"));
    let envelope = include_bytes!("fixtures/ckks-item/v2-all.bin");
    let anchor = AnchorInput {
        id: root,
        key: UnwrappingKey::new(Zeroizing::new(core::array::from_fn(|i| i as u8))),
    };
    for class in [KeyClass::ClassA, KeyClass::ClassC] {
        let records = [
            KeyRecord {
                id: root,
                parent: Some(root),
                class: KeyClass::Tlk,
                wrapped: &self_wrap,
            },
            KeyRecord {
                id: parent,
                parent: Some(root),
                class,
                wrapped: &class_wrap,
            },
        ];
        let graph = KeyGraph::validate(
            scope,
            &records,
            InputCompleteness::Complete,
            root,
            HierarchyLimits::default(),
        )
        .unwrap();
        let selected = graph.unwrap_target(&anchor, parent).unwrap();
        let fields = [
            Field {
                name: "parentkeyref",
                value: FieldValue::Reference(parent),
            },
            Field {
                name: "wrappedkey",
                value: FieldValue::WrappedKey(&item_wrap),
            },
            Field {
                name: "data",
                value: FieldValue::Data(envelope),
            },
            Field {
                name: "gen",
                value: FieldValue::Integer(0x0102030405060708),
            },
            Field {
                name: "encver",
                value: FieldValue::Integer(2),
            },
            Field {
                name: "pcsservice",
                value: FieldValue::Integer(0x01020304),
            },
            Field {
                name: "pcspublickey",
                value: FieldValue::Data(&[0x10, 0x20]),
            },
            Field {
                name: "pcspublicidentity",
                value: FieldValue::Data(&[0, 255]),
            },
        ];
        let owner = item::open(
            ItemId {
                scope,
                name: "item-a",
            },
            "item",
            &fields,
            FieldCompleteness::Complete,
            &selected,
        )
        .unwrap();
        // Opening returns an independent zeroizing payload owner. Neither the
        // resolved key nor graph needs to survive the next explicit operation.
        drop(selected);
        drop(graph);
        let mut expected =
            Zeroizing::new(include_bytes!("fixtures/ckks-plaintext/inet.bplist").to_vec());
        expected.push(0x80);
        expected.resize(240, 0);
        assert!(owner.expose_secret() == expected.as_slice());
        let view = parse_ckks_plaintext(&owner).unwrap();
        let candidate = view.internet_password_candidate().unwrap();
        assert!(candidate.account().equals("fixture-reader-한😀"));
        assert!(candidate.server().equals("login.example.invalid"));
        assert!(candidate.password() == [0, 255, 128, 0, 65]);
        let start = owner.expose_secret().as_ptr() as usize;
        let borrowed = candidate.password().as_ptr() as usize;
        assert!(borrowed >= start);
        assert!(borrowed + candidate.password().len() <= start + owner.expose_secret().len());
    }
}
