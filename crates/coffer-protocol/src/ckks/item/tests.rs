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
use crate::ckks::hierarchy::{Database, Environment, KeyId, KeyScope};

const WRAPPED: &[u8] = &[0x53; 80];
const ENVELOPE: &[u8] = &[0x29; 48];
fn scope() -> KeyScope<'static> {
    KeyScope {
        account: "synthetic-account",
        container: "synthetic-container",
        environment: Environment::Production,
        database: Database::Private,
        zone_owner: "synthetic-owner",
        zone_name: "synthetic-zone",
    }
}
fn id() -> ItemId<'static> {
    ItemId {
        scope: scope(),
        name: "item-a",
    }
}
fn parent() -> KeyId<'static> {
    KeyId {
        scope: scope(),
        name: "class-a",
    }
}
fn fields() -> Vec<Field<'static>> {
    vec![
        Field {
            name: "parentkeyref",
            value: FieldValue::Reference(parent()),
        },
        Field {
            name: "wrappedkey",
            value: FieldValue::WrappedKey(WRAPPED),
        },
        Field {
            name: "data",
            value: FieldValue::Data(ENVELOPE),
        },
        Field {
            name: "gen",
            value: FieldValue::Integer(0x0102030405060708),
        },
        Field {
            name: "encver",
            value: FieldValue::Integer(2),
        },
    ]
}
fn build<'a>(fields: &[Field<'a>]) -> Result<ItemAssociatedData<'a>, ItemError> {
    build_associated_data(id(), "item", fields, FieldCompleteness::Complete)
}
fn reject(fields: &[Field<'_>], expected: ItemError) {
    assert_eq!(build(fields).unwrap_err(), expected);
    // Exercise the same malformed inventory through the composition boundary.
    with_class_key(parent(), KeyClass::ClassA, false, |key| {
        reject_open(key, fields, expected, (0, 0));
    });
}

#[test]
fn handwritten_components_are_byte_exact_in_fixed_key_order() {
    let mut input = fields();
    input.extend([
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
            value: FieldValue::Data(&[0x00, 0xff]),
        },
    ]);
    let expected: &[&[u8]] = &[
        b"item-a",
        &[2, 0, 0, 0, 0, 0, 0, 0],
        &[8, 7, 6, 5, 4, 3, 2, 1],
        &[0, 255],
        &[16, 32],
        &[4, 3, 2, 1, 0, 0, 0, 0],
        b"class-a",
    ];
    for _ in 0..input.len() {
        let ad = build(&input).unwrap();
        assert_eq!(ad.components().as_slice(), expected);
        input.rotate_left(1);
    }
    input.reverse();
    assert_eq!(build(&input).unwrap().components().as_slice(), expected);
}

#[test]
fn required_fields_completeness_and_record_type_are_explicit() {
    for index in 0..5 {
        let mut input = fields();
        input.remove(index);
        reject(&input, ItemError::MissingField);
    }
    reject(&[], ItemError::MissingField);
    assert_eq!(
        build_associated_data(id(), "item", &fields(), FieldCompleteness::Incomplete).unwrap_err(),
        ItemError::IncompleteInput
    );
    for kind in ["", "Item", "synckey", "item ", "item\0"] {
        assert_eq!(
            build_associated_data(id(), kind, &fields(), FieldCompleteness::Complete).unwrap_err(),
            ItemError::UnsupportedRecordType
        );
    }
}

#[test]
fn every_known_field_rejects_duplicates_and_wrong_types() {
    let mut full = fields();
    full.extend([
        Field {
            name: "uploadver",
            value: FieldValue::Text("synthetic-os"),
        },
        Field {
            name: "pcsservice",
            value: FieldValue::Integer(0),
        },
        Field {
            name: "pcspublickey",
            value: FieldValue::Data(b""),
        },
        Field {
            name: "pcspublicidentity",
            value: FieldValue::Data(b""),
        },
    ]);
    for duplicate in &full {
        // Keep within the independent inventory count cap.
        let mut input = fields();
        if !input.iter().any(|f| f.name == duplicate.name) {
            input.push(*duplicate);
        }
        input.push(*duplicate);
        reject(&input, ItemError::DuplicateField);
    }
    for index in 0..full.len() {
        for wrong in [
            FieldValue::Text("2"),
            FieldValue::Integer(2),
            FieldValue::Data(b""),
            FieldValue::WrappedKey(WRAPPED),
            FieldValue::Reference(parent()),
            FieldValue::Unsupported,
        ] {
            if core::mem::discriminant(&wrong) == core::mem::discriminant(&full[index].value) {
                continue;
            }
            let mut input = full.clone();
            input[index].value = wrong;
            reject(&input, ItemError::UnsupportedFieldType);
        }
    }
}

#[test]
fn all_unknown_names_fail_including_empty_values_and_reserved_names() {
    for name in [
        "",
        "UUID",
        "server_future",
        "osver",
        "unknown",
        "Gen",
        "gen ",
        "gén",
        "gen\0",
    ] {
        for value in [
            FieldValue::Data(b""),
            FieldValue::Text(""),
            FieldValue::Unsupported,
        ] {
            let mut input = fields();
            input.push(Field { name, value });
            reject(&input, ItemError::UnknownField);
        }
    }
}

#[test]
fn only_checked_nonnegative_integers_and_version_two_are_supported() {
    for index in [3, 4, 5] {
        for number in [-1, i128::MIN, i128::from(u64::MAX) + 1, i128::MAX] {
            let mut input = fields();
            input.push(Field {
                name: "pcsservice",
                value: FieldValue::Integer(0),
            });
            input[index].value = FieldValue::Integer(number);
            reject(&input, ItemError::IntegerOutOfRange);
        }
    }
    for version in [0, 1, 3, i128::from(u64::MAX)] {
        let mut input = fields();
        input[4].value = FieldValue::Integer(version);
        reject(&input, ItemError::UnsupportedVersion);
    }
    for number in [0, i128::from(u64::MAX)] {
        let mut input = fields();
        input[3].value = FieldValue::Integer(number);
        input.push(Field {
            name: "pcsservice",
            value: FieldValue::Integer(number),
        });
        let ad = build(&input).unwrap();
        let components = ad.components();
        assert_eq!(components.as_slice()[2], (number as u64).to_le_bytes());
        assert_eq!(components.as_slice()[3], (number as u64).to_le_bytes());
    }
}

#[test]
fn pcs_absence_and_present_empty_are_distinct_for_every_combination() {
    for service in [false, true] {
        for key in [None, Some(b"".as_slice()), Some(b"key".as_slice())] {
            for identity in [None, Some(b"".as_slice()), Some(b"identity".as_slice())] {
                let mut input = fields();
                if service {
                    input.push(Field {
                        name: "pcsservice",
                        value: FieldValue::Integer(0),
                    });
                }
                if let Some(value) = key {
                    input.push(Field {
                        name: "pcspublickey",
                        value: FieldValue::Data(value),
                    });
                }
                if let Some(value) = identity {
                    input.push(Field {
                        name: "pcspublicidentity",
                        value: FieldValue::Data(value),
                    });
                }
                let ad = build(&input).unwrap();
                let components = ad.components();
                let mut expected = vec![
                    b"item-a".as_slice(),
                    &[2, 0, 0, 0, 0, 0, 0, 0],
                    &[8, 7, 6, 5, 4, 3, 2, 1],
                ];
                expected.extend(identity);
                expected.extend(key);
                if service {
                    expected.push(&[0; 8]);
                }
                expected.push(b"class-a");
                assert_eq!(components.as_slice(), expected);
            }
        }
    }
}

#[test]
fn wrapped_ciphertext_is_validated_but_parent_name_supplies_ad() {
    let expected = build(&fields()).unwrap();
    let mut input = fields();
    input[1].value = FieldValue::WrappedKey(&[0xab; 80]);
    assert_eq!(
        build(&input).unwrap().components().as_slice(),
        expected.components().as_slice()
    );
    input[0].value = FieldValue::Reference(KeyId {
        name: "different",
        ..parent()
    });
    assert_eq!(
        build(&input).unwrap().components().as_slice().last(),
        Some(&b"different".as_slice())
    );
    for len in [0, 79, 81] {
        let bytes = vec![0; len];
        let mut input = fields();
        input[1].value = FieldValue::WrappedKey(&bytes);
        reject(&input, ItemError::InvalidWrappedKeyLength);
    }
}

#[test]
fn identifiers_are_exact_utf8_and_all_scope_components_must_match() {
    let mut input = fields();
    input[0].value = FieldValue::Reference(KeyId {
        name: "é\u{301}",
        ..parent()
    });
    let ad = build_associated_data(
        ItemId {
            name: "한😀",
            ..id()
        },
        "item",
        &input,
        FieldCompleteness::Complete,
    )
    .unwrap();
    assert_eq!(ad.components().as_slice()[0], "한😀".as_bytes());
    assert_eq!(ad.components().as_slice()[3], "é\u{301}".as_bytes());
    for changed in [
        KeyScope {
            account: "other",
            ..scope()
        },
        KeyScope {
            container: "other",
            ..scope()
        },
        KeyScope {
            environment: Environment::Development,
            ..scope()
        },
        KeyScope {
            database: Database::Shared,
            ..scope()
        },
        KeyScope {
            zone_owner: "other",
            ..scope()
        },
        KeyScope {
            zone_name: "other",
            ..scope()
        },
    ] {
        input[0].value = FieldValue::Reference(KeyId {
            scope: changed,
            ..parent()
        });
        reject(&input, ItemError::ScopeMismatch);
    }
}

#[test]
fn all_identifier_occurrences_have_exact_byte_limits() {
    for n in [0, 1023, 1024, 1025] {
        let value = "x".repeat(n);
        let expected = if n == 0 {
            Err(ItemError::InvalidIdentifier)
        } else if n > 1024 {
            Err(ItemError::LimitExceeded)
        } else {
            Ok(())
        };
        for index in 0..6 {
            let mut item = id();
            let mut key = parent();
            match index {
                0 => {
                    item.scope.account = &value;
                    key.scope.account = &value;
                }
                1 => {
                    item.scope.container = &value;
                    key.scope.container = &value;
                }
                2 => {
                    item.scope.zone_owner = &value;
                    key.scope.zone_owner = &value;
                }
                3 => {
                    item.scope.zone_name = &value;
                    key.scope.zone_name = &value;
                }
                4 => item.name = &value,
                _ => key.name = &value,
            }
            let mut input = fields();
            input[0].value = FieldValue::Reference(key);
            assert_eq!(
                build_associated_data(item, "item", &input, FieldCompleteness::Complete)
                    .map(|_| ()),
                expected
            );
        }
    }
}

#[test]
fn inventory_count_names_upload_and_pcs_limits_are_enforced() {
    let mut full = fields();
    full.extend([
        Field {
            name: "pcsservice",
            value: FieldValue::Integer(0),
        },
        Field {
            name: "pcspublickey",
            value: FieldValue::Data(b""),
        },
        Field {
            name: "pcspublicidentity",
            value: FieldValue::Data(b""),
        },
        Field {
            name: "uploadver",
            value: FieldValue::Text(""),
        },
    ]);
    assert!(build(&full[..8]).is_ok());
    assert!(build(&full).is_ok());
    full.push(full[0]);
    reject(&full, ItemError::LimitExceeded);
    for n in [63, 64, 65] {
        let name = "a".repeat(n);
        let mut input = fields();
        input.push(Field {
            name: &name,
            value: FieldValue::Unsupported,
        });
        reject(
            &input,
            if n > 64 {
                ItemError::LimitExceeded
            } else {
                ItemError::UnknownField
            },
        );
        assert_eq!(
            build_associated_data(id(), &name, &fields(), FieldCompleteness::Complete).unwrap_err(),
            if n > 64 {
                ItemError::LimitExceeded
            } else {
                ItemError::UnsupportedRecordType
            }
        );
    }
    for n in [0, 1023, 1024, 1025] {
        let value = "v".repeat(n);
        let mut input = fields();
        input.push(Field {
            name: "uploadver",
            value: FieldValue::Text(&value),
        });
        if n <= 1024 {
            assert_eq!(
                build(&input).unwrap().components().as_slice(),
                build(&fields()).unwrap().components().as_slice()
            );
        } else {
            reject(&input, ItemError::LimitExceeded);
        }
    }
    for name in ["pcspublickey", "pcspublicidentity"] {
        for n in [0, 65535, 65536, 65537] {
            let bytes = vec![0; n];
            let mut input = fields();
            input.push(Field {
                name,
                value: FieldValue::Data(&bytes),
            });
            assert_eq!(
                build(&input).map(|_| ()),
                if n <= 65536 {
                    Ok(())
                } else {
                    Err(ItemError::LimitExceeded)
                }
            );
        }
    }
}

#[test]
fn envelope_and_aggregate_caps_precede_output_and_never_modify_input() {
    // Independent accounting of the public input contract for these fixtures.
    let scope_size = "synthetic-account".len()
        + "synthetic-container".len()
        + "synthetic-owner".len()
        + "synthetic-zone".len()
        + 2;
    let overhead = scope_size * 2
        + "item-a".len()
        + "class-a".len()
        + "item".len()
        + ["parentkeyref", "wrappedkey", "data", "gen", "encver"]
            .iter()
            .map(|n| n.len() + 1)
            .sum::<usize>()
        + 80
        + 16 * 2;
    for n in [
        0,
        31,
        32,
        33,
        1024 * 1024 - overhead - 1,
        1024 * 1024 - overhead,
        1024 * 1024 - overhead + 1,
        1024 * 1024,
        1024 * 1024 + 1,
    ] {
        let bytes = vec![0x5a; n];
        let before = bytes.clone();
        let mut input = fields();
        input[2].value = FieldValue::Data(&bytes);
        let expected = if n + overhead > 1024 * 1024 {
            Err(ItemError::LimitExceeded)
        } else if n < 32 {
            Err(ItemError::InvalidEnvelopeLength)
        } else {
            Ok(())
        };
        assert_eq!(build(&input).map(|_| ()), expected);
        assert_eq!(bytes, before);
    }
    // Late input sizes are checked before early schema errors.
    let big = vec![0; 1024 * 1024];
    let mut input = fields();
    input[0].name = "unknown";
    input.push(Field {
        name: "pcspublickey",
        value: FieldValue::Data(&big),
    });
    reject(&input, ItemError::LimitExceeded);
}

#[test]
fn all_views_and_errors_are_secret_free_and_integer_storage_is_zeroizing() {
    let input = fields();
    let ad = build(&input).unwrap();
    let parts = ad.components();
    for output in [
        format!("{:?}", id()),
        format!("{:?}", input[0]),
        format!("{:?}", input[0].value),
        format!("{ad:?}"),
        format!("{ad:#?}"),
        format!("{parts:?}"),
    ] {
        assert_eq!(output, "<redacted>");
    }
    for value in [
        FieldValue::Text("private"),
        FieldValue::Data(b"private"),
        FieldValue::WrappedKey(b"private"),
        FieldValue::Integer(987654321),
        FieldValue::Unsupported,
    ] {
        assert_eq!(format!("{value:?}"), "<redacted>");
    }
    for error in [
        ItemError::IncompleteInput,
        ItemError::LimitExceeded,
        ItemError::InvalidIdentifier,
        ItemError::UnsupportedRecordType,
        ItemError::UnknownField,
        ItemError::DuplicateField,
        ItemError::MissingField,
        ItemError::UnsupportedFieldType,
        ItemError::IntegerOutOfRange,
        ItemError::UnsupportedVersion,
        ItemError::ScopeMismatch,
        ItemError::InvalidWrappedKeyLength,
        ItemError::InvalidEnvelopeLength,
    ] {
        assert!(!format!("{error:?}: {error}").contains("synthetic"));
        assert!(std::error::Error::source(&error).is_none());
    }
    fn zeroizing(_: &zeroize::Zeroizing<[[u8; 8]; 3]>) {}
    zeroizing(&ad.integers);
    assert!(core::mem::needs_drop::<ItemAssociatedData<'_>>());
}

const ALL: &[u8] = include_bytes!("../../../tests/fixtures/ckks-item/v2-all.bin");
const NONE: &[u8] = include_bytes!("../../../tests/fixtures/ckks-item/v2-none.bin");
const EMPTY: &[u8] = include_bytes!("../../../tests/fixtures/ckks-item/v2-empty.bin");
const NONCE_LAST: &[u8] = include_bytes!("../../../tests/fixtures/ckks-item/v2-nonce-last.bin");
const CONCATENATED: &[u8] = include_bytes!("../../../tests/fixtures/ckks-item/v2-concatenated.bin");
fn fixture_fields(all: bool) -> Vec<Field<'static>> {
    let mut input = fields();
    input[2].value = FieldValue::Data(if all { ALL } else { NONE });
    if all {
        input.extend([
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
        ]);
    }
    input
}
fn fixture_key() -> crate::ckks::UnwrappingKey {
    crate::ckks::UnwrappingKey::new(zeroize::Zeroizing::new(core::array::from_fn(|i| {
        128 + i as u8
    })))
}

#[test]
fn independent_openssl_envelopes_decrypt_through_the_existing_payload_api() {
    use crate::ckks::{payload, plaintext::parse_ckks_plaintext};
    let mut expected = zeroize::Zeroizing::new(
        include_bytes!("../../../tests/fixtures/ckks-plaintext/inet.bplist").to_vec(),
    );
    expected.push(0x80);
    expected.resize(240, 0);
    assert_eq!(NONE, EMPTY);
    for (envelope, all, empty) in [
        (ALL, true, false),
        (NONE, false, false),
        (EMPTY, false, true),
    ] {
        let mut input = fixture_fields(all);
        if empty {
            input.extend([
                Field {
                    name: "pcspublickey",
                    value: FieldValue::Data(b""),
                },
                Field {
                    name: "pcspublicidentity",
                    value: FieldValue::Data(b""),
                },
            ]);
        }
        let ad = build(&input).unwrap();
        let owner = payload::decrypt(&fixture_key(), envelope, ad.components().as_slice()).unwrap();
        assert_eq!(owner.expose_secret(), &*expected);
        let view = parse_ckks_plaintext(&owner).unwrap();
        let candidate = view.internet_password_candidate().unwrap();
        assert!(candidate.account().equals("fixture-reader-한😀"));
        assert!(candidate.server().equals("login.example.invalid"));
        assert_eq!(candidate.password(), &[0, 255, 128, 0, 65]);
    }
}

#[test]
fn independent_nonce_and_component_boundary_negatives_fail_without_fallback() {
    use crate::ckks::payload::{self, PayloadError};
    let input = fixture_fields(true);
    let ad = build(&input).unwrap();
    let components = ad.components();
    for envelope in [NONCE_LAST, CONCATENATED] {
        assert_eq!(
            payload::decrypt(&fixture_key(), envelope, components.as_slice()).unwrap_err(),
            PayloadError::AuthenticationFailed
        );
    }
    let mut reversed = components.as_slice().to_vec();
    reversed.reverse();
    assert!(payload::decrypt(&fixture_key(), ALL, &reversed).is_err());
    let joined = components.as_slice().concat();
    assert!(payload::decrypt(&fixture_key(), ALL, &[&joined]).is_err());
    let mut split = components.as_slice().to_vec();
    split[0] = b"item";
    split.insert(1, b"-a");
    assert!(payload::decrypt(&fixture_key(), ALL, &split).is_err());
    for end in 0..ALL.len() {
        let mut truncated = fixture_fields(true);
        truncated[2].value = FieldValue::Data(&ALL[..end]);
        if end < 32 {
            reject(&truncated, ItemError::InvalidEnvelopeLength);
        } else {
            let ad = build(&truncated).unwrap();
            assert!(
                payload::decrypt(&fixture_key(), &ALL[..end], ad.components().as_slice()).is_err()
            );
        }
    }
}

#[test]
fn supported_metadata_changes_and_every_envelope_byte_fail_authentication() {
    use crate::ckks::payload;
    let key = fixture_key();
    for index in [0, 3, 5, 6, 7] {
        let mut input = fixture_fields(true);
        input[index].value = match index {
            0 => FieldValue::Reference(KeyId {
                name: "other-class",
                ..parent()
            }),
            3 | 5 => FieldValue::Integer(1),
            _ => FieldValue::Data(b"changed"),
        };
        let ad = build(&input).unwrap();
        assert!(payload::decrypt(&key, ALL, ad.components().as_slice()).is_err());
    }
    let ad = build_associated_data(
        ItemId {
            name: "other-item",
            ..id()
        },
        "item",
        &fixture_fields(true),
        FieldCompleteness::Complete,
    )
    .unwrap();
    assert!(payload::decrypt(&key, ALL, ad.components().as_slice()).is_err());
    let ad = build(&fixture_fields(true)).unwrap();
    for offset in 0..ALL.len() {
        let mut altered = ALL.to_vec();
        altered[offset] ^= 1;
        assert!(payload::decrypt(&key, &altered, ad.components().as_slice()).is_err());
    }
}

#[test]
fn omitted_unknowns_never_reach_the_payload_call() {
    let mut input = fixture_fields(true);
    input.push(Field {
        name: "unknown",
        value: FieldValue::Data(b"nonempty"),
    });
    let mut decrypt_called = false;
    let result = build(&input).map(|ad| {
        decrypt_called = true;
        crate::ckks::payload::decrypt(&fixture_key(), ALL, ad.components().as_slice())
    });
    assert_eq!(result.unwrap_err(), ItemError::UnknownField);
    assert!(!decrypt_called);
    input.pop();
    // If an upstream adapter discards that field, this layer cannot discover it.
    let ad = build(&input).unwrap();
    assert!(crate::ckks::payload::decrypt(&fixture_key(), ALL, ad.components().as_slice()).is_ok());
}

#[test]
fn ignored_uploadver_and_scope_are_not_cryptographically_authenticated() {
    let mut input = fixture_fields(true);
    input.push(Field {
        name: "uploadver",
        value: FieldValue::Text("invented-os"),
    });
    let foreign = KeyScope {
        account: "different-account",
        ..scope()
    };
    input[0].value = FieldValue::Reference(KeyId {
        scope: foreign,
        ..parent()
    });
    let ad = build_associated_data(
        ItemId {
            scope: foreign,
            ..id()
        },
        "item",
        &input,
        FieldCompleteness::Complete,
    )
    .unwrap();
    // Consistent rebinding is structurally valid and produces the same AD.
    // Success must not be advertised as authenticating the account or uploadver.
    assert!(crate::ckks::payload::decrypt(&fixture_key(), ALL, ad.components().as_slice()).is_ok());
}

#[test]
fn independent_fixture_hashes_are_fixed() {
    use sha2::{Digest, Sha256};
    for (bytes, hash) in [
        (
            ALL,
            "f93065b3286fdb810aa2872c08d2077e00290202b8b0513895647b78c0a339e5",
        ),
        (
            NONE,
            "ace20ee9dc1642bf8d47ee1f267e70c7e89d43c8d5f4faca3a8c4c337d5da065",
        ),
        (
            EMPTY,
            "ace20ee9dc1642bf8d47ee1f267e70c7e89d43c8d5f4faca3a8c4c337d5da065",
        ),
        (
            NONCE_LAST,
            "66a4f39ee908a78978e2d82ca915339fd00c5f0420b9c8f0e9c6525763668717",
        ),
        (
            CONCATENATED,
            "d3e99880f87ec845f89c591353cb085d986f9ac600ea1c59866d3865f4101342",
        ),
    ] {
        assert_eq!(bytes.len(), 272);
        let hex = Sha256::digest(bytes)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        assert_eq!(hex, hash);
    }
}

// Item opening reuses independent OpenSSL wrap and payload fixtures. All graph
// metadata is invented; successful authentication does not make it trusted.
fn wrap_fixture(hex: &str) -> Vec<u8> {
    let hex = hex.trim();
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect()
}
fn item_wrap() -> Vec<u8> {
    wrap_fixture(include_str!(
        "../../../tests/fixtures/ckks-wrap/grandchild.hex"
    ))
}
fn with_class_key(
    selected: KeyId<'_>,
    class: crate::ckks::hierarchy::KeyClass,
    wrong_bytes: bool,
    test: impl FnOnce(&ResolvedKey<'_>),
) {
    use crate::ckks::{UnwrappingKey, hierarchy::*};
    let self_wrap = wrap_fixture(include_str!("../../../tests/fixtures/ckks-wrap/self.hex"));
    let child = wrap_fixture(include_str!("../../../tests/fixtures/ckks-wrap/child.hex"));
    let root = KeyId {
        name: "root",
        ..selected
    };
    let records = [
        KeyRecord {
            id: root,
            parent: Some(root),
            class: KeyClass::Tlk,
            wrapped: &self_wrap,
        },
        KeyRecord {
            id: selected,
            parent: Some(root),
            class,
            wrapped: if wrong_bytes { &self_wrap } else { &child },
        },
    ];
    let anchor = AnchorInput {
        id: root,
        key: UnwrappingKey::new(Zeroizing::new(core::array::from_fn(|i| i as u8))),
    };
    let graph = KeyGraph::validate(
        selected.scope,
        &records,
        InputCompleteness::Complete,
        root,
        HierarchyLimits::default(),
    )
    .unwrap();
    let key = graph.unwrap_target(&anchor, selected).unwrap();
    OPEN_CALLS.with(|n| n.set((0, 0)));
    test(&key);
}
fn open_calls() -> (usize, usize) {
    OPEN_CALLS.with(|n| n.replace((0, 0)))
}
fn open_fixture(key: &ResolvedKey<'_>, input: &[Field<'_>]) -> Result<PayloadPlaintext, ItemError> {
    open(id(), "item", input, FieldCompleteness::Complete, key)
}
fn reject_open(
    key: &ResolvedKey<'_>,
    input: &[Field<'_>],
    error: ItemError,
    calls: (usize, usize),
) {
    // Failure carries no plaintext or key, and the explicit parser cannot run.
    let mut parser_calls = 0;
    let result = open_fixture(key, input).map(|owner| {
        parser_calls += 1;
        let _ = crate::ckks::plaintext::parse_ckks_plaintext(&owner);
    });
    assert_eq!(result.unwrap_err(), error);
    assert_eq!(open_calls(), calls);
    assert_eq!(parser_calls, 0);
}

#[test]
fn open_independent_class_a_and_c_vectors_once_then_explicit_parse() {
    use crate::ckks::hierarchy::KeyClass;
    let wrapped = item_wrap();
    for class in [KeyClass::ClassA, KeyClass::ClassC] {
        with_class_key(parent(), class, false, |key| {
            for all in [false, true] {
                let mut input = fixture_fields(all);
                input[1].value = FieldValue::WrappedKey(&wrapped);
                let owner = open_fixture(key, &input).unwrap();
                assert_eq!(open_calls(), (1, 1));
                let plain = include_bytes!("../../../tests/fixtures/ckks-plaintext/inet.bplist");
                assert!(owner.expose_secret()[..plain.len()] == plain[..]);
                assert!(owner.expose_secret()[plain.len()..] == [0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
                let view = crate::ckks::plaintext::parse_ckks_plaintext(&owner).unwrap();
                let candidate = view.internet_password_candidate().unwrap();
                assert!(candidate.account().equals("fixture-reader-한😀"));
                assert!(candidate.server().equals("login.example.invalid"));
                assert!(candidate.password() == [0, 255, 128, 0, 65]);
                assert_eq!(format!("{owner:?}"), "PayloadPlaintext(<redacted>)");
                assert_eq!(format!("{key:?}"), "ResolvedKey(<redacted>)");
            }
        });
    }
}

#[test]
fn open_checks_every_selected_scope_component_and_parent_name_before_crypto() {
    use crate::ckks::hierarchy::KeyClass;
    let wrapped = item_wrap();
    let mut input = fixture_fields(true);
    input[1].value = FieldValue::WrappedKey(&wrapped);
    for changed in [
        KeyScope {
            account: "other",
            ..scope()
        },
        KeyScope {
            container: "other",
            ..scope()
        },
        KeyScope {
            environment: Environment::Development,
            ..scope()
        },
        KeyScope {
            database: Database::Shared,
            ..scope()
        },
        KeyScope {
            database: Database::Public,
            ..scope()
        },
        KeyScope {
            zone_owner: "other",
            ..scope()
        },
        KeyScope {
            zone_name: "other",
            ..scope()
        },
    ] {
        with_class_key(
            KeyId {
                scope: changed,
                ..parent()
            },
            KeyClass::ClassA,
            false,
            |key| {
                reject_open(key, &input, ItemError::ParentKeyMismatch, (0, 0));
            },
        );
    }
    for name in ["Class-a", "class-a ", "other"] {
        with_class_key(KeyId { name, ..parent() }, KeyClass::ClassA, false, |key| {
            reject_open(key, &input, ItemError::ParentKeyMismatch, (0, 0));
        });
    }
    // This TLK contains the correct B bytes; class policy must still reject it.
    with_class_key(parent(), KeyClass::Tlk, false, |key| {
        reject_open(key, &input, ItemError::UnsupportedKeyClass, (0, 0));
    });
    with_class_key(parent(), KeyClass::ClassA, true, |key| {
        reject_open(key, &input, ItemError::KeyAuthenticationFailed, (1, 0));
    });
}

#[test]
fn open_rejects_every_wrap_corruption_and_truncation_without_payload_attempt() {
    use crate::ckks::hierarchy::KeyClass;
    let wrapped = item_wrap();
    with_class_key(parent(), KeyClass::ClassC, false, |key| {
        for i in 0..wrapped.len() {
            let mut altered = wrapped.clone();
            altered[i] ^= 1;
            let before = altered.clone();
            let mut input = fixture_fields(true);
            input[1].value = FieldValue::WrappedKey(&altered);
            reject_open(key, &input, ItemError::KeyAuthenticationFailed, (1, 0));
            assert_eq!(altered, before);
        }
        for end in 0..wrapped.len() {
            let mut input = fixture_fields(true);
            input[1].value = FieldValue::WrappedKey(&wrapped[..end]);
            reject_open(key, &input, ItemError::InvalidWrappedKeyLength, (0, 0));
        }
    });
}

#[test]
fn open_payload_corruptions_truncations_and_negative_fixtures_stop_after_one_attempt() {
    use crate::ckks::hierarchy::KeyClass;
    let wrapped = item_wrap();
    with_class_key(parent(), KeyClass::ClassA, false, |key| {
        for i in 0..ALL.len() {
            let mut altered = ALL.to_vec();
            altered[i] ^= 1;
            let before = altered.clone();
            let mut input = fixture_fields(true);
            input[1].value = FieldValue::WrappedKey(&wrapped);
            input[2].value = FieldValue::Data(&altered);
            reject_open(key, &input, ItemError::PayloadAuthenticationFailed, (1, 1));
            assert_eq!(altered, before);
        }
        for end in 0..ALL.len() {
            let mut input = fixture_fields(true);
            input[1].value = FieldValue::WrappedKey(&wrapped);
            input[2].value = FieldValue::Data(&ALL[..end]);
            let (error, calls) = if end < 32 {
                (ItemError::InvalidEnvelopeLength, (0, 0))
            } else {
                (ItemError::PayloadAuthenticationFailed, (1, 1))
            };
            reject_open(key, &input, error, calls);
        }
        for envelope in [NONCE_LAST, CONCATENATED] {
            let mut input = fixture_fields(true);
            input[1].value = FieldValue::WrappedKey(&wrapped);
            input[2].value = FieldValue::Data(envelope);
            reject_open(key, &input, ItemError::PayloadAuthenticationFailed, (1, 1));
        }
    });
}

#[test]
fn open_authenticates_metadata_but_does_not_authenticate_omitted_claims() {
    use crate::ckks::hierarchy::KeyClass;
    let wrapped = item_wrap();
    with_class_key(parent(), KeyClass::ClassA, false, |key| {
        for index in [3, 5, 6, 7] {
            let mut input = fixture_fields(true);
            input[1].value = FieldValue::WrappedKey(&wrapped);
            input[index].value = match index {
                3 | 5 => FieldValue::Integer(1),
                _ => FieldValue::Data(b"changed"),
            };
            reject_open(key, &input, ItemError::PayloadAuthenticationFailed, (1, 1));
        }
        let mut input = fixture_fields(true);
        input[1].value = FieldValue::WrappedKey(&wrapped);
        assert_eq!(
            open(
                ItemId {
                    name: "changed",
                    ..id()
                },
                "item",
                &input,
                FieldCompleteness::Complete,
                key
            )
            .unwrap_err(),
            ItemError::PayloadAuthenticationFailed
        );
        assert_eq!(open_calls(), (1, 1));
        input.push(Field {
            name: "uploadver",
            value: FieldValue::Text("changed"),
        });
        assert!(open_fixture(key, &input).is_ok());
        assert_eq!(open_calls(), (1, 1));
    });
    // Consistently rebinding unauthenticated metadata still succeeds. This must
    // never be interpreted as authenticated account ownership or trusted class.
    let changed = KeyScope {
        account: "rebound",
        ..scope()
    };
    let selected = KeyId {
        scope: changed,
        ..parent()
    };
    with_class_key(selected, KeyClass::ClassC, false, |key| {
        let mut input = fixture_fields(true);
        input[0].value = FieldValue::Reference(selected);
        input[1].value = FieldValue::WrappedKey(&wrapped);
        assert!(
            open(
                ItemId {
                    scope: changed,
                    ..id()
                },
                "item",
                &input,
                FieldCompleteness::Complete,
                key
            )
            .is_ok()
        );
        assert_eq!(open_calls(), (1, 1));
    });
}

#[test]
fn open_complete_preflight_precedes_even_invalid_wrap_authentication() {
    use crate::ckks::hierarchy::KeyClass;
    with_class_key(parent(), KeyClass::ClassA, false, |key| {
        let input = fields(); // Valid shape, deliberately unauthentic ciphertext.
        assert_eq!(
            open(id(), "item", &input, FieldCompleteness::Incomplete, key).unwrap_err(),
            ItemError::IncompleteInput
        );
        assert_eq!(open_calls(), (0, 0));
        assert_eq!(
            open(id(), "wrong", &input, FieldCompleteness::Complete, key).unwrap_err(),
            ItemError::UnsupportedRecordType
        );
        assert_eq!(open_calls(), (0, 0));
        for value in [0, 1, 3] {
            let mut input = fields();
            input[4].value = FieldValue::Integer(value);
            reject_open(key, &input, ItemError::UnsupportedVersion, (0, 0));
        }
        let huge = vec![0; 1024 * 1024];
        let pcs = vec![0; 65537];
        for (name, value, error) in [
            (
                "pcspublickey",
                FieldValue::Data(&pcs),
                ItemError::LimitExceeded,
            ),
            (
                "pcspublicidentity",
                FieldValue::Data(&huge),
                ItemError::LimitExceeded,
            ),
            (
                "uploadver",
                FieldValue::Unsupported,
                ItemError::UnsupportedFieldType,
            ),
            (
                "server_future",
                FieldValue::Data(b""),
                ItemError::UnknownField,
            ),
            ("gen", FieldValue::Integer(0), ItemError::DuplicateField),
        ] {
            let mut input = fields();
            input.push(Field { name, value });
            reject_open(key, &input, error, (0, 0));
        }
    });
}

#[test]
fn open_errors_have_only_fixed_messages_and_no_sources() {
    for (error, debug, display) in [
        (
            ItemError::ParentKeyMismatch,
            "ParentKeyMismatch",
            "CKKS item parent key mismatch",
        ),
        (
            ItemError::UnsupportedKeyClass,
            "UnsupportedKeyClass",
            "unsupported CKKS item parent key class",
        ),
        (
            ItemError::KeyAuthenticationFailed,
            "KeyAuthenticationFailed",
            "CKKS item key authentication failed",
        ),
        (
            ItemError::PayloadAuthenticationFailed,
            "PayloadAuthenticationFailed",
            "CKKS item payload authentication failed",
        ),
    ] {
        assert_eq!(format!("{error:?}"), debug);
        assert_eq!(format!("{error}"), display);
        assert!(std::error::Error::source(&error).is_none());
    }
}

#[test]
fn open_validated_record_retains_exact_borrows_and_parent_ad_is_authenticated() {
    let wrapped = item_wrap();
    let mut input = fixture_fields(true);
    input[1].value = FieldValue::WrappedKey(&wrapped);
    let validated = validate_record(id(), "item", &input, FieldCompleteness::Complete).unwrap();
    assert_eq!(validated.parent, parent());
    assert!(core::ptr::eq(validated.wrapped.as_ptr(), wrapped.as_ptr()));
    assert!(core::ptr::eq(validated.envelope.as_ptr(), ALL.as_ptr()));
    assert_eq!(format!("{validated:?}"), "<redacted>");
    let renamed = KeyId {
        name: "renamed-class",
        ..parent()
    };
    input[0].value = FieldValue::Reference(renamed);
    with_class_key(renamed, KeyClass::ClassA, false, |key| {
        reject_open(key, &input, ItemError::PayloadAuthenticationFailed, (1, 1));
    });
}
