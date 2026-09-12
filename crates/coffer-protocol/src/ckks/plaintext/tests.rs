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
const SMALL: &[u8] = include_bytes!("../../../tests/fixtures/ckks-plaintext/small.bplist");
const INET: &[u8] = include_bytes!("../../../tests/fixtures/ckks-plaintext/inet.bplist");
fn padded(bytes: &[u8]) -> Vec<u8> {
    let mut bytes = bytes.to_vec();
    bytes.extend_from_slice(&[0x80, 0, 0]);
    bytes
}
#[test]
fn independent_positive_fixtures() {
    for bytes in [SMALL, INET] {
        assert!(parse_bytes(&padded(bytes)).is_ok());
    }
}
#[test]
fn invalid_padding_fails_closed() {
    for bytes in [&[][..], &[0], &[0x81], SMALL] {
        assert!(parse_bytes(bytes).is_err());
    }
}

use crate::ckks::{UnwrappingKey, payload};
use aes_siv::{KeyInit, siv::Aes256Siv};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

// Independent hand assembly from marker/count/reference facts. This test-only
// builder permits intentionally malformed bytes; it is not a production writer.
fn number(value: u64, width: usize) -> Vec<u8> {
    value.to_be_bytes()[8 - width..].to_vec()
}
fn token(kind: u8, count: usize, extended: Option<usize>) -> Vec<u8> {
    if count < 15 && extended.is_none() {
        return vec![kind | count as u8];
    }
    let width = extended.unwrap_or(if count < 256 {
        1
    } else if count < 65536 {
        2
    } else {
        4
    });
    let mut bytes = vec![kind | 15, 0x10 | width.trailing_zeros() as u8];
    bytes.extend(number(count as u64, width));
    bytes
}
fn body(kind: u8, bytes: &[u8]) -> Vec<u8> {
    let mut result = token(
        kind,
        if kind == 0x60 {
            bytes.len() / 2
        } else {
            bytes.len()
        },
        None,
    );
    result.extend(bytes);
    result
}
fn ascii(text: &str) -> Vec<u8> {
    body(0x50, text.as_bytes())
}
fn utf16(text: &str) -> Vec<u8> {
    body(
        0x60,
        &text
            .encode_utf16()
            .flat_map(u16::to_be_bytes)
            .collect::<Vec<_>>(),
    )
}
fn dictionary(keys: &[usize], values: &[usize], width: usize) -> Vec<u8> {
    assert_eq!(keys.len(), values.len());
    let mut result = token(0xd0, keys.len(), None);
    for id in keys.iter().chain(values) {
        result.extend(number(*id as u64, width));
    }
    result
}
fn assemble(objects: &[Vec<u8>], root: usize, ow: usize, rw: usize) -> Vec<u8> {
    let mut result = b"bplist00".to_vec();
    let mut offsets = Vec::new();
    for object in objects {
        offsets.push(result.len());
        result.extend(object);
    }
    let table = result.len();
    for offset in offsets {
        result.extend(number(offset as u64, ow));
    }
    result.extend([0, 0, 0, 0, 0, 0, ow as u8, rw as u8]);
    result.extend(number(objects.len() as u64, 8));
    result.extend(number(root as u64, 8));
    result.extend(number(table as u64, 8));
    result
}
fn single(key: Vec<u8>, value: Vec<u8>) -> Vec<u8> {
    assemble(&[dictionary(&[1], &[2], 2), key, value], 0, 4, 2)
}
fn fields(fields: Vec<(&str, Vec<u8>)>) -> Vec<u8> {
    let n = fields.len();
    let mut objects = vec![dictionary(
        &(1..=n).collect::<Vec<_>>(),
        &(n + 1..=2 * n).collect::<Vec<_>>(),
        2,
    )];
    objects.extend(fields.iter().map(|(key, _)| ascii(key)));
    objects.extend(fields.into_iter().map(|(_, value)| value));
    assemble(&objects, 0, 4, 2)
}
fn inet_fields() -> Vec<(&'static str, Vec<u8>)> {
    vec![
        ("class", ascii("inet")),
        ("acct", ascii("")),
        ("srvr", utf16("host.invalid")),
        ("ptcl", ascii("http")),
        ("v_Data", body(0x40, b"")),
        ("tomb", vec![0x10, 0]),
    ]
}
fn rejects(bytes: &[u8], error: PlaintextError) {
    assert_eq!(parse_bytes(&padded(bytes)).unwrap_err(), error);
}
fn trailer_number(bytes: &mut [u8], offset: usize, value: u64) {
    let start = bytes.len() - 32 + offset;
    bytes[start..start + 8].copy_from_slice(&value.to_be_bytes());
}

#[test]
fn independent_hashes_hand_layout_and_semantics() {
    assert_eq!(SMALL.len(), 51);
    assert_eq!(
        &SMALL[..19],
        b"bplist00\xd1\x01\x02\x51k\x42\x00\xff\x08\x0b\x0d"
    );
    assert_eq!(
        &SMALL[19..],
        &[
            0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 16
        ]
    );
    assert_eq!(
        Sha256::digest(SMALL)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>(),
        "9da3d3006e097a8f9ccc4ca9fa10b89a5aed734c3428fa8fe1cf599636a18ebd"
    );
    assert_eq!(
        Sha256::digest(INET)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>(),
        "fd475d545b0c946a5002a938b43e63f92b95f7823560f189c44a6acc724372b1"
    );
    let input = Zeroizing::new(padded(INET));
    let view = parse_bytes(&input).unwrap();
    let candidate = view.internet_password_candidate().unwrap();
    assert!(candidate.account().equals("fixture-reader-한😀"));
    assert!(candidate.server().equals("login.example.invalid"));
    assert_eq!(*candidate.protocol(), WebsiteProtocol::Https);
    assert_eq!(candidate.password(), &[0, 255, 128, 0, 65]);
    assert_eq!(candidate.tombstone_state(), TombstoneState::NotTombstone);
    assert_eq!(
        view.get("binn").unwrap().as_data(),
        Some(&b"bplist00\x00\xff"[..])
    );
    assert!(
        view.get("unknown")
            .unwrap()
            .as_text()
            .unwrap()
            .equals("opaque-sentinel")
    );
    assert_eq!(view.entries().len(), 8);
    let raw = view.get("v_Data").unwrap().raw_body();
    assert!(raw.as_ptr() >= input.as_ptr());
    assert!(raw.as_ptr_range().end <= input.as_ptr_range().end);
}

#[test]
fn padding_is_explicit_without_writer_block_assumptions() {
    assert_eq!(
        parse_bytes(&[0x80]).unwrap_err(),
        PlaintextError::UnsupportedFormat
    );
    for suffix in [
        vec![0x80],
        vec![0x80, 0],
        vec![0x80; 2],
        vec![0x80, 0, 0, 0x81],
    ] {
        let mut input = SMALL.to_vec();
        input.extend(&suffix);
        if suffix == [0x80; 2] {
            assert!(parse_bytes(&input).is_err());
        } else if suffix.last() == Some(&0x81) {
            assert_eq!(
                parse_bytes(&input).unwrap_err(),
                PlaintextError::InvalidPadding
            );
        } else {
            assert!(parse_bytes(&input).is_ok());
        }
    }
    for length in [0, 19, 20, 21, 39, 40, 41] {
        let bytes = single(ascii("k"), body(0x40, &vec![0x80; length]));
        for padding in [0, 1, 19, 20, 21, 40] {
            let mut input = bytes.clone();
            input.push(0x80);
            input.resize(input.len() + padding, 0);
            let view = parse_bytes(&input).unwrap();
            assert_eq!(view.get("k").unwrap().raw_body(), vec![0x80; length]);
        }
    }
}

#[test]
fn all_truncations_and_alternate_formats_fail() {
    for bytes in [SMALL, INET] {
        for end in 0..bytes.len() {
            assert!(parse_bytes(&padded(&bytes[..end])).is_err());
        }
        let input = padded(bytes);
        // Prefixes retaining the padding marker are intentionally accepted.
        for end in 0..=bytes.len() {
            assert!(parse_bytes(&input[..end]).is_err());
        }
    }
    for bytes in [
        &b"<?xml version='1.0'?>"[..],
        b"\x31\x00",
        b"\x1f\x8b\x08",
        b"bplist01",
        b"bplist10",
        b"random",
    ] {
        rejects(bytes, PlaintextError::UnsupportedFormat);
    }
}

#[test]
fn count_boundaries_and_nonminimal_unsigned_widths() {
    for length in [0, 1, 14, 15, 16, 127, 128, 255, 256] {
        for width in [1, 2, 4, 8] {
            if width == 1 && length > 255 {
                continue;
            }
            for kind in [0x40, 0x50, 0x60] {
                let mut value = token(kind, length, Some(width));
                value.extend(vec![0; length * if kind == 0x60 { 2 } else { 1 }]);
                let input = padded(&single(ascii("k"), value));
                assert!(
                    parse_bytes(&input).is_ok(),
                    "length {length}, width {width}, kind {kind}"
                );
            }
        }
        let mut objects = vec![dictionary(
            &(1..=length).collect::<Vec<_>>(),
            &vec![length + 1; length],
            2,
        )];
        objects.extend((0..length).map(|i| ascii(&format!("k{i}"))));
        if length != 0 {
            objects.push(body(0x40, b""));
        }
        // The zero-pair root references no extra object.
        let input = padded(&assemble(&objects, 0, 4, 2));
        assert_eq!(parse_bytes(&input).unwrap().entries().count(), length);
    }
    for width in [1, 2, 4, 8] {
        let mut root = token(0xd0, 1, Some(width));
        root.extend([1, 2]);
        assert!(
            parse_bytes(&padded(&assemble(
                &[root, ascii("k"), body(0x40, b"")],
                0,
                1,
                1
            )))
            .is_ok()
        );
    }
}

#[test]
fn every_extended_marker_is_checked_in_full() {
    for marker in 0u8..=255 {
        if (0x10..=0x13).contains(&marker) {
            continue;
        }
        for kind in [0x4f, 0x5f, 0x6f] {
            rejects(
                &single(ascii("k"), vec![kind, marker, 0, 0, 0, 0, 0, 0, 0, 0]),
                PlaintextError::UnsupportedRepresentation,
            );
        }
        rejects(
            &assemble(&[vec![0xdf, marker, 0, 0, 0, 0, 0, 0, 0, 0]], 0, 1, 1),
            PlaintextError::UnsupportedRepresentation,
        );
    }
    for kind in [0x4f, 0x5f, 0x6f] {
        let mut value = vec![kind, 0x13];
        value.extend([0xff; 8]);
        rejects(&single(ascii("k"), value), PlaintextError::LimitExceeded);
    }
    for offset in [8, 16, 24] {
        let mut bytes = SMALL.to_vec();
        trailer_number(&mut bytes, offset, u64::MAX);
        assert!(parse_bytes(&padded(&bytes)).is_err());
    }
}

#[test]
fn offset_reference_widths_and_permuted_nonzero_root() {
    for ow in [1, 2, 4, 8] {
        for rw in [1, 2, 4, 8] {
            let objects = vec![body(0x40, b"value"), ascii("k"), dictionary(&[1], &[0], rw)];
            let mut bytes = assemble(&objects, 2, ow, rw);
            let input = padded(&bytes);
            assert_eq!(
                parse_bytes(&input).unwrap().get("k").unwrap().raw_body(),
                b"value"
            );
            // Reorder logical IDs via the offset table, without moving objects.
            let table = bytes.len() - 32 - 3 * ow;
            for i in 0..ow {
                bytes.swap(table + i, table + ow + i);
            }
            let root_offset = 8 + objects[0].len() + objects[1].len();
            bytes[root_offset + 1..root_offset + 1 + rw].copy_from_slice(&number(0, rw));
            bytes[root_offset + 1 + rw..root_offset + 1 + 2 * rw].copy_from_slice(&number(1, rw));
            assert_eq!(
                parse_bytes(&padded(&bytes))
                    .unwrap()
                    .get("k")
                    .unwrap()
                    .raw_body(),
                b"value"
            );
        }
    }
    for bad in [0, 3, 5, 6, 7, 9, 16, 255] {
        for field in [6, 7] {
            let mut bytes = SMALL.to_vec();
            let at = bytes.len() - 32 + field;
            bytes[at] = bad;
            rejects(&bytes, PlaintextError::UnsupportedRepresentation);
        }
    }
}

#[test]
fn geometry_rejects_gaps_overlaps_region_intrusions_and_bad_refs() {
    for (index, value) in [
        (16, 0),
        (16, 7),
        (16, 16),
        (16, 19),
        (16, 51),
        (17, 8),
        (17, 9),
        (17, 12),
        (18, 12),
    ] {
        let mut bytes = SMALL.to_vec();
        bytes[index] = value;
        assert!(parse_bytes(&padded(&bytes)).is_err());
    }
    for index in [9, 10] {
        for value in [3, 255] {
            let mut bytes = SMALL.to_vec();
            bytes[index] = value;
            rejects(&bytes, PlaintextError::MalformedLayout);
        }
        let mut bytes = SMALL.to_vec();
        bytes[index] = 0;
        rejects(&bytes, PlaintextError::UnsupportedRepresentation);
    }
    let mut bytes = SMALL.to_vec();
    bytes[13] = 0x43; // Data would absorb the offset table.
    rejects(&bytes, PlaintextError::MalformedLayout);
    let mut bytes = SMALL.to_vec();
    bytes[8] = 0xd2; // Root would overlap key/Data.
    rejects(&bytes, PlaintextError::MalformedLayout);
    let mut bytes = SMALL.to_vec();
    bytes.insert(16, 0);
    trailer_number(&mut bytes, 24, 17);
    rejects(&bytes, PlaintextError::MalformedLayout); // Unclaimed object-region gap.
    let mut bytes = SMALL.to_vec();
    bytes.insert(19, 0);
    rejects(&bytes, PlaintextError::MalformedLayout); // Offset table no longer ends at trailer.
    let mut bytes = SMALL.to_vec();
    bytes.push(0);
    assert!(parse_bytes(&padded(&bytes)).is_err());
    for offset in 0..6 {
        let mut bytes = SMALL.to_vec();
        let at = bytes.len() - 32 + offset;
        bytes[at] = 1;
        rejects(&bytes, PlaintextError::UnsupportedRepresentation);
    }
    for (offset, value) in [(8, 0), (16, 3), (24, 7), (24, 19)] {
        let mut bytes = SMALL.to_vec();
        trailer_number(&mut bytes, offset, value);
        rejects(&bytes, PlaintextError::MalformedLayout);
    }
}

#[test]
fn unsupported_objects_and_late_failure_have_no_partial_view() {
    for value in [
        vec![0x00],
        vec![0x0f],
        vec![0x80, 0],
        vec![0xa0],
        vec![0xd0],
        vec![0xf0],
        vec![0x15; 33],
        vec![0x21; 3],
        vec![0x24; 17],
        vec![0x30; 9],
        vec![0x70],
    ] {
        rejects(
            &fields(vec![
                ("early", body(0x40, b"early-sentinel")),
                ("late", value),
            ]),
            PlaintextError::UnsupportedRepresentation,
        );
    }
    for root in [ascii("not-dict"), vec![0xa0], vec![0x40], vec![0x10, 1]] {
        rejects(
            &assemble(&[root], 0, 1, 1),
            PlaintextError::UnsupportedRepresentation,
        );
    }
    rejects(
        &assemble(
            &[
                dictionary(&[1], &[2], 1),
                ascii("k"),
                body(0x40, b""),
                ascii("unused"),
            ],
            0,
            1,
            1,
        ),
        PlaintextError::UnsupportedRepresentation,
    );
    rejects(
        &single(vec![0x10, 0], ascii("value")),
        PlaintextError::UnsupportedRepresentation,
    );
}

#[test]
fn shared_values_allowed_decoded_duplicate_keys_rejected() {
    let objects = vec![
        dictionary(&[1, 2], &[3, 3], 1),
        ascii("a"),
        utf16("b"),
        body(0x40, b"shared"),
    ];
    let input = padded(&assemble(&objects, 0, 1, 1));
    let view = parse_bytes(&input).unwrap();
    assert_eq!(
        view.get("a").unwrap().raw_body().as_ptr(),
        view.get("b").unwrap().raw_body().as_ptr()
    );
    for second in [ascii("a"), utf16("a")] {
        rejects(
            &assemble(
                &[
                    dictionary(&[1, 2], &[3, 3], 1),
                    ascii("a"),
                    second,
                    body(0x40, b"x"),
                ],
                0,
                1,
                1,
            ),
            PlaintextError::DuplicateKey,
        );
    }
    rejects(
        &assemble(
            &[
                dictionary(&[1, 1], &[2, 3], 1),
                ascii("a"),
                body(0x40, b"x"),
                body(0x40, b"y"),
            ],
            0,
            1,
            1,
        ),
        PlaintextError::DuplicateKey,
    );
    for pair in [("é", "e\u{301}"), ("A", "a"), ("", "x")] {
        let input = padded(&assemble(
            &[
                dictionary(&[1, 2], &[3, 3], 1),
                utf16(pair.0),
                utf16(pair.1),
                body(0x40, b""),
            ],
            0,
            1,
            1,
        ));
        assert_eq!(parse_bytes(&input).unwrap().entries().count(), 2);
    }
}

#[test]
fn utf16_validation_and_iteration_are_exact() {
    for text in ["", "ASCII\0", "한글", "é", "😀", "a𐀀z", "\u{10ffff}"] {
        let input = padded(&single(utf16("k"), utf16(text)));
        let view = parse_bytes(&input).unwrap();
        let value = view.get("k").unwrap();
        assert_eq!(value.kind(), ScalarKind::Utf16);
        assert!(value.as_text().unwrap().chars().eq(text.chars()));
        let mut chars = value.as_text().unwrap().chars();
        while chars.next().is_some() {}
        assert_eq!(chars.next(), None);
        assert_eq!(chars.next(), None);
    }
    for units in [
        vec![0xd800],
        vec![0xdc00],
        vec![0xdc00, 0xd800],
        vec![0xd800, 0x61],
        vec![0xd800, 0xd800],
        vec![0x61, 0xdc00],
    ] {
        let value = body(
            0x60,
            &units
                .into_iter()
                .flat_map(u16::to_be_bytes)
                .collect::<Vec<_>>(),
        );
        rejects(&single(ascii("k"), value), PlaintextError::InvalidText);
    }
    rejects(
        &single(ascii("k"), vec![0x61, 0]),
        PlaintextError::MalformedLayout,
    );
    rejects(
        &single(ascii("k"), body(0x50, &[0xff])),
        PlaintextError::InvalidText,
    );
    // Invalid final object invalidates the whole item after valid early data.
    rejects(
        &fields(vec![
            ("first", body(0x40, b"synthetic-secret")),
            ("last", vec![0x61, 0xd8, 0]),
        ]),
        PlaintextError::InvalidText,
    );
}

#[test]
fn scalar_raw_fidelity_and_no_numeric_coercion() {
    let mut cases = vec![
        (ScalarKind::Data, body(0x40, b"\0\xff\x80")),
        (ScalarKind::Boolean, vec![0x08]),
        (ScalarKind::Boolean, vec![0x09]),
        (ScalarKind::Real, vec![0x22, 0x80, 0, 0, 0]),
        (
            ScalarKind::Real,
            vec![0x23, 0x7f, 0xf8, 0, 0, 0, 0, 0, 0x42],
        ),
        (ScalarKind::Date, vec![0x33, 0xff, 0xf0, 0, 0, 0, 0, 0, 0]),
    ];
    for exponent in 0..=4 {
        let mut bytes = vec![0x10 | exponent];
        bytes.extend(vec![0xff; 1 << exponent]);
        cases.push((ScalarKind::Integer, bytes));
    }
    for (kind, encoding) in cases {
        let input = padded(&single(ascii("k"), encoding.clone()));
        let view = parse_bytes(&input).unwrap();
        let value = view.get("k").unwrap();
        assert_eq!(value.kind(), kind);
        assert_eq!(value.raw_encoding(), encoding);
        assert_eq!(value.raw_body(), &encoding[1..]);
        assert_eq!(
            value.as_bool(),
            if kind == ScalarKind::Boolean {
                Some(encoding[0] == 9)
            } else {
                None
            }
        );
        assert!(value.as_text().is_none());
    }
}

#[test]
fn tombstone_three_states_gate_candidates_without_password_dependency() {
    for exponent in 0..=4 {
        for n in [0, 1, 2] {
            let mut value = vec![0x10 | exponent];
            value.extend(vec![0; 1 << exponent]);
            *value.last_mut().unwrap() = n;
            let mut f = inet_fields();
            f.last_mut().unwrap().1 = value;
            let input = padded(&fields(f));
            let view = parse_bytes(&input).unwrap();
            match n {
                0 => {
                    assert_eq!(
                        view.tombstone_state().unwrap(),
                        TombstoneState::NotTombstone
                    );
                    assert!(view.internet_password_candidate().is_ok());
                }
                1 => {
                    assert_eq!(view.tombstone_state().unwrap(), TombstoneState::Tombstone);
                    assert_eq!(
                        view.internet_password_candidate().unwrap_err(),
                        ProjectionError::Tombstone
                    );
                }
                _ => assert_eq!(
                    view.tombstone_state().unwrap_err(),
                    ProjectionError::UnsupportedTombstone
                ),
            }
        }
    }
    let mut f = inet_fields();
    f.pop();
    let input = padded(&fields(f));
    let view = parse_bytes(&input).unwrap();
    assert_eq!(view.tombstone_state().unwrap(), TombstoneState::Missing);
    assert_eq!(
        view.internet_password_candidate().unwrap_err(),
        ProjectionError::MissingTombstone
    );
    for value in [
        vec![0x08],
        vec![0x09],
        ascii("0"),
        ascii("1"),
        vec![0x22, 0, 0, 0, 0],
        vec![0x10, 0xff],
        vec![0x11, 1, 0],
        body(0x40, b"0"),
    ] {
        let input = padded(&fields(vec![("tomb", value)]));
        let view = parse_bytes(&input).unwrap();
        assert_eq!(
            view.tombstone_state().unwrap_err(),
            ProjectionError::UnsupportedTombstone
        );
        assert_eq!(
            view.internet_password_candidate().unwrap_err(),
            ProjectionError::UnsupportedTombstone
        );
    }
    let input = padded(&fields(vec![("tomb", vec![0x10, 1])]));
    let view = parse_bytes(&input).unwrap();
    assert_eq!(view.tombstone_state().unwrap(), TombstoneState::Tombstone);
    assert_eq!(
        view.internet_password_candidate().unwrap_err(),
        ProjectionError::Tombstone
    );
}

#[test]
fn projection_errors_are_separate_and_raw_extensions_preserved() {
    for field in 0..5 {
        let mut f = inet_fields();
        f.remove(field);
        let input = padded(&fields(f));
        let view = parse_bytes(&input).unwrap();
        assert_eq!(
            view.internet_password_candidate().unwrap_err(),
            ProjectionError::MissingField
        );
        let mut f = inet_fields();
        f[field].1 = vec![0x10, 0];
        let input = padded(&fields(f));
        let view = parse_bytes(&input).unwrap();
        assert_eq!(
            view.internet_password_candidate().unwrap_err(),
            ProjectionError::UnsupportedFieldType
        );
    }
    for (index, value, error) in [
        (0, ascii("genp"), ProjectionError::UnsupportedClass),
        (0, ascii("INET"), ProjectionError::UnsupportedClass),
        (2, ascii(""), ProjectionError::EmptyServer),
        (3, ascii("ftp"), ProjectionError::UnsupportedProtocol),
        (3, ascii("https"), ProjectionError::UnsupportedProtocol),
    ] {
        let mut f = inet_fields();
        f[index].1 = value;
        let input = padded(&fields(f));
        let view = parse_bytes(&input).unwrap();
        assert_eq!(view.internet_password_candidate().unwrap_err(), error);
    }
    for protocol in ["http", "htps"] {
        let mut f = inet_fields();
        f[3].1 = utf16(protocol);
        f.extend([
            ("port", ascii("not-a-port")),
            ("path", vec![0x09]),
            ("UUID", ascii("untrusted")),
            ("sync", vec![0x08]),
            ("notes", body(0x40, b"\x31\x80")),
        ]);
        let input = padded(&fields(f));
        let view = parse_bytes(&input).unwrap();
        let candidate = view.internet_password_candidate().unwrap();
        assert!(candidate.account().is_empty());
        assert!(candidate.password().is_empty());
        assert!(
            view.get("port")
                .unwrap()
                .as_text()
                .unwrap()
                .equals("not-a-port")
        );
        assert_eq!(view.get("path").unwrap().kind(), ScalarKind::Boolean);
        assert_eq!(view.get("notes").unwrap().raw_body(), b"\x31\x80");
        assert_eq!(view.entries().count(), 11);
    }
}

#[test]
fn every_resource_cap_below_at_and_above() {
    for length in [MAX_INPUT - 1, MAX_INPUT, MAX_INPUT + 1] {
        let mut input = SMALL.to_vec();
        input.push(0x80);
        input.resize(length, 0);
        if length <= MAX_INPUT {
            assert!(parse_bytes(&input).is_ok());
        } else {
            assert_eq!(
                parse_bytes(&input).unwrap_err(),
                PlaintextError::LimitExceeded
            );
        }
    }
    for n in [MAX_PAIRS - 1, MAX_PAIRS, MAX_PAIRS + 1] {
        let mut objects = vec![dictionary(&(1..=n).collect::<Vec<_>>(), &vec![n + 1; n], 2)];
        objects.extend((0..n).map(|i| ascii(&format!("{i:0256}"))));
        objects.push(body(0x40, b""));
        let input = padded(&assemble(&objects, 0, 4, 2));
        if n <= MAX_PAIRS {
            assert_eq!(parse_bytes(&input).unwrap().entries().count(), n);
        } else {
            assert_eq!(
                parse_bytes(&input).unwrap_err(),
                PlaintextError::LimitExceeded
            );
        }
    }
    for n in [MAX_OBJECTS - 1, MAX_OBJECTS, MAX_OBJECTS + 1] {
        let values = n - 257;
        let mut objects = vec![dictionary(
            &(1..=256).collect::<Vec<_>>(),
            &(0..256).map(|i| 257 + i % values).collect::<Vec<_>>(),
            2,
        )];
        objects.extend((0..256).map(|i| ascii(&format!("k{i}"))));
        objects.extend((0..values).map(|_| body(0x40, b"")));
        let input = padded(&assemble(&objects, 0, 4, 2));
        if n <= MAX_OBJECTS {
            assert_eq!(parse_bytes(&input).unwrap().entries().count(), 256);
        } else {
            assert_eq!(
                parse_bytes(&input).unwrap_err(),
                PlaintextError::LimitExceeded
            );
        }
    }
    for kind in [0x40, 0x50, 0x60] {
        let step = if kind == 0x60 { 2 } else { 1 };
        for length in [MAX_SCALAR - step, MAX_SCALAR, MAX_SCALAR + step] {
            let input = padded(&single(ascii("k"), body(kind, &vec![0; length])));
            if length <= MAX_SCALAR {
                assert_eq!(
                    parse_bytes(&input)
                        .unwrap()
                        .get("k")
                        .unwrap()
                        .raw_body()
                        .len(),
                    length
                );
            } else {
                assert_eq!(
                    parse_bytes(&input).unwrap_err(),
                    PlaintextError::LimitExceeded
                );
            }
        }
    }
    for kind in [0x50, 0x60] {
        let step = if kind == 0x60 { 2 } else { 1 };
        for length in [MAX_KEY - step, MAX_KEY, MAX_KEY + step] {
            let input = padded(&single(body(kind, &vec![0; length]), body(0x40, b"")));
            if length <= MAX_KEY {
                assert!(parse_bytes(&input).is_ok());
            } else {
                assert_eq!(
                    parse_bytes(&input).unwrap_err(),
                    PlaintextError::LimitExceeded
                );
            }
        }
    }
    // Distinct body accounting is bounded by disjoint spans and total input.
    let input = padded(&fields(vec![
        ("a", body(0x40, &vec![0; MAX_SCALAR])),
        ("b", body(0x40, &vec![0; MAX_SCALAR])),
        ("c", body(0x40, &vec![0; MAX_SCALAR])),
    ]));
    assert!(parse_bytes(&input).is_ok());
    let input = padded(&fields(vec![
        ("a", body(0x40, &vec![0; MAX_SCALAR])),
        ("b", body(0x40, &vec![0; MAX_SCALAR])),
        ("c", body(0x40, &vec![0; MAX_SCALAR])),
        ("d", body(0x40, &vec![0; MAX_SCALAR])),
    ]));
    assert_eq!(
        parse_bytes(&input).unwrap_err(),
        PlaintextError::LimitExceeded
    );
}

#[test]
fn secret_views_iterators_and_errors_have_fixed_redacted_debug() {
    let input = Zeroizing::new(padded(INET));
    let view = parse_bytes(&input).unwrap();
    let entry = view.entries().next().unwrap();
    let mut chars = entry.key.chars();
    chars.next();
    for debug in [
        format!("{view:?}"),
        format!("{:?}", view.entries()),
        format!("{entry:?}"),
        format!("{:?}", entry.key),
        format!("{:?}", entry.value),
        format!("{chars:?}"),
        format!("{:?}", view.internet_password_candidate().unwrap()),
        format!("{:?}", PlaintextError::DuplicateKey),
        format!("{:?}", ProjectionError::MissingField),
    ] {
        assert_eq!(debug, "<redacted>");
    }
}

// Existing RustCrypto primitives only; this is composition evidence, not an
// independent crypto vector. All key/nonce/AD/plaintext values are invented.
fn encrypt_synthetic(bytes: &[u8]) -> (UnwrappingKey, Vec<u8>) {
    let key = UnwrappingKey::new(Zeroizing::new([0x47; 64]));
    let mut envelope = vec![0x29; 32];
    envelope.extend(bytes);
    let (prefix, body) = envelope.split_at_mut(32);
    let tag = Aes256Siv::new(key.expose_secret().into())
        .encrypt_inout_detached([&prefix[..16], &b"synthetic-ad"[..]], body.into())
        .unwrap();
    prefix[16..32].copy_from_slice(&tag);
    (key, envelope)
}
#[test]
fn actual_payload_decrypt_then_explicit_parse_owner_unchanged_on_failure() {
    let bytes = Zeroizing::new(padded(INET));
    let (key, envelope) = encrypt_synthetic(&bytes);
    let owner = payload::decrypt(&key, &envelope, &[b"synthetic-ad"]).unwrap();
    let view = parse_ckks_plaintext(&owner).unwrap();
    assert!(view.internet_password_candidate().is_ok());
    assert_eq!(owner.expose_secret(), &*bytes);
    drop(owner);
    let bytes = Zeroizing::new(padded(&fields(vec![
        ("early", ascii("secret-sentinel")),
        ("late", vec![0xa0]),
    ])));
    let (key, mut envelope) = encrypt_synthetic(&bytes);
    let owner = payload::decrypt(&key, &envelope, &[b"synthetic-ad"]).unwrap();
    assert_eq!(
        parse_ckks_plaintext(&owner).unwrap_err(),
        PlaintextError::UnsupportedRepresentation
    );
    assert_eq!(owner.expose_secret(), &*bytes);
    drop(owner); // Caller explicitly releases failure input.
    envelope[16] ^= 1;
    let mut parser_called = false;
    let result = payload::decrypt(&key, &envelope, &[b"synthetic-ad"]).map(|owner| {
        parser_called = true;
        parse_ckks_plaintext(&owner).is_ok()
    });
    assert!(result.is_err());
    assert!(!parser_called);
}

#[test]
fn concrete_metadata_storage_stays_bounded() {
    let view = core::mem::size_of::<FlatItemView<'static>>();
    let object = core::mem::size_of::<Object>();
    let scratch = core::mem::size_of::<[usize; MAX_OBJECTS]>();
    assert!(view + scratch + object <= 64 * 1024);
    eprintln!(
        "view={view}, object={object}, sorting_scratch={scratch}, sum={}",
        view + scratch + object
    );
}

#[test]
fn short_counts_extended_truncation_and_late_limit_failures() {
    for count in [14, 15, 16, 127, 128, 255, 256] {
        for kind in [0x40, 0x50, 0x60] {
            let bytes = vec![0; count * if kind == 0x60 { 2 } else { 1 }];
            let input = padded(&single(ascii("k"), body(kind, &bytes)));
            assert_eq!(
                parse_bytes(&input).unwrap().get("k").unwrap().raw_body(),
                bytes
            );
        }
    }
    for width in [1, 2, 4, 8] {
        let full = token(0x40, 14, Some(width));
        for end in 1..full.len() {
            rejects(
                &single(ascii("k"), full[..end].to_vec()),
                PlaintextError::MalformedLayout,
            );
        }
    }
    rejects(
        &fields(vec![
            ("early", ascii("sentinel")),
            ("late", body(0x40, &vec![0; MAX_SCALAR + 1])),
        ]),
        PlaintextError::LimitExceeded,
    );
    for rw in [1, 2, 4, 8] {
        let mut root = dictionary(&[1], &[2], rw);
        root[1 + rw..].fill(0xff);
        rejects(
            &assemble(&[root, ascii("k"), body(0x40, b"")], 0, 4, rw),
            PlaintextError::MalformedLayout,
        );
    }
    let input = padded(&assemble(
        &[dictionary(&[1], &[1], 1), ascii("self-value")],
        0,
        1,
        1,
    ));
    assert!(
        parse_bytes(&input)
            .unwrap()
            .get("self-value")
            .unwrap()
            .as_text()
            .unwrap()
            .equals("self-value")
    );
    rejects(
        &assemble(
            &[
                dictionary(&[1], &[2], 1),
                ascii("k"),
                body(0x40, b""),
                vec![0x61, 0xdc, 0],
            ],
            0,
            1,
            1,
        ),
        PlaintextError::InvalidText,
    );
}
