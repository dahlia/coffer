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

//! Independent bottle wire fixtures and hostile-input regression tests.

use coffer_protocol::octagon::bottle::{BottleEnvelope, BottleError};

const ORIGINAL: &[u8] = include_bytes!("fixtures/octagon-bottle/original.bin");
const ESCROW: &[u8] = include_bytes!("fixtures/octagon-bottle/original-escrow.der");
const PEER: &[u8] = include_bytes!("fixtures/octagon-bottle/original-peer.der");
const SPKI: &[u8] = include_bytes!("fixtures/octagon-bottle/key-1-spki.der");
const OTHER: &[u8] = include_bytes!("fixtures/octagon-bottle/key-2-spki.der");

const PEER_SIGNING: &[u8] = include_bytes!("fixtures/octagon-bottle/key-3-spki.der");
const PEER_ENCRYPTION: &[u8] = include_bytes!("fixtures/octagon-bottle/key-4-spki.der");

fn varint(mut n: u64) -> Vec<u8> {
    let mut result = Vec::new();
    while n > 127 {
        result.push((n as u8 & 127) | 128);
        n >>= 7;
    }
    result.push(n as u8);
    result
}
fn field(n: u64, value: &[u8]) -> Vec<u8> {
    let mut bytes = varint(n * 8 + 2);
    bytes.extend(varint(value.len() as u64));
    bytes.extend(value);
    bytes
}
fn nested() -> Vec<u8> {
    [field(1, b"cipher"), field(2, b"tag"), field(3, b"iv")].concat()
}
fn parts(contents: &[u8]) -> Vec<Vec<u8>> {
    vec![
        field(1, b"peer"),
        field(2, b"bottle"),
        field(8, SPKI),
        field(9, OTHER),
        field(10, PEER_SIGNING),
        field(11, PEER_ENCRYPTION),
        field(12, contents),
    ]
}
fn reject(bytes: &[u8], error: BottleError) {
    assert_eq!(BottleEnvelope::parse(bytes).unwrap_err(), error);
}

#[test]
fn independent_golden_preserves_all_borrowed_bytes_and_checks_both_signatures() {
    let envelope = BottleEnvelope::parse(ORIGINAL).unwrap();
    assert_eq!(envelope.raw_bytes(), ORIGINAL);
    assert_eq!(envelope.raw_bytes().as_ptr(), ORIGINAL.as_ptr());
    assert_eq!(envelope.peer_id(), "synthetic-peer");
    assert_eq!(envelope.bottle_id(), "synthetic-bottle");
    assert_eq!(envelope.escrow_signing_spki(), SPKI);
    assert_eq!(envelope.escrow_encryption_spki(), OTHER);
    assert_eq!(envelope.peer_signing_spki(), PEER_SIGNING);
    assert_eq!(envelope.peer_encryption_spki(), PEER_ENCRYPTION);
    let expected = [
        field(1, b"opaque synthetic ciphertext"),
        field(2, b"not-an-aead-tag"),
        field(3, b"iv"),
        field(21, b"\xff\x00"),
        field(21, b"\x80"),
    ]
    .concat();
    assert_eq!(envelope.contents_bytes(), expected);
    assert_eq!(envelope.ciphertext(), b"opaque synthetic ciphertext");
    assert_eq!(envelope.authentication_code(), b"not-an-aead-tag");
    assert_eq!(envelope.initialization_vector(), b"iv");
    for slice in [
        envelope.contents_bytes(),
        envelope.ciphertext(),
        envelope.escrow_signing_spki(),
    ] {
        let start = slice.as_ptr() as usize;
        let raw = ORIGINAL.as_ptr() as usize;
        assert!(start >= raw && start + slice.len() <= raw + ORIGINAL.len());
    }
    let consistency = envelope.verify_embedded_signatures(ESCROW, PEER).unwrap();
    assert!(std::ptr::eq(consistency.envelope(), &envelope));
}

#[test]
fn order_is_not_canonicalized_and_unknown_bytes_remain_signed() {
    let raw = include_bytes!("fixtures/octagon-bottle/reordered.bin");
    let reordered = BottleEnvelope::parse(raw).unwrap();
    assert_eq!(reordered.peer_id(), "synthetic-peer");
    assert_eq!(
        reordered
            .verify_embedded_signatures(ESCROW, PEER)
            .unwrap_err(),
        BottleError::SignatureMismatch
    );
    reordered
        .verify_embedded_signatures(
            include_bytes!("fixtures/octagon-bottle/reordered-escrow.der"),
            include_bytes!("fixtures/octagon-bottle/reordered-peer.der"),
        )
        .unwrap();
    // The final byte is an opaque unknown field, not a known property.
    let mut changed = ORIGINAL.to_vec();
    *changed.last_mut().unwrap() ^= 1;
    assert_eq!(
        BottleEnvelope::parse(&changed)
            .unwrap()
            .verify_embedded_signatures(ESCROW, PEER)
            .unwrap_err(),
        BottleError::SignatureMismatch
    );
    let mut changed = ORIGINAL.to_vec();
    let parsed = BottleEnvelope::parse(ORIGINAL).unwrap();
    let contents_offset = parsed.contents_bytes().as_ptr() as usize - ORIGINAL.as_ptr() as usize;
    let marker = field(21, &[0xff, 0]);
    let offset = contents_offset
        + parsed
            .contents_bytes()
            .windows(marker.len())
            .position(|w| w == marker)
            .unwrap()
        + marker.len()
        - 2;
    changed[offset] ^= 1;
    assert_eq!(
        BottleEnvelope::parse(&changed)
            .unwrap()
            .verify_embedded_signatures(ESCROW, PEER)
            .unwrap_err(),
        BottleError::SignatureMismatch
    );
}

#[test]
fn attacker_chosen_replacement_also_passes_consistency_without_establishing_trust() {
    let envelope =
        BottleEnvelope::parse(include_bytes!("fixtures/octagon-bottle/replacement.bin")).unwrap();
    assert_eq!(envelope.peer_id(), "attacker-peer");
    assert_ne!(envelope.escrow_signing_spki(), SPKI);
    envelope
        .verify_embedded_signatures(
            include_bytes!("fixtures/octagon-bottle/replacement-escrow.der"),
            include_bytes!("fixtures/octagon-bottle/replacement-peer.der"),
        )
        .unwrap();
}

#[test]
fn signature_encodings_lengths_wrong_keys_and_both_s_ranges() {
    let envelope = BottleEnvelope::parse(ORIGINAL).unwrap();
    for escrow in [
        include_bytes!("fixtures/octagon-bottle/original-escrow-high.der").as_slice(),
        include_bytes!("fixtures/octagon-bottle/original-escrow-low.der").as_slice(),
    ] {
        envelope.verify_embedded_signatures(escrow, PEER).unwrap();
    }
    assert_eq!(
        envelope
            .verify_embedded_signatures(PEER, ESCROW)
            .unwrap_err(),
        BottleError::SignatureMismatch
    );
    assert_eq!(
        envelope
            .verify_embedded_signatures(ESCROW, ESCROW)
            .unwrap_err(),
        BottleError::SignatureMismatch
    );
    for len in [0, 7, 8, 103, 104, 105] {
        let invalid = vec![0; len];
        for (a, b) in [(invalid.as_slice(), PEER), (ESCROW, invalid.as_slice())] {
            assert_eq!(
                envelope.verify_embedded_signatures(a, b).unwrap_err(),
                BottleError::InvalidSignatureEncoding
            );
        }
    }
    for len in 0..ESCROW.len() {
        assert_eq!(
            envelope
                .verify_embedded_signatures(&ESCROW[..len], PEER)
                .unwrap_err(),
            BottleError::InvalidSignatureEncoding
        );
    }
    let mut trailing = ESCROW.to_vec();
    trailing.push(0);
    assert_eq!(
        envelope
            .verify_embedded_signatures(&trailing, PEER)
            .unwrap_err(),
        BottleError::InvalidSignatureEncoding
    );
    let mut mismatch = ESCROW.to_vec();
    *mismatch.last_mut().unwrap() ^= 1;
    assert_eq!(
        envelope
            .verify_embedded_signatures(&mismatch, PEER)
            .unwrap_err(),
        BottleError::SignatureMismatch
    );
}

#[test]
fn known_fields_are_mandatory_unique_and_length_delimited() {
    let contents = nested();
    let outer = parts(&contents);
    for (index, n) in [1, 2, 8, 9, 10, 11, 12].into_iter().enumerate() {
        let mut absent = outer.clone();
        absent.remove(index);
        reject(&absent.concat(), BottleError::MissingField);
        let mut duplicate = outer.clone();
        duplicate.push(outer[index].clone());
        reject(&duplicate.concat(), BottleError::DuplicateField);
        let mut wrong = outer.clone();
        wrong[index] = [varint(n * 8), vec![0]].concat();
        reject(&wrong.concat(), BottleError::MalformedWire);
        let mut duplicate_wrong_wire = outer.clone();
        duplicate_wrong_wire.push([varint(n * 8), vec![0]].concat());
        reject(&duplicate_wrong_wire.concat(), BottleError::DuplicateField);
    }
    let inner = [field(1, b"cipher"), field(2, b"tag"), field(3, b"iv")];
    for (i, n) in [1, 2, 3].into_iter().enumerate() {
        let absent = inner
            .iter()
            .enumerate()
            .filter(|(j, _)| *j != i)
            .flat_map(|(_, b)| b.clone())
            .collect::<Vec<_>>();
        reject(&parts(&absent).concat(), BottleError::MissingField);
        let duplicate = [contents.clone(), inner[i].clone()].concat();
        reject(&parts(&duplicate).concat(), BottleError::DuplicateField);
        let mut wrong = inner.to_vec();
        wrong[i] = [varint(n * 8), vec![0]].concat();
        reject(&parts(&wrong.concat()).concat(), BottleError::MalformedWire);
        let duplicate = [contents.clone(), varint(n * 8), vec![0]].concat();
        reject(&parts(&duplicate).concat(), BottleError::DuplicateField);
    }
    let mut merge = parts(&field(1, b"cipher"));
    merge.push(field(12, &[field(2, b"tag"), field(3, b"iv")].concat()));
    reject(&merge.concat(), BottleError::DuplicateField);
}

#[test]
fn malformed_wire_varints_groups_reserved_and_lengths_are_rejected() {
    let base = parts(&nested()).concat();
    let mut cases = vec![
        vec![0],
        vec![0x80],
        vec![0x80; 10],
        vec![0xff; 11],
        vec![0x82, 0, 0],                              // nonminimal field key
        vec![0x6a, 0x80, 0],                           // nonminimal length
        vec![0x68, 0x80, 0],                           // nonminimal unknown varint
        [vec![0x68], vec![0xff; 9], vec![2]].concat(), // u64 overflow
        [vec![0x6a], varint(u64::MAX)].concat(),
        [vec![0x6a], varint(1024)].concat(),
        varint(536_870_912u64 * 8),
    ];
    for wire in [3, 4, 6, 7] {
        cases.push(vec![0x68 | wire]);
    }
    for bytes in cases {
        let bad = [base.clone(), bytes].concat();
        assert!(BottleEnvelope::parse(&bad).is_err());
        let inner = [nested(), bad[base.len()..].to_vec()].concat();
        assert!(BottleEnvelope::parse(&parts(&inner).concat()).is_err());
    }
    for n in 3..=7 {
        reject(
            &[base.clone(), field(n, b"old")].concat(),
            BottleError::UnsupportedEncoding,
        );
    }
    for wire in [1, 5] {
        let length = if wire == 1 { 8 } else { 4 };
        for len in 0..length {
            let suffix = [varint(20 * 8 + wire), vec![0; len]].concat();
            reject(&[base.clone(), suffix].concat(), BottleError::MalformedWire);
        }
    }
}

#[test]
fn unknown_fields_are_skipped_without_interpreting_or_deduplicating() {
    let base = parts(&nested()).concat();
    let suffix = [
        field(536_870_911, b"\xff\x00\x80"),
        field(20, b""),
        field(20, b"\xff"),
        varint(21 * 8),
        varint(u64::MAX),
        varint(22 * 8 + 1),
        vec![0; 8],
        varint(23 * 8 + 5),
        vec![0; 4],
    ]
    .concat();
    let raw = [base, suffix.clone()].concat();
    assert_eq!(BottleEnvelope::parse(&raw).unwrap().raw_bytes(), raw);
    let contents = [nested(), suffix].concat();
    let raw = parts(&contents).concat();
    assert_eq!(
        BottleEnvelope::parse(&raw).unwrap().contents_bytes(),
        contents
    );
}

#[test]
fn empty_opaque_fields_and_each_size_boundary() {
    let contents = [field(1, b""), field(2, b""), field(3, b"")].concat();
    let raw = parts(&contents).concat();
    let envelope = BottleEnvelope::parse(&raw).unwrap();
    assert!(envelope.ciphertext().is_empty());
    assert!(envelope.authentication_code().is_empty());
    assert!(envelope.initialization_vector().is_empty());
    for tag in [2, 3] {
        for len in [63, 64, 65] {
            let mut inner = [field(1, b""), field(2, b""), field(3, b"")];
            inner[tag - 1] = field(tag as u64, &vec![0; len]);
            let raw = parts(&inner.concat()).concat();
            if len <= 64 {
                BottleEnvelope::parse(&raw).unwrap();
            } else {
                reject(&raw, BottleError::SizeLimit);
            }
        }
    }
    for (index, n) in [(0, 1), (1, 2)] {
        for len in [0, 1, 1023, 1024, 1025] {
            let mut outer = parts(&nested());
            outer[index] = field(n, &vec![b'a'; len]);
            let raw = outer.concat();
            match len {
                0 => reject(&raw, BottleError::InvalidIdentifier),
                1025 => reject(&raw, BottleError::SizeLimit),
                _ => {
                    BottleEnvelope::parse(&raw).unwrap();
                }
            }
        }
        let mut outer = parts(&nested());
        outer[index] = field(n, b"\xff");
        reject(&outer.concat(), BottleError::InvalidIdentifier);
    }
    // A 2-byte UTF-8 character counts as two bytes, without normalization.
    let mut outer = parts(&nested());
    outer[0] = field(1, "é".repeat(512).as_bytes());
    assert_eq!(
        BottleEnvelope::parse(&outer.concat())
            .unwrap()
            .peer_id()
            .len(),
        1024
    );
    let base = parts(&nested()).concat();
    for length in [1_048_575, 1_048_576, 1_048_577] {
        // Unknown tag 20 occupies two bytes, the payload length three bytes.
        let payload = vec![0; length - base.len() - 5];
        let raw = [base.clone(), field(20, &payload)].concat();
        assert_eq!(raw.len(), length);
        if length <= 1_048_576 {
            BottleEnvelope::parse(&raw).unwrap();
        } else {
            reject(&raw, BottleError::SizeLimit);
        }
    }
    reject(&[], BottleError::SizeLimit);
    reject(&[0], BottleError::MalformedWire);
}

#[test]
fn field_budget_is_shared_by_outer_and_contents() {
    // Seven known outer fields plus three inner fields leave 54 occurrences.
    for count in [53, 54, 55] {
        for inside in [false, true] {
            let extra = field(20, b"").repeat(count);
            let raw = if inside {
                parts(&[nested(), extra].concat()).concat()
            } else {
                [parts(&nested()).concat(), extra].concat()
            };
            if count <= 54 {
                BottleEnvelope::parse(&raw).unwrap();
            } else {
                reject(&raw, BottleError::SizeLimit);
            }
        }
    }
}

#[test]
fn every_spki_is_validated_and_structural_failures_precede_key_parsing() {
    for (index, n) in [(2, 8), (3, 9), (4, 10), (5, 11)] {
        for len in [119, 121] {
            let mut outer = parts(&nested());
            outer[index] = field(n, &vec![0; len]);
            reject(&outer.concat(), BottleError::InvalidKey);
        }
        for bad in [
            vec![0; 120],
            include_bytes!("fixtures/octagon-keys/p256-spki.der").to_vec(),
        ] {
            let mut outer = parts(&nested());
            outer[index] = field(n, &bad);
            reject(&outer.concat(), BottleError::InvalidKey);
        }
        let mut bad = SPKI.to_vec();
        bad[0] = 0x31;
        let mut outer = parts(&nested());
        outer[index] = field(n, &bad);
        reject(&outer.concat(), BottleError::InvalidKey);
        let mut bad = SPKI.to_vec();
        bad[23] = 2;
        outer[index] = field(n, &bad);
        reject(&outer.concat(), BottleError::InvalidKey);
    }
    let mut outer = parts(&nested());
    outer[2] = field(8, &[0; 120]);
    let malformed = [outer.concat(), vec![0]].concat();
    reject(&malformed, BottleError::MalformedWire);
    outer[6] = field(12, &[nested(), field(3, b"duplicate")].concat());
    reject(&outer.concat(), BottleError::DuplicateField);
}

#[test]
fn all_truncations_and_single_byte_mutations_fail_structure_or_signatures() {
    for end in 0..ORIGINAL.len() {
        if let Ok(envelope) = BottleEnvelope::parse(&ORIGINAL[..end]) {
            assert!(
                envelope.verify_embedded_signatures(ESCROW, PEER).is_err(),
                "prefix {end}"
            );
        }
    }
    for i in 0..ORIGINAL.len() {
        let mut changed = ORIGINAL.to_vec();
        changed[i] ^= 1;
        if let Ok(envelope) = BottleEnvelope::parse(&changed) {
            assert!(
                envelope.verify_embedded_signatures(ESCROW, PEER).is_err(),
                "offset {i}"
            );
        }
    }
}

#[test]
fn debug_and_static_errors_never_disclose_inputs() {
    use std::error::Error;
    let envelope = BottleEnvelope::parse(ORIGINAL).unwrap();
    let consistency = envelope.verify_embedded_signatures(ESCROW, PEER).unwrap();
    assert_eq!(format!("{envelope:?}"), "BottleEnvelope(<redacted>)");
    assert_eq!(format!("{envelope:#?}"), "BottleEnvelope(<redacted>)");
    assert_eq!(
        format!("{consistency:?}"),
        "BottleSignatureConsistency(<redacted>)"
    );
    assert_eq!(
        format!("{consistency:#?}"),
        "BottleSignatureConsistency(<redacted>)"
    );
    for error in [
        BottleError::SizeLimit,
        BottleError::MalformedWire,
        BottleError::UnsupportedEncoding,
        BottleError::MissingField,
        BottleError::DuplicateField,
        BottleError::InvalidIdentifier,
        BottleError::InvalidKey,
        BottleError::InvalidSignatureEncoding,
        BottleError::SignatureMismatch,
    ] {
        assert!(error.source().is_none());
        assert!(!error.to_string().contains("synthetic"));
        assert!(!format!("{error:#?}").contains("synthetic"));
    }
}

#[test]
fn deterministic_arbitrary_bounded_input_does_not_panic() {
    // This is a hostile-byte generator, not a cryptographic RNG.
    let mut state = 1u32;
    for length in 0..2048 {
        let bytes: Vec<u8> = (0..length)
            .map(|_| {
                state = state.wrapping_mul(1664525).wrapping_add(1013904223);
                (state >> 24) as u8
            })
            .collect();
        let _ = BottleEnvelope::parse(&bytes);
    }
}
