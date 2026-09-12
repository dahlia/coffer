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

//! Independent offline vectors and hostile encodings for Octagon key primitives.

use coffer_protocol::octagon::keys::{KeyError, MAX_MESSAGE_LEN, PrivateKey, PublicKey};
use zeroize::Zeroizing;

const POINT: &[u8; 97] = include_bytes!("fixtures/octagon-keys/p384-public.sec1");
const OTHER: &[u8; 97] = include_bytes!("fixtures/octagon-keys/p384-other-public.sec1");
const SPKI: &[u8; 120] = include_bytes!("fixtures/octagon-keys/p384-spki.der");
const FULL: &[u8; 145] = include_bytes!("fixtures/octagon-keys/p384-private.full");
const MESSAGE: &[u8] = include_bytes!("fixtures/octagon-keys/message.bin");
const HIGH: &[u8] = include_bytes!("fixtures/octagon-keys/signature-high.der");
const LOW: &[u8] = include_bytes!("fixtures/octagon-keys/signature-low.der");

#[test]
fn openssl_public_and_private_byte_exact_exports() {
    let public = PublicKey::from_sec1_bytes(POINT).unwrap();
    assert_eq!(public.to_sec1_bytes(), *POINT);
    assert_eq!(public.to_spki_der().unwrap(), SPKI);
    let spki = PublicKey::from_spki_der(SPKI).unwrap();
    assert_eq!(spki.to_sec1_bytes(), *POINT);
    assert_eq!(spki.to_spki_der().unwrap(), SPKI);
    assert_eq!(
        PublicKey::from_sec1_bytes(OTHER)
            .unwrap()
            .to_spki_der()
            .unwrap(),
        include_bytes!("fixtures/octagon-keys/p384-other-spki.der")
    );
    let private = PrivateKey::from_apple_full(Zeroizing::new(FULL.to_vec())).unwrap();
    assert_eq!(private.expose_secret(), FULL);
    assert_eq!(private.public_key().to_sec1_bytes(), *POINT);
}

#[test]
fn openssl_sha384_signatures_accept_high_and_low_s() {
    let key = PublicKey::from_sec1_bytes(POINT).unwrap();
    key.verify_sha384(MESSAGE, HIGH).unwrap();
    key.verify_sha384(MESSAGE, LOW).unwrap();
    assert_eq!(
        key.verify_sha384(b"modified message", HIGH),
        Err(KeyError::VerificationFailed)
    );
    assert_eq!(
        key.verify_sha384(b"", HIGH),
        Err(KeyError::VerificationFailed)
    );
    assert_eq!(
        key.verify_sha384(&vec![0; MAX_MESSAGE_LEN], HIGH),
        Err(KeyError::VerificationFailed)
    );
    assert!(
        PublicKey::from_sec1_bytes(OTHER)
            .unwrap()
            .verify_sha384(MESSAGE, HIGH)
            .is_err()
    );
    for i in 0..HIGH.len() {
        let mut modified = HIGH.to_vec();
        modified[i] ^= 1;
        assert!(key.verify_sha384(MESSAGE, &modified).is_err(), "offset {i}");
    }
}

#[test]
fn sec1_rejects_truncation_lengths_prefixes_and_off_curve_points() {
    for len in 0..POINT.len() {
        assert!(PublicKey::from_sec1_bytes(&POINT[..len]).is_err());
    }
    for prefix in [0, 2, 3, 6, 7, 255] {
        let mut point = *POINT;
        point[0] = prefix;
        assert!(PublicKey::from_sec1_bytes(&point).is_err());
    }
    let mut off_curve = [0u8; 97];
    off_curve[0] = 4;
    assert!(PublicKey::from_sec1_bytes(&off_curve).is_err());
    let mut out_of_field = [255u8; 97];
    out_of_field[0] = 4;
    assert!(PublicKey::from_sec1_bytes(&out_of_field).is_err());
    assert!(PublicKey::from_sec1_bytes(&[4; 98]).is_err());
    assert!(
        PublicKey::from_sec1_bytes(include_bytes!("fixtures/octagon-keys/p256-public.sec1"))
            .is_err()
    );
}

#[test]
fn private_rejects_bad_scalar_point_and_binding() {
    for len in 0..FULL.len() {
        assert!(PrivateKey::from_apple_full(Zeroizing::new(FULL[..len].to_vec())).is_err());
    }
    for scalar in [[0u8; 48], [255u8; 48], order()] {
        let mut full = FULL.to_vec();
        full[97..].copy_from_slice(&scalar);
        assert_eq!(
            PrivateKey::from_apple_full(Zeroizing::new(full)).unwrap_err(),
            KeyError::InvalidPrivateKey
        );
    }
    let mut mismatch = FULL.to_vec();
    mismatch[..97].copy_from_slice(OTHER);
    assert_eq!(
        PrivateKey::from_apple_full(Zeroizing::new(mismatch)).unwrap_err(),
        KeyError::PublicKeyMismatch
    );
    let mut off_curve = FULL.to_vec();
    off_curve[1..97].fill(0);
    assert!(PrivateKey::from_apple_full(Zeroizing::new(off_curve)).is_err());
    let mut prefix = FULL.to_vec();
    prefix[0] = 2;
    assert!(PrivateKey::from_apple_full(Zeroizing::new(prefix)).is_err());
    assert!(PrivateKey::from_apple_full(Zeroizing::new(vec![0; 146])).is_err());
}

fn order() -> [u8; 48] {
    // Public secp384r1 group order, SEC 2 section 2.5.1.
    let mut n = [255; 48];
    n[24..].copy_from_slice(&[
        0xc7, 0x63, 0x4d, 0x81, 0xf4, 0x37, 0x2d, 0xdf, 0x58, 0x1a, 0x0d, 0xb2, 0x48, 0xb0, 0xa7,
        0x7a, 0xec, 0xec, 0x19, 0x6a, 0xcc, 0xc5, 0x29, 0x73,
    ]);
    n
}

#[test]
fn spki_rejects_noncanonical_structures_and_wrong_curve() {
    for len in 0..SPKI.len() {
        assert!(PublicKey::from_spki_der(&SPKI[..len]).is_err());
    }
    let mut trailing = SPKI.to_vec();
    trailing.push(0);
    assert!(PublicKey::from_spki_der(&trailing).is_err());
    // Insert a duplicate AlgorithmIdentifier into a complete outer SEQUENCE.
    let mut duplicate = SPKI.to_vec();
    duplicate.splice(20..20, SPKI[2..20].iter().copied());
    duplicate[1] += 18;
    assert!(PublicKey::from_spki_der(&duplicate).is_err());
    // Non-minimal long-form length, indefinite length, invalid BIT STRING,
    // wrong named curve/algorithm OIDs, invalid point and unexpected tag.
    let mut long_length = SPKI.to_vec();
    long_length.insert(1, 0x81);
    assert!(PublicKey::from_spki_der(&long_length).is_err());
    for (offset, byte) in [(1, 0x80), (0, 0x31), (22, 1), (19, 35), (12, 2), (23, 6)] {
        let mut malformed = *SPKI;
        malformed[offset] = byte;
        assert!(
            PublicKey::from_spki_der(&malformed).is_err(),
            "offset {offset}"
        );
    }
    assert!(
        PublicKey::from_spki_der(include_bytes!("fixtures/octagon-keys/p256-spki.der")).is_err()
    );
    let mut off_curve = *SPKI;
    off_curve[24..].fill(0);
    assert!(PublicKey::from_spki_der(&off_curve).is_err());
    assert!(PublicKey::from_spki_der(&vec![0; 1024 * 1024]).is_err());
}

#[test]
fn signature_der_rejects_truncation_trailing_duplicates_and_bad_integers() {
    let key = PublicKey::from_sec1_bytes(POINT).unwrap();
    for len in 0..HIGH.len() {
        assert!(key.verify_sha384(MESSAGE, &HIGH[..len]).is_err());
    }
    let malformed: &[&[u8]] = &[
        &[0x30, 6, 2, 1, 0, 2, 1, 1],          // zero r
        &[0x30, 6, 2, 1, 1, 2, 1, 0],          // zero s
        &[0x30, 6, 2, 1, 0x80, 2, 1, 1],       // negative r
        &[0x30, 6, 2, 1, 1, 2, 1, 0x80],       // negative s
        &[0x30, 7, 2, 2, 0, 1, 2, 1, 1],       // unnecessary zero
        &[0x30, 5, 2, 0, 2, 1, 1],             // empty INTEGER
        &[0x30, 9, 2, 1, 1, 2, 1, 1, 2, 1, 1], // duplicate INTEGER
        &[0x30, 0x81, 6, 2, 1, 1, 2, 1, 1],    // non-minimal length
        &[0x30, 0x80, 2, 1, 1, 2, 1, 1, 0, 0], // indefinite length
        &[0x30, 6, 4, 1, 1, 2, 1, 1],          // wrong tag
    ];
    for bytes in malformed {
        assert_eq!(
            key.verify_sha384(MESSAGE, bytes),
            Err(KeyError::InvalidSignatureEncoding)
        );
    }
    // A full syntactically valid DER INTEGER at the group order is invalid.
    for swap in [false, true] {
        let mut large = vec![2, 49, 0];
        large.extend_from_slice(&order());
        let small = [2, 1, 1];
        let mut der = vec![0x30, 54];
        if swap {
            der.extend_from_slice(&small);
            der.extend_from_slice(&large);
        } else {
            der.extend_from_slice(&large);
            der.extend_from_slice(&small);
        }
        assert_eq!(
            key.verify_sha384(MESSAGE, &der),
            Err(KeyError::InvalidSignatureEncoding)
        );
    }
    // LOW has 102 bytes, so this trailing byte remains below the 104-byte cap.
    let mut trailing = LOW.to_vec();
    trailing.push(0);
    assert_eq!(
        key.verify_sha384(MESSAGE, &trailing),
        Err(KeyError::InvalidSignatureEncoding)
    );
    assert_eq!(
        key.verify_sha384(MESSAGE, &[0; 105]),
        Err(KeyError::InvalidSignatureEncoding)
    );
    assert_eq!(
        key.verify_sha384(&vec![0; MAX_MESSAGE_LEN + 1], HIGH),
        Err(KeyError::MessageTooLarge)
    );
}

#[test]
fn debug_and_errors_are_static_and_redacted() {
    let public = PublicKey::from_sec1_bytes(POINT).unwrap();
    let private = PrivateKey::from_apple_full(Zeroizing::new(FULL.to_vec())).unwrap();
    assert_eq!(format!("{public:?}"), "PublicKey(<redacted>)");
    assert_eq!(format!("{public:#?}"), "PublicKey(<redacted>)");
    assert_eq!(format!("{private:?}"), "PrivateKey(<redacted>)");
    assert_eq!(format!("{private:#?}"), "PrivateKey(<redacted>)");
    assert_eq!(
        KeyError::InvalidPrivateKey.to_string(),
        "invalid Octagon private key"
    );
}

#[test]
fn rfc6979_p384_sha384_published_vectors() {
    let point = include_bytes!("fixtures/octagon-keys/rfc6979-public.sec1");
    let spki = include_bytes!("fixtures/octagon-keys/rfc6979-spki.der");
    let full = include_bytes!("fixtures/octagon-keys/rfc6979-private.full");
    let key = PublicKey::from_sec1_bytes(point).unwrap();
    assert_eq!(key.to_sec1_bytes(), *point);
    assert_eq!(key.to_spki_der().unwrap(), spki);
    assert_eq!(
        PublicKey::from_spki_der(spki).unwrap().to_sec1_bytes(),
        *point
    );
    let private = PrivateKey::from_apple_full(Zeroizing::new(full.to_vec())).unwrap();
    assert_eq!(private.expose_secret(), full);
    assert_eq!(private.public_key().to_sec1_bytes(), *point);
    let cases: &[(&[u8], &[u8])] = &[
        (
            include_bytes!("fixtures/octagon-keys/rfc6979-sample-message.bin"),
            include_bytes!("fixtures/octagon-keys/rfc6979-sample-signature.der"),
        ),
        (
            include_bytes!("fixtures/octagon-keys/rfc6979-test-message.bin"),
            include_bytes!("fixtures/octagon-keys/rfc6979-test-signature.der"),
        ),
    ];
    for (message, signature) in cases {
        key.verify_sha384(message, signature).unwrap();
        assert_eq!(
            key.verify_sha384(b"modified message", signature),
            Err(KeyError::VerificationFailed)
        );
    }
}
