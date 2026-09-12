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
use aes_siv::{KeyInit, siv::Aes256Siv};

const NO_AD: &[u8] = include_bytes!("../../../tests/fixtures/ckks-payload/no-ad.bin");
const MULTIPLE_AD: &[u8] = include_bytes!("../../../tests/fixtures/ckks-payload/multiple-ad.bin");
const EMPTY_AD: &[u8] = include_bytes!("../../../tests/fixtures/ckks-payload/empty-ad.bin");
const EMPTY_PLAINTEXT: &[u8] =
    include_bytes!("../../../tests/fixtures/ckks-payload/empty-plaintext.bin");
const NONALIGNED: &[u8] = include_bytes!("../../../tests/fixtures/ckks-payload/nonaligned.bin");
const NONCE_LAST: &[u8] = include_bytes!("../../../tests/fixtures/ckks-payload/nonce-last.bin");
const AD: &[&[u8]] = &[
    b"coffer-payload-public-alpha",
    &[0x00, 0x50, 0x41, 0x44, 0xff, 0x02],
];
const WITH_EMPTY_AD: &[&[u8]] = &[b"", AD[0], b"", AD[1], b""];
const MIB: usize = 1024 * 1024;
const KIB64: usize = 64 * 1024;

fn key() -> UnwrappingKey {
    UnwrappingKey::new(Zeroizing::new(core::array::from_fn(|i| (7 * i + 19) as u8)))
}
fn plaintext(length: usize) -> Vec<u8> {
    (0..length).map(|i| (11 * i + 5) as u8).collect()
}
type FixtureCase = (&'static [u8], &'static [&'static [u8]], usize);

fn positive_cases() -> [FixtureCase; 5] {
    [
        (NO_AD, &[], 32),
        (MULTIPLE_AD, AD, 48),
        (EMPTY_AD, WITH_EMPTY_AD, 48),
        (EMPTY_PLAINTEXT, AD, 0),
        (NONALIGNED, AD, 37),
    ]
}
fn rejects(envelope: &[u8], ad: &[&[u8]], expected: PayloadError) {
    CRYPTO_CALLS.with(|n| n.set(0));
    assert_eq!(decrypt(&key(), envelope, ad).unwrap_err(), expected);
    CRYPTO_CALLS.with(|n| {
        assert_eq!(
            n.get(),
            usize::from(expected == PayloadError::AuthenticationFailed)
        )
    });
}

// This RustCrypto encryption helper is used only for local policy boundaries.
// Interoperability assertions below consume independent static EVP fixtures.
fn policy_envelope(length: usize, ad: &[&[u8]]) -> Vec<u8> {
    let mut result = vec![0u8; length + 32];
    result[..16].copy_from_slice(&NO_AD[..16]);
    result[32..].copy_from_slice(&plaintext(length));
    let (prefix, body) = result.split_at_mut(32);
    let headers =
        core::iter::once(&prefix[..16]).chain(ad.iter().copied().filter(|v| !v.is_empty()));
    let tag = Aes256Siv::new(key().expose_secret().into())
        .encrypt_inout_detached(headers, body.into())
        .unwrap();
    prefix[16..].copy_from_slice(&tag);
    result
}

#[test]
fn independent_byte_exact_vectors() {
    for (envelope, ad, length) in positive_cases() {
        assert_eq!(
            &envelope[..16],
            &(0..16).map(|i| 0xd3 - 3 * i).collect::<Vec<u8>>()
        );
        assert_eq!(
            decrypt(&key(), envelope, ad).unwrap().expose_secret(),
            plaintext(length)
        );
    }
    assert_eq!(EMPTY_AD, MULTIPLE_AD);
}

#[test]
fn empty_components_are_omitted_without_concatenating_or_sorting() {
    for ad in [AD, WITH_EMPTY_AD] {
        assert_eq!(
            decrypt(&key(), MULTIPLE_AD, ad).unwrap().expose_secret(),
            plaintext(48)
        );
    }
    assert_eq!(
        decrypt(&key(), NO_AD, &[b"", b""]).unwrap().expose_secret(),
        plaintext(32)
    );
    rejects(
        MULTIPLE_AD,
        &[&AD.concat()],
        PayloadError::AuthenticationFailed,
    );
    rejects(
        MULTIPLE_AD,
        &[AD[1], AD[0]],
        PayloadError::AuthenticationFailed,
    );
    rejects(MULTIPLE_AD, &[AD[0]], PayloadError::AuthenticationFailed);
    rejects(MULTIPLE_AD, &[], PayloadError::AuthenticationFailed);
}

#[test]
fn nonce_last_is_rejected_without_fallback() {
    assert_ne!(NONALIGNED, NONCE_LAST);
    rejects(NONCE_LAST, AD, PayloadError::AuthenticationFailed);
}

#[test]
fn every_nonce_tag_ciphertext_byte_and_bit_is_authenticated() {
    for (envelope, ad, _) in positive_cases() {
        for index in 0..envelope.len() {
            for bit in 0..8 {
                let mut changed = envelope.to_vec();
                changed[index] ^= 1 << bit;
                rejects(&changed, ad, PayloadError::AuthenticationFailed);
            }
        }
    }
}

#[test]
fn every_key_and_ad_byte_is_authenticated() {
    for index in 0..64 {
        let mut bytes = Zeroizing::new(*key().expose_secret());
        bytes[index] ^= 1;
        assert_eq!(
            decrypt(&UnwrappingKey::new(bytes), MULTIPLE_AD, AD).unwrap_err(),
            PayloadError::AuthenticationFailed
        );
    }
    for component in 0..AD.len() {
        for index in 0..AD[component].len() {
            let mut changed = AD[component].to_vec();
            changed[index] ^= 1;
            let mut ad = AD.to_vec();
            ad[component] = &changed;
            rejects(MULTIPLE_AD, &ad, PayloadError::AuthenticationFailed);
        }
    }
}

#[test]
fn every_short_prefix_is_rejected() {
    for (envelope, ad, _) in positive_cases() {
        for length in 0..envelope.len() {
            rejects(
                &envelope[..length],
                ad,
                if length < 32 {
                    PayloadError::InvalidEnvelopeLength
                } else {
                    PayloadError::AuthenticationFailed
                },
            );
        }
    }
}

#[test]
fn envelope_exact_minimum_maximum_and_over_limit() {
    assert_eq!(EMPTY_PLAINTEXT.len(), 32);
    assert!(
        decrypt(&key(), EMPTY_PLAINTEXT, AD)
            .unwrap()
            .expose_secret()
            .is_empty()
    );
    let mut envelope = policy_envelope(MIB - 32, &[]);
    assert_eq!(envelope.len(), MIB);
    assert_eq!(
        decrypt(&key(), &envelope, &[]).unwrap().expose_secret(),
        plaintext(MIB - 32)
    );
    envelope.push(0);
    rejects(&envelope, &[], PayloadError::InvalidEnvelopeLength);
}

#[test]
fn supplied_ad_count_includes_empty_components() {
    let nonempty = vec![b"x".as_slice(); 125];
    let envelope = policy_envelope(1, &nonempty);
    assert_eq!(
        decrypt(&key(), &envelope, &nonempty)
            .unwrap()
            .expose_secret(),
        plaintext(1)
    );
    let mut empty = vec![b"".as_slice(); 125];
    assert_eq!(
        decrypt(&key(), NO_AD, &empty).unwrap().expose_secret(),
        plaintext(32)
    );
    empty.push(b"");
    rejects(NO_AD, &empty, PayloadError::AssociatedDataLimitExceeded);
    let mut too_many = nonempty;
    too_many.push(b"x");
    rejects(
        &envelope,
        &too_many,
        PayloadError::AssociatedDataLimitExceeded,
    );
}

#[test]
fn each_ad_length_exact_and_over_limit() {
    let mut value = vec![0x42; KIB64];
    let envelope = policy_envelope(1, &[&value]);
    assert_eq!(
        decrypt(&key(), &envelope, &[&value])
            .unwrap()
            .expose_secret(),
        plaintext(1)
    );
    value.push(0);
    rejects(
        &envelope,
        &[&value],
        PayloadError::AssociatedDataLimitExceeded,
    );
}

#[test]
fn aggregate_ad_exact_and_over_limit_counts_repeated_slices() {
    let value = vec![0x73; KIB64];
    let mut ad = vec![value.as_slice(); 16];
    let envelope = policy_envelope(1, &ad);
    assert_eq!(
        decrypt(&key(), &envelope, &ad).unwrap().expose_secret(),
        plaintext(1)
    );
    ad.push(b"");
    assert!(decrypt(&key(), &envelope, &ad).is_ok());
    ad.push(b"x");
    rejects(&envelope, &ad, PayloadError::AssociatedDataLimitExceeded);
}

#[test]
fn all_ad_preflight_precedes_authentication() {
    let oversized = vec![0u8; KIB64 + 1];
    let mut ad = vec![b"".as_slice(); 124];
    ad.push(&oversized);
    // A valid length with a bad tag must not reach crypto before the final AD check.
    rejects(&[0; 32], &ad, PayloadError::AssociatedDataLimitExceeded);
}

#[test]
fn caller_inputs_remain_unchanged_on_success_and_failure() {
    let key = key();
    let key_before = Zeroizing::new(*key.expose_secret());
    let mut envelope = MULTIPLE_AD.to_vec();
    let ad: Vec<Vec<u8>> = AD.iter().map(|v| v.to_vec()).collect();
    let before_ad = ad.clone();
    for valid in [true, false] {
        if !valid {
            envelope[16] ^= 1;
        }
        let before = envelope.clone();
        let result = decrypt(
            &key,
            &envelope,
            &ad.iter().map(Vec::as_slice).collect::<Vec<_>>(),
        );
        assert_eq!(result.is_ok(), valid);
        assert_eq!(envelope, before);
        assert_eq!(ad, before_ad);
        assert_eq!(key.expose_secret(), &*key_before);
    }
}

#[test]
fn plaintext_key_and_errors_have_fixed_redacted_output() {
    let key = key();
    assert_eq!(format!("{key:?}"), "UnwrappingKey(<redacted>)");
    for (envelope, ad, _) in positive_cases() {
        let plaintext = decrypt(&key, envelope, ad).unwrap();
        assert_eq!(format!("{plaintext:?}"), "PayloadPlaintext(<redacted>)");
    }
    for (error, debug, display) in [
        (
            PayloadError::InvalidEnvelopeLength,
            "InvalidEnvelopeLength",
            "invalid CKKS payload envelope length",
        ),
        (
            PayloadError::AssociatedDataLimitExceeded,
            "AssociatedDataLimitExceeded",
            "CKKS payload associated data limit exceeded",
        ),
        (
            PayloadError::AuthenticationFailed,
            "AuthenticationFailed",
            "CKKS payload authentication failed",
        ),
    ] {
        assert_eq!(format!("{error:?}"), debug);
        assert_eq!(error.to_string(), display);
        assert!(std::error::Error::source(&error).is_none());
    }
}

#[test]
fn plaintext_owns_zeroizing_storage() {
    // Type-check the actual private owner, without reading deallocated memory.
    fn assert_zeroizing_owner(_: &Zeroizing<Vec<u8>>) {}
    let plaintext = decrypt(&key(), NONALIGNED, AD).unwrap();
    assert_zeroizing_owner(&plaintext.0);
    assert!(core::mem::needs_drop::<PayloadPlaintext>());
    assert!(core::mem::needs_drop::<UnwrappingKey>());
    drop(plaintext);
}
