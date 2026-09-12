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

//! Independent synthetic OpenSSL vectors for the offline wrapped-key primitive.
use coffer_protocol::ckks::{UnwrapError, UnwrappingKey};
use zeroize::Zeroizing;

fn fixture(name: &str) -> Vec<u8> {
    let hex = match name {
        "child" => include_str!("fixtures/ckks-wrap/child.hex"),
        "grandchild" => include_str!("fixtures/ckks-wrap/grandchild.hex"),
        "self" => include_str!("fixtures/ckks-wrap/self.hex"),
        "with-ad" => include_str!("fixtures/ckks-wrap/with-ad.hex"),
        _ => panic!("unknown synthetic fixture"),
    }
    .trim();
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect()
}
fn key(start: u8) -> UnwrappingKey {
    UnwrappingKey::new(Zeroizing::new(core::array::from_fn(|i| {
        start + u8::try_from(i).unwrap()
    })))
}

#[test]
fn independent_vectors_unwrap_child_and_grandchild() {
    let parent = key(0);
    let child = parent.unwrap_key(&fixture("child")).unwrap();
    assert_eq!(child.expose_secret(), key(64).expose_secret());
    let grandchild = child.unwrap_key(&fixture("grandchild")).unwrap();
    assert_eq!(grandchild.expose_secret(), key(128).expose_secret());
    // Explicit parent selection is required: no traversal or fallback is hidden.
    assert_eq!(
        parent.unwrap_key(&fixture("grandchild")).unwrap_err(),
        UnwrapError::AuthenticationFailed
    );
}

#[test]
fn self_wrap_requires_the_existing_key() {
    let parent = key(0);
    let child = parent.unwrap_key(&fixture("self")).unwrap();
    assert_eq!(child.expose_secret(), parent.expose_secret());
    assert_eq!(
        key(1).unwrap_key(&fixture("self")).unwrap_err(),
        UnwrapError::AuthenticationFailed
    );
}

#[test]
fn malformed_lengths_fail_without_touching_input() {
    let parent = key(0);
    let good = fixture("child");
    for len in 0..80 {
        assert_eq!(
            parent.unwrap_key(&good[..len]).unwrap_err(),
            UnwrapError::InvalidLength
        );
    }
    for len in [81, 96, 1024 * 1024] {
        assert_eq!(
            parent.unwrap_key(&vec![0; len]).unwrap_err(),
            UnwrapError::InvalidLength
        );
    }
}

#[test]
fn every_tag_or_ciphertext_byte_is_authenticated() {
    let parent = key(0);
    let good = fixture("child");
    for index in 0..80 {
        let mut altered = good.clone();
        altered[index] ^= 1;
        let before = altered.clone();
        assert_eq!(
            parent.unwrap_key(&altered).unwrap_err(),
            UnwrapError::AuthenticationFailed
        );
        assert_eq!(altered, before);
    }
    assert_eq!(
        key(1).unwrap_key(&good).unwrap_err(),
        UnwrapError::AuthenticationFailed
    );
    assert_eq!(
        parent.unwrap_key(&fixture("with-ad")).unwrap_err(),
        UnwrapError::AuthenticationFailed
    );
    // A failed operation neither poisons the key nor mutates caller ciphertext.
    assert!(parent.unwrap_key(&good).is_ok());
    assert_eq!(good, fixture("child"));
}

#[test]
fn keys_and_errors_do_not_disclose_inputs() {
    let secret = UnwrappingKey::new(Zeroizing::new([b'Z'; 64]));
    assert_eq!(format!("{secret:?}"), "UnwrappingKey(<redacted>)");
    let error = secret.unwrap_key(&[b'Z'; 80]).unwrap_err();
    assert_eq!(format!("{error:?}"), "AuthenticationFailed");
    assert_eq!(error.to_string(), "CKKS wrapped-key authentication failed");
}

#[test]
fn cipher_and_mac_owners_enable_zeroization() {
    fn on_drop<T: zeroize::ZeroizeOnDrop>() {}
    on_drop::<aes::Aes256>();
    on_drop::<aes_siv::siv::Aes256Siv>();
    // Cmac delegates ownership to this core and its zeroizing block buffer.
    on_drop::<cmac::block_api::CmacCore<aes::Aes256>>();
}
