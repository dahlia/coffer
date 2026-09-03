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

//! Source-policy checks for the narrowly patched vendored dependency.

const OPENSSL_CRYPTO: &str = include_str!("../vendor/oo7-0.6.0/src/crypto/openssl.rs");

#[test]
fn vendored_dh_intermediates_remain_zeroizing_and_preallocated() {
    let function = OPENSSL_CRYPTO
        .split_once("pub(crate) fn generate_aes_key")
        .expect("vendored function exists")
        .1
        .split_once("pub fn generate_iv")
        .expect("next function exists")
        .0;

    assert!(function.contains("let common_secret_bytes = Zeroizing::new("));
    assert!(function.contains("let mut ikm = Zeroizing::new(Vec::with_capacity(128))"));
    assert!(function.contains("ikm.resize(128 - common_secret_bytes.len(), 0)"));
    assert!(function.contains("ikm.extend_from_slice(&common_secret_bytes)"));
    assert!(!function.contains("common_secret_padded"));
    assert!(!function.contains("let mut common_secret_bytes ="));
}
