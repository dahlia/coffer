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

//! Composition of Apple's SRP-6a variant over the `srp` crate.
//!
//! No SRP arithmetic is implemented here.  The [`srp`] crate provides the
//! group operations; this module only fixes the parameters Apple uses and
//! derives the password input.
//!
//! # Parameters
//!
//! - Group: the 2048-bit group of RFC 5054 with `g = 2`; hash: SHA-256.
//! - Password input `P'`: `PBKDF2-HMAC-SHA256(SHA-256(password), s, i)` with a
//!   32-byte output, where `s` and `i` come from the `init` response.  This
//!   is the `s2k` protocol.
//! - `x = H(s | H(":" | P'))`: the identity is *omitted* from `x`, which is
//!   the `srp` crate's `username_in_x = false` option documented as the
//!   Apple-compatible mode.
//! - `k = H(N | PAD(g))`, `u = H(PAD(A) | PAD(B))`, `K = H(S)`: the SRP-6a
//!   definitions with padding, matching corecrypto's `ccsrp` default
//!   (`CCSRP_OPTION_SRP6a_HASH`).
//! - `M1 = H((H(N) xor H(PAD(g))) | H(I) | s | A | B | K)` with `I` the
//!   account name, and `M2 = H(A | M1 | K)`, per RFC 2945.
//!
//! The padding of `u` is where implementations differ: corecrypto pads,
//! the `srp` crate pads, and SideStore's vendored fork does not.  The
//! difference shows only when `A` or `B` has a leading zero byte.  Coffer
//! follows corecrypto.  A captured vector with a leading-zero `B` would
//! settle the question conclusively and is on the maintainers' list.

use sha2::{Digest, Sha256};
use srp::{ClientG2048, ClientVerifier};
use zeroize::Zeroizing;

use super::error::{Malformed, MalformedReason};
use crate::entropy::{Entropy, EntropyError};
use crate::secret::{AccountName, Password, SESSION_KEY_LEN, wipe};

/// Length in bytes of the client's private ephemeral `a`.
pub(crate) const EPHEMERAL_LEN: usize = 32;

/// The 32-byte SRP password input derived from the user's password.
pub(crate) type PasswordKey = Zeroizing<[u8; 32]>;

/// The client's ephemeral key pair `(a, A)`.
pub(crate) struct ClientEphemeral {
    secret: Zeroizing<[u8; EPHEMERAL_LEN]>,
    public: Vec<u8>,
}

impl ClientEphemeral {
    /// Draws `a` from `entropy` and computes `A = g^a mod N`.
    pub(crate) fn generate<E: Entropy + ?Sized>(entropy: &E) -> Result<Self, EntropyError> {
        let mut secret = Zeroizing::new([0u8; EPHEMERAL_LEN]);
        entropy.fill(&mut secret[..])?;
        if secret.iter().all(|&b| b == 0) {
            return Err(EntropyError::new("entropy source returned all-zero bytes"));
        }
        let public =
            ClientG2048::<Sha256>::new_with_options(false).compute_public_ephemeral(&secret[..]);
        Ok(Self { secret, public })
    }

    /// Returns `A` as big-endian bytes without leading zeros.
    pub(crate) fn public(&self) -> &[u8] {
        &self.public
    }
}

/// Derives the `s2k` password input.
pub(crate) fn derive_password_key(
    password: &Password,
    salt: &[u8],
    iterations: u32,
) -> PasswordKey {
    let mut digest = Sha256::digest(password.as_bytes());
    let mut key = Zeroizing::new([0u8; 32]);
    pbkdf2::pbkdf2_hmac::<Sha256>(&digest, salt, iterations, &mut key[..]);
    wipe(digest.as_mut());
    key
}

/// The client's side of the exchange after processing the server's `B`.
///
/// Holds the `srp` crate's verifier, which contains `S` and `K`.  The crate
/// does not zeroize them itself, so this value is dropped as soon as the
/// session key has been copied out.
pub(crate) struct Proof {
    verifier: ClientVerifier<Sha256>,
}

impl Proof {
    /// Computes `M1` and the expected `M2` from the server's salt and `B`.
    ///
    /// Fails with a malformed-`B` error when `B mod N = 0`, which the `srp`
    /// crate rejects as a malicious parameter.
    pub(crate) fn compute(
        ephemeral: &ClientEphemeral,
        account: &AccountName,
        password_key: &PasswordKey,
        salt: &[u8],
        b_pub: &[u8],
    ) -> Result<Self, Malformed> {
        let client = ClientG2048::<Sha256>::new_with_options(false);
        let verifier = client
            .process_reply(
                &ephemeral.secret[..],
                account.as_str().as_bytes(),
                &password_key[..],
                salt,
                b_pub,
            )
            .map_err(|_| Malformed::new("B", MalformedReason::InvalidParameter))?;
        Ok(Self { verifier })
    }

    /// Returns the client proof `M1`.
    pub(crate) fn m1(&self) -> &[u8] {
        self.verifier.proof()
    }

    /// Checks the server proof and, on success, returns `K = H(S)`.
    ///
    /// The comparison is constant-time inside the `srp` crate.  On failure
    /// nothing is returned and the caller must not try again with the same
    /// exchange.
    pub(crate) fn verify_server(self, m2: &[u8]) -> Option<Zeroizing<[u8; SESSION_KEY_LEN]>> {
        let key = self.verifier.verify_server(m2).ok()?;
        let mut out = Zeroizing::new([0u8; SESSION_KEY_LEN]);
        if key.len() != SESSION_KEY_LEN {
            return None;
        }
        out.copy_from_slice(key);
        Some(out)
    }
}
