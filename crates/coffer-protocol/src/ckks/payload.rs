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

//! One bounded offline CKKS payload operation, using an already selected key.
//!
//! The caller supplies ordered, serialized associated-data values. This module
//! does not sort metadata, parse records/plaintext, obtain keys, or perform I/O.
//! Successful authentication does not establish account/record/key binding,
//! freshness or trust. See `tests/fixtures/ckks-payload/README.md` for the
//! independent synthetic vectors and the limited composition evidence.

use super::UnwrappingKey;
use aes_siv::{KeyInit, Tag, siv::Aes256Siv};
use core::fmt;
use zeroize::Zeroizing;

const MAX_ENVELOPE_BYTES: usize = 1024 * 1024;
const MAX_AD_COMPONENTS: usize = 125;
const MAX_AD_COMPONENT_BYTES: usize = 64 * 1024;
const MAX_AD_BYTES: usize = 1024 * 1024;

/// Authenticated opaque payload bytes owned in zeroizing storage.
///
/// Created only by successful [`decrypt`]. This is not a parsed credential or
/// a claim of trusted metadata. No cloning, serialization or owned raw-byte
/// escape is provided. Drop promptly after the caller's explicit offline use.
/// The owner wipes its buffer on drop, but cannot guarantee erasure of every
/// compiler-generated copy or temporary inside external cryptographic code.
///
/// The secret owner cannot be cloned:
///
/// ```compile_fail
/// use coffer_protocol::ckks::payload::PayloadPlaintext;
/// fn duplicate(value: PayloadPlaintext) { let _ = value.clone(); }
/// ```
pub struct PayloadPlaintext(Zeroizing<Vec<u8>>);
impl PayloadPlaintext {
    /// Explicitly borrows plaintext for the caller's next offline operation.
    /// Never log or persist these bytes without appropriate protection. The
    /// borrow cannot outlive this owner; the bytes may be empty or non-text.
    #[must_use]
    pub fn expose_secret(&self) -> &[u8] {
        &self.0
    }
}
impl fmt::Debug for PayloadPlaintext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PayloadPlaintext(<redacted>)")
    }
}
/// Fixed, secret-free failures for one offline payload operation.
/// No variant carries input data, a dynamic message or partial plaintext.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PayloadError {
    /// Envelope is outside 32 bytes through 1 MiB; no crypto was attempted.
    InvalidEnvelopeLength,
    /// AD count, individual length or aggregate exceeds local policy.
    /// No crypto was attempted, even if only the last component exceeded it.
    AssociatedDataLimitExceeded,
    /// The key, nonce, AD, tag or ciphertext did not authenticate.
    /// No plaintext is returned and the private working buffer is wiped.
    AuthenticationFailed,
}
impl fmt::Display for PayloadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidEnvelopeLength => "invalid CKKS payload envelope length",
            Self::AssociatedDataLimitExceeded => "CKKS payload associated data limit exceeded",
            Self::AuthenticationFailed => "CKKS payload authentication failed",
        })
    }
}
impl std::error::Error for PayloadError {}
/// Authenticates and decrypts one nonce/tag/ciphertext envelope offline.
///
/// Borrows an already selected 64-byte key, a 16-byte nonce followed by a
/// 16-byte tag and ciphertext, and already serialized AD in caller order.
/// There is exactly one attempt, without alternate keys, ordering or retries.
/// The caller retains responsibility for key/account/record binding and for
/// metadata selection, sorting and serialization. Success authenticates only
/// this composition of bytes, not omitted metadata or the meaning of plaintext.
///
/// Before any input copying, allocation or cryptography, local policy requires
/// an envelope of 32 bytes through 1 MiB, at most 125 supplied AD components
/// (including empty ones), each at most 64 KiB, and at most 1 MiB aggregate AD.
/// These bounds are Coffer policies, not claimed Apple limits. The nonce is
/// always the first SIV component, followed by each nonempty AD component in
/// order. Empty AD is omitted, with no concatenation or normalization.
/// The fixed nonempty nonce also permits empty plaintext without entering the
/// unsupported all-inputs-absent case.
///
/// Inputs remain unchanged and caller-owned. Plaintext is returned only after
/// authentication in a redacted, zeroizing owner; all failure exits drop the
/// private zeroizing working buffer. AES/SIV/CMAC use the existing enabled
/// zeroization features, subject to the limits documented on [`PayloadPlaintext`].
///
/// # Errors
/// Returns [`PayloadError::InvalidEnvelopeLength`] or
/// [`PayloadError::AssociatedDataLimitExceeded`] during preflight, otherwise
/// [`PayloadError::AuthenticationFailed`] on authentication failure.
pub fn decrypt(
    key: &UnwrappingKey,
    envelope: &[u8],
    associated_data: &[&[u8]],
) -> Result<PayloadPlaintext, PayloadError> {
    if !(32..=MAX_ENVELOPE_BYTES).contains(&envelope.len()) {
        return Err(PayloadError::InvalidEnvelopeLength);
    }
    if associated_data.len() > MAX_AD_COMPONENTS {
        return Err(PayloadError::AssociatedDataLimitExceeded);
    }
    let mut total = 0usize;
    for component in associated_data {
        if component.len() > MAX_AD_COMPONENT_BYTES {
            return Err(PayloadError::AssociatedDataLimitExceeded);
        }
        total = total
            .checked_add(component.len())
            .ok_or(PayloadError::AssociatedDataLimitExceeded)?;
        if total > MAX_AD_BYTES {
            return Err(PayloadError::AssociatedDataLimitExceeded);
        }
    }

    let nonce = &envelope[..16];
    let tag = Tag::try_from(&envelope[16..32]).map_err(|_| PayloadError::InvalidEnvelopeLength)?;
    // Only ciphertext is copied, after every preflight check. Decryption is
    // in place: this allocation never grows or leaves plaintext in an old Vec.
    let mut working = Zeroizing::new(envelope[32..].to_vec());
    let headers = core::iter::once(nonce).chain(
        associated_data
            .iter()
            .copied()
            .filter(|value| !value.is_empty()),
    );
    #[cfg(test)]
    CRYPTO_CALLS.with(|n| n.set(n.get() + 1));
    let mut cipher = Aes256Siv::new(key.expose_secret().into());
    // aes-siv 0.8.0 re-encrypts the output on a tag mismatch, but an S2V
    // header-overflow error can return earlier. Preflight caps nonce + AD at
    // 126 headers; the Zeroizing owner nevertheless covers every error exit.
    cipher
        .decrypt_inout_detached(headers, working.as_mut_slice().into(), &tag)
        .map_err(|_| PayloadError::AuthenticationFailed)?;
    Ok(PayloadPlaintext(working))
}
#[cfg(test)]
std::thread_local! { static CRYPTO_CALLS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) }; }
#[cfg(test)]
mod tests;
