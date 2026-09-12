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

//! Bounded P-384 key encodings and ECDSA/SHA-384 verification.
//!
//! Only uncompressed SEC1 points and named-curve DER SPKI are accepted.
//! Apple's full private encoding is validated against the derived public point.
//! No signing, generation, I/O, fallback, or trust decision is exposed.

use core::fmt;
use p384::{
    ecdsa::{Signature, VerifyingKey, signature::hazmat::PrehashVerifier},
    elliptic_curve::sec1::ToEncodedPoint,
    pkcs8::{DecodePublicKey, EncodePublicKey},
};
use sha2::{Digest, Sha384};
use zeroize::Zeroizing;

/// Local resource policy for a single signed message, not an Apple wire limit.
pub const MAX_MESSAGE_LEN: usize = 1024 * 1024;

/// A validated P-384 public key; its account-identifying bytes are redacted.
///
/// Construction validates curve membership, not identity or account ownership.
/// Explicit byte exports must be kept out of logs and diagnostic output.
pub struct PublicKey {
    inner: p384::PublicKey,
    sec1: [u8; 97],
}

impl PublicKey {
    /// Parses exactly 97 bytes of uncompressed SEC1 (`04 || X || Y`).
    ///
    /// Borrows input only for this call. Returns [`KeyError::InvalidPublicKey`]
    /// for a wrong length/prefix, point at infinity, out-of-field coordinate,
    /// or point outside P-384. Compressed and hybrid encodings are rejected.
    pub fn from_sec1_bytes(bytes: &[u8]) -> Result<Self, KeyError> {
        let sec1: [u8; 97] = bytes.try_into().map_err(|_| KeyError::InvalidPublicKey)?;
        if sec1[0] != 4 {
            return Err(KeyError::InvalidPublicKey);
        }
        let inner =
            p384::PublicKey::from_sec1_bytes(&sec1).map_err(|_| KeyError::InvalidPublicKey)?;
        Ok(Self { inner, sec1 })
    }

    /// Parses one canonical 120-byte DER SubjectPublicKeyInfo (SPKI).
    ///
    /// Requires `id-ecPublicKey`, named curve `secp384r1`, and an uncompressed
    /// point. Returns [`KeyError::InvalidPublicKey`] on any structural, curve,
    /// or canonical-encoding error, including trailing bytes. The size is
    /// checked before ASN.1 parsing; input is never retained.
    pub fn from_spki_der(bytes: &[u8]) -> Result<Self, KeyError> {
        if bytes.len() != 120 {
            return Err(KeyError::InvalidPublicKey);
        }
        let inner =
            p384::PublicKey::from_public_key_der(bytes).map_err(|_| KeyError::InvalidPublicKey)?;
        let sec1 = inner
            .to_encoded_point(false)
            .as_bytes()
            .try_into()
            .map_err(|_| KeyError::InvalidPublicKey)?;
        let key = Self { inner, sec1 };
        if key.to_spki_der()?.as_slice() != bytes {
            return Err(KeyError::InvalidPublicKey);
        }
        Ok(key)
    }

    /// Explicitly exports an owned 97-byte uncompressed public point.
    ///
    /// The bytes can identify an account or peer; do not log them.
    #[must_use]
    pub fn to_sec1_bytes(&self) -> [u8; 97] {
        self.sec1
    }

    /// Explicitly exports canonical named-curve SPKI DER into owned storage.
    ///
    /// Output is 120 account-identifying bytes; do not log it. Returns
    /// [`KeyError::InvalidPublicKey`] if the underlying encoder fails.
    pub fn to_spki_der(&self) -> Result<Vec<u8>, KeyError> {
        self.inner
            .to_public_key_der()
            .map(|der| der.as_bytes().to_vec())
            .map_err(|_| KeyError::InvalidPublicKey)
    }

    /// Verifies an ECDSA/SHA-384 DER signature over the exact message bytes.
    ///
    /// Both high-S and low-S signatures are accepted. This establishes only
    /// mathematical validity under this key, not trust or account binding.
    /// No input is retained, and there is no retry or alternate algorithm.
    ///
    /// # Errors
    /// Returns [`KeyError::MessageTooLarge`] before hashing messages larger
    /// than [`MAX_MESSAGE_LEN`], [`KeyError::InvalidSignatureEncoding`] for
    /// noncanonical DER, lengths outside 8..=104, or zero/out-of-range r/s,
    /// and [`KeyError::VerificationFailed`] for a well-formed invalid signature.
    pub fn verify_sha384(&self, message: &[u8], der: &[u8]) -> Result<(), KeyError> {
        if message.len() > MAX_MESSAGE_LEN {
            return Err(KeyError::MessageTooLarge);
        }
        if !(8..=104).contains(&der.len()) {
            return Err(KeyError::InvalidSignatureEncoding);
        }
        let signature = Signature::from_der(der).map_err(|_| KeyError::InvalidSignatureEncoding)?;
        if signature.to_der().as_bytes() != der {
            return Err(KeyError::InvalidSignatureEncoding);
        }
        // Use the workspace SHA-384 with zeroization enabled. The prehash
        // interface receives exactly its 48-byte output, never a caller digest.
        let digest = Zeroizing::new(Sha384::digest(message));
        VerifyingKey::from(&self.inner)
            .verify_prehash(digest.as_slice(), &signature)
            .map_err(|_| KeyError::VerificationFailed)
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PublicKey(<redacted>)")
    }
}

/// An owned, validated Apple full private encoding with its matching public key.
///
/// The private bytes are zeroized on drop. There is no clone, signing, key
/// generation, or implicit serialization. Drop this value promptly after use.
/// Validation makes no claim about peer identity or trust.
pub struct PrivateKey {
    encoded: Zeroizing<[u8; 145]>,
    public: PublicKey,
}

impl PrivateKey {
    /// Consumes exactly 145 bytes of Apple's `04 || X || Y || D` encoding.
    ///
    /// Requires a P-384 point and a nonzero scalar below the group order, then
    /// derives the public point using RustCrypto and checks it matches X/Y.
    /// The supplied buffer is wiped on success and error; callers remain
    /// responsible for any copies they made before transferring ownership.
    /// The temporary RustCrypto secret key is also wiped when dropped.
    ///
    /// # Errors
    /// Returns [`KeyError::InvalidPrivateKey`] for invalid length, prefix,
    /// point, or scalar, and [`KeyError::PublicKeyMismatch`] when valid scalar
    /// and point disagree. No input bytes enter the error.
    pub fn from_apple_full(bytes: Zeroizing<Vec<u8>>) -> Result<Self, KeyError> {
        if bytes.len() != 145 {
            return Err(KeyError::InvalidPrivateKey);
        }
        let public =
            PublicKey::from_sec1_bytes(&bytes[..97]).map_err(|_| KeyError::InvalidPrivateKey)?;
        let scalar =
            p384::SecretKey::from_slice(&bytes[97..]).map_err(|_| KeyError::InvalidPrivateKey)?;
        // Own the derived scalar in a wiping wrapper as well; the convenience
        // SecretKey::public_key path creates this temporary internally.
        let nonzero = Zeroizing::new(scalar.to_nonzero_scalar());
        if p384::PublicKey::from_secret_scalar(&nonzero) != public.inner {
            return Err(KeyError::PublicKeyMismatch);
        }
        let mut encoded = Zeroizing::new([0u8; 145]);
        encoded.copy_from_slice(&bytes);
        Ok(Self { encoded, public })
    }

    /// Explicitly borrows the validated full private encoding for serialization.
    ///
    /// Never log or persist these bytes without suitable protection. Any copy
    /// made from this borrow needs its own zeroizing owner and short lifetime.
    #[must_use]
    pub fn expose_secret(&self) -> &[u8; 145] {
        &self.encoded
    }

    /// Borrows the public key whose point was checked against the private scalar.
    #[must_use]
    pub fn public_key(&self) -> &PublicKey {
        &self.public
    }
}

impl fmt::Debug for PrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PrivateKey(<redacted>)")
    }
}

/// Static, input-free errors from offline key handling.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyError {
    /// Invalid public point or public encoding.
    InvalidPublicKey,
    /// Invalid private length, scalar, or point.
    InvalidPrivateKey,
    /// The private scalar and encoded public point disagree.
    PublicKeyMismatch,
    /// Invalid DER or scalar range in a signature.
    InvalidSignatureEncoding,
    /// A well-formed signature failed verification.
    VerificationFailed,
    /// Message exceeds the local resource policy.
    MessageTooLarge,
}
impl fmt::Display for KeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidPublicKey => "invalid Octagon public key",
            Self::InvalidPrivateKey => "invalid Octagon private key",
            Self::PublicKeyMismatch => "Octagon private/public key mismatch",
            Self::InvalidSignatureEncoding => "invalid Octagon signature encoding",
            Self::VerificationFailed => "Octagon signature verification failed",
            Self::MessageTooLarge => "Octagon signed message too large",
        })
    }
}
impl std::error::Error for KeyError {}
