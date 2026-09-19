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

//! Bounded, borrowed bottle inspection and embedded-key signature consistency.
//!
//! This deliberately narrow protobuf subset preserves the exact signed bytes.
//! It performs no I/O, key derivation, decryption, recovery, or trust decision.
//! See `OCTAGON_BOTTLE.md` for field provenance and local acceptance policies.

use super::keys::{KeyError, MAX_MESSAGE_LEN, PublicKey};
use core::fmt;

/// A structurally checked bottle with four valid P-384 public-key encodings.
///
/// Identifiers, ciphertext, and unknown fields remain borrowed from the caller.
/// No field establishes account ownership, peer identity, freshness, or trust.
/// Ciphertext, tag, and IV are opaque, including when empty; parsing makes no
/// claim about their algorithm or cryptographic validity. Keep all input and
/// explicitly exposed bytes out of logs. The caller owns their storage lifetime.
///
/// The envelope cannot outlive the input:
/// ```compile_fail
/// use coffer_protocol::octagon::bottle::BottleEnvelope;
/// fn escape() -> BottleEnvelope<'static> {
///     let bytes = vec![0u8; 100];
///     BottleEnvelope::parse(&bytes).unwrap()
/// }
/// ```
/// It cannot be cloned:
/// ```compile_fail
/// use coffer_protocol::octagon::bottle::BottleEnvelope;
/// fn duplicate(value: BottleEnvelope<'_>) { let _ = value.clone(); }
/// ```
pub struct BottleEnvelope<'a> {
    raw: &'a [u8],
    peer_id: &'a str,
    bottle_id: &'a str,
    spki: [&'a [u8]; 4],
    keys: [PublicKey; 4],
    contents: &'a [u8],
    opaque: [&'a [u8]; 3],
}

impl<'a> BottleEnvelope<'a> {
    /// Inspects one raw, unframed Bottle without modifying or reserializing it.
    ///
    /// Local limits are 1..=1 MiB total, 64 field occurrences across the outer
    /// message and its contents, nonempty UTF-8 IDs of at most 1,024 bytes each,
    /// four 120-byte SPKIs, and tag/IV lengths of 0..=64 bytes. Ciphertext may
    /// be empty and shares the total byte limit. These are not Apple limits.
    /// All seven known outer fields and all three known contents fields must
    /// appear exactly once, with wire type 2. Unknown wire 0/1/2/5 fields may
    /// repeat and remain in the borrowed raw bytes; unknown LEN payloads are
    /// never interpreted. Only the known contents message is traversed.
    ///
    /// Field numbers must be 1..=536,870,911 and all varints minimal u64
    /// encodings. Groups, invalid wire types, and outer reserved fields 3..=7
    /// are rejected. This intentionally differs from general protobuf's
    /// duplicate-field merging and last-value behavior.
    ///
    /// All wire, count, presence, identifier, and length checks finish without
    /// allocation or cryptography before any key parser runs. The existing
    /// key parser then validates each SPKI, including curve and canonical DER.
    ///
    /// # Errors
    /// Returns the corresponding static [`BottleError`] for resource limits,
    /// malformed/unsupported wire, missing/duplicate fields, invalid IDs, or
    /// invalid keys. Errors retain no input, and no partial envelope is returned.
    pub fn parse(raw: &'a [u8]) -> Result<Self, BottleError> {
        if raw.is_empty() || raw.len() > MAX_MESSAGE_LEN {
            return Err(BottleError::SizeLimit);
        }
        let mut count = 0;
        let fields = scan(raw, [1, 2, 8, 9, 10, 11, 12], true, &mut count)?;
        let opaque = scan(fields[6], [1, 2, 3], false, &mut count)?;
        let peer_id = identifier(fields[0])?;
        let bottle_id = identifier(fields[1])?;
        let spki = [fields[2], fields[3], fields[4], fields[5]];
        if spki.iter().any(|bytes| bytes.len() != 120) {
            return Err(BottleError::InvalidKey);
        }
        if opaque[1].len() > 64 || opaque[2].len() > 64 {
            return Err(BottleError::SizeLimit);
        }
        let keys = [
            parse_key(spki[0])?,
            parse_key(spki[1])?,
            parse_key(spki[2])?,
            parse_key(spki[3])?,
        ];
        Ok(Self {
            raw,
            peer_id,
            bottle_id,
            spki,
            keys,
            contents: fields[6],
            opaque,
        })
    }

    /// Borrows the exact original Bottle, including every unknown field.
    ///
    /// These are the signature message bytes. Do not log identifying material.
    #[must_use]
    pub fn raw_bytes(&self) -> &'a [u8] {
        self.raw
    }

    /// Borrows the unnormalized peer identifier; it is not a verified identity.
    /// Do not log this potentially identifying value.
    #[must_use]
    pub fn peer_id(&self) -> &'a str {
        self.peer_id
    }

    /// Borrows the unnormalized bottle identifier, without proving viability.
    /// Do not log this potentially identifying value.
    #[must_use]
    pub fn bottle_id(&self) -> &'a str {
        self.bottle_id
    }

    /// Borrows the canonical escrow signing SPKI, without establishing trust.
    /// Explicit exposure can identify a peer/account; do not log it.
    #[must_use]
    pub fn escrow_signing_spki(&self) -> &'a [u8] {
        self.spki[0]
    }

    /// Borrows the canonical escrow encryption SPKI, without proving possession.
    /// Explicit exposure can identify a peer/account; do not log it.
    #[must_use]
    pub fn escrow_encryption_spki(&self) -> &'a [u8] {
        self.spki[1]
    }

    /// Borrows the canonical peer signing SPKI, without establishing identity.
    /// Explicit exposure can identify a peer/account; do not log it.
    #[must_use]
    pub fn peer_signing_spki(&self) -> &'a [u8] {
        self.spki[2]
    }

    /// Borrows the canonical peer encryption SPKI, without proving possession.
    /// Explicit exposure can identify a peer/account; do not log it.
    #[must_use]
    pub fn peer_encryption_spki(&self) -> &'a [u8] {
        self.spki[3]
    }

    /// Borrows the exact nested contents message, including unknown fields.
    /// This is opaque encrypted material, not decoded private keys; do not log it.
    #[must_use]
    pub fn contents_bytes(&self) -> &'a [u8] {
        self.contents
    }

    /// Borrows opaque ciphertext bytes, possibly empty; no AEAD check was made.
    /// Keep exposed bytes out of logs and diagnostics.
    #[must_use]
    pub fn ciphertext(&self) -> &'a [u8] {
        self.opaque[0]
    }

    /// Borrows opaque tag bytes, possibly empty; no algorithm/validity is implied.
    /// Keep exposed bytes out of logs and diagnostics.
    #[must_use]
    pub fn authentication_code(&self) -> &'a [u8] {
        self.opaque[1]
    }

    /// Borrows opaque IV bytes, possibly empty; no nonce format is implied.
    /// Keep exposed bytes out of logs and diagnostics.
    #[must_use]
    pub fn initialization_vector(&self) -> &'a [u8] {
        self.opaque[2]
    }

    /// Checks two detached DER ECDSA/SHA-384 signatures over the original bytes.
    ///
    /// Both lengths must be 8..=104 before any verification runs. The escrow
    /// signature is checked using field 8, then the peer signature using field
    /// 10, at most once each. The first failure ends the call without retries,
    /// alternate keys, or fallback. Signature slices are not retained.
    ///
    /// An attacker can replace the entire bottle, its keys, and both signatures
    /// and still pass. Success proves only consistency with the embedded keys;
    /// it establishes neither trust nor entropy/account/peer binding. It also
    /// says nothing about private keys, decryption, freshness, or recovery.
    ///
    /// # Errors
    /// Returns [`BottleError::InvalidSignatureEncoding`] for either length or
    /// the first malformed DER signature, or [`BottleError::SignatureMismatch`]
    /// for the first well-formed invalid signature. No partial success escapes.
    pub fn verify_embedded_signatures(
        &self,
        escrow_der: &[u8],
        peer_der: &[u8],
    ) -> Result<BottleSignatureConsistency<'_>, BottleError> {
        if !(8..=104).contains(&escrow_der.len()) || !(8..=104).contains(&peer_der.len()) {
            return Err(BottleError::InvalidSignatureEncoding);
        }
        verify_signature(&self.keys[0], self.raw, escrow_der)?;
        verify_signature(&self.keys[2], self.raw, peer_der)?;
        Ok(BottleSignatureConsistency { envelope: self })
    }
}

impl fmt::Debug for BottleEnvelope<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("BottleEnvelope(<redacted>)")
    }
}

/// Evidence that both signatures matched this envelope's embedded signing keys.
///
/// Created only by [`BottleEnvelope::verify_embedded_signatures`]. It borrows
/// the envelope and makes no trust, account, identity, or recovery claim.
/// Neither the envelope nor its backing bytes may be dropped while used here.
///
/// ```compile_fail
/// use coffer_protocol::octagon::bottle::{BottleEnvelope, BottleSignatureConsistency};
/// fn escape<'a>(bytes: &'a [u8], a: &[u8], b: &[u8]) -> BottleSignatureConsistency<'a> {
///     let envelope = BottleEnvelope::parse(bytes).unwrap();
///     envelope.verify_embedded_signatures(a, b).unwrap()
/// }
/// ```
/// ```compile_fail
/// use coffer_protocol::octagon::bottle::BottleSignatureConsistency;
/// fn duplicate(value: BottleSignatureConsistency<'_>) { let _ = value.clone(); }
/// ```
pub struct BottleSignatureConsistency<'a> {
    envelope: &'a BottleEnvelope<'a>,
}

impl<'a> BottleSignatureConsistency<'a> {
    /// Borrows the exact envelope whose two signatures were checked.
    /// Inspecting it still requires independent trust and account binding.
    #[must_use]
    pub fn envelope(&self) -> &'a BottleEnvelope<'a> {
        self.envelope
    }
}

impl fmt::Debug for BottleSignatureConsistency<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("BottleSignatureConsistency(<redacted>)")
    }
}

/// Fixed failures with no input, identifiers, or dependency error payloads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BottleError {
    /// A byte or field-count bound was exceeded, or the input was empty.
    SizeLimit,
    /// Invalid field number, wire type for a known field, varint, or truncation.
    MalformedWire,
    /// Groups, invalid wire types, or reserved outer field numbers.
    UnsupportedEncoding,
    /// A field required by the local inspection profile is absent.
    MissingField,
    /// A known singular field occurred more than once, even with the same value.
    DuplicateField,
    /// An identifier is empty or not UTF-8.
    InvalidIdentifier,
    /// A public key has the wrong length or is not canonical P-384 SPKI.
    InvalidKey,
    /// A signature has an invalid length or DER encoding.
    InvalidSignatureEncoding,
    /// A well-formed signature did not match the original bytes and its key.
    SignatureMismatch,
}
impl fmt::Display for BottleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::SizeLimit => "Octagon bottle resource limit",
            Self::MalformedWire => "malformed Octagon bottle wire data",
            Self::UnsupportedEncoding => "unsupported Octagon bottle encoding",
            Self::MissingField => "missing Octagon bottle field",
            Self::DuplicateField => "duplicate Octagon bottle field",
            Self::InvalidIdentifier => "invalid Octagon bottle identifier",
            Self::InvalidKey => "invalid Octagon bottle public key",
            Self::InvalidSignatureEncoding => "invalid Octagon bottle signature encoding",
            Self::SignatureMismatch => "Octagon bottle signature mismatch",
        })
    }
}
impl std::error::Error for BottleError {}

fn identifier(bytes: &[u8]) -> Result<&str, BottleError> {
    if bytes.len() > 1024 {
        return Err(BottleError::SizeLimit);
    }
    if bytes.is_empty() {
        return Err(BottleError::InvalidIdentifier);
    }
    core::str::from_utf8(bytes).map_err(|_| BottleError::InvalidIdentifier)
}

fn parse_key(bytes: &[u8]) -> Result<PublicKey, BottleError> {
    #[cfg(test)]
    KEY_PARSES.with(|count| count.set(count.get() + 1));
    PublicKey::from_spki_der(bytes).map_err(|_| BottleError::InvalidKey)
}

fn verify_signature(key: &PublicKey, message: &[u8], signature: &[u8]) -> Result<(), BottleError> {
    #[cfg(test)]
    SIGNATURE_CHECKS.with(|count| count.set(count.get() + 1));
    key.verify_sha384(message, signature)
        .map_err(|error| match error {
            KeyError::InvalidSignatureEncoding => BottleError::InvalidSignatureEncoding,
            _ => BottleError::SignatureMismatch,
        })
}

// This scanner only extracts bounded slices. It has no recursion, allocation,
// schema generator, or cryptographic operations. The caller explicitly scans
// the one known nested message after scanning the complete outer message.
fn scan<'a, const N: usize>(
    bytes: &'a [u8],
    known: [u64; N],
    outer: bool,
    count: &mut usize,
) -> Result<[&'a [u8]; N], BottleError> {
    let mut reader = Reader { remaining: bytes };
    let mut fields = [None; N];
    while !reader.remaining.is_empty() {
        if *count >= 64 {
            return Err(BottleError::SizeLimit);
        }
        *count += 1;
        let key = reader.varint()?;
        let number = key >> 3;
        if !(1..=536_870_911).contains(&number) {
            return Err(BottleError::MalformedWire);
        }
        if outer && (3..=7).contains(&number) {
            return Err(BottleError::UnsupportedEncoding);
        }
        let index = known.iter().position(|&n| n == number);
        if let Some(i) = index
            && fields[i].is_some()
        {
            return Err(BottleError::DuplicateField);
        }
        if !matches!(key & 7, 0 | 1 | 2 | 5) {
            return Err(BottleError::UnsupportedEncoding);
        }
        if index.is_some() && key & 7 != 2 {
            return Err(BottleError::MalformedWire);
        }
        match key & 7 {
            0 => {
                reader.varint()?;
            }
            1 => {
                reader.take(8)?;
            }
            2 => {
                let len =
                    usize::try_from(reader.varint()?).map_err(|_| BottleError::MalformedWire)?;
                let value = reader.take(len)?;
                if let Some(i) = index {
                    fields[i] = Some(value);
                }
            }
            5 => {
                reader.take(4)?;
            }
            _ => return Err(BottleError::UnsupportedEncoding),
        }
    }
    let mut required = [&[][..]; N];
    for (destination, field) in required.iter_mut().zip(fields) {
        *destination = field.ok_or(BottleError::MissingField)?;
    }
    Ok(required)
}

struct Reader<'a> {
    remaining: &'a [u8],
}
impl<'a> Reader<'a> {
    fn take(&mut self, length: usize) -> Result<&'a [u8], BottleError> {
        let (value, rest) = self
            .remaining
            .split_at_checked(length)
            .ok_or(BottleError::MalformedWire)?;
        self.remaining = rest;
        Ok(value)
    }
    fn varint(&mut self) -> Result<u64, BottleError> {
        let mut value = 0u64;
        for index in 0..10 {
            let byte = self.take(1)?[0];
            // The tenth byte has at most one payload bit and no continuation.
            if index == 9 && byte > 1 {
                return Err(BottleError::MalformedWire);
            }
            value |= u64::from(byte & 127) << (index * 7);
            if byte & 128 == 0 {
                if index > 0 && byte == 0 {
                    return Err(BottleError::MalformedWire);
                }
                return Ok(value);
            }
        }
        Err(BottleError::MalformedWire)
    }
}

#[cfg(test)]
std::thread_local! {
    static KEY_PARSES: core::cell::Cell<usize> = const { core::cell::Cell::new(0) };
    static SIGNATURE_CHECKS: core::cell::Cell<usize> = const { core::cell::Cell::new(0) };
}

#[cfg(test)]
mod tests {
    use super::*;
    const RAW: &[u8] = include_bytes!("../../tests/fixtures/octagon-bottle/original.bin");
    const ESCROW: &[u8] = include_bytes!("../../tests/fixtures/octagon-bottle/original-escrow.der");
    const PEER: &[u8] = include_bytes!("../../tests/fixtures/octagon-bottle/original-peer.der");

    #[test]
    fn preflight_precedes_every_key_parser() {
        KEY_PARSES.with(|count| count.set(0));
        let bad = [RAW, &[0][..]].concat();
        assert_eq!(
            BottleEnvelope::parse(&bad).unwrap_err(),
            BottleError::MalformedWire
        );
        assert_eq!(KEY_PARSES.with(|count| count.get()), 0);
        // Each length/presence check also precedes the first key parser.
        let oversized = vec![0; MAX_MESSAGE_LEN + 1];
        assert_eq!(
            BottleEnvelope::parse(&oversized).unwrap_err(),
            BottleError::SizeLimit
        );
        let mut count = 0;
        let original = scan(RAW, [1, 2, 8, 9, 10, 11, 12], true, &mut count).unwrap();
        for (number, replacement, expected) in [
            (1, vec![], BottleError::InvalidIdentifier),
            (2, vec![b'a'; 1025], BottleError::SizeLimit),
            (8, vec![0; 119], BottleError::InvalidKey),
            (12, vec![], BottleError::MissingField),
            (
                12,
                [vec![10, 0, 18, 65], vec![0; 65], vec![26, 0]].concat(),
                BottleError::SizeLimit,
            ),
            (
                12,
                [vec![10, 0, 18, 0, 26, 65], vec![0; 65]].concat(),
                BottleError::SizeLimit,
            ),
            (
                12,
                [vec![10, 0, 18, 0, 26, 0], [32, 0].repeat(55)].concat(),
                BottleError::SizeLimit,
            ),
        ] {
            let mut encoded = Vec::new();
            for (n, value) in [1u8, 2, 8, 9, 10, 11, 12].into_iter().zip(original) {
                let value = if n == number {
                    replacement.as_slice()
                } else {
                    value
                };
                encoded.push(n * 8 + 2);
                let mut len = value.len();
                while len > 127 {
                    encoded.push((len as u8 & 127) | 128);
                    len >>= 7;
                }
                encoded.push(len as u8);
                encoded.extend(value);
            }
            assert_eq!(BottleEnvelope::parse(&encoded).unwrap_err(), expected);
            assert_eq!(KEY_PARSES.with(|count| count.get()), 0);
        }
        BottleEnvelope::parse(RAW).unwrap();
        assert_eq!(KEY_PARSES.with(|count| count.get()), 4);
    }

    #[test]
    fn both_signature_lengths_precede_verification_and_first_failure_stops() {
        let envelope = BottleEnvelope::parse(RAW).unwrap();
        for (escrow, peer, expected) in [
            (ESCROW, &[0][..], 0),
            (&[0][..], PEER, 0),
            (PEER, ESCROW, 1),
            (&[0; 8][..], PEER, 1),
            (ESCROW, ESCROW, 2),
            (ESCROW, PEER, 2),
        ] {
            SIGNATURE_CHECKS.with(|count| count.set(0));
            let _ = envelope.verify_embedded_signatures(escrow, peer);
            assert_eq!(SIGNATURE_CHECKS.with(|count| count.get()), expected);
        }
    }
}
