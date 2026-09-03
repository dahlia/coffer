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

//! Bounded, versioned serialization for a reusable authentication session.

use std::io::{self, Cursor, Write};

use core::fmt;

use serde::de::{self, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use serde_bytes::Bytes;
use zeroize::Zeroizing;

use crate::store::{
    MAX_STORED_SESSION_BYTES, ReusableSession, SESSION_SLOT_LEN, SessionSlot, StoreError,
};

const MAGIC: &[u8; 8] = b"COFFSESS";
const VERSION: u16 = 1;
const HEADER_LEN: usize = MAGIC.len() + size_of::<u16>() + size_of::<u32>();
const MAX_STRING_BYTES: usize = 1_024;
const MAX_COOKIE_BYTES: usize = 4_096;
const CBOR_SCRATCH_BYTES: usize = MAX_COOKIE_BYTES;
const MAX_BODY_BYTES: usize = MAX_STORED_SESSION_BYTES - HEADER_LEN;

struct BoundedWriter<'a>(&'a mut Vec<u8>);

impl Write for BoundedWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > self.0.capacity() - self.0.len() {
            return Err(io::Error::other("session envelope capacity exceeded"));
        }
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[derive(Serialize)]
struct BodyRef<'a> {
    slot: &'a Bytes,
    account_id: &'a str,
    idms_token: &'a str,
    session_key: &'a Bytes,
    cookie: &'a Bytes,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Body {
    slot: DecodedBytes,
    account_id: DecodedString,
    idms_token: DecodedString,
    session_key: DecodedBytes,
    cookie: DecodedBytes,
}

struct DecodedString(Zeroizing<String>);

impl<'de> Deserialize<'de> for DecodedString {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct StringVisitor;

        impl Visitor<'_> for StringVisitor {
            type Value = DecodedString;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a bounded text string")
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(DecodedString(Zeroizing::new(value.to_owned())))
            }
        }

        // `deserialize_str` makes ciborium use the caller-owned scratch
        // buffer.  It therefore rejects oversized/indefinite text before
        // allocating an ordinary intermediate `String`.
        deserializer.deserialize_str(StringVisitor)
    }
}

struct DecodedBytes(Zeroizing<Vec<u8>>);

impl<'de> Deserialize<'de> for DecodedBytes {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct BytesVisitor;

        impl Visitor<'_> for BytesVisitor {
            type Value = DecodedBytes;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a bounded definite-length byte string")
            }

            fn visit_bytes<E>(self, value: &[u8]) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(DecodedBytes(Zeroizing::new(value.to_vec())))
            }
        }

        // `deserialize_bytes` avoids ciborium's ordinary `Vec<u8>`
        // intermediate.  Values are first read into the zeroizing scratch
        // buffer and copied directly into their zeroizing owner.
        deserializer.deserialize_bytes(BytesVisitor)
    }
}

pub(crate) fn encode(
    slot: &SessionSlot,
    session: &ReusableSession,
) -> Result<Zeroizing<Vec<u8>>, StoreError> {
    validate_session(session)?;
    let body = BodyRef {
        slot: Bytes::new(slot.as_bytes()),
        account_id: session.expose_account_id(),
        idms_token: session.expose_idms_token(),
        session_key: Bytes::new(session.expose_session_key()),
        cookie: Bytes::new(session.expose_cookie()),
    };
    // The writer refuses to exceed this one allocation.  This prevents Vec
    // growth from releasing an earlier allocation containing plaintext.
    let mut encoded_body = Zeroizing::new(Vec::with_capacity(MAX_BODY_BYTES));
    ciborium::ser::into_writer(&body, BoundedWriter(&mut encoded_body))
        .map_err(|_| StoreError::EncodingFailed)?;
    let body_len = u32::try_from(encoded_body.len()).map_err(|_| StoreError::EncodingFailed)?;
    let total_len = HEADER_LEN
        .checked_add(encoded_body.len())
        .ok_or(StoreError::EncodingFailed)?;
    if total_len > MAX_STORED_SESSION_BYTES {
        return Err(StoreError::TooLarge);
    }

    let mut envelope = Zeroizing::new(Vec::with_capacity(total_len));
    envelope.extend_from_slice(MAGIC);
    envelope.extend_from_slice(&VERSION.to_be_bytes());
    envelope.extend_from_slice(&body_len.to_be_bytes());
    envelope.extend_from_slice(&encoded_body);
    Ok(envelope)
}

pub(crate) fn validate_session(session: &ReusableSession) -> Result<(), StoreError> {
    if session.expose_account_id().is_empty()
        || session.expose_account_id().len() > MAX_STRING_BYTES
        || session.expose_idms_token().is_empty()
        || session.expose_idms_token().len() > MAX_STRING_BYTES
        || session.expose_cookie().is_empty()
        || session.expose_cookie().len() > MAX_COOKIE_BYTES
    {
        return Err(StoreError::EncodingFailed);
    }
    Ok(())
}

pub(crate) fn decode(
    expected_slot: &SessionSlot,
    envelope: &[u8],
) -> Result<ReusableSession, StoreError> {
    if envelope.len() > MAX_STORED_SESSION_BYTES {
        return Err(StoreError::TooLarge);
    }
    if envelope.len() < HEADER_LEN || envelope.get(..MAGIC.len()) != Some(MAGIC) {
        return Err(StoreError::Corrupt);
    }

    let version = u16::from_be_bytes(
        envelope[MAGIC.len()..MAGIC.len() + 2]
            .try_into()
            .map_err(|_| StoreError::Corrupt)?,
    );
    if version != VERSION {
        return Err(StoreError::UnsupportedVersion(version));
    }
    let body_len = u32::from_be_bytes(
        envelope[MAGIC.len() + 2..HEADER_LEN]
            .try_into()
            .map_err(|_| StoreError::Corrupt)?,
    );
    let body_len = usize::try_from(body_len).map_err(|_| StoreError::Corrupt)?;
    if body_len != envelope.len() - HEADER_LEN {
        return Err(StoreError::Corrupt);
    }

    let body_bytes = &envelope[HEADER_LEN..];
    let mut reader = Cursor::new(body_bytes);
    let mut scratch = Zeroizing::new([0; CBOR_SCRATCH_BYTES]);
    let body: Body = ciborium::de::from_reader_with_buffer(&mut reader, &mut *scratch)
        .map_err(|_| StoreError::Corrupt)?;
    if usize::try_from(reader.position()).ok() != Some(body_bytes.len()) {
        return Err(StoreError::Corrupt);
    }
    validate_body(expected_slot, &body)?;

    let mut session_key = Zeroizing::new([0; 32]);
    session_key.copy_from_slice(&body.session_key.0);
    Ok(ReusableSession::from_decoded(
        body.account_id.0,
        body.idms_token.0,
        session_key,
        body.cookie.0,
    ))
}

fn validate_body(expected_slot: &SessionSlot, body: &Body) -> Result<(), StoreError> {
    if body.slot.0.as_slice() != expected_slot.as_bytes()
        || body.slot.0.len() != SESSION_SLOT_LEN
        || body.account_id.0.is_empty()
        || body.account_id.0.len() > MAX_STRING_BYTES
        || body.idms_token.0.is_empty()
        || body.idms_token.0.len() > MAX_STRING_BYTES
        || body.session_key.0.len() != 32
        || body.cookie.0.is_empty()
        || body.cookie.0.len() > MAX_COOKIE_BYTES
    {
        return Err(StoreError::Corrupt);
    }
    Ok(())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) const SLOT: SessionSlot = SessionSlot::from_random_bytes([0x5a; 16]);

    pub(crate) fn session() -> ReusableSession {
        ReusableSession::from_decoded(
            Zeroizing::new("synthetic-account-id".to_owned()),
            Zeroizing::new("synthetic-idms-token".to_owned()),
            Zeroizing::new([0x42; 32]),
            Zeroizing::new(b"synthetic-cookie".to_vec()),
        )
    }

    #[test]
    fn envelope_round_trips_and_is_byte_exact() {
        let encoded = encode(&SLOT, &session()).expect("encode");
        let expected = [
            "434f46465345535300010000009da564736c6f74505a5a5a5a5a5a5a5a5a5a5a5a5a5a5a",
            "5a6a6163636f756e745f69647473796e7468657469632d6163636f756e742d69646a6964",
            "6d735f746f6b656e7473796e7468657469632d69646d732d746f6b656e6b73657373696f",
            "6e5f6b657958204242424242424242424242424242424242424242424242424242424242",
            "42424266636f6f6b69655073796e7468657469632d636f6f6b6965",
        ]
        .concat();
        assert_eq!(hex(&encoded), expected);

        let decoded = decode(&SLOT, &encoded).expect("decode");
        assert_eq!(decoded.expose_account_id(), "synthetic-account-id");
        assert_eq!(decoded.expose_idms_token(), "synthetic-idms-token");
        assert_eq!(decoded.expose_session_key(), &[0x42; 32]);
        assert_eq!(decoded.expose_cookie(), b"synthetic-cookie");
    }

    #[test]
    fn corrupt_truncated_trailing_and_wrong_slot_envelopes_fail_closed() {
        assert_eq!(decode(&SLOT, b"").expect_err("empty"), StoreError::Corrupt);
        let encoded = encode(&SLOT, &session()).expect("encode");
        for end in 0..encoded.len() {
            assert_eq!(
                decode(&SLOT, &encoded[..end]).expect_err("truncated"),
                StoreError::Corrupt
            );
        }
        let mut trailing = encoded.to_vec();
        trailing.push(0);
        assert_eq!(
            decode(&SLOT, &trailing).expect_err("trailing"),
            StoreError::Corrupt
        );
        let other = SessionSlot::from_random_bytes([0xa5; 16]);
        assert_eq!(
            decode(&other, &encoded).expect_err("wrong slot"),
            StoreError::Corrupt
        );
    }

    #[test]
    fn oversized_and_unsupported_envelopes_are_distinct() {
        assert_eq!(
            decode(&SLOT, &vec![0; MAX_STORED_SESSION_BYTES + 1]).expect_err("oversized"),
            StoreError::TooLarge
        );
        let mut encoded = encode(&SLOT, &session()).expect("encode").to_vec();
        encoded[MAGIC.len()..MAGIC.len() + 2].copy_from_slice(&7u16.to_be_bytes());
        assert_eq!(
            decode(&SLOT, &encoded).expect_err("unsupported version"),
            StoreError::UnsupportedVersion(7)
        );
    }

    #[test]
    fn duplicate_and_unknown_fields_are_corrupt() {
        // A CBOR map with two `slot` fields.  Serde's struct visitor rejects
        // the duplicate before a value can be selected implicitly.
        let duplicate_body = hex_bytes(
            "a264736c6f74505a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a64736c6f74505a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a",
        );
        assert_eq!(
            decode(&SLOT, &wrap_body(&duplicate_body)).expect_err("duplicate field"),
            StoreError::Corrupt
        );

        let unknown_body = hex_bytes("a167756e6b6e6f776e01");
        assert_eq!(
            decode(&SLOT, &wrap_body(&unknown_body)).expect_err("unknown field"),
            StoreError::Corrupt
        );
    }

    #[test]
    fn debug_and_errors_reveal_no_session_values() {
        let session = session();
        assert_eq!(format!("{session:?}"), "ReusableSession(<redacted>)");
        assert_eq!(format!("{SLOT:?}"), "SessionSlot(<redacted>)");
        for error in [
            StoreError::Corrupt,
            StoreError::TooLarge,
            StoreError::UnsupportedVersion(2),
            StoreError::BackendFailure(crate::BackendOperation::Read),
        ] {
            let rendered = format!("{error:?} {error}");
            assert!(!rendered.contains(session.expose_account_id()));
            assert!(!rendered.contains(session.expose_idms_token()));
            assert!(!rendered.contains("synthetic-cookie"));
        }
    }

    fn wrap_body(body: &[u8]) -> Vec<u8> {
        let mut envelope = Vec::new();
        envelope.extend_from_slice(MAGIC);
        envelope.extend_from_slice(&VERSION.to_be_bytes());
        envelope.extend_from_slice(&u32::try_from(body.len()).expect("small body").to_be_bytes());
        envelope.extend_from_slice(body);
        envelope
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    fn hex_bytes(value: &str) -> Vec<u8> {
        value
            .as_bytes()
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| {
                let text = std::str::from_utf8(pair).expect("ASCII hex");
                u8::from_str_radix(text, 16).expect("valid hex")
            })
            .collect()
    }
}
