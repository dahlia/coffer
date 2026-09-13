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

//! Bounded canonical tagged encoding for local delegate material.

use crate::SessionSlot;
use crate::delegate::{
    DelegateBindingRef, DelegateStoreError as Error, LIMITS, MAX_STORED_DELEGATE_BYTES,
    StoredDelegateCredentials, validate,
};
use zeroize::Zeroizing;

const MAGIC: &[u8; 8] = b"COFFDLGT";
const VERSION: [u8; 2] = [0, 1];
const HEADER_LEN: usize = 26;

pub(crate) fn encode(
    slot: &SessionSlot,
    value: &StoredDelegateCredentials,
) -> Result<Zeroizing<Vec<u8>>, Error> {
    let mut size = HEADER_LEN;
    for (field, limit) in value.fields.iter().zip(LIMITS) {
        validate(field, limit)?;
        size += 3 + field.len();
    }
    if size > MAX_STORED_DELEGATE_BYTES {
        return Err(Error::TooLarge);
    }
    let mut bytes = Zeroizing::new(Vec::with_capacity(size));
    bytes.extend_from_slice(MAGIC);
    bytes.extend_from_slice(&VERSION);
    bytes.extend_from_slice(slot.as_bytes());
    for (tag, field) in (1u8..=5).zip(&value.fields) {
        let len = u16::try_from(field.len()).map_err(|_| Error::InvalidMaterial)?;
        bytes.push(tag);
        bytes.extend_from_slice(&len.to_be_bytes());
        bytes.extend_from_slice(field.as_bytes());
    }
    Ok(bytes)
}

pub(crate) fn decode(
    slot: &SessionSlot,
    expected: DelegateBindingRef<'_>,
    bytes: &[u8],
) -> Result<StoredDelegateCredentials, Error> {
    if bytes.len() > MAX_STORED_DELEGATE_BYTES {
        return Err(Error::TooLarge);
    }
    if bytes.len() < HEADER_LEN || bytes.get(..8) != Some(MAGIC) {
        return Err(Error::Corrupt);
    }
    if bytes[8..10] != VERSION {
        return Err(Error::UnsupportedVersion);
    }
    if bytes[10..HEADER_LEN] != *slot.as_bytes() {
        return Err(Error::BindingMismatch);
    }
    let mut remaining = &bytes[HEADER_LEN..];
    let mut fields = [""; 5];
    // Fixed ascending tags reject duplicate, unknown, missing, and reordered fields.
    // Validate every borrowed field and trailing bytes before any secret allocation.
    for ((tag, field), limit) in (1u8..=5).zip(&mut fields).zip(LIMITS) {
        let header = remaining.get(..3).ok_or(Error::Corrupt)?;
        if header[0] != tag {
            return Err(Error::Corrupt);
        }
        let len = usize::from(u16::from_be_bytes([header[1], header[2]]));
        if len == 0 || len > limit {
            return Err(Error::Corrupt);
        }
        let raw = remaining.get(3..3 + len).ok_or(Error::Corrupt)?;
        let text = std::str::from_utf8(raw).map_err(|_| Error::Corrupt)?;
        validate(text, limit).map_err(|_| Error::Corrupt)?;
        *field = text;
        remaining = &remaining[3 + len..];
    }
    if !remaining.is_empty() {
        return Err(Error::Corrupt);
    }
    if fields[0] != expected.adsid || fields[1] != expected.client_id {
        return Err(Error::BindingMismatch);
    }
    StoredDelegateCredentials::from_fields(fields)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    pub(crate) const SLOT: SessionSlot = SessionSlot::from_random_bytes([b'S'; 16]);
    pub(crate) const FIXTURE: &[u8] = include_bytes!("../tests/fixtures/delegate/v1.bin");
    pub(crate) fn binding() -> DelegateBindingRef<'static> {
        DelegateBindingRef::new("A", "C").unwrap()
    }
    pub(crate) fn material() -> StoredDelegateCredentials {
        StoredDelegateCredentials::from_fields(["A", "C", "D", "M", "K"]).unwrap()
    }
    #[test]
    fn delegate_synthetic_v1_decodes() {
        let decoded = decode(&SLOT, binding(), FIXTURE).unwrap();
        assert_eq!(decoded.expose_dsid(), "D");
        assert_eq!(decoded.expose_adsid(), "A");
        assert_eq!(decoded.expose_client_id(), "C");
        assert_eq!(decoded.expose_mme_auth_token(), "M");
        assert_eq!(decoded.expose_cloudkit_token(), "K");
        assert_eq!(&*encode(&SLOT, &decoded).unwrap(), FIXTURE);
    }
    #[test]
    fn rejects_every_truncation_duplicate_unknown_order_and_trailing() {
        for end in 0..FIXTURE.len() {
            assert!(decode(&SLOT, binding(), &FIXTURE[..end]).is_err());
        }
        for tag in [0, 1, 3, 255] {
            let mut bytes = FIXTURE.to_vec();
            bytes[30] = tag;
            assert_eq!(
                decode(&SLOT, binding(), &bytes).unwrap_err(),
                Error::Corrupt
            );
        }
        let mut trailing = FIXTURE.to_vec();
        trailing.extend_from_slice(&FIXTURE[26..30]);
        assert_eq!(
            decode(&SLOT, binding(), &trailing).unwrap_err(),
            Error::Corrupt
        );
        let mut unknown = FIXTURE.to_vec();
        unknown.extend_from_slice(b"\xff\x00\x01Z");
        assert_eq!(
            decode(&SLOT, binding(), &unknown).unwrap_err(),
            Error::Corrupt
        );
        let mut reordered = FIXTURE.to_vec();
        reordered[26..34].rotate_left(4);
        assert_eq!(
            decode(&SLOT, binding(), &reordered).unwrap_err(),
            Error::Corrupt
        );
    }
    #[test]
    fn rejects_wrong_magic_version_slot_and_both_account_bindings() {
        let mut bytes = FIXTURE.to_vec();
        bytes[..8].copy_from_slice(b"COFFSESS");
        assert_eq!(
            decode(&SLOT, binding(), &bytes).unwrap_err(),
            Error::Corrupt
        );
        let mut bytes = FIXTURE.to_vec();
        bytes[9] = 2;
        assert_eq!(
            decode(&SLOT, binding(), &bytes).unwrap_err(),
            Error::UnsupportedVersion
        );
        let other = SessionSlot::from_random_bytes([0; 16]);
        assert_eq!(
            decode(&other, binding(), FIXTURE).unwrap_err(),
            Error::BindingMismatch
        );
        for expected in [
            DelegateBindingRef::new("B", "C").unwrap(),
            DelegateBindingRef::new("A", "E").unwrap(),
        ] {
            assert_eq!(
                decode(&SLOT, expected, FIXTURE).unwrap_err(),
                Error::BindingMismatch
            );
        }
        assert!(crate::codec::decode(&SLOT, FIXTURE).is_err());
        let gsa = crate::codec::encode(&SLOT, &crate::codec::tests::session()).unwrap();
        assert_eq!(decode(&SLOT, binding(), &gsa).unwrap_err(), Error::Corrupt);
    }
    #[test]
    fn rejects_oversized_malformed_and_empty_fields() {
        assert_eq!(
            decode(&SLOT, binding(), &vec![0; MAX_STORED_DELEGATE_BYTES + 1]).unwrap_err(),
            Error::TooLarge
        );
        for offset in [26, 30, 34, 38, 42] {
            for len in [0u16, 65535] {
                let mut bytes = FIXTURE.to_vec();
                bytes[offset + 1..offset + 3].copy_from_slice(&len.to_be_bytes());
                assert_eq!(
                    decode(&SLOT, binding(), &bytes).unwrap_err(),
                    Error::Corrupt
                );
            }
            for byte in [0, 10, 31, 127, 255] {
                let mut bytes = FIXTURE.to_vec();
                bytes[offset + 3] = byte;
                assert_eq!(
                    decode(&SLOT, binding(), &bytes).unwrap_err(),
                    Error::Corrupt
                );
            }
        }
    }
    #[test]
    fn fully_present_fields_over_their_specific_limits_are_rejected() {
        for (index, limit) in LIMITS.into_iter().enumerate() {
            let mut bytes = FIXTURE[..26].to_vec();
            for tag in 1u8..=5 {
                let len = if usize::from(tag - 1) == index {
                    limit + 1
                } else {
                    1
                };
                bytes.push(tag);
                bytes.extend_from_slice(&u16::try_from(len).unwrap().to_be_bytes());
                bytes.extend(std::iter::repeat_n(b'X', len));
            }
            assert_eq!(
                decode(&SLOT, binding(), &bytes).unwrap_err(),
                Error::Corrupt
            );
        }
        for value in ["", "line\nbreak", "nonascii-é"] {
            assert_eq!(
                DelegateBindingRef::new(value, "C").unwrap_err(),
                Error::InvalidMaterial
            );
            assert_eq!(
                DelegateBindingRef::new("A", value).unwrap_err(),
                Error::InvalidMaterial
            );
        }
        assert_eq!(
            DelegateBindingRef::new(&"X".repeat(1025), "C").unwrap_err(),
            Error::InvalidMaterial
        );
        assert_eq!(
            DelegateBindingRef::new("A", &"X".repeat(257)).unwrap_err(),
            Error::InvalidMaterial
        );
    }

    #[test]
    fn field_limits_are_exact_and_preserve_spaces_and_leading_zeroes() {
        let fields = LIMITS.map(|len| "X".repeat(len));
        let refs = fields.each_ref().map(String::as_str);
        let value = StoredDelegateCredentials::from_fields(refs).unwrap();
        let expected = DelegateBindingRef::new(refs[0], refs[1]).unwrap();
        let bytes = encode(&SLOT, &value).unwrap();
        assert!(decode(&SLOT, expected, &bytes).is_ok());
        for i in 0..5 {
            let too_long = "X".repeat(LIMITS[i] + 1);
            let mut invalid = refs;
            invalid[i] = &too_long;
            assert_eq!(
                StoredDelegateCredentials::from_fields(invalid).unwrap_err(),
                Error::InvalidMaterial
            );
        }
        let value =
            StoredDelegateCredentials::from_fields([" A ", " C ", " 001 ", " M ", " K "]).unwrap();
        let expected = DelegateBindingRef::new(" A ", " C ").unwrap();
        let decoded = decode(&SLOT, expected, &encode(&SLOT, &value).unwrap()).unwrap();
        assert_eq!(decoded.expose_dsid(), " 001 ");
    }
}
