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

//! Bounded offline construction of known CKKS v2 item associated data.
//!
//! This module accepts a complete caller-supplied typed field inventory, not
//! CloudKit wire bytes. It validates a deliberately closed subset before
//! constructing ordered AD. It performs no crypto, key lookup, I/O or retries.
//! Completeness, original wire types and account trust remain caller assertions.
//! See `CKKS_ITEM.md` for the field contract, evidence and unsupported cases.

use super::hierarchy::{KeyId, KeyScope};
use core::fmt;
use zeroize::Zeroizing;

const MAX_FIELDS: usize = 9;
const MAX_IDENTIFIER_BYTES: usize = 1024;
const MAX_FIELD_NAME_BYTES: usize = 64;
const MAX_PCS_BYTES: usize = 64 * 1024;
const MAX_INPUT_BYTES: usize = 1024 * 1024;
const MAX_ENVELOPE_BYTES: usize = 1024 * 1024;

/// Caller-supplied item identity, distinct from a key identity.
/// Identifiers are borrowed, compared exactly and redacted in Debug.
#[derive(Clone, Copy)]
pub struct ItemId<'a> {
    /// Full claimed account/container/database/zone context, never an auth token.
    pub scope: KeyScope<'a>,
    /// Exact record name, without UUID parsing or normalization.
    pub name: &'a str,
}

/// One field occurrence; a slice preserves duplicate names for rejection.
/// The caller must include every field, including unsupported ones, and bound
/// allocations while decoding its original representation. No wire parser is
/// provided here. Borrowed input remains caller-owned and is never wiped here.
#[derive(Clone, Copy)]
pub struct Field<'a> {
    /// Exact field name, without normalization or alias substitution.
    pub name: &'a str,
    /// Explicitly typed value; no automatic scalar coercion is performed.
    pub value: FieldValue<'a>,
}

/// Typed adapter input, not a CloudKit wire value enum.
///
/// Adapters must preserve source type distinctions, reject malformed/truncated
/// source encodings, and represent unsupported types rather than dropping them.
/// No inferred conversion from dates, floating numbers, Booleans or text to an
/// integer is allowed. All variants redact Debug, including unsupported input.
#[derive(Clone, Copy)]
pub enum FieldValue<'a> {
    /// UTF-8 text; supported only for the optional `uploadver` field.
    Text(&'a str),
    /// Opaque bytes for `data`, `pcspublickey` or `pcspublicidentity`.
    Data(&'a [u8]),
    /// An integer, checked to be in `0..=u64::MAX` before encoding.
    Integer(i128),
    /// Complete scoped parent-key reference, without default-owner aliases.
    Reference(KeyId<'a>),
    /// Decoded wrapped-key bytes, required to be exactly 80 bytes.
    ///
    /// This is a semantic adapter value, not the original `wrappedkey` wire
    /// string. The adapter must validate the original field type and encoding
    /// before constructing it. This module does not decode base64 or unwrap it.
    WrappedKey(&'a [u8]),
    /// An unsupported source type. Always rejected, never treated as absence.
    Unsupported,
}

/// The caller's assertion about the supplied field inventory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FieldCompleteness {
    /// All original field occurrences are supplied, without dropping unknowns.
    Complete,
    /// Inventory may be partial; construction always refuses this state.
    Incomplete,
}

/// Ordered AD for the supported item subset; not authenticated metadata.
///
/// Retains only borrowed string/Data values and zeroizing fixed integer bytes.
/// No cloning, implicit serialization or owned raw-byte export is provided.
/// Input owners must outlive the result and remain responsible for wiping their
/// buffers. Dropping this result cannot wipe caller-owned input. Stack/compiler
/// copies of numeric inputs are not covered by the zeroizing owner's guarantee.
///
/// Component views cannot outlive this owner:
/// ```compile_fail
/// use coffer_protocol::ckks::item::ItemAssociatedData;
/// fn invalid(ad: ItemAssociatedData<'_>) {
///     let parts = ad.components();
///     drop(ad);
///     let _ = parts.as_slice();
/// }
/// ```
/// ```compile_fail
/// use coffer_protocol::ckks::item::ItemAssociatedData;
/// fn invalid(ad: ItemAssociatedData<'_>) { let _ = ad.clone(); }
/// ```
pub struct ItemAssociatedData<'a> {
    record_name: &'a str,
    parent_name: &'a str,
    integers: Zeroizing<[[u8; 8]; 3]>,
    pcs_service_present: bool,
    pcs_public_key: Option<&'a [u8]>,
    pcs_public_identity: Option<&'a [u8]>,
}

impl ItemAssociatedData<'_> {
    /// Borrows value components in fixed ASCII key order: `UUID`, `encver`,
    /// `gen`, optional `pcspublicidentity`, `pcspublickey`, `pcsservice`, then
    /// `wrappedkey`. That final value is the parent name, not wrapped bytes.
    ///
    /// Absent PCS fields contribute no component; present empty Data contributes
    /// an empty component. Pass [`AdComponents::as_slice`] explicitly to the
    /// existing payload decryptor, which omits empty values and adds nonce first.
    /// No sorting, concatenation, decryption or fallback occurs here.
    #[must_use]
    pub fn components(&self) -> AdComponents<'_> {
        let mut result = AdComponents {
            values: [&[]; 7],
            len: 0,
        };
        // The fixed list contains at most seven entries; no input controls it.
        for value in [
            Some(self.record_name.as_bytes()),
            Some(self.integers[0].as_slice()),
            Some(self.integers[1].as_slice()),
            self.pcs_public_identity,
            self.pcs_public_key,
            self.pcs_service_present
                .then_some(self.integers[2].as_slice()),
            Some(self.parent_name.as_bytes()),
        ]
        .into_iter()
        .flatten()
        {
            result.values[result.len] = value;
            result.len += 1;
        }
        result
    }
}

/// Bounded, redacted component borrows tied to the AD owner's lifetime.
/// No component bytes are copied. Drop promptly with the owner after use.
pub struct AdComponents<'a> {
    values: [&'a [u8]; 7],
    len: usize,
}
impl AdComponents<'_> {
    /// Explicitly borrows the ordered components, including present empty Data.
    /// These bytes can identify a record/account and must not be logged.
    #[must_use]
    pub fn as_slice(&self) -> &[&[u8]] {
        &self.values[..self.len]
    }
}

/// Fixed failures with no input, dynamic messages, offsets or partial output.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ItemError {
    /// The caller did not assert a complete field inventory.
    IncompleteInput,
    /// A count, byte length or aggregate input cap was exceeded.
    LimitExceeded,
    /// An item, parent or scope identifier was empty.
    InvalidIdentifier,
    /// The exact record type was not `item`.
    UnsupportedRecordType,
    /// A name outside the closed field subset was supplied, even with no value.
    UnknownField,
    /// A supported name appeared more than once.
    DuplicateField,
    /// A required field was absent.
    MissingField,
    /// A supported name carried a different or unsupported value type.
    UnsupportedFieldType,
    /// An integer was negative or above `u64::MAX`.
    IntegerOutOfRange,
    /// The supplied integer encryption version was not two.
    UnsupportedVersion,
    /// The parent reference's full scope did not match the item's scope.
    ScopeMismatch,
    /// Decoded wrapped-key bytes were not exactly 80 bytes.
    InvalidWrappedKeyLength,
    /// Envelope bytes were outside 32 bytes through 1 MiB.
    InvalidEnvelopeLength,
}
impl fmt::Display for ItemError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::IncompleteInput => "incomplete CKKS item inventory",
            Self::LimitExceeded => "CKKS item input limit exceeded",
            Self::InvalidIdentifier => "invalid CKKS item identifier",
            Self::UnsupportedRecordType => "unsupported CKKS record type",
            Self::UnknownField => "unsupported CKKS item field",
            Self::DuplicateField => "duplicate CKKS item field",
            Self::MissingField => "missing CKKS item field",
            Self::UnsupportedFieldType => "unsupported CKKS item field type",
            Self::IntegerOutOfRange => "CKKS item integer out of range",
            Self::UnsupportedVersion => "unsupported CKKS item encryption version",
            Self::ScopeMismatch => "CKKS item parent scope mismatch",
            Self::InvalidWrappedKeyLength => "invalid CKKS item wrapped-key length",
            Self::InvalidEnvelopeLength => "invalid CKKS item envelope length",
        })
    }
}
impl std::error::Error for ItemError {}

/// Validates one complete typed inventory and constructs known v2 item AD.
///
/// Required fields are `parentkeyref` (Reference), `wrappedkey` (WrappedKey),
/// `data` (Data), `gen` (Integer), and `encver` (Integer, exactly two). Optional
/// fields are `pcsservice` (Integer), `pcspublickey`/`pcspublicidentity` (Data),
/// and `uploadver` (Text). Every other name, including `UUID` and `server_*`,
/// is rejected. Record identity is supplied only through `id`; it cannot be
/// overridden by a field. The bounded `uploadver` is validated but not AD.
///
/// All input bounds and types are checked before constructing the result.
/// Local caps: nine occurrences, 1,024 bytes per identifier/Text, 64 bytes per
/// field name/record type, 64 KiB per PCS Data, 32 bytes through 1 MiB envelope,
/// exactly 80 wrapped bytes, and 1 MiB aggregate. Aggregate accounting includes
/// every string/byte occurrence, each integer as 16 bytes, each value tag as
/// one byte, and each scope's two enum bytes. Repeated parent scopes count again.
/// This conservative aggregate cap can reject an envelope below its own cap.
/// No heap allocation, crypto, transport, key lookup or retry is performed.
///
/// The caller must bound original wire decoding, preserve every field and
/// validate source types before making semantic values such as WrappedKey.
/// This checks neither actual collection completeness nor metadata authenticity,
/// freshness, authorization or account trust. Scope comparison is structural;
/// scope bytes are not included in the AD. Live interoperability is unverified.
///
/// # Errors
/// Returns a fixed [`ItemError`] for incomplete, out-of-bounds, unknown,
/// duplicate, missing, incorrectly typed or unsupported input. No partial AD
/// is returned. Borrowed input is unchanged and stays caller-owned on failure.
pub fn build_associated_data<'a>(
    id: ItemId<'a>,
    record_type: &str,
    fields: &[Field<'a>],
    completeness: FieldCompleteness,
) -> Result<ItemAssociatedData<'a>, ItemError> {
    if completeness != FieldCompleteness::Complete {
        return Err(ItemError::IncompleteInput);
    }
    if fields.len() > MAX_FIELDS {
        return Err(ItemError::LimitExceeded);
    }
    let mut total = 0;
    scope_bytes(id.scope, &mut total)?;
    identifier(id.name, &mut total)?;
    bounded(record_type.len(), MAX_FIELD_NAME_BYTES, &mut total)?;
    // Inspect every input size before schema extraction or integer encoding.
    for field in fields {
        bounded(field.name.len(), MAX_FIELD_NAME_BYTES, &mut total)?;
        add(&mut total, 1)?;
        match field.value {
            FieldValue::Text(value) => bounded(value.len(), MAX_IDENTIFIER_BYTES, &mut total)?,
            FieldValue::Data(value) | FieldValue::WrappedKey(value) => {
                add(&mut total, value.len())?
            }
            FieldValue::Integer(_) => add(&mut total, 16)?,
            FieldValue::Reference(key) => {
                scope_bytes(key.scope, &mut total)?;
                identifier(key.name, &mut total)?;
            }
            FieldValue::Unsupported => {}
        }
    }
    if record_type != "item" {
        return Err(ItemError::UnsupportedRecordType);
    }
    let mut slots = [None; MAX_FIELDS];
    for field in fields {
        let index = match field.name {
            "parentkeyref" => 0,
            "wrappedkey" => 1,
            "data" => 2,
            "gen" => 3,
            "encver" => 4,
            "pcsservice" => 5,
            "pcspublickey" => 6,
            "pcspublicidentity" => 7,
            "uploadver" => 8,
            _ => return Err(ItemError::UnknownField),
        };
        if slots[index].replace(field.value).is_some() {
            return Err(ItemError::DuplicateField);
        }
    }
    let parent = match required(slots[0])? {
        FieldValue::Reference(key) => key,
        _ => return Err(ItemError::UnsupportedFieldType),
    };
    if parent.scope != id.scope {
        return Err(ItemError::ScopeMismatch);
    }
    match required(slots[1])? {
        FieldValue::WrappedKey(bytes) if bytes.len() == 80 => {}
        FieldValue::WrappedKey(_) => return Err(ItemError::InvalidWrappedKeyLength),
        _ => return Err(ItemError::UnsupportedFieldType),
    }
    match required(slots[2])? {
        FieldValue::Data(bytes) if (32..=MAX_ENVELOPE_BYTES).contains(&bytes.len()) => {}
        FieldValue::Data(_) => return Err(ItemError::InvalidEnvelopeLength),
        _ => return Err(ItemError::UnsupportedFieldType),
    }
    let generation = integer(required(slots[3])?)?;
    let version = integer(required(slots[4])?)?;
    if version != 2 {
        return Err(ItemError::UnsupportedVersion);
    }
    let service = slots[5].map(integer).transpose()?;
    let public_key = pcs_data(slots[6])?;
    let public_identity = pcs_data(slots[7])?;
    if let Some(value) = slots[8]
        && !matches!(value, FieldValue::Text(_))
    {
        return Err(ItemError::UnsupportedFieldType);
    }
    Ok(ItemAssociatedData {
        record_name: id.name,
        parent_name: parent.name,
        integers: Zeroizing::new([
            version.to_le_bytes(),
            generation.to_le_bytes(),
            service.unwrap_or(0).to_le_bytes(),
        ]),
        pcs_service_present: service.is_some(),
        pcs_public_key: public_key,
        pcs_public_identity: public_identity,
    })
}
fn required(value: Option<FieldValue<'_>>) -> Result<FieldValue<'_>, ItemError> {
    value.ok_or(ItemError::MissingField)
}
fn integer(value: FieldValue<'_>) -> Result<u64, ItemError> {
    match value {
        FieldValue::Integer(n) => u64::try_from(n).map_err(|_| ItemError::IntegerOutOfRange),
        _ => Err(ItemError::UnsupportedFieldType),
    }
}
fn pcs_data(value: Option<FieldValue<'_>>) -> Result<Option<&[u8]>, ItemError> {
    match value {
        None => Ok(None),
        Some(FieldValue::Data(bytes)) if bytes.len() <= MAX_PCS_BYTES => Ok(Some(bytes)),
        Some(FieldValue::Data(_)) => Err(ItemError::LimitExceeded),
        Some(_) => Err(ItemError::UnsupportedFieldType),
    }
}
fn add(total: &mut usize, length: usize) -> Result<(), ItemError> {
    *total = total.checked_add(length).ok_or(ItemError::LimitExceeded)?;
    if *total > MAX_INPUT_BYTES {
        return Err(ItemError::LimitExceeded);
    }
    Ok(())
}
fn bounded(length: usize, limit: usize, total: &mut usize) -> Result<(), ItemError> {
    if length > limit {
        return Err(ItemError::LimitExceeded);
    }
    add(total, length)
}
fn identifier(value: &str, total: &mut usize) -> Result<(), ItemError> {
    if value.is_empty() {
        return Err(ItemError::InvalidIdentifier);
    }
    bounded(value.len(), MAX_IDENTIFIER_BYTES, total)
}
fn scope_bytes(scope: KeyScope<'_>, total: &mut usize) -> Result<(), ItemError> {
    for value in [
        scope.account,
        scope.container,
        scope.zone_owner,
        scope.zone_name,
    ] {
        identifier(value, total)?;
    }
    add(total, 2)
}
macro_rules! redacted {
    ($($ty:ty),+ $(,)?) => { $(impl fmt::Debug for $ty {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { f.write_str("<redacted>") }
    })+ };
}
redacted!(
    ItemId<'_>,
    Field<'_>,
    FieldValue<'_>,
    ItemAssociatedData<'_>,
    AdComponents<'_>
);

#[cfg(test)]
mod tests;
