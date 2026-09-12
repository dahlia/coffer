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

//! Explicit offline CKKS unpadding and a flat binary-plist view.
//!
//! Only `bplist00`, a root dictionary and scalar children are supported. Every
//! object, reference and decoded key is validated before any view is returned.
//! Unknown scalar fields retain their bytes; nested containers, unused objects,
//! alternate formats and implicit fallback are unsupported. This establishes no
//! account/record binding, trust, freshness, sidecar meaning or live compatibility.
//!
//! Parsing/projection use borrowed bytes and fixed metadata, with no dynamic
//! allocations or decoded secret heap copies. UTF-16 is read through safe byte
//! chunks. The metadata size assertion includes the view and sorting scratch;
//! it is not a measurement of compiler-generated copies or peak stack usage.
//! No runtime allocator instrumentation is supplied. Parsing errors leave the
//! caller's owner unchanged: the caller must drop it promptly after failure or
//! cancellation. This module cannot wipe a borrowed owner's bytes.

use super::payload::PayloadPlaintext;
use core::fmt;

mod decoder;
use decoder::{Object, parse_bytes};

const MAX_INPUT: usize = 1024 * 1024;
const MAX_PAIRS: usize = 256;
const MAX_OBJECTS: usize = 513;
const MAX_SCALAR: usize = 256 * 1024;
const MAX_KEY: usize = 256;

/// Fixed parse failures with no input bytes, offsets, dynamic messages or output.
#[derive(PartialEq, Eq)]
pub enum PlaintextError {
    /// The padded input or a bounded structural resource exceeds local policy.
    LimitExceeded,
    /// No final `0x80` marker preceded the trailing zero bytes.
    InvalidPadding,
    /// The unpadded input does not begin with exactly `bplist00`.
    UnsupportedFormat,
    /// The supported representation has invalid lengths, references or geometry.
    MalformedLayout,
    /// A marker, width, root shape, reserved trailer byte or unused object is unsupported.
    UnsupportedRepresentation,
    /// ASCII bytes or UTF-16 surrogate pairs are invalid.
    InvalidText,
    /// Two dictionary keys have the same decoded characters, without normalization.
    DuplicateKey,
}

/// The preserved scalar encoding; numeric values are never normalized.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScalarKind {
    /// Opaque Data, including empty, NUL and non-UTF-8 bodies.
    Data,
    /// Validated ASCII text.
    Ascii,
    /// Validated big-endian UTF-16 text.
    Utf16,
    /// A big-endian integer body of 1, 2, 4, 8 or 16 bytes.
    Integer,
    /// Raw IEEE floating bits of 4 or 8 bytes, including NaNs and signed zero.
    Real,
    /// A date's raw 8-byte floating encoding, without timestamp conversion.
    Date,
    /// A distinct false/true marker; never coerced to an integer.
    Boolean,
}

/// A fully validated dictionary borrowing its payload owner.
///
/// Views have redacted Debug and no Clone, Display or Serialize convenience.
/// Raw access is explicit and must not be logged or persisted unprotected.
///
/// The owner cannot be dropped or mutably borrowed while a view remains in use:
///
/// ```compile_fail
/// use coffer_protocol::ckks::{payload::PayloadPlaintext, plaintext::parse_ckks_plaintext};
/// fn invalid(owner: PayloadPlaintext) {
///     let view = parse_ckks_plaintext(&owner).unwrap();
///     drop(owner);
///     let _ = view.entries();
/// }
/// ```
///
/// ```compile_fail
/// use coffer_protocol::ckks::{payload::PayloadPlaintext, plaintext::parse_ckks_plaintext};
/// fn invalid(owner: &mut PayloadPlaintext) {
///     let view = parse_ckks_plaintext(owner).unwrap();
///     let mutable = &mut *owner;
///     let _ = mutable;
///     let _ = view.entries();
/// }
/// ```
///
/// ```compile_fail
/// use coffer_protocol::ckks::{payload::PayloadPlaintext, plaintext::{FlatItemView, parse_ckks_plaintext}};
/// fn invalid(owner: PayloadPlaintext) -> FlatItemView<'static> {
///     parse_ckks_plaintext(&owner).unwrap()
/// }
/// ```
///
/// ```compile_fail
/// use coffer_protocol::ckks::plaintext::FlatItemView;
/// fn invalid(view: FlatItemView<'_>) { let _ = view.clone(); }
/// ```
///
/// ```compile_fail
/// use coffer_protocol::ckks::plaintext::FlatItemView;
/// fn invalid(view: FlatItemView<'_>) { let _ = format!("{view}"); }
/// ```
pub struct FlatItemView<'a> {
    bytes: &'a [u8],
    objects: [Object; MAX_OBJECTS],
    root: usize,
    pairs: usize,
    ref_width: usize,
}

/// Explicitly removes CKKS padding and validates the complete flat item.
///
/// Borrows an already authenticated opaque owner; success does not authenticate
/// metadata or imply a website credential. Limits are local hard caps: 1 MiB
/// padded input, 256 pairs, 513 objects, 256 KiB per scalar body, and 256 bytes
/// per encoded key body. Sorted object spans must cover the region exactly.
/// Shared value references are allowed; decoded duplicate keys are rejected.
/// There is no recursion or format retry. No modulo-20/extra-block constraint
/// is imposed on padding: the final nonzero byte must be the `0x80` marker.
///
/// # Errors
/// Returns a fixed [`PlaintextError`] after an unsupported or invalid input,
/// without a partial view or a new secret heap copy. The owner remains borrowed
/// only for this call on failure; the caller must drop it when no longer needed.
pub fn parse_ckks_plaintext(owner: &PayloadPlaintext) -> Result<FlatItemView<'_>, PlaintextError> {
    parse_bytes(owner.expose_secret())
}

/// One dictionary entry, preserving its validated key and raw scalar value.
pub struct EntryView<'a> {
    /// The decoded-key view; no normalization or owned conversion is performed.
    pub key: TextView<'a>,
    /// The original scalar encoding, including fields with unknown meanings.
    pub value: ScalarView<'a>,
}

/// A borrowed validated scalar with explicit raw access.
pub struct ScalarView<'a> {
    kind: ScalarKind,
    body: &'a [u8],
    encoded: &'a [u8],
}
impl<'a> ScalarView<'a> {
    /// Returns the preserved encoding kind, without coercion.
    #[must_use]
    pub fn kind(&self) -> ScalarKind {
        self.kind
    }
    /// Borrows the exact scalar body; numeric width is this slice's length.
    /// Boolean bodies are empty; their value is retained in the marker.
    #[must_use]
    pub fn raw_body(&self) -> &'a [u8] {
        self.body
    }
    /// Borrows the complete marker/count/body encoding, without normalization.
    #[must_use]
    pub fn raw_encoding(&self) -> &'a [u8] {
        self.encoded
    }
    /// Borrows opaque Data only, without text or nested-format conversion.
    #[must_use]
    pub fn as_data(&self) -> Option<&'a [u8]> {
        (self.kind == ScalarKind::Data).then_some(self.body)
    }
    /// Creates a text view only for already validated ASCII/UTF-16 strings.
    #[must_use]
    pub fn as_text(&self) -> Option<TextView<'a>> {
        matches!(self.kind, ScalarKind::Ascii | ScalarKind::Utf16).then_some(TextView {
            bytes: self.body,
            utf16: self.kind == ScalarKind::Utf16,
        })
    }
    /// Returns a Boolean only for a Boolean marker; integers stay distinct.
    #[must_use]
    pub fn as_bool(&self) -> Option<bool> {
        (self.kind == ScalarKind::Boolean).then(|| self.encoded[0] == 0x09)
    }
}

/// A validated ASCII or UTF-16 string borrowing the payload bytes.
/// No owned, lossy or normalized conversion is provided.
pub struct TextView<'a> {
    bytes: &'a [u8],
    utf16: bool,
}
impl<'a> TextView<'a> {
    /// Iterates Unicode scalar values without allocation or replacement characters.
    #[must_use]
    pub fn chars(&self) -> TextChars<'a> {
        TextChars {
            bytes: self.bytes,
            utf16: self.utf16,
        }
    }
    /// Compares exact decoded characters; no case folding or normalization.
    #[must_use]
    pub fn equals(&self, text: &str) -> bool {
        self.chars().eq(text.chars())
    }
    /// Reports an empty encoded string, which is also an empty decoded string.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
    /// Borrows original text bytes; UTF-16 retains big-endian code units.
    #[must_use]
    pub fn raw_bytes(&self) -> &'a [u8] {
        self.bytes
    }
}

/// Allocation-free Unicode scalar iteration over a validated borrowed string.
/// Debug is fixed and redacted even after partial iteration.
pub struct TextChars<'a> {
    bytes: &'a [u8],
    utf16: bool,
}
impl Iterator for TextChars<'_> {
    type Item = char;
    fn next(&mut self) -> Option<char> {
        if !self.utf16 {
            let (&first, rest) = self.bytes.split_first()?;
            self.bytes = rest;
            return Some(char::from(first));
        }
        // Construction is private and only follows whole-string validation.
        // decode_utf16 uses safe byte chunks; no alignment cast or secret buffer.
        let mut units = self
            .bytes
            .as_chunks::<2>()
            .0
            .iter()
            .map(|b| u16::from_be_bytes([b[0], b[1]]));
        let first = units.next()?;
        let width = if (0xd800..=0xdbff).contains(&first) {
            4
        } else {
            2
        };
        let result = char::decode_utf16(core::iter::once(first).chain(units))
            .next()?
            .ok()?;
        self.bytes = &self.bytes[width..];
        Some(result)
    }
}
impl core::iter::FusedIterator for TextChars<'_> {}

/// Ordered entry iteration after complete validation; no partial parse events.
pub struct Entries<'v, 'a> {
    view: &'v FlatItemView<'a>,
    index: usize,
}
impl<'a> Iterator for Entries<'_, 'a> {
    type Item = EntryView<'a>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.index == self.view.pairs {
            return None;
        }
        let key = self.view.scalar(self.view.reference(self.index));
        let value = self
            .view
            .scalar(self.view.reference(self.view.pairs + self.index));
        self.index += 1;
        Some(EntryView {
            // These references and text kinds were checked before publishing view.
            key: TextView {
                bytes: key.body,
                utf16: key.kind == ScalarKind::Utf16,
            },
            value,
        })
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = self.view.pairs - self.index;
        (remaining, Some(remaining))
    }
}
impl ExactSizeIterator for Entries<'_, '_> {}
impl core::iter::FusedIterator for Entries<'_, '_> {}

impl<'a> FlatItemView<'a> {
    /// Iterates every validated raw entry in original dictionary reference order.
    #[must_use]
    pub fn entries(&self) -> Entries<'_, 'a> {
        Entries {
            view: self,
            index: 0,
        }
    }
    /// Finds an exact decoded key without allocation, normalization or sidecar joins.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<ScalarView<'a>> {
        self.entries()
            .find(|entry| entry.key.equals(key))
            .map(|entry| entry.value)
    }
    /// Reads the independent three-state tombstone field, even without a password.
    ///
    /// # Errors
    /// Returns [`ProjectionError::UnsupportedTombstone`] for non-integer or
    /// integer values other than raw zero/one at any supported width.
    pub fn tombstone_state(&self) -> Result<TombstoneState, ProjectionError> {
        let Some(value) = self.get("tomb") else {
            return Ok(TombstoneState::Missing);
        };
        if value.kind == ScalarKind::Integer {
            let (last, prefix) = value
                .body
                .split_last()
                .ok_or(ProjectionError::UnsupportedTombstone)?;
            if prefix.iter().all(|b| *b == 0) {
                match last {
                    0 => return Ok(TombstoneState::NotTombstone),
                    1 => return Ok(TombstoneState::Tombstone),
                    _ => {}
                }
            }
        }
        Err(ProjectionError::UnsupportedTombstone)
    }
    /// Projects the narrow `inet` subset only when `tomb` is explicitly integer zero.
    ///
    /// Requires exact string `class=inet`, a string account (empty allowed), a
    /// nonempty string server, string `ptcl=http`/`htps`, and Data `v_Data`
    /// (empty/non-UTF-8/NUL allowed). All other fields remain available as raw
    /// entries, without port/path/date/title/notes semantics or normalization.
    /// Success is a candidate, not an authenticated, trusted or current credential.
    ///
    /// # Errors
    /// Distinguishes unknown tombstone state, tombstones, unsupported tomb values,
    /// missing fields, wrong types, unknown classes and unsupported protocols.
    /// Parsing success remains available independently from these projection errors.
    pub fn internet_password_candidate(
        &self,
    ) -> Result<InternetPasswordCandidate<'a>, ProjectionError> {
        match self.tombstone_state()? {
            TombstoneState::Missing => return Err(ProjectionError::MissingTombstone),
            TombstoneState::Tombstone => return Err(ProjectionError::Tombstone),
            TombstoneState::NotTombstone => {}
        }
        if !self.text_field("class")?.equals("inet") {
            return Err(ProjectionError::UnsupportedClass);
        }
        let account = self.text_field("acct")?;
        let server = self.text_field("srvr")?;
        if server.is_empty() {
            return Err(ProjectionError::EmptyServer);
        }
        let protocol = self.text_field("ptcl")?;
        let protocol = if protocol.equals("http") {
            WebsiteProtocol::Http
        } else if protocol.equals("htps") {
            WebsiteProtocol::Https
        } else {
            return Err(ProjectionError::UnsupportedProtocol);
        };
        let password = self
            .get("v_Data")
            .ok_or(ProjectionError::MissingField)?
            .as_data()
            .ok_or(ProjectionError::UnsupportedFieldType)?;
        Ok(InternetPasswordCandidate {
            account,
            server,
            protocol,
            password,
        })
    }
    fn text_field(&self, key: &str) -> Result<TextView<'a>, ProjectionError> {
        self.get(key)
            .ok_or(ProjectionError::MissingField)?
            .as_text()
            .ok_or(ProjectionError::UnsupportedFieldType)
    }
}

/// Independent tombstone interpretation, with absence retained as unknown.
#[derive(Debug, PartialEq, Eq)]
pub enum TombstoneState {
    /// No tomb field; never treated as an active item.
    Missing,
    /// An integer encoding of zero; does not imply freshness or trust.
    NotTombstone,
    /// An integer encoding of one; never projected as an active candidate.
    Tombstone,
}
/// The two exact supported protocol strings, without inferred ports or origins.
#[derive(Debug, PartialEq, Eq)]
pub enum WebsiteProtocol {
    /// Exact decoded `http`.
    Http,
    /// Exact decoded `htps`.
    Https,
}
/// A borrowed candidate whose tomb field was explicitly integer zero.
/// No constructor bypasses the tomb gate; raw fields confer no account binding.
///
/// Callers cannot manufacture or mutate a candidate to bypass projection:
///
/// ```compile_fail
/// use coffer_protocol::ckks::plaintext::{InternetPasswordCandidate, TextView, WebsiteProtocol};
/// fn invalid<'a>(account: TextView<'a>, server: TextView<'a>) -> InternetPasswordCandidate<'a> {
///     InternetPasswordCandidate { account, server, protocol: WebsiteProtocol::Http, password: b"" }
/// }
/// ```
///
/// ```compile_fail
/// use coffer_protocol::ckks::plaintext::InternetPasswordCandidate;
/// fn invalid(candidate: &mut InternetPasswordCandidate<'_>) { candidate.password = b"changed"; }
/// ```
pub struct InternetPasswordCandidate<'a> {
    account: TextView<'a>,
    server: TextView<'a>,
    protocol: WebsiteProtocol,
    password: &'a [u8],
}
impl<'a> InternetPasswordCandidate<'a> {
    /// Borrows the exact account text, possibly empty.
    #[must_use]
    pub fn account(&self) -> &TextView<'a> {
        &self.account
    }
    /// Borrows the nonempty server text, without URL/domain normalization.
    #[must_use]
    pub fn server(&self) -> &TextView<'a> {
        &self.server
    }
    /// Returns the exact supported protocol, without port inference.
    #[must_use]
    pub fn protocol(&self) -> &WebsiteProtocol {
        &self.protocol
    }
    /// Explicitly borrows opaque password bytes, possibly empty or non-text.
    #[must_use]
    pub fn password(&self) -> &'a [u8] {
        self.password
    }
    /// Reports the explicit integer-zero tomb state required by construction.
    /// This does not establish freshness or authorization.
    #[must_use]
    pub fn tombstone_state(&self) -> TombstoneState {
        TombstoneState::NotTombstone
    }
}
/// Fixed projection failures, separate from binary-plist layout errors.
#[derive(PartialEq, Eq)]
pub enum ProjectionError {
    /// A required candidate field is absent.
    MissingField,
    /// A required field has a scalar type outside the narrow projection.
    UnsupportedFieldType,
    /// The exact class string is not `inet`.
    UnsupportedClass,
    /// The exact protocol string is neither `http` nor `htps`.
    UnsupportedProtocol,
    /// The server string is empty.
    EmptyServer,
    /// Tomb is absent, so active-item status is unknown.
    MissingTombstone,
    /// Tomb is integer one, so no active candidate is returned.
    Tombstone,
    /// Tomb is neither a supported integer zero nor integer one.
    UnsupportedTombstone,
}

macro_rules! redacted_debug {
    ($($type:ty),+ $(,)?) => { $(impl fmt::Debug for $type {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { f.write_str("<redacted>") }
    })+ };
}
redacted_debug!(
    PlaintextError,
    ProjectionError,
    FlatItemView<'_>,
    EntryView<'_>,
    ScalarView<'_>,
    TextView<'_>,
    TextChars<'_>,
    Entries<'_, '_>,
    InternetPasswordCandidate<'_>
);

#[cfg(test)]
mod tests;
