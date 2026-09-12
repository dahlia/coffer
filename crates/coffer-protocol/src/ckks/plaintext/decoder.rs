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

use super::*;

// Metadata only: never copies a scalar body or decoded string into this array.
#[derive(Clone, Copy)]
pub(super) struct Object {
    start: usize,
    body: usize,
    end: usize,
    kind: ScalarKind,
    used: bool,
}
impl Object {
    const EMPTY: Self = Self {
        start: 0,
        body: 0,
        end: 0,
        kind: ScalarKind::Data,
        used: false,
    };
}

// Counts the actual view (including the sole object array), sorting indices,
// and the small per-object descriptor returned by inspect_object. No second
// array is constructed by validation. This is a storage audit, not peak-stack
// evidence: compiler-generated moves/copies and sort call frames are unmeasured.
const _: () = assert!(
    core::mem::size_of::<FlatItemView<'static>>()
        + core::mem::size_of::<[usize; MAX_OBJECTS]>()
        + core::mem::size_of::<Object>()
        <= 64 * 1024
);

pub(super) fn parse_bytes(padded: &[u8]) -> Result<FlatItemView<'_>, PlaintextError> {
    if padded.len() > MAX_INPUT {
        return Err(PlaintextError::LimitExceeded);
    }
    let marker = padded
        .iter()
        .rposition(|b| *b != 0)
        .ok_or(PlaintextError::InvalidPadding)?;
    if padded[marker] != 0x80 {
        return Err(PlaintextError::InvalidPadding);
    }
    let bytes = &padded[..marker];
    if !bytes.starts_with(b"bplist00") {
        return Err(PlaintextError::UnsupportedFormat);
    }
    if bytes.len() < 40 {
        return Err(PlaintextError::MalformedLayout);
    }
    let trailer_start = bytes.len() - 32;
    let trailer = &bytes[trailer_start..];
    if trailer[..6].iter().any(|b| *b != 0) {
        return Err(PlaintextError::UnsupportedRepresentation);
    }
    let offset_width = width(trailer[6])?;
    let ref_width = width(trailer[7])?;
    let count = bounded_integer(read(trailer, 8, 8)?, MAX_OBJECTS)?;
    if count == 0 {
        return Err(PlaintextError::MalformedLayout);
    }
    let root = index(read(trailer, 16, 8)?, count)?;
    let table = index(read(trailer, 24, 8)?, trailer_start)?;
    if table < 8
        || table.checked_add(
            count
                .checked_mul(offset_width)
                .ok_or(PlaintextError::MalformedLayout)?,
        ) != Some(trailer_start)
    {
        return Err(PlaintextError::MalformedLayout);
    }
    let mut view = FlatItemView {
        bytes,
        objects: [Object::EMPTY; MAX_OBJECTS],
        root,
        pairs: 0,
        ref_width,
    };
    for id in 0..count {
        // count/width/table equality above bounds all offset-table reads.
        let start = index(read(bytes, table + id * offset_width, offset_width)?, table)?;
        if start < 8 {
            return Err(PlaintextError::MalformedLayout);
        }
        let (object, pairs) = inspect_object(&bytes[..table], start, id == root, ref_width)?;
        view.objects[id] = object;
        if id == root {
            view.pairs = pairs;
        }
    }
    validate_geometry(&view.objects[..count], table)?;
    view.objects[root].used = true;
    for pair in 0..view.pairs {
        let key = view.checked_reference(pair, count)?;
        let value = view.checked_reference(view.pairs + pair, count)?;
        if key == root || value == root {
            return Err(PlaintextError::UnsupportedRepresentation);
        }
        let key_object = &view.objects[key];
        if key_object.end - key_object.body > MAX_KEY {
            return Err(PlaintextError::LimitExceeded);
        }
        if !matches!(key_object.kind, ScalarKind::Ascii | ScalarKind::Utf16) {
            return Err(PlaintextError::UnsupportedRepresentation);
        }
        view.objects[key].used = true;
        view.objects[value].used = true;
        let key_text = view
            .scalar(key)
            .as_text()
            .ok_or(PlaintextError::UnsupportedRepresentation)?;
        // At most 256*255/2 = 32,640 comparisons; at most 256 characters/key.
        for earlier in 0..pair {
            let previous = view
                .scalar(view.reference(earlier))
                .as_text()
                .ok_or(PlaintextError::UnsupportedRepresentation)?;
            if key_text.chars().eq(previous.chars()) {
                return Err(PlaintextError::DuplicateKey);
            }
        }
    }
    if view.objects[..count].iter().any(|object| !object.used) {
        return Err(PlaintextError::UnsupportedRepresentation);
    }
    Ok(view)
}

fn validate_geometry(objects: &[Object], table: usize) -> Result<(), PlaintextError> {
    let mut order = [0usize; MAX_OBJECTS];
    for (id, slot) in order[..objects.len()].iter_mut().enumerate() {
        *slot = id;
    }
    order[..objects.len()].sort_unstable_by_key(|id| objects[*id].start);
    let mut expected = 8;
    for id in &order[..objects.len()] {
        let object = &objects[*id];
        if object.start != expected {
            return Err(PlaintextError::MalformedLayout);
        }
        expected = object.end;
    }
    if expected != table {
        return Err(PlaintextError::MalformedLayout);
    }
    Ok(())
}

fn inspect_object(
    bytes: &[u8],
    start: usize,
    root: bool,
    ref_width: usize,
) -> Result<(Object, usize), PlaintextError> {
    let marker = *bytes.get(start).ok_or(PlaintextError::MalformedLayout)?;
    let mut body = start
        .checked_add(1)
        .ok_or(PlaintextError::MalformedLayout)?;
    let mut pairs = 0;
    let (kind, length) = if root {
        if marker >> 4 != 0xd {
            return Err(PlaintextError::UnsupportedRepresentation);
        }
        pairs = bounded_integer(count(bytes, &mut body, marker)?, MAX_PAIRS)?;
        (
            ScalarKind::Data,
            pairs
                .checked_mul(2)
                .and_then(|n| n.checked_mul(ref_width))
                .ok_or(PlaintextError::MalformedLayout)?,
        )
    } else {
        match marker {
            0x08 | 0x09 => (ScalarKind::Boolean, 0),
            0x10..=0x14 => (ScalarKind::Integer, 1usize << (marker & 0xf)),
            0x22 => (ScalarKind::Real, 4),
            0x23 => (ScalarKind::Real, 8),
            0x33 => (ScalarKind::Date, 8),
            0x40..=0x6f => {
                let units = count(bytes, &mut body, marker)?;
                let (kind, unit_width) = match marker >> 4 {
                    4 => (ScalarKind::Data, 1u64),
                    5 => (ScalarKind::Ascii, 1),
                    _ => (ScalarKind::Utf16, 2),
                };
                let length = units
                    .checked_mul(unit_width)
                    .ok_or(PlaintextError::LimitExceeded)?;
                (kind, bounded_integer(length, MAX_SCALAR)?)
            }
            _ => return Err(PlaintextError::UnsupportedRepresentation),
        }
    };
    let end = body
        .checked_add(length)
        .ok_or(PlaintextError::MalformedLayout)?;
    let scalar = bytes
        .get(body..end)
        .ok_or(PlaintextError::MalformedLayout)?;
    if !root {
        match kind {
            ScalarKind::Ascii if !scalar.is_ascii() => return Err(PlaintextError::InvalidText),
            ScalarKind::Utf16 => {
                let units = scalar
                    .as_chunks::<2>()
                    .0
                    .iter()
                    .map(|b| u16::from_be_bytes([b[0], b[1]]));
                if char::decode_utf16(units).any(|c| c.is_err()) {
                    return Err(PlaintextError::InvalidText);
                }
            }
            _ => {}
        }
    }
    Ok((
        Object {
            start,
            body,
            end,
            kind,
            used: false,
        },
        pairs,
    ))
}

fn count(bytes: &[u8], cursor: &mut usize, marker: u8) -> Result<u64, PlaintextError> {
    let short = marker & 0x0f;
    if short != 15 {
        return Ok(u64::from(short));
    }
    let integer_marker = *bytes.get(*cursor).ok_or(PlaintextError::MalformedLayout)?;
    // Full integer marker validation; no DER minimal-length constraint.
    let width = match integer_marker {
        0x10..=0x13 => 1usize << (integer_marker & 0xf),
        _ => return Err(PlaintextError::UnsupportedRepresentation),
    };
    *cursor = cursor
        .checked_add(1)
        .ok_or(PlaintextError::MalformedLayout)?;
    let value = read(bytes, *cursor, width)?;
    *cursor = cursor
        .checked_add(width)
        .ok_or(PlaintextError::MalformedLayout)?;
    Ok(value)
}
fn width(value: u8) -> Result<usize, PlaintextError> {
    match value {
        1 | 2 | 4 | 8 => Ok(usize::from(value)),
        _ => Err(PlaintextError::UnsupportedRepresentation),
    }
}
fn read(bytes: &[u8], offset: usize, width: usize) -> Result<u64, PlaintextError> {
    let end = offset
        .checked_add(width)
        .ok_or(PlaintextError::MalformedLayout)?;
    let bytes = bytes
        .get(offset..end)
        .ok_or(PlaintextError::MalformedLayout)?;
    // All callers select widths <= 8 before this helper; there is no truncation.
    Ok(bytes.iter().fold(0u64, |n, b| (n << 8) | u64::from(*b)))
}
fn bounded_integer(value: u64, maximum: usize) -> Result<usize, PlaintextError> {
    let value = usize::try_from(value).map_err(|_| PlaintextError::LimitExceeded)?;
    if value > maximum {
        return Err(PlaintextError::LimitExceeded);
    }
    Ok(value)
}
fn index(value: u64, end: usize) -> Result<usize, PlaintextError> {
    let value = usize::try_from(value).map_err(|_| PlaintextError::MalformedLayout)?;
    if value >= end {
        return Err(PlaintextError::MalformedLayout);
    }
    Ok(value)
}
impl<'a> FlatItemView<'a> {
    fn checked_reference(&self, position: usize, count: usize) -> Result<usize, PlaintextError> {
        let offset = position
            .checked_mul(self.ref_width)
            .and_then(|n| n.checked_add(self.objects[self.root].body))
            .ok_or(PlaintextError::MalformedLayout)?;
        index(read(self.bytes, offset, self.ref_width)?, count)
    }
    pub(super) fn reference(&self, position: usize) -> usize {
        // Private callers only access positions/references already validated in
        // parse_bytes (earlier keys during validation, all refs after success).
        let offset = self.objects[self.root].body + position * self.ref_width;
        self.bytes[offset..offset + self.ref_width]
            .iter()
            .fold(0usize, |n, b| (n << 8) | usize::from(*b))
    }
    pub(super) fn scalar(&self, id: usize) -> ScalarView<'a> {
        let object = &self.objects[id];
        ScalarView {
            kind: object.kind,
            body: &self.bytes[object.body..object.end],
            encoded: &self.bytes[object.start..object.end],
        }
    }
}
