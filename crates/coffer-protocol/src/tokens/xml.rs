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

//! Bounded XML-only plist grammar with secret-owning scalars and keys.
//!
//! A lexical whitelist precedes quick-xml so its internal tag-name stack and
//! syntax errors can only contain static public markup. All actual values are
//! borrowed events or immediately placed in preallocated zeroizing buffers.

use super::{PlistProblem, ResponseStage, TokenError as Error};
use base64::Engine as _;
use quick_xml::{Reader, events::Event};
use zeroize::Zeroizing;

pub(super) const MAX_BODY: usize = 128 * 1024;
pub(super) const MAX_DATA: usize = 64 * 1024;
const MAX_STRING: usize = 4096;
const MAX_KEY: usize = 256;
const MAX_DEPTH: usize = 8;
const MAX_ELEMENTS: usize = 512;
const DOCTYPE: &str = "!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\"";

pub(super) enum Value {
    Dict(Vec<(Zeroizing<String>, Value)>),
    Array(Vec<Value>),
    Text(Zeroizing<String>),
    Integer(Zeroizing<String>),
    Data(Zeroizing<Vec<u8>>),
    Bool,
    OtherScalar(Zeroizing<String>),
}
impl Value {
    pub(super) fn dict(&self) -> Result<&[(Zeroizing<String>, Value)], Error> {
        match self {
            Self::Dict(v) => Ok(v),
            _ => Err(Error::Malformed),
        }
    }
    pub(super) fn get(&self, key: &str) -> Result<&Self, Error> {
        self.dict()?
            .iter()
            .find(|(k, _)| k.as_str() == key)
            .map(|(_, v)| v)
            .ok_or(Error::Malformed)
    }
    pub(super) fn optional(&self, key: &str) -> Result<Option<&Self>, Error> {
        Ok(self
            .dict()?
            .iter()
            .find(|(k, _)| k.as_str() == key)
            .map(|(_, v)| v))
    }
    pub(super) fn text(&self) -> Result<&str, Error> {
        match self {
            Self::Text(v) => Ok(v),
            _ => Err(Error::Malformed),
        }
    }
    pub(super) fn integer(&self) -> Result<i64, Error> {
        match self {
            Self::Integer(v) => v.parse().map_err(|_| Error::Malformed),
            _ => Err(Error::Malformed),
        }
    }
    pub(super) fn data(&self) -> Result<&[u8], Error> {
        match self {
            Self::Data(v) => Ok(v),
            _ => Err(Error::Malformed),
        }
    }
}
// Touch array contents explicitly while dropping; recursion is bounded by MAX_DEPTH.
impl Drop for Value {
    fn drop(&mut self) {
        match self {
            Self::Array(items) => items.clear(),
            Self::OtherScalar(text) => {
                use zeroize::Zeroize;
                text.zeroize();
            }
            _ => {}
        }
    }
}

pub(super) fn valid_char(c: char) -> bool {
    matches!(c, '\t' | '\n' | '\r' | '\u{20}'..='\u{d7ff}' | '\u{e000}'..='\u{fffd}' | '\u{10000}'..='\u{10ffff}')
}
fn whitespace(bytes: &[u8]) -> bool {
    bytes
        .iter()
        .all(|c| matches!(c, b' ' | b'\r' | b'\n' | b'\t'))
}

fn preflight(bytes: &[u8], stage: ResponseStage) -> Result<(), Error> {
    if bytes.len() > MAX_BODY {
        return Err(Error::TooLarge);
    }
    if bytes.starts_with(b"bplist") {
        return Err(Error::Unsupported);
    }
    let text = std::str::from_utf8(bytes).map_err(|_| malformed(stage, PlistProblem::Encoding))?;
    if !text.chars().all(valid_char) {
        return Err(malformed(stage, PlistProblem::Character));
    }
    let mut rest = text;
    let mut elements = 0;
    while let Some(start) = rest.find('<') {
        rest = &rest[start + 1..];
        let end = rest
            .find('>')
            .ok_or(malformed(stage, PlistProblem::Markup))?;
        let markup = &rest[..end];
        let allowed = matches!(
            markup,
            "?xml version=\"1.0\"?"
                | "?xml version=\"1.0\" encoding=\"UTF-8\"?"
                | "plist version=\"1.0\""
                | "/plist"
                | "dict"
                | "/dict"
                | "dict/"
                | "array"
                | "/array"
                | "array/"
                | "key"
                | "/key"
                | "key/"
                | "string"
                | "/string"
                | "string/"
                | "integer"
                | "/integer"
                | "data"
                | "/data"
                | "data/"
                | "true/"
                | "false/"
                | "real"
                | "/real"
                | "date"
                | "/date"
        ) || markup == DOCTYPE;
        if !allowed {
            return Err(malformed(stage, PlistProblem::Markup));
        }
        elements += 1;
        // Includes end tags and declarations as well: an intentionally stricter cap.
        if elements > MAX_ELEMENTS {
            return Err(Error::TooLarge);
        }
        rest = &rest[end + 1..];
    }
    Ok(())
}

struct Parser<'a> {
    reader: Reader<&'a [u8]>,
    bytes: &'a [u8],
    stage: ResponseStage,
}
fn malformed(stage: ResponseStage, problem: PlistProblem) -> Error {
    Error::MalformedPlist { stage, problem }
}

impl<'a> Parser<'a> {
    fn malformed(&self, problem: PlistProblem) -> Error {
        malformed(self.stage, problem)
    }

    fn event(&mut self) -> Result<Event<'a>, Error> {
        self.reader
            .read_event()
            .map_err(|_| self.malformed(PlistProblem::XmlSyntax))
    }
    fn significant(&mut self) -> Result<Event<'a>, Error> {
        loop {
            let event = self.event()?;
            if matches!(&event, Event::Text(t) if whitespace(t.as_ref())) {
                continue;
            }
            return Ok(event);
        }
    }
    fn scalar(
        &mut self,
        tag: &[u8],
        limit: usize,
        empty: bool,
    ) -> Result<Zeroizing<String>, Error> {
        if empty {
            return Ok(Zeroizing::new(String::new()));
        }
        let start = usize::try_from(self.reader.buffer_position())
            .map_err(|_| self.malformed(PlistProblem::Scalar))?;
        let remaining = self
            .bytes
            .get(start..)
            .ok_or(self.malformed(PlistProblem::Scalar))?;
        let raw_len = remaining
            .iter()
            .position(|b| *b == b'<')
            .ok_or(self.malformed(PlistProblem::Scalar))?;
        // Entity decoding never expands UTF-8 relative to its ASCII spelling.
        // Allocate once, before writing any secret, and never grow the buffer.
        if raw_len > limit {
            return Err(Error::TooLarge);
        }
        let mut out = Zeroizing::new(String::with_capacity(raw_len));
        loop {
            match self.event()? {
                Event::End(end) if end.name().as_ref() == tag => return Ok(out),
                Event::Text(text) => {
                    let text = std::str::from_utf8(text.as_ref())
                        .map_err(|_| self.malformed(PlistProblem::Scalar))?;
                    if text.contains("]]>") {
                        return Err(self.malformed(PlistProblem::Scalar));
                    }
                    let mut chars = text.chars().peekable();
                    while let Some(c) = chars.next() {
                        if c == '\r' {
                            if chars.peek() == Some(&'\n') {
                                chars.next();
                            }
                            out.push('\n');
                        } else {
                            out.push(c);
                        }
                    }
                }
                Event::GeneralRef(reference) => {
                    let raw = std::str::from_utf8(reference.as_ref())
                        .map_err(|_| self.malformed(PlistProblem::Entity))?;
                    let c = match raw {
                        "amp" => '&',
                        "lt" => '<',
                        "gt" => '>',
                        "quot" => '"',
                        "apos" => '\'',
                        _ => {
                            let (digits, radix) = if let Some(d) = raw.strip_prefix("#x") {
                                (d, 16)
                            } else if let Some(d) = raw.strip_prefix('#') {
                                (d, 10)
                            } else {
                                return Err(self.malformed(PlistProblem::Entity));
                            };
                            if digits.is_empty()
                                || !digits.bytes().all(|b| {
                                    if radix == 16 {
                                        b.is_ascii_hexdigit()
                                    } else {
                                        b.is_ascii_digit()
                                    }
                                })
                            {
                                return Err(self.malformed(PlistProblem::Entity));
                            }
                            char::from_u32(
                                u32::from_str_radix(digits, radix)
                                    .map_err(|_| self.malformed(PlistProblem::Entity))?,
                            )
                            .filter(|c| valid_char(*c))
                            .ok_or(self.malformed(PlistProblem::Entity))?
                        }
                    };
                    out.push(c);
                }
                _ => return Err(self.malformed(PlistProblem::Scalar)),
            }
        }
    }
    fn value(&mut self, event: Event<'a>, depth: usize) -> Result<Value, Error> {
        if depth > MAX_DEPTH {
            return Err(Error::TooLarge);
        }
        let (start, empty) = match event {
            Event::Start(s) => (s, false),
            Event::Empty(s) => (s, true),
            _ => return Err(self.malformed(PlistProblem::Structure)),
        };
        let name = start.name();
        let tag = name.as_ref();
        match tag {
            b"dict" => {
                let mut entries = Vec::new();
                if empty {
                    return Ok(Value::Dict(entries));
                }
                loop {
                    let event = self.significant()?;
                    if matches!(&event, Event::End(e) if e.name().as_ref() == b"dict") {
                        break;
                    }
                    let empty_key = match &event {
                        Event::Start(s) if s.name().as_ref() == b"key" => false,
                        Event::Empty(s) if s.name().as_ref() == b"key" => true,
                        _ => return Err(self.malformed(PlistProblem::Structure)),
                    };
                    let key = self.scalar(b"key", MAX_KEY, empty_key)?;
                    if entries
                        .iter()
                        .any(|(k, _): &(Zeroizing<String>, Value)| **k == *key)
                    {
                        return Err(self.malformed(PlistProblem::DuplicateKey));
                    }
                    let event = self.significant()?;
                    let value = self.value(event, depth + 1)?;
                    entries.push((key, value));
                }
                Ok(Value::Dict(entries))
            }
            b"array" => {
                let mut entries = Vec::new();
                if !empty {
                    loop {
                        let event = self.significant()?;
                        if matches!(&event, Event::End(e) if e.name().as_ref() == b"array") {
                            break;
                        }
                        entries.push(self.value(event, depth + 1)?);
                    }
                }
                Ok(Value::Array(entries))
            }
            b"string" => Ok(Value::Text(self.scalar(tag, MAX_STRING, empty)?)),
            b"integer" => {
                let text = self.scalar(tag, 20, empty)?;
                let digits = text.strip_prefix('-').unwrap_or(&text);
                if digits.is_empty()
                    || !digits.bytes().all(|b| b.is_ascii_digit())
                    || text.parse::<i64>().is_err()
                {
                    return Err(self.malformed(PlistProblem::Integer));
                }
                Ok(Value::Integer(text))
            }
            b"data" => {
                let mut text = self.scalar(tag, MAX_DATA.div_ceil(3) * 4 + 4096, empty)?;
                text.retain(|c| !matches!(c, ' ' | '\t' | '\r' | '\n'));
                let size = text.len().div_ceil(4) * 3;
                if size > MAX_DATA + 2 {
                    return Err(Error::TooLarge);
                }
                let mut bytes = Zeroizing::new(vec![0; size]);
                let len = base64::engine::general_purpose::STANDARD
                    .decode_slice(text.as_bytes(), &mut bytes)
                    .map_err(|_| self.malformed(PlistProblem::Base64))?;
                if len > MAX_DATA {
                    return Err(Error::TooLarge);
                }
                bytes.truncate(len);
                Ok(Value::Data(bytes))
            }
            b"true" | b"false" if empty => Ok(Value::Bool),
            // Inert standard plist scalar types are validated even in unknown fields.
            b"real" => {
                let text = self.scalar(tag, 64, empty)?;
                if !text.parse::<f64>().is_ok_and(f64::is_finite) {
                    return Err(self.malformed(PlistProblem::Real));
                }
                Ok(Value::OtherScalar(text))
            }
            b"date" => {
                let text = self.scalar(tag, 32, empty)?;
                // Only the canonical UTC plist representation is in scope.
                if text.len() != 20
                    || text.as_bytes()[4] != b'-'
                    || text.as_bytes()[7] != b'-'
                    || text.as_bytes()[10] != b'T'
                    || text.as_bytes()[13] != b':'
                    || text.as_bytes()[16] != b':'
                    || !text.ends_with('Z')
                    || !text
                        .bytes()
                        .enumerate()
                        .all(|(i, b)| matches!(i, 4 | 7 | 10 | 13 | 16 | 19) || b.is_ascii_digit())
                {
                    return Err(self.malformed(PlistProblem::Date));
                }
                let number = |start: usize, end: usize| {
                    text[start..end]
                        .parse::<u32>()
                        .map_err(|_| self.malformed(PlistProblem::Date))
                };
                let year = number(0, 4)?;
                let month = number(5, 7)?;
                let days = match month {
                    1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
                    4 | 6 | 9 | 11 => 30,
                    2 => {
                        if year.is_multiple_of(4)
                            && (!year.is_multiple_of(100) || year.is_multiple_of(400))
                        {
                            29
                        } else {
                            28
                        }
                    }
                    _ => return Err(self.malformed(PlistProblem::Date)),
                };
                if year == 0
                    || !(1..=days).contains(&number(8, 10)?)
                    || number(11, 13)? > 23
                    || number(14, 16)? > 59
                    || number(17, 19)? > 59
                {
                    return Err(self.malformed(PlistProblem::Date));
                }
                Ok(Value::OtherScalar(text))
            }
            _ => Err(self.malformed(PlistProblem::Structure)),
        }
    }
}

pub(super) fn parse_at(bytes: &[u8], stage: ResponseStage) -> Result<Value, Error> {
    parse_document(bytes, stage, false)
}

/// Allows a bare dictionary only after the caller authenticated the plaintext.
pub(super) fn parse_authenticated(bytes: &[u8]) -> Result<Value, Error> {
    parse_document(bytes, ResponseStage::AuthenticatedPlist, true)
}

fn parse_document(
    bytes: &[u8],
    stage: ResponseStage,
    allow_bare_dictionary: bool,
) -> Result<Value, Error> {
    preflight(bytes, stage)?;
    let mut parser = Parser {
        reader: Reader::from_reader(bytes),
        bytes,
        stage,
    };
    let mut event = parser.significant()?;
    if matches!(event, Event::Decl(_)) {
        event = parser.significant()?;
    }
    if matches!(event, Event::DocType(_)) {
        event = parser.significant()?;
    }
    let wrapped = matches!(&event, Event::Start(s) if s.name().as_ref() == b"plist");
    let root = if wrapped {
        parser.significant()?
    } else if allow_bare_dictionary
        && matches!(&event, Event::Start(s) | Event::Empty(s) if s.name().as_ref() == b"dict")
    {
        event
    } else {
        return Err(malformed(stage, PlistProblem::Structure));
    };
    let value = parser.value(root, 1)?;
    value
        .dict()
        .map_err(|_| malformed(stage, PlistProblem::Structure))?;
    if wrapped && !matches!(parser.significant()?, Event::End(e) if e.name().as_ref() == b"plist") {
        return Err(malformed(stage, PlistProblem::Structure));
    }
    if !matches!(parser.significant()?, Event::Eof) {
        return Err(malformed(stage, PlistProblem::Structure));
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn parse(bytes: &[u8]) -> Result<Value, Error> {
        parse_at(bytes, ResponseStage::OuterPlist)
    }
    fn wrapped(value: &str) -> Vec<u8> {
        format!("<plist version=\"1.0\"><dict><key>unknown</key>{value}</dict></plist>")
            .into_bytes()
    }
    #[test]
    fn exact_scalar_data_depth_and_element_bounds() {
        assert!(
            parse(&wrapped(&format!(
                "<string>{}</string>",
                "x".repeat(MAX_STRING)
            )))
            .is_ok()
        );
        assert!(matches!(
            parse(&wrapped(&format!(
                "<string>{}</string>",
                "x".repeat(MAX_STRING + 1)
            ))),
            Err(Error::TooLarge)
        ));
        for (len, valid) in [(MAX_DATA, true), (MAX_DATA + 1, false)] {
            let encoded = base64::engine::general_purpose::STANDARD.encode(vec![0; len]);
            assert_eq!(
                parse(&wrapped(&format!("<data>{encoded}</data>"))).is_ok(),
                valid
            );
        }
        for (n, valid) in [(6, true), (7, false)] {
            assert_eq!(
                parse(&wrapped(&format!(
                    "{}<string>x</string>{}",
                    "<array>".repeat(n),
                    "</array>".repeat(n)
                )))
                .is_ok(),
                valid
            );
        }
        // Outer plist/dict/key/array contribute eight markup events.
        for (n, valid) in [(504, true), (505, false)] {
            assert_eq!(
                parse(&wrapped(&format!("<array>{}</array>", "<true/>".repeat(n)))).is_ok(),
                valid
            );
        }
    }
    #[test]
    fn all_unknown_values_are_validated_and_partial_trees_fail_closed() {
        for value in [
            "<data>Zh==</data>",
            "<data>AA=A</data>",
            "<data>A</data>",
            "<string>&unknown;</string>",
            "<string>]]></string>",
            "<real>NaN</real>",
            "<real>inf</real>",
            "<date>2026-02-30T00:00:00Z</date>",
            "<date>2026-01-01T24:00:00Z</date>",
            "<dict><key>secret</key></dict>",
            "<dict><key/><string>a</string><key/><string>b</string></dict>",
        ] {
            assert!(parse(&wrapped(value)).is_err(), "{value}");
        }
        assert!(parse(&wrapped("<date>2024-02-29T00:00:00Z</date>")).is_ok());
        assert!(parse(&wrapped("<array><dict/><string/><data/><true/><false/><real>1.5</real><date>2026-09-11T00:00:00Z</date></array>")).is_ok());
    }
}
