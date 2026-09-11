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

//! Independent composition of the pinned request facts and authenticated envelope.
use super::{EpochMillis, IssuedToken, Service, SessionMaterialRef, TokenError as Error, xml};
use crate::{
    anisette::AnisetteData,
    transport::{Method, Request},
};
use aes_gcm::{AeadInOut, AesGcm, KeyInit, aead::consts::U16, aes::Aes256};
use base64::Engine as _;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use zeroize::{Zeroize, Zeroizing};

// Digest output is not itself a secret owner; guard it before any fallible write.
struct Checksum(sha2::digest::Output<Sha256>);
impl Drop for Checksum {
    fn drop(&mut self) {
        self.0.as_mut_slice().zeroize();
    }
}

struct Writer(Zeroizing<Vec<u8>>);
impl Writer {
    fn raw(&mut self, value: &[u8]) -> Result<(), Error> {
        if value.len() > xml::MAX_BODY - self.0.len() {
            return Err(Error::TooLarge);
        }
        self.0.extend_from_slice(value);
        Ok(())
    }
    fn text(&mut self, value: &str) -> Result<(), Error> {
        for c in value.chars() {
            match c {
                '&' => self.raw(b"&amp;")?,
                '<' => self.raw(b"&lt;")?,
                '>' => self.raw(b"&gt;")?,
                '"' => self.raw(b"&quot;")?,
                '\'' => self.raw(b"&apos;")?,
                _ => {
                    let mut scratch = Zeroizing::new([0u8; 4]);
                    self.raw(c.encode_utf8(&mut *scratch).as_bytes())?;
                }
            }
        }
        Ok(())
    }
    fn string(&mut self, key: &str, value: &str) -> Result<(), Error> {
        self.raw(b"<key>")?;
        self.text(key)?;
        self.raw(b"</key><string>")?;
        self.text(value)?;
        self.raw(b"</string>")
    }
    fn boolean(&mut self, key: &str, value: bool) -> Result<(), Error> {
        self.raw(b"<key>")?;
        self.text(key)?;
        self.raw(b"</key>")?;
        self.raw(if value { b"<true/>" } else { b"<false/>" })
    }
    fn data(&mut self, key: &str, value: &[u8]) -> Result<(), Error> {
        self.raw(b"<key>")?;
        self.text(key)?;
        self.raw(b"</key><data>")?;
        let mut encoded = Zeroizing::new(vec![0; value.len().div_ceil(3) * 4]);
        let len = base64::engine::general_purpose::STANDARD
            .encode_slice(value, &mut encoded)
            .map_err(|_| Error::TooLarge)?;
        self.raw(&encoded[..len])?;
        self.raw(b"</data>")
    }
}

pub(super) fn request(
    session: &SessionMaterialRef<'_>,
    service: Service,
    anisette: &AnisetteData,
) -> Result<Request, Error> {
    enum CpdValue<'a> {
        String(&'a str),
        Boolean(bool),
    }
    let mut mac = <Hmac<Sha256> as hmac::KeyInit>::new_from_slice(session.key)
        .map_err(|_| Error::InvalidSession)?;
    mac.update(b"apptokens");
    mac.update(session.account.as_bytes());
    mac.update(service.identifier().as_bytes());
    let checksum = Checksum(mac.finalize().into_bytes());
    let mut writer = Writer(Zeroizing::new(Vec::with_capacity(xml::MAX_BODY)));
    // Input bounds establish an upper bound below MAX_BODY; raw() also checks
    // every append so the secret-bearing allocation can never grow.
    let result = (|| {
        writer.raw(b"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\">\n<dict><key>Header</key><dict><key>Version</key><string>1.0.1</string></dict><key>Request</key><dict><key>app</key><array><string>")?;
        writer.text(service.identifier())?;
        writer.raw(b"</string></array>")?;
        writer.data("c", session.cookie)?;
        writer.data("checksum", &checksum.0)?;
        writer.raw(b"<key>cpd</key><dict>")?;
        let mut cpd: Vec<(&str, CpdValue<'_>)> = anisette
            .entries()
            .into_iter()
            .filter(|(k, _)| *k != crate::anisette::CLIENT_INFO_HEADER)
            .map(|(key, value)| (key, CpdValue::String(value)))
            .collect();
        // Token-only Boolean profile; auth::gsa intentionally retains M1 strings.
        cpd.extend([
            ("bootstrap", CpdValue::Boolean(true)),
            ("icscrec", CpdValue::Boolean(true)),
            ("loc", CpdValue::String(anisette.locale.as_str())),
            ("pbe", CpdValue::Boolean(false)),
            ("prkgen", CpdValue::Boolean(true)),
            ("svct", CpdValue::String("iCloud")),
        ]);
        cpd.sort_unstable_by_key(|(key, _)| *key);
        for (key, value) in cpd {
            match value {
                CpdValue::String(value) => writer.string(key, value)?,
                CpdValue::Boolean(value) => writer.boolean(key, value)?,
            }
        }
        writer.raw(b"</dict>")?;
        writer.string("o", "apptokens")?;
        writer.string("t", session.idms)?;
        writer.string("u", session.account)?;
        writer.raw(b"</dict></dict></plist>")
    })();
    result?;
    Ok(Request {
        method: Method::Post,
        url: crate::auth::GSA_ENDPOINT.to_owned(),
        headers: crate::auth::gsa::gsa_headers(anisette),
        body: Some(writer.0),
        max_response_body: xml::MAX_BODY,
    })
}

pub(super) fn response(
    bytes: &[u8],
    session: &SessionMaterialRef<'_>,
    service: Service,
) -> Result<IssuedToken, Error> {
    let outer = xml::parse(bytes)?;
    let response = outer.get("Response")?;
    let status = response.get("Status")?;
    let code = status.get("ec")?.integer()?;
    if let Some(message) = status.optional("em")? {
        message.text()?;
    }
    let secondary = status.optional("au")?;
    if let Some(selector) = secondary {
        selector.text()?;
    }
    if code != 0 || secondary.is_some() {
        return Err(Error::Rejected {
            code,
            additional_authentication: secondary.is_some(),
        });
    }
    let envelope = response.get("et")?.data()?;
    let plaintext = decrypt(envelope, session.key)?;
    let inner = xml::parse(&plaintext)?;
    let tokens = inner.get("t")?;
    if tokens.dict()?.len() != 1 || tokens.optional(service.identifier())?.is_none() {
        return Err(Error::Unsupported);
    }
    let entry = tokens.get(service.identifier())?;
    let token = entry.get("token")?.text()?;
    if token.is_empty() || token.chars().any(char::is_control) {
        return Err(Error::Malformed);
    }
    let expiry = entry.get("expiry")?.integer()?;
    let expires = EpochMillis::new(u64::try_from(expiry).map_err(|_| Error::Malformed)?)
        .map_err(|_| Error::Malformed)?;
    Ok(IssuedToken {
        account: Zeroizing::new(session.account.to_owned()),
        service,
        expires,
        token: Zeroizing::new(token.to_owned()),
    })
}

fn decrypt(envelope: &[u8], key: &[u8; 32]) -> Result<Zeroizing<Vec<u8>>, Error> {
    if envelope.len() > xml::MAX_DATA {
        return Err(Error::TooLarge);
    }
    if envelope.len() < 35 {
        return Err(Error::Malformed);
    }
    if &envelope[..3] != b"XYZ" {
        return Err(Error::Unsupported);
    }
    // The reviewed wire uses a 16-byte IV; Aes256Gcm's 12-byte alias is wrong.
    let cipher = AesGcm::<Aes256, U16>::new_from_slice(key).map_err(|_| Error::InvalidSession)?;
    let nonce = <&aes_gcm::Nonce<U16>>::try_from(&envelope[3..19]).map_err(|_| Error::Malformed)?;
    let tag_start = envelope.len() - 16;
    let tag = <&aes_gcm::Tag>::try_from(&envelope[tag_start..]).map_err(|_| Error::Malformed)?;
    let mut plaintext = Zeroizing::new(envelope[19..tag_start].to_vec());
    cipher
        .decrypt_inout_detached(nonce, &envelope[..3], plaintext.as_mut_slice().into(), tag)
        .map_err(|_| Error::AuthenticationTag)?;
    Ok(plaintext)
}
