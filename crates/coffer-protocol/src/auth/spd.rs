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

//! Decryption and extraction of the server-provided data (`spd`).
//!
//! A successful `complete` response carries `spd`, an AES-256-CBC
//! ciphertext with PKCS#7 padding whose key and IV are derived from the SRP
//! session key `K`:
//!
//! ```text
//! key = HMAC-SHA256(K, "extra data key:")
//! iv  = HMAC-SHA256(K, "extra data iv:")[0..16]
//! ```
//!
//! The plaintext is a property-list dictionary carrying the account
//! identifier (`adsid`), the IdMS token (`GsIdmsToken`), the 32-byte session
//! key (`sk`), an opaque cookie (`c`), a dictionary of per-service tokens
//! (`t`), and the account holder's given and family name (`fn`, `ln`).
//!
//! # Provenance
//!
//! The derivation labels, cipher mode, and field names are wire facts
//! corroborated against SideStore's MPL-2.0 `icloud-auth`.  Unknown fields are
//! ignored, never interpreted.

use std::collections::BTreeMap;

use aes::cipher::block_padding::Pkcs7;
use aes::cipher::{BlockModeDecrypt, KeyIvInit};
use hmac::{Hmac, KeyInit, Mac};
use plist::{Dictionary, Value};
use sha2::Sha256;
use zeroize::Zeroizing;

use super::error::{Malformed, MalformedReason};
use super::gsa::{ResponseLimits, get_data, get_string, parse_plist, wipe_tree};
use crate::secret::{AccountId, IdmsToken, SESSION_KEY_LEN, ServiceToken, SessionKey, wipe};

const KEY_LABEL: &[u8] = b"extra data key:";
const IV_LABEL: &[u8] = b"extra data iv:";

fn hmac_sha256(key: &[u8], label: &[u8]) -> Result<Zeroizing<[u8; 32]>, Malformed> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key)
        .map_err(|_| Malformed::new("spd", MalformedReason::InvalidParameter))?;
    mac.update(label);
    let mut tag = mac.finalize().into_bytes();
    let mut out = Zeroizing::new([0u8; 32]);
    out.copy_from_slice(&tag);
    wipe(tag.as_mut());
    Ok(out)
}

/// Decrypts `spd` under the session key.
///
/// `ciphertext` must already have been checked to be a non-empty multiple of
/// the block size.  The plaintext is returned in a zeroizing buffer.
pub(crate) fn decrypt(
    session_key: &[u8; SESSION_KEY_LEN],
    ciphertext: &[u8],
) -> Result<Zeroizing<Vec<u8>>, Malformed> {
    let key = hmac_sha256(session_key, KEY_LABEL)?;
    let iv = hmac_sha256(session_key, IV_LABEL)?;
    let decryptor = cbc::Decryptor::<aes::Aes256>::new_from_slices(&key[..], &iv[..16])
        .map_err(|_| Malformed::new("spd", MalformedReason::InvalidParameter))?;
    decryptor
        .decrypt_padded_vec::<Pkcs7>(ciphertext)
        .map(Zeroizing::new)
        .map_err(|_| Malformed::new("spd", MalformedReason::BadPadding))
}

/// The typed contents of a decrypted `spd`.
pub(crate) struct ServerProvidedData {
    pub account_id: AccountId,
    pub idms_token: IdmsToken,
    pub session_key: SessionKey,
    pub cookie: Vec<u8>,
    pub tokens: BTreeMap<String, ServiceToken>,
    pub given_name: Option<String>,
    pub family_name: Option<String>,
}

/// Parses decrypted `spd` plaintext.
///
/// The `plist` crate does not zeroize the `Value` tree it builds, so the
/// tree is held in a [`WipeOnDrop`] guard that overwrites every value when
/// this function returns, on the error paths as well.  The typed result
/// wraps every secret in a zeroizing type.
pub(crate) fn parse(
    plaintext: &[u8],
    limits: &ResponseLimits,
) -> Result<ServerProvidedData, Malformed> {
    let guard = WipeOnDrop(parse_plist(plaintext, "spd", limits)?);
    let dict = &guard.0;

    let account_id = AccountId::new(required_string(dict, "adsid", limits)?);
    let idms_token = IdmsToken::new(required_string(dict, "GsIdmsToken", limits)?);
    let sk = get_data(dict, "sk", SESSION_KEY_LEN)?;
    let sk: [u8; SESSION_KEY_LEN] = sk.try_into().map_err(|_| {
        Malformed::new(
            "sk",
            MalformedReason::WrongLength {
                expected: SESSION_KEY_LEN,
            },
        )
    })?;
    let session_key = SessionKey::new(sk);
    let cookie = get_data(dict, "c", limits.max_cookie)?.to_vec();
    let tokens = parse_tokens(dict, limits)?;
    let given_name = optional_string(dict, "fn", limits)?;
    let family_name = optional_string(dict, "ln", limits)?;

    Ok(ServerProvidedData {
        account_id,
        idms_token,
        session_key,
        cookie,
        tokens,
        given_name,
        family_name,
    })
}

/// Owns the decrypted property-list tree and wipes every value in it on
/// drop, including on the early-return paths of [`parse`].
///
/// The typed outputs are copies wrapped in zeroizing types; without this
/// guard the originals (the IdMS token, the session key, the service tokens)
/// would be freed without being overwritten.
struct WipeOnDrop(Dictionary);

impl Drop for WipeOnDrop {
    fn drop(&mut self) {
        let mut tree = Value::Dictionary(std::mem::replace(&mut self.0, Dictionary::new()));
        wipe_tree(&mut tree);
    }
}

/// Reads a string that must be present and non-empty.
///
/// An empty account identifier or token would produce a session that looks
/// valid but cannot authenticate anything, so it is rejected here.
fn required_string(
    dict: &Dictionary,
    key: &'static str,
    limits: &ResponseLimits,
) -> Result<String, Malformed> {
    let value = get_string(dict, key, limits.max_string)?;
    if value.is_empty() {
        return Err(Malformed::new(
            key,
            MalformedReason::TooShort { minimum: 1 },
        ));
    }
    Ok(value)
}

fn optional_string(
    dict: &Dictionary,
    key: &'static str,
    limits: &ResponseLimits,
) -> Result<Option<String>, Malformed> {
    if dict.contains_key(key) {
        get_string(dict, key, limits.max_string).map(Some)
    } else {
        Ok(None)
    }
}

/// Extracts the `t` dictionary: `{service id: {token: string, ...}}`.
///
/// The dictionary is optional.  Each entry must be a dictionary; an entry
/// without a `token` string is skipped because its meaning is unknown.
fn parse_tokens(
    dict: &Dictionary,
    limits: &ResponseLimits,
) -> Result<BTreeMap<String, ServiceToken>, Malformed> {
    let mut tokens = BTreeMap::new();
    let table = match dict.get("t") {
        None => return Ok(tokens),
        Some(Value::Dictionary(t)) => t,
        Some(_) => return Err(Malformed::new("t", MalformedReason::WrongType)),
    };
    if table.len() > limits.max_tokens {
        return Err(Malformed::new(
            "t",
            MalformedReason::TooLong {
                limit: limits.max_tokens,
            },
        ));
    }
    for (service, entry) in table {
        if service.len() > limits.max_string {
            return Err(Malformed::new(
                "t",
                MalformedReason::TooLong {
                    limit: limits.max_string,
                },
            ));
        }
        let Value::Dictionary(entry) = entry else {
            return Err(Malformed::new("t", MalformedReason::WrongType));
        };
        match entry.get("token") {
            Some(Value::String(token)) => {
                if token.is_empty() {
                    return Err(Malformed::new(
                        "token",
                        MalformedReason::TooShort { minimum: 1 },
                    ));
                }
                if token.len() > limits.max_string {
                    return Err(Malformed::new(
                        "token",
                        MalformedReason::TooLong {
                            limit: limits.max_string,
                        },
                    ));
                }
                tokens.insert(service.clone(), ServiceToken::new(token.clone()));
            }
            Some(_) => return Err(Malformed::new("token", MalformedReason::WrongType)),
            None => {}
        }
    }
    Ok(tokens)
}
