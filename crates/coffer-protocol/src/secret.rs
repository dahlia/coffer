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

//! Secret-bearing and identifying value types.
//!
//! Every type here exists so that a secret or account identifier cannot be
//! printed by accident.  None of them implements `Display`, every `Debug`
//! implementation prints a fixed redaction marker instead of the value, and
//! the secret types wipe their memory on drop through [`zeroize`].
//!
//! Types that hold long-lived secrets ([`IdmsToken`], [`SessionKey`],
//! [`ServiceToken`]) expose their value only through an explicitly named
//! `expose_secret` method, so that every read of a secret is visible in a
//! diff.  The caller-supplied inputs ([`Password`], [`VerificationCode`]) have
//! no public accessor at all: they are consumed by the authentication flow and
//! never leave this crate.

use core::fmt;

use zeroize::{Zeroize, Zeroizing};

/// Maximum accepted length, in bytes, of an [`AccountName`].
///
/// Apple Account names are e-mail addresses or phone numbers; anything longer
/// than this is rejected before it can reach the wire.
pub const MAX_ACCOUNT_NAME_LEN: usize = 256;

/// Number of digits in a trusted-device verification code.
pub const VERIFICATION_CODE_LEN: usize = 6;

/// Length in bytes of the GSA session key `sk`.
pub const SESSION_KEY_LEN: usize = 32;

const REDACTED: &str = "<redacted>";

macro_rules! redacted_debug {
    ($ty:ident) => {
        impl fmt::Debug for $ty {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, concat!(stringify!($ty), "({})"), REDACTED)
            }
        }
    };
}

/// An Apple Account password supplied by the user.
///
/// The password is used exactly once, to derive the SRP password key after
/// the server has revealed the salt and iteration count, and the
/// authentication flow drops it immediately afterwards.  The flow never
/// stores a password across a two-factor prompt: post-two-factor
/// re-authentication takes a fresh `Password`.
///
/// The value is zeroized on drop and has no accessor outside this crate.
pub struct Password(Zeroizing<String>);

impl Password {
    /// Wraps a password.
    ///
    /// Takes ownership of the `String` so that the only copy of the password
    /// lives inside the zeroizing wrapper; callers should avoid keeping
    /// another copy around.
    #[must_use]
    pub fn new(password: String) -> Self {
        Self(Zeroizing::new(password))
    }

    pub(crate) fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

redacted_debug!(Password);

/// A trusted-device verification code entered by the user.
///
/// The code is submitted exactly once through
/// [`CodeRequested::submit_code`](crate::auth::CodeRequested::submit_code).
/// It is zeroized on drop and is never included in errors or `Debug` output.
pub struct VerificationCode(Zeroizing<String>);

/// Reasons a verification code is rejected before any network request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InvalidVerificationCode {
    /// The code does not have exactly [`VERIFICATION_CODE_LEN`] characters.
    Length,
    /// The code contains a character other than an ASCII digit.
    NotDigits,
}

impl fmt::Display for InvalidVerificationCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Length => write!(
                f,
                "verification code must be exactly {VERIFICATION_CODE_LEN} digits"
            ),
            Self::NotDigits => f.write_str("verification code must contain only ASCII digits"),
        }
    }
}

impl std::error::Error for InvalidVerificationCode {}

impl VerificationCode {
    /// Validates and wraps a verification code.
    ///
    /// Takes ownership of the `String` so that it is zeroized whether or not
    /// validation succeeds.  Only strings of exactly
    /// [`VERIFICATION_CODE_LEN`] ASCII digits are accepted; rejecting anything
    /// else locally means a mistyped code never consumes a server-side
    /// verification attempt.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidVerificationCode`] when the shape is wrong.
    pub fn parse(code: String) -> Result<Self, InvalidVerificationCode> {
        let code = Zeroizing::new(code);
        if code.len() != VERIFICATION_CODE_LEN {
            return Err(InvalidVerificationCode::Length);
        }
        if !code.bytes().all(|b| b.is_ascii_digit()) {
            return Err(InvalidVerificationCode::NotDigits);
        }
        Ok(Self(code))
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

redacted_debug!(VerificationCode);

/// The name of an Apple Account, usually an e-mail address.
///
/// This is an identifier rather than a secret, but Coffer treats account
/// identifiers as private: `Debug` output is redacted and the value never
/// appears in errors.  It is sent to Apple as the SRP identity `u` and is
/// hashed into the SRP client proof.
#[derive(Clone, PartialEq, Eq)]
pub struct AccountName(String);

/// Reasons an account name is rejected before any network request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InvalidAccountName {
    /// The name is empty.
    Empty,
    /// The name is longer than [`MAX_ACCOUNT_NAME_LEN`] bytes.
    TooLong,
    /// The name contains an ASCII control character.
    ControlCharacter,
}

impl fmt::Display for InvalidAccountName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => f.write_str("account name must not be empty"),
            Self::TooLong => write!(
                f,
                "account name must be at most {MAX_ACCOUNT_NAME_LEN} bytes"
            ),
            Self::ControlCharacter => {
                f.write_str("account name must not contain control characters")
            }
        }
    }
}

impl std::error::Error for InvalidAccountName {}

impl AccountName {
    /// Validates and wraps an account name.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidAccountName`] for an empty, oversized, or
    /// control-character-bearing name.
    pub fn new(name: String) -> Result<Self, InvalidAccountName> {
        if name.is_empty() {
            return Err(InvalidAccountName::Empty);
        }
        if name.len() > MAX_ACCOUNT_NAME_LEN {
            return Err(InvalidAccountName::TooLong);
        }
        if name.chars().any(char::is_control) {
            return Err(InvalidAccountName::ControlCharacter);
        }
        Ok(Self(name))
    }

    /// Returns the account name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

redacted_debug!(AccountName);

impl Drop for AccountName {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// The account's directory services identifier (`adsid`).
///
/// Apple returns it in the decrypted server-provided data after a successful
/// password exchange.  Together with the [`IdmsToken`] it forms the
/// `X-Apple-Identity-Token` header used by the two-factor endpoints.  It is
/// an identifier, not a secret, but it is redacted from `Debug` output like
/// every other account identifier in Coffer.
#[derive(Clone, PartialEq, Eq)]
pub struct AccountId(String);

impl AccountId {
    pub(crate) fn new(id: String) -> Self {
        Self(id)
    }

    /// Returns the identifier.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

redacted_debug!(AccountId);

impl Drop for AccountId {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// The GS IdMS token (`GsIdmsToken`) that identifies an authenticated session.
///
/// This is a bearer credential: anyone holding it together with the
/// [`AccountId`] can call the two-factor endpoints and request service
/// tokens.  It is zeroized on drop.
pub struct IdmsToken(Zeroizing<String>);

impl IdmsToken {
    pub(crate) fn new(token: String) -> Self {
        Self(Zeroizing::new(token))
    }

    /// Returns the token.
    ///
    /// The name is deliberately loud: every call site is a place where a
    /// bearer credential leaves its wrapper.
    #[must_use]
    pub fn expose_secret(&self) -> &str {
        &self.0
    }
}

redacted_debug!(IdmsToken);

/// The GSA session key (`sk`) established by the SRP exchange.
///
/// It keys the HMAC checksum of later `apptokens` requests and decrypts the
/// tokens they return.  It is zeroized on drop.
pub struct SessionKey(Zeroizing<[u8; SESSION_KEY_LEN]>);

impl SessionKey {
    pub(crate) fn new(key: [u8; SESSION_KEY_LEN]) -> Self {
        Self(Zeroizing::new(key))
    }

    /// Returns the key bytes.
    #[must_use]
    pub fn expose_secret(&self) -> &[u8; SESSION_KEY_LEN] {
        &self.0
    }
}

redacted_debug!(SessionKey);

/// A per-service token returned in the server-provided data.
///
/// The most important one is the password-equivalent token (PET) under the
/// `com.apple.gs.idms.pet` service identifier.  Tokens are zeroized on drop.
pub struct ServiceToken(Zeroizing<String>);

impl ServiceToken {
    pub(crate) fn new(token: String) -> Self {
        Self(Zeroizing::new(token))
    }

    /// Returns the token.
    #[must_use]
    pub fn expose_secret(&self) -> &str {
        &self.0
    }
}

redacted_debug!(ServiceToken);

/// Zeroizes a byte buffer in place through a volatile write.
pub(crate) fn wipe(bytes: &mut [u8]) {
    bytes.zeroize();
}

/// Zeroizes a string's whole allocation and empties it.
pub(crate) fn wipe_string(s: &mut String) {
    s.zeroize();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_output_is_redacted() {
        let password = Password::new("hunter2".to_owned());
        assert_eq!(format!("{password:?}"), "Password(<redacted>)");
        let code = VerificationCode::parse("123456".to_owned()).unwrap();
        assert_eq!(format!("{code:?}"), "VerificationCode(<redacted>)");
        let name = AccountName::new("someone@example.com".to_owned()).unwrap();
        assert_eq!(format!("{name:?}"), "AccountName(<redacted>)");
        assert_eq!(
            format!("{:?}", AccountId::new("000".to_owned())),
            "AccountId(<redacted>)"
        );
        assert_eq!(
            format!("{:?}", IdmsToken::new("tok".to_owned())),
            "IdmsToken(<redacted>)"
        );
        assert_eq!(
            format!("{:?}", SessionKey::new([7; SESSION_KEY_LEN])),
            "SessionKey(<redacted>)"
        );
        assert_eq!(
            format!("{:?}", ServiceToken::new("pet".to_owned())),
            "ServiceToken(<redacted>)"
        );
    }

    #[test]
    fn verification_code_shape_is_enforced() {
        assert_eq!(
            VerificationCode::parse("12345".to_owned()).unwrap_err(),
            InvalidVerificationCode::Length
        );
        assert_eq!(
            VerificationCode::parse("1234567".to_owned()).unwrap_err(),
            InvalidVerificationCode::Length
        );
        assert_eq!(
            VerificationCode::parse("12345a".to_owned()).unwrap_err(),
            InvalidVerificationCode::NotDigits
        );
        assert_eq!(
            VerificationCode::parse("１２３４５６".to_owned()).unwrap_err(),
            InvalidVerificationCode::Length
        );
        assert_eq!(
            VerificationCode::parse("000000".to_owned())
                .unwrap()
                .as_str(),
            "000000"
        );
    }

    #[test]
    fn account_name_shape_is_enforced() {
        assert_eq!(
            AccountName::new(String::new()).unwrap_err(),
            InvalidAccountName::Empty
        );
        assert_eq!(
            AccountName::new("a".repeat(MAX_ACCOUNT_NAME_LEN + 1)).unwrap_err(),
            InvalidAccountName::TooLong
        );
        assert_eq!(
            AccountName::new("a\r\nb".to_owned()).unwrap_err(),
            InvalidAccountName::ControlCharacter
        );
        assert!(AccountName::new("a".repeat(MAX_ACCOUNT_NAME_LEN)).is_ok());
    }
}
