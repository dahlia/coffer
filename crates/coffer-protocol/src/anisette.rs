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

//! The anisette boundary.
//!
//! Anisette is Apple's device-attestation scheme: every GSA request carries a
//! set of headers (a one-time password, a machine identifier, and device
//! description fields) that prove the request comes from a provisioned
//! client.  Generating them requires Apple's proprietary ADI library, which
//! is out of scope for this crate.  The protocol layer instead receives a
//! ready-made [`AnisetteData`] from a caller-supplied [`AnisetteProvider`]
//! and turns it into request headers and the `cpd` (client-provided data)
//! dictionary of GSA request bodies.
//!
//! The header names below are the ones observed on the wire by SideStore's
//! MPL-2.0 `omnisette` implementation; the values are opaque to this crate.
//! Coffer's project policy forbids an implicit fallback to a remote anisette
//! server, so a provider must fail rather than silently consult one.

use core::fmt;
use std::future::Future;

use zeroize::Zeroize;

/// Header carrying the anisette one-time password.
pub const ONE_TIME_PASSWORD_HEADER: &str = "X-Apple-I-MD";
/// Header carrying the anisette machine identifier.
pub const MACHINE_ID_HEADER: &str = "X-Apple-I-MD-M";
/// Header carrying the anisette routing information.
pub const ROUTING_INFO_HEADER: &str = "X-Apple-I-MD-RINFO";
/// Header carrying the local user identifier.
pub const LOCAL_USER_ID_HEADER: &str = "X-Apple-I-MD-LU";
/// Header carrying the device serial number.
pub const SERIAL_NUMBER_HEADER: &str = "X-Apple-I-SRL-NO";
/// Header describing the client software and hardware.
pub const CLIENT_INFO_HEADER: &str = "X-Mme-Client-Info";
/// Header carrying the device identifier.
pub const DEVICE_ID_HEADER: &str = "X-Mme-Device-Id";
/// Header carrying the client's current time.
pub const CLIENT_TIME_HEADER: &str = "X-Apple-I-Client-Time";
/// Header carrying the client's time zone.
pub const TIME_ZONE_HEADER: &str = "X-Apple-I-TimeZone";
/// Header carrying the client's locale.
pub const LOCALE_HEADER: &str = "X-Apple-Locale";

/// Maximum accepted length, in bytes, of any single anisette value.
pub const MAX_ANISETTE_VALUE_LEN: usize = 1024;

/// One set of anisette values, valid for a short window.
///
/// Every field is sent verbatim as an HTTP header value and, for GSA
/// requests, as a string inside the `cpd` dictionary.  Values must therefore
/// be non-empty printable ASCII of at most [`MAX_ANISETTE_VALUE_LEN`] bytes;
/// [`AnisetteData::validate`] enforces this and the authentication flow
/// refuses to send anything that fails it, which rules out header injection
/// from a misbehaving provider.
///
/// The one-time password and machine identifier are attestation secrets, so
/// `Debug` prints no field values and every field is zeroized on drop.
pub struct AnisetteData {
    /// One-time password, sent as [`ONE_TIME_PASSWORD_HEADER`].
    pub one_time_password: String,
    /// Machine identifier, sent as [`MACHINE_ID_HEADER`].
    pub machine_id: String,
    /// Routing information, sent as [`ROUTING_INFO_HEADER`].
    pub routing_info: String,
    /// Local user identifier, sent as [`LOCAL_USER_ID_HEADER`].
    pub local_user_id: String,
    /// Device serial number, sent as [`SERIAL_NUMBER_HEADER`].
    pub serial_number: String,
    /// Client description, sent as [`CLIENT_INFO_HEADER`].
    ///
    /// The value has the form
    /// `<Model> <OS;Version;Build> <com.apple.AuthKit/1 (...)>`.  It is sent
    /// exactly as supplied.
    pub client_info: String,
    /// Device identifier, sent as [`DEVICE_ID_HEADER`].
    pub device_id: String,
    /// Client wall-clock time in RFC 3339 form, sent as
    /// [`CLIENT_TIME_HEADER`].
    pub client_time: String,
    /// Client time zone, sent as [`TIME_ZONE_HEADER`].
    pub time_zone: String,
    /// Client locale such as `en_US`, sent as [`LOCALE_HEADER`] and as the
    /// `loc` entry of the `cpd` dictionary.
    pub locale: String,
}

impl AnisetteData {
    /// Checks that every value is safe to place in an HTTP header.
    ///
    /// # Errors
    ///
    /// Returns [`AnisetteError::InvalidValue`] naming the first offending
    /// header.
    pub fn validate(&self) -> Result<(), AnisetteError> {
        for (header, value) in self.entries() {
            if value.is_empty()
                || value.len() > MAX_ANISETTE_VALUE_LEN
                || !value.bytes().all(|b| (0x20..=0x7e).contains(&b))
            {
                return Err(AnisetteError::InvalidValue { header });
            }
        }
        Ok(())
    }

    /// Returns every value paired with its header name, in wire order.
    pub(crate) fn entries(&self) -> [(&'static str, &str); 10] {
        [
            (ONE_TIME_PASSWORD_HEADER, &self.one_time_password),
            (MACHINE_ID_HEADER, &self.machine_id),
            (ROUTING_INFO_HEADER, &self.routing_info),
            (LOCAL_USER_ID_HEADER, &self.local_user_id),
            (SERIAL_NUMBER_HEADER, &self.serial_number),
            (CLIENT_INFO_HEADER, &self.client_info),
            (DEVICE_ID_HEADER, &self.device_id),
            (CLIENT_TIME_HEADER, &self.client_time),
            (TIME_ZONE_HEADER, &self.time_zone),
            (LOCALE_HEADER, &self.locale),
        ]
    }
}

impl fmt::Debug for AnisetteData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AnisetteData(<redacted>)")
    }
}

/// Every field is wiped on drop.  The one-time password and machine
/// identifier are attestation secrets; the rest are wiped too rather than
/// maintaining a list of which fields count.
impl Drop for AnisetteData {
    fn drop(&mut self) {
        self.one_time_password.zeroize();
        self.machine_id.zeroize();
        self.routing_info.zeroize();
        self.local_user_id.zeroize();
        self.serial_number.zeroize();
        self.client_info.zeroize();
        self.device_id.zeroize();
        self.client_time.zeroize();
        self.time_zone.zeroize();
        self.locale.zeroize();
    }
}

/// Produces fresh anisette data on demand.
///
/// The authentication flow calls [`AnisetteProvider::anisette`] once per
/// authentication step, immediately before building the requests for that
/// step, and never caches the result.  A provider is therefore free to cache
/// internally, but it must return data that is still valid for the next few
/// seconds.
///
/// # Security
///
/// An implementation must generate the data locally or fail.  It must not
/// fall back to a third-party anisette server; doing so would send the
/// device's provisioning state to an untrusted host.
pub trait AnisetteProvider: Send + Sync {
    /// Returns a fresh set of anisette values.
    ///
    /// # Errors
    ///
    /// Resolves to [`AnisetteError`] when no valid data can be produced.
    fn anisette(&self) -> impl Future<Output = Result<AnisetteData, AnisetteError>> + Send;
}

/// Failure to obtain usable anisette data.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum AnisetteError {
    /// The provider could not produce data.
    Unavailable {
        /// Secret-free description of the failure.
        detail: String,
    },
    /// A value cannot be sent as an HTTP header.
    InvalidValue {
        /// Name of the header whose value was rejected.
        header: &'static str,
    },
}

impl fmt::Display for AnisetteError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unavailable { detail } => write!(f, "anisette data unavailable: {detail}"),
            Self::InvalidValue { header } => {
                write!(f, "anisette value for {header} is not a valid header value")
            }
        }
    }
}

impl std::error::Error for AnisetteError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> AnisetteData {
        AnisetteData {
            one_time_password: "otp".to_owned(),
            machine_id: "mid".to_owned(),
            routing_info: "17106176".to_owned(),
            local_user_id: "LU".to_owned(),
            serial_number: "0".to_owned(),
            client_info: "<Model> <macOS;13.1;22C65> <com.apple.AuthKit/1 (x)>".to_owned(),
            device_id: "DEVICE".to_owned(),
            client_time: "2026-01-01T00:00:00Z".to_owned(),
            time_zone: "UTC".to_owned(),
            locale: "en_US".to_owned(),
        }
    }

    #[test]
    fn valid_data_passes() {
        assert_eq!(sample().validate(), Ok(()));
    }

    #[test]
    fn control_characters_are_rejected() {
        let mut data = sample();
        data.machine_id = "mid\r\nX-Injected: 1".to_owned();
        assert_eq!(
            data.validate(),
            Err(AnisetteError::InvalidValue {
                header: MACHINE_ID_HEADER
            })
        );
    }

    #[test]
    fn empty_oversized_and_non_ascii_values_are_rejected() {
        let mut data = sample();
        data.locale = String::new();
        assert!(data.validate().is_err());
        let mut data = sample();
        data.serial_number = "9".repeat(MAX_ANISETTE_VALUE_LEN + 1);
        assert!(data.validate().is_err());
        let mut data = sample();
        data.time_zone = "UTC\u{e9}".to_owned();
        assert!(data.validate().is_err());
    }

    #[test]
    fn debug_is_redacted() {
        assert_eq!(format!("{:?}", sample()), "AnisetteData(<redacted>)");
    }
}
