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

//! Finite observations from one initial SRP exchange.
//!
//! Reports own only enums: no raw callbacks, server text, lengths, hashes,
//! credentials, tokens, or authentication continuation capabilities. Observed
//! status shapes do not identify account policy. Validation fields report only
//! their named checks; SRP proof does not authenticate the status dictionary.

use super::{ResponseLimits, gsa};
use plist::{Dictionary, Value};

/// Last SRP round entered; local preparation belongs to init.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InitialPhase {
    /// No round entered.
    NotStarted,
    /// Initial SRP round.
    Init,
    /// Completion SRP round.
    Complete,
}

/// Terminal result, without a session or a continuation capability.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InitialOutcome {
    /// The exchange failed; no retry is implied.
    Failed,
    /// Proof and SPD passed without a secondary selector; data was discarded.
    CompleteWithoutSecondary,
    /// Proof and SPD passed with the trusted-device selector; no code was requested.
    TrustedDeviceRequired,
    /// Proof and SPD passed with another selector; nothing further was sent.
    Unsupported,
}

/// Fixed failure category with no source, message, code, or size payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Failure {
    /// No failure has been observed.
    None,
    /// Local anisette was unavailable or invalid.
    Anisette,
    /// Local entropy failed.
    Entropy,
    /// Transport did not deliver a response.
    Transport,
    /// A non-success HTTP response was received.
    Http,
    /// The parsed status reported a nonzero protocol error.
    Protocol,
    /// Parsing, bounds, or SPD decryption failed.
    Malformed,
    /// The selected password protocol is unsupported.
    UnsupportedProtocol,
    /// The SRP server proof did not verify.
    Proof,
    /// An internal request-building invariant failed.
    Internal,
    /// An error outside the initial exchange's known categories occurred.
    UnrecognizedVariant,
}
impl Failure {
    pub(super) fn classify(error: &super::AuthErrorKind) -> Self {
        use super::AuthErrorKind;
        match error {
            AuthErrorKind::Anisette(_) => Self::Anisette,
            AuthErrorKind::Entropy(_) => Self::Entropy,
            AuthErrorKind::Transport(_) => Self::Transport,
            AuthErrorKind::HttpStatus(_) => Self::Http,
            AuthErrorKind::Protocol(_) => Self::Protocol,
            AuthErrorKind::Malformed(_) => Self::Malformed,
            AuthErrorKind::UnsupportedProtocol { .. } => Self::UnsupportedProtocol,
            AuthErrorKind::ServerProofMismatch => Self::Proof,
            AuthErrorKind::Internal { .. } => Self::Internal,
            _ => Self::UnrecognizedVariant,
        }
    }
}

/// HTTP class actually returned by the transport.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpClass {
    /// Transport returned no response.
    NotObserved,
    /// HTTP 2xx.
    Success,
    /// HTTP 3xx.
    Redirect,
    /// HTTP 4xx.
    ClientError,
    /// HTTP 5xx.
    ServerError,
    /// Another HTTP class; exact status is discarded.
    Other,
}

/// Location selected by the existing status parser.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatusLocation {
    /// No bounded response dictionary was parsed.
    NotParsed,
    /// Response.Status dictionary.
    NestedStatus,
    /// Response itself, when Status is absent.
    ResponseFallback,
    /// Response or Status has an invalid shape.
    Invalid,
}

/// Shape of the protocol status code, without its value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ec {
    /// No status dictionary.
    NotObserved,
    /// No ec field.
    Missing,
    /// Integer zero.
    Zero,
    /// Nonzero integer.
    Nonzero,
    /// Not an integer representable by the existing parser.
    InvalidType,
}

/// Diagnostic-only hsc shape; never changes authentication decisions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Hsc {
    /// No status dictionary.
    NotObserved,
    /// No hsc field.
    Absent,
    /// Integer 200.
    Integer200,
    /// Integer 409.
    Integer409,
    /// Integer 433.
    Integer433,
    /// Integer 434.
    Integer434,
    /// Another integer; exact value is discarded.
    OtherInteger,
    /// Not an integer; numeric strings are not coerced.
    InvalidType,
}

/// Bounded selector class; these labels do not establish account state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Au {
    /// No status dictionary.
    NotObserved,
    /// No au field.
    Absent,
    /// Empty string, distinct from absent.
    Empty,
    /// Exact trustedDeviceSecondaryAuth.
    TrustedDevice,
    /// Exact secondaryAuth.
    Secondary,
    /// Exact repair; no repair operation is implemented.
    Repair,
    /// ASCII case-insensitive http:// or https:// prefix only; no URL is retained.
    HttpUrlLike,
    /// Another bounded string; value is discarded.
    OtherString,
    /// Not a string.
    InvalidType,
    /// String exceeds the existing byte bound; no length is retained.
    BoundsRejected,
}

/// Whether a specific validation was reached and passed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verification {
    /// Validation was not reached.
    NotReached,
    /// Validation completed successfully.
    Passed,
    /// Validation was reached and failed.
    Failed,
}

/// One fixed response slot. All fields are finite observations, not credentials.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExchangeReport {
    /// HTTP class received before body validation.
    pub http: HttpClass,
    /// Existing parser's status location.
    pub location: StatusLocation,
    /// Protocol error-code shape.
    pub ec: Ec,
    /// Diagnostic-only hsc shape.
    pub hsc: Hsc,
    /// Bounded selector class.
    pub au: Au,
    /// Existing status parsing and success check, including em/au validation.
    pub status_accepted: Verification,
}
impl Default for ExchangeReport {
    fn default() -> Self {
        Self {
            http: HttpClass::NotObserved,
            location: StatusLocation::NotParsed,
            ec: Ec::NotObserved,
            hsc: Hsc::NotObserved,
            au: Au::NotObserved,
            status_accepted: Verification::NotReached,
        }
    }
}
/// Terminal report from [`super::PasswordLogin::diagnose_initial`].
///
/// No session, token, raw error, or second-factor capability survives in this
/// value. Failure ends the consumed attempt, without retry. A passed report
/// proves only this exchange's validation, not account policy or future access.
/// The existing plist parser keeps the last duplicate key; observations describe
/// only that dictionary survivor, without proving raw-wire uniqueness.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InitialAuthReport {
    /// Last round entered.
    pub phase: InitialPhase,
    /// Terminal outcome after dropping server-provided data.
    pub outcome: InitialOutcome,
    /// Fixed failure category; never an underlying error object.
    pub failure: Failure,
    /// Initial response observations.
    pub init: ExchangeReport,
    /// Completion response observations.
    pub complete: ExchangeReport,
    /// SRP server-proof verification.
    pub proof_verified: Verification,
    /// SPD decryption and parsing, only after server-proof verification.
    pub spd_parsed: Verification,
}
impl Default for InitialAuthReport {
    fn default() -> Self {
        Self {
            phase: InitialPhase::NotStarted,
            outcome: InitialOutcome::Failed,
            failure: Failure::None,
            init: ExchangeReport::default(),
            complete: ExchangeReport::default(),
            proof_verified: Verification::NotReached,
            spd_parsed: Verification::NotReached,
        }
    }
}

// None is the normal authentication path: no status inspection or collection.
#[derive(Default)]
pub(super) struct Observer(pub Option<InitialAuthReport>);
impl Observer {
    pub fn phase(&mut self, phase: InitialPhase) {
        if let Some(report) = &mut self.0 {
            report.phase = phase;
        }
    }
    pub fn slot(&mut self) -> Option<&mut ExchangeReport> {
        self.0.as_mut().map(|r| match r.phase {
            InitialPhase::Complete => &mut r.complete,
            _ => &mut r.init,
        })
    }
    pub fn http(&mut self, status: u16) {
        if let Some(slot) = self.slot() {
            slot.http = match status {
                200..=299 => HttpClass::Success,
                300..=399 => HttpClass::Redirect,
                400..=499 => HttpClass::ClientError,
                500..=599 => HttpClass::ServerError,
                _ => HttpClass::Other,
            };
        }
    }
    pub fn status(&mut self, response: &Dictionary, limits: &ResponseLimits) {
        let Some(slot) = self.slot() else {
            return;
        };
        let Ok(status) = gsa::status_dictionary(response) else {
            slot.location = StatusLocation::Invalid;
            return;
        };
        slot.location = if response.contains_key("Status") {
            StatusLocation::NestedStatus
        } else {
            StatusLocation::ResponseFallback
        };
        slot.ec = match status.get("ec") {
            None => Ec::Missing,
            Some(Value::Integer(i)) => match i.as_signed() {
                Some(0) => Ec::Zero,
                Some(_) => Ec::Nonzero,
                None => Ec::InvalidType,
            },
            Some(_) => Ec::InvalidType,
        };
        slot.hsc = match status.get("hsc") {
            None => Hsc::Absent,
            Some(Value::Integer(i)) => match i.as_signed() {
                Some(200) => Hsc::Integer200,
                Some(409) => Hsc::Integer409,
                Some(433) => Hsc::Integer433,
                Some(434) => Hsc::Integer434,
                _ => Hsc::OtherInteger,
            },
            Some(_) => Hsc::InvalidType,
        };
        slot.au = match status.get("au") {
            None => Au::Absent,
            Some(Value::String(s)) if s.len() > limits.max_string => Au::BoundsRejected,
            Some(Value::String(s)) => match s.as_str() {
                "" => Au::Empty,
                gsa::TRUSTED_DEVICE_AU => Au::TrustedDevice,
                "secondaryAuth" => Au::Secondary,
                "repair" => Au::Repair,
                _ if s
                    .get(..7)
                    .is_some_and(|p| p.eq_ignore_ascii_case("http://"))
                    || s.get(..8)
                        .is_some_and(|p| p.eq_ignore_ascii_case("https://")) =>
                {
                    Au::HttpUrlLike
                }
                _ => Au::OtherString,
            },
            Some(_) => Au::InvalidType,
        };
    }
    pub fn status_accepted(&mut self, value: Verification) {
        if let Some(slot) = self.slot() {
            slot.status_accepted = value;
        }
    }
    pub fn invalid_location(&mut self) {
        if let Some(slot) = self.slot() {
            slot.location = StatusLocation::Invalid;
        }
    }
    pub fn proof(&mut self, value: Verification) {
        if let Some(report) = &mut self.0 {
            report.proof_verified = value;
        }
    }
    pub fn spd(&mut self, value: Verification) {
        if let Some(report) = &mut self.0 {
            report.spd_parsed = value;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn observe(dict: &Dictionary) -> ExchangeReport {
        let mut observer = Observer(Some(InitialAuthReport::default()));
        observer.phase(InitialPhase::Init);
        observer.status(dict, &ResponseLimits::default());
        observer.0.unwrap().init
    }
    fn status() -> Dictionary {
        let mut dict = Dictionary::new();
        dict.insert("ec".into(), Value::Integer(0.into()));
        dict
    }

    #[test]
    fn hsc_is_diagnostic_only_and_never_coerces_strings() {
        for (value, expected) in [
            (None, Hsc::Absent),
            (Some(Value::Integer(200.into())), Hsc::Integer200),
            (Some(Value::Integer(409.into())), Hsc::Integer409),
            (Some(Value::Integer(433.into())), Hsc::Integer433),
            (Some(Value::Integer(434.into())), Hsc::Integer434),
            (Some(Value::Integer(987654321.into())), Hsc::OtherInteger),
            (Some(Value::Integer(u64::MAX.into())), Hsc::OtherInteger),
            (Some(Value::String("433".into())), Hsc::InvalidType),
            (Some(Value::Boolean(true)), Hsc::InvalidType),
        ] {
            let mut dict = status();
            if let Some(value) = value {
                dict.insert("hsc".into(), value);
            }
            assert_eq!(observe(&dict).hsc, expected);
            assert!(
                gsa::parse_status(&dict, &ResponseLimits::default())
                    .unwrap()
                    .into_result()
                    .is_ok()
            );
        }
    }

    #[test]
    fn au_classification_is_exact_bounded_and_discards_arbitrary_values() {
        for (value, expected) in [
            (None, Au::Absent),
            (Some(Value::String("".into())), Au::Empty),
            (Some(Value::String("repair".into())), Au::Repair),
            (Some(Value::String("Repair".into())), Au::OtherString),
            (Some(Value::String("repair ".into())), Au::OtherString),
            (Some(Value::String("ｒｅｐａｉｒ".into())), Au::OtherString),
            (
                Some(Value::String("securityUpgrade".into())),
                Au::OtherString,
            ),
            (Some(Value::String("https://".into())), Au::HttpUrlLike),
            (
                Some(Value::String("HtTp://sentinel.invalid/?private".into())),
                Au::HttpUrlLike,
            ),
            (Some(Value::String("/relative".into())), Au::OtherString),
            (
                Some(Value::String("ftp://synthetic.invalid".into())),
                Au::OtherString,
            ),
            (
                Some(Value::String("https://".to_owned() + &"x".repeat(1024))),
                Au::BoundsRejected,
            ),
            (Some(Value::String("x".repeat(1024))), Au::OtherString),
            (Some(Value::Integer(1234567.into())), Au::InvalidType),
        ] {
            let mut dict = status();
            if let Some(value) = value {
                dict.insert("au".into(), value);
            }
            let observed = observe(&dict);
            assert_eq!(observed.au, expected);
            let parsed = gsa::parse_status(&dict, &ResponseLimits::default());
            assert_eq!(
                parsed.is_err(),
                matches!(expected, Au::BoundsRejected | Au::InvalidType)
            );
            let output = format!("{observed:?}");
            for private in ["sentinel", "private", "1234567", "ｒｅｐａｉｒ"] {
                assert!(!output.contains(private));
            }
        }
        let a = {
            let mut d = status();
            d.insert("au".into(), Value::String("abcdef".into()));
            observe(&d)
        };
        let b = {
            let mut d = status();
            d.insert(
                "au".into(),
                Value::String("私\n\u{1b} sentinel of a different length".into()),
            );
            observe(&d)
        };
        assert_eq!(format!("{a:?}"), format!("{b:?}"));
    }

    #[test]
    fn location_and_ec_match_existing_parser_policy() {
        for (value, expected) in [
            (None, Ec::Missing),
            (Some(Value::Integer(0.into())), Ec::Zero),
            (Some(Value::Integer((-9876543).into())), Ec::Nonzero),
            (Some(Value::Integer(u64::MAX.into())), Ec::InvalidType),
            (Some(Value::String("0".into())), Ec::InvalidType),
        ] {
            let mut dict = Dictionary::new();
            if let Some(value) = value {
                dict.insert("ec".into(), value);
            }
            assert_eq!(observe(&dict).ec, expected);
            assert_eq!(observe(&dict).location, StatusLocation::ResponseFallback);
            let mut nested = Dictionary::new();
            nested.insert("au".into(), Value::String("repair".into()));
            nested.insert("Status".into(), Value::Dictionary(dict));
            let report = observe(&nested);
            assert_eq!(report.ec, expected);
            assert_eq!(report.au, Au::Absent);
            assert_eq!(report.location, StatusLocation::NestedStatus);
        }
        let mut dict = status();
        dict.insert("Status".into(), Value::String("private".into()));
        let report = observe(&dict);
        assert_eq!(report.location, StatusLocation::Invalid);
        assert_eq!(report.au, Au::NotObserved);
        assert_eq!(report.ec, Ec::NotObserved);
    }
}
