// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Derived from SideStore apple-private-apis
// omnisette/src/anisette_headers_provider.rs and local composition in
// omnisette/src/adi_proxy.rs.
// Upstream repository: https://github.com/SideStore/apple-private-apis
// Upstream commit: 03beb1aa42991ccdad6214dee77e72282bef461f
// Modified by the Coffer project in 2026 to compose only existing local state,
// return NotProvisioned without side effects, and retain secrets in redacted
// owning types. The modified file remains MPL-2.0.

//! Side-effect-free local anisette header composition.

use core::fmt;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;

use crate::{AdiProxy, AnisetteError, DeviceIdentity, SecretString};

/// Names of the seven values produced by the local composition layer.
pub const LOCAL_HEADER_NAMES: [&str; 7] = [
    "X-Apple-I-MD",
    "X-Apple-I-MD-M",
    "X-Apple-I-MD-RINFO",
    "X-Apple-I-MD-LU",
    "X-Apple-I-SRL-NO",
    "X-Mme-Client-Info",
    "X-Mme-Device-Id",
];

const CLIENT_INFO: &str =
    "<MacBookPro13,2> <macOS;13.1;22C65> <com.apple.AuthKit/1 (com.apple.dt.Xcode/3594.4.19)>";

/// Seven local anisette values retained in redacted, zeroizing storage.
pub struct LocalAnisetteHeaders {
    values: [SecretString; 7],
}

impl LocalAnisetteHeaders {
    /// Iterates over exact header names and explicitly exposed values.
    pub fn iter(&self) -> impl ExactSizeIterator<Item = (&'static str, &str)> {
        LOCAL_HEADER_NAMES
            .into_iter()
            .zip(self.values.iter().map(SecretString::expose_secret))
    }
}

impl fmt::Debug for LocalAnisetteHeaders {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("LocalAnisetteHeaders([REDACTED])")
    }
}

/// Composes local headers from one caller-supplied ADI proxy.
///
/// Construction configures the derived Android ID but performs no loading,
/// persistence, provisioning, or network operation. Header retrieval checks
/// provisioned state exactly once. An unprovisioned result stops immediately.
pub struct LocalAnisetteProvider<Proxy: AdiProxy> {
    proxy: Proxy,
    identity: DeviceIdentity,
}

impl<Proxy: AdiProxy> LocalAnisetteProvider<Proxy> {
    /// Creates a local provider and configures its deterministic Android ID.
    ///
    /// # Errors
    ///
    /// Returns a stage-safe proxy failure if Android ID configuration fails.
    pub fn new(mut proxy: Proxy, identity: DeviceIdentity) -> Result<Self, AnisetteError> {
        proxy.set_android_id(identity.android_id())?;
        Ok(Self { proxy, identity })
    }

    /// Returns local headers only when existing state is already provisioned.
    ///
    /// This method never calls provisioning methods, performs network I/O, or
    /// retries. If the single state check is false it returns
    /// [`AnisetteError::NotProvisioned`] before requesting any other value.
    ///
    /// # Errors
    ///
    /// Returns [`AnisetteError::NotProvisioned`], a stage-safe proxy failure,
    /// or [`AnisetteError::InvalidData`] for malformed helper text.
    pub fn get_headers(&mut self) -> Result<LocalAnisetteHeaders, AnisetteError> {
        if !self.proxy.is_machine_provisioned()? {
            return Err(AnisetteError::NotProvisioned);
        }

        let otp = self.proxy.request_otp(self.identity.local_user_id())?;
        let values = [
            SecretString::try_from_string(
                STANDARD.encode(otp.one_time_password().expose_secret()),
            )?,
            SecretString::try_from_string(STANDARD.encode(otp.machine_id().expose_secret()))?,
            SecretString::try_from_string(self.proxy.routing_info()?)?,
            SecretString::try_from_string(
                self.identity.local_user_id().expose_secret().to_owned(),
            )?,
            SecretString::try_from_string(self.proxy.serial_number()?)?,
            SecretString::try_from_string(CLIENT_INFO.to_owned())?,
            SecretString::try_from_string(
                self.identity.device_identifier().expose_secret().to_owned(),
            )?,
        ];
        Ok(LocalAnisetteHeaders { values })
    }

    /// Returns the owned proxy for a later explicit provisioning operation.
    #[must_use]
    pub fn into_proxy(self) -> Proxy {
        self.proxy
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;
    use crate::{AdiError, OtpMaterial, ProvisioningSession, ProvisioningStart, SecretBytes};

    #[derive(Clone, Copy, Default, Eq, PartialEq)]
    enum FailureStage {
        #[default]
        None,
        SetAndroidId,
        Provisioned,
        Otp,
    }

    #[derive(Default)]
    struct FakeProxy {
        provisioned: bool,
        calls: Vec<&'static str>,
        routing: String,
        serial: String,
        failure: FailureStage,
    }

    impl AdiProxy for FakeProxy {
        fn is_machine_provisioned(&mut self) -> Result<bool, AdiError> {
            self.calls.push("is_machine_provisioned");
            if self.failure == FailureStage::Provisioned {
                return Err(AdiError::OperationFailed);
            }
            Ok(self.provisioned)
        }

        fn set_android_id(&mut self, android_id: &[u8; 16]) -> Result<(), AdiError> {
            assert_eq!(android_id, b"00112233-4455-66");
            self.calls.push("set_android_id");
            if self.failure == FailureStage::SetAndroidId {
                return Err(AdiError::OperationFailed);
            }
            Ok(())
        }

        fn start_provisioning(
            &mut self,
            _spim: SecretBytes,
            _local_user_id: &SecretString,
        ) -> Result<ProvisioningStart, AdiError> {
            self.calls.push("start_provisioning");
            Err(AdiError::OperationFailed)
        }

        fn end_provisioning(
            &mut self,
            _session: ProvisioningSession,
            _ptm: SecretBytes,
            _tk: SecretBytes,
        ) -> Result<(), AdiError> {
            self.calls.push("end_provisioning");
            Err(AdiError::OperationFailed)
        }

        fn destroy_provisioning(&mut self, _session: ProvisioningSession) -> Result<(), AdiError> {
            self.calls.push("destroy_provisioning");
            Err(AdiError::OperationFailed)
        }

        fn request_otp(&mut self, _local_user_id: &SecretString) -> Result<OtpMaterial, AdiError> {
            self.calls.push("request_otp");
            if self.failure == FailureStage::Otp {
                return Err(AdiError::OperationFailed);
            }
            Ok(OtpMaterial::new(
                SecretBytes::try_from_vec(b"otp-bytes".to_vec()).expect("bounded"),
                SecretBytes::try_from_vec(b"machine-id".to_vec()).expect("bounded"),
            ))
        }

        fn routing_info(&mut self) -> Result<String, AdiError> {
            self.calls.push("routing_info");
            Ok(self.routing.clone())
        }

        fn serial_number(&mut self) -> Result<String, AdiError> {
            self.calls.push("serial_number");
            Ok(self.serial.clone())
        }
    }

    fn identity() -> DeviceIdentity {
        DeviceIdentity::from_random_identifier([
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff,
        ])
    }

    #[test]
    fn local_headers_are_byte_exact() {
        let proxy = FakeProxy {
            provisioned: true,
            routing: "17106176".to_owned(),
            serial: "0".to_owned(),
            ..FakeProxy::default()
        };
        let mut provider = LocalAnisetteProvider::new(proxy, identity()).expect("provider");
        let headers = provider.get_headers().expect("headers");
        let actual: BTreeMap<_, _> = headers.iter().collect();
        let expected = BTreeMap::from([
            ("X-Apple-I-MD", "b3RwLWJ5dGVz"),
            ("X-Apple-I-MD-M", "bWFjaGluZS1pZA=="),
            ("X-Apple-I-MD-RINFO", "17106176"),
            (
                "X-Apple-I-MD-LU",
                "A8FAED6ABBF35C12A4B26E40F6FEB19D736D90045C83B9F9A31F638D323E6811",
            ),
            ("X-Apple-I-SRL-NO", "0"),
            (
                "X-Mme-Client-Info",
                "<MacBookPro13,2> <macOS;13.1;22C65> <com.apple.AuthKit/1 (com.apple.dt.Xcode/3594.4.19)>",
            ),
            ("X-Mme-Device-Id", "00112233-4455-6677-8899-AABBCCDDEEFF"),
        ]);
        assert_eq!(actual, expected);
        assert_eq!(format!("{headers:?}"), "LocalAnisetteHeaders([REDACTED])");
    }

    #[test]
    fn unprovisioned_retrieval_stops_without_any_provisioning_or_otp_call() {
        let mut provider =
            LocalAnisetteProvider::new(FakeProxy::default(), identity()).expect("provider");
        assert!(matches!(
            provider.get_headers(),
            Err(AnisetteError::NotProvisioned)
        ));
        let proxy = provider.into_proxy();
        assert_eq!(proxy.calls, ["set_android_id", "is_machine_provisioned"]);
    }

    #[test]
    fn malformed_and_oversized_helper_text_is_rejected() {
        for (routing, serial) in [
            ("not-ascii-\u{80}".to_owned(), "0".to_owned()),
            ("x".repeat(1_025), "0".to_owned()),
            ("17106176".to_owned(), "not-ascii-\u{80}".to_owned()),
            ("17106176".to_owned(), "x".repeat(1_025)),
        ] {
            let proxy = FakeProxy {
                provisioned: true,
                routing,
                serial,
                ..FakeProxy::default()
            };
            let mut provider = LocalAnisetteProvider::new(proxy, identity()).expect("provider");
            assert!(matches!(
                provider.get_headers(),
                Err(AnisetteError::InvalidData)
            ));
        }
    }

    #[test]
    fn proxy_failures_are_stage_safe_and_do_not_advance() {
        let construction = LocalAnisetteProvider::new(
            FakeProxy {
                failure: FailureStage::SetAndroidId,
                ..FakeProxy::default()
            },
            identity(),
        );
        assert!(matches!(
            construction,
            Err(AnisetteError::Proxy(AdiError::OperationFailed))
        ));

        let mut provisioned = LocalAnisetteProvider::new(
            FakeProxy {
                failure: FailureStage::Provisioned,
                ..FakeProxy::default()
            },
            identity(),
        )
        .expect("provider");
        assert!(matches!(
            provisioned.get_headers(),
            Err(AnisetteError::Proxy(AdiError::OperationFailed))
        ));
        assert_eq!(
            provisioned.into_proxy().calls,
            ["set_android_id", "is_machine_provisioned"]
        );

        let mut otp = LocalAnisetteProvider::new(
            FakeProxy {
                provisioned: true,
                failure: FailureStage::Otp,
                ..FakeProxy::default()
            },
            identity(),
        )
        .expect("provider");
        assert!(matches!(
            otp.get_headers(),
            Err(AnisetteError::Proxy(AdiError::OperationFailed))
        ));
        assert_eq!(
            otp.into_proxy().calls,
            ["set_android_id", "is_machine_provisioned", "request_otp"]
        );
    }
}
