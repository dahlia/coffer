// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Derived from SideStore apple-private-apis omnisette/src/adi_proxy.rs.
// Upstream repository: https://github.com/SideStore/apple-private-apis
// Upstream commit: 03beb1aa42991ccdad6214dee77e72282bef461f
// Modified by the Coffer project in 2026 to remove transport, automatic
// provisioning, native loading, and borrowed secret buffers. The modified
// file remains MPL-2.0.

//! Loader-neutral ADI operations and owning secret values.

use core::fmt;

use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::SecretString;

const MAX_SECRET_BYTES: usize = 1024 * 1024;

/// A stage-safe ADI failure that carries no native text or secret bytes.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[non_exhaustive]
pub enum AdiError {
    /// An input or native output was empty or exceeded the one-mebibyte bound.
    #[error("invalid ADI data")]
    InvalidData,
    /// The local helper or native operation failed.
    #[error("ADI operation failed")]
    OperationFailed,
}

/// Move-only secret bytes that are zeroized on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecretBytes(Zeroizing<Vec<u8>>);

impl SecretBytes {
    /// Validates and takes ownership of nonempty bounded secret bytes.
    ///
    /// # Errors
    ///
    /// Returns [`AdiError::InvalidData`] for an empty value or one larger than
    /// one mebibyte. The input is zeroized on error.
    pub fn try_from_vec(bytes: Vec<u8>) -> Result<Self, AdiError> {
        let bytes = Zeroizing::new(bytes);
        if bytes.is_empty() || bytes.len() > MAX_SECRET_BYTES {
            return Err(AdiError::InvalidData);
        }
        Ok(Self(bytes))
    }

    /// Exposes the bytes only to the operation that immediately consumes them.
    #[must_use]
    pub fn expose_secret(&self) -> &[u8] {
        self.0.as_slice()
    }
}

impl fmt::Debug for SecretBytes {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretBytes([REDACTED])")
    }
}

/// A move-only native provisioning session token.
pub struct ProvisioningSession(Zeroizing<u32>);

impl ProvisioningSession {
    /// Wraps one helper-issued session token.
    #[must_use]
    pub fn new(token: u32) -> Self {
        Self(Zeroizing::new(token))
    }

    /// Consumes the owner and returns the token for one terminal operation.
    #[must_use]
    pub fn into_token(self) -> u32 {
        *self.0
    }
}

impl fmt::Debug for ProvisioningSession {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ProvisioningSession([REDACTED])")
    }
}

/// Output from one native provisioning-start operation.
pub struct ProvisioningStart {
    cpim: SecretBytes,
    session: ProvisioningSession,
}

impl ProvisioningStart {
    /// Creates an owned start result from validated helper outputs.
    #[must_use]
    pub fn new(cpim: SecretBytes, session: ProvisioningSession) -> Self {
        Self { cpim, session }
    }

    /// Consumes the result into its secret CPIM and single-use session owner.
    #[must_use]
    pub fn into_parts(self) -> (SecretBytes, ProvisioningSession) {
        (self.cpim, self.session)
    }
}

impl fmt::Debug for ProvisioningStart {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ProvisioningStart([REDACTED])")
    }
}

/// Secret output from one native OTP request.
pub struct OtpMaterial {
    one_time_password: SecretBytes,
    machine_id: SecretBytes,
}

impl OtpMaterial {
    /// Creates an owned OTP result from a validated helper output.
    #[must_use]
    pub fn new(one_time_password: SecretBytes, machine_id: SecretBytes) -> Self {
        Self {
            one_time_password,
            machine_id,
        }
    }

    /// Borrows the one-time password for immediate encoding.
    #[must_use]
    pub fn one_time_password(&self) -> &SecretBytes {
        &self.one_time_password
    }

    /// Borrows the paired machine identifier for immediate encoding.
    #[must_use]
    pub fn machine_id(&self) -> &SecretBytes {
        &self.machine_id
    }
}

impl fmt::Debug for OtpMaterial {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("OtpMaterial([REDACTED])")
    }
}

/// Local ADI behavior required by composition and explicit provisioning.
///
/// Implementations are supplied by Coffer's sandboxed helper client. This
/// trait performs no transport, loading, persistence, retry, or fallback.
/// Provisioning sessions are move-only and must be consumed by exactly one
/// [`AdiProxy::end_provisioning`] or [`AdiProxy::destroy_provisioning`] call.
pub trait AdiProxy: Send {
    /// Reports whether existing local state is provisioned.
    fn is_machine_provisioned(&mut self) -> Result<bool, AdiError>;

    /// Sets exactly the first 16 ASCII bytes of the uppercase UUID.
    fn set_android_id(&mut self, android_id: &[u8; 16]) -> Result<(), AdiError>;

    /// Starts one native provisioning session without performing network I/O.
    fn start_provisioning(
        &mut self,
        spim: SecretBytes,
        local_user_id: &SecretString,
    ) -> Result<ProvisioningStart, AdiError>;

    /// Ends one native provisioning session.
    fn end_provisioning(
        &mut self,
        session: ProvisioningSession,
        ptm: SecretBytes,
        tk: SecretBytes,
    ) -> Result<(), AdiError>;

    /// Destroys one native provisioning session after a failed attempt.
    fn destroy_provisioning(&mut self, session: ProvisioningSession) -> Result<(), AdiError>;

    /// Requests one atomic local OTP and machine-identifier pair.
    fn request_otp(&mut self, local_user_id: &SecretString) -> Result<OtpMaterial, AdiError>;

    /// Returns the routing-information header value.
    fn routing_info(&mut self) -> Result<String, AdiError>;

    /// Returns the local serial-number header value.
    fn serial_number(&mut self) -> Result<String, AdiError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_bytes_are_bounded_redacted_and_zeroizable() {
        assert!(matches!(
            SecretBytes::try_from_vec(Vec::new()),
            Err(AdiError::InvalidData)
        ));
        assert!(matches!(
            SecretBytes::try_from_vec(vec![0; MAX_SECRET_BYTES + 1]),
            Err(AdiError::InvalidData)
        ));

        let mut bytes = SecretBytes::try_from_vec(b"secret-marker".to_vec()).expect("bounded");
        assert_eq!(format!("{bytes:?}"), "SecretBytes([REDACTED])");
        bytes.zeroize();
        assert!(bytes.0.is_empty());
    }

    #[test]
    fn provisioning_owners_are_move_only_and_redacted() {
        let start = ProvisioningStart::new(
            SecretBytes::try_from_vec(vec![1]).expect("bounded"),
            ProvisioningSession::new(7),
        );
        assert_eq!(format!("{start:?}"), "ProvisioningStart([REDACTED])");
        let (_, session) = start.into_parts();
        assert_eq!(format!("{session:?}"), "ProvisioningSession([REDACTED])");
        assert_eq!(session.into_token(), 7);

        let otp = OtpMaterial::new(
            SecretBytes::try_from_vec(b"otp-marker".to_vec()).expect("bounded"),
            SecretBytes::try_from_vec(b"mid-marker".to_vec()).expect("bounded"),
        );
        assert_eq!(format!("{otp:?}"), "OtpMaterial([REDACTED])");
    }
}
