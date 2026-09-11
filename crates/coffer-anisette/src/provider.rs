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

//! Reusable local-only anisette provider.

use core::fmt;
use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};
use std::time::Duration;

use coffer_bootstrap::{BootstrapPaths, InstalledLibraries};
use coffer_protocol::anisette::{AnisetteData, AnisetteError as ProtocolAnisetteError};
use omnisette_local::{
    AdiError, AdiProxy, DeviceIdentity, LocalAnisetteProvider, OtpMaterial as LocalOtpMaterial,
    ProvisioningSession as LocalProvisioningSession, ProvisioningStart, SecretBytes as LocalBytes,
    SecretString as LocalString,
};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use zeroize::{Zeroize, Zeroizing};

use crate::{
    AndroidId, BridgeError, DirectoryServiceId, HelperClient, ProvisioningStore,
    VerifiedLibraryPaths,
};

/// Public, non-secret values appended to the seven local ADI headers.
#[derive(Clone)]
pub struct AnisetteContext {
    pub(crate) time_zone: String,
    pub(crate) locale: String,
    pub(crate) clock: Arc<dyn Clock>,
}

impl AnisetteContext {
    /// Validates a time-zone name and locale for later header construction.
    ///
    /// Both values must be printable ASCII, nonempty, and no longer than the
    /// protocol's 1,024-byte per-value bound.
    ///
    /// # Errors
    ///
    /// Returns [`CofferAnisetteError::InvalidContext`] when either value is
    /// not a safe HTTP header value.
    pub fn new(time_zone: String, locale: String) -> Result<Self, CofferAnisetteError> {
        validate_public_value(&time_zone)?;
        validate_public_value(&locale)?;
        Ok(Self {
            time_zone,
            locale,
            clock: Arc::new(SystemClock),
        })
    }

    #[cfg(test)]
    fn with_clock(mut self, clock: Arc<dyn Clock>) -> Self {
        self.clock = clock;
        self
    }
}

impl fmt::Debug for AnisetteContext {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AnisetteContext")
            .field("time_zone", &self.time_zone)
            .field("locale", &self.locale)
            .finish_non_exhaustive()
    }
}

pub(crate) trait Clock: Send + Sync {
    fn now(&self) -> Result<String, CofferAnisetteError>;
}

struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> Result<String, CofferAnisetteError> {
        OffsetDateTime::now_utc()
            .replace_nanosecond(0)
            .map_err(|_| CofferAnisetteError::InvalidTime)?
            .format(&Rfc3339)
            .map_err(|_| CofferAnisetteError::InvalidTime)
    }
}

/// A local anisette failure with no secret-bearing payload.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum CofferAnisetteError {
    /// The verified local generation has not been provisioned.
    NotProvisioned,
    /// Public time-zone or locale configuration was invalid.
    InvalidContext,
    /// The public clock value was invalid or unavailable.
    InvalidTime,
    /// The persisted identifier was malformed.
    InvalidIdentifier,
    /// State belongs to a different install, helper protocol, upstream
    /// revision, or identifier schema and requires an explicit migration.
    IncompatibleState,
    /// A sandboxed helper or state operation failed at its original stage.
    Bridge(BridgeError),
    /// The bounded worker thread could not run to completion.
    WorkerUnavailable,
}

impl fmt::Display for CofferAnisetteError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotProvisioned => formatter.write_str("local anisette state is not provisioned"),
            Self::InvalidContext => formatter.write_str("anisette public context is invalid"),
            Self::InvalidTime => formatter.write_str("anisette client time is invalid"),
            Self::InvalidIdentifier => formatter.write_str("anisette identifier is invalid"),
            Self::IncompatibleState => formatter.write_str(
                "anisette state requires an explicit migration or reprovisioning decision",
            ),
            Self::Bridge(error) => error.fmt(formatter),
            Self::WorkerUnavailable => formatter.write_str("anisette worker is unavailable"),
        }
    }
}

impl std::error::Error for CofferAnisetteError {}

impl From<BridgeError> for CofferAnisetteError {
    fn from(error: BridgeError) -> Self {
        if error == BridgeError::StateIncompatible {
            Self::IncompatibleState
        } else {
            Self::Bridge(error)
        }
    }
}

/// A reusable provider backed only by a verified install and local XDG state.
///
/// [`CofferAnisetteProvider::open`] performs no network request and never
/// provisions. Each header request runs blocking helper work on a bounded
/// worker thread and is serialized with provisioning through the same lock.
pub struct CofferAnisetteProvider {
    pub(crate) shared: Arc<SharedProvider>,
}

pub(crate) struct SharedProvider {
    provider: Mutex<Box<dyn LocalHeaderSource>>,
    context: AnisetteContext,
    pub(crate) runtime: Arc<HelperRuntime>,
    pub(crate) provisioning_context: Arc<crate::provision::ProvisioningContext>,
}

impl CofferAnisetteProvider {
    /// Connects a verified support-library install, the dedicated helper, and
    /// XDG provisioning storage without starting the helper or using network.
    ///
    /// # Errors
    ///
    /// Returns a path, identifier, or public-context error. Existing bound
    /// state is checked on first use while holding the generation lock.
    pub fn open(
        installation: &InstalledLibraries,
        paths: &BootstrapPaths,
        helper_executable: PathBuf,
        helper_timeout: Duration,
        context: AnisetteContext,
    ) -> Result<Self, CofferAnisetteError> {
        let store = ProvisioningStore::from_installation(paths, installation)?;
        Self::open_store(
            installation,
            store,
            helper_executable,
            helper_timeout,
            context,
        )
    }

    /// Opens only an existing local identity for a stored-session operation.
    ///
    /// Missing identity, lock, or active provisioning is never initialized.
    /// Generation rechecks the active state while locked before starting native
    /// work. Successful OTP generation still stages and publishes local state;
    /// this is not a filesystem read-only provider. No network request or
    /// provisioning occurs automatically.
    ///
    /// # Errors
    ///
    /// Returns [`CofferAnisetteError::NotProvisioned`] for a missing identity,
    /// or a path/identifier error for invalid local state. Missing or
    /// incompatible active provisioning is rejected on generation.
    pub fn open_existing(
        installation: &InstalledLibraries,
        paths: &BootstrapPaths,
        helper_executable: PathBuf,
        helper_timeout: Duration,
        context: AnisetteContext,
    ) -> Result<Self, CofferAnisetteError> {
        let store = ProvisioningStore::from_installation(paths, installation)?.existing_only();
        Self::open_store(
            installation,
            store,
            helper_executable,
            helper_timeout,
            context,
        )
    }

    fn open_store(
        installation: &InstalledLibraries,
        store: ProvisioningStore,
        helper_executable: PathBuf,
        helper_timeout: Duration,
        context: AnisetteContext,
    ) -> Result<Self, CofferAnisetteError> {
        let identifiers = store.identifiers().map_err(|error| {
            if error == BridgeError::StateCorrupt {
                CofferAnisetteError::InvalidIdentifier
            } else if error == BridgeError::StateMissing {
                CofferAnisetteError::NotProvisioned
            } else {
                error.into()
            }
        })?;
        let identity = identity_from_uuid(identifiers.device_identifier())?;
        let provisioning_context = Arc::new(crate::provision::ProvisioningContext::new(
            &identifiers,
            &context,
        ));
        let last_error = Arc::new(Mutex::new(None));
        let runtime = Arc::new(HelperRuntime {
            client: HelperClient::new(helper_executable, helper_timeout),
            libraries: VerifiedLibraryPaths::from_installation(installation),
            store,
        });
        let proxy = HelperAdiProxy {
            runtime: Arc::clone(&runtime),
            android_id: None,
            last_error: Arc::clone(&last_error),
        };
        let provider = LocalAnisetteProvider::new(proxy, identity)
            .map_err(|_| CofferAnisetteError::InvalidIdentifier)?;
        Ok(Self {
            shared: Arc::new(SharedProvider {
                provider: Mutex::new(Box::new(OmnisetteHeaderSource {
                    provider,
                    last_error,
                })),
                context,
                runtime,
                provisioning_context,
            }),
        })
    }

    /// Produces one set of ten typed anisette values without provisioning.
    ///
    /// # Errors
    ///
    /// Returns [`CofferAnisetteError::NotProvisioned`] without network access
    /// when local state is unprovisioned. No failure is retried.
    pub fn generate(
        &self,
    ) -> impl Future<Output = Result<AnisetteData, CofferAnisetteError>> + Send + 'static {
        let shared = Arc::clone(&self.shared);
        WorkerFuture::spawn(
            move |cancelled| shared.generate(cancelled),
            Err(CofferAnisetteError::WorkerUnavailable),
        )
    }

    /// Creates the explicit, single-attempt provisioning coordinator.
    ///
    /// Construction performs no network or native operation. The caller must
    /// separately create and consume an [`ExplicitProvisioningRequest`](crate::ExplicitProvisioningRequest).
    #[must_use]
    pub fn provisioning_coordinator(
        &self,
        attempt_deadline: Duration,
    ) -> crate::ProvisioningCoordinator {
        crate::ProvisioningCoordinator::production(
            Arc::clone(&self.shared.runtime),
            Arc::clone(&self.shared.provisioning_context),
            attempt_deadline,
        )
    }
}

impl coffer_protocol::anisette::AnisetteProvider for CofferAnisetteProvider {
    async fn anisette(&self) -> Result<AnisetteData, ProtocolAnisetteError> {
        self.generate()
            .await
            .map_err(|error| ProtocolAnisetteError::Unavailable {
                detail: error.to_string(),
            })
    }
}

impl fmt::Debug for CofferAnisetteProvider {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CofferAnisetteProvider(<local-only>)")
    }
}

impl SharedProvider {
    fn generate(&self, cancelled: &AtomicBool) -> Result<AnisetteData, CofferAnisetteError> {
        generate_from_source(&self.provider, &self.context, cancelled)
    }
}

fn generate_from_source(
    source: &Mutex<Box<dyn LocalHeaderSource>>,
    context: &AnisetteContext,
    cancelled: &AtomicBool,
) -> Result<AnisetteData, CofferAnisetteError> {
    if cancelled.load(Ordering::Acquire) {
        return Err(CofferAnisetteError::WorkerUnavailable);
    }
    let mut provider = source
        .lock()
        .map_err(|_| CofferAnisetteError::WorkerUnavailable)?;
    if cancelled.load(Ordering::Acquire) {
        return Err(CofferAnisetteError::WorkerUnavailable);
    }
    let values = provider.headers()?;
    let values: [String; 7] = values.try_into().map_err(|mut values: Vec<String>| {
        values.zeroize();
        CofferAnisetteError::Bridge(BridgeError::InvalidMessage)
    })?;
    let mut values = Zeroizing::new(values);
    if cancelled.load(Ordering::Acquire) {
        return Err(CofferAnisetteError::WorkerUnavailable);
    }
    validate_public_value(&values[5])
        .map_err(|_| CofferAnisetteError::Bridge(BridgeError::InvalidMessage))?;
    values[5].zeroize();
    values[5].push_str(crate::LOCAL_AUTH_CLIENT_INFO);
    let client_time = context.clock.now()?;
    validate_public_value(&client_time).map_err(|_| CofferAnisetteError::InvalidTime)?;
    let [
        one_time_password,
        machine_id,
        routing_info,
        local_user_id,
        serial_number,
        client_info,
        device_id,
    ] = std::mem::take(&mut *values);
    let data = AnisetteData {
        one_time_password,
        machine_id,
        routing_info,
        local_user_id,
        serial_number,
        client_info,
        device_id,
        client_time,
        time_zone: context.time_zone.clone(),
        locale: context.locale.clone(),
    };
    data.validate()
        .map_err(|_| CofferAnisetteError::Bridge(BridgeError::InvalidMessage))?;
    Ok(data)
}

trait LocalHeaderSource: Send {
    fn headers(&mut self) -> Result<Vec<String>, CofferAnisetteError>;
}

struct OmnisetteHeaderSource {
    provider: LocalAnisetteProvider<HelperAdiProxy>,
    last_error: Arc<Mutex<Option<BridgeError>>>,
}

impl LocalHeaderSource for OmnisetteHeaderSource {
    fn headers(&mut self) -> Result<Vec<String>, CofferAnisetteError> {
        let headers = match self.provider.get_headers() {
            Ok(headers) => headers,
            Err(omnisette_local::AnisetteError::NotProvisioned) => {
                return Err(CofferAnisetteError::NotProvisioned);
            }
            Err(omnisette_local::AnisetteError::InvalidData) => {
                return Err(CofferAnisetteError::Bridge(BridgeError::InvalidMessage));
            }
            Err(omnisette_local::AnisetteError::Proxy(error)) => {
                return Err(map_proxy_error(&self.last_error, error));
            }
            Err(_) => return Err(CofferAnisetteError::Bridge(BridgeError::InvalidMessage)),
        };
        Ok(headers.iter().map(|(_, value)| value.to_owned()).collect())
    }
}

fn map_proxy_error(
    last_error: &Mutex<Option<BridgeError>>,
    error: AdiError,
) -> CofferAnisetteError {
    match error {
        AdiError::InvalidData => CofferAnisetteError::Bridge(BridgeError::InvalidMessage),
        AdiError::OperationFailed => last_error
            .lock()
            .map_err(|_| CofferAnisetteError::WorkerUnavailable)
            .and_then(|mut slot| {
                slot.take()
                    .ok_or(CofferAnisetteError::Bridge(BridgeError::HelperFailed))
            })
            .map_or_else(|error| error, CofferAnisetteError::from),
        _ => CofferAnisetteError::Bridge(BridgeError::InvalidMessage),
    }
}

pub(crate) struct HelperRuntime {
    pub(crate) client: HelperClient,
    pub(crate) libraries: VerifiedLibraryPaths,
    pub(crate) store: ProvisioningStore,
}

struct HelperAdiProxy {
    runtime: Arc<HelperRuntime>,
    android_id: Option<AndroidId>,
    last_error: Arc<Mutex<Option<BridgeError>>>,
}

impl HelperAdiProxy {
    fn android_id(&self) -> Result<&AndroidId, AdiError> {
        self.android_id.as_ref().ok_or(AdiError::OperationFailed)
    }

    fn map<T>(&self, result: Result<T, BridgeError>) -> Result<T, AdiError> {
        result.map_err(|error| {
            if let Ok(mut slot) = self.last_error.lock() {
                *slot = Some(error);
            }
            AdiError::OperationFailed
        })
    }
}

impl AdiProxy for HelperAdiProxy {
    fn is_machine_provisioned(&mut self) -> Result<bool, AdiError> {
        let android_id = self.android_id()?;
        self.map(self.runtime.client.is_machine_provisioned(
            &self.runtime.libraries,
            &self.runtime.store,
            DirectoryServiceId::LOCAL_MACHINE,
            android_id,
        ))
    }

    fn set_android_id(&mut self, android_id: &[u8; 16]) -> Result<(), AdiError> {
        self.android_id = Some(AndroidId::new(*android_id).map_err(|_| AdiError::InvalidData)?);
        Ok(())
    }

    fn start_provisioning(
        &mut self,
        _spim: LocalBytes,
        _local_user_id: &LocalString,
    ) -> Result<ProvisioningStart, AdiError> {
        Err(AdiError::OperationFailed)
    }

    fn end_provisioning(
        &mut self,
        _session: LocalProvisioningSession,
        _ptm: LocalBytes,
        _tk: LocalBytes,
    ) -> Result<(), AdiError> {
        Err(AdiError::OperationFailed)
    }

    fn destroy_provisioning(&mut self, _session: LocalProvisioningSession) -> Result<(), AdiError> {
        Err(AdiError::OperationFailed)
    }

    fn request_otp(&mut self, _local_user_id: &LocalString) -> Result<LocalOtpMaterial, AdiError> {
        let android_id = self.android_id()?;
        let result = self.runtime.client.request_otp(
            &self.runtime.libraries,
            &self.runtime.store,
            DirectoryServiceId::LOCAL_MACHINE,
            android_id,
        );
        let material = self.map(result)?;
        Ok(LocalOtpMaterial::new(
            LocalBytes::try_from_vec(material.one_time_password.expose().to_vec())?,
            LocalBytes::try_from_vec(material.machine_id.expose().to_vec())?,
        ))
    }

    fn routing_info(&mut self) -> Result<String, AdiError> {
        Ok("17106176".to_owned())
    }

    fn serial_number(&mut self) -> Result<String, AdiError> {
        Ok("0".to_owned())
    }
}

fn identity_from_uuid(uuid: &str) -> Result<DeviceIdentity, CofferAnisetteError> {
    if uuid.len() != 36 {
        return Err(CofferAnisetteError::InvalidIdentifier);
    }
    let mut bytes = [0u8; 16];
    let mut nibble = None;
    let mut index = 0usize;
    for (position, value) in uuid.bytes().enumerate() {
        if matches!(position, 8 | 13 | 18 | 23) {
            if value != b'-' {
                return Err(CofferAnisetteError::InvalidIdentifier);
            }
            continue;
        }
        let value = match value {
            b'0'..=b'9' => value - b'0',
            b'A'..=b'F' => value - b'A' + 10,
            _ => return Err(CofferAnisetteError::InvalidIdentifier),
        };
        if let Some(high) = nibble.take() {
            let byte = bytes
                .get_mut(index)
                .ok_or(CofferAnisetteError::InvalidIdentifier)?;
            *byte = high << 4 | value;
            index += 1;
        } else {
            nibble = Some(value);
        }
    }
    if index != bytes.len() || nibble.is_some() {
        return Err(CofferAnisetteError::InvalidIdentifier);
    }
    Ok(DeviceIdentity::from_random_identifier(bytes))
}

fn validate_public_value(value: &str) -> Result<(), CofferAnisetteError> {
    if value.is_empty()
        || value.len() > coffer_protocol::anisette::MAX_ANISETTE_VALUE_LEN
        || !value.bytes().all(|byte| (0x20..=0x7e).contains(&byte))
    {
        Err(CofferAnisetteError::InvalidContext)
    } else {
        Ok(())
    }
}

struct WorkerState<T> {
    result: Option<T>,
    waker: Option<Waker>,
}

pub(crate) struct WorkerFuture<T> {
    state: Arc<Mutex<WorkerState<T>>>,
    cancelled: Arc<AtomicBool>,
}

impl<T: Send + 'static> WorkerFuture<T> {
    pub(crate) fn spawn(
        work: impl FnOnce(&AtomicBool) -> T + Send + 'static,
        spawn_failure: T,
    ) -> Self {
        let state = Arc::new(Mutex::new(WorkerState {
            result: None,
            waker: None,
        }));
        let cancelled = Arc::new(AtomicBool::new(false));
        let worker_state = Arc::clone(&state);
        let worker_cancelled = Arc::clone(&cancelled);
        if std::thread::Builder::new()
            .name("coffer-anisette-worker".to_owned())
            .spawn(move || {
                let result = work(&worker_cancelled);
                if let Ok(mut state) = worker_state.lock() {
                    state.result = Some(result);
                    if let Some(waker) = state.waker.take() {
                        waker.wake();
                    }
                }
            })
            .is_err()
        {
            let mut state = state.lock().unwrap_or_else(|error| error.into_inner());
            state.result = Some(spawn_failure);
        }
        Self { state, cancelled }
    }
}

impl<T> Future for WorkerFuture<T> {
    type Output = T;

    fn poll(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        if let Some(result) = state.result.take() {
            Poll::Ready(result)
        } else {
            state.waker = Some(context.waker().clone());
            Poll::Pending
        }
    }
}

impl<T> Drop for WorkerFuture<T> {
    fn drop(&mut self) {
        self.cancelled.store(true, Ordering::Release);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FixedClock(&'static str);

    struct FakeHeaders(Result<Vec<String>, CofferAnisetteError>);

    struct HeaderOrderProxy;

    impl AdiProxy for HeaderOrderProxy {
        fn is_machine_provisioned(&mut self) -> Result<bool, AdiError> {
            Ok(true)
        }

        fn set_android_id(&mut self, _android_id: &[u8; 16]) -> Result<(), AdiError> {
            Ok(())
        }

        fn start_provisioning(
            &mut self,
            _spim: LocalBytes,
            _local_user_id: &LocalString,
        ) -> Result<ProvisioningStart, AdiError> {
            Err(AdiError::OperationFailed)
        }

        fn end_provisioning(
            &mut self,
            _session: LocalProvisioningSession,
            _ptm: LocalBytes,
            _tk: LocalBytes,
        ) -> Result<(), AdiError> {
            Err(AdiError::OperationFailed)
        }

        fn destroy_provisioning(
            &mut self,
            _session: LocalProvisioningSession,
        ) -> Result<(), AdiError> {
            Err(AdiError::OperationFailed)
        }

        fn request_otp(
            &mut self,
            _local_user_id: &LocalString,
        ) -> Result<LocalOtpMaterial, AdiError> {
            Ok(LocalOtpMaterial::new(
                LocalBytes::try_from_vec(vec![1])?,
                LocalBytes::try_from_vec(vec![2])?,
            ))
        }

        fn routing_info(&mut self) -> Result<String, AdiError> {
            Ok("17106176".to_owned())
        }

        fn serial_number(&mut self) -> Result<String, AdiError> {
            Ok("0".to_owned())
        }
    }

    impl LocalHeaderSource for FakeHeaders {
        fn headers(&mut self) -> Result<Vec<String>, CofferAnisetteError> {
            std::mem::replace(&mut self.0, Err(CofferAnisetteError::WorkerUnavailable))
        }
    }

    impl Clock for FixedClock {
        fn now(&self) -> Result<String, CofferAnisetteError> {
            Ok(self.0.to_owned())
        }
    }

    #[test]
    fn public_context_and_time_are_bounded() {
        assert!(AnisetteContext::new("UTC".to_owned(), "en_US".to_owned()).is_ok());
        assert!(AnisetteContext::new(String::new(), "en_US".to_owned()).is_err());
        assert!(AnisetteContext::new("UTC\nInjected".to_owned(), "en_US".to_owned()).is_err());
        assert!(AnisetteContext::new("UTC".to_owned(), "x".repeat(1025)).is_err());
        let context = AnisetteContext::new("UTC".to_owned(), "en_US".to_owned())
            .expect("context")
            .with_clock(Arc::new(FixedClock("2026-09-04T00:00:00Z")));
        assert_eq!(context.clock.now().expect("time"), "2026-09-04T00:00:00Z");
        let system_time = SystemClock.now().expect("system time");
        let parsed = OffsetDateTime::parse(&system_time, &Rfc3339).expect("RFC 3339");
        assert_eq!(parsed.nanosecond(), 0);
        assert_eq!(system_time.len(), 20);
    }

    #[test]
    fn identity_round_trip_matches_the_mpl_composition() {
        let identity =
            identity_from_uuid("00112233-4455-6677-8899-AABBCCDDEEFF").expect("identity");
        assert_eq!(identity.android_id(), b"00112233-4455-66");
        assert_eq!(
            identity.local_user_id().expose_secret(),
            "A8FAED6ABBF35C12A4B26E40F6FEB19D736D90045C83B9F9A31F638D323E6811"
        );
    }

    #[test]
    fn debug_output_is_redacted() {
        assert_eq!(
            format!("{:?}", CofferAnisetteError::Bridge(BridgeError::OtpFailed)),
            "Bridge(OtpFailed)"
        );
    }

    #[test]
    fn all_ten_headers_are_composed_and_validated() {
        assert_eq!(
            crate::LOCAL_AUTH_CLIENT_INFO,
            "<Mac14,2> <macOS;27.0;26A5378j> <com.apple.AuthKit/1 (com.apple.akd/1.0)>"
        );
        let source: Mutex<Box<dyn LocalHeaderSource>> =
            Mutex::new(Box::new(FakeHeaders(Ok(vec![
                "otp".to_owned(),
                "mid".to_owned(),
                "17106176".to_owned(),
                "local-user".to_owned(),
                "0".to_owned(),
                "<MacBookPro13,2> <macOS;13.1;22C65> <com.apple.AuthKit/1 (com.apple.dt.Xcode/3594.4.19)>"
                    .to_owned(),
                "device".to_owned(),
            ]))));
        let context = AnisetteContext::new("UTC".to_owned(), "en_US".to_owned())
            .expect("context")
            .with_clock(Arc::new(FixedClock("2026-09-04T00:00:00Z")));
        let data = generate_from_source(&source, &context, &AtomicBool::new(false)).expect("data");
        assert_eq!(data.one_time_password, "otp");
        assert_eq!(data.machine_id, "mid");
        assert_eq!(data.routing_info, "17106176");
        assert_eq!(data.local_user_id, "local-user");
        assert_eq!(data.serial_number, "0");
        assert_eq!(data.client_info, crate::LOCAL_AUTH_CLIENT_INFO);
        assert!(!data.client_info.contains("com.apple.dt.Xcode"));
        assert!(!data.client_info.contains("macOS;13.1;22C65"));
        assert_eq!(data.device_id, "device");
        assert_eq!(data.client_time, "2026-09-04T00:00:00Z");
        assert_eq!(data.time_zone, "UTC");
        assert_eq!(data.locale, "en_US");
        data.validate().expect("valid headers");
    }

    #[test]
    fn local_source_client_info_slot_matches_the_protocol_order() {
        let identity = DeviceIdentity::from_random_identifier([0; 16]);
        let mut provider =
            LocalAnisetteProvider::new(HeaderOrderProxy, identity).expect("local source");
        let headers = provider.get_headers().expect("local headers");

        assert_eq!(
            headers.iter().nth(5).map(|(name, _)| name),
            Some(coffer_protocol::anisette::CLIENT_INFO_HEADER)
        );
    }

    #[test]
    fn valid_source_client_info_is_always_replaced_by_the_local_profile() {
        for source_client_info in [
            "<arbitrary-client>",
            "<MacBookPro13,2> <macOS;13.1;22C65> <com.apple.AuthKit/1 (com.apple.dt.Xcode/3594.4.19)>",
        ] {
            let source: Mutex<Box<dyn LocalHeaderSource>> =
                Mutex::new(Box::new(FakeHeaders(Ok(vec![
                    "otp".to_owned(),
                    "mid".to_owned(),
                    "17106176".to_owned(),
                    "local-user".to_owned(),
                    "0".to_owned(),
                    source_client_info.to_owned(),
                    "device".to_owned(),
                ]))));
            let context = AnisetteContext::new("UTC".to_owned(), "en_US".to_owned())
                .expect("context")
                .with_clock(Arc::new(FixedClock("2026-09-04T00:00:00Z")));
            let data = generate_from_source(&source, &context, &AtomicBool::new(false))
                .expect("local profile");

            assert_eq!(data.client_info, crate::LOCAL_AUTH_CLIENT_INFO);
            assert!(!data.client_info.contains("com.apple.dt.Xcode"));
            assert!(!data.client_info.contains("macOS;13.1;22C65"));
        }
    }

    #[test]
    fn malformed_source_client_info_is_rejected_before_replacement() {
        for source_client_info in [
            "client\r\ninjected".to_owned(),
            "x".repeat(coffer_protocol::anisette::MAX_ANISETTE_VALUE_LEN + 1),
        ] {
            let source: Mutex<Box<dyn LocalHeaderSource>> =
                Mutex::new(Box::new(FakeHeaders(Ok(vec![
                    "otp".to_owned(),
                    "mid".to_owned(),
                    "17106176".to_owned(),
                    "local-user".to_owned(),
                    "0".to_owned(),
                    source_client_info,
                    "device".to_owned(),
                ]))));
            let context = AnisetteContext::new("UTC".to_owned(), "en_US".to_owned())
                .expect("context")
                .with_clock(Arc::new(FixedClock("2026-09-04T00:00:00Z")));

            assert!(matches!(
                generate_from_source(&source, &context, &AtomicBool::new(false)),
                Err(CofferAnisetteError::Bridge(BridgeError::InvalidMessage))
            ));
        }
    }

    #[test]
    fn unprovisioned_source_stops_without_advancing() {
        let source: Mutex<Box<dyn LocalHeaderSource>> = Mutex::new(Box::new(FakeHeaders(Err(
            CofferAnisetteError::NotProvisioned,
        ))));
        let context = AnisetteContext::new("UTC".to_owned(), "en_US".to_owned()).expect("context");
        assert!(matches!(
            generate_from_source(&source, &context, &AtomicBool::new(false)),
            Err(CofferAnisetteError::NotProvisioned)
        ));
    }

    #[test]
    fn invalid_proxy_output_keeps_its_message_classification() {
        assert_eq!(
            map_proxy_error(&Mutex::new(None), AdiError::InvalidData),
            CofferAnisetteError::Bridge(BridgeError::InvalidMessage)
        );
        assert_eq!(
            map_proxy_error(
                &Mutex::new(Some(BridgeError::StateIncompatible)),
                AdiError::OperationFailed
            ),
            CofferAnisetteError::IncompatibleState
        );
    }
}
