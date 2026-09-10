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

//! Explicit one-attempt local provisioning.

use core::fmt;
use std::io::Read as _;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use quick_xml::Reader;
use quick_xml::escape::resolve_xml_entity;
use quick_xml::events::{BytesRef, BytesStart, Event};
use ureq::tls::{Certificate, RootCerts, TlsConfig};
use zeroize::{Zeroize, Zeroizing};

use crate::client::NativeTerminalError;
use crate::provider::{AnisetteContext, Clock, HelperRuntime, WorkerFuture};
use crate::{BridgeError, DeviceIdentifiers, DirectoryServiceId, SecretBytes};

const MAX_RESPONSE_BYTES: usize = 2 * 1024 * 1024;
const MAX_XML_FIELDS: usize = 512;
const MAX_XML_NODES: usize = MAX_XML_FIELDS + 1;
const MAX_XML_DEPTH: usize = 8;
const CONTENT_TYPE: &str = "text/x-xml-plist";
const LOOKUP_ENDPOINT: &str = "https://gsa.apple.com/grandslam/GsService2/lookup";
const START_ENDPOINT: &str = "https://gsa.apple.com/grandslam/MidService/startMachineProvisioning";
const FINISH_ENDPOINT: &str =
    "https://gsa.apple.com/grandslam/MidService/finishMachineProvisioning";
const AKD_USER_AGENT: &str = "akd/1.0 CFNetwork/808.1.4";
const SERIAL_NUMBER_PLACEHOLDER: &str = "0";
const CLIENT_INFO: &str =
    "<MacBookPro13,2> <macOS;13.1;22C65> <com.apple.AuthKit/1 (com.apple.dt.Xcode/3594.4.19)>";

pub(crate) struct ProvisioningContext {
    local_user_id: Zeroizing<String>,
    device_id: Zeroizing<String>,
    serial_number: &'static str,
    time_zone: String,
    locale: String,
    clock: Arc<dyn Clock>,
}

impl ProvisioningContext {
    pub(crate) fn new(identifiers: &DeviceIdentifiers, context: &AnisetteContext) -> Self {
        Self {
            local_user_id: Zeroizing::new(identifiers.local_user_id().expose().to_owned()),
            device_id: Zeroizing::new(identifiers.device_identifier().to_owned()),
            serial_number: SERIAL_NUMBER_PLACEHOLDER,
            time_zone: context.time_zone.clone(),
            locale: context.locale.clone(),
            clock: Arc::clone(&context.clock),
        }
    }

    fn headers(&self) -> Result<ProvisioningHeaders<'_>, ProvisioningErrorKind> {
        let client_time = self
            .clock
            .now()
            .map_err(|_| ProvisioningErrorKind::InvalidContext)?;
        validate_header_value(&client_time)?;
        Ok(ProvisioningHeaders {
            local_user_id: Zeroizing::new(self.local_user_id.to_string()),
            device_id: Zeroizing::new(self.device_id.to_string()),
            serial_number: self.serial_number,
            client_info: CLIENT_INFO,
            client_time: Zeroizing::new(client_time),
            time_zone: &self.time_zone,
            locale: &self.locale,
        })
    }
}

impl fmt::Debug for ProvisioningContext {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ProvisioningContext(<redacted>)")
    }
}

struct ProvisioningHeaders<'a> {
    local_user_id: Zeroizing<String>,
    device_id: Zeroizing<String>,
    serial_number: &'static str,
    client_info: &'static str,
    client_time: Zeroizing<String>,
    time_zone: &'a str,
    locale: &'a str,
}

impl ProvisioningHeaders<'_> {
    fn entries(&self) -> [(&'static str, &str); 7] {
        [
            ("X-Apple-I-MD-LU", &self.local_user_id),
            ("X-Mme-Device-Id", &self.device_id),
            ("X-Mme-Client-Info", self.client_info),
            ("X-Apple-I-SRL-NO", self.serial_number),
            ("X-Apple-I-Client-Time", &self.client_time),
            ("X-Apple-I-TimeZone", self.time_zone),
            ("X-Apple-Locale", self.locale),
        ]
    }
}

fn validate_header_value(value: &str) -> Result<(), ProvisioningErrorKind> {
    if value.is_empty()
        || value.len() > coffer_protocol::anisette::MAX_ANISETTE_VALUE_LEN
        || !value.bytes().all(|byte| (0x20..=0x7e).contains(&byte))
    {
        Err(ProvisioningErrorKind::InvalidContext)
    } else {
        Ok(())
    }
}

/// A caller-owned authorization for exactly one provisioning attempt.
///
/// It is intentionally move-only. Creating it does nothing; passing it to
/// [`ProvisioningCoordinator::provision_once`] is the explicit action that
/// permits one lookup/start/native-start/finish/native-end sequence.
pub struct ExplicitProvisioningRequest {
    _private: (),
}

impl fmt::Debug for ExplicitProvisioningRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ExplicitProvisioningRequest")
    }
}

/// The externally meaningful stage at which a provisioning attempt stopped.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ProvisioningStage {
    /// Fetching and validating the fixed lookup document.
    Lookup,
    /// Sending the fixed start request and validating SPIM.
    StartRequest,
    /// Starting the one native helper transaction.
    NativeStart,
    /// Sending CPIM and validating PTM/TK.
    FinishRequest,
    /// Ending the native session and atomically publishing the generation.
    NativeEnd,
    /// Best-effort destruction after a pre-end failure.
    Cleanup,
    /// The returned future was cancelled.
    Cancelled,
}

/// Secret-free classification of a provisioning failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ProvisioningErrorKind {
    /// HTTPS transport failed or exceeded the absolute deadline.
    Transport,
    /// TLS negotiation or certificate verification failed.
    Tls,
    /// The endpoint returned a redirect.
    Redirect,
    /// The endpoint returned an authentication challenge.
    AuthenticationChallenge,
    /// The endpoint returned a non-success HTTP status.
    HttpStatus(u16),
    /// The response content type was not the fixed property-list type.
    ContentType,
    /// The body was malformed, oversized, duplicated, or unexpected.
    MalformedResponse,
    /// HTTP succeeded but the protocol status reported failure.
    ProtocolStatus(i64),
    /// The sandboxed native helper failed.
    Native(BridgeError),
    /// The caller dropped the attempt future.
    Cancelled,
    /// The bounded blocking worker could not be started.
    WorkerUnavailable,
    /// The public provisioning header context was invalid or unavailable.
    InvalidContext,
}

/// One failed attempt, retaining the first failure separately from cleanup.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProvisioningError {
    stage: ProvisioningStage,
    kind: ProvisioningErrorKind,
    cleanup: Option<BridgeError>,
}

impl ProvisioningError {
    /// Returns the stage of the first failure.
    #[must_use]
    pub fn stage(&self) -> ProvisioningStage {
        self.stage
    }

    /// Returns the secret-free first failure classification.
    #[must_use]
    pub fn kind(&self) -> ProvisioningErrorKind {
        self.kind
    }

    /// Returns a separate best-effort destroy failure, if cleanup also failed.
    #[must_use]
    pub fn cleanup_failure(&self) -> Option<BridgeError> {
        self.cleanup
    }

    fn at(stage: ProvisioningStage, kind: ProvisioningErrorKind) -> Self {
        Self {
            stage,
            kind,
            cleanup: None,
        }
    }

    fn with_cleanup(mut self, cleanup: Result<(), BridgeError>) -> Self {
        self.cleanup = cleanup.err();
        self
    }
}

impl fmt::Display for ProvisioningError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "anisette provisioning failed during {:?}",
            self.stage
        )
    }
}

impl std::error::Error for ProvisioningError {}

/// Proof that one explicit attempt reached durable atomic publication.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProvisioningReceipt {
    completed: (),
}

impl ProvisioningReceipt {
    /// Confirms that native end and atomic publication completed.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        true
    }
}

/// Coordinates one explicit attempt without fallback or retry.
pub struct ProvisioningCoordinator {
    transport: Arc<dyn ProvisioningTransport>,
    native: Arc<dyn NativeProvisioner>,
    context: Arc<ProvisioningContext>,
    timeout: Duration,
}

impl ProvisioningCoordinator {
    pub(crate) fn production(
        runtime: Arc<HelperRuntime>,
        context: Arc<ProvisioningContext>,
        timeout: Duration,
    ) -> Self {
        Self {
            transport: Arc::new(AppleProvisioningTransport),
            native: Arc::new(HelperProvisioner(runtime)),
            context,
            timeout,
        }
    }

    /// Creates a move-only authorization token for an explicit user action.
    #[must_use]
    pub fn begin(&self) -> ExplicitProvisioningRequest {
        ExplicitProvisioningRequest { _private: () }
    }

    /// Performs exactly one bounded provisioning attempt.
    ///
    /// There is no loop, remote-provider fallback, or retry path. After native
    /// start, every cancellation or failure before native end performs exactly
    /// one best-effort destroy while preserving the original error.
    pub fn provision_once(
        &self,
        request: ExplicitProvisioningRequest,
    ) -> impl std::future::Future<Output = Result<ProvisioningReceipt, ProvisioningError>> + Send + 'static
    {
        let transport = Arc::clone(&self.transport);
        let native = Arc::clone(&self.native);
        let context = Arc::clone(&self.context);
        let timeout = self.timeout;
        WorkerFuture::spawn(
            move |cancelled| {
                let _request = request;
                run_once(
                    transport.as_ref(),
                    native.as_ref(),
                    context.as_ref(),
                    timeout,
                    cancelled,
                )
            },
            Err(ProvisioningError::at(
                ProvisioningStage::Lookup,
                ProvisioningErrorKind::WorkerUnavailable,
            )),
        )
    }
}

impl fmt::Debug for ProvisioningCoordinator {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ProvisioningCoordinator(<local-only, one-attempt>)")
    }
}

struct Lookup {
    start_endpoint: Endpoint,
    finish_endpoint: Endpoint,
}

struct StartResponse(SecretBytes);

struct FinishResponse {
    ptm: SecretBytes,
    tk: SecretBytes,
}

trait ProvisioningTransport: Send + Sync {
    fn lookup(
        &self,
        headers: &ProvisioningHeaders<'_>,
        deadline: Instant,
    ) -> Result<Lookup, ProvisioningErrorKind>;
    fn start(
        &self,
        endpoint: Endpoint,
        headers: &ProvisioningHeaders<'_>,
        deadline: Instant,
    ) -> Result<StartResponse, ProvisioningErrorKind>;
    fn finish(
        &self,
        endpoint: Endpoint,
        cpim: &[u8],
        headers: &ProvisioningHeaders<'_>,
        deadline: Instant,
    ) -> Result<FinishResponse, ProvisioningErrorKind>;
}

trait NativeProvisioner: Send + Sync {
    fn start(
        &self,
        spim: SecretBytes,
        deadline: Instant,
    ) -> Result<Box<dyn NativeSession>, BridgeError>;
}

trait NativeSession {
    fn cpim(&self) -> &[u8];
    fn finish(
        self: Box<Self>,
        ptm: SecretBytes,
        tk: SecretBytes,
    ) -> Result<(), NativeTerminalError>;
    fn cancel(self: Box<Self>) -> Result<(), BridgeError>;
}

fn run_once(
    transport: &dyn ProvisioningTransport,
    native: &dyn NativeProvisioner,
    context: &ProvisioningContext,
    timeout: Duration,
    cancelled: &AtomicBool,
) -> Result<ProvisioningReceipt, ProvisioningError> {
    let deadline = Instant::now().checked_add(timeout).ok_or_else(|| {
        ProvisioningError::at(ProvisioningStage::Lookup, ProvisioningErrorKind::Transport)
    })?;
    let headers = context
        .headers()
        .map_err(|kind| ProvisioningError::at(ProvisioningStage::Lookup, kind))?;
    check_ready(cancelled, deadline, ProvisioningStage::Lookup)?;
    let lookup = transport
        .lookup(&headers, deadline)
        .map_err(|kind| ProvisioningError::at(ProvisioningStage::Lookup, kind))?;
    check_ready(cancelled, deadline, ProvisioningStage::StartRequest)?;
    let StartResponse(spim) = transport
        .start(lookup.start_endpoint, &headers, deadline)
        .map_err(|kind| ProvisioningError::at(ProvisioningStage::StartRequest, kind))?;
    check_ready(cancelled, deadline, ProvisioningStage::NativeStart)?;
    let session = native.start(spim, deadline).map_err(|error| {
        ProvisioningError::at(
            ProvisioningStage::NativeStart,
            ProvisioningErrorKind::Native(error),
        )
    })?;
    if session.cpim().is_empty() {
        return Err(ProvisioningError::at(
            ProvisioningStage::NativeStart,
            ProvisioningErrorKind::Native(BridgeError::InvalidMessage),
        )
        .with_cleanup(session.cancel()));
    }
    if let Err(error) = check_ready(cancelled, deadline, ProvisioningStage::FinishRequest) {
        return Err(error.with_cleanup(session.cancel()));
    }
    let finish = match transport.finish(lookup.finish_endpoint, session.cpim(), &headers, deadline)
    {
        Ok(finish) => finish,
        Err(kind) => {
            return Err(
                ProvisioningError::at(ProvisioningStage::FinishRequest, kind)
                    .with_cleanup(session.cancel()),
            );
        }
    };
    if let Err(error) = check_ready(cancelled, deadline, ProvisioningStage::NativeEnd) {
        return Err(error.with_cleanup(session.cancel()));
    }
    session
        .finish(finish.ptm, finish.tk)
        .map_err(|error| ProvisioningError {
            stage: ProvisioningStage::NativeEnd,
            kind: ProvisioningErrorKind::Native(error.first),
            cleanup: error.cleanup,
        })?;
    Ok(ProvisioningReceipt { completed: () })
}

fn check_ready(
    cancelled: &AtomicBool,
    deadline: Instant,
    stage: ProvisioningStage,
) -> Result<(), ProvisioningError> {
    if cancelled.load(Ordering::Acquire) {
        Err(ProvisioningError::at(
            ProvisioningStage::Cancelled,
            ProvisioningErrorKind::Cancelled,
        ))
    } else if Instant::now() >= deadline {
        Err(ProvisioningError::at(
            stage,
            ProvisioningErrorKind::Transport,
        ))
    } else {
        Ok(())
    }
}

struct HelperProvisioner(Arc<HelperRuntime>);

impl NativeProvisioner for HelperProvisioner {
    fn start(
        &self,
        spim: SecretBytes,
        deadline: Instant,
    ) -> Result<Box<dyn NativeSession>, BridgeError> {
        let identifiers = self.0.store.identifiers()?;
        let session = self.0.client.start_provisioning_until(
            &self.0.libraries,
            &self.0.store,
            DirectoryServiceId::LOCAL_MACHINE,
            identifiers.android_id(),
            spim,
            deadline,
        )?;
        Ok(Box::new(HelperNativeSession(session)))
    }
}

struct HelperNativeSession(crate::ProvisioningSession);

impl NativeSession for HelperNativeSession {
    fn cpim(&self) -> &[u8] {
        self.0.cpim()
    }

    fn finish(
        self: Box<Self>,
        ptm: SecretBytes,
        tk: SecretBytes,
    ) -> Result<(), NativeTerminalError> {
        self.0.finish_with_cleanup(ptm, tk)
    }

    fn cancel(self: Box<Self>) -> Result<(), BridgeError> {
        self.0.cancel()
    }
}

#[derive(Clone, Copy)]
enum Endpoint {
    Start,
    Finish,
}

impl Endpoint {
    fn value(self) -> &'static str {
        match self {
            Self::Start => START_ENDPOINT,
            Self::Finish => FINISH_ENDPOINT,
        }
    }

    fn parse(value: &str, expected: Self) -> Result<Self, ProvisioningErrorKind> {
        if value == expected.value() {
            Ok(expected)
        } else {
            Err(ProvisioningErrorKind::MalformedResponse)
        }
    }
}

struct AppleProvisioningTransport;

impl ProvisioningTransport for AppleProvisioningTransport {
    fn lookup(
        &self,
        headers: &ProvisioningHeaders<'_>,
        deadline: Instant,
    ) -> Result<Lookup, ProvisioningErrorKind> {
        let body = request(LOOKUP_ENDPOINT, Method::Get, None, headers, deadline)?;
        parse_lookup_response(&body)
    }

    fn start(
        &self,
        endpoint: Endpoint,
        headers: &ProvisioningHeaders<'_>,
        deadline: Instant,
    ) -> Result<StartResponse, ProvisioningErrorKind> {
        let body = request(
            endpoint.value(),
            Method::Post,
            Some(&start_request()),
            headers,
            deadline,
        )?;
        parse_start_response(&body)
    }

    fn finish(
        &self,
        endpoint: Endpoint,
        cpim: &[u8],
        headers: &ProvisioningHeaders<'_>,
        deadline: Instant,
    ) -> Result<FinishResponse, ProvisioningErrorKind> {
        let request_body = finish_request(cpim);
        let body = request(
            endpoint.value(),
            Method::Post,
            Some(&request_body),
            headers,
            deadline,
        )?;
        parse_finish_response(&body)
    }
}

fn parse_lookup_response(body: &[u8]) -> Result<Lookup, ProvisioningErrorKind> {
    let root = parse_document(body)?;
    let document = root.dict_containing(&[])?;
    let values = match (document.optional("Response"), document.optional("Status")) {
        (Some(response), Some(status)) => {
            validate_status(status)?;
            response.dict_containing(&["urls"])?
        }
        (None, Some(status)) => {
            validate_status(status)?;
            document
        }
        (None, None) => document,
        (Some(_), None) => return Err(ProvisioningErrorKind::MalformedResponse),
    };
    let urls = values
        .get("urls")?
        .dict_containing(&["midStartProvisioning", "midFinishProvisioning"])?;
    Ok(Lookup {
        start_endpoint: Endpoint::parse(
            urls.get("midStartProvisioning")?.string()?,
            Endpoint::Start,
        )?,
        finish_endpoint: Endpoint::parse(
            urls.get("midFinishProvisioning")?.string()?,
            Endpoint::Finish,
        )?,
    })
}

fn parse_start_response(body: &[u8]) -> Result<StartResponse, ProvisioningErrorKind> {
    let root = parse_document(body)?;
    let envelope = root.dict_containing(&["Response"])?;
    envelope.only_known(&["Header", "Response", "Status"])?;
    validate_optional_empty_header(&envelope)?;
    let response = envelope.get("Response")?.dict_containing(&["spim"])?;
    response.only_known(&["spim", "Status", "X-Apple-I-MD-RINFO"])?;
    validate_optional_routing(&response)?;
    validate_envelope_status(&envelope, &response)?;
    Ok(StartResponse(secret_data(response.get("spim")?)?))
}

fn parse_finish_response(body: &[u8]) -> Result<FinishResponse, ProvisioningErrorKind> {
    let root = parse_document(body)?;
    let envelope = root.dict_containing(&["Response"])?;
    envelope.only_known(&["Header", "Response", "Status"])?;
    validate_optional_empty_header(&envelope)?;
    let response = envelope.get("Response")?.dict_containing(&["ptm", "tk"])?;
    response.only_known(&["ptm", "tk", "Status", "X-Apple-I-MD-RINFO"])?;
    validate_optional_routing(&response)?;
    validate_envelope_status(&envelope, &response)?;
    Ok(FinishResponse {
        ptm: secret_data(response.get("ptm")?)?,
        tk: secret_data(response.get("tk")?)?,
    })
}

fn validate_optional_empty_header(envelope: &DictRef<'_>) -> Result<(), ProvisioningErrorKind> {
    if let Some(header) = envelope.optional("Header") {
        header.dict_containing(&[])?.only_known(&[])?;
    }
    Ok(())
}

fn validate_envelope_status(
    envelope: &DictRef<'_>,
    response: &DictRef<'_>,
) -> Result<(), ProvisioningErrorKind> {
    match (response.optional("Status"), envelope.optional("Status")) {
        (Some(status), None) | (None, Some(status)) => validate_status(status),
        _ => Err(ProvisioningErrorKind::MalformedResponse),
    }
}

fn validate_optional_routing(response: &DictRef<'_>) -> Result<(), ProvisioningErrorKind> {
    if let Some(value) = response.optional("X-Apple-I-MD-RINFO") {
        let Node::String(value) = value else {
            return Err(ProvisioningErrorKind::MalformedResponse);
        };
        validate_header_value(value).map_err(|_| ProvisioningErrorKind::MalformedResponse)?;
    }
    Ok(())
}

enum Method {
    Get,
    Post,
}

fn add_protocol_headers<B>(
    mut request: ureq::RequestBuilder<B>,
    headers: &ProvisioningHeaders<'_>,
) -> ureq::RequestBuilder<B> {
    request = request.header("content-type", CONTENT_TYPE);
    for (name, value) in headers.entries() {
        request = request.header(name, value);
    }
    request
}

fn request(
    url: &str,
    method: Method,
    body: Option<&[u8]>,
    headers: &ProvisioningHeaders<'_>,
    deadline: Instant,
) -> Result<Zeroizing<Vec<u8>>, ProvisioningErrorKind> {
    let remaining = deadline
        .checked_duration_since(Instant::now())
        .ok_or(ProvisioningErrorKind::Transport)?;
    let agent = provisioning_agent(remaining);
    let response = match method {
        Method::Get => add_protocol_headers(agent.get(url), headers).call(),
        Method::Post => add_protocol_headers(agent.post(url), headers).send(body.unwrap_or(&[])),
    }
    .map_err(classify_transport)?;
    if response.status().as_u16() != 200 {
        return Err(ProvisioningErrorKind::HttpStatus(
            response.status().as_u16(),
        ));
    }
    let content_types = response.headers().get_all("content-type");
    let mut values = content_types.iter();
    let content_type = values.next().and_then(|value| value.to_str().ok());
    if !content_type.is_some_and(valid_content_type) || values.next().is_some() {
        return Err(ProvisioningErrorKind::ContentType);
    }
    let mut bytes = Zeroizing::new(Vec::with_capacity(MAX_RESPONSE_BYTES + 1));
    response
        .into_body()
        .into_reader()
        .take((MAX_RESPONSE_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| ProvisioningErrorKind::Transport)?;
    if bytes.len() > MAX_RESPONSE_BYTES {
        return Err(ProvisioningErrorKind::MalformedResponse);
    }
    Ok(bytes)
}

fn provisioning_agent(timeout: Duration) -> ureq::Agent {
    let config = ureq::Agent::config_builder()
        .max_redirects(0)
        .max_redirects_will_error(true)
        .http_status_as_error(true)
        .https_only(true)
        .proxy(None)
        .tls_config(gsa_tls_config())
        .user_agent(AKD_USER_AGENT)
        .timeout_global(Some(timeout))
        .build();
    ureq::Agent::new_with_config(config)
}

fn gsa_tls_config() -> TlsConfig {
    let certificate = Certificate::from_der(coffer_protocol::pki::APPLE_INC_ROOT_CA_DER);
    TlsConfig::builder()
        .root_certs(RootCerts::new_with_certs(&[certificate]))
        .use_sni(true)
        .disable_verification(false)
        .build()
}

fn classify_transport(error: ureq::Error) -> ProvisioningErrorKind {
    match error {
        ureq::Error::Tls(_) | ureq::Error::Rustls(_) => ProvisioningErrorKind::Tls,
        ureq::Error::Io(error)
            if error
                .get_ref()
                .is_some_and(|source| source.is::<rustls::Error>()) =>
        {
            ProvisioningErrorKind::Tls
        }
        ureq::Error::TooManyRedirects | ureq::Error::RedirectFailed => {
            ProvisioningErrorKind::Redirect
        }
        ureq::Error::StatusCode(401 | 407) => ProvisioningErrorKind::AuthenticationChallenge,
        ureq::Error::StatusCode(status) if (300..400).contains(&status) => {
            ProvisioningErrorKind::Redirect
        }
        ureq::Error::StatusCode(status) => ProvisioningErrorKind::HttpStatus(status),
        _ => ProvisioningErrorKind::Transport,
    }
}

fn valid_content_type(value: &str) -> bool {
    let mut parts = value.split(';');
    if !parts
        .next()
        .is_some_and(|media_type| media_type.trim().eq_ignore_ascii_case(CONTENT_TYPE))
    {
        return false;
    }
    let parameters: Vec<_> = parts.collect();
    parameters.is_empty()
        || (parameters.len() == 1 && parameters[0].trim().eq_ignore_ascii_case("charset=utf-8"))
}

fn start_request() -> Zeroizing<Vec<u8>> {
    Zeroizing::new(b"<?xml version=\"1.0\" encoding=\"UTF-8\"?><plist version=\"1.0\"><dict><key>Header</key><dict/><key>Request</key><dict/></dict></plist>".to_vec())
}

fn finish_request(cpim: &[u8]) -> Zeroizing<Vec<u8>> {
    const PREFIX: &[u8] = b"<?xml version=\"1.0\" encoding=\"UTF-8\"?><plist version=\"1.0\"><dict><key>Header</key><dict/><key>Request</key><dict><key>cpim</key><string>";
    const SUFFIX: &[u8] = b"</string></dict></dict></plist>";
    let mut encoded = Zeroizing::new(STANDARD.encode(cpim));
    let capacity = PREFIX.len() + encoded.len() + SUFFIX.len();
    let mut body = Zeroizing::new(Vec::with_capacity(capacity));
    body.extend_from_slice(PREFIX);
    body.extend_from_slice(encoded.as_bytes());
    body.extend_from_slice(SUFFIX);
    encoded.zeroize();
    body
}

enum Node {
    Dict(Vec<(String, Node)>),
    String(Zeroizing<String>),
    Data(Zeroizing<String>),
    Integer(i64),
    IgnoredStandardValue,
}

impl Node {
    fn dict_containing(&self, keys: &[&str]) -> Result<DictRef<'_>, ProvisioningErrorKind> {
        let Self::Dict(values) = self else {
            return Err(ProvisioningErrorKind::MalformedResponse);
        };
        if !keys
            .iter()
            .all(|key| values.iter().any(|(name, _)| name == key))
        {
            return Err(ProvisioningErrorKind::MalformedResponse);
        }
        Ok(DictRef(values))
    }

    fn string(&self) -> Result<&str, ProvisioningErrorKind> {
        match self {
            Self::String(value) => Ok(value),
            _ => Err(ProvisioningErrorKind::MalformedResponse),
        }
    }
}

struct DictRef<'a>(&'a [(String, Node)]);

impl<'a> DictRef<'a> {
    fn only_known(&self, keys: &[&str]) -> Result<(), ProvisioningErrorKind> {
        if self.0.iter().all(|(name, _)| keys.contains(&name.as_str())) {
            Ok(())
        } else {
            Err(ProvisioningErrorKind::MalformedResponse)
        }
    }

    fn optional(&self, key: &str) -> Option<&'a Node> {
        self.0
            .iter()
            .find_map(|(name, value)| (name == key).then_some(value))
    }

    fn get(&self, key: &str) -> Result<&'a Node, ProvisioningErrorKind> {
        self.optional(key)
            .ok_or(ProvisioningErrorKind::MalformedResponse)
    }
}

fn validate_status(node: &Node) -> Result<(), ProvisioningErrorKind> {
    let status = node.dict_containing(&["ec"])?;
    status.only_known(&["ec", "em", "au", "hsc", "ed", "ptxid", "rsh"])?;
    for name in ["em", "au"] {
        if let Some(value) = status.optional(name)
            && !matches!(value, Node::String(_))
        {
            return Err(ProvisioningErrorKind::MalformedResponse);
        }
    }
    match status.get("ec")? {
        Node::Integer(0) => Ok(()),
        Node::Integer(code) => Err(ProvisioningErrorKind::ProtocolStatus(*code)),
        _ => Err(ProvisioningErrorKind::MalformedResponse),
    }
}

fn secret_data(node: &Node) -> Result<SecretBytes, ProvisioningErrorKind> {
    let value = match node {
        Node::String(value) | Node::Data(value) => value,
        _ => return Err(ProvisioningErrorKind::MalformedResponse),
    };
    let encoded = Zeroizing::new(
        value
            .bytes()
            .filter(|byte| !byte.is_ascii_whitespace())
            .collect::<Vec<_>>(),
    );
    if encoded.len() > 4 * 1024 * 1024 / 3 + 8 {
        return Err(ProvisioningErrorKind::MalformedResponse);
    }
    let maximum_length = encoded.len() / 4 * 3 + 3;
    let mut decoded = Zeroizing::new(vec![0; maximum_length]);
    let decoded_length = STANDARD
        .decode_slice(encoded.as_slice(), &mut decoded)
        .map_err(|_| ProvisioningErrorKind::MalformedResponse)?;
    decoded.truncate(decoded_length);
    if decoded.is_empty() {
        return Err(ProvisioningErrorKind::MalformedResponse);
    }
    SecretBytes::new(std::mem::take(&mut *decoded))
        .map_err(|_| ProvisioningErrorKind::MalformedResponse)
}

fn parse_document(bytes: &[u8]) -> Result<Node, ProvisioningErrorKind> {
    if bytes.is_empty() || bytes.len() > MAX_RESPONSE_BYTES {
        return Err(ProvisioningErrorKind::MalformedResponse);
    }
    let mut reader = Reader::from_reader(bytes);
    reader.config_mut().trim_text(false);
    let mut buffer = Zeroizing::new(Vec::new());
    let mut stack: Vec<Container> = Vec::new();
    let mut root = None;
    let mut fields = 0usize;
    let mut nodes = 0usize;
    let mut started = false;
    let mut saw_declaration = false;
    let mut saw_doctype = false;
    loop {
        match reader.read_event_into(&mut buffer) {
            Ok(Event::Decl(_)) if !started && !saw_declaration => {
                saw_declaration = true;
            }
            Ok(Event::Decl(_)) => return Err(ProvisioningErrorKind::MalformedResponse),
            Ok(Event::DocType(_)) if !started && !saw_doctype => {
                saw_doctype = true;
            }
            Ok(Event::DocType(_)) => return Err(ProvisioningErrorKind::MalformedResponse),
            Ok(Event::Start(tag)) => {
                started = true;
                let name = tag.name();
                match name.as_ref() {
                    b"plist" => {
                        if !stack.is_empty() || root.is_some() {
                            return Err(ProvisioningErrorKind::MalformedResponse);
                        }
                        validate_attributes(&tag, true)?;
                        stack.push(Container::Plist);
                    }
                    b"dict" => {
                        validate_attributes(&tag, false)?;
                        stack.push(Container::Dict {
                            values: Vec::new(),
                            key: None,
                        });
                    }
                    b"array" => {
                        validate_attributes(&tag, false)?;
                        stack.push(Container::Array);
                    }
                    b"key" => {
                        validate_attributes(&tag, false)?;
                        stack.push(Container::Text(
                            TextKind::Key,
                            Zeroizing::new(String::new()),
                        ));
                    }
                    b"string" => {
                        validate_attributes(&tag, false)?;
                        stack.push(Container::Text(
                            TextKind::String,
                            Zeroizing::new(String::new()),
                        ));
                    }
                    b"data" => {
                        validate_attributes(&tag, false)?;
                        stack.push(Container::Text(
                            TextKind::Data,
                            Zeroizing::new(String::new()),
                        ));
                    }
                    b"integer" => {
                        validate_attributes(&tag, false)?;
                        stack.push(Container::Text(
                            TextKind::Integer,
                            Zeroizing::new(String::new()),
                        ));
                    }
                    b"real" => {
                        validate_attributes(&tag, false)?;
                        stack.push(Container::Text(
                            TextKind::Real,
                            Zeroizing::new(String::new()),
                        ));
                    }
                    b"date" => {
                        validate_attributes(&tag, false)?;
                        stack.push(Container::Text(
                            TextKind::Date,
                            Zeroizing::new(String::new()),
                        ));
                    }
                    _ => return Err(ProvisioningErrorKind::MalformedResponse),
                }
                if stack.len() > MAX_XML_DEPTH {
                    return Err(ProvisioningErrorKind::MalformedResponse);
                }
            }
            Ok(Event::Empty(tag)) => {
                started = true;
                validate_attributes(&tag, false)?;
                let node = match tag.name().as_ref() {
                    b"dict" => Node::Dict(Vec::new()),
                    b"string" => Node::String(Zeroizing::new(String::new())),
                    b"data" => Node::Data(Zeroizing::new(String::new())),
                    b"array" | b"true" | b"false" => Node::IgnoredStandardValue,
                    _ => return Err(ProvisioningErrorKind::MalformedResponse),
                };
                push_node(&mut stack, &mut root, &mut nodes, node)?
            }
            Ok(Event::Text(text)) => {
                let decoded = text
                    .decode()
                    .map_err(|_| ProvisioningErrorKind::MalformedResponse)?;
                if let Some(Container::Text(_, value)) = stack.last_mut() {
                    value.push_str(&decoded);
                    if value.len() > MAX_RESPONSE_BYTES {
                        return Err(ProvisioningErrorKind::MalformedResponse);
                    }
                } else if !decoded.bytes().all(is_xml_whitespace) {
                    return Err(ProvisioningErrorKind::MalformedResponse);
                }
            }
            Ok(Event::GeneralRef(reference)) => {
                let Container::Text(_, value) = stack
                    .last_mut()
                    .ok_or(ProvisioningErrorKind::MalformedResponse)?
                else {
                    return Err(ProvisioningErrorKind::MalformedResponse);
                };
                append_reference(&reference, value)?;
            }
            Ok(Event::End(tag)) => {
                let container = stack
                    .pop()
                    .ok_or(ProvisioningErrorKind::MalformedResponse)?;
                match (tag.name().as_ref(), container) {
                    (b"plist", Container::Plist) => {}
                    (b"dict", Container::Dict { values, key: None }) => {
                        push_node(&mut stack, &mut root, &mut nodes, Node::Dict(values))?;
                    }
                    (b"array", Container::Array) => {
                        push_node(
                            &mut stack,
                            &mut root,
                            &mut nodes,
                            Node::IgnoredStandardValue,
                        )?;
                    }
                    (b"key", Container::Text(TextKind::Key, key)) => {
                        let Some(Container::Dict { values, key: slot }) = stack.last_mut() else {
                            return Err(ProvisioningErrorKind::MalformedResponse);
                        };
                        if key.is_empty()
                            || values.iter().any(|(existing, _)| existing == key.as_str())
                            || slot.is_some()
                        {
                            return Err(ProvisioningErrorKind::MalformedResponse);
                        }
                        *slot = Some(key.to_string());
                        fields += 1;
                        if fields > MAX_XML_FIELDS {
                            return Err(ProvisioningErrorKind::MalformedResponse);
                        }
                    }
                    (b"string", Container::Text(TextKind::String, value)) => {
                        push_node(&mut stack, &mut root, &mut nodes, Node::String(value))?
                    }
                    (b"data", Container::Text(TextKind::Data, value)) => {
                        push_node(&mut stack, &mut root, &mut nodes, Node::Data(value))?
                    }
                    (b"integer", Container::Text(TextKind::Integer, value)) => {
                        let value = value
                            .as_str()
                            .trim()
                            .parse()
                            .map_err(|_| ProvisioningErrorKind::MalformedResponse)?;
                        push_node(&mut stack, &mut root, &mut nodes, Node::Integer(value))?;
                    }
                    (b"real", Container::Text(TextKind::Real, value)) => {
                        value
                            .as_str()
                            .trim()
                            .parse::<f64>()
                            .map_err(|_| ProvisioningErrorKind::MalformedResponse)?;
                        push_node(
                            &mut stack,
                            &mut root,
                            &mut nodes,
                            Node::IgnoredStandardValue,
                        )?;
                    }
                    (b"date", Container::Text(TextKind::Date, value))
                        if !value.trim().is_empty() =>
                    {
                        push_node(
                            &mut stack,
                            &mut root,
                            &mut nodes,
                            Node::IgnoredStandardValue,
                        )?;
                    }
                    _ => return Err(ProvisioningErrorKind::MalformedResponse),
                }
            }
            Ok(Event::Eof) => break,
            Ok(Event::Comment(_) | Event::CData(_) | Event::PI(_)) => {
                return Err(ProvisioningErrorKind::MalformedResponse);
            }
            Err(_) => return Err(ProvisioningErrorKind::MalformedResponse),
        }
        buffer.zeroize();
    }
    if !stack.is_empty() {
        return Err(ProvisioningErrorKind::MalformedResponse);
    }
    root.ok_or(ProvisioningErrorKind::MalformedResponse)
}

enum TextKind {
    Key,
    String,
    Data,
    Integer,
    Real,
    Date,
}

enum Container {
    Plist,
    Dict {
        values: Vec<(String, Node)>,
        key: Option<String>,
    },
    Array,
    Text(TextKind, Zeroizing<String>),
}

fn append_reference(
    reference: &BytesRef<'_>,
    value: &mut String,
) -> Result<(), ProvisioningErrorKind> {
    let decoded = reference
        .decode()
        .map_err(|_| ProvisioningErrorKind::MalformedResponse)?;
    if let Some(entity) = resolve_xml_entity(&decoded) {
        value.push_str(entity);
    } else {
        let character = reference
            .resolve_char_ref()
            .map_err(|_| ProvisioningErrorKind::MalformedResponse)?
            .filter(|character| is_valid_xml_character(*character))
            .ok_or(ProvisioningErrorKind::MalformedResponse)?;
        value.push(character);
    }
    if value.len() > MAX_RESPONSE_BYTES {
        return Err(ProvisioningErrorKind::MalformedResponse);
    }
    Ok(())
}

fn is_valid_xml_character(character: char) -> bool {
    matches!(
        character,
        '\u{9}' | '\u{a}' | '\u{d}' | '\u{20}'..='\u{d7ff}' | '\u{e000}'..='\u{fffd}' | '\u{10000}'..='\u{10ffff}'
    )
}

fn is_xml_whitespace(byte: u8) -> bool {
    matches!(byte, b' ' | b'\t' | b'\n' | b'\r')
}

fn validate_attributes(tag: &BytesStart<'_>, plist: bool) -> Result<(), ProvisioningErrorKind> {
    let mut attributes = tag.attributes();
    attributes.with_checks(true);
    if plist {
        let attribute = attributes
            .next()
            .ok_or(ProvisioningErrorKind::MalformedResponse)?
            .map_err(|_| ProvisioningErrorKind::MalformedResponse)?;
        if attribute.key.as_ref() != b"version" || attribute.value.as_ref() != b"1.0" {
            return Err(ProvisioningErrorKind::MalformedResponse);
        }
    }
    if attributes.next().is_some() {
        return Err(ProvisioningErrorKind::MalformedResponse);
    }
    Ok(())
}

fn push_node(
    stack: &mut [Container],
    root: &mut Option<Node>,
    nodes: &mut usize,
    node: Node,
) -> Result<(), ProvisioningErrorKind> {
    *nodes = nodes
        .checked_add(1)
        .ok_or(ProvisioningErrorKind::MalformedResponse)?;
    if *nodes > MAX_XML_NODES {
        return Err(ProvisioningErrorKind::MalformedResponse);
    }
    if let Some(Container::Dict { values, key }) = stack.last_mut() {
        let key = key.take().ok_or(ProvisioningErrorKind::MalformedResponse)?;
        values.push((key, node));
        Ok(())
    } else if matches!(stack.last(), Some(Container::Array)) {
        Ok(())
    } else if matches!(stack.last(), Some(Container::Plist)) && root.is_none() {
        *root = Some(node);
        Ok(())
    } else {
        Err(ProvisioningErrorKind::MalformedResponse)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    const CAPTURED_START_ENDPOINT: &str =
        "https://gsa.apple.com/grandslam/MidService/startMachineProvisioning";
    const CAPTURED_FINISH_ENDPOINT: &str =
        "https://gsa.apple.com/grandslam/MidService/finishMachineProvisioning";

    fn lookup_with_endpoints(start: &str, finish: &str) -> Vec<u8> {
        format!(
            "<plist version=\"1.0\"><dict><key>urls</key><dict><key>midStartProvisioning</key><string>{start}</string><key>midFinishProvisioning</key><string>{finish}</string></dict></dict></plist>"
        )
        .into_bytes()
    }

    fn synthetic_url(scheme: &str, remainder: &str) -> String {
        format!("{scheme}:{}{}", "/", format_args!("/{remainder}"))
    }

    #[test]
    fn provisioning_agent_uses_only_apples_root() {
        let agent = provisioning_agent(Duration::from_secs(30));
        let config = agent.config();
        let tls = config.tls_config();
        let RootCerts::Specific(certificates) = tls.root_certs() else {
            panic!("GSA provisioning must use endpoint-specific roots");
        };

        assert_eq!(certificates.len(), 1);
        assert_eq!(
            certificates[0].der(),
            coffer_protocol::pki::APPLE_INC_ROOT_CA_DER
        );
        assert!(tls.use_sni());
        assert!(!tls.disable_verification());
        assert!(config.https_only());
        assert_eq!(config.max_redirects(), 0);
        assert!(config.max_redirects_will_error());
        assert!(config.proxy().is_none());
        assert!(config.http_status_as_error());
    }

    #[test]
    fn tls_failures_are_distinct_and_secret_free() {
        assert_eq!(
            classify_transport(ureq::Error::Tls("server-controlled detail")),
            ProvisioningErrorKind::Tls
        );
        let certificate_error =
            rustls::Error::InvalidCertificate(rustls::CertificateError::UnknownIssuer);
        assert_eq!(
            classify_transport(ureq::Error::Rustls(certificate_error.clone())),
            ProvisioningErrorKind::Tls
        );
        let wrapped = std::io::Error::new(std::io::ErrorKind::InvalidData, certificate_error);
        assert_eq!(
            classify_transport(ureq::Error::Io(wrapped)),
            ProvisioningErrorKind::Tls
        );
        assert_eq!(
            classify_transport(ureq::Error::ConnectionFailed),
            ProvisioningErrorKind::Transport
        );
    }

    #[test]
    fn lookup_fixture_is_exact_and_strict() {
        let lookup = b"<?xml version=\"1.0\"?><plist version=\"1.0\"><dict><key>Response</key><dict><key>urls</key><dict><key>midStartProvisioning</key><string>https://gsa.apple.com/grandslam/MidService/startMachineProvisioning</string><key>midFinishProvisioning</key><string>https://gsa.apple.com/grandslam/MidService/finishMachineProvisioning</string></dict></dict><key>Status</key><dict><key>ec</key><integer>0</integer></dict></dict></plist>";
        parse_lookup_response(lookup).expect("wrapped lookup");
        let root = parse_document(lookup).expect("parse");
        let response = root.dict_containing(&["Response", "Status"]).expect("root");
        validate_status(response.get("Status").expect("status")).expect("ok");
        let duplicate = b"<plist version=\"1.0\"><dict><key>Status</key><integer>0</integer><key>Status</key><integer>0</integer></dict></plist>";
        assert!(matches!(
            parse_document(duplicate),
            Err(ProvisioningErrorKind::MalformedResponse)
        ));
        let bounded_extra = b"<plist version=\"1.0\"><dict><key>Response</key><dict/><key>Status</key><dict><key>ec</key><integer>0</integer></dict><key>extra</key><string>x</string></dict></plist>";
        assert!(
            parse_document(bounded_extra)
                .expect("parse")
                .dict_containing(&["Response", "Status"])
                .is_ok()
        );
        assert!(matches!(
            parse_document(b"<plist version=\"1.0\" extra=\"x\"><dict/></plist>"),
            Err(ProvisioningErrorKind::MalformedResponse)
        ));
        assert!(matches!(
            parse_document(
                b"<plist version=\"1.0\"><plist version=\"1.0\"><dict/></plist></plist>"
            ),
            Err(ProvisioningErrorKind::MalformedResponse)
        ));
        assert!(matches!(
            parse_document(b"<plist version=\"1.0\"><dict extra=\"x\"/></plist>"),
            Err(ProvisioningErrorKind::MalformedResponse)
        ));
        assert!(matches!(
            parse_document(&vec![b'x'; MAX_RESPONSE_BYTES + 1]),
            Err(ProvisioningErrorKind::MalformedResponse)
        ));

        let directory = b"<plist version=\"1.0\"><dict><key>urls</key><dict><key>unrelated</key><string>unused</string><key>midStartProvisioning</key><string>https://gsa.apple.com/grandslam/MidService/startMachineProvisioning</string><key>midFinishProvisioning</key><string>https://gsa.apple.com/grandslam/MidService/finishMachineProvisioning</string></dict><key>extra</key><string>bounded</string></dict></plist>";
        parse_lookup_response(directory).expect("top-level directory with bounded extras");
    }

    #[test]
    fn lookup_accepts_realistic_standard_values_and_entities() {
        let mut extras = String::new();
        for index in 0..150 {
            extras.push_str(&format!(
                "<key>synthetic-{index}</key><string>bounded &amp; inert</string>"
            ));
        }
        let document = format!(
            "<?xml version=\"1.0\"?><!DOCTYPE plist><plist version=\"1.0\"><dict><key>empty-string</key><string/><key>empty-data</key><data/><key>enabled</key><true/><key>disabled</key><false/><key>ratio</key><real>1.25</real><key>timestamp</key><date>2026-09-11T00:00:00Z</date><key>items</key><array><string>one</string><integer>2</integer><true/><dict/><array/></array>{extras}<key>urls</key><dict><key>midStartProvisioning</key><string>{CAPTURED_START_ENDPOINT}</string><key>midFinishProvisioning</key><string>{CAPTURED_FINISH_ENDPOINT}</string></dict><key>Status</key><dict><key>hsc</key><integer>200</integer><key>ed</key><string>success</string><key>ec</key><integer>0</integer><key>em</key><string></string><key>ptxid</key><string>synthetic-transaction</string><key>rsh</key><string>synthetic-routing</string></dict></dict></plist>"
        );
        let lookup = parse_lookup_response(document.as_bytes()).expect("realistic lookup bag");
        assert_eq!(lookup.start_endpoint.value(), CAPTURED_START_ENDPOINT);
        assert_eq!(lookup.finish_endpoint.value(), CAPTURED_FINISH_ENDPOINT);
    }

    #[test]
    fn provisioning_endpoint_allowlists_are_role_exact() {
        let valid = lookup_with_endpoints(CAPTURED_START_ENDPOINT, CAPTURED_FINISH_ENDPOINT);
        parse_lookup_response(&valid).expect("captured MidService endpoints");

        for invalid_start in [
            synthetic_url(
                "http",
                "gsa.apple.com/grandslam/MidService/startMachineProvisioning",
            ),
            synthetic_url(
                "https",
                "evil.example/grandslam/MidService/startMachineProvisioning",
            ),
            CAPTURED_FINISH_ENDPOINT.to_owned(),
            synthetic_url(
                "https",
                "gsa.apple.com/grandslam/MidService/startMachineProvisioning/",
            ),
            synthetic_url(
                "https",
                "gsa.apple.com/grandslam/MidService/startMachineProvisioning?x=1",
            ),
            synthetic_url(
                "https",
                "gsa.apple.com/grandslam/MidService/startMachineProvisioning#x",
            ),
        ] {
            assert!(matches!(
                parse_lookup_response(&lookup_with_endpoints(
                    &invalid_start,
                    CAPTURED_FINISH_ENDPOINT
                )),
                Err(ProvisioningErrorKind::MalformedResponse)
            ));
        }
        for invalid_finish in [
            synthetic_url(
                "http",
                "gsa.apple.com/grandslam/MidService/finishMachineProvisioning",
            ),
            synthetic_url(
                "https",
                "evil.example/grandslam/MidService/finishMachineProvisioning",
            ),
            CAPTURED_START_ENDPOINT.to_owned(),
            synthetic_url(
                "https",
                "gsa.apple.com/grandslam/MidService/finishMachineProvisioning/",
            ),
            synthetic_url(
                "https",
                "gsa.apple.com/grandslam/MidService/finishMachineProvisioning?x=1",
            ),
            synthetic_url(
                "https",
                "gsa.apple.com/grandslam/MidService/finishMachineProvisioning#x",
            ),
        ] {
            assert!(matches!(
                parse_lookup_response(&lookup_with_endpoints(
                    CAPTURED_START_ENDPOINT,
                    &invalid_finish
                )),
                Err(ProvisioningErrorKind::MalformedResponse)
            ));
        }
    }

    #[test]
    fn ignored_standard_nodes_cannot_supply_required_values() {
        for value in [
            "<data>aHR0cHM6Ly9nc2EuYXBwbGUuY29tLw==</data>",
            "<integer>1</integer>",
            "<true/>",
            "<real>1.0</real>",
            "<date>2026-09-11T00:00:00Z</date>",
            "<array/>",
            "<dict/>",
        ] {
            let document = format!(
                "<plist version=\"1.0\"><dict><key>urls</key><dict><key>midStartProvisioning</key>{value}<key>midFinishProvisioning</key><string>{CAPTURED_FINISH_ENDPOINT}</string></dict></dict></plist>"
            );
            assert!(matches!(
                parse_lookup_response(document.as_bytes()),
                Err(ProvisioningErrorKind::MalformedResponse)
            ));
        }

        let wrong_spim = b"<plist version=\"1.0\"><dict><key>Response</key><dict><key>spim</key><array/></dict><key>Status</key><dict><key>ec</key><integer>0</integer></dict></dict></plist>";
        assert!(matches!(
            parse_start_response(wrong_spim),
            Err(ProvisioningErrorKind::MalformedResponse)
        ));
    }

    #[test]
    fn xml_references_are_bounded_and_restricted() {
        let node = parse_document(
            b"<plist version=\"1.0\"><string>&amp;&lt;&gt;&apos;&quot;&#65;&#x1F642;</string></plist>",
        )
        .expect("predefined and numeric references");
        assert_eq!(node.string().expect("string"), "&<>'\"A🙂");
        let spaced =
            parse_document(b"<plist version=\"1.0\"><string>bounded &amp; inert</string></plist>")
                .expect("reference whitespace");
        assert_eq!(spaced.string().expect("string"), "bounded & inert");
        let distinct_keys = parse_document(
            b"<plist version=\"1.0\"><dict><key>a &amp; b</key><string/><key>a&amp;b</key><string/></dict></plist>",
        )
        .expect("distinct decoded keys");
        let distinct_keys = distinct_keys.dict_containing(&[]).expect("dictionary");
        distinct_keys.get("a & b").expect("spaced key");
        distinct_keys.get("a&b").expect("unspaced key");

        for invalid in [
            b"<plist version=\"1.0\"><string>&custom;</string></plist>".as_slice(),
            b"<plist version=\"1.0\"><string>&#0;</string></plist>".as_slice(),
            b"<plist version=\"1.0\"><string>&#1;</string></plist>".as_slice(),
            b"<!DOCTYPE plist [<!ENTITY custom \"x\">]><plist version=\"1.0\"><string>&custom;</string></plist>".as_slice(),
        ] {
            assert!(matches!(
                parse_document(invalid),
                Err(ProvisioningErrorKind::MalformedResponse)
            ));
        }
        let external_entity = format!(
            "<!DOCTYPE plist [<!ENTITY external SYSTEM \"{}:{}//etc/passwd\">]><plist version=\"1.0\"><string>&external;</string></plist>",
            "file", "/"
        );
        assert!(matches!(
            parse_document(external_entity.as_bytes()),
            Err(ProvisioningErrorKind::MalformedResponse)
        ));
    }

    #[test]
    fn parser_rejects_unknown_markup_and_attributes() {
        for invalid in [
            b"<plist version=\"1.0\"><set/></plist>".as_slice(),
            b"<plist version=\"1.0\"><array extra=\"x\"/></plist>".as_slice(),
            b"<plist version=\"1.0\"><!-- no comments --><dict/></plist>".as_slice(),
            b"<plist version=\"1.0\"><string><![CDATA[x]]></string></plist>".as_slice(),
            b"<plist version=\"1.0\"><?target x?><dict/></plist>".as_slice(),
            b"<plist version=\"1.0\"><dict/>stray</plist>".as_slice(),
        ] {
            assert!(matches!(
                parse_document(invalid),
                Err(ProvisioningErrorKind::MalformedResponse)
            ));
        }
    }

    #[test]
    fn field_depth_node_and_body_bounds_hold() {
        let mut at_field_limit = String::from("<plist version=\"1.0\"><dict>");
        for index in 0..MAX_XML_FIELDS {
            at_field_limit.push_str(&format!("<key>k{index}</key><string/>"));
        }
        at_field_limit.push_str("</dict></plist>");
        parse_document(at_field_limit.as_bytes()).expect("inclusive field and node limit");

        let over_field_limit = at_field_limit.replacen(
            "</dict>",
            &format!("<key>k{MAX_XML_FIELDS}</key><string/></dict>"),
            1,
        );
        assert!(matches!(
            parse_document(over_field_limit.as_bytes()),
            Err(ProvisioningErrorKind::MalformedResponse)
        ));

        let mut at_node_limit = String::from("<plist version=\"1.0\"><array>");
        for _ in 0..MAX_XML_FIELDS {
            at_node_limit.push_str("<string/>");
        }
        at_node_limit.push_str("</array></plist>");
        parse_document(at_node_limit.as_bytes()).expect("inclusive completed-node limit");
        let over_node_limit = at_node_limit.replacen("</array>", "<string/></array>", 1);
        assert!(matches!(
            parse_document(over_node_limit.as_bytes()),
            Err(ProvisioningErrorKind::MalformedResponse)
        ));

        let too_deep = format!(
            "<plist version=\"1.0\">{}<array/>{}</plist>",
            "<array>".repeat(MAX_XML_DEPTH),
            "</array>".repeat(MAX_XML_DEPTH)
        );
        assert!(matches!(
            parse_document(too_deep.as_bytes()),
            Err(ProvisioningErrorKind::MalformedResponse)
        ));
        assert!(matches!(
            parse_document(&vec![b'x'; MAX_RESPONSE_BYTES + 1]),
            Err(ProvisioningErrorKind::MalformedResponse)
        ));
    }

    #[test]
    fn provisioning_headers_are_exact_and_secret_redacted() {
        let context = context();
        let headers = context.headers().expect("headers");
        assert_eq!(
            headers.entries().as_slice(),
            [
                ("X-Apple-I-MD-LU", "local-user"),
                ("X-Mme-Device-Id", "device-id"),
                ("X-Mme-Client-Info", CLIENT_INFO),
                ("X-Apple-I-SRL-NO", "0"),
                ("X-Apple-I-Client-Time", "2026-09-04T00:00:00Z"),
                ("X-Apple-I-TimeZone", "UTC"),
                ("X-Apple-Locale", "en_US"),
            ]
            .as_slice()
        );
        assert!(matches!(
            provisioning_agent(Duration::from_secs(30))
                .config()
                .user_agent(),
            ureq::config::AutoHeaderValue::Provided(value) if value.as_str() == "akd/1.0 CFNetwork/808.1.4"
        ));
        let agent = provisioning_agent(Duration::from_secs(30));
        let lookup_request = add_protocol_headers(agent.get(LOOKUP_ENDPOINT), &headers);
        let request_headers = lookup_request.headers_ref().expect("lookup headers");
        assert_eq!(
            request_headers
                .get("content-type")
                .expect("content type")
                .as_bytes(),
            CONTENT_TYPE.as_bytes()
        );
        for (name, value) in headers.entries() {
            assert_eq!(
                request_headers
                    .get(name)
                    .expect("provisioning header")
                    .as_bytes(),
                value.as_bytes()
            );
        }
        assert_eq!(format!("{context:?}"), "ProvisioningContext(<redacted>)");
    }

    #[test]
    fn plist_content_type_accepts_only_the_exact_type_and_utf8_parameter() {
        assert!(valid_content_type("text/x-xml-plist"));
        assert!(valid_content_type("text/x-xml-plist; charset=UTF-8"));
        assert!(!valid_content_type("application/xml"));
        assert!(!valid_content_type("text/x-xml-plist; boundary=x"));
        assert!(!valid_content_type(
            "text/x-xml-plist; charset=UTF-8; boundary=x"
        ));
    }

    #[test]
    fn secret_data_and_protocol_status_fail_closed() {
        assert!(matches!(
            secret_data(&Node::Data(Zeroizing::new(String::new()))),
            Err(ProvisioningErrorKind::MalformedResponse)
        ));
        assert!(matches!(
            secret_data(&Node::Data(Zeroizing::new("c2VjcmV0!".to_owned()))),
            Err(ProvisioningErrorKind::MalformedResponse)
        ));
        assert!(matches!(
            secret_data(&Node::Data(Zeroizing::new(
                "A".repeat(4 * 1024 * 1024 / 3 + 9)
            ))),
            Err(ProvisioningErrorKind::MalformedResponse)
        ));
        for invalid in [
            String::new(),
            "c2VjcmV0!".to_owned(),
            "A".repeat(4 * 1024 * 1024 / 3 + 9),
        ] {
            assert!(matches!(
                secret_data(&Node::String(Zeroizing::new(invalid))),
                Err(ProvisioningErrorKind::MalformedResponse)
            ));
        }
        let failure = Node::Dict(vec![("ec".to_owned(), Node::Integer(7))]);
        assert_eq!(
            validate_status(&failure),
            Err(ProvisioningErrorKind::ProtocolStatus(7))
        );

        let response = b"<plist version=\"1.0\"><dict><key>Response</key><dict><key>ptm</key><data>cHRt</data><key>tk</key><data>dGs=</data></dict><key>Status</key><dict><key>ec</key><integer>0</integer></dict></dict></plist>";
        let finish = parse_finish_response(response).expect("valid finish response");
        assert_eq!(finish.ptm.expose(), b"ptm");
        assert_eq!(finish.tk.expose(), b"tk");

        let wrapped = b"<?xml version=\"1.0\"?><!DOCTYPE plist><plist version=\"1.0\"><dict><key>Response</key><dict><key>ptm</key><data>\n cH\tRt \n</data><key>tk</key><data>\n dGs= \n</data><key>X-Apple-I-MD-RINFO</key><string>17106176</string><key>Status</key><dict><key>ec</key><integer>0</integer><key>em</key><string></string></dict></dict></dict></plist>";
        let finish = parse_finish_response(wrapped).expect("nested status and wrapped data");
        assert_eq!(finish.ptm.expose(), b"ptm");
        assert_eq!(finish.tk.expose(), b"tk");
        assert!(matches!(
            parse_document(
                b"<!DOCTYPE plist><!DOCTYPE plist><plist version=\"1.0\"><dict/></plist>"
            ),
            Err(ProvisioningErrorKind::MalformedResponse)
        ));

        let start = b"<plist version=\"1.0\"><dict><key>Response</key><dict><key>spim</key><data>c3BpbQ==</data><key>Status</key><dict><key>ec</key><integer>0</integer><key>em</key><string></string></dict></dict></dict></plist>";
        let StartResponse(spim) = parse_start_response(start).expect("valid start response");
        assert_eq!(spim.expose(), b"spim");
        let missing = b"<plist version=\"1.0\"><dict><key>Response</key><dict><key>Status</key><dict><key>ec</key><integer>0</integer></dict></dict></dict></plist>";
        assert!(matches!(
            parse_start_response(missing),
            Err(ProvisioningErrorKind::MalformedResponse)
        ));
        let ambiguous = b"<plist version=\"1.0\"><dict><key>Response</key><dict><key>spim</key><data>c3BpbQ==</data><key>Status</key><dict><key>ec</key><integer>0</integer></dict></dict><key>Status</key><dict><key>ec</key><integer>0</integer></dict></dict></plist>";
        assert!(matches!(
            parse_start_response(ambiguous),
            Err(ProvisioningErrorKind::MalformedResponse)
        ));
        let unknown_response = b"<plist version=\"1.0\"><dict><key>Response</key><dict><key>ptm</key><data>cHRt</data><key>tk</key><data>dGs=</data><key>unknown</key><string>x</string><key>Status</key><dict><key>ec</key><integer>0</integer></dict></dict></dict></plist>";
        assert!(matches!(
            parse_finish_response(unknown_response),
            Err(ProvisioningErrorKind::MalformedResponse)
        ));
        let unknown_status = b"<plist version=\"1.0\"><dict><key>Response</key><dict><key>spim</key><data>c3BpbQ==</data><key>Status</key><dict><key>ec</key><integer>0</integer><key>unknown</key><string>x</string></dict></dict></dict></plist>";
        assert!(matches!(
            parse_start_response(unknown_status),
            Err(ProvisioningErrorKind::MalformedResponse)
        ));
        let invalid_routing = b"<plist version=\"1.0\"><dict><key>Response</key><dict><key>ptm</key><data>cHRt</data><key>tk</key><data>dGs=</data><key>X-Apple-I-MD-RINFO</key><integer>17106176</integer><key>Status</key><dict><key>ec</key><integer>0</integer></dict></dict></dict></plist>";
        assert!(matches!(
            parse_finish_response(invalid_routing),
            Err(ProvisioningErrorKind::MalformedResponse)
        ));

        let valid_routing = Node::Dict(vec![(
            "X-Apple-I-MD-RINFO".to_owned(),
            Node::String(Zeroizing::new("17106176".to_owned())),
        )]);
        assert_eq!(
            validate_optional_routing(&valid_routing.dict_containing(&[]).expect("dictionary")),
            Ok(())
        );
        for invalid in [
            String::new(),
            "line\nbreak".to_owned(),
            "비ASCII".to_owned(),
            "x".repeat(coffer_protocol::anisette::MAX_ANISETTE_VALUE_LEN + 1),
        ] {
            let routing = Node::Dict(vec![(
                "X-Apple-I-MD-RINFO".to_owned(),
                Node::String(Zeroizing::new(invalid)),
            )]);
            assert_eq!(
                validate_optional_routing(&routing.dict_containing(&[]).expect("dictionary")),
                Err(ProvisioningErrorKind::MalformedResponse)
            );
        }
    }

    #[test]
    fn start_and_finish_accept_full_envelopes_and_string_secrets() {
        let start = b"<plist version=\"1.0\"><dict><key>Header</key><dict/><key>Response</key><dict><key>spim</key><string>c3BpbQ==</string></dict><key>Status</key><dict><key>hsc</key><integer>200</integer><key>ed</key><string>success</string><key>ec</key><integer>0</integer><key>em</key><string></string><key>ptxid</key><string>synthetic-transaction</string><key>rsh</key><string>synthetic-routing</string><key>au</key><string>synthetic-auth</string></dict></dict></plist>";
        let StartResponse(spim) = parse_start_response(start).expect("full start envelope");
        assert_eq!(spim.expose(), b"spim");

        let indented_start = br#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0">
  <dict>
    <key>Header</key>
    <dict/>
    <key>Response</key>
    <dict>
      <key>spim</key>
      <string>c3BpbQ==</string>
    </dict>
    <key>Status</key>
    <dict>
      <key>ec</key>
      <integer>0</integer>
    </dict>
  </dict>
</plist>"#;
        let StartResponse(spim) =
            parse_start_response(indented_start).expect("indented start envelope");
        assert_eq!(spim.expose(), b"spim");

        let finish = b"<plist version=\"1.0\"><dict><key>Header</key><dict/><key>Response</key><dict><key>ptm</key><string>cHRt</string><key>tk</key><string>dGs=</string></dict><key>Status</key><dict><key>hsc</key><integer>200</integer><key>ed</key><string>success</string><key>ec</key><integer>0</integer><key>em</key><string></string><key>ptxid</key><string>synthetic-transaction</string><key>rsh</key><string>synthetic-routing</string></dict></dict></plist>";
        let finish = parse_finish_response(finish).expect("full finish envelope");
        assert_eq!(finish.ptm.expose(), b"ptm");
        assert_eq!(finish.tk.expose(), b"tk");

        let nonempty_header = b"<plist version=\"1.0\"><dict><key>Header</key><dict><key>extra</key><string>x</string></dict><key>Response</key><dict><key>spim</key><string>c3BpbQ==</string></dict><key>Status</key><dict><key>ec</key><integer>0</integer></dict></dict></plist>";
        assert!(matches!(
            parse_start_response(nonempty_header),
            Err(ProvisioningErrorKind::MalformedResponse)
        ));
        let wrong_em_type = b"<plist version=\"1.0\"><dict><key>Response</key><dict><key>spim</key><string>c3BpbQ==</string></dict><key>Status</key><dict><key>ec</key><integer>0</integer><key>em</key><integer>0</integer></dict></dict></plist>";
        assert!(matches!(
            parse_start_response(wrong_em_type),
            Err(ProvisioningErrorKind::MalformedResponse)
        ));
    }

    #[test]
    fn wire_requests_are_byte_exact_and_secret_safe() {
        assert_eq!(&*start_request(), b"<?xml version=\"1.0\" encoding=\"UTF-8\"?><plist version=\"1.0\"><dict><key>Header</key><dict/><key>Request</key><dict/></dict></plist>");
        assert_eq!(&*finish_request(b"cpim"), b"<?xml version=\"1.0\" encoding=\"UTF-8\"?><plist version=\"1.0\"><dict><key>Header</key><dict/><key>Request</key><dict><key>cpim</key><string>Y3BpbQ==</string></dict></dict></plist>");
    }

    #[derive(Clone, Copy, Eq, PartialEq)]
    enum Fail {
        None,
        Lookup,
        Start,
        NativeStart,
        EmptyCpim,
        Finish,
        NativeEnd,
        NativeEndCleanup,
        Cancel,
    }

    struct FakeTransport {
        calls: Arc<Mutex<Vec<&'static str>>>,
        fail: Fail,
        cancel_after_finish: Option<Arc<AtomicBool>>,
    }
    impl ProvisioningTransport for FakeTransport {
        fn lookup(
            &self,
            _: &ProvisioningHeaders<'_>,
            _: Instant,
        ) -> Result<Lookup, ProvisioningErrorKind> {
            self.calls.lock().expect("calls").push("lookup");
            if self.fail == Fail::Lookup {
                return Err(ProvisioningErrorKind::Transport);
            }
            Ok(Lookup {
                start_endpoint: Endpoint::Start,
                finish_endpoint: Endpoint::Finish,
            })
        }
        fn start(
            &self,
            _: Endpoint,
            _: &ProvisioningHeaders<'_>,
            _: Instant,
        ) -> Result<StartResponse, ProvisioningErrorKind> {
            self.calls.lock().expect("calls").push("start-request");
            if self.fail == Fail::Start {
                return Err(ProvisioningErrorKind::Transport);
            }
            Ok(StartResponse(
                SecretBytes::new(b"spim".to_vec()).expect("spim"),
            ))
        }
        fn finish(
            &self,
            _: Endpoint,
            _: &[u8],
            _: &ProvisioningHeaders<'_>,
            _: Instant,
        ) -> Result<FinishResponse, ProvisioningErrorKind> {
            self.calls.lock().expect("calls").push("finish-request");
            if matches!(self.fail, Fail::Finish | Fail::Cancel) {
                return Err(ProvisioningErrorKind::ProtocolStatus(7));
            }
            if let Some(cancelled) = &self.cancel_after_finish {
                cancelled.store(true, Ordering::Release);
            }
            Ok(FinishResponse {
                ptm: SecretBytes::new(b"ptm".to_vec()).expect("ptm"),
                tk: SecretBytes::new(b"tk".to_vec()).expect("tk"),
            })
        }
    }

    struct TestClock;

    impl Clock for TestClock {
        fn now(&self) -> Result<String, crate::CofferAnisetteError> {
            Ok("2026-09-04T00:00:00Z".to_owned())
        }
    }

    fn context() -> ProvisioningContext {
        ProvisioningContext {
            local_user_id: Zeroizing::new("local-user".to_owned()),
            device_id: Zeroizing::new("device-id".to_owned()),
            serial_number: SERIAL_NUMBER_PLACEHOLDER,
            time_zone: "UTC".to_owned(),
            locale: "en_US".to_owned(),
            clock: Arc::new(TestClock),
        }
    }
    struct FakeNative {
        calls: Arc<Mutex<Vec<&'static str>>>,
        fail: Fail,
    }
    impl NativeProvisioner for FakeNative {
        fn start(&self, _: SecretBytes, _: Instant) -> Result<Box<dyn NativeSession>, BridgeError> {
            self.calls.lock().expect("calls").push("native-start");
            if self.fail == Fail::NativeStart {
                return Err(BridgeError::StartProvisioningFailed);
            }
            Ok(Box::new(FakeSession {
                calls: Arc::clone(&self.calls),
                fail: self.fail,
            }))
        }
    }
    struct FakeSession {
        calls: Arc<Mutex<Vec<&'static str>>>,
        fail: Fail,
    }
    impl NativeSession for FakeSession {
        fn cpim(&self) -> &[u8] {
            if self.fail == Fail::EmptyCpim {
                b""
            } else {
                b"cpim"
            }
        }
        fn finish(
            self: Box<Self>,
            _: SecretBytes,
            _: SecretBytes,
        ) -> Result<(), NativeTerminalError> {
            self.calls.lock().expect("calls").push("native-end-publish");
            match self.fail {
                Fail::NativeEnd => Err(NativeTerminalError {
                    first: BridgeError::EndProvisioningFailed,
                    cleanup: None,
                }),
                Fail::NativeEndCleanup => Err(NativeTerminalError {
                    first: BridgeError::EndProvisioningFailed,
                    cleanup: Some(BridgeError::DestroyProvisioningFailed),
                }),
                _ => Ok(()),
            }
        }
        fn cancel(self: Box<Self>) -> Result<(), BridgeError> {
            self.calls.lock().expect("calls").push("destroy");
            if self.fail == Fail::Cancel {
                Err(BridgeError::DestroyProvisioningFailed)
            } else {
                Ok(())
            }
        }
    }

    fn run(
        fail: Fail,
    ) -> (
        Result<ProvisioningReceipt, ProvisioningError>,
        Vec<&'static str>,
    ) {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let transport = FakeTransport {
            calls: Arc::clone(&calls),
            fail,
            cancel_after_finish: None,
        };
        let native = FakeNative {
            calls: Arc::clone(&calls),
            fail,
        };
        let result = run_once(
            &transport,
            &native,
            &context(),
            Duration::from_secs(1),
            &AtomicBool::new(false),
        );
        let calls = calls.lock().expect("calls").clone();
        (result, calls)
    }

    #[test]
    fn exact_order_has_one_call_per_stage_and_no_retry() {
        let (result, calls) = run(Fail::None);
        assert!(result.is_ok());
        assert_eq!(
            calls,
            [
                "lookup",
                "start-request",
                "native-start",
                "finish-request",
                "native-end-publish"
            ]
        );
        for fail in [
            Fail::Lookup,
            Fail::Start,
            Fail::NativeStart,
            Fail::EmptyCpim,
            Fail::Finish,
            Fail::NativeEnd,
            Fail::NativeEndCleanup,
        ] {
            let (_, calls) = run(fail);
            assert!(
                calls.iter().all(|call| calls
                    .iter()
                    .filter(|candidate| candidate == &call)
                    .count()
                    == 1)
            );
        }
    }

    #[test]
    fn empty_native_cpim_is_rejected_and_destroyed_before_http_finish() {
        let (result, calls) = run(Fail::EmptyCpim);
        let error = result.expect_err("empty CPIM");
        assert_eq!(error.stage(), ProvisioningStage::NativeStart);
        assert_eq!(
            error.kind(),
            ProvisioningErrorKind::Native(BridgeError::InvalidMessage)
        );
        assert_eq!(
            calls,
            ["lookup", "start-request", "native-start", "destroy"]
        );
    }

    #[test]
    fn native_end_preserves_first_and_cleanup_failures_separately() {
        let (result, calls) = run(Fail::NativeEndCleanup);
        let error = result.expect_err("native end and cleanup failure");
        assert_eq!(error.stage(), ProvisioningStage::NativeEnd);
        assert_eq!(
            error.kind(),
            ProvisioningErrorKind::Native(BridgeError::EndProvisioningFailed)
        );
        assert_eq!(
            error.cleanup_failure(),
            Some(BridgeError::DestroyProvisioningFailed)
        );
        assert_eq!(
            calls
                .iter()
                .filter(|call| **call == "native-end-publish")
                .count(),
            1
        );
    }

    #[test]
    fn pre_end_failure_destroys_once_and_preserves_first_error() {
        let (result, calls) = run(Fail::Finish);
        let error = result.expect_err("failure");
        assert_eq!(error.stage(), ProvisioningStage::FinishRequest);
        assert_eq!(error.kind(), ProvisioningErrorKind::ProtocolStatus(7));
        assert_eq!(error.cleanup_failure(), None);
        assert_eq!(
            calls,
            [
                "lookup",
                "start-request",
                "native-start",
                "finish-request",
                "destroy"
            ]
        );

        let (result, calls) = run(Fail::Cancel);
        let error = result.expect_err("failure with cleanup failure");
        assert_eq!(error.stage(), ProvisioningStage::FinishRequest);
        assert_eq!(error.kind(), ProvisioningErrorKind::ProtocolStatus(7));
        assert_eq!(
            error.cleanup_failure(),
            Some(BridgeError::DestroyProvisioningFailed)
        );
        assert_eq!(calls.iter().filter(|call| **call == "destroy").count(), 1);
    }

    #[test]
    fn elapsed_deadline_stops_before_the_first_operation() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let transport = FakeTransport {
            calls: Arc::clone(&calls),
            fail: Fail::None,
            cancel_after_finish: None,
        };
        let native = FakeNative {
            calls: Arc::clone(&calls),
            fail: Fail::None,
        };
        let error = run_once(
            &transport,
            &native,
            &context(),
            Duration::ZERO,
            &AtomicBool::new(false),
        )
        .expect_err("deadline");
        assert_eq!(error.stage(), ProvisioningStage::Lookup);
        assert_eq!(error.kind(), ProvisioningErrorKind::Transport);
        assert!(calls.lock().expect("calls").is_empty());
    }

    #[test]
    fn cancellation_after_native_start_destroys_once() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let cancelled = Arc::new(AtomicBool::new(false));
        let transport = FakeTransport {
            calls: Arc::clone(&calls),
            fail: Fail::None,
            cancel_after_finish: Some(Arc::clone(&cancelled)),
        };
        let native = FakeNative {
            calls: Arc::clone(&calls),
            fail: Fail::None,
        };
        let error = run_once(
            &transport,
            &native,
            &context(),
            Duration::from_secs(1),
            &cancelled,
        )
        .expect_err("cancelled");
        assert_eq!(error.stage(), ProvisioningStage::Cancelled);
        assert_eq!(error.kind(), ProvisioningErrorKind::Cancelled);
        assert_eq!(
            calls
                .lock()
                .expect("calls")
                .iter()
                .filter(|call| **call == "destroy")
                .count(),
            1
        );
    }

    #[test]
    fn protocol_status_is_distinct_from_http_status() {
        assert_ne!(
            ProvisioningErrorKind::ProtocolStatus(200),
            ProvisioningErrorKind::HttpStatus(200)
        );
    }
}
