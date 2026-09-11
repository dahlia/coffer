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

//! The HTTPS transport that carries GSA requests to Apple.
//!
//! [`GsaTransport`] implements [`coffer_protocol::transport::Transport`] with
//! a deliberately small policy:
//!
//! - Only the three requests the protocol layer builds are sent.  The URL,
//!   method, body presence, and `Content-Type` of every request are checked
//!   against an allowlist before any connection is opened, so a bug elsewhere
//!   cannot turn this transport into a general HTTP client.
//! - One call is one HTTP exchange.  There is no retry, no redirect following,
//!   no proxy, and no response to an authentication challenge. A `3xx` or
//!   `407` status is a transport failure; `401` is returned to the protocol
//!   without reading its body or answering the challenge.
//! - TLS uses rustls with Apple's published “Apple Inc. Root” as the only
//!   trust anchor.  This policy is private to the fixed GSA endpoints; the
//!   Apple CDN transport continues to use the public WebPKI.
//! - The response body is read through a hard cap of
//!   [`Request::max_response_body`] bytes and every exchange runs under both a
//!   per-exchange timeout and a deadline for the whole harness run.
//! - Failures carry fixed descriptions.  Neither request nor response
//!   headers, bodies, nor the HTTP library's own error text ever appear in an
//!   error.

use core::fmt;
use std::io::Read;
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

use coffer_protocol::auth::{GSA_ENDPOINT, TRUSTED_DEVICE_ENDPOINT, VALIDATE_ENDPOINT};
use coffer_protocol::transport::{Method, Request, Response, Transport, TransportError};
use ureq::config::AutoHeaderValue;
use ureq::tls::{Certificate, RootCerts, TlsConfig};

/// The only `Content-Type` GSA requests carry.
pub const PLIST_CONTENT_TYPE: &str = "text/x-xml-plist";

/// Hard ceiling on any response body, whatever the request asks for.
pub const MAX_RESPONSE_BODY_CEILING: usize = 4 * 1024 * 1024;

/// How long the TCP connection and TLS handshake may take.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

/// Which of the allowed GSA requests a [`Request`] is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Endpoint {
    /// `POST` to the password-exchange service.
    GsService,
    /// `GET` that submits a verification code.
    Validate,
    /// `GET` that pushes a code to the trusted devices.
    TrustedDevice,
}

impl Endpoint {
    fn for_url(url: &str) -> Option<Self> {
        match url {
            GSA_ENDPOINT => Some(Self::GsService),
            VALIDATE_ENDPOINT => Some(Self::Validate),
            TRUSTED_DEVICE_ENDPOINT => Some(Self::TrustedDevice),
            _ => None,
        }
    }

    fn method(self) -> Method {
        match self {
            Self::GsService => Method::Post,
            Self::Validate | Self::TrustedDevice => Method::Get,
        }
    }
}

/// Checks a request against the allowlist before it is sent.
///
/// # Errors
///
/// Returns [`TransportError::Other`] with a fixed description naming the
/// violated rule.  The request's URL is not echoed back.
pub fn validate_request(request: &Request) -> Result<Endpoint, TransportError> {
    let refuse = |detail: &str| TransportError::Other {
        detail: detail.to_owned(),
    };
    let endpoint = Endpoint::for_url(&request.url).ok_or_else(|| refuse("URL not allowlisted"))?;
    if request.method != endpoint.method() {
        return Err(refuse("method not allowed for endpoint"));
    }
    match (endpoint.method(), request.body.as_ref()) {
        (Method::Post, None) => return Err(refuse("POST without body")),
        (Method::Get, Some(_)) => return Err(refuse("GET with body")),
        _ => {}
    }
    let mut content_types = request
        .headers
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case("content-type"));
    match (content_types.next(), content_types.next()) {
        (Some((_, value)), None) if value.as_str() == PLIST_CONTENT_TYPE => {}
        _ => {
            return Err(refuse(
                "Content-Type must be the GSA property-list type exactly once",
            ));
        }
    }
    for (name, value) in &request.headers {
        let name_ok = !name.is_empty()
            && name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'));
        let value_ok = value.bytes().all(|b| (0x20..=0x7e).contains(&b));
        if !name_ok || !value_ok {
            return Err(refuse("header is not printable ASCII"));
        }
    }
    if request.max_response_body == 0 || request.max_response_body > MAX_RESPONSE_BODY_CEILING {
        return Err(refuse("response bound out of range"));
    }
    Ok(endpoint)
}

/// Performs one already-validated HTTP exchange.
///
/// Implementations must send the request once, verify TLS, enforce
/// `request.max_response_body`, and give up after `timeout`.
pub trait Exchange: Send + Sync {
    /// Sends `request` and returns the status and bounded body.
    ///
    /// # Errors
    ///
    /// Returns a [`TransportError`] whose text is fixed and secret-free.
    fn exchange(&self, request: &Request, timeout: Duration) -> Result<Response, TransportError>;
}

/// Deadlines applied to every exchange.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Deadlines {
    /// Upper bound on one exchange, from connect to the last body byte.
    pub per_exchange: Duration,
    /// Instant after which no exchange is started or allowed to continue.
    pub overall: Instant,
}

impl Deadlines {
    /// Builds deadlines from a per-exchange bound and a total budget starting
    /// now.
    #[must_use]
    pub fn starting_now(per_exchange: Duration, total: Duration) -> Self {
        Self {
            per_exchange,
            overall: Instant::now() + total,
        }
    }

    fn remaining(&self, now: Instant) -> Option<Duration> {
        let until_overall = self.overall.checked_duration_since(now)?;
        if until_overall.is_zero() {
            return None;
        }
        Some(until_overall.min(self.per_exchange))
    }
}

/// The GSA [`Transport`].
pub struct GsaTransport<X> {
    exchange: X,
    deadlines: Deadlines,
}

impl GsaTransport<UreqExchange> {
    /// Builds the production transport on `ureq` and rustls.
    #[must_use]
    pub fn production(deadlines: Deadlines) -> Self {
        Self::new(UreqExchange::new(), deadlines)
    }
}

impl<X: Exchange> GsaTransport<X> {
    /// Wraps an [`Exchange`] with the allowlist and deadline policy.
    #[must_use]
    pub fn new(exchange: X, deadlines: Deadlines) -> Self {
        Self {
            exchange,
            deadlines,
        }
    }

    /// Borrows the exchange so tests can count calls.
    #[cfg(test)]
    pub(crate) fn exchange_ref(&self) -> &X {
        &self.exchange
    }

    fn send_once(&self, request: &Request) -> Result<Response, TransportError> {
        validate_request(request)?;
        let timeout = self
            .deadlines
            .remaining(Instant::now())
            .ok_or(TransportError::Timeout)?;
        let response = self.exchange.exchange(request, timeout)?;
        classify_status(response.status())?;
        if response.body().len() > request.max_response_body {
            return Err(TransportError::ResponseTooLarge {
                limit: request.max_response_body,
            });
        }
        Ok(response)
    }
}

/// Refuses statuses the transport must not act on.
fn classify_status(status: u16) -> Result<(), TransportError> {
    let detail = match status {
        300..=399 => "redirect refused",
        407 => "authentication challenge refused",
        _ => return Ok(()),
    };
    Err(TransportError::Other {
        detail: detail.to_owned(),
    })
}

impl<X: Exchange> Transport for GsaTransport<X> {
    async fn send(&self, request: Request) -> Result<Response, TransportError> {
        self.send_once(&request)
    }
}

impl<X> fmt::Debug for GsaTransport<X> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GsaTransport")
            .field("deadlines", &self.deadlines)
            .finish_non_exhaustive()
    }
}

/// The production [`Exchange`] on `ureq` 3 with rustls.
pub struct UreqExchange {
    agent: ureq::Agent,
}

impl UreqExchange {
    /// Builds the agent with redirects, proxies, and automatic headers off.
    #[must_use]
    pub fn new() -> Self {
        let config = ureq::Agent::config_builder()
            .max_redirects(0)
            .http_status_as_error(false)
            .https_only(true)
            .proxy(None)
            // The protocol layer sets `User-Agent` and `Accept` itself; no
            // header may be added behind its back.
            .user_agent(AutoHeaderValue::None)
            .accept(AutoHeaderValue::None)
            .accept_encoding(AutoHeaderValue::None)
            .timeout_connect(Some(CONNECT_TIMEOUT))
            .tls_config(gsa_tls_config())
            .build();
        Self {
            agent: ureq::Agent::new_with_config(config),
        }
    }
}

fn gsa_tls_config() -> TlsConfig {
    let certificate = Certificate::from_der(coffer_protocol::pki::APPLE_INC_ROOT_CA_DER);
    TlsConfig::builder()
        .root_certs(RootCerts::new_with_certs(&[certificate]))
        .use_sni(true)
        .disable_verification(false)
        .build()
}

impl Default for UreqExchange {
    fn default() -> Self {
        Self::new()
    }
}

impl Exchange for UreqExchange {
    fn exchange(&self, request: &Request, timeout: Duration) -> Result<Response, TransportError> {
        // Exchange is public too: direct calls must satisfy the same endpoint
        // policy and allocation ceiling before HTTP construction or reading.
        validate_request(request)?;
        let limit = request.max_response_body;
        let response = match request.method {
            Method::Post => {
                let mut builder = self
                    .agent
                    .post(&request.url)
                    .config()
                    .timeout_global(Some(timeout))
                    .build();
                for (name, value) in &request.headers {
                    builder = builder.header(name.as_str(), value.as_str());
                }
                builder.send(
                    request
                        .body
                        .as_deref()
                        .map_or(&[][..], |body| body.as_slice()),
                )
            }
            Method::Get => {
                let mut builder = self
                    .agent
                    .get(&request.url)
                    .config()
                    .timeout_global(Some(timeout))
                    .build();
                for (name, value) in &request.headers {
                    builder = builder.header(name.as_str(), value.as_str());
                }
                builder.call()
            }
        }
        .map_err(|error| classify_ureq_error(&error, limit))?;
        let status = response.status().as_u16();
        if status == 401 || classify_status(status).is_err() {
            // Do not read a body the transport is about to refuse.
            return Ok(Response::new(status, Vec::new()));
        }
        // Allocate the bound once before it contains secrets; never grow or
        // leave an ordinary read scratch buffer behind on failure.
        let mut body = Zeroizing::new(vec![0; limit + 1]);
        let mut reader = response.into_body().into_reader();
        let mut used = 0;
        loop {
            let read = reader
                .read(&mut body[used..])
                .map_err(|_| TransportError::Other {
                    detail: "response body read failed".to_owned(),
                })?;
            if read == 0 {
                break;
            }
            used += read;
            if used > limit {
                return Err(TransportError::ResponseTooLarge { limit });
            }
        }
        body.truncate(used);
        Ok(Response::from_zeroizing(status, body))
    }
}

impl fmt::Debug for UreqExchange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("UreqExchange")
    }
}

/// Maps a `ureq` failure onto the protocol's vocabulary with fixed text.
fn classify_ureq_error(error: &ureq::Error, limit: usize) -> TransportError {
    match error {
        ureq::Error::Timeout(_) => TransportError::Timeout,
        ureq::Error::Tls(_) | ureq::Error::Rustls(_) => TransportError::Tls {
            detail: "TLS handshake or certificate verification failed".to_owned(),
        },
        ureq::Error::Io(error)
            if error
                .get_ref()
                .is_some_and(|source| source.is::<rustls::Error>()) =>
        {
            TransportError::Tls {
                detail: "TLS handshake or certificate verification failed".to_owned(),
            }
        }
        ureq::Error::HostNotFound | ureq::Error::ConnectionFailed | ureq::Error::Io(_) => {
            TransportError::Connect {
                detail: "connection failed".to_owned(),
            }
        }
        ureq::Error::BodyExceedsLimit(_) => TransportError::ResponseTooLarge { limit },
        ureq::Error::TooManyRedirects | ureq::Error::RedirectFailed => TransportError::Other {
            detail: "redirect refused".to_owned(),
        },
        _ => TransportError::Other {
            detail: "HTTP exchange failed".to_owned(),
        },
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use std::sync::Mutex;

    use zeroize::Zeroizing;

    use super::*;

    fn header(name: &str, value: &str) -> (String, Zeroizing<String>) {
        (name.to_owned(), Zeroizing::new(value.to_owned()))
    }

    pub(crate) fn post_request() -> Request {
        Request {
            method: Method::Post,
            url: GSA_ENDPOINT.to_owned(),
            headers: vec![
                header("Content-Type", PLIST_CONTENT_TYPE),
                header("Accept", "*/*"),
                header("User-Agent", "akd/1.0"),
            ],
            body: Some(Zeroizing::new(b"<plist/>".to_vec())),
            max_response_body: 1024,
        }
    }

    fn get_request(url: &str) -> Request {
        Request {
            method: Method::Get,
            url: url.to_owned(),
            headers: vec![header("Content-Type", PLIST_CONTENT_TYPE)],
            body: None,
            max_response_body: 1024,
        }
    }

    type Outcome = Result<(u16, Vec<u8>), TransportError>;

    /// Scripted exchange that counts calls and records only timeouts.
    pub(crate) struct FakeExchange {
        pub(crate) outcomes: Mutex<Vec<Outcome>>,
        pub(crate) calls: Mutex<usize>,
        pub(crate) timeouts: Mutex<Vec<Duration>>,
    }

    impl FakeExchange {
        pub(crate) fn new(outcomes: Vec<Outcome>) -> Self {
            Self {
                outcomes: Mutex::new(outcomes),
                calls: Mutex::new(0),
                timeouts: Mutex::new(Vec::new()),
            }
        }

        pub(crate) fn calls(&self) -> usize {
            *self.calls.lock().unwrap()
        }
    }

    impl Exchange for FakeExchange {
        fn exchange(&self, _: &Request, timeout: Duration) -> Result<Response, TransportError> {
            *self.calls.lock().unwrap() += 1;
            self.timeouts.lock().unwrap().push(timeout);
            let mut outcomes = self.outcomes.lock().unwrap();
            if outcomes.is_empty() {
                panic!("exchange called more often than scripted");
            }
            outcomes
                .remove(0)
                .map(|(status, body)| Response::new(status, body))
        }
    }

    fn deadlines() -> Deadlines {
        Deadlines::starting_now(Duration::from_secs(30), Duration::from_secs(300))
    }

    fn detail(error: &TransportError) -> String {
        match error {
            TransportError::Other { detail } => detail.clone(),
            other => panic!("expected Other, got {other:?}"),
        }
    }

    #[test]
    fn the_three_protocol_requests_pass_the_allowlist() {
        assert_eq!(
            validate_request(&post_request()).unwrap(),
            Endpoint::GsService
        );
        assert_eq!(
            validate_request(&get_request(VALIDATE_ENDPOINT)).unwrap(),
            Endpoint::Validate
        );
        assert_eq!(
            validate_request(&get_request(TRUSTED_DEVICE_ENDPOINT)).unwrap(),
            Endpoint::TrustedDevice
        );
    }

    #[test]
    fn foreign_urls_and_near_misses_are_refused() {
        for url in [
            "https://gsa.apple.com/grandslam/GsService2/",
            "http://gsa.apple.com/grandslam/GsService2",
            "https://gsa.apple.com/grandslam/GsService2?x=1",
            "https://gsa.apple.com.evil.example/grandslam/GsService2",
            "https://example.com/",
            "",
        ] {
            let mut request = post_request();
            request.url = url.to_owned();
            assert_eq!(
                detail(&validate_request(&request).unwrap_err()),
                "URL not allowlisted"
            );
        }
    }

    #[test]
    fn method_and_body_must_match_the_endpoint() {
        let mut request = post_request();
        request.method = Method::Get;
        assert_eq!(
            detail(&validate_request(&request).unwrap_err()),
            "method not allowed for endpoint"
        );
        let mut request = get_request(VALIDATE_ENDPOINT);
        request.method = Method::Post;
        assert_eq!(
            detail(&validate_request(&request).unwrap_err()),
            "method not allowed for endpoint"
        );
        let mut request = post_request();
        request.body = None;
        assert_eq!(
            detail(&validate_request(&request).unwrap_err()),
            "POST without body"
        );
        let mut request = get_request(TRUSTED_DEVICE_ENDPOINT);
        request.body = Some(Zeroizing::new(vec![1]));
        assert_eq!(
            detail(&validate_request(&request).unwrap_err()),
            "GET with body"
        );
    }

    #[test]
    fn content_type_must_be_the_plist_type_exactly_once() {
        let mut request = post_request();
        request.headers[0] = header("Content-Type", "application/json");
        assert!(validate_request(&request).is_err());
        let mut request = post_request();
        request.headers.remove(0);
        assert!(validate_request(&request).is_err());
        let mut request = post_request();
        request
            .headers
            .push(header("content-type", PLIST_CONTENT_TYPE));
        assert!(validate_request(&request).is_err());
        let mut request = post_request();
        request.headers[0] = header("content-type", PLIST_CONTENT_TYPE);
        assert!(validate_request(&request).is_ok());
    }

    #[test]
    fn header_shape_and_response_bound_are_checked() {
        let mut request = post_request();
        request.headers.push(header("X-Bad", "line\r\nbreak"));
        assert_eq!(
            detail(&validate_request(&request).unwrap_err()),
            "header is not printable ASCII"
        );
        let mut request = post_request();
        request.headers.push(header("Bad Name", "x"));
        assert!(validate_request(&request).is_err());
        let mut request = post_request();
        request.max_response_body = 0;
        assert_eq!(
            detail(&validate_request(&request).unwrap_err()),
            "response bound out of range"
        );
        let mut request = post_request();
        request.max_response_body = MAX_RESPONSE_BODY_CEILING + 1;
        assert!(validate_request(&request).is_err());
    }

    #[test]
    fn a_refused_request_never_reaches_the_exchange() {
        let exchange = FakeExchange::new(vec![]);
        let transport = GsaTransport::new(exchange, deadlines());
        let mut request = post_request();
        request.url = "https://example.com/".to_owned();
        assert!(futures_lite::future::block_on(transport.send(request)).is_err());
        assert_eq!(transport.exchange.calls(), 0);
    }

    #[test]
    fn one_call_is_exactly_one_exchange_even_on_failure() {
        let exchange = FakeExchange::new(vec![Err(TransportError::Timeout)]);
        let transport = GsaTransport::new(exchange, deadlines());
        let result = futures_lite::future::block_on(transport.send(post_request()));
        assert_eq!(result.unwrap_err(), TransportError::Timeout);
        assert_eq!(transport.exchange.calls(), 1);
    }

    #[test]
    fn success_and_server_errors_pass_through_unchanged() {
        let exchange =
            FakeExchange::new(vec![Ok((200, b"ok".to_vec())), Ok((500, b"boom".to_vec()))]);
        let transport = GsaTransport::new(exchange, deadlines());
        let response = futures_lite::future::block_on(transport.send(post_request())).unwrap();
        assert_eq!((response.status(), response.body()), (200, &b"ok"[..]));
        let response = futures_lite::future::block_on(transport.send(post_request())).unwrap();
        assert_eq!(response.status(), 500);
    }

    #[test]
    fn redirects_and_authentication_challenges_are_refused() {
        for status in [301, 302, 303, 307, 308, 407] {
            let exchange = FakeExchange::new(vec![Ok((status, b"Location: elsewhere".to_vec()))]);
            let transport = GsaTransport::new(exchange, deadlines());
            let error = futures_lite::future::block_on(transport.send(post_request())).unwrap_err();
            let text = detail(&error);
            assert!(text == "redirect refused" || text == "authentication challenge refused");
            assert!(!text.contains("elsewhere"));
        }
    }

    #[test]
    fn unauthorized_status_is_returned_without_another_exchange() {
        let transport =
            GsaTransport::new(FakeExchange::new(vec![Ok((401, Vec::new()))]), deadlines());
        let response = futures_lite::future::block_on(transport.send(post_request())).unwrap();
        assert_eq!(response.status(), 401);
        assert_eq!(transport.exchange.calls(), 1);
    }

    #[test]
    fn oversized_bodies_are_refused_after_the_exchange_too() {
        let exchange = FakeExchange::new(vec![Ok((200, vec![0u8; 1025]))]);
        let transport = GsaTransport::new(exchange, deadlines());
        let error = futures_lite::future::block_on(transport.send(post_request())).unwrap_err();
        assert_eq!(error, TransportError::ResponseTooLarge { limit: 1024 });
    }

    #[test]
    fn per_exchange_timeout_is_capped_by_the_overall_deadline() {
        let deadlines = Deadlines {
            per_exchange: Duration::from_secs(30),
            overall: Instant::now() + Duration::from_secs(5),
        };
        let exchange = FakeExchange::new(vec![Ok((200, Vec::new()))]);
        let transport = GsaTransport::new(exchange, deadlines);
        futures_lite::future::block_on(transport.send(post_request())).unwrap();
        let recorded = transport.exchange.timeouts.lock().unwrap()[0];
        assert!(recorded <= Duration::from_secs(5));
        assert!(recorded > Duration::from_secs(3));
    }

    #[test]
    fn an_expired_overall_deadline_sends_nothing() {
        let deadlines = Deadlines {
            per_exchange: Duration::from_secs(30),
            overall: Instant::now() - Duration::from_secs(1),
        };
        let exchange = FakeExchange::new(vec![]);
        let transport = GsaTransport::new(exchange, deadlines);
        let error = futures_lite::future::block_on(transport.send(post_request())).unwrap_err();
        assert_eq!(error, TransportError::Timeout);
        assert_eq!(transport.exchange.calls(), 0);
    }

    #[test]
    fn ureq_errors_map_to_fixed_text() {
        assert_eq!(
            classify_ureq_error(&ureq::Error::HostNotFound, 1),
            TransportError::Connect {
                detail: "connection failed".to_owned()
            }
        );
        assert_eq!(
            classify_ureq_error(&ureq::Error::Io(std::io::Error::other("secret host")), 1),
            TransportError::Connect {
                detail: "connection failed".to_owned()
            }
        );
        assert_eq!(
            classify_ureq_error(&ureq::Error::Tls("chain"), 1),
            TransportError::Tls {
                detail: "TLS handshake or certificate verification failed".to_owned()
            }
        );
        let certificate_error =
            rustls::Error::InvalidCertificate(rustls::CertificateError::UnknownIssuer);
        assert_eq!(
            classify_ureq_error(&ureq::Error::Rustls(certificate_error.clone()), 1),
            TransportError::Tls {
                detail: "TLS handshake or certificate verification failed".to_owned()
            }
        );
        let wrapped = std::io::Error::new(std::io::ErrorKind::InvalidData, certificate_error);
        assert_eq!(
            classify_ureq_error(&ureq::Error::Io(wrapped), 1),
            TransportError::Tls {
                detail: "TLS handshake or certificate verification failed".to_owned()
            }
        );
        assert_eq!(
            classify_ureq_error(&ureq::Error::BodyExceedsLimit(9), 77),
            TransportError::ResponseTooLarge { limit: 77 }
        );
        assert_eq!(
            classify_ureq_error(&ureq::Error::TooManyRedirects, 1),
            TransportError::Other {
                detail: "redirect refused".to_owned()
            }
        );
        assert_eq!(
            classify_ureq_error(
                &ureq::Error::BadUri("https://secret.example/".to_owned()),
                1
            ),
            TransportError::Other {
                detail: "HTTP exchange failed".to_owned()
            }
        );
    }

    #[test]
    fn production_agent_uses_only_apples_root_without_redirects_or_proxy() {
        let transport = GsaTransport::production(deadlines());
        let config = transport.exchange_ref().agent.config();
        let tls = config.tls_config();
        let RootCerts::Specific(certificates) = tls.root_certs() else {
            panic!("GSA authentication must use endpoint-specific roots");
        };

        assert_eq!(certificates.len(), 1);
        assert_eq!(
            certificates[0].der(),
            coffer_protocol::pki::APPLE_INC_ROOT_CA_DER
        );
        assert!(tls.use_sni());
        assert!(!tls.disable_verification());
        assert_eq!(config.max_redirects(), 0);
        assert!(config.proxy().is_none());
        assert!(!config.http_status_as_error());
        assert!(config.https_only());
        assert!(matches!(config.user_agent(), AutoHeaderValue::None));
        assert!(matches!(config.accept(), AutoHeaderValue::None));
        assert!(matches!(config.accept_encoding(), AutoHeaderValue::None));
    }
}
