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

//! Offline-tested developer transport for the fixed legacy delegate endpoint.
//!
//! This adapter is not wired to a frontend. Its existence does not authorize
//! live authentication. Delegate token issuance may consume an authentication
//! attempt; rotation, registration and consent effects remain unknown.
//! [`DelegateTransport`] sends once and never answers challenges or retries.
//! HTTP 200 bodies remain opaque for the protocol layer to validate.
//!
//! The URL, media type and size bounds are a Coffer subset, not a claim of
//! independently confirmed Apple server requirements. GSA keeps its separate
//! endpoint allowlist and Apple Root TLS policy.

use crate::transport::{Deadlines, Exchange, classify_ureq_error};
use core::fmt;
use std::io::Read;
use std::time::{Duration, Instant};
use ureq::config::AutoHeaderValue;
use ureq::tls::{RootCerts, TlsConfig, TlsProvider};
use zeroize::Zeroizing;

use coffer_protocol::transport::{Method, Request, Response, Transport, TransportError};

/// The sole delegate URL accepted by this local policy.
pub const DELEGATE_ENDPOINT: &str = "https://setup.icloud.com/setup/iosbuddy/loginDelegates";
/// The initial Coffer subset media type, not a confirmed server specification.
pub const DELEGATE_CONTENT_TYPE: &str = "text/xml";
/// Local request body ceiling in bytes.
pub const MAX_REQUEST_BODY: usize = 64 * 1024;
/// Local response body ceiling in bytes.
pub const MAX_RESPONSE_BODY: usize = 128 * 1024;
/// Maximum caller-supplied header count.
pub const MAX_HEADERS: usize = 32;
/// Maximum caller-supplied header bytes, including colon, space and CRLF.
// Covers the protocol maximum PET/ADSID plus ten anisette-derived values.
// The maximum-input integration test keeps the two policies aligned.
pub const MAX_HEADER_BYTES: usize = 32 * 1024;

/// Validates the delegate request without performing I/O.
///
/// # Errors
/// Returns a static, secret-free policy error for an unsupported request.
pub fn validate_request(request: &Request) -> Result<(), TransportError> {
    if request.url != DELEGATE_ENDPOINT {
        return Err(refuse("URL not allowlisted"));
    }
    if request.method != Method::Post {
        return Err(refuse("delegate requires POST"));
    }
    if !request
        .body
        .as_ref()
        .is_some_and(|b| !b.is_empty() && b.len() <= MAX_REQUEST_BODY)
    {
        return Err(refuse("request body bound out of range"));
    }
    if request.max_response_body == 0 || request.max_response_body > MAX_RESPONSE_BODY {
        return Err(refuse("response bound out of range"));
    }
    if request.headers.len() > MAX_HEADERS {
        return Err(refuse("too many headers"));
    }
    let mut bytes = 0_usize;
    let mut has_content_type = false;
    for (index, (name, value)) in request.headers.iter().enumerate() {
        bytes = bytes
            .checked_add(name.len())
            .and_then(|n| n.checked_add(value.len()))
            .and_then(|n| n.checked_add(4))
            .filter(|n| *n <= MAX_HEADER_BYTES)
            .ok_or_else(|| refuse("header size bound exceeded"))?;
        if name.is_empty()
            || !name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
            || !value.bytes().all(|b| (0x20..=0x7e).contains(&b))
        {
            return Err(refuse("header is not printable ASCII"));
        }
        if request.headers[..index]
            .iter()
            .any(|(previous, _)| previous.eq_ignore_ascii_case(name))
        {
            return Err(refuse("duplicate header refused"));
        }
        // Routing, framing, compression and challenge behavior belong to the
        // adapter, never to a protocol-supplied header. ureq supplies only the
        // required Host and Content-Length framing from the validated request.
        if [
            "host",
            "content-length",
            "transfer-encoding",
            "connection",
            "upgrade",
            "expect",
            "trailer",
            "te",
            "proxy-authorization",
            "proxy-connection",
            "accept-encoding",
            "content-encoding",
        ]
        .iter()
        .any(|forbidden| name.eq_ignore_ascii_case(forbidden))
        {
            return Err(refuse("transport control header refused"));
        }
        if name.eq_ignore_ascii_case("content-type") {
            if value.as_str() != DELEGATE_CONTENT_TYPE {
                return Err(refuse("unsupported delegate Content-Type"));
            }
            has_content_type = true;
        }
    }
    if !has_content_type {
        return Err(refuse("delegate Content-Type required exactly once"));
    }
    Ok(())
}

fn refuse(detail: &'static str) -> TransportError {
    TransportError::Other {
        detail: detail.to_owned(),
    }
}

/// Fixed-endpoint delegate transport, owning its exchange and shared deadline.
///
/// The caller supplies the fully formed protocol request and is responsible
/// for explicit live authorization. Each send performs at most one exchange;
/// timeout after transmission leaves token issuance unknown. Custom exchanges
/// must uphold [`Exchange`]'s blocking I/O timeout contract. Returned results
/// are rechecked for deadlines and size, and arbitrary error text is discarded.
pub struct DelegateTransport<X> {
    exchange: X,
    deadlines: Deadlines,
}

impl<X: Exchange> DelegateTransport<X> {
    /// Wraps an exchange with the fixed request policy and absolute deadline.
    ///
    /// Zero or elapsed budgets are refused on send, without calling the exchange.
    #[must_use]
    pub fn new(exchange: X, deadlines: Deadlines) -> Self {
        Self {
            exchange,
            deadlines,
        }
    }

    fn send_once(&self, request: &Request) -> Result<Response, TransportError> {
        validate_request(request)?;
        let now = Instant::now();
        let timeout = self
            .deadlines
            .remaining(now)
            .ok_or(TransportError::Timeout)?;
        let deadline = exchange_deadline(now, timeout)?;
        let result = self.exchange.exchange(request, timeout);
        ensure_time(deadline)?;
        let response = result.map_err(|error| sanitize_error(error, request.max_response_body))?;
        classify_status(response.status())?;
        if response.status() == 401 {
            return Ok(Response::new(401, Vec::new()));
        }
        if response.body().len() > request.max_response_body {
            return Err(TransportError::ResponseTooLarge {
                limit: request.max_response_body,
            });
        }
        Ok(response)
    }
}

impl DelegateTransport<UreqDelegateExchange> {
    /// Builds the WebPKI HTTPS adapter without opening any connection.
    ///
    /// This is not live authorization and is not called by either harness.
    #[must_use]
    pub fn production(deadlines: Deadlines) -> Self {
        Self::new(UreqDelegateExchange::new(), deadlines)
    }
}

impl<X: Exchange> Transport for DelegateTransport<X> {
    async fn send(&self, request: Request) -> Result<Response, TransportError> {
        self.send_once(&request)
    }
}

impl<X> fmt::Debug for DelegateTransport<X> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DelegateTransport")
    }
}

fn sanitize_error(error: TransportError, limit: usize) -> TransportError {
    match error {
        TransportError::Timeout => TransportError::Timeout,
        TransportError::Connect { .. } => TransportError::Connect {
            detail: "connection failed".to_owned(),
        },
        TransportError::Tls { .. } => TransportError::Tls {
            detail: "TLS handshake or certificate verification failed".to_owned(),
        },
        TransportError::ResponseTooLarge { .. } => TransportError::ResponseTooLarge { limit },
        _ => refuse("HTTP exchange failed"),
    }
}

fn classify_status(status: u16) -> Result<(), TransportError> {
    match status {
        300..=399 => Err(refuse("redirect refused")),
        407 => Err(refuse("authentication challenge refused")),
        _ => Ok(()),
    }
}

fn exchange_deadline(now: Instant, timeout: Duration) -> Result<Instant, TransportError> {
    if timeout.is_zero() {
        return Err(TransportError::Timeout);
    }
    now.checked_add(timeout).ok_or(TransportError::Timeout)
}

fn ensure_time(deadline: Instant) -> Result<(), TransportError> {
    if Instant::now() >= deadline {
        Err(TransportError::Timeout)
    } else {
        Ok(())
    }
}

/// Production delegate exchange, with a private WebPKI rustls agent.
///
/// Direct [`Exchange::exchange`] calls validate the same request limits and
/// timeout before HTTP construction. No redirect, proxy, challenge response,
/// retry, cookie store, optional automatic header or decompressor is enabled.
/// Required Host and Content-Length framing is derived by ureq. The current
/// locked ureq graph enables rustls only; it has no compression/cookie feature.
/// Library-owned headers/TLS buffers are not guaranteed to be zeroized; Coffer
/// avoids logging them and zeroizes its bounded response allocation on drop.
pub struct UreqDelegateExchange {
    agent: ureq::Agent,
}

impl UreqDelegateExchange {
    /// Builds an agent without connecting or reading account/provisioning state.
    #[must_use]
    pub fn new() -> Self {
        let tls = TlsConfig::builder()
            .provider(TlsProvider::Rustls)
            .root_certs(RootCerts::WebPki)
            .use_sni(true)
            .disable_verification(false)
            .build();
        let config = ureq::Agent::config_builder()
            .max_redirects(0)
            .http_status_as_error(false)
            .https_only(true)
            .proxy(None)
            .user_agent(AutoHeaderValue::None)
            .accept(AutoHeaderValue::None)
            .accept_encoding(AutoHeaderValue::None)
            .max_idle_connections(0)
            .max_idle_connections_per_host(0)
            .max_response_header_size(MAX_HEADER_BYTES)
            .timeout_connect(Some(Duration::from_secs(30)))
            .tls_config(tls)
            .build();
        Self {
            agent: ureq::Agent::new_with_config(config),
        }
    }
}

impl Default for UreqDelegateExchange {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for UreqDelegateExchange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("UreqDelegateExchange")
    }
}

impl Exchange for UreqDelegateExchange {
    fn exchange(&self, request: &Request, timeout: Duration) -> Result<Response, TransportError> {
        validate_request(request)?;
        let deadline = exchange_deadline(Instant::now(), timeout)?;
        let mut builder = self.agent.post(DELEGATE_ENDPOINT);
        for (name, value) in &request.headers {
            // Sensitive marking also prevents http HeaderValue's Debug from
            // exposing a value inside the HTTP stack.
            let mut value = ureq::http::HeaderValue::from_str(value)
                .map_err(|_| refuse("invalid header value"))?;
            value.set_sensitive(true);
            builder = builder.header(name.as_str(), value);
        }
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .filter(|d| !d.is_zero())
            .ok_or(TransportError::Timeout)?;
        let body = request
            .body
            .as_ref()
            .ok_or_else(|| refuse("request body required"))?;
        let response = builder
            .config()
            .timeout_global(Some(remaining))
            .build()
            .send(body.as_slice())
            .map_err(|error| classify_ureq_error(&error, request.max_response_body))?;
        ensure_time(deadline)?;
        finish_response(
            response.status().as_u16(),
            || response.into_body().into_reader(),
            request.max_response_body,
            deadline,
        )
    }
}

fn finish_response<R: Read>(
    status: u16,
    reader: impl FnOnce() -> R,
    limit: usize,
    deadline: Instant,
) -> Result<Response, TransportError> {
    ensure_time(deadline)?;
    classify_status(status)?;
    if status == 401 {
        // Never obtain a body reader or answer WWW-Authenticate.
        return Ok(Response::new(status, Vec::new()));
    }
    read_response(status, reader(), limit, deadline)
}

// The existing GSA reader's single preallocated zeroizing buffer pattern,
// with explicit deadline checks around reads, including buffered reads/EOF.
fn read_response(
    status: u16,
    mut reader: impl Read,
    limit: usize,
    deadline: Instant,
) -> Result<Response, TransportError> {
    if limit == 0 || limit > MAX_RESPONSE_BODY {
        return Err(refuse("response bound out of range"));
    }
    ensure_time(deadline)?;
    let mut body = Zeroizing::new(vec![0; limit + 1]);
    let mut used = 0;
    loop {
        ensure_time(deadline)?;
        let result = reader.read(&mut body[used..]);
        ensure_time(deadline)?;
        let read = result.map_err(|error| {
            if error.kind() == std::io::ErrorKind::TimedOut {
                TransportError::Timeout
            } else {
                refuse("response body read failed")
            }
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

#[cfg(test)]
mod tests {
    use super::*;
    use zeroize::Zeroizing;

    fn header(name: &str, value: &str) -> (String, Zeroizing<String>) {
        (name.to_owned(), Zeroizing::new(value.to_owned()))
    }

    fn request() -> Request {
        Request {
            method: Method::Post,
            url: DELEGATE_ENDPOINT.to_owned(),
            headers: vec![header("Content-Type", DELEGATE_CONTENT_TYPE)],
            body: Some(Zeroizing::new(b"synthetic-body".to_vec())),
            max_response_body: MAX_RESPONSE_BODY,
        }
    }

    #[test]
    fn validator_rejects_url_near_misses() {
        for url in [
            "http://setup.icloud.com/setup/iosbuddy/loginDelegates",
            "https://setup.icloud.com/setup/iosbuddy/loginDelegates/",
            "https://setup.icloud.com/setup/iosbuddy/loginDelegates?x=1",
            "https://setup.icloud.com/setup/iosbuddy/loginDelegates#fragment",
            "https://setup.icloud.com:443/setup/iosbuddy/loginDelegates",
            "https://setup.icloud.com.evil.invalid/setup/iosbuddy/loginDelegates",
            "https://other.invalid/setup/iosbuddy/loginDelegates",
            "https://user@setup.icloud.com/setup/iosbuddy/loginDelegates",
            "https://setup.icloud.com/setup/iosbuddy/loginDelegate",
            coffer_protocol::auth::GSA_ENDPOINT,
        ] {
            let mut req = request();
            req.url = url.to_owned();
            let expected = validate_request(&req).unwrap_err();
            let production = UreqDelegateExchange::new();
            assert_eq!(
                production.exchange(&req, Duration::ZERO).unwrap_err(),
                expected
            );
            let transport = DelegateTransport::new(
                crate::transport::tests::FakeExchange::new(vec![]),
                deadlines(),
            );
            assert_eq!(transport.send_once(&req).unwrap_err(), expected);
            assert_eq!(transport.exchange.calls(), 0);
        }
    }

    fn deadlines() -> Deadlines {
        Deadlines::starting_now(Duration::from_secs(10), Duration::from_secs(30))
    }

    fn invalid_requests() -> Vec<Request> {
        let mut requests = Vec::new();
        let mut get = request();
        get.method = Method::Get;
        requests.push(get);
        for body in [
            None,
            Some(Zeroizing::new(vec![])),
            Some(Zeroizing::new(vec![0; MAX_REQUEST_BODY + 1])),
        ] {
            let mut req = request();
            req.body = body;
            requests.push(req);
        }
        for limit in [0, MAX_RESPONSE_BODY + 1, usize::MAX] {
            let mut req = request();
            req.max_response_body = limit;
            requests.push(req);
        }
        for headers in [
            vec![],
            vec![header("Content-Type", "text/x-xml-plist")],
            vec![header("Content-Type", "text/xml; charset=utf-8")],
            vec![
                header("Content-Type", "text/xml"),
                header("content-TYPE", "text/xml"),
            ],
            vec![
                header("Content-Type", "text/xml"),
                header("Authorization", "synthetic"),
                header("authorization", "synthetic"),
            ],
            vec![header("Content-Type", "text/xml"), header("", "synthetic")],
            vec![
                header("Content-Type", "text/xml"),
                header("X bad", "synthetic"),
            ],
            vec![
                header("Content-Type", "text/xml"),
                header("X:bad", "synthetic"),
            ],
            vec![
                header("Content-Type", "text/xml"),
                header("X-한글", "synthetic"),
            ],
            vec![
                header("Content-Type", "text/xml"),
                header("X-Name", "synthetic\r\nInjected: yes"),
            ],
            vec![
                header("Content-Type", "text/xml"),
                header("X-Name", "synthetic\tvalue"),
            ],
            vec![
                header("Content-Type", "text/xml"),
                header("X-Name", "synthetic\u{7f}"),
            ],
            vec![header("Content-Type", "text/xml"), header("X-Name", "비밀")],
            vec![
                header("Content-Type", "text/xml"),
                header("X-Name", &"x".repeat(MAX_HEADER_BYTES)),
            ],
            vec![
                header("Content-Type", "text/xml"),
                header(&"X".repeat(MAX_HEADER_BYTES), ""),
            ],
        ] {
            let mut req = request();
            req.headers = headers;
            requests.push(req);
        }
        for name in [
            "Host",
            "Content-Length",
            "Transfer-Encoding",
            "Connection",
            "Upgrade",
            "Expect",
            "Trailer",
            "TE",
            "Proxy-Authorization",
            "Proxy-Connection",
            "Accept-Encoding",
            "Content-Encoding",
        ] {
            let mut req = request();
            req.headers.push(header(name, "synthetic"));
            requests.push(req);
        }
        let mut req = request();
        req.headers
            .extend((0..MAX_HEADERS).map(|i| header(&format!("X-{i}"), "synthetic")));
        requests.push(req);
        requests
    }

    #[test]
    fn invalid_input_makes_zero_exchanges_in_both_entry_points() {
        use crate::transport::tests::FakeExchange;
        let transport = DelegateTransport::new(FakeExchange::new(vec![]), deadlines());
        let production = UreqDelegateExchange::new();
        for req in invalid_requests() {
            // Validate before invoking production, so a policy regression can
            // never turn this offline test into a network request.
            let expected = validate_request(&req).unwrap_err();
            assert_eq!(
                production.exchange(&req, Duration::ZERO).unwrap_err(),
                expected
            );
            assert_eq!(transport.send_once(&req).unwrap_err(), expected);
        }
        assert_eq!(transport.exchange.calls(), 0);
    }

    #[test]
    fn inclusive_body_response_header_count_and_byte_bounds() {
        let mut req = request();
        req.body = Some(Zeroizing::new(vec![0; MAX_REQUEST_BODY]));
        req.headers
            .extend((1..MAX_HEADERS).map(|i| header(&format!("X-{i}"), "")));
        assert!(validate_request(&req).is_ok());
        let bytes: usize = req.headers.iter().map(|(n, v)| n.len() + v.len() + 4).sum();
        req.headers
            .last_mut()
            .unwrap()
            .1
            .push_str(&"x".repeat(MAX_HEADER_BYTES - bytes));
        assert!(validate_request(&req).is_ok());
        req.headers.last_mut().unwrap().1.push('x');
        assert!(validate_request(&req).is_err());
    }

    #[test]
    fn one_send_returns_opaque_200_and_never_retries_failures() {
        use crate::transport::tests::FakeExchange;
        let transport = DelegateTransport::new(
            FakeExchange::new(vec![Ok((200, b"opaque synthetic XML".to_vec()))]),
            deadlines(),
        );
        let response = futures_lite::future::block_on(transport.send(request())).unwrap();
        assert_eq!(response.body(), b"opaque synthetic XML");
        assert_eq!(transport.exchange.calls(), 1);
        for error in [
            TransportError::Timeout,
            TransportError::Connect {
                detail: "synthetic secret".into(),
            },
            TransportError::Tls {
                detail: "synthetic secret".into(),
            },
            TransportError::Other {
                detail: "synthetic secret".into(),
            },
        ] {
            let transport =
                DelegateTransport::new(FakeExchange::new(vec![Err(error)]), deadlines());
            let error = transport.send_once(&request()).unwrap_err();
            assert!(!format!("{error:?} {error}").contains("synthetic secret"));
            assert!(std::error::Error::source(&error).is_none());
            assert_eq!(transport.exchange.calls(), 1);
        }
    }

    #[test]
    fn transport_rechecks_response_bound_and_suppresses_401_body() {
        use crate::transport::tests::FakeExchange;
        for status in [200, 401, 302, 407] {
            let transport = DelegateTransport::new(
                FakeExchange::new(vec![Ok((status, vec![0; MAX_RESPONSE_BODY + 1]))]),
                deadlines(),
            );
            let result = transport.send_once(&request());
            match status {
                200 => assert_eq!(
                    result.unwrap_err(),
                    TransportError::ResponseTooLarge {
                        limit: MAX_RESPONSE_BODY
                    }
                ),
                401 => assert!(result.unwrap().body().is_empty()),
                _ => assert!(matches!(result, Err(TransportError::Other { .. }))),
            }
            assert_eq!(transport.exchange.calls(), 1);
        }
    }

    #[test]
    fn production_response_path_never_obtains_reader_for_challenges_or_redirects() {
        for status in [401, 300, 301, 302, 303, 307, 308, 399, 407] {
            let result = finish_response(
                status,
                || -> std::io::Empty { panic!("refused response body must not be read") },
                MAX_RESPONSE_BODY,
                deadlines().overall,
            );
            if status == 401 {
                let response = result.unwrap();
                assert_eq!(response.status(), 401);
                assert!(response.body().is_empty());
            } else {
                assert!(result.is_err());
            }
        }
    }

    #[test]
    fn bounded_reader_checks_eof_oversize_failure_and_timeout() {
        for length in [0, 7, 8, 9] {
            let body = vec![b'x'; length];
            let result = read_response(200, body.as_slice(), 8, deadlines().overall);
            if length > 8 {
                assert_eq!(
                    result.unwrap_err(),
                    TransportError::ResponseTooLarge { limit: 8 }
                );
            } else {
                assert_eq!(result.unwrap().body(), body);
            }
        }
        struct FailingReader(std::io::ErrorKind);
        impl Read for FailingReader {
            fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
                Err(std::io::Error::new(self.0, "synthetic body secret"))
            }
        }
        for kind in [std::io::ErrorKind::Other, std::io::ErrorKind::TimedOut] {
            let error =
                read_response(200, FailingReader(kind), 8, deadlines().overall).unwrap_err();
            assert!(!format!("{error:?} {error}").contains("synthetic body secret"));
            if kind == std::io::ErrorKind::TimedOut {
                assert_eq!(error, TransportError::Timeout);
            }
        }
    }

    #[test]
    fn expired_and_zero_deadlines_make_zero_exchanges() {
        use crate::transport::tests::FakeExchange;
        for limits in [
            Deadlines {
                per_exchange: Duration::ZERO,
                overall: deadlines().overall,
            },
            Deadlines {
                per_exchange: Duration::from_secs(10),
                overall: Instant::now(),
            },
        ] {
            let transport = DelegateTransport::new(FakeExchange::new(vec![]), limits);
            assert_eq!(
                transport.send_once(&request()).unwrap_err(),
                TransportError::Timeout
            );
            assert_eq!(transport.exchange.calls(), 0);
        }
        let production = UreqDelegateExchange::new();
        for timeout in [Duration::ZERO, Duration::MAX] {
            assert!(exchange_deadline(Instant::now(), timeout).is_err());
            assert_eq!(
                production.exchange(&request(), timeout).unwrap_err(),
                TransportError::Timeout
            );
        }
    }

    #[test]
    fn earliest_deadline_is_passed_to_exchange() {
        use crate::transport::tests::FakeExchange;
        for (per, total) in [(10, 30), (30, 10)] {
            let transport = DelegateTransport::new(
                FakeExchange::new(vec![Ok((200, vec![]))]),
                Deadlines::starting_now(Duration::from_secs(per), Duration::from_secs(total)),
            );
            transport.send_once(&request()).unwrap();
            let recorded = transport.exchange.timeouts.lock().unwrap();
            assert_eq!(recorded.len(), 1);
            assert!(!recorded[0].is_zero());
            assert!(recorded[0] <= Duration::from_secs(10));
        }
    }

    #[test]
    fn late_exchange_and_late_eof_are_refused_without_retry() {
        struct LateExchange;
        impl Exchange for LateExchange {
            fn exchange(&self, _: &Request, timeout: Duration) -> Result<Response, TransportError> {
                std::thread::sleep(timeout + Duration::from_millis(1));
                Ok(Response::new(200, vec![]))
            }
        }
        let transport = DelegateTransport::new(
            LateExchange,
            Deadlines::starting_now(Duration::from_millis(1), Duration::from_secs(10)),
        );
        assert_eq!(
            transport.send_once(&request()).unwrap_err(),
            TransportError::Timeout
        );
        struct LateEof;
        impl Read for LateEof {
            fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
                std::thread::sleep(Duration::from_millis(3));
                Ok(0)
            }
        }
        assert_eq!(
            read_response(200, LateEof, 8, Instant::now() + Duration::from_millis(1)).unwrap_err(),
            TransportError::Timeout
        );
        assert_eq!(
            read_response(200, std::io::empty(), 8, Instant::now()).unwrap_err(),
            TransportError::Timeout
        );
    }

    #[test]
    fn production_agent_uses_webpki_verified_rustls_and_no_implicit_features() {
        let transport = DelegateTransport::production(deadlines());
        let config = transport.exchange.agent.config();
        let tls = config.tls_config();
        assert!(matches!(tls.root_certs(), RootCerts::WebPki));
        assert_eq!(tls.provider(), TlsProvider::Rustls);
        assert!(tls.use_sni());
        assert!(!tls.disable_verification());
        assert_eq!(config.max_redirects(), 0);
        assert!(config.proxy().is_none());
        assert!(!config.http_status_as_error());
        assert!(config.https_only());
        assert!(matches!(config.user_agent(), AutoHeaderValue::None));
        assert!(matches!(config.accept(), AutoHeaderValue::None));
        assert!(matches!(config.accept_encoding(), AutoHeaderValue::None));
        assert_eq!(config.max_idle_connections(), 0);
        assert_eq!(config.max_idle_connections_per_host(), 0);
        assert_eq!(config.max_response_header_size(), MAX_HEADER_BYTES);
        assert_eq!(format!("{transport:?}"), "DelegateTransport");
        assert_eq!(format!("{:?}", transport.exchange), "UreqDelegateExchange");
    }

    #[test]
    fn invalid_secret_headers_and_body_never_appear_in_errors() {
        let mut req = request();
        req.headers
            .push(header("synthetic-secret-name:", "synthetic-secret-value"));
        let error = validate_request(&req).unwrap_err();
        let text = format!("{error:?} {error}");
        for secret in [
            "synthetic-secret-name",
            "synthetic-secret-value",
            "synthetic-body",
        ] {
            assert!(!text.contains(secret));
        }
    }
}
