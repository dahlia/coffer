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

//! The HTTP transport boundary.
//!
//! The protocol layer builds fully formed HTTP requests and hands them to a
//! caller-supplied [`Transport`].  It never opens a socket, negotiates TLS,
//! follows a redirect, or retries on its own.  A concrete implementation
//! (for example one built on a Rust HTTP client with rustls) lives in a
//! higher layer of Coffer, and tests use a scripted implementation that
//! replays canned responses.

use core::fmt;
use std::future::Future;

use zeroize::Zeroizing;

/// HTTP method of a [`Request`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Method {
    /// `GET`.
    Get,
    /// `POST`.
    Post,
}

impl Method {
    /// Returns the method token as it appears on the request line.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Post => "POST",
        }
    }
}

/// An HTTP request built by the protocol layer.
///
/// Header values and bodies frequently carry secrets (the SRP proof, the
/// identity token, a verification code), so the `Debug` implementation prints
/// only the method, the URL, the header *names*, and the body length.  A
/// transport implementation must not log the values either.
pub struct Request {
    /// HTTP method.
    pub method: Method,
    /// Absolute `https://` URL.
    pub url: String,
    /// Request headers in the order they should be sent.
    ///
    /// Every value has already been checked to be printable ASCII without
    /// control characters.  Values are wrapped in [`Zeroizing`] because some
    /// of them are secrets (the identity token, the anisette one-time
    /// password, a verification code); they are wiped when the request is
    /// dropped.  A transport should avoid making further copies that outlive
    /// the exchange.
    pub headers: Vec<(String, Zeroizing<String>)>,
    /// Request body, if the method carries one.
    ///
    /// GSA request bodies embed the anisette attestation values, so the
    /// buffer is wiped when the request is dropped.
    pub body: Option<Zeroizing<Vec<u8>>>,
    /// Upper bound on the response body the transport may return.
    ///
    /// A transport must stop reading and fail with
    /// [`TransportError::ResponseTooLarge`] rather than buffer more than this
    /// many bytes.  The protocol layer re-checks the bound on the returned
    /// body as a second line of defense.
    pub max_response_body: usize,
}

impl fmt::Debug for Request {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let names: Vec<&str> = self.headers.iter().map(|(k, _)| k.as_str()).collect();
        f.debug_struct("Request")
            .field("method", &self.method)
            .field("url", &self.url)
            .field("header_names", &names)
            .field("body_len", &self.body.as_ref().map(|b| b.len()))
            .field("max_response_body", &self.max_response_body)
            .finish()
    }
}

/// An HTTP response returned by a [`Transport`].
///
/// Only the status code and the body are needed by the protocol layer.
/// Response headers are deliberately not modelled yet; they will be added
/// when a protocol step needs one.  `Debug` prints the status and the body
/// length only, because bodies contain session material.
pub struct Response {
    status: u16,
    body: Vec<u8>,
}

impl Response {
    /// Creates a response from its status code and body.
    #[must_use]
    pub fn new(status: u16, body: Vec<u8>) -> Self {
        Self { status, body }
    }

    /// Returns the HTTP status code.
    #[must_use]
    pub fn status(&self) -> u16 {
        self.status
    }

    /// Returns the body bytes.
    #[must_use]
    pub fn body(&self) -> &[u8] {
        &self.body
    }

    pub(crate) fn is_success(&self) -> bool {
        (200..300).contains(&self.status)
    }
}

impl fmt::Debug for Response {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Response")
            .field("status", &self.status)
            .field("body_len", &self.body.len())
            .finish()
    }
}

/// Performs exactly one HTTP exchange per call.
///
/// # Contract
///
/// An implementation must:
///
/// - send the request exactly once and never retry, even on a transport
///   failure, because the protocol layer decides whether a step may be
///   attempted again and most authentication steps must not be;
/// - not follow redirects, since a redirected authentication request would
///   deliver credentials to an unexpected host;
/// - verify the server certificate against a trust store the caller
///   controls; and
/// - enforce [`Request::max_response_body`].
///
/// The returned future is `Send` so that the authentication flow can run on
/// a multi-threaded executor; a single-threaded executor works just as well.
pub trait Transport: Send + Sync {
    /// Sends `request` and resolves to the server's response.
    ///
    /// # Errors
    ///
    /// Resolves to [`TransportError`] when no complete response was obtained.
    /// A response with a non-success status code is *not* an error at this
    /// level; the protocol layer interprets the status.
    fn send(
        &self,
        request: Request,
    ) -> impl Future<Output = Result<Response, TransportError>> + Send;
}

/// Failure to complete an HTTP exchange.
///
/// The `detail` strings are meant for diagnostics and must not contain
/// request headers or bodies.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum TransportError {
    /// The connection could not be established.
    Connect {
        /// Secret-free description of the failure.
        detail: String,
    },
    /// TLS negotiation or certificate verification failed.
    Tls {
        /// Secret-free description of the failure.
        detail: String,
    },
    /// The exchange did not complete within the transport's deadline.
    Timeout,
    /// The response body exceeded [`Request::max_response_body`].
    ResponseTooLarge {
        /// The limit that was exceeded.
        limit: usize,
    },
    /// Any other failure.
    Other {
        /// Secret-free description of the failure.
        detail: String,
    },
}

impl fmt::Display for TransportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Connect { detail } => write!(f, "connection failed: {detail}"),
            Self::Tls { detail } => write!(f, "TLS failed: {detail}"),
            Self::Timeout => f.write_str("request timed out"),
            Self::ResponseTooLarge { limit } => {
                write!(f, "response body exceeded {limit} bytes")
            }
            Self::Other { detail } => write!(f, "transport failed: {detail}"),
        }
    }
}

impl std::error::Error for TransportError {}
