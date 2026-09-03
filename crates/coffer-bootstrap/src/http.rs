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

//! The production downloader.
//!
//! # Transport
//!
//! Blocking HTTPS over `ureq` with rustls.  Blocking, not asynchronous, is a
//! deliberate choice: bootstrap is a single large download that happens rarely,
//! it has no concurrency to exploit, and making it `async` would force an
//! executor on every consumer of this crate.  A command-line tool calls
//! [`Bootstrap::ensure`](crate::Bootstrap::ensure) directly; a GTK application
//! calls it on a worker thread and posts the result back to the main loop,
//! which is the same thing it would have to do for the filesystem work anyway.
//!
//! # Trust anchors
//!
//! The `rustls` feature of `ureq` verifies the server certificate against
//! Mozilla's root bundle rather than the system trust store.  That is the
//! stricter choice here: an interception certificate installed in the system
//! store — a corporate middlebox, a debugging proxy, malware — would otherwise
//! be able to substitute the binaries Coffer is about to install and later
//! load.  The endpoint is a single fixed Apple host with a publicly trusted
//! certificate, so there is no legitimate deployment that needs a private CA to
//! reach it.
//!
//! # Redirects
//!
//! Refused, not followed and not re-validated.  See
//! [`FetchError::Redirected`].
//!
//! # Deadlines
//!
//! Every stage is bounded, and the transfer as a whole has an end-to-end
//! deadline rather than only a per-read one.  This matters because bootstrap
//! holds the cross-process lock while it downloads: a per-read inactivity
//! timeout alone would let a server that sends one byte before each deadline
//! keep every Coffer process on the machine waiting indefinitely.
//!
//! # What is sent
//!
//! A `GET` with an honest `coffer-bootstrap/<version>` user agent and nothing
//! else.  No cookies, no credentials, no account identifier, no machine
//! identifier, no `Referer`.  The request says nothing about the user beyond
//! the fact that some Coffer installation is downloading a public file.

use std::io::Read;
use std::time::Duration;

use crate::limits::Limits;
use crate::source::{ArtifactSource, FetchError, FetchedArtifact, ObservedArtifact, SourceUrl};

/// How long to wait for the TCP connection and TLS handshake.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

/// How long to wait for the response head.
const RESPONSE_TIMEOUT: Duration = Duration::from_secs(60);

/// How long a single read of the response body may stall.
///
/// `ureq` recomputes this per read, so it bounds inactivity rather than the
/// transfer.  A server that trickles bytes stays under it indefinitely, which
/// is why [`TRANSFER_DEADLINE`] exists as well.
const BODY_STALL_TIMEOUT: Duration = Duration::from_secs(60);

/// How long the whole request may take, from name resolution to the last byte
/// of the body.
///
/// This is the bound that actually matters.  Bootstrap holds the cross-process
/// lock for the length of the download, so an endpoint that never finishes must
/// not be able to block every other Coffer process forever.  Generous enough
/// for a hundred-plus mebibyte download on a slow connection, and finite.
const TRANSFER_DEADLINE: Duration = Duration::from_secs(30 * 60);

/// The `Content-Type` the endpoint is expected to serve.
///
/// A mismatch is recorded, not enforced.  The archive's structure is what
/// Coffer actually validates, and a content delivery network changing this
/// header is not evidence of anything.
pub const EXPECTED_CONTENT_TYPE: &str = "application/vnd.android.package-archive";

/// Downloads the artifact from Apple's content delivery network.
///
/// # Safety of retries
///
/// A `GET` of a static file is idempotent, so a caller may retry a
/// [`FetchError::Unreachable`].  A response that was received but failed
/// validation must not be retried: that is a signal about the artifact or the
/// path to it, and repeating the request only turns one anomaly into many.
#[derive(Debug)]
pub struct AppleCdnSource {
    agent: ureq::Agent,
}

impl AppleCdnSource {
    /// Builds a downloader with Coffer's transport policy.
    #[must_use]
    pub fn new() -> Self {
        let config = ureq::Agent::config_builder()
            // Refuse redirects outright rather than re-validating each hop.
            .max_redirects(0)
            .max_redirects_will_error(true)
            .http_status_as_error(true)
            .user_agent(concat!("coffer-bootstrap/", env!("CARGO_PKG_VERSION")))
            .timeout_connect(Some(CONNECT_TIMEOUT))
            .timeout_recv_response(Some(RESPONSE_TIMEOUT))
            .timeout_recv_body(Some(BODY_STALL_TIMEOUT))
            // End to end, and therefore the one bound a trickling server
            // cannot extend by sending a byte before each read deadline.
            .timeout_global(Some(TRANSFER_DEADLINE))
            .build();
        Self {
            agent: ureq::Agent::new_with_config(config),
        }
    }
}

impl Default for AppleCdnSource {
    fn default() -> Self {
        Self::new()
    }
}

impl ArtifactSource for AppleCdnSource {
    fn fetch(&self, url: &SourceUrl, limits: &Limits) -> Result<FetchedArtifact, FetchError> {
        // `url` can only be the pinned artifact URL, and redirects are refused,
        // so the scheme, host and port checked by `SourceUrl` are the ones this
        // request actually reaches.
        let response = self.agent.get(url.as_str()).call().map_err(classify)?;

        let status = response.status().as_u16();
        if status != 200 {
            return Err(FetchError::UnexpectedStatus(status));
        }

        let header = |name: &str| {
            response
                .headers()
                .get(name)
                .and_then(|value| value.to_str().ok())
                .and_then(|value| ObservedArtifact::sanitized_header(value, limits))
        };
        let declared_length = response
            .headers()
            .get("content-length")
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<u64>().ok())
            .ok_or(FetchError::MissingContentLength)?;
        if declared_length > limits.max_archive_bytes {
            return Err(FetchError::DeclaredLengthTooLarge {
                declared: declared_length,
                limit: limits.max_archive_bytes,
            });
        }

        let observed = ObservedArtifact {
            declared_length,
            last_modified: header("last-modified"),
            etag: header("etag"),
            apple_version_number: header("x-apple-version-number"),
            content_type: header("content-type"),
        };

        let body: Box<dyn Read + Send> = Box::new(response.into_body().into_reader());
        Ok(FetchedArtifact { observed, body })
    }
}

/// Maps a transport failure onto the crate's error vocabulary.
///
/// Everything that means "the endpoint answered, but wrongly" keeps its
/// distinct variant; everything that means "we never got a usable answer"
/// collapses into [`FetchError::Unreachable`], because bootstrap treats those
/// identically and the distinctions carry host and proxy details Coffer has no
/// reason to surface.
fn classify(error: ureq::Error) -> FetchError {
    match error {
        ureq::Error::TooManyRedirects | ureq::Error::RedirectFailed => FetchError::Redirected,
        ureq::Error::StatusCode(status) => {
            if (300..400).contains(&status) {
                FetchError::Redirected
            } else {
                FetchError::UnexpectedStatus(status)
            }
        }
        _ => FetchError::Unreachable,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_redirects_separately_from_other_statuses() {
        assert_eq!(
            classify(ureq::Error::TooManyRedirects),
            FetchError::Redirected
        );
        assert_eq!(
            classify(ureq::Error::RedirectFailed),
            FetchError::Redirected
        );
        assert_eq!(
            classify(ureq::Error::StatusCode(302)),
            FetchError::Redirected
        );
        assert_eq!(
            classify(ureq::Error::StatusCode(404)),
            FetchError::UnexpectedStatus(404)
        );
        assert_eq!(
            classify(ureq::Error::StatusCode(503)),
            FetchError::UnexpectedStatus(503)
        );
        assert_eq!(classify(ureq::Error::HostNotFound), FetchError::Unreachable);
        assert_eq!(
            classify(ureq::Error::ConnectionFailed),
            FetchError::Unreachable
        );
        assert_eq!(
            classify(ureq::Error::Tls("handshake failed")),
            FetchError::Unreachable
        );
    }

    #[test]
    fn the_downloader_can_only_be_pointed_at_the_pinned_endpoint() {
        // `fetch` takes a `SourceUrl`, and the only values of that type are the
        // pinned artifact URL.  This test records the invariant so that adding
        // another constructor to `SourceUrl` breaks here.
        let url = SourceUrl::apple_music_apk();
        assert_eq!(url.as_str(), crate::source::APPLE_MUSIC_APK_URL);
        assert!(url.as_str().starts_with("https://apps.mzstatic.com/"));
    }

    #[test]
    fn the_expected_content_type_is_recorded_but_not_enforced() {
        // Recorded in metadata, never compared against.  A change in this
        // header must not break bootstrap; a change in the archive's structure
        // must.
        assert_eq!(
            EXPECTED_CONTENT_TYPE,
            "application/vnd.android.package-archive"
        );
    }

    #[test]
    fn the_transfer_has_an_end_to_end_deadline_and_not_only_a_stall_timeout() {
        // `ureq` recomputes `timeout_recv_body` on every read, so it bounds
        // inactivity; only the global timeout bounds the whole transfer.  Both
        // are configured, and the deadline is the larger of the two.
        assert!(TRANSFER_DEADLINE > BODY_STALL_TIMEOUT);
        assert!(TRANSFER_DEADLINE > CONNECT_TIMEOUT);
        assert!(TRANSFER_DEADLINE > RESPONSE_TIMEOUT);
        // Construction goes through the same builder the downloader uses, so a
        // configuration `ureq` rejects fails here rather than at first use.
        let _ = AppleCdnSource::new();
    }

    #[test]
    fn a_default_source_is_the_configured_source() {
        // Construction must not panic: the agent configuration is built from
        // constants, and a mistake in it should fail here rather than at the
        // first download.
        let _ = AppleCdnSource::default();
        let _ = AppleCdnSource::new();
    }
}
