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

//! The artifact endpoint policy and the interface every downloader implements.
//!
//! Splitting the network out behind [`ArtifactSource`] is what makes the rest of
//! this crate testable.  The orchestration in [`Bootstrap`](crate::Bootstrap)
//! performs no I/O of its own beyond the filesystem, so a deterministic fake
//! source drives
//! the archive, verification, install and publish paths end to end without a
//! socket.
//!
//! The endpoint policy lives here rather than in the HTTP implementation on
//! purpose: [`SourceUrl`] can only be constructed for the single Apple-owned
//! artifact, so no implementation of [`ArtifactSource`] can be asked to fetch
//! anything else, and the policy is unit-testable without a network stack.

use core::fmt;
use std::io::Read;

use crate::limits::Limits;

/// The scheme the artifact endpoint must use.
const ALLOWED_SCHEME: &str = "https";

/// The host the artifact endpoint must use.
const ALLOWED_HOST: &str = "apps.mzstatic.com";

/// The path the artifact endpoint must use.
const ALLOWED_PATH: &str = "/content/android-apple-music-apk/applemusic.apk";

/// The only artifact URL Coffer will fetch.
///
/// This is an Apple-owned host serving the Apple Music Android application
/// archive, which is the only Apple-controlled distribution point known to
/// carry the support libraries local anisette generation needs.  Coffer does
/// not accept mirrors, third-party archives of the same file, or any
/// anisette-as-a-service endpoint.
pub const APPLE_MUSIC_APK_URL: &str =
    "https://apps.mzstatic.com/content/android-apple-music-apk/applemusic.apk";

/// A URL that has been checked against Coffer's artifact endpoint policy.
///
/// # Invariants
///
/// A value of this type is always exactly [`APPLE_MUSIC_APK_URL`].  There is no
/// constructor that produces anything else, so a downloader holding one cannot
/// be redirected to another origin by configuration, by an environment
/// variable, or by a caller.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SourceUrl {
    url: &'static str,
}

impl SourceUrl {
    /// The Apple Music Android archive endpoint.
    #[must_use]
    pub const fn apple_music_apk() -> Self {
        Self {
            url: APPLE_MUSIC_APK_URL,
        }
    }

    /// Checks a candidate URL against the endpoint policy.
    ///
    /// This exists so that a URL arriving from outside the crate, such as a
    /// configuration file or a redirect target a future implementation decides
    /// to inspect, is measured against the same rules as the constant.  The
    /// scheme, host, port and path must all match, and userinfo, query strings
    /// and fragments are refused rather than ignored.
    ///
    /// # Errors
    ///
    /// Returns the specific [`UrlPolicyViolation`] that made the candidate
    /// unacceptable.  The candidate itself is never carried in the error: it
    /// may be attacker-influenced and there is no diagnostic value in echoing
    /// it back.
    pub fn parse(candidate: &str) -> Result<Self, UrlPolicyViolation> {
        let (scheme, rest) = candidate
            .split_once("://")
            .ok_or(UrlPolicyViolation::MalformedUrl)?;
        if !scheme.eq_ignore_ascii_case(ALLOWED_SCHEME) {
            return Err(UrlPolicyViolation::SchemeNotAllowed);
        }

        if rest.contains('#') {
            return Err(UrlPolicyViolation::FragmentNotAllowed);
        }
        if rest.contains('?') {
            return Err(UrlPolicyViolation::QueryNotAllowed);
        }

        let (authority, path) = match rest.find('/') {
            Some(index) => rest.split_at(index),
            None => (rest, ""),
        };
        if authority.contains('@') {
            return Err(UrlPolicyViolation::UserInfoNotAllowed);
        }

        let (host, port) = match authority.rsplit_once(':') {
            Some((host, port)) => (host, Some(port)),
            None => (authority, None),
        };
        if !host.eq_ignore_ascii_case(ALLOWED_HOST) {
            return Err(UrlPolicyViolation::HostNotAllowed);
        }
        // An explicit `:443` is the same endpoint; anything else is not, and an
        // empty or non-numeric port is malformed rather than merely different.
        match port {
            None => {}
            Some("443") => {}
            Some(_) => return Err(UrlPolicyViolation::PortNotAllowed),
        }

        if path != ALLOWED_PATH {
            return Err(UrlPolicyViolation::PathNotAllowed);
        }

        Ok(Self::apple_music_apk())
    }

    /// The URL as a string, always [`APPLE_MUSIC_APK_URL`].
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        self.url
    }
}

impl fmt::Display for SourceUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.url)
    }
}

/// The reason a candidate URL is not Coffer's artifact endpoint.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum UrlPolicyViolation {
    /// The candidate is not an absolute URL with a scheme.
    MalformedUrl,
    /// The scheme is not `https`.
    SchemeNotAllowed,
    /// The host is not the allowed Apple host.
    HostNotAllowed,
    /// An explicit port other than the default HTTPS port was given.
    PortNotAllowed,
    /// The path is not the allowed artifact path.
    PathNotAllowed,
    /// The authority carried userinfo, which can disguise the real host.
    UserInfoNotAllowed,
    /// The URL carried a query string.
    QueryNotAllowed,
    /// The URL carried a fragment.
    FragmentNotAllowed,
}

impl fmt::Display for UrlPolicyViolation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let reason = match self {
            UrlPolicyViolation::MalformedUrl => "not an absolute URL",
            UrlPolicyViolation::SchemeNotAllowed => "scheme is not https",
            UrlPolicyViolation::HostNotAllowed => "host is not the Apple artifact host",
            UrlPolicyViolation::PortNotAllowed => "port is not the default HTTPS port",
            UrlPolicyViolation::PathNotAllowed => "path is not the Apple artifact path",
            UrlPolicyViolation::UserInfoNotAllowed => "URL carries userinfo",
            UrlPolicyViolation::QueryNotAllowed => "URL carries a query string",
            UrlPolicyViolation::FragmentNotAllowed => "URL carries a fragment",
        };
        write!(f, "rejected artifact URL: {reason}")
    }
}

impl std::error::Error for UrlPolicyViolation {}

/// Response metadata Coffer observed while fetching the artifact.
///
/// Every field except [`ObservedArtifact::declared_length`] is remote-controlled
/// free text that ends up in a file on disk, so all of them are sanitized by
/// [`ObservedArtifact::sanitized_header`] before being recorded: a value is kept
/// only if it is short and printable ASCII, and dropped otherwise.  None of
/// these values is trusted for a security decision; they exist so a maintainer
/// can tell which build of the artifact an installation came from.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ObservedArtifact {
    /// The `Content-Length` the server declared.
    pub declared_length: u64,
    /// The `Last-Modified` header, if the server sent a usable one.
    pub last_modified: Option<String>,
    /// The `ETag` header, if the server sent a usable one.
    ///
    /// Treated as an opaque token.  The observed endpoint's `ETag` is not a
    /// digest of the body and conditional requests using it are ignored, so it
    /// is recorded for diagnostics only.
    pub etag: Option<String>,
    /// The `x-apple-version-number` header, if the server sent a usable one.
    ///
    /// A non-standard header the observed endpoint sends as
    /// `<versionName>.<versionCode>`.  It is a hint, not a verified property of
    /// the archive: Coffer identifies an installation by content digest.
    pub apple_version_number: Option<String>,
    /// The `Content-Type` header, if the server sent a usable one.
    pub content_type: Option<String>,
}

impl ObservedArtifact {
    /// Normalizes a header value for recording in install metadata.
    ///
    /// Returns `None` when the value is empty, longer than
    /// [`Limits::max_header_value_bytes`], or contains a byte outside printable
    /// ASCII.  Dropping such a value is deliberate: metadata is written to disk
    /// and read back by other Coffer components, and a header is not worth
    /// giving a remote party a channel into that file.
    #[must_use]
    pub fn sanitized_header(value: &str, limits: &Limits) -> Option<String> {
        if value.is_empty() || value.len() > limits.max_header_value_bytes {
            return None;
        }
        if !value.bytes().all(|b| (0x20..=0x7e).contains(&b)) {
            return None;
        }
        Some(value.to_owned())
    }
}

/// A response body together with the metadata observed alongside it.
///
/// The body is a stream, not a buffer: the artifact is over a hundred
/// mebibytes, and the caller enforces [`Limits::max_archive_bytes`] while
/// copying it to disk rather than trusting `declared_length`.
pub struct FetchedArtifact {
    /// What the response said about the artifact.
    pub observed: ObservedArtifact,
    /// The response body.
    pub body: Box<dyn Read + Send>,
}

impl fmt::Debug for FetchedArtifact {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FetchedArtifact")
            .field("observed", &self.observed)
            .finish_non_exhaustive()
    }
}

/// Why fetching the artifact failed.
///
/// The variants distinguish "the network is not available" from "the endpoint
/// answered, but not with the artifact", because those lead to different
/// behavior: the first is a normal offline condition under which Coffer reuses
/// an existing installation, and the second means the distribution point
/// changed and a maintainer needs to look.
///
/// No variant carries a URL, a path, a header value or a response body.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum FetchError {
    /// The endpoint could not be reached: DNS, connect, or TLS failed, or the
    /// transfer was interrupted.
    Unreachable,
    /// The server answered with a redirect.
    ///
    /// Coffer refuses redirects outright rather than re-validating each hop.
    /// The artifact endpoint has never redirected, and refusing is the
    /// fail-closed choice: there is no origin other than the one in
    /// [`APPLE_MUSIC_APK_URL`] that Coffer would accept the artifact from.
    Redirected,
    /// The server answered with a status other than `200 OK`.
    UnexpectedStatus(u16),
    /// The response carried no usable `Content-Length`.
    ///
    /// Coffer requires the declared length so that an oversized transfer is
    /// refused before any of it is written to disk.
    MissingContentLength,
    /// The declared length exceeds [`Limits::max_archive_bytes`].
    DeclaredLengthTooLarge {
        /// The length the server declared.
        declared: u64,
        /// The configured ceiling.
        limit: u64,
    },
}

impl fmt::Display for FetchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FetchError::Unreachable => f.write_str("the artifact endpoint could not be reached"),
            FetchError::Redirected => {
                f.write_str("the artifact endpoint answered with a redirect, which is refused")
            }
            FetchError::UnexpectedStatus(status) => {
                write!(f, "the artifact endpoint answered with HTTP {status}")
            }
            FetchError::MissingContentLength => {
                f.write_str("the artifact response declared no usable content length")
            }
            FetchError::DeclaredLengthTooLarge { declared, limit } => write!(
                f,
                "the artifact response declared {declared} bytes, over the {limit}-byte limit"
            ),
        }
    }
}

impl std::error::Error for FetchError {}

/// Something that can retrieve the artifact.
///
/// # Implementation requirements
///
/// An implementation must not log, persist or transmit anything about the
/// caller, and must not fall back to another origin when the endpoint is
/// unavailable: [`SourceUrl`] names the only acceptable origin, and a fallback
/// would defeat the point of the type.  Returning [`FetchError::Unreachable`]
/// is the correct response to an outage; Coffer then reuses an existing
/// installation if it has one.
///
/// Implementations are used from a single thread at a time but must be `Send`
/// so that a graphical front end can drive bootstrap on a worker thread.
pub trait ArtifactSource {
    /// Fetches the artifact.
    ///
    /// # Errors
    ///
    /// Returns [`FetchError`] describing which stage of the fetch failed.  An
    /// implementation must not retry an unreachable endpoint on the caller's
    /// behalf more times than a plain idempotent download warrants, and must
    /// never retry a response that failed validation.
    fn fetch(&self, url: &SourceUrl, limits: &Limits) -> Result<FetchedArtifact, FetchError>;
}

impl<T: ArtifactSource + ?Sized> ArtifactSource for &T {
    fn fetch(&self, url: &SourceUrl, limits: &Limits) -> Result<FetchedArtifact, FetchError> {
        (**self).fetch(url, limits)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_only_the_apple_artifact_url() {
        let url = SourceUrl::parse(APPLE_MUSIC_APK_URL).expect("the constant must satisfy policy");
        assert_eq!(url, SourceUrl::apple_music_apk());
        assert_eq!(url.as_str(), APPLE_MUSIC_APK_URL);
    }

    #[test]
    fn accepts_an_explicit_default_https_port_and_a_differently_cased_scheme_and_host() {
        for candidate in [
            "https://apps.mzstatic.com:443/content/android-apple-music-apk/applemusic.apk",
            "HTTPS://APPS.MZSTATIC.COM/content/android-apple-music-apk/applemusic.apk",
        ] {
            assert_eq!(
                SourceUrl::parse(candidate).expect("equivalent endpoint"),
                SourceUrl::apple_music_apk()
            );
        }
    }

    #[test]
    fn rejects_every_other_endpoint() {
        let cases = [
            (
                "http://apps.mzstatic.com/content/android-apple-music-apk/applemusic.apk",
                UrlPolicyViolation::SchemeNotAllowed,
            ),
            (
                "https://evil.example/content/android-apple-music-apk/applemusic.apk",
                UrlPolicyViolation::HostNotAllowed,
            ),
            (
                "https://apps.mzstatic.com.evil.example/content/android-apple-music-apk/applemusic.apk",
                UrlPolicyViolation::HostNotAllowed,
            ),
            (
                "https://apps.mzstatic.com:8443/content/android-apple-music-apk/applemusic.apk",
                UrlPolicyViolation::PortNotAllowed,
            ),
            (
                "https://apps.mzstatic.com/content/android-apple-music-apk/other.apk",
                UrlPolicyViolation::PathNotAllowed,
            ),
            (
                "https://apps.mzstatic.com/",
                UrlPolicyViolation::PathNotAllowed,
            ),
            (
                "https://apps.mzstatic.com",
                UrlPolicyViolation::PathNotAllowed,
            ),
            (
                "https://apps.mzstatic.com@evil.example/content/android-apple-music-apk/applemusic.apk",
                UrlPolicyViolation::UserInfoNotAllowed,
            ),
            (
                "https://apps.mzstatic.com/content/android-apple-music-apk/applemusic.apk?x=1",
                UrlPolicyViolation::QueryNotAllowed,
            ),
            (
                "https://apps.mzstatic.com/content/android-apple-music-apk/applemusic.apk#f",
                UrlPolicyViolation::FragmentNotAllowed,
            ),
            ("apps.mzstatic.com", UrlPolicyViolation::MalformedUrl),
            ("", UrlPolicyViolation::MalformedUrl),
            (
                "file:///content/android-apple-music-apk/applemusic.apk",
                UrlPolicyViolation::SchemeNotAllowed,
            ),
        ];
        for (candidate, expected) in cases {
            assert_eq!(
                SourceUrl::parse(candidate),
                Err(expected),
                "unexpected verdict for {candidate}"
            );
        }
    }

    #[test]
    fn rejects_a_path_that_only_looks_like_the_artifact_path() {
        assert_eq!(
            SourceUrl::parse(
                "https://apps.mzstatic.com/content/android-apple-music-apk/applemusic.apk/../evil"
            ),
            Err(UrlPolicyViolation::PathNotAllowed)
        );
    }

    #[test]
    fn sanitizes_header_values_before_they_reach_metadata() {
        let limits = Limits::DEFAULT;
        assert_eq!(
            ObservedArtifact::sanitized_header("4.9.6.1447", &limits),
            Some("4.9.6.1447".to_owned())
        );
        assert_eq!(ObservedArtifact::sanitized_header("", &limits), None);
        assert_eq!(ObservedArtifact::sanitized_header("a\nb", &limits), None);
        assert_eq!(ObservedArtifact::sanitized_header("a\0b", &limits), None);
        assert_eq!(ObservedArtifact::sanitized_header("héllo", &limits), None);
        let long = "a".repeat(limits.max_header_value_bytes + 1);
        assert_eq!(ObservedArtifact::sanitized_header(&long, &limits), None);
        let exact = "a".repeat(limits.max_header_value_bytes);
        assert_eq!(
            ObservedArtifact::sanitized_header(&exact, &limits),
            Some(exact)
        );
    }
}
