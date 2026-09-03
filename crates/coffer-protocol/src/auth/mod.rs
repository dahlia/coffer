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

//! Apple Account authentication as an explicit, self-consuming state
//! machine.
//!
//! # Flow
//!
//! ```text
//! Authenticator::login(account, password)
//!   └─▶ PasswordLogin ──authenticate()──▶ LoginOutcome
//!                                          ├─ Authenticated(Session)
//!                                          ├─ SecondFactorRequired ──request_trusted_device_code()──▶ CodeRequested
//!                                          │        CodeRequested ──submit_code(code)──▶ SecondFactorVerified
//!                                          │        SecondFactorVerified ──reauthenticate(password)──▶ Session
//!                                          └─ Unsupported(UnsupportedStep)
//! ```
//!
//! Each arrow is an `async fn` that takes `self` by value, performs exactly
//! the network requests the protocol requires for that step, and returns
//! either the next stage or an [`AuthError`].  There is no way to obtain a
//! stage other than by completing the previous one: every stage type has
//! private fields and no public constructor.  Consequently:
//!
//! - a caller cannot skip a step, submit a code before one was requested, or
//!   re-authenticate before the code was accepted;
//! - a failed step cannot be repeated, because the stage value was consumed;
//!   the only path forward is a new [`Authenticator::login`] with a fresh
//!   user action and a fresh [`Password`]; and
//! - the crate itself never retries or loops.  A successful trusted-device
//!   verification is followed by one re-authentication, driven by the
//!   caller, and if that still demands a second factor the flow fails with
//!   [`AuthErrorKind::SecondFactorStillRequired`] instead of trying again.
//!
//! Every [`AuthError`] carries an [`AuthStage`], so a failure of the initial
//! password exchange is distinguishable from a failure of the post-two-factor
//! exchange.
//!
//! # Requests per step
//!
//! | Step                          | Requests |
//! | ----------------------------- | -------- |
//! | `authenticate`                | 2        |
//! | `request_trusted_device_code` | 1        |
//! | `submit_code`                 | 1        |
//! | `reauthenticate`              | 2        |
//!
//! # Secrets
//!
//! The password is consumed by the step that needs it and dropped before
//! the step returns.  The flow never keeps a password across a two-factor
//! prompt; [`SecondFactorVerified::reauthenticate`] asks for it again.  Only
//! the account identifier and the IdMS token, which the two-factor endpoints
//! need, survive between steps.  Nothing in this module implements `Display`
//! or a `Debug` that reveals a value.
//!
//! # Stage skipping does not compile
//!
//! A stage cannot be forged, because its fields are private:
//!
//! ```compile_fail,E0451
//! use coffer_protocol::auth::CodeRequested;
//! use coffer_protocol::anisette::AnisetteProvider;
//! use coffer_protocol::entropy::Entropy;
//! use coffer_protocol::transport::Transport;
//!
//! fn forge<'a, T: Transport, A: AnisetteProvider, E: Entropy>() -> CodeRequested<'a, T, A, E> {
//!     CodeRequested {
//!         auth: unimplemented!(),
//!         account: unimplemented!(),
//!         account_id: unimplemented!(),
//!         idms_token: unimplemented!(),
//!     }
//! }
//! ```
//!
//! A stage cannot be used twice, because each transition consumes it:
//!
//! ```compile_fail,E0382
//! use coffer_protocol::anisette::AnisetteProvider;
//! use coffer_protocol::auth::PasswordLogin;
//! use coffer_protocol::entropy::Entropy;
//! use coffer_protocol::transport::Transport;
//!
//! async fn twice<T: Transport, A: AnisetteProvider, E: Entropy>(login: PasswordLogin<'_, T, A, E>) {
//!     let _ = login.authenticate().await;
//!     let _ = login.authenticate().await;
//! }
//! ```
//!
//! The same code with a single call compiles, which shows the failure above
//! is the move and not a typo:
//!
//! ```
//! use coffer_protocol::anisette::AnisetteProvider;
//! use coffer_protocol::auth::PasswordLogin;
//! use coffer_protocol::entropy::Entropy;
//! use coffer_protocol::transport::Transport;
//!
//! async fn once<T: Transport, A: AnisetteProvider, E: Entropy>(login: PasswordLogin<'_, T, A, E>) {
//!     let _ = login.authenticate().await;
//! }
//! ```

mod error;
mod gsa;
mod spd;
mod srp;

use core::fmt;
use std::collections::BTreeMap;

use zeroize::{Zeroize, Zeroizing};

pub use error::{
    AuthError, AuthErrorKind, AuthStage, Malformed, MalformedReason, ProtocolStatus, ServerSelector,
};
pub use gsa::{
    GSA_ENDPOINT, ResponseLimits, SUPPORTED_PROTOCOL, TRUSTED_DEVICE_ENDPOINT, VALIDATE_ENDPOINT,
};

use crate::anisette::{AnisetteData, AnisetteProvider};
use crate::entropy::Entropy;
use crate::secret::{
    AccountId, AccountName, IdmsToken, Password, ServiceToken, SessionKey, VerificationCode,
};
use crate::transport::{Request, Response, Transport};
use spd::ServerProvidedData;
use srp::{ClientEphemeral, Proof, derive_password_key};

/// Service identifier of the password-equivalent token in
/// [`Session::service_token`].
pub const PET_SERVICE: &str = "com.apple.gs.idms.pet";

/// The context every authentication step runs in.
///
/// It owns the caller-supplied [`Transport`], [`AnisetteProvider`], and
/// [`Entropy`] source together with the [`ResponseLimits`].  Stage values
/// borrow it, so an `Authenticator` outlives every flow started from it and
/// two authenticators cannot be mixed within one flow.
///
/// An `Authenticator` holds no account state; it can start any number of
/// independent flows.
pub struct Authenticator<T, A, E> {
    transport: T,
    anisette: A,
    entropy: E,
    limits: ResponseLimits,
}

impl<T: Transport, A: AnisetteProvider, E: Entropy> Authenticator<T, A, E> {
    /// Creates an authenticator with default [`ResponseLimits`].
    #[must_use]
    pub fn new(transport: T, anisette: A, entropy: E) -> Self {
        Self {
            transport,
            anisette,
            entropy,
            limits: ResponseLimits::default(),
        }
    }

    /// Replaces the response limits.
    #[must_use]
    pub fn with_limits(mut self, limits: ResponseLimits) -> Self {
        self.limits = limits;
        self
    }

    /// Returns the response limits in effect.
    #[must_use]
    pub fn limits(&self) -> &ResponseLimits {
        &self.limits
    }

    /// Returns the transport.
    #[must_use]
    pub fn transport(&self) -> &T {
        &self.transport
    }

    /// Begins a password login.
    ///
    /// Nothing is sent until [`PasswordLogin::authenticate`] is called; this
    /// merely binds the credentials to the flow.
    #[must_use]
    pub fn login(&self, account: AccountName, password: Password) -> PasswordLogin<'_, T, A, E> {
        PasswordLogin {
            auth: self,
            account,
            password,
        }
    }

    async fn fresh_anisette(&self, stage: AuthStage) -> Result<AnisetteData, AuthError> {
        let data = self
            .anisette
            .anisette()
            .await
            .map_err(|e| AuthError::new(stage, AuthErrorKind::Anisette(e)))?;
        data.validate()
            .map_err(|e| AuthError::new(stage, AuthErrorKind::Anisette(e)))?;
        Ok(data)
    }

    /// Sends one request and checks the HTTP status and body cap.
    async fn exchange(&self, stage: AuthStage, request: Request) -> Result<Response, AuthError> {
        let response = self
            .transport
            .send(request)
            .await
            .map_err(|e| AuthError::new(stage, AuthErrorKind::Transport(e)))?;
        if !response.is_success() {
            return Err(AuthError::new(
                stage,
                AuthErrorKind::HttpStatus(response.status()),
            ));
        }
        if response.body().len() > self.limits.max_body {
            return Err(AuthError::new(
                stage,
                AuthErrorKind::Malformed(Malformed::new(
                    "body",
                    MalformedReason::TooLong {
                        limit: self.limits.max_body,
                    },
                )),
            ));
        }
        Ok(response)
    }
}

/// Which pair of stages an SRP exchange reports.
#[derive(Clone, Copy)]
struct SrpStages {
    init: AuthStage,
    complete: AuthStage,
}

const INITIAL_STAGES: SrpStages = SrpStages {
    init: AuthStage::SrpInit,
    complete: AuthStage::SrpComplete,
};

const REAUTH_STAGES: SrpStages = SrpStages {
    init: AuthStage::ReauthSrpInit,
    complete: AuthStage::ReauthSrpComplete,
};

/// Runs the two-round SRP password exchange.
///
/// Returns the decrypted server-provided data and the `au` value, if any,
/// from the `complete` response.  Exactly two requests are sent; a failure
/// at any point aborts without retrying.
async fn run_srp<T: Transport, A: AnisetteProvider, E: Entropy>(
    auth: &Authenticator<T, A, E>,
    account: &AccountName,
    password: Password,
    stages: SrpStages,
) -> Result<(ServerProvidedData, Option<String>), AuthError> {
    let limits = &auth.limits;
    let at_init = |kind| AuthError::new(stages.init, kind);
    let at_complete = |kind| AuthError::new(stages.complete, kind);

    // Round 1: send A, receive salt, B, iteration count, and cookie.
    let anisette = auth.fresh_anisette(stages.init).await?;
    let ephemeral =
        ClientEphemeral::generate(&auth.entropy).map_err(|e| at_init(AuthErrorKind::Entropy(e)))?;
    let request =
        gsa::init_request(&anisette, account, ephemeral.public(), limits).map_err(at_init)?;
    let response = auth.exchange(stages.init, request).await?;
    let root = gsa::parse_body(response.body(), limits)
        .map_err(|m| at_init(AuthErrorKind::Malformed(m)))?;
    let section = gsa::response_section(&root).map_err(|m| at_init(AuthErrorKind::Malformed(m)))?;
    let status =
        gsa::parse_status(section, limits).map_err(|m| at_init(AuthErrorKind::Malformed(m)))?;
    status
        .into_result()
        .map_err(|s| at_init(AuthErrorKind::Protocol(s)))?;
    let init =
        gsa::parse_init(section, limits).map_err(|m| at_init(AuthErrorKind::Malformed(m)))?;
    if let Some(protocol) = init.protocol
        && protocol != SUPPORTED_PROTOCOL
    {
        return Err(at_init(AuthErrorKind::UnsupportedProtocol {
            protocol: ServerSelector::new(protocol),
        }));
    }

    // Derive the password key, then let the password go.
    let password_key = derive_password_key(&password, &init.salt, init.iterations);
    drop(password);
    let proof = Proof::compute(&ephemeral, account, &password_key, &init.salt, &init.b_pub)
        .map_err(|m| at_init(AuthErrorKind::Malformed(m)))?;
    drop(password_key);
    drop(ephemeral);

    // Round 2: send M1, receive M2 and the encrypted server-provided data.
    let request = gsa::complete_request(&anisette, account, proof.m1(), &init.cookie, limits)
        .map_err(at_complete)?;
    let response = auth.exchange(stages.complete, request).await?;
    let root = gsa::parse_body(response.body(), limits)
        .map_err(|m| at_complete(AuthErrorKind::Malformed(m)))?;
    let section =
        gsa::response_section(&root).map_err(|m| at_complete(AuthErrorKind::Malformed(m)))?;
    let status =
        gsa::parse_status(section, limits).map_err(|m| at_complete(AuthErrorKind::Malformed(m)))?;
    let secondary_auth = status
        .into_result()
        .map_err(|s| at_complete(AuthErrorKind::Protocol(s)))?;
    let complete = gsa::parse_complete(section, limits)
        .map_err(|m| at_complete(AuthErrorKind::Malformed(m)))?;
    let session_key = proof
        .verify_server(&complete.m2)
        .ok_or_else(|| at_complete(AuthErrorKind::ServerProofMismatch))?;
    let plaintext = spd::decrypt(&session_key, &complete.encrypted_data)
        .map_err(|m| at_complete(AuthErrorKind::Malformed(m)))?;
    drop(session_key);
    let data =
        spd::parse(&plaintext, limits).map_err(|m| at_complete(AuthErrorKind::Malformed(m)))?;
    Ok((data, secondary_auth))
}

/// A password login that has not been sent yet.
///
/// Created by [`Authenticator::login`].  Holds the [`Password`] until
/// [`PasswordLogin::authenticate`] consumes it.
pub struct PasswordLogin<'a, T, A, E> {
    auth: &'a Authenticator<T, A, E>,
    account: AccountName,
    password: Password,
}

impl<'a, T: Transport, A: AnisetteProvider, E: Entropy> PasswordLogin<'a, T, A, E> {
    /// Runs the initial SRP password exchange.
    ///
    /// Sends the `init` and `complete` requests and, on success, returns
    /// either an authenticated [`Session`], a request for a trusted-device
    /// second factor, or an unsupported step.  The password is dropped
    /// before this method returns in every case.
    ///
    /// # Errors
    ///
    /// Any failure is reported at [`AuthStage::SrpInit`] or
    /// [`AuthStage::SrpComplete`].  A wrong password normally surfaces as a
    /// protocol error from the server or as
    /// [`AuthErrorKind::ServerProofMismatch`].  Apple rate-limits password
    /// attempts, so the caller must not retry without a new user action.
    pub async fn authenticate(self) -> Result<LoginOutcome<'a, T, A, E>, AuthError> {
        let Self {
            auth,
            account,
            password,
        } = self;
        let (data, secondary_auth) = run_srp(auth, &account, password, INITIAL_STAGES).await?;
        match secondary_auth {
            None => Ok(LoginOutcome::Authenticated(Session::new(account, data))),
            Some(step) if step == gsa::TRUSTED_DEVICE_AU => {
                let ServerProvidedData {
                    account_id,
                    idms_token,
                    ..
                } = data;
                Ok(LoginOutcome::SecondFactorRequired(SecondFactorRequired {
                    auth,
                    account,
                    account_id,
                    idms_token,
                }))
            }
            Some(step) => Ok(LoginOutcome::Unsupported(UnsupportedStep {
                step: ServerSelector::new(step),
            })),
        }
    }
}

impl<T, A, E> fmt::Debug for PasswordLogin<'_, T, A, E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PasswordLogin")
    }
}

/// Result of a successful password exchange.
#[non_exhaustive]
pub enum LoginOutcome<'a, T, A, E> {
    /// The account needs no second factor; the session is ready.
    Authenticated(Session),
    /// The account requires trusted-device two-factor authentication.
    SecondFactorRequired(SecondFactorRequired<'a, T, A, E>),
    /// The password was accepted but the account requires a step this crate
    /// does not implement, such as SMS verification.
    Unsupported(UnsupportedStep),
}

impl<T, A, E> fmt::Debug for LoginOutcome<'_, T, A, E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Authenticated(_) => f.write_str("LoginOutcome::Authenticated"),
            Self::SecondFactorRequired(_) => f.write_str("LoginOutcome::SecondFactorRequired"),
            Self::Unsupported(step) => f
                .debug_tuple("LoginOutcome::Unsupported")
                .field(step)
                .finish(),
        }
    }
}

/// A secondary-authentication step this crate cannot perform.
///
/// The password exchange succeeded, but the server asked for something other
/// than trusted-device verification.  Nothing further is sent; the user has
/// to resolve the requirement elsewhere.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnsupportedStep {
    step: ServerSelector,
}

impl UnsupportedStep {
    /// Returns the server's `au` value, a bounded server-controlled string.
    ///
    /// `Debug` on this type prints the value only when it is a plain token;
    /// see [`ServerSelector`].
    #[must_use]
    pub fn step(&self) -> &ServerSelector {
        &self.step
    }
}

/// The account requires a trusted-device verification code.
///
/// Holds only what the two-factor endpoints need: the account identifier and
/// the IdMS token.  The session key and service tokens from the pre-2FA
/// exchange are discarded because they are not usable until the second
/// factor is complete.
pub struct SecondFactorRequired<'a, T, A, E> {
    auth: &'a Authenticator<T, A, E>,
    account: AccountName,
    account_id: AccountId,
    idms_token: IdmsToken,
}

impl<'a, T: Transport, A: AnisetteProvider, E: Entropy> SecondFactorRequired<'a, T, A, E> {
    /// Returns the account identifier.
    #[must_use]
    pub fn account_id(&self) -> &AccountId {
        &self.account_id
    }

    /// Asks Apple to push a verification code to the user's trusted devices.
    ///
    /// This sends one request.  It is a user-visible action on every trusted
    /// device, so call it only in direct response to the user choosing to
    /// proceed.  Success is judged by the HTTP status alone; the response
    /// body carries no information this crate interprets.
    ///
    /// # Errors
    ///
    /// Reported at [`AuthStage::TrustedDevicePush`].
    pub async fn request_trusted_device_code(
        self,
    ) -> Result<CodeRequested<'a, T, A, E>, AuthError> {
        let stage = AuthStage::TrustedDevicePush;
        let Self {
            auth,
            account,
            account_id,
            idms_token,
        } = self;
        let anisette = auth.fresh_anisette(stage).await?;
        let identity = gsa::identity_token(&account_id, &idms_token);
        let request = gsa::trusted_device_request(&anisette, &identity, &auth.limits);
        auth.exchange(stage, request).await?;
        Ok(CodeRequested {
            auth,
            account,
            account_id,
            idms_token,
        })
    }
}

impl<T, A, E> fmt::Debug for SecondFactorRequired<'_, T, A, E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecondFactorRequired")
    }
}

/// A verification code has been pushed and can be submitted once.
pub struct CodeRequested<'a, T, A, E> {
    auth: &'a Authenticator<T, A, E>,
    account: AccountName,
    account_id: AccountId,
    idms_token: IdmsToken,
}

impl<'a, T: Transport, A: AnisetteProvider, E: Entropy> CodeRequested<'a, T, A, E> {
    /// Returns the account identifier.
    #[must_use]
    pub fn account_id(&self) -> &AccountId {
        &self.account_id
    }

    /// Submits the verification code the user entered.
    ///
    /// Sends one request.  A rejected code consumes this stage: Apple may
    /// count wrong codes against the account, so the caller must start a new
    /// login rather than resubmit.  Acceptance is judged by the server's
    /// `ec` status, not by the HTTP status alone.
    ///
    /// The code is placed in the `security-code` request header; the
    /// [`Request`] handed to the transport is therefore secret-bearing.
    ///
    /// # Errors
    ///
    /// Reported at [`AuthStage::CodeValidation`].  A wrong or expired code
    /// arrives as [`AuthErrorKind::Protocol`] with the server's code and
    /// message; this crate does not assign meanings to specific codes.
    pub async fn submit_code(
        self,
        code: VerificationCode,
    ) -> Result<SecondFactorVerified<'a, T, A, E>, AuthError> {
        let stage = AuthStage::CodeValidation;
        let Self {
            auth,
            account,
            account_id,
            idms_token,
        } = self;
        let anisette = auth.fresh_anisette(stage).await?;
        let identity = gsa::identity_token(&account_id, &idms_token);
        let request = gsa::validate_request(&anisette, &identity, &code, &auth.limits);
        drop(code);
        let response = auth.exchange(stage, request).await?;
        let root = gsa::parse_body(response.body(), &auth.limits)
            .map_err(|m| AuthError::new(stage, AuthErrorKind::Malformed(m)))?;
        let status = gsa::parse_status(&root, &auth.limits)
            .map_err(|m| AuthError::new(stage, AuthErrorKind::Malformed(m)))?;
        status
            .into_result()
            .map_err(|s| AuthError::new(stage, AuthErrorKind::Protocol(s)))?;
        Ok(SecondFactorVerified { auth, account })
    }
}

impl<T, A, E> fmt::Debug for CodeRequested<'_, T, A, E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CodeRequested")
    }
}

/// The verification code was accepted; a re-authentication is required.
///
/// Apple issues session material only from a password exchange performed
/// after the second factor is satisfied, so the flow has to run SRP once
/// more.  The pre-2FA tokens were discarded and the password must be
/// supplied again.
pub struct SecondFactorVerified<'a, T, A, E> {
    auth: &'a Authenticator<T, A, E>,
    account: AccountName,
}

impl<T: Transport, A: AnisetteProvider, E: Entropy> SecondFactorVerified<'_, T, A, E> {
    /// Runs the post-two-factor SRP exchange and yields the session.
    ///
    /// Sends two requests.  The password is dropped before this method
    /// returns.
    ///
    /// # Errors
    ///
    /// Reported at [`AuthStage::ReauthSrpInit`] or
    /// [`AuthStage::ReauthSrpComplete`], which is how a caller tells this
    /// failure apart from an initial-login failure.  If the server still
    /// asks for a second factor the error is
    /// [`AuthErrorKind::SecondFactorStillRequired`]; the crate does not loop
    /// back to another code request.
    pub async fn reauthenticate(self, password: Password) -> Result<Session, AuthError> {
        let Self { auth, account } = self;
        let (data, secondary_auth) = run_srp(auth, &account, password, REAUTH_STAGES).await?;
        match secondary_auth {
            None => Ok(Session::new(account, data)),
            Some(step) if step == gsa::TRUSTED_DEVICE_AU => Err(AuthError::new(
                AuthStage::ReauthSrpComplete,
                AuthErrorKind::SecondFactorStillRequired,
            )),
            Some(step) => Err(AuthError::new(
                AuthStage::ReauthSrpComplete,
                AuthErrorKind::UnsupportedStep {
                    step: ServerSelector::new(step),
                },
            )),
        }
    }
}

impl<T, A, E> fmt::Debug for SecondFactorVerified<'_, T, A, E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecondFactorVerified")
    }
}

/// An authenticated GSA session.
///
/// Holds the material later protocol steps need: the account identifier, the
/// IdMS token, the session key, the opaque cookie, and the per-service tokens
/// (including the password-equivalent token).  The secret fields are
/// zeroized on drop.  `Session` does not implement `Clone`, so there is one
/// copy of the session material, and `Debug` prints nothing but the type
/// name.
///
/// Persisting a session is the job of a higher layer, which must use the
/// platform secret store.
pub struct Session {
    account: AccountName,
    account_id: AccountId,
    idms_token: IdmsToken,
    session_key: SessionKey,
    cookie: Zeroizing<Vec<u8>>,
    tokens: BTreeMap<String, ServiceToken>,
    given_name: Option<String>,
    family_name: Option<String>,
}

impl Session {
    fn new(account: AccountName, data: ServerProvidedData) -> Self {
        let ServerProvidedData {
            account_id,
            idms_token,
            session_key,
            cookie,
            tokens,
            given_name,
            family_name,
        } = data;
        Self {
            account,
            account_id,
            idms_token,
            session_key,
            cookie,
            tokens,
            given_name,
            family_name,
        }
    }

    /// Returns the account name the session was established for.
    #[must_use]
    pub fn account(&self) -> &AccountName {
        &self.account
    }

    /// Returns the account identifier (`adsid`).
    #[must_use]
    pub fn account_id(&self) -> &AccountId {
        &self.account_id
    }

    /// Returns the IdMS token.
    #[must_use]
    pub fn idms_token(&self) -> &IdmsToken {
        &self.idms_token
    }

    /// Returns the session key `sk`.
    #[must_use]
    pub fn session_key(&self) -> &SessionKey {
        &self.session_key
    }

    /// Returns the opaque cookie `c` that later requests echo.
    #[must_use]
    pub fn cookie(&self) -> &[u8] {
        &self.cookie
    }

    /// Returns the token issued for `service`, if any.
    #[must_use]
    pub fn service_token(&self, service: &str) -> Option<&ServiceToken> {
        self.tokens.get(service)
    }

    /// Returns the password-equivalent token, if the server issued one.
    #[must_use]
    pub fn password_equivalent_token(&self) -> Option<&ServiceToken> {
        self.service_token(PET_SERVICE)
    }

    /// Returns the identifiers of every service that received a token.
    pub fn service_ids(&self) -> impl Iterator<Item = &str> {
        self.tokens.keys().map(String::as_str)
    }

    /// Returns the account holder's given name, if the server sent it.
    #[must_use]
    pub fn given_name(&self) -> Option<&str> {
        self.given_name.as_deref()
    }

    /// Returns the account holder's family name, if the server sent it.
    #[must_use]
    pub fn family_name(&self) -> Option<&str> {
        self.family_name.as_deref()
    }
}

impl fmt::Debug for Session {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Session(<redacted>)")
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        self.given_name.zeroize();
        self.family_name.zeroize();
    }
}
