coffer-live-auth
================

`coffer-live-auth` is the developer-only harness that runs one live Apple
Account authentication through the Coffer crates. It is an engineering check
for Milestone 1, not part of the Coffer application, and it is deliberately
excluded from `mise run test` and `mise run ci`.

Run it only on a machine and with an account you control:

~~~~ sh
mise run test-live-auth
~~~~

The task builds `coffer-anisette-helper` and the harness in the same graph and
then starts the harness, which locates the helper beside itself.


What one run does
-----------------

1.  Resolves or creates the opaque profile slot under
    *$XDG\_STATE\_HOME/coffer/live-auth/profile-slot* (0700 directory, 0600
    file, symbolic links refused, corrupt state never replaced).
2.  Checks that Secret Service is reachable and unlocked before anything
    else, so a missing keyring never costs an authentication attempt.
3.  Runs the Apple support-library bootstrap, reusing a verified install or
    downloading once from Apple's pinned URL.
4.  Generates local anisette headers. If the machine is not provisioned, it
    asks you to type `provision` and then runs exactly one provisioning
    attempt.
5.  Asks for the account name and the password, both without echo, on
    */dev/tty* and runs the initial SRP exchange once.
6.  If a trusted-device code is required, requests one push, asks for the
    code once, submits it once, asks for the password again, and runs the
    post-2FA exchange once.
7.  Writes the reusable session to Secret Service under the slot, reloads it
    over a new connection, and compares.

Every step runs once. Any failure stops the run with a static, stage-labelled
message. Nothing is retried, no redirect or proxy is followed, and there is no
remote anisette or plaintext fallback anywhere in the graph. Connections to
the fixed `gsa.apple.com` endpoints use Apple's published “Apple Inc. Root” as
their sole trust anchor while retaining certificate and hostname verification;
the Apple CDN bootstrap continues to use the public WebPKI.

The authentication HTTP budget starts at the first validated exchange, after
initial account/password input, and lasts 20 minutes. Each exchange retains
its own timeout. Later 2FA/password prompts consume the remaining total budget;
they do not reset it. A timeout alone does not prove server rejection or even
that the current request reached Apple. No failure triggers another attempt.


Human interaction points
------------------------

In order: possibly the word `provision` (only on an unprovisioned machine,
before any account prompt), the account name, the password, and, only if the
account requires a trusted-device code, the verification code and the password
a second time. Everything is read from the controlling terminal with echo off,
except the one-word provisioning confirmation. The binary refuses to start if
it is given any argument, and nothing it prints contains an account, token,
code, header, body, slot, or path.

If a hidden prompt is interrupted with Ctrl-C, the terminal mode is restored
and the run stops once the line ends; a `SIGTERM` or `SIGHUP` that arrives
during a hidden prompt is likewise deferred until the mode is restored and
then takes its default effect.


What the success report means
-----------------------------

The report lists static verdicts: local anisette, the initial SRP exchange,
whether the trusted-device and post-2FA branches ran, the Secret Service store
and reload, and the absence of a remote fallback. The two-factor lines are
marked verified only if the account actually required a code during the run.
The M1 Secret Service line means persistence and reload only. This binary
does not exercise the separate stored-session token path.


Stored-session Xcode token check
--------------------------------

`coffer-live-token` is a separate developer-only binary. Build it and its
helper without running either:

~~~~ sh
mise run build-live-token
~~~~

After independent review, full CI, and separate approval for one live token
issuance, the interactive entry point is:

~~~~ sh
mise run test-live-token
~~~~

This operation may consume an authentication attempt. Its effect on previously
issued tokens is unknown. It is excluded from ordinary tests and CI, takes no
arguments, and reads only the word `ISSUE` from the controlling terminal.

The binary loads the existing profile slot and GSA session over a fresh Secret
Service connection. It checks existing support libraries with
`Bootstrap::installed` and opens existing provisioning with
`CofferAnisetteProvider::open_existing`. Missing/corrupt/incompatible state
stops the run before an Apple request; no slot, identifier, or initial
provisioning state is created. Normal OTP generation can stage and publish
updates to existing local anisette state.

One explicit `Service::XcodeAuthentication` request follows confirmation.
There are no passwords, 2FA, downloads, provisioning, keyring writes/deletes,
service iteration, or automatic retries. HTTP/session rejection or an expired
issued token ends the run and preserves the stored session. Successful output
states only that one authenticated, unexpired Xcode token was obtained; the
token is immediately dropped and never printed or stored.

The initial decoder supports strict XML plaintext only. Binary plist is
explicitly unsupported. Offline vectors do not establish current Apple
compatibility, GSA session lifetime, CloudKit access, or token rotation rules.
See [the protocol scope](../../crates/coffer-protocol/SERVICE_TOKENS.md).


Delegate transport: offline implementation
------------------------------------------

The library's `delegate_transport::DelegateTransport` is a separate HTTPS
adapter for legacy MobileMe delegate token issuance. It is covered by synthetic
exchange/reader tests and production agent configuration assertions only.
The separate developer-only `coffer-live-delegate` frontend described below
composes it with explicit login and local persistence. The implementation
is not authorization to execute it live.

Its local allowlist accepts only `POST` to
`https://setup.icloud.com/setup/iosbuddy/loginDelegates`, with a nonempty body
of at most 64 KiB and exactly one `Content-Type: text/xml`. This media type and
these limits define the initial Coffer subset; they do not establish Apple's
server specification. The caller's response bound must be 1–128 KiB. At most
32 caller headers and 32 KiB of header names/values plus `: ` and CRLF are
accepted. Header names use ASCII letters/digits/hyphen/underscore, values use
printable ASCII, and all duplicate names are rejected case-insensitively.
Routing, framing, compression and challenge-control headers are refused.

TLS explicitly uses rustls and WebPKI roots with SNI, certificate and hostname
verification enabled. GSA retains its separate Apple Root policy and unchanged
three-URL allowlist. Redirects, proxies, challenge responses, connection pooling
and optional automatic headers are disabled. The current locked ureq feature
graph has no cookies or decompression; ureq supplies required Host and
Content-Length framing from the validated URL/body. Each send makes at most
one exchange with no retry and enforces both per-exchange and overall deadlines.
Calling the production exchange directly still enforces the same request bounds
and a positive, representable timeout.

The response reader allocates one bounded zeroizing buffer and rejects oversized
or late results. HTTP 401 returns once without obtaining a body reader or
answering a challenge; redirects and proxy challenges fail without reading
bodies. HTTP 200 content remains opaque for the protocol API to interpret.
Errors use fixed descriptions and never include header/body/library error text.
Coffer-owned request values and response bodies are zeroized; zeroization of
ureq/rustls-owned buffers is not guaranteed.

No Apple endpoint, other live endpoint, account, Secret Service item, or
proprietary support library was accessed to validate this adapter. Server
acceptance of the request profile, identifier binding, token lifetime/rotation,
and registration/consent effects remain unknown. A timeout after transmission
leaves issuance unknown. Integration, independent review and a separate explicit
live plan are still required before any live attempt.


Fresh-login delegate harness: offline implementation
----------------------------------------------------

`coffer-live-delegate` implements an explicit fresh GSA login, at most one
legacy delegate issuance, and separate GSA/delegate Secret Service round trips.
It has been developed with synthetic data. Live Apple acceptance, client
binding, token lifetime/reuse/rotation, registration, consent, and security
notification effects remain unverified. This is authentication/token issuance
and may affect account protection or server state. There is no CloudKit
initialization, trust join, recovery, keychain mutation, credential cache, or
daemon.

Build the harness and local anisette helper without running either:

~~~~ sh
mise run build-live-delegate
~~~~

The opt-in `test-live-delegate` task is excluded from normal tests and CI.
Do not execute it until the coordinator's independent code-review-loop and
integrated CI have passed and the user has authorized the concrete one-run
plan, including the unknown server effects. An implementation report does not
provide that authorization.

### Existing-state preflight

The harness calls only `SlotState::load` and `SessionStore::load` for its
initial state. A missing, locked, duplicate, corrupt, or unsupported GSA item
stops the run before password input or an Apple request. It reuses the token
harness's `Bootstrap::installed`/`CofferAnisetteProvider::open_existing`
preparation; there is no download, provisioning, new UUID, reset, or alternate
profile. Normal local anisette generation may update existing local
provisioning state.

One validated local anisette result supplies the existing `device_id`. Coffer
explicitly selects and retains that exact value as the delegate `client-id`;
this policy does not prove Apple's binding requirements. The stored GSA ADSID
and that client ID bind the delegate preflight. An existing validly decoded,
bound item returns `AlreadyStored`, with no confirmation, password, fresh
login, issuance, or local write. This result proves only local presence, not
current validity or live reuse. Locked, duplicate, corrupt, unknown-version,
or mismatched delegate records stop the run without changing them.

### Confirmation and request counts

Only a missing delegate item reaches the visible confirmation. The fixed
notice explains fresh authentication, one delegate attempt, two separate local
writes, and unknown token-rotation/registration/consent effects. The user must
type exactly `LOGIN AND ISSUE`. Declining or interrupting that prompt causes
zero hidden prompts and zero Apple requests.

After confirmation, the existing `run_login` flow reads the account and password
from the controlling terminal with echo disabled. Initial SRP uses at most two
GSA exchanges. If trusted-device 2FA is required, there is one code push, one
code submission, and at most two post-2FA SRP exchanges; the code and second
password are also hidden terminal inputs. Thus a successful flow uses two GSA
requests without 2FA or six with it, plus one delegate request. A failure stops
at the current stage, without repeating login, a code, issuance, a store
operation, an endpoint, or a record.

The fresh ADSID must equal the stored ADSID. A mismatch stops before either
local write or delegate issuance and preserves existing items. The fresh
session must contain a usable password-equivalent token (PET); no IdMS/Xcode
substitution is possible. Missing PET stops before delegate transport creation
and before either write. The fresh GSA reusable subset is then written and
reloaded through the existing `persist_and_reload`; failure prevents issuance.

GSA's 20-minute total deadline starts at its first exchange, with a 60-second
per-exchange limit. Later 2FA/password input uses the remaining budget. The
separate delegate transport is constructed only after login, GSA persistence,
and the final issuance notice. Its 300-second total and 60-second exchange
limits therefore exclude earlier human input and store waits.

Successful issuance is converted with
`StoredDelegateCredentials::from_issued` and written once to the separate
delegate item. A new connector connection reloads it; ADSID, client ID, DSID,
MME token, and CloudKit token must all compare equal. The successful path uses
five Secret Service connections: initial preflight, GSA writer, GSA reader,
delegate writer, and delegate reader. It performs two explicit item-write
operations, with no rollback or delete. Backend availability/search/read calls
are implementation details of those bounded operations; there is no keyring
or network retry loop. Serialize invocations for the same slot; concurrent
writers are not a supported transaction model.

### Partial failures and retained material

| Failure point                                                                                       | Local state after stopping                                                                                                    |
| --------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------- |
| Preflight, confirmation, login, ADSID mismatch, or missing PET                                      | Neither GSA nor delegate item is written by this run. A completed or interrupted login may already have server effects.       |
| GSA write/reload                                                                                    | GSA storage may have changed. Delegate issuance/storage has not started.                                                      |
| Delegate input conversion after issuance, issuance failure, or interruption before delegate storage | Fresh GSA material remains stored. Delegate issuance may have occurred; no delegate item was written by this run.             |
| Delegate write, fresh connection, or reload/equality failure                                        | Fresh GSA material remains stored. Delegate storage may have changed, including when a write reports timeout or cancellation. |
| Success                                                                                             | Both separately stored subsets round-tripped; this does not establish CloudKit access, expiry, or future reuse.               |

The two writes are not an atomic transaction. Errors and interruptions trigger
no cleanup, rollback, repair, fallback, or retry. In-memory owners are dropped
and zeroized; the stored GSA subset omits account name and PET, while the
separate delegate envelope holds the explicit binding and issued tokens.
Diagnostics contain only fixed stage/cause/retention labels, never raw sources,
account/client identifiers, PETs, tokens, keys, or response bodies.

### Safe terminal handoff

After review and a separate one-run authorization, the human takes over the
existing controlling TTY for the visible confirmation and hidden account,
password, optional code, and optional second password. The binary refuses every
argument before opening the terminal. Credentials must not be supplied through
arguments, environment, standard input, files, chat, or an agent/secret-manager
command. Do not capture or replay terminal input. The existing terminal adapter
restores hidden-input mode on its supported interruption paths; an interruption
ends this run and requires a new human decision before another attempt.
