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
Neither binary invokes it, and there is no delegate frontend or credential
input path. The adapter's existence is not authorization to execute it live.

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
