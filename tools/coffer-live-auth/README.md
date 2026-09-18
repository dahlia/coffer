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

### Safe terminal handoff for the original binary

After review and a separate one-run authorization, the human takes over the
existing controlling TTY for the visible confirmation and hidden account,
password, optional code, and optional second password. The binary refuses every
argument before opening the terminal. In this TTY-only binary, credentials must
not be supplied through arguments, environment, standard input, files, chat, or
an agent/secret-manager command. Do not capture or replay terminal input. The
existing terminal adapter restores hidden-input mode on its supported
interruption paths; an interruption ends this run and requires a new human
decision before another attempt.


1Password delegate input: offline implementation
------------------------------------------------

`coffer-live-delegate-op` is a separate developer-only entry point for the
explicitly authorized 1Password handoff. It passes `OpTerminal` to the existing
`delegate_harness::run`. The original `coffer-live-delegate` remains TTY-only;
the new entry point changes only account and password input. Preflight, the
exact `LOGIN AND ISSUE` confirmation on the controlling TTY, stored GSA ADSID
matching, request counts, local writes, and partial-failure behavior remain
owned by the existing harness.

Build it and the anisette helper without executing either:

~~~~ sh
mise run build-live-delegate-op
~~~~

Independent review and integrated CI must pass before a live handoff. This
implementation and its synthetic tests do not establish compatibility with
actual 1Password field output or authorize an Apple attempt.

### Selector and credential channels

The binary rejects every argument. Its inherited stdin must be an anonymous
pipe containing exactly this frame: a 26-character item selector (lowercase
ASCII letters/digits), LF, the expected account (1 to 256 UTF-8 bytes, without
Unicode control characters), LF, then EOF. Both LFs and EOF are mandatory.
The launcher must independently extract the expected account from the same
user approval that selected the item, pass both values privately, and close
the writer. It must never derive the expected account from fetched fields.

The binary checks Linux descriptor metadata and the kernel's */proc/self/fd*
link to reject regular files, named FIFOs, sockets, and terminals. Input is
nonblocking, has a five-second deadline, and reads at most 285 bytes: a
284-byte frame plus one overflow probe. Invalid sources, framing, nonblocking
setup, read failures, timeouts, and oversized input all report the fixed
selector error before a credential fetch. The selector and expected account
remain in a zeroizing owner until the fetch; neither is printed or passed
through arguments, environment, or a temporary file. The stdin exception
accepts only this selector/account frame, never a password.

No credential fetch occurs during construction, local preflight, or visible
confirmation. Only the first account prompt after confirmation, with the exact
label listed below, starts a single child process with this fixed argument
vector:

~~~~ text
/usr/bin/op item get - --fields label=username,label=password --reveal --debug=false --cache=false --format human-readable --no-color
~~~~

Only the selector and one LF go to the child's stdin pipe, which is then
closed. The expected account stays in the wrapper. Child stdout has a separate
bounded pipe; stderr has its own private bounded pipe. GUI integration
environment is inherited without reading its values or creating secret
variables. Explicit flags pin formatting, color, cache, and debug behavior.
UTF-8 is the CLI default; do not pass `--encoding UTF-8`. Installed CLI 2.39.0
rejects that explicit value even for the account-free `op completion bash`
command. The adapter never starts a sign-in, fallback, or second fetch. A fixed
notice explains that unlock or approval may require human interaction in the
1Password application; a failure returns control.

The [1Password item-command documentation] describes combined `username` and
`password` selection as CSV. The adapter accepts exactly one row containing
exactly two fields, including quoted commas and doubled quotes. It removes at
most one terminal LF, preserves other whitespace, and rejects extra rows or
fields, malformed quoting, empty values, invalid UTF-8, and Unicode control
characters. Each decoded field is limited to the existing 1,024-byte terminal
input bound. The encoded output limit is 4,102 bytes; the reader consumes at
most 4,103 bytes including the overflow probe. Unsupported output fails before
any Apple login. The adapter does not rely on output field order being
guaranteed: the decoded first field must byte-exactly match the independently
approved expected account. A mismatch, including swapped fields, produces a
fixed error before returning any account or password to the login flow, with
one fetch, zero Apple authentication calls, and no fallback or retry. It does
not trim, case-fold, or normalize either account value.

A 120-second budget covers child output and exit, starting before spawn. The
pipes are nonblocking, with deadline checks between reads and waits. Each loop
reads stdout and stderr once so either writer can progress. Stderr is capped
at 16 KiB plus one overflow probe; exceeding either pipe limit stops the child,
even if its exit status would be successful. Both EOFs and a successful exit
are required before stdout can be accepted. The child
owner kills and reaps the direct child on failure, including timeout or excess
output. Valid bytes are accepted only after a successful exit. Errors retain
only fixed categories, OS exit-code/signal metadata, and the allowlisted stderr
hints described below. They contain no child output, arbitrary source error, or
identifying data. Stderr is zeroized on every path, including success;
successful stderr never supplies a hint. Normal process scheduling and kernel
termination/reaping still apply; this is not a sandbox for a compromised CLI or
its descendants.

[1Password item-command documentation]: https://www.1password.dev/cli/reference/management-commands/item

### Prompt order and memory lifetime

The wrapper accepts these exact hidden prompt labels in order:

1.  `Apple Account (e-mail address or phone number, not echoed): `
2.  `Password (not echoed): `
3.  `Verification code (6 digits, not echoed): `, only if 2FA is required.
4.  `Password again, for post-2FA re-authentication (not echoed): `, only after
    the code prompt.

Both fields must decode and the username must match the expected account
before the account is returned.
The account moves to the existing login flow. One zeroizing password copy is
returned for initial authentication; the wrapper keeps the original only for
the optional post-2FA exchange. OTP always goes through the wrapped terminal's
`prompt_hidden`, with its existing echo and interruption handling. For post-2FA
re-authentication, the wrapper transfers ownership of the retained password to
the login flow without running `op` again. On the no-2FA branch, the first
session-persistence notice wipes the retained password; the entry point also
clears all retained input immediately after the harness returns. Any unknown,
repeated, or out-of-order prompt permanently disables credential input and
wipes the retained values. The wrapper replaces the two existing notices about
typed input and discarded passwords with fixed text that accurately describes
this adapter's input and retention.

All Coffer-owned selector, expected-account, encoded-output, decoded-field, and
password buffers
use zeroizing owners. Encoded and decoded byte buffers are allocated to their
bounds before reading and never grow while holding input. The CLI's own
allocations, kernel pipe buffers, and abrupt process termination are outside
this zeroization guarantee. No temporary credential file is created.

Tests use synthetic CSV, scripted terminal/login steps, and local fake child
processes only. They cover selection through stdin and EOF, argument/environment
configuration, stdout bounds, nonzero exit, timeout/kill/reap, static failures,
confirmation gating, exact account binding and swapped-field rejection before
authentication, prompt rejection, OTP routing, and password reuse. A source
assertion links the no-2FA wipe test to the real persistence notice and verifies
that it precedes store connection and replacement. The
worker did not invoke `op`, read an account or item, access Secret Service, load
proprietary libraries, provision local state, or contact Apple.


1Password first login into a new profile: offline implementation
----------------------------------------------------------------

`coffer-live-login-op` is a separate developer-only entry point for the first
GSA login.
It reuses the bounded anonymous-pipe selector/expected-account frame, CSV
validation, account binding, child cancellation and zeroizing password owners
of `coffer-live-delegate-op`. It does not issue delegate or service tokens or
make trust, escrow, CloudKit or CKKS requests. This implementation and its
synthetic tests do not authorize a live run.

The new binary requires exactly `--new-profile <label>`. This is a narrow
exception to the other binaries' no-arguments rule: the label is non-secret
local metadata, 1–32 lowercase ASCII letters, digits or hyphens. Use an opaque
development label, never an account name, item selector or credential. No other
argument or credential input channel is accepted. The approved item selector
and independently approved expected account still arrive only through the
existing bounded anonymous stdin pipe; the password never passes through argv,
environment, files or the launcher. The controlling TTY supplies confirmation
and, when needed, the trusted-device code.

### Reservation and preflight

After validating the arguments and selector frame, the harness exclusively
creates *$XDG\_STATE\_HOME/coffer/live-auth/profiles/<label>/* with mode 0700.
It publishes a single random *profile-slot* file with mode 0600 using the
existing descriptor-relative slot writer. Coffer-owned directories reject
symlinks and wrong modes. An existing selected profile directory, even empty,
corrupt or containing a valid slot, stops the run before a credential fetch or
Apple authentication. A concurrent invocation cannot adopt the winner's slot.
The default *coffer/live-auth/profile-slot* is never selected or replaced.

The harness reserves the profile before Secret Service and local anisette
preflight and before confirmation. Consequently a preflight failure, decline,
interruption or login failure can leave the reservation behind; it is
deliberately not removed. An error while publishing the slot can leave an empty
reserved directory. Re-running with that label fails closed. No failure picks
another label, generates a replacement slot or retries authentication
automatically. A further attempt requires an explicit human decision and a
separate new profile.

The selected random slot must have no Secret Service session. Unavailable,
locked, duplicate, corrupt, unsupported or occupied records stop before
credential input/authentication. Only installed support libraries and existing
anisette provisioning are opened, through `Bootstrap::installed` and
`CofferAnisetteProvider::open_existing`. The process does not change
`XDG_STATE_HOME`, download libraries or provision another device. It generates
and discards one set of anisette headers before confirmation or credential
fetch: opening the identity alone does not validate active provisioning or its
library binding. This local preflight can update existing provisioning state,
but performs no network request and never falls back to provisioning.

### Confirmation, authentication and storage

After successful preflight, the user must enter exactly `LOGIN AND STORE` at
the controlling TTY.
Declining or interrupting it fetches no credentials and sends no Apple request,
but retains the local reservation described above. The `LOGIN AND ISSUE`
confirmation remains exclusive to the delegate entry point.

After confirmation, one credential fetch must match the independently approved
account byte for byte before `run_login` receives either field. Initial GSA
uses at most two requests. Trusted-device 2FA adds one code push, one code
submission and at most two post-2FA GSA requests, for a maximum of six. The
password is reused once from zeroizing memory for post-2FA authentication;
1Password is not called a second time. The existing GSA limits remain 60 seconds
per exchange and 20 minutes from the first exchange, including later human
input. Each failure stops at its stage, with zero automatic retries.

`persist_and_reload` writes the reusable GSA subset once and compares all
retained fields after loading through a new Secret Service connection. A wrapper
rechecks that the slot is still empty immediately before its one `replace` call.
The retained password is wiped at the existing persistence notice, before the
writer connects. Three connections are used on success: preflight, writer and
reader. No account name or password-equivalent token (PET) is persisted by this
path. Existing profiles and their sessions remain unchanged.

Secret Service's current `SessionStore` interface has no atomic
create-if-absent operation. Exclusive profile reservation and a final empty-slot
check prevent accidental reuse by this entry point; an external process running
as the same user can still race the check and write. Do not concurrently modify
the reserved slot. A write/reload failure leaves storage potentially changed,
with no rollback, deletion or retry. Successful reload proves local persistence,
not token validity, future session reuse or CloudKit access.

Build the harness and its helper without running either binary:

~~~~ sh
mise run build-live-login-op
~~~~

This task builds `coffer-anisette-helper` and `coffer-live-login-op` together
with `--locked`. Live execution is excluded from normal tests and CI.
Selecting this new profile from the existing token/delegate tools is separate
future work; those tools continue to select the default profile.

Offline tests cover preflight before credential fetch, wrong-account rejection,
decline/cancellation, each authentication failure without retry, both 2FA
branches, original-profile preservation, concurrent reservation, invalid paths
and modes, last-moment session occupancy, and reload over a new connection.
They use only synthetic input, fake login steps and an in-memory store.


1Password diagnostic only: offline implementation
-------------------------------------------------

`coffer-op-diagnose` performs one separately confirmed 1Password fetch,
validates CSV and the independently approved account binding, then immediately
drops and zeroizes the selector, account, password and encoded output before
reporting. It takes no arguments and reuses the existing anonymous stdin
selector/account frame. It opens the controlling TTY and requires exactly
`DIAGNOSE OP` before fetching. Decline or terminal failure fetches nothing. No
diagnostic result contains credentials; success means only that this fetch
passed local validation.

The entry point calls only the terminal and `op_input::diagnose` APIs. It never
opens a Coffer profile, connects to Secret Service, loads anisette or Apple
libraries, or creates an Apple transport. There is no login, token request,
local storage operation or retry. Its crate shares dependencies with the live
harnesses, but the diagnostic call path does not invoke those adapters. The
1Password CLI itself can contact its application/services and can require human
approval; this is a credential access operation, not an offline command. The
implementation and fake-process tests do not authorize executing it. A live run
requires separate approval and the exact TTY confirmation.

Build the binary without executing the lookup:

~~~~ sh
mise run build-op-diagnose
~~~~

Build/test/CI never invoke the live diagnostic lookup. No
existing launcher binding, account, item, transcript, or real credential was
read during implementation.

### Fixed failure metadata and provenance

A nonzero exit now reports that the process failed and the cause is not
established. It does not presume that 1Password is locked. The standalone
report includes an OS exit code or terminating signal, without interpreting
numeric values as 1Password error codes. Timeouts, interruptions, pipe errors,
size limits, malformed CSV and account mismatch remain separate fixed errors.

The first three stderr markers are `LostConnectionToApp`, `connectionreset`
and `No accounts configured for use with 1Password CLI`. These names/words come
from the troubleshooting section of the
[official app-integration documentation], checked on 18 September 2026.

One additional marker, `isn't a field in` with an ASCII apostrophe, maps to
`FieldLookupText`. This marker comes from a [direct CLI 2.30 user report] dated
31 October 2024 and checked on 18 September 2026. It is not an official error
contract. A separate offline check found that substring in the installed
*/usr/bin/op* 2.39.0 binary. The string's presence does not prove that this
version emits it on a particular code path or establish an exit code or failure
cause. The hint returns no field, item or account value.

Matching is case-sensitive and requires word boundaries around the whole
marker/phrase. Only one distinct marker produces a fixed `OpStderrHint`; empty,
invalid UTF-8, unrecognized or ambiguous stderr returns `Unknown`. No other
text is emitted or retained in an error. A marker can appear in unrelated text
or a private value, so every label explicitly says it is a hint and that the
cause is not established. Hints never select a follow-up action or retry. This
allowlist does not claim that every CLI version emits these strings or that
every occurrence is an error of the same cause.

The tests construct synthetic marker envelopes and local fake processes. They
are not upstream message fixtures, captured 1Password output, or evidence of
live compatibility. Tests cover simultaneous pipe progress, a full stderr pipe
before stdout, independent limits and overflow probes, unknown and ambiguous
hints, exit/signal metadata, successful stderr privacy, timeouts and child
reaping, parent-only cancellation, separate confirmation, CSV/account rejection,
and the diagnostic entry point's restricted composition. The previous discarded
stderr cannot be recovered or used to diagnose the earlier failure. Its cause
remains unconfirmed; this additional hint does not establish it.

Coffer-owned buffers are zeroized when their Rust owners are dropped on
ordinary return. Signal termination does not unwind Rust stacks and can skip
destructors, so it does not guarantee a wipe of every live buffer, including
the selector/account frame or a pending stdout result. Kernel pipes,
allocations in the CLI, other abrupt termination, and a compromised CLI or its
descendants are also outside this guarantee. Raw stderr is never printed,
logged, placed in `Debug` or errors, or written to a diagnostic file.

[official app-integration documentation]: https://www.1password.dev/cli/app-integration
[direct CLI 2.30 user report]: https://www.1password.community/developers-69/how-can-i-covert-op-get-items-command-to-op-item-get-1512


Disposable-account file input: offline implementation
-----------------------------------------------------

`coffer-live-login-file` is a separate developer-only exception for an
explicitly approved disposable account. It requires both
`--credentials-file PATH` and `--new-profile LABEL`, in either order. Both
selectors must be non-secret; do not put an account identifier in the filename
or profile label. No credential value is accepted through arguments,
environment variables, stdin, shell sourcing, or 1Password. The ordinary auth,
token, delegate and 1Password entry points retain their existing input
contracts and default profile selection.

Keep this temporary plaintext file outside the repository, owned by the current
user with exactly mode `0600`. It contains precisely two UTF-8 records, `EMAIL=`
and `PASSWORD=`, separated by LF, with an optional final LF. Record order does
not matter. CRLF and all control characters in values are rejected. Values are
nonempty and at most 1024 bytes each; the whole file is at most 2065 bytes.
Unknown, missing or duplicate keys and blank lines are rejected. Only the first
`=` separates a key and value. Values are literal: spaces, additional equals
signs, quotes, backslashes, dollar signs and hash signs are preserved byte for
byte. Do not wrap values in quotes, since the quote characters would become
part of the credential. There is no trimming, interpolation, comment syntax,
shell execution, or dotenv parsing.

Build the binary and its existing-state helper without running either:

~~~~ sh
mise run build-live-login-file
~~~~

Execution requires separate live authorization and a controlling TTY. The
binary reuses `first_login::run`: it reserves a new profile, checks Secret
Service and existing local anisette, and requires exactly `LOGIN AND STORE`
before opening the file. Declining reads no credential file and sends no Apple
request; the profile reservation can remain. The file adapter validates both
fields before returning either to the existing login flow. Invalid input stops
before an Apple request, without falling back to another input source.

Path components are opened relative to held directory descriptors with
`O_NOFOLLOW`; parent traversal and symlink components are refused. The leaf is
opened with `O_NONBLOCK` before checking the opened descriptor for regular-file
type, current effective UID and exact permissions. Reads are bounded even if
the file grows. A fixed buffer includes one overflow byte and never reallocates
while holding input. These checks do not protect against a malicious process
running as the same user, concurrent in-place edits, kernel copies, or a hostile
filesystem. The outside-repository location is an operator requirement, not a
runtime repository-discovery mechanism.

One read supplies the account and initial password. Only the trusted-device
verification code comes from hidden TTY input. After successful code submission,
the existing protocol's post-2FA step consumes the retained password once,
without reopening the file. This is not a retry after failed authentication.
Repeated or out-of-order prompts stop the adapter and drop retained input.
Passwords are kept in zeroizing memory only through this bounded login flow;
the persistence notice or explicit finish drops any remaining copy before
result reporting. Normal errors wipe owned buffers; abrupt process termination
can skip destructors and does not guarantee erasure. The tool does not remove
or overwrite the operator's plaintext file.

This path adds no token/delegate issuance, trust, escrow, CKKS, or provisioning
operation. It uses the existing isolated-profile reservation and Secret Service
round trip, including their no-retry and no-rollback behavior described above.
Successful storage proves only local persistence. Synthetic offline tests cover
literal parsing, bounds, metadata, symlinks, FIFO rejection, confirmation order,
OTP and one-time post-2FA handoff, failure paths and CLI rejection. No real
credential file, account, Apple endpoint or Secret Service was accessed to
implement or validate this adapter; live compatibility remains unverified.
