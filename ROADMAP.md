Coffer roadmap
==============

This document defines the intended order of development for Coffer.

It is an engineering roadmap, not a release schedule. Milestones may be split,
reordered, or expanded as protocol research uncovers new constraints.

Safety takes precedence over feature completeness.

A later milestone must not be pulled forward merely because its user interface
is easy to implement. In particular, remote mutation, escrow recovery,
automatic retries, and passkey operations require a substantially higher
confidence level than local read-only functionality.


Definition of done
------------------

A roadmap item is complete only when:

 -  the implementation is covered by appropriate tests;
 -  relevant protocol invariants are documented;
 -  failure behavior is understood;
 -  `mise run ci` succeeds;
 -  no new Rust or Clippy warnings are introduced;
 -  affected Markdown passes Hongdown;
 -  no real user secrets have entered fixtures or logs; and
 -  the implementation does not widen the set of dangerous live-account
    operations without documenting and reviewing that change.

For protocol work, “it worked once on one account” is evidence, not completion.


Milestone 0: Repository foundation
----------------------------------

Goal: establish a development environment in which subsequent protocol work is
reproducible and difficult to accidentally weaken.

 -  [x] Create the Cargo workspace using Rust 2024 edition.
 -  [x] Configure the Rust toolchain through *mise.toml*.
 -  [x] Include rust-analyzer, `rustfmt`, and Clippy in the mise-managed Rust
    toolchain.
 -  [x] Configure workspace Rust warnings as errors.
 -  [x] Configure Clippy's `all` lint group as errors.
 -  [x] Add canonical `mise run fmt`, `mise run fmt-check`, `mise run check`,
    `mise run build`, `mise run test`, `mise run doc`, and `mise run ci` tasks.
 -  [x] Add Hongdown through mise.
 -  [x] Make Hongdown formatting part of the normal formatting and CI gates.
 -  [x] Add CI that executes the same mise tasks used locally.
 -  [x] Add the GPL-3.0-or-later license.
 -  [x] Establish dependency-license auditing.
 -  [x] Establish rules for secret redaction and protocol test fixtures.
 -  [x] Establish a small architecture that keeps Apple protocols independent
    from the GUI.
 -  [x] Add *AGENTS.md* and *CLAUDE.md* as symbolic links to
    *CONTRIBUTING.md*.


Milestone 1: Local Apple authentication
---------------------------------------

Goal: authenticate a Linux machine without requiring a separately operated
anisette server.

### Local anisette

 -  [ ] Integrate SideStore's `apple-private-apis`.
 -  [ ] Use `omnisette` directly from Rust.
 -  [ ] Disable implicit remote-anisette fallback.
 -  [ ] Define a stable local location for anisette provisioning state.
 -  [ ] Implement runtime bootstrap for the Apple libraries needed by the
    local provider.
 -  [ ] Retrieve proprietary libraries only from Apple-controlled distribution
    endpoints.
 -  [ ] Never commit or redistribute Apple proprietary binaries.
 -  [ ] Handle updates to the underlying Apple libraries without silently
    corrupting existing provisioning state.

### Apple Account authentication

 -  [ ] Evaluate `apple-private-apis`‘ `icloud-auth` implementation against the
    authentication behavior needed by Coffer.
 -  [ ] Reuse or extend it where licensing and behavior permit.
 -  [ ] Implement the remaining native GSA authentication flow.
 -  [ ] Support trusted-device two-factor authentication.
 -  [ ] Represent authentication states explicitly rather than as loosely
    coupled network calls.
 -  [ ] Store reusable authentication secrets through Secret Service.
 -  [ ] Ensure passwords, PETs, service tokens, SRP material, and 2FA codes are
    never logged.
 -  [ ] Distinguish initial authentication failure from post-2FA
    reauthentication failure.
 -  [ ] Do not automatically retry authentication attempts.

Authentication tests should use deterministic cryptographic and serialization
fixtures wherever possible. Tests against a real Apple Account must be
explicitly invoked and must never run in ordinary CI.


Milestone 2: Read-only Apple Passwords (formerly iCloud Keychain) core
----------------------------------------------------------------------

Goal: obtain decrypted credential records without changing keychain contents.

### CloudKit transport

 -  [ ] Obtain CloudKit account configuration and service tokens.
 -  [ ] Implement the CloudKit/CKCode transport needed by Cuttlefish and CKKS.
 -  [ ] Implement protobuf framing and compression with byte-level test
    fixtures.
 -  [ ] Preserve opaque fields that are not yet understood.
 -  [ ] Classify protocol errors without exposing credential material.

### Octagon identity and trust

 -  [ ] Implement or integrate Octagon peer identity generation.
 -  [ ] Validate P-384 key serialization and signatures against public test
    vectors.
 -  [ ] Implement viable-bottle discovery.
 -  [ ] Implement read-only inspection of recovery metadata.
 -  [ ] Implement the minimum trust join required for keychain access.
 -  [ ] Document every state-changing trust operation separately from read
    operations.

### Escrow recovery

Escrow recovery is a high-risk operation because incorrect recovery attempts
may consume a finite server-side attempt budget.

 -  [ ] Implement escrow record enumeration without consuming a recovery
    attempt.
 -  [ ] Correlate recovery records with enough device metadata for the user to
    select the intended record.
 -  [ ] Implement passcode recovery behind an explicit user confirmation.
 -  [ ] Never automatically retry a rejected recovery attempt.
 -  [ ] Never execute escrow recovery in CI.
 -  [ ] Make the UI and API clearly distinguish “inspect” from “attempt
    recovery”.
 -  [ ] Test cryptographic processing with offline fixtures before live use.

### CKKS

 -  [ ] Retrieve CKKS zones and record changes.
 -  [ ] Recover the top-level key hierarchy.
 -  [ ] Decrypt class keys and item keys.
 -  [ ] Decrypt website password records.
 -  [ ] Parse metadata sidecars.
 -  [ ] Recognize, but initially ignore, unsupported record classes.
 -  [ ] Add stable fixture-based regression tests for known CKKS record shapes.
 -  [ ] Keep the entire remote path read-only.

Completion of this milestone should produce a library-level API capable of
returning a typed list of credentials from an authenticated account without a
GUI.


Milestone 3: Local credential model and CLI
-------------------------------------------

Goal: make the read-only core usable and observable without depending on GTK.

 -  [ ] Define domain types for website credentials.
 -  [ ] Support associated notes and titles.
 -  [ ] Support verification-code seeds and local TOTP generation.
 -  [ ] Support Hide My Email aliases.
 -  [ ] Preserve record identifiers needed by future synchronization.
 -  [ ] Build an encrypted local cache.
 -  [ ] Protect the cache's master secret through Secret Service.
 -  [ ] Provide explicit lock/unlock semantics.
 -  [ ] Zeroize sensitive transient buffers where practical.
 -  [ ] Avoid implementing `Debug` for types that contain secrets.
 -  [ ] Add a small CLI for authentication diagnostics, synchronization, and
    credential inspection.
 -  [ ] Make plain-text credential output opt-in and conspicuous.
 -  [ ] Implement `sync` as a manually invokable read-only operation.

The CLI is primarily an engineering and recovery interface. It is not intended
to become the primary Coffer user experience.


Milestone 4: GNOME application
------------------------------

Goal: provide a native graphical credential manager suitable for daily use.

 -  [ ] Build the application with GTK 4 and libadwaita.
 -  [ ] Follow current GNOME human-interface conventions.
 -  [ ] Implement first-run account setup.
 -  [ ] Present authentication and recovery states without exposing protocol
    jargon unnecessarily.
 -  [ ] Implement credential search.
 -  [ ] Implement credential detail views.
 -  [ ] Implement explicit password reveal.
 -  [ ] Implement copy-to-clipboard behavior.
 -  [ ] Clear copied secrets from the clipboard when practical.
 -  [ ] Display and refresh verification codes.
 -  [ ] Display Hide My Email addresses.
 -  [ ] Surface last successful synchronization and relevant sync errors.
 -  [ ] Make unsupported keychain record types fail gracefully.
 -  [ ] Ensure the graphical process never writes credential values to logs.

The GUI must consume the application/service layer. GTK code must not become
the owner of authentication, CloudKit, Octagon, or CKKS protocol state.


Milestone 5: Browser integration
--------------------------------

Goal: support normal browser login workflows while keeping decrypted credential
access narrow.

### Native messaging host

 -  [ ] Implement the native messaging host in Rust.
 -  [ ] Define a small versioned protocol between the host and browser
    extensions.
 -  [ ] Match credentials conservatively by origin/domain.
 -  [ ] Return only credentials relevant to the requesting site.
 -  [ ] Generate TOTP values at the last practical moment.
 -  [ ] Never expose raw TOTP seeds to the browser extension.
 -  [ ] Reject malformed and oversized native-messaging requests.

### WebExtension

 -  [ ] Support Firefox.
 -  [ ] Support Chromium-based browsers.
 -  [ ] Provide username/password autofill.
 -  [ ] Support email-first and multi-step login forms.
 -  [ ] Provide TOTP autofill.
 -  [ ] Avoid collecting browsing history.
 -  [ ] Avoid transmitting page contents to Coffer beyond what is necessary
    for credential matching.

Saving newly entered passwords remains out of scope while the keychain backend
is read-only.


Milestone 6: Robust synchronization
-----------------------------------

Goal: move from periodic full snapshots toward a reliable long-running sync
engine.

 -  [ ] Persist CloudKit change tokens safely.
 -  [ ] Implement incremental record synchronization.
 -  [ ] Handle token invalidation and full-resync recovery.
 -  [ ] Handle authentication-token renewal without unnecessary 2FA prompts.
 -  [ ] Distinguish retryable transport failures from account and protocol
    failures.
 -  [ ] Add bounded backoff only to operations independently known to be safe
    to retry.
 -  [ ] Add background synchronization appropriate for the GNOME desktop.
 -  [ ] Avoid keeping decrypted credentials resident when they are not needed.
 -  [ ] Expose synchronization health to the GUI.

The read path should be considered mature before remote credential mutation is
started.


Milestone 7: Keychain write support
-----------------------------------

Goal: allow Linux to become a full participant in password synchronization.

This milestone is intentionally separate because a write implementation can
damage or delete remote credential state.

No write API should be exposed merely because a corresponding CloudKit endpoint
has been identified.

### Research

 -  [ ] Document CKKS item creation and update semantics.
 -  [ ] Document wrapping-key selection for new records.
 -  [ ] Document record generations and conflict behavior.
 -  [ ] Document deletion semantics.
 -  [ ] Document metadata-sidecar updates.
 -  [ ] Establish offline or disposable-account tests for mutation behavior.

### Implementation

 -  [ ] Create a new website credential.
 -  [ ] Update an existing credential.
 -  [ ] Delete a credential.
 -  [ ] Synchronize notes and verification-code metadata.
 -  [ ] Detect remote conflicts rather than silently overwriting them.
 -  [ ] Make every mutation observable to the user.
 -  [ ] Ensure interrupted writes can recover to a consistent state.
 -  [ ] Add browser-driven “save password” support only after the underlying
    mutation API is mature.

Automated agents must not perform live CKKS mutation experiments on a
maintainer's normal account without an explicit instruction for that specific
operation.


Milestone 8: Passkeys and extended Passwords features
-----------------------------------------------------

Goal: close the largest remaining functional gaps with Apple's credential
ecosystem.

### Passkeys

 -  [ ] Fully decode WebAuthn credential records.
 -  [ ] Determine the private-key protection and synchronization model.
 -  [ ] Integrate with Linux/browser WebAuthn APIs where technically possible.
 -  [ ] Support authentication with synchronized passkeys.
 -  [ ] Research passkey creation on Linux.
 -  [ ] Add passkey writes only after the same safety review required for
    password writes.

### Additional record types

 -  [ ] Evaluate shared credential groups.
 -  [ ] Evaluate deleted/recoverable credentials.
 -  [ ] Evaluate security-recommendation metadata.
 -  [ ] Evaluate Sign in with Apple-related records.
 -  [ ] Evaluate payment-card records separately from login credentials.

Unsupported record types should remain preserved or ignored safely rather than
being guessed at.


Milestone 9: Distribution
-------------------------

Goal: make Coffer practical to install on mainstream Linux desktops.

 -  [ ] Establish reproducible release builds.
 -  [ ] Provide native packages suitable for early testing.
 -  [ ] Evaluate Fedora/RPM packaging.
 -  [ ] Evaluate Flatpak and Flathub distribution.
 -  [ ] Resolve browser native-messaging integration under sandboxed
    distributions.
 -  [ ] Ensure runtime acquisition of Apple proprietary libraries complies
    with project distribution rules and does not bundle those libraries.
 -  [ ] Document supported CPU architectures and desktop environments.
 -  [ ] Sign release artifacts where supported.
 -  [ ] Publish an installation and troubleshooting guide.


Ongoing work
------------

The following requirements apply across all milestones.

### Security

 -  Threat-model new secret-bearing components.
 -  Keep secrets out of logs, crash reports, and telemetry.
 -  Minimize plaintext lifetime.
 -  Treat network data as untrusted input.
 -  Place explicit size limits on remotely controlled allocations.
 -  Prefer constant-time primitives from established cryptographic crates over
    handwritten cryptography.

### Protocol research

 -  Record the provenance of protocol facts.
 -  Prefer Apple's published open-source code and independently observable wire
    behavior as primary evidence.
 -  Preserve unknown fields and avoid assigning semantics based solely on names.
 -  Add test vectors for every byte-sensitive format.

### Dependency hygiene

 -  Keep dependencies reasonably current.
 -  Avoid adopting an abandoned security-critical dependency without a clear
    maintenance plan.
 -  Review feature flags so that unnecessary networking and remote fallbacks
    are not enabled accidentally.
 -  Audit dependency licenses before release.

### Documentation

 -  Keep *README.md*, *ROADMAP.md*, and *CONTRIBUTING.md* synchronized with the
    implementation.
 -  Format all Markdown with Hongdown.
 -  Update this roadmap when the architecture materially changes.
 -  Do not mark an item complete merely because code exists; completion
    requires the corresponding verification and safety work.
