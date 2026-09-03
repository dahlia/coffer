Contributing guide
==================

Thank you for contributing to Coffer.

This document is also the operating guide for coding agents working in this
repository. *AGENTS.md* and *CLAUDE.md* are symbolic links to this file.

Before changing code, read:

1.  [*README.md*](./README.md), for the purpose and security posture of the
    project;
2.  [*ROADMAP.md*](./ROADMAP.md), for current scope and milestone ordering; and
3.  this document in full.

If you use an AI coding agent, read and follow [*AI\_POLICY.md*](./AI_POLICY.md)
first.

When instructions conflict, favor credential safety, data integrity, license
compliance, and the narrower interpretation of the requested change.


Development environment
-----------------------

Coffer uses [mise] as the single entry point for project tooling.

Do not add instructions that require contributors to manage the Coffer Rust
toolchain with `rustup`, and do not assume a globally selected Rust version.

Install the project's pinned tools with:

~~~~ sh
mise install
~~~~

Inspect available tasks with:

~~~~ sh
mise tasks
~~~~

The Rust toolchain configured in *mise.toml* must include:

 -  rust-analyzer;
 -  `rustfmt`; and
 -  Clippy.

Auxiliary tools, including [Hongdown], [cargo-deny], [actionlint], and
[zizmor], must likewise be managed through mise where practical.

Linux builds also require `pkg-config` and OpenSSL development headers because
the Secret Service adapter selects oo7's `openssl_crypto` backend to avoid an
unwiped plaintext buffer in oo7 0.6.0's `native_crypto` implementation.

Avoid introducing ad hoc setup commands when the operation should instead be a
reproducible mise task.

[mise]: https://mise.jdx.dev/
[Hongdown]: https://github.com/dahlia/hongdown
[cargo-deny]: https://github.com/EmbarkStudios/cargo-deny
[actionlint]: https://github.com/rhysd/actionlint
[zizmor]: https://github.com/zizmorcore/zizmor


Canonical development tasks
---------------------------

The repository should expose the following task interface through *mise.toml*.

### `mise run fmt`

Format all project-owned source and documentation.

At minimum this includes:

~~~~ sh
cargo fmt --all
hongdown --write
mise fmt
~~~~

If new languages or generated sources are added, extend the mise task rather
than requiring contributors to remember an additional formatter.

### `mise run fmt-check`

Verify formatting without modifying the working tree.

At minimum this includes:

~~~~ sh
cargo fmt --all --check
hongdown --check
mise fmt --check
~~~~

### `mise run check`

Run fast static verification suitable for frequent use and pre-commit checks.

This should include:

 -  Clippy for the entire workspace and all relevant targets, which runs the
    full compiler front end and therefore subsumes `cargo check`;
 -  `rustfmt` verification;
 -  Hongdown verification;
 -  mise configuration formatting verification;
 -  GitHub Actions workflow linting; and
 -  checks for other project-owned languages when they are introduced.

Checks that need the network, such as the dependency audit, do not belong here.

### `mise run build`

Build every workspace target, including tests, examples, and benchmarks,
without running them.

### `mise run test`

Run the normal test suite for the complete workspace.

Tests that access a live Apple Account or perform security-sensitive network
operations must not be part of this default task.

### `mise run doc`

Build Rust API documentation with warnings denied.

Public Rust APIs are expected to remain useful and reviewable through rustdoc.

### `mise run deny`

Audit the dependency graph with cargo-deny against *deny.toml*: security
advisories, license policy, banned crates, and permitted sources.

This task fetches the RustSec advisory database and therefore needs network
access.

### `mise run ci`

Run the complete local verification gate expected to match continuous
integration. It runs `check`, `build`, `test`, `doc`, and `deny`; continuous
integration runs exactly this task and nothing else.

A change is not complete until `mise run ci` succeeds.

Every Cargo invocation in the gate that resolves dependencies passes
`--locked`. When a change to a *Cargo.toml* requires a lockfile update, update
*Cargo.lock* deliberately with `cargo update` or `cargo add` and review the
result before running the gate.

If one of these tasks is absent while bootstrapping the repository, add the task
instead of bypassing the intended interface.


Rust quality policy
-------------------

Coffer has a zero-warning policy.

The workspace should configure:

~~~~ toml
[workspace.lints.rust]
warnings = "deny"

[workspace.lints.clippy]
all = "deny"
~~~~

The workspace additionally denies missing documentation on public items,
denies `unsafe` code unless it is allowed in a narrow scope, and requires every
`unsafe` block to carry a `SAFETY:` comment through Clippy's
`undocumented_unsafe_blocks` lint. The `coffer-protocol` crate goes further and
forbids `unsafe` at the crate level; if FFI ever has to live there, relax that
attribute to `deny` deliberately before adding a scoped allowance.

Workspace crates must inherit the workspace lint configuration with
`[lints] workspace = true`. The Clippy task also passes `-D warnings` on the
command line, but that only backs up ordinary warnings and Clippy's `all`
group; the documentation and `unsafe` lints are allow-by-default and reach a
crate solely through inheritance. Check the manifest of every new crate for
the inherit line.

Do not weaken a lint globally to make a change pass. If a lint must be allowed,
scope the exception as narrowly as possible and document why the code is safer
or clearer with the exception than without it.

Run `rustfmt` rather than manually approximating Rust formatting.

New public Rust APIs must have rustdoc documentation explaining:

 -  their purpose;
 -  security-relevant invariants;
 -  ownership or lifetime expectations when non-obvious;
 -  error behavior; and
 -  where the API fits into the larger protocol or application flow.

Treat broken intra-doc links and rustdoc warnings as build failures.


Rust implementation guidelines
------------------------------

Prefer safe Rust.

`unsafe` code is acceptable only where required for FFI or another operation
that cannot reasonably be expressed safely. Every `unsafe` block must have a
nearby safety explanation stating the invariants that make the operation valid.

Do not use panics as normal error handling for network data, keychain records,
browser messages, local databases, or other untrusted input.

Avoid `unwrap()` and `expect()` in production paths unless the invariant is
local, obvious, and impossible for external input to violate. Tests may use
them where doing so makes the assertion clearer.

Represent protocol states and important invariants in types where practical.
Prefer explicit state transitions to mutable structures whose valid states are
implicit.

Keep protocol crates independent of GTK. Authentication, CloudKit, Octagon,
CKKS, encrypted storage, and synchronization must be testable without a
graphical session. The Apple protocol layer lives in the `coffer-protocol`
crate under *crates/*; higher layers will be added as separate crates that
depend on it, and only the GNOME application crate may depend on GTK or
libadwaita.

Start every new Rust source file with the GPL notice block used in
*crates/coffer-protocol/src/lib.rs*. That per-file notice is where the
“or any later version” election of the project license is recorded.

Avoid introducing a new cryptographic implementation when a well-reviewed Rust
crate already provides the required primitive. Protocol-specific composition is
expected; reimplementing AES, SHA, ECDSA, SRP arithmetic, or similar primitives
without a compelling reason is not.


Handling secrets
----------------

Coffer handles passwords, authentication tokens, cryptographic keys, device
passcodes, recovery material, and other sensitive values.

These values must never appear in:

 -  normal logs;
 -  debug logs;
 -  panic messages;
 -  `Debug` output;
 -  snapshots;
 -  test fixtures committed to the repository;
 -  issue text;
 -  diagnostic bundles; or
 -  telemetry.

Secret-bearing types should not derive `Debug` unless their implementation
redacts the secret.

Prefer types that make accidental secret exposure difficult. Zeroize sensitive
transient material when practical, especially private keys, decrypted key
material, passwords, and recovery passcodes.

Do not keep decrypted credentials resident longer than required by the
operation being performed.

Long-lived local authentication secrets must be protected using an appropriate
platform secret store. The encrypted credential cache must not simply embed its
own decryption key beside the ciphertext.

Never add telemetry that contains credential domains, usernames, account
identifiers, or other data from which a user's stored accounts can be
reconstructed without a separate privacy review.


Live Apple Account safety
-------------------------

Not all Apple protocol requests are equivalent.

Before adding a network call, classify it by its side effects and retry
behavior.

### Read-only operations

Examples include record retrieval and non-mutating metadata queries.

These may use ordinary bounded retry behavior only after it is known that the
specific operation is idempotent and safe to retry.

### Authentication and 2FA

Apple Account authentication may be rate limited or contribute to account
protection mechanisms.

Do not automatically retry a failed password, SRP, or two-factor authentication
operation.

A failure must be surfaced with enough context to distinguish which protocol
stage failed before another attempt is made.

### Escrow recovery

Escrow recovery using a device passcode or iCloud Security Code is a dangerous
operation. Failed attempts may consume a finite recovery-attempt budget.

Therefore:

 -  never automatically retry a recovery attempt;
 -  never guess a recovery passcode;
 -  never brute-force recovery material;
 -  never run a live recovery attempt in CI;
 -  do not combine record inspection and recovery into a single implicit
    operation;
 -  require an explicit user action immediately before an attempt; and
 -  after a failure, return control to the user rather than trying another
    record or credential.

Offline cryptographic processing must be validated with fixtures before a new
live recovery path is exercised.

### Trust and keychain mutation

Operations that change Octagon trust or CKKS contents require the same degree of
care as escrow recovery.

Until *ROADMAP.md* explicitly reaches keychain write support, do not add remote
credential create, update, or delete behavior as an incidental part of another
change.

AI agents must not perform experimental live mutations against a maintainer's
normal account unless the user explicitly requests that exact operation after
the implementation and risk have been described.


Testing protocol code
---------------------

Protocol code should be developed against deterministic evidence whenever
possible.

Prefer:

 -  public test vectors;
 -  sanitized binary fixtures;
 -  synthetic protobuf/plist messages;
 -  captured messages from test accounts with all identifying and secret
    material removed;
 -  property tests for parsers and serializers; and
 -  round-trip tests for representations where round trips are meaningful.

Byte-exact formats need byte-exact tests.

For parsers consuming remotely controlled data, include malformed, truncated,
oversized, duplicate-field, and unexpected-value cases as appropriate.

Never make a unit test depend on the continued availability or exact response
of a live Apple endpoint.

Live integration tests must be separately invoked, clearly named, and excluded
from normal CI. They must explain whether the operation is read-only,
rate-limited, trust-mutating, recovery-sensitive, or keychain-mutating.

Do not commit captured real credentials even when they belong to a contributor.

Keep fixtures next to the crate whose tests consume them, in a
*tests/fixtures/* directory inside that crate, and record where each fixture
came from and how it was sanitized in a *README.md* in that directory.


Dependency policy
-----------------

Keep the dependency surface deliberate, especially for crates involved in:

 -  cryptography;
 -  TLS;
 -  serialization;
 -  FFI;
 -  secret storage;
 -  authentication; and
 -  automatic update or download behavior.

Disable unnecessary default features where doing so reduces networking,
platform assumptions, or attack surface.

Dependencies are audited with cargo-deny against *deny.toml*, which is part of
the canonical gate through `mise run deny`. The policy allows GPL-3.0-or-later
itself, the permissive licenses commonly found in the Rust ecosystem, and
MPL-2.0, which covers `apple-private-apis`; any other license fails the gate
until it has been reviewed and added deliberately. External crates may only
come from crates.io or an explicitly allowed Git repository, and a Git
dependency must be pinned to a commit revision. Workspace crates may depend on
each other by path.

For `apple-private-apis`, Coffer intends to use local anisette generation.
Implicit fallback to a public or third-party remote anisette server must not be
enabled accidentally.

When runtime Apple support libraries are required, download them from an
Apple-controlled source. Do not commit those proprietary binaries to the
repository and do not package them as part of Coffer releases.


License and source provenance
-----------------------------

Coffer is GPL-3.0-or-later software. See *LICENSE* for the full license terms.

License provenance is especially important because Coffer implements private
protocols for which several independent reverse-engineered implementations
exist.

### Code that may be used

SideStore's [`apple-private-apis`] is licensed under MPL 2.0 and may be used as
a dependency subject to its license.

Prefer keeping MPL-licensed code in its upstream dependency rather than copying
it into the Coffer tree. If an upstream change is needed, prefer contributing
the change upstream.

If MPL-covered source is vendored or modified, preserve its required notices and
license treatment. Do not silently relicense upstream files merely because the
larger Coffer work is GPL-3.0-or-later.

[`apple-private-apis`]: https://github.com/SideStore/apple-private-apis

### Reference-only implementations

The following projects may be useful for understanding observed behavior, but
their source code must be treated as reference-only unless their licensing
situation changes:

 -  [`OpenBubbles/rustpush`], currently under SSPL; and
 -  [`Sank6/iCloud-Keychain-for-Linux`], whose repository does not currently
    grant Coffer a license to copy its implementation.

Do not copy, paste, translate, mechanically port, or adapt source code from a
reference-only implementation into Coffer.

This restriction applies equally to human contributors and AI coding agents.
Giving reference-only code to an AI model and asking it to rewrite the code in
Rust does not make the resulting implementation independent.

Protocol facts are different from source code. Independently observable facts
such as endpoint behavior, field meanings, serialization formats, cryptographic
algorithms, and test results may be used to build an independent
implementation.

Where practical, corroborate such facts against Apple's published open-source
Security code, public cryptographic specifications, independent wire
observations, or reproducible test vectors.

When implementing a particularly obscure protocol detail, leave enough
documentation or test evidence for a future maintainer to understand where the
behavior came from without reconstructing the entire research process.

[`OpenBubbles/rustpush`]: https://github.com/OpenBubbles/rustpush
[`Sank6/iCloud-Keychain-for-Linux`]: https://github.com/Sank6/iCloud-Keychain-for-Linux


AI-assisted development
-----------------------

AI-assisted development is explicitly welcome in Coffer.

AI assistance does not lower the quality, safety, testing, or licensing
requirements of a contribution.

Before making changes, an agent must read *README.md*, *ROADMAP.md*,
*AI\_POLICY.md*, and this file.

An agent must:

 -  stay within the requested task;
 -  inspect existing architecture before introducing a competing abstraction;
 -  use mise tasks rather than globally installed substitutes;
 -  run relevant tests while developing;
 -  run `mise run ci` before declaring a change complete;
 -  preserve license provenance;
 -  avoid copying or translating reference-only implementations;
 -  never expose secrets in its output or generated fixtures;
 -  never automatically retry authentication or recovery operations;
 -  never perform a live escrow or CKKS mutation experiment without explicit
    instruction;
 -  treat failures in security-sensitive flows as information to investigate,
    not as an invitation to retry;
 -  add regression tests for bugs it fixes; and
 -  update documentation when its change invalidates documented behavior.

Agents must not mark roadmap checkboxes complete unless the corresponding code,
tests, documentation, and verification requirements are actually complete.

Do not silence tests or lints merely to finish a task. Diagnose the failure or
report the unresolved problem.


Making changes
--------------

Keep changes focused.

Avoid unrelated refactors in the same change as protocol or security-sensitive
behavior. Small diffs make it easier to review subtle byte-level and
state-machine changes.

For bug fixes, add a regression test that fails for the original behavior
whenever practical.

For new protocol behavior, prefer writing the fixture or test vector before the
implementation. Confirm that the test fails for the expected reason, then
implement the behavior.

Changes that alter serialization, cryptography, key derivation, trust state,
credential matching, or remote mutation behavior deserve especially narrow
commits and explicit tests.

Do not modify a golden fixture simply because a test fails. First determine
whether the implementation changed intentionally and whether the new output is
actually correct.


Documentation
-------------

All Markdown is formatted with Hongdown. The project configuration lives in
*.hongdown.toml*; it sets `no_inherit = true` so that a contributor's personal
Hongdown configuration cannot change what `mise run fmt` produces.

After editing Markdown, run:

~~~~ sh
hongdown --write path/to/file.md
~~~~

or use the canonical repository formatter:

~~~~ sh
mise run fmt
~~~~

Before committing, verify formatting with:

~~~~ sh
mise run fmt-check
~~~~

Follow these prose conventions:

 -  Use sentence case for headings.
 -  Prefer direct technical prose over marketing language in developer
    documentation.
 -  Avoid em dashes; use punctuation or rewrite the sentence.
 -  Do not put spaces around slashes.
 -  Use italics for file and document names, such as *Cargo.toml* and
    *ROADMAP.md*.
 -  Use inline code for commands, symbols, options, crate names when
    appropriate, and literal protocol values.
 -  Use official capitalization for technologies and proper nouns.
 -  Explain uncommon Apple protocol terms when first introduced outside
    research-oriented documentation.

Do not hand-format Markdown against Hongdown's output.


Before committing
-----------------

At minimum, run:

~~~~ sh
mise run fmt
mise run check
mise run test
~~~~

Before opening or merging a pull request, run:

~~~~ sh
mise run ci
~~~~

For documentation-only work, use the narrowest applicable checks if the full
Rust build is genuinely unaffected, but Markdown must always pass Hongdown.

Review the final diff for accidental secret material before committing.


Review checklist
----------------

A reviewer, human or automated, should ask:

 -  Does the change match the current roadmap scope?
 -  Does it preserve the read-only boundary where required?
 -  Could any new operation consume an authentication or recovery attempt?
 -  Could any failure path retry a dangerous operation?
 -  Can any secret reach logs, errors, `Debug`, fixtures, or telemetry?
 -  Are untrusted lengths and fields bounded and validated?
 -  Is unsafe code justified and documented?
 -  Are cryptographic primitives taken from established libraries?
 -  Are byte-sensitive formats covered by exact tests?
 -  Is source-code provenance clear and license-compatible?
 -  Were reference-only implementations used only as behavioral references?
 -  Does all Rust pass `rustfmt` and Clippy without warnings?
 -  Does all Markdown pass Hongdown?
 -  Does `mise run ci` pass?

If the answer to a safety-sensitive question is unknown, the change is not
ready to merge.
