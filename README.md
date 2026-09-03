Coffer
======

Coffer is a native Linux client for passwords and other credentials stored in
Apple Passwords (formerly iCloud Keychain).

It is intended for people who use Apple devices alongside Linux and want their
existing credentials to remain available without adopting a separate password
manager solely for Linux.

Coffer is written primarily in Rust and is designed as a first-class GNOME
application using GTK 4 and libadwaita.

> [!WARNING]
>
> Coffer is in early development. Do not rely on it as the only way to access
> your credentials, and do not use development builds with an account for which
> you do not have another trusted recovery path.

Coffer is an independent project. It is not affiliated with, endorsed by, or
supported by Apple Inc. Apple, iCloud, Apple Passwords, and other Apple product
names are trademarks of Apple Inc.


Why Coffer?
-----------

Apple's password manager works well across Apple platforms and has an official
Windows client, but there is no corresponding Linux client.

Coffer aims to fill that gap without becoming another independent password
ecosystem.

The long-term goal is for a credential saved on an Apple device to be
conveniently available on Linux, and eventually for changes made on Linux to
synchronize back through iCloud as well.

The name *Coffer* refers to a strongbox used for keeping valuable things safe.


Project principles
------------------

### Native Linux experience

Coffer should feel like a Linux application, not a web application wrapped in a
desktop shell.

The primary graphical interface targets GNOME and follows contemporary GNOME
design conventions using GTK 4 and libadwaita.

### Local-first credential handling

Coffer should not introduce an intermediary Coffer service or send credentials
to third-party servers.

Communication needed for synchronization should be directly between the local
machine and Apple's services. Secrets cached locally must be encrypted and
integrated with the platform's secret storage facilities where appropriate.

### Safe before complete

Reverse-engineered authentication and keychain protocols can have destructive
or rate-limited operations.

Coffer therefore prefers a smaller safe implementation over a more complete
implementation whose failure modes are not understood.

The initial synchronization implementation is deliberately read-only. Write
support will not be added until the read path, key hierarchy, synchronization
semantics, and failure behavior are sufficiently understood and tested.

### No hidden remote anisette service

Coffer intends to generate anisette data locally through SideStore's
[`apple-private-apis`] project, particularly its `omnisette` crate, instead of
depending on a separately hosted anisette service.

On platforms where Apple's Android support libraries are required, Coffer may
retrieve those libraries from Apple at runtime. Proprietary Apple binaries must
not be committed to or redistributed with the Coffer source repository.

[`apple-private-apis`]: https://github.com/SideStore/apple-private-apis

### Auditable implementation

Credential handling, cryptography, serialization, authentication state, and
protocol transitions should be explicit and testable.

Security-sensitive code should favor small typed components with well-defined
invariants over broad convenience abstractions.

### Free software

Coffer is free software distributed under the GNU General Public License,
version 3 or any later version (GPL-3.0-or-later). See *LICENSE* for the exact
license terms.

Third-party dependencies retain their respective licenses.


Planned capabilities
--------------------

Coffer is expected to grow incrementally. Planned capabilities include:

 -  Signing in to an Apple Account using Apple's native authentication flow.
 -  Local anisette generation without a separately managed server.
 -  Joining the account's Apple Passwords trust using Octagon.
 -  Reading and decrypting CKKS keychain records from CloudKit.
 -  Synchronizing website passwords.
 -  Verification code (TOTP) support.
 -  Hide My Email address discovery.
 -  A native GTK 4/libadwaita credential browser.
 -  Firefox and Chromium-compatible browser autofill.
 -  Secure local caching and integration with Secret Service.
 -  Incremental background synchronization.
 -  Eventually, creating, updating, and deleting credentials.
 -  Eventually, passkey support.

See [*ROADMAP.md*](./ROADMAP.md) for the intended development order and the
safety requirements attached to later milestones.


Architecture
------------

The precise crate layout will evolve while the protocol implementation is
validated, but Coffer is expected to separate the following responsibilities:

~~~~ text
Coffer
│
├── GNOME application
│   └── GTK 4 + libadwaita
│
├── application/service layer
│   ├── synchronization
│   ├── local encrypted storage
│   └── platform integration
│
├── browser integration
│   ├── native messaging host
│   └── WebExtension
│
└── Apple protocol layer
    ├── authentication
    │   └── apple-private-apis
    │       ├── icloud-auth
    │       └── omnisette
    ├── CloudKit/CKCode
    ├── Octagon
    └── CKKS
~~~~

The protocol and synchronization layers must remain independent of GTK. A
command-line or test harness should be able to exercise them without starting a
graphical session.

The workspace currently contains a single crate, `coffer-protocol` under
*crates/*, which is the Apple protocol layer. The remaining layers will be added
as separate crates that depend on it, and only the GNOME application crate will
depend on GTK and libadwaita.

Likewise, browser integration must consume a narrow application-facing
interface rather than directly accessing decrypted keychain internals.


Development
-----------

Coffer uses [mise] as the single entry point for its development toolchain.
Do not install or select the project Rust toolchain with `rustup` manually.

Install the configured toolchain and development tools:

~~~~ sh
mise install
~~~~

Inspect available project tasks:

~~~~ sh
mise tasks
~~~~

The standard development loop is expected to use:

~~~~ sh
mise run fmt
mise run check
mise run test
~~~~

Before considering a change complete, run the full verification gate:

~~~~ sh
mise run ci
~~~~

`mise run ci` runs every canonical verification task, including `fmt-check`,
`build`, `doc`, and the dependency audit `deny`; it checks formatting but never
rewrites files. Continuous integration runs the same task. Run `mise tasks` for
the complete list.

The Rust toolchain, including `rustfmt`, Clippy, and rust-analyzer, is pinned in
*mise.toml*. The repository treats Rust and Clippy warnings as errors.

Markdown is formatted with [Hongdown]. Do not manually reformat Markdown to a
different style.

For detailed development, security, licensing, and AI-agent rules, read
[*CONTRIBUTING.md*](./CONTRIBUTING.md) before making changes.

[mise]: https://mise.jdx.dev/
[Hongdown]: https://github.com/dahlia/hongdown


Security
--------

Coffer handles some of the most sensitive data on a user's computer.

Never include real passwords, authentication tokens, recovery material,
passcodes, decrypted keychain payloads, or other user secrets in:

 -  source code;
 -  tests or fixtures;
 -  logs;
 -  panic messages;
 -  screenshots;
 -  issue reports; or
 -  diagnostic bundles.

Authentication retries, escrow recovery, trust changes, and future CKKS writes
must be treated differently from ordinary idempotent network requests. Some
Apple-side operations can be rate limited or consume a finite number of
recovery attempts.

Automated retries are therefore forbidden for security-sensitive operations
unless the protocol has been independently established to make those retries
safe.

See *CONTRIBUTING.md* for the complete development safety rules.


Protocol research and provenance
--------------------------------

Coffer necessarily relies on publicly available reverse-engineering research
and implementations to understand Apple's private protocols.

Source-code provenance matters.

[`apple-private-apis`] is an intended source dependency and is licensed under
MPL 2.0.

Other implementations may be useful as behavioral or protocol references
without being acceptable sources of code. In particular, contributors must
follow the licensing and clean-implementation rules documented in
[*CONTRIBUTING.md*](./CONTRIBUTING.md).

Protocol facts should, wherever practical, be corroborated against:

 -  Apple's published open-source components;
 -  independently captured protocol behavior;
 -  public specifications for the underlying cryptographic primitives and
    formats; and
 -  reproducible test vectors.


Status
------

Coffer is pre-alpha.

The first objective is not a complete password manager. It is a reliable,
well-tested, read-only path from an Apple Passwords account to a local Linux
credential model.

Features that mutate remote keychain state intentionally come later.


License
-------

Coffer is distributed under the GNU General Public License, version 3 or any
later version (GPL-3.0-or-later). See [*LICENSE*](./LICENSE).

Third-party source code and libraries remain subject to their own licenses.
