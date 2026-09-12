Service tokens from stored GSA material
=======================================

Phase 1 implements one explicit `apptokens` exchange for
`com.apple.gs.xcode.auth`. This is Xcode authentication, not CloudKit access.
The implementation has deterministic offline evidence; Apple interoperability
and the effect of issuance on existing tokens remain unverified.


The twelve scope decisions
--------------------------

1.  Borrow the stored `adsid`, IdMS token, 32-byte `sk`, and binary `c` through
    `SessionMaterialRef`. Keep `COFFSESS` v1 and require no account name or PET.
2.  Expose only `Service::XcodeAuthentication`. Do not guess or iterate
    services.
3.  Keep issued tokens in a short-lived zeroizing owner bound to the requesting
    account and service, with checked Unix epoch-millisecond expiry. Do not
    persist them or change the session after rejection.
4.  Keep wire/crypto in `coffer-protocol`, the stored-field bridge in
    `coffer-service`, and concrete adapters in the developer harness.
5.  Adopt no CloudKit/Cuttlefish protobuf schema. Apple's semantic interfaces
    do not establish field numbers, framing, or an interoperable transport.
6.  Validate unknown plist fields, including their duplicates and bounds, then
    wipe them. Future signed protobuf data needs bounded original bytes and
    must not be decoded and reserialized as an assumed canonical form.
7.  Treat token issuance as authentication. Add no implicit login, 2FA,
    provisioning, repair, trust operation, or credential upload.
8.  Keep Octagon trust mutations behind a separate reviewed operation plan and
    immediate user action. A trust join can upload top-level-key shares.
9.  Separate escrow inspection from a selected single recovery attempt.
    Recovery must not iterate credentials or retry an unknown outcome.
10. Future CKKS keys need account/container/database/zone/record context and a
    bounded graph rooted in explicitly trusted keys. Missing keys must not
    trigger recovery or remote writes. No credential API is implemented here.
11. Require offline request/HMAC/AEAD/parser/store/no-retry evidence. XML is the
    only supported plaintext; binary plist is explicitly unsupported.
12. Permit no automatic retry. Any live issuance requires separate approval
    after review and full CI, with existing libraries, provisioning and session.
    Failure preserves the session and ends the attempt.


Wire and parser boundary
------------------------

The fixed endpoint is `POST https://gsa.apple.com/grandslam/GsService2`.
The checksum is `HMAC-SHA256(sk, "apptokens" || adsid || service)` without
separators. The request contains an `app` array with one service string,
data-valued `c` and `checksum`, string `o`, `t`, `u`, and the existing Coffer
HTTP profile. The token-specific `cpd` encodes `bootstrap`, `icscrec`, and
`prkgen` as true Booleans and `pbe` as false, matching xtool's pinned
[operation request]. Other `cpd` entries remain strings. M1 retains its
independently verified request representation: it sends these flags as strings
to the same endpoint and authenticated successfully. Boolean typing is not
established as required by that endpoint or as the cause of token rejection.

The request uses the canonical Apple plist prologue used by M1, with compact
interior XML. These representation choices align with documented/evidenced
serialization; neither proves that the earlier compact/string-flag request
caused HTTP 404. The fixed endpoint and client-info remain unchanged.

HTTP 200 is insufficient: `Response.Status.ec` must be integer zero and an
`au` selector stops the attempt. Non-200 HTTP responses, including 401, preserve
only their numeric status in `TokenError::Http`; challenge handling is disabled.
An HTTP 200 protocol rejection instead retains only the numeric `ec` and a
boolean indicating whether `au` was present. The selector value and remote
message are never retained in an error. No undocumented server error number
means “session expired.” Transport, malformed, oversized, unsupported,
authentication-tag, clock, and locally expired-token outcomes remain distinct
fixed classifications. Malformed HTTP 200 responses also retain a fixed
`ResponseStage`: outer plist, Response/Status dictionary, individual status
field, envelope, authenticated plaintext plist, service dictionary, token, or
expiry. No remote field name, value, parser error, offset, or response excerpt
is retained. Size, unsupported format, tag failure, and protocol rejection keep
their existing classifications. These diagnostics identify the failing stage,
not its underlying cause or permission to retry. The harness reports them
without headers or response content. Remote text and adapter error strings
never become diagnostic output.

The encrypted `et` data contains three bytes `XYZ` as AAD, a 16-byte IV,
ciphertext, then a 16-byte tag. RustCrypto `AesGcm<Aes256, U16>` authenticates
before decrypting with the original session key. The decrypted `t` dictionary
must contain exactly the requested service with string `token` and integer
`expiry`. Account binding derives from the input/key; there is no independently
evidenced account field in this response.

The token parser accepts one XML 1.0 UTF-8 plist dictionary. It accepts the
canonical Apple public plist DOCTYPE as inert syntax, never resolves it, and
rejects internal subsets, arbitrary DTDs, comments, CDATA, namespaces,
attributes other than the canonical plist version, and trailing documents.
Standard/numeric character references are decoded before duplicate comparison.
Every dictionary rejects duplicates, including unknown keys. Scalar/collection
structure and scalar types are checked before required fields are selected.

Bounds are 128 KiB per XML body, 64 KiB decoded data, 4 KiB encoded string
content, 256-byte encoded keys, depth 8, and 512 markup events including end
tags/declarations. Data allows bounded base64 whitespace. No decompression or
binary parser exists. These are implementation limits, not Apple guarantees.

All parsed keys/scalars, partial trees, base64 scratch, decrypted bytes and
owned responses use RAII cleanup. Request/read buffers are allocated before
receiving secrets and never grown. A lexical markup whitelist prevents
quick-xml's internal tag stack/errors from holding remote values. HMAC/SHA/AES
state uses dependency zeroization features. This does not promise to erase
copies inside external HTTP/TLS/D-Bus libraries or operating-system buffers.

[operation request]: https://github.com/xtool-org/xtool/blob/4208c77c8128568f8b938d0c67d2f4bdcf04e100/Sources/XKit/GrandSlam/Requests/GrandSlamOperationRequest.swift


Evidence and unknowns
---------------------

On 12 September 2026, two explicitly authorized stored-session Xcode
`apptokens` attempts with the prior string-flag/compact representation ended
in HTTP errors. The second returned HTTP 404; the first numeric status was
not retained. No token was verified, and neither execution automatically
retried or started a new login. These observations do not identify the cause
or verify the revised request representation.

Protocol facts were independently implemented from SideStore's MPL-2.0
[request source] at `03beb1aa42991ccdad6214dee77e72282bef461f` and xtool's MIT
[AEAD framing] and [token schema] at
`4208c77c8128568f8b938d0c67d2f4bdcf04e100`. SideStore's response implementation
is incomplete and is not called. The independent OpenSSL fixture and Python
HMAC composition are documented in *tests/fixtures/apptokens/README.md*.

Apple Security pin `db15acbe6a7f257a859ad9a3bb86097bfe0679d9` supplies
[trust-operation semantics], not copied code or private wire schemas. The
Octagon investigation also examined pin
`97c3a4296c1ea06b0fe1877a7e616aa84450b5b2`; a possible recovery path without
joining remains unproven, including caller authorization and cryptography.

CloudKit service IDs/configuration, native RPC schemas/framing/compression,
Octagon/escrow cryptography and mutation effects, CKKS interoperability, GSA
session lifetime/error mappings, and token rotation/invalidation are deferred.
Synthetic vectors establish this implementation's contract, not a successful
Apple request. The roadmap's M2 checkboxes remain open.

[request source]: https://github.com/SideStore/apple-private-apis/blob/03beb1aa42991ccdad6214dee77e72282bef461f/icloud-auth/src/client.rs
[AEAD framing]: https://github.com/xtool-org/xtool/blob/4208c77c8128568f8b938d0c67d2f4bdcf04e100/Sources/XKit/GrandSlam/Crypto/AppTokens.swift
[token schema]: https://github.com/xtool-org/xtool/blob/4208c77c8128568f8b938d0c67d2f4bdcf04e100/Sources/XKit/GrandSlam/Operations/GrandSlamFetchAppTokensOperation.swift
[trust-operation semantics]: https://github.com/apple-oss-distributions/Security/blob/db15acbe6a7f257a859ad9a3bb86097bfe0679d9/keychain/TrustedPeersHelper/TrustedPeersHelperProtocol.h


Fresh-session validation
------------------------

On 12 September 2026, the reviewed live authentication harness successfully
stored and reloaded fresh GSA material without requiring 2FA. A separate
process then made one Xcode token request and stopped with the former generic
malformed-response error. The current control flow establishes HTTP 200 for
that failure, but does not establish which parser check failed, successful
AEAD verification, or token issuance. No response was retained and no retry
occurred. The new fixed-stage diagnostics have synthetic evidence only.


Plist failure categories
------------------------

A subsequent single request verified AES-GCM authentication/decryption using
the stored session key, then failed authenticated plist grammar validation.
This proves that part of session reuse, not valid token fields or expiry.

`MalformedPlist` now distinguishes fixed encoding, character, markup, XML event,
structure, duplicate-key, character-reference, scalar, integer, base64, real,
and date checks. `MalformedResponse` still describes later schema validation.
These categories contain no remote text, field name, offset, or excerpt. No
parser acceptance, size limit, or cryptographic behavior changes. Synthetic
tests verify classifications on outer and authenticated plaintext failures.
