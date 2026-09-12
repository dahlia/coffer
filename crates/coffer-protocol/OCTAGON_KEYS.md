Offline Octagon key primitives
==============================

`octagon::keys` validates P-384 key encodings and ECDSA/SHA-384 signatures
without I/O. It provides offline serialization/verification primitives, not a
complete Octagon identity. A valid key or signature does not establish peer
identity, account ownership, trust, or permission to decrypt a record.

This subset has no signing, key generation, peer ID, protobuf, bottle,
recovery, trust mutation, session, storage, or network API. Live Apple
interoperability remains unverified. The deterministic fixtures cover only
this serialization/verification subset; they do not validate a complete
Octagon peer identity or trust operation.


API and limits
--------------

`PublicKey::from_sec1_bytes` accepts exactly 97 bytes: `04 || X || Y`, with
48-byte big-endian coordinates. RustCrypto validates that the point belongs
to P-384. Infinity, compressed/hybrid points, invalid coordinates, and wrong
lengths fail with a static error.

`PublicKey::from_spki_der` accepts exactly 120 bytes of canonical DER
SubjectPublicKeyInfo (SPKI), with `id-ecPublicKey`, the `secp384r1` named-curve
OID, and an uncompressed point. The size check precedes parsing. RustCrypto
parses ASN.1 and checks algorithm/curve identifiers; re-encoding must match
the input exactly. Trailing, duplicate, indefinite-length, or non-minimal DER
is rejected. These are deliberately narrow format choices, not a general
certificate or EC key parser.

`PrivateKey::from_apple_full` consumes `Zeroizing<Vec<u8>>` containing exactly
145 bytes of Apple's full private encoding, `04 || X || Y || D`. It validates
both the point and scalar, requires `1 <= D < n`, derives the public point with
RustCrypto, and rejects a mismatch. The type retains the validated encoding in
zeroizing storage and exposes the matching public key by borrow. It does not
turn that key into an identity or expose an API for cryptographic operations
using D.

`PublicKey::verify_sha384` hashes the exact message with the workspace's
zeroizing SHA-384 implementation and passes the resulting 48-byte digest to
RustCrypto's ECDSA prehash verifier. It accepts only canonical DER signatures
of 8 through 104 bytes, with two positive, nonzero INTEGERs below the curve
order. Both high-S and low-S signatures are accepted, as the independent
OpenSSL fixtures test; Apple's normalization policy is not established here.
The message limit is 1 MiB, checked before hashing. This is a local resource
policy, not a claim about an Apple protocol limit.

`to_sec1_bytes`, `to_spki_der`, and `expose_secret` explicitly disclose bytes
for subsequent serialization. Public encodings can identify an account or
peer and must not enter logs. Private bytes must never be logged and require
protected storage if persisted. Both key types redact ordinary and alternate
`Debug`; neither implements `Display`, `Clone`, or an implicit serializer.
Errors have static messages and retain no input or dependency error payload.

The consumed input, stored private encoding, temporary RustCrypto secret key
and nonzero scalar, and SHA-384 digest are zeroized on drop. Caller-owned
copies remain the caller's responsibility. This does not promise erasure of
every compiler copy or intermediate inside external cryptographic code. Drop
private keys promptly.


Independent evidence
--------------------

The implementation uses protocol facts from Apple's Security repository at
commit `97c3a4296c1ea06b0fe1877a7e616aa84450b5b2`, tagged
`Security-61901.120.67`:

 -  [*BottledPeer.swift*]
    selects P-384, SHA-384, and X9.62 signatures in `signingOperation`, and
    uses SPKI for public keys.
 -  [*EscrowKeys.swift*]
    passes the exported full P-384 key encoding to `SecKeyCreateWithData`.
 -  [*SecKey.h*]
    documents the external EC format for `SecKeyCreateWithData` and
    `SecKeyCopyExternalRepresentation`, and explicitly identifies DER X9.62
    with automatic SHA-384 hashing for the corresponding signature algorithm.

These facts were corroborated against [SEC 1 v2.0 section 2.3.3]
for point encoding, [RFC 5480]
for SPKI and named curves, and [RFC 3279 section 2.2.3]
for the ECDSA signature structure. RFC 3279 supplies the structure, not the
SHA-384 choice. Apple's header supplies that algorithm fact. The private
145-byte length follows from the full encoding and P-384's 48-byte fields.

Apple's cited files carry APSL-2.0 notices and remain reference-only. No Apple
source, schema, fixture, or translated implementation enters this GPL project.
The restricted rustpush and Sank6 implementations were not consulted. All
Coffer code and synthetic fixtures were independently authored from these
facts using existing cryptographic libraries.

SHA-256 of the original references fetched for this implementation:

~~~~ text
ccb61a08d7f6c762c42c6597b8eaf19eb7d27e49eb18845acd4f0b2e78a85dea  BottledPeer.swift
0e383f5ef8f4fd9df7846b4c3f6c1ea0099f4a3ad7c91d096501a05c481e9399  EscrowKeys.swift
2cba3b0d904c00560c1f7d4d7efb163d75a1aa941bb40b7ef851723806f6d3a0  SecKey.h
54687189af3de645756a30a801b596fd14c6566992c13bfd58eede399f324a89  sec1-v2.pdf
87b8f3703364ed5b21ba8582e411cc0cbf477bcaa3f4f45e0d6580d1c00d9952  sec2-v2.pdf
593bf29fd0da2ff8b903c3ebf1c9d189a770039159e2ba46a0c3b91355037f26  rfc5480.txt
6d3f19f18e17fa1c68da5aaf4021327748fabca840d7300443b77357a1fc1614  rfc3279.txt
~~~~

[*BottledPeer.swift*]: https://github.com/apple-oss-distributions/Security/blob/97c3a4296c1ea06b0fe1877a7e616aa84450b5b2/keychain/TrustedPeersHelper/BottledPeer/BottledPeer.swift
[*EscrowKeys.swift*]: https://github.com/apple-oss-distributions/Security/blob/97c3a4296c1ea06b0fe1877a7e616aa84450b5b2/keychain/TrustedPeersHelper/BottledPeer/EscrowKeys.swift
[*SecKey.h*]: https://github.com/apple-oss-distributions/Security/blob/97c3a4296c1ea06b0fe1877a7e616aa84450b5b2/keychain/headers/SecKey.h
[SEC 1 v2.0 section 2.3.3]: https://www.secg.org/sec1-v2.pdf
[RFC 5480]: https://www.rfc-editor.org/rfc/rfc5480
[RFC 3279 section 2.2.3]: https://www.rfc-editor.org/rfc/rfc3279#section-2.2.3


Dependency and verification
---------------------------

The coordinator added one direct dependency, `p384 = "=0.13.1"`, with
`default-features = false` and `ecdsa/pkcs8/alloc`. Its published license is
`Apache-2.0 OR MIT`. The registry archive SHA-256 is
`fe42f1670a52a47d448f14b6a5c61dd78fce51856e68edaa38f7ae3a46b8d6b6`;
its crate VCS record identifies RustCrypto/elliptic-curves commit
`409fd29e00f91cea6cb4f7b632326670e0162388`.

On 12 September 2026, the latest stable release in the registry was 0.14.0.
That release's feature unification enables a `hybrid-array` trait
implementation which breaks the existing pinned SRP dependency's
Array-versus-slice method resolution. The exact 0.13.1 pin keeps its arithmetic
dependency series separate without patching authentication code. Revisit the
pin after the SRP compatibility issue is resolved. The existing SHA-384 and
zeroize dependencies are reused; ASN.1, SEC1, SPKI, and ECDSA APIs come through
RustCrypto reexports. No primitive, ASN.1 parser, or elliptic-curve arithmetic
is implemented by Coffer.

Independent OpenSSL vectors, published RFC 6979 P-384/SHA-384 verification
vectors, reproduction recipes, and byte hashes live in
<tests/fixtures/octagon-keys/README.md>.
Tests cover byte-exact public/private exports, both S ranges, altered messages
and signatures, wrong curves and keys, scalar/point/binding errors, redaction,
length limits, and malformed DER. They truncate each valid format at every
byte boundary. Run the focused test with the pinned toolchain:

~~~~ sh
mise exec -- cargo test --locked -p coffer-protocol --test octagon_keys
~~~~
