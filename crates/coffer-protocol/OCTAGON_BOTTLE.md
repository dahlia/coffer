Offline Octagon bottle inspection
=================================

`octagon::bottle` inspects a bounded bottle envelope and checks two detached
signatures against the signing keys inside it. A bottle is an Octagon message
containing peer identifiers, public keys, and encrypted peer key material.
Inspection preserves its original bytes, including unknown fields.

`BottleSignatureConsistency` records only that the two signatures matched the
embedded keys. An attacker can replace the entire bottle, its keys, and both
signatures and still pass. Callers must establish trust, account/peer binding,
entropy binding, and freshness separately. The API does not establish bottle
viability, private-key possession, or permission to use a key.

There is no I/O, discovery, key generation, HKDF, recovery attempt, decryption,
trust join, storage, or serialization API. Neither the inspection result nor
its signature consistency result can initiate a server request. Live Apple
interoperability remains unverified.


API and ownership
-----------------

`BottleEnvelope::parse` borrows one raw protobuf Bottle after any transport
framing, compression, or base64 decoding has been removed. It first checks the
entire outer message and its one recognized nested contents message, then all
field lengths and identifiers, before calling `keys::PublicKey::from_spki_der`
for the four public keys. The structural checks allocate nothing and perform
no cryptography. The existing key parser may allocate after this preflight.

The ID and SPKI accessors return borrowed values without normalization.
`raw_bytes` exposes the original whole Bottle; `contents_bytes` exposes the
original nested message. Both retain unknown fields. `ciphertext`,
`authentication_code`, and `initialization_vector` expose separate opaque byte
slices. The API never concatenates them into a guessed encryption format.

`verify_embedded_signatures` first requires both DER signature lengths to be
8 through 104 bytes. It calls the existing ECDSA/SHA-384 verifier with the
original whole Bottle and the escrow signing key, then with the same bytes
and the peer signing key. The first failure ends the call; there is no retry,
alternate key, or algorithm fallback. The existing verifier checks canonical
DER and accepts both high-S and low-S signatures. Each signature is checked
at most once, and signature input is not retained.

Success borrows the inspected envelope through `BottleSignatureConsistency`.
The caller must retain the envelope and its backing input for the borrow's
lifetime. Both types redact ordinary and alternate `Debug`; neither implements
`Clone`, `Display`, or implicit serialization. Explicitly exposed bytes and IDs
can identify accounts or peers and must stay out of logs. Caller-owned input
storage is not wiped by these borrowed types.

Errors are fixed variants of `BottleError`, with static messages and no input
or dependency error payload. They distinguish limits, malformed/unsupported
wire, missing/duplicate fields, invalid identifiers/keys, malformed signature
encoding, and signature mismatch. Failure returns no partial result.


Wire subset and local limits
----------------------------

The public schema declares all Bottle fields below optional. Coffer's narrow
inspection profile requires each once because the observed creator populates
all of them. That local policy does not change the schema's requiredness.
All known fields use wire type 2 (length-delimited).

| Message                 | Field number | Value                                                                      |
| ----------------------- | ------------ | -------------------------------------------------------------------------- |
| Bottle                  | 1, 2         | `peerID`, `bottleID`: UTF-8 strings                                        |
| Bottle                  | 8, 9         | `escrowedSigningSPKI`, `escrowedEncryptionSPKI`: bytes                     |
| Bottle                  | 10, 11       | `peerSigningSPKI`, `peerEncryptionSPKI`: bytes                             |
| Bottle                  | 12           | `contents`: AuthenticatedCiphertext message                                |
| AuthenticatedCiphertext | 1, 2, 3      | Required bytes: `ciphertext`, `authenticationCode`, `initializationVector` |

The following are Coffer resource and acceptance policies, not Apple limits:

 -  Total input is 1 byte through 1 MiB, matching `keys::MAX_MESSAGE_LEN`.
 -  At most 64 field occurrences span the outer message and contents together.
 -  Each identifier is nonempty UTF-8 of at most 1,024 bytes. IDs are not
    normalized or checked against an account.
 -  Each SPKI is exactly 120 bytes, canonical named-curve P-384 DER with an
    uncompressed point, as required by the existing key primitive.
 -  Ciphertext shares the total input bound. Tag and IV are at most 64 bytes
    each. All three opaque fields may be empty, but must be present.
 -  Field numbers are 1 through 536,870,911. Keys, lengths, and unknown varint
    values must use minimal encodings without u64 overflow or truncation.
 -  Known singular fields cannot repeat, even with identical values or another
    wire type. Repeated contents messages cannot merge.
 -  Unknown wire types 0/1/2/5 are skipped within bounds and preserved in raw
    bytes, including repeated unknown numbers. Unknown length-delimited values
    are never parsed recursively. Only the known contents message is traversed,
    so recognized depth is two.
 -  Groups, invalid wire types, field zero, and reserved outer fields 3–7 are
    rejected. Lengths must fit the remaining slice before any slicing occurs.

General protobuf permits duplicate scalar fields and merges repeated embedded
messages. Coffer deliberately rejects those ambiguous representations for known
fields. The parser also rejects nonminimal varints rather than claiming full
protobuf compatibility. Field order remains unrestricted; reordering a message
requires signatures over the reordered bytes.

Empty tag/IV/ciphertext acceptance is structural only. The inspected Apple
source selects a 32-byte key and an AES-256 authenticated-encryption wrapper,
but does not specify its mode, nonce/tag lengths, or internal AAD behavior.
These fields are not validated as AEAD inputs. CKKS's AES-SIV layout and the
apptokens GCM envelope are not reused here.


Evidence and provenance
-----------------------

Protocol facts come from Apple's public Security repository at exact commit
`db15acbe6a7f257a859ad9a3bb86097bfe0679d9`, under
*keychain/TrustedPeersHelper*:

 -  [*proto/OTBottle.proto*] supplies the field numbers, types, optional fields,
    and reserved numbers.
 -  [*proto/OTAuthenticatedCiphertext.proto*] supplies the three required byte
    fields inside contents.
 -  [*BottledPeer/BottledPeer.swift*], lines 105–141 and 168–238, shows that the
    complete serialized Bottle is the message for both detached signatures and
    selects P-384/SHA-384/X9.62 ECDSA. Its creator fills all current fields.

SHA-256 of the fetched raw source bytes:

~~~~ text
b25f904d7c322faf587456f8f31871b94e3178e706f4bcb925f885965fb831a9  proto/OTBottle.proto
8c6988fead2f1b35e32c7f8c81255bfb8f3f99b68587e439ef307d165ba845b3  proto/OTAuthenticatedCiphertext.proto
ccb61a08d7f6c762c42c6597b8eaf19eb7d27e49eb18845acd4f0b2e78a85dea  BottledPeer/BottledPeer.swift
~~~~

These files carry APSL-2.0 notices and remain reference-only. Public access
and protocol observations do not grant permission to copy their source into
Coffer. No Apple schema, source, generated code, or fixture was incorporated,
translated, or adapted. The wire scanner and synthetic fixture recipe were
independently authored from field facts and the public
[protobuf encoding specification]. No rustpush, Sank6, or corecrypto source was
consulted.

The *BottledPeer.swift* hash is identical to the older pin documented in
*OCTAGON\_KEYS.md*. This supports reuse of the existing signature primitive; it
does not establish compatibility with a current Apple endpoint. The HKDF to
P-384 deterministic derivation and actual bottle decryption remain separate
research tasks, with no implementation or interoperability claim here.

Independent OpenSSL fixture provenance, reproduction instructions, and hashes
are in *tests/fixtures/octagon-bottle/README.md*. They test the local wire and
signature contract using public synthetic keys and opaque synthetic contents.
They are not Apple recovery, derivation, or decryption vectors.

[*proto/OTBottle.proto*]: https://github.com/apple-oss-distributions/Security/blob/db15acbe6a7f257a859ad9a3bb86097bfe0679d9/keychain/TrustedPeersHelper/proto/OTBottle.proto
[*proto/OTAuthenticatedCiphertext.proto*]: https://github.com/apple-oss-distributions/Security/blob/db15acbe6a7f257a859ad9a3bb86097bfe0679d9/keychain/TrustedPeersHelper/proto/OTAuthenticatedCiphertext.proto
[*BottledPeer/BottledPeer.swift*]: https://github.com/apple-oss-distributions/Security/blob/db15acbe6a7f257a859ad9a3bb86097bfe0679d9/keychain/TrustedPeersHelper/BottledPeer/BottledPeer.swift
[protobuf encoding specification]: https://protobuf.dev/programming-guides/encoding/
