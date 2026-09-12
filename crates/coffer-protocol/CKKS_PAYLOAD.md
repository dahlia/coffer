Offline CKKS payload decryption
===============================

`coffer_protocol::ckks::payload::decrypt` authenticates one supplied CKKS item
envelope with an already
selected 64-byte AES-256-SIV key. It performs no I/O. Its result is an opaque
plaintext buffer, not a website credential or a validated keychain record.
The returned `PayloadPlaintext::expose_secret` explicitly borrows the bytes.
The caller remains responsible for key/account/record binding, authenticated
metadata construction, freshness and authorization.


Composition and limits
----------------------

The envelope is a 16-byte nonce, a 16-byte SIV authentication tag, and the
ciphertext. Empty plaintext is supported; every envelope still contains the
nonce and tag. The caller supplies already serialized associated-data values
in their required order. The nonce is the first S2V component, followed by each
nonempty associated-data value as a separate component. Empty values are
omitted. Components are never concatenated, sorted, normalized or retried in a
different order after a failure.

These are local defensive limits, not advertised Apple service maxima:

| Input                                      | Limit                  |
| ------------------------------------------ | ---------------------- |
| Entire envelope                            | 32 bytes through 1 MiB |
| Supplied AD values, including empty values | 125                    |
| Each AD value                              | 64 KiB                 |
| Aggregate AD bytes                         | 1 MiB                  |

All bounds are checked before plaintext allocation or cryptography. The nonce
adds one component to the at most 125 supplied values, keeping within RFC 5297's
126-header limit. Caller-owned buffers are borrowed and remain unchanged.
On authentication failure no plaintext is returned. Working and returned
plaintext use zeroizing ownership; the key and plaintext have redacted Debug
and no implicit cloning or serialization. Existing AES/SIV/CMAC zeroization
features remain enabled. This does not guarantee erasure of every temporary
inside dependencies or every compiler-generated copy.


Protocol evidence
-----------------

Apple's published [CKKSSIV.m] at Security revision
`db15acbe6a7f257a859ad9a3bb86097bfe0679d9` prefixes a 16-byte nonce to the
SIV output. Its context calls submit the nonce first, then each dictionary
value separately in key order. Only these protocol facts are used here;
Apple source, schemas and tests were not copied or translated. This byte-slice
API does not implement Foundation dictionary ordering, NSNumber/date
serialization, CKRecord fields, plaintext decoding or metadata sidecars.

A separately approved internal synthetic verification of corecrypto revision
`9612a959abb6eac0aac3ee6a7245c46365c9d81b` checked nonce order, separate AD
components and omission of zero-byte nonce/AD calls against independently
written OpenSSL/RustCrypto drivers. The selected unchanged C sources were built
outside Coffer with assembly disabled and network access isolated. An
independent Codex gpt-6-astra review checked the drivers and result assertions.
The source archive and build outputs were deleted at the end of that exercise.
Corecrypto is not a Coffer dependency, test oracle or distributed artifact.

That exercise found a discrepancy when plaintext and every effective nonce/AD
component were absent. It did not establish general algorithm equivalence.
The present envelope always supplies a nonempty 16-byte nonce, including for
empty plaintext, so that combination cannot occur. The experiment was limited
to synthetic inputs and does not establish live Apple record compatibility.

Repository fixtures are generated independently with OpenSSL using public,
invented keys, nonce, AD and plaintext. They are not copied corecrypto outputs
or captured Apple records. Their recipes and hashes are documented in
<tests/fixtures/ckks-payload/README.md>.
Normal tests use static fixtures and existing RustCrypto primitives; they do
not build corecrypto, contact Apple or require OpenSSL execution.

[CKKSSIV.m]: https://github.com/apple-oss-distributions/Security/blob/db15acbe6a7f257a859ad9a3bb86097bfe0679d9/keychain/ckks/CKKSSIV.m


Remaining integration boundary
------------------------------

A future record adapter must validate the complete metadata schema, preserve
required opaque fields and construct every authenticated-data value correctly
before calling this component. Successful decryption alone does not prove
that the adapter included all required metadata. Unsupported serialization
must fail explicitly; dropping an unknown nonempty field is not safe.

This subset neither obtains an item key nor discovers a trusted root. It does
not retrieve or parse CloudKit records, decode website passwords or sidecars,
join trust, enumerate escrow records, attempt recovery, or mutate credentials.
The M2 account-to-typed-credential API and its live validation remain
incomplete.
