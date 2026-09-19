Offline CKKS v2 item associated data
====================================

`coffer_protocol::ckks::item::build_associated_data` validates a complete
caller-supplied field inventory and constructs the associated data (AD) used
by a narrow CKKS v2 item subset. Callers can pass its ordered component view
to the existing `payload::decrypt` primitive with a separately selected item
key and envelope. This module does no cryptography or I/O.

The API checks the supplied metadata's structure. It cannot establish that an
adapter actually supplied every original field or preserved its wire type.
A caller must assert `FieldCompleteness::Complete` explicitly; incomplete
input fails. Never build the inventory by dropping unsupported fields,
collapsing duplicates in a map, or treating malformed input as absent.


Typed input contract
--------------------

`ItemId` supplies a record name and the existing `KeyScope`. The separate
record type must be exactly `item`. Scope includes account context, container,
environment, database, zone owner and zone name; all identifiers compare
exactly without normalization. The account context is caller-assigned metadata,
never an authentication token. The parent reference must carry the same scope.

A `Field` slice retains each name/value occurrence. The accepted names and
semantic value types are fixed:

| Name                | Presence | `FieldValue` | Rule                                        |
| ------------------- | -------- | ------------ | ------------------------------------------- |
| `parentkeyref`      | Required | `Reference`  | Full parent `KeyId`, same scope             |
| `wrappedkey`        | Required | `WrappedKey` | Exactly 80 decoded bytes                    |
| `data`              | Required | `Data`       | Envelope length from 32 bytes through 1 MiB |
| `gen`               | Required | `Integer`    | Checked nonnegative `u64` subset            |
| `encver`            | Required | `Integer`    | Exactly 2                                   |
| `pcsservice`        | Optional | `Integer`    | Checked nonnegative `u64` subset            |
| `pcspublickey`      | Optional | `Data`       | At most 64 KiB                              |
| `pcspublicidentity` | Optional | `Data`       | At most 64 KiB                              |
| `uploadver`         | Optional | `Text`       | At most 1,024 UTF-8 bytes; excluded from AD |

The PCS fields are separate plaintext item metadata; this module preserves
their supported byte representation without assigning credential semantics.
Missing PCS Data and present empty Data remain distinct. Absent fields add no
component, while present empty Data adds an empty component. The payload
primitive later omits empty AD values according to its existing contract.

This is an adapter contract, not a CloudKit wire schema. In particular,
`WrappedKey` carries decoded bytes. A future adapter must validate the original
`wrappedkey` field type and encoding before constructing that variant. The AD
builder does not parse base64, authenticate a wrapped key, or obtain an item
key. `Integer(i128)` allows explicit rejection of negative and above-`u64`
values. It does not coerce text, Boolean, float or date values; adapters must
not hide those types behind an integer conversion.

Every unknown name fails, even with an empty or unsupported value. This
includes `server_*`, `osver` and `UUID`. The record name comes only from
`ItemId`, so a field cannot replace it. `uploadver` is the exact published
literal for `SecCKRecordHostOSVersionKey`; `osver` is not an alias. Even the
ignored `uploadver` field is subject to duplicate, type and length checks.
This closed subset deliberately rejects records that a broader Apple reader
may support. Version 0, version 1 and other versions fail without fallback.


Component order and ownership
-----------------------------

The returned `ItemAssociatedData` borrows input names/Data and owns three
fixed integer encodings in zeroizing storage. It neither allocates secret
heap buffers nor copies borrowed byte values. `components()` constructs a
fixed-capacity `AdComponents` view. Its explicit `as_slice()` is suitable for
`payload::decrypt`; no implicit decryption or plaintext parsing occurs.

| ASCII AD key order  | Value bytes                                  |
| ------------------- | -------------------------------------------- |
| `UUID`              | Item record name in UTF-8                    |
| `encver`            | 2 as eight little-endian bytes               |
| `gen`               | Generation as eight little-endian bytes      |
| `pcspublicidentity` | Present Data, unchanged                      |
| `pcspublickey`      | Present Data, unchanged                      |
| `pcsservice`        | Present integer as eight little-endian bytes |
| `wrappedkey`        | Parent key record name in UTF-8              |

The AD value under `wrappedkey` is the parent name, not the 80 wrapped-key
bytes or their base64 encoding. Component boundaries remain distinct; the
builder never concatenates them. The fixed ASCII key set avoids a general
Foundation string ordering implementation. Non-ASCII identifier *values*
remain exact UTF-8 bytes.

Only these component values participate in payload authentication. Account,
container, zone and `uploadver` are not authenticated by this AD. Tests show
that consistent account rebinding leaves it unchanged. Supplying a structurally
matching scope does not prove account ownership, trusted key origin, freshness,
authorization or collection completeness. Supplying an incomplete inventory
while asserting completeness can also produce a cryptographic success; the
API cannot discover fields the caller omitted.

Inputs stay borrowed and unchanged on success and failure. The caller retains
responsibility for dropping/wiping its original buffers. Secret-bearing input
and result Debug output is fixed and redacted; errors contain only fixed
categories. Result/component views have no Clone, Display or serialization
convenience. The owned integer buffer is wiped on drop, without a guarantee
about all compiler-generated copies or stack temporaries.


Local resource limits
---------------------

Bounds are checked before the result and its encoded integers are constructed.
No input-controlled allocation, recursion, crypto attempt or retry occurs.

| Resource                      | Cap         |
| ----------------------------- | ----------- |
| Field occurrences             | 9           |
| Each identifier or Text value | 1,024 bytes |
| Field name/record type        | 64 bytes    |
| Each PCS Data value           | 64 KiB      |
| Aggregate supplied input      | 1 MiB       |
| Returned AD components        | 7           |

Aggregate accounting includes every string/byte occurrence, each integer as
16 bytes, one byte per field value tag and two bytes per scope's enums.
Repeated scopes count each time. Item identity, record type and every field
count, including fields excluded from AD. Checked arithmetic rejects overflow.
The aggregate cap can reject an envelope below its separate 1 MiB cap.
Identifiers must be nonempty; present optional Text/Data may be empty.
The fixed seven components and these caps remain below the payload API's AD
count, per-component and aggregate limits. These are Coffer policies, not
Apple service maxima or proof that the original wire decoder was bounded.


Evidence and tests
------------------

Protocol facts use Apple's public Security revision
`db15acbe6a7f257a859ad9a3bb86097bfe0679d9`:

 -  [*CKKSItem.m*, lines 283–378] selects versioned AD, encodes v2 base/PCS
    values, and distinguishes fields excluded from AD. Its broader extra-field
    behavior is outside this closed subset.
 -  [*CKKSConstants.m*, lines 36–46] supplies the exact field literals,
    including `uploadver` and the distinct `parentkeyref`/`wrappedkey` names.
 -  [*CKKSSIV.m*, lines 395–422] supplies nonce-first processing followed by
    separately submitted AD values in key order. The payload primitive already
    implements that composition.

These are protocol facts, not source code incorporated into Coffer. No Apple
source, schema, fixture or translated implementation was copied. Reference-only
rustpush/Sank6 implementations were not consulted. No corecrypto build or
execution is part of this change.

| Original pinned source | SHA-256                                                            |
| ---------------------- | ------------------------------------------------------------------ |
| *CKKSItem.m*           | `4dab212d9157519e2575f24849a57bc245b66da3094c454d8e14a43cd3402180` |
| *CKKSConstants.m*      | `8f593106b3291e81af676b6d3cdf4ca949f192292e07e54b2a9c75b71139db5c` |
| *CKKSSIV.m*            | `61fdef2d9c851903e13dadb08d4ac3d5b4119192ed840c859d778d758474ab8f` |

[Independent fixtures](tests/fixtures/ckks-item/README.md) use handwritten AD
bytes and the existing Coffer OpenSSL EVP recipe with an invented item key.
Positive fixtures cover all PCS fields, no PCS fields and present empty Data;
negative fixtures use nonce-last and concatenated AD. The decrypted bytes
match the existing synthetic Internet-password plist with explicit padding.
No class-key-to-item-key unwrap is added by these composition tests.

Rust tests additionally check all optional PCS combinations, permutations,
integer ranges, every known duplicate/wrong type, unknown empty fields,
identity/scope and input caps, every envelope truncation/byte mutation, explicit
redaction and owner lifetime. Malformed inventory returns no partial AD.
These results do not establish live Apple interoperability, complete CKKS
record coverage, CloudKit transport, trusted key recovery or an authenticated
account-to-credential path.

[*CKKSItem.m*, lines 283–378]: https://github.com/apple-oss-distributions/Security/blob/db15acbe6a7f257a859ad9a3bb86097bfe0679d9/keychain/ckks/CKKSItem.m#L283
[*CKKSConstants.m*, lines 36–46]: https://github.com/apple-oss-distributions/Security/blob/db15acbe6a7f257a859ad9a3bb86097bfe0679d9/keychain/ckks/CKKSConstants.m#L36
[*CKKSSIV.m*, lines 395–422]: https://github.com/apple-oss-distributions/Security/blob/db15acbe6a7f257a859ad9a3bb86097bfe0679d9/keychain/ckks/CKKSSIV.m#L395
