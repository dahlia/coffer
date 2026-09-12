Offline CKKS plaintext views
============================

The plaintext component explicitly interprets a borrowed authenticated
`PayloadPlaintext` as a restricted CKKS binary property list. It does not
fetch records or establish the key, account, metadata, freshness or trust
claims required to retrieve credentials. The caller must have selected this
representation deliberately; raw AES-SIV success alone does not identify a
CKKS dictionary.


Representation and ownership
----------------------------

The parser first bounds its input, then removes the final `0x80` marker and
following zero padding. It does not enforce the writer's block-length policy
on the reader. The resulting bytes must be exactly the supported `bplist00`
format. There is no XML, DER, compression or alternate-format fallback.

The supported graph is one root dictionary whose keys are strings and whose
values are scalars. Data, ASCII strings, well-formed big-endian UTF-16 strings,
raw integers, raw reals, raw dates and booleans remain distinct. Integer widths
and floating-point bits are preserved. Bytes inside a Data value are not
recursively interpreted, even if they resemble another plist, DER or JSON.

Views borrow ranges from the existing zeroizing payload owner. UTF-16 is
validated and exposed through a character iterator, without an owned decoded
String. Parsing and projection do not create decoded secret heap buffers.
The caller still owns the original plaintext after an error and must drop it
when no longer needed. Borrowing the buffer cannot erase it on the caller's
behalf. Secret-bearing views and errors have redacted output.

Dictionary key/value references may share a scalar object; the root cannot
be referenced as a scalar. Distinct object IDs with
overlapping byte spans, unreferenced objects, nested containers, unknown
markers and unsupported widths are outside this initial subset. All object
extents, references, scalar encodings, keys and limits are checked before a
complete view is returned. Dictionary keys compare decoded characters exactly;
ASCII and UTF-16 spellings of the same key are duplicates. No case folding or
Unicode normalization occurs.


Local resource limits
---------------------

These limits describe Coffer's subset, not Apple service maxima:

| Resource                       | Hard cap  |
| ------------------------------ | --------- |
| Padded plaintext input         | 1 MiB     |
| Dictionary pairs               | 256       |
| Objects, including the root    | 513       |
| Encoded scalar body            | 256 KiB   |
| Encoded key body               | 256 bytes |
| Fixed metadata storage         | 64 KiB    |
| Recursive child containers     | 0         |
| Decoded secret heap allocation | 0         |

The payload decryptor's envelope limit additionally bounds the plaintext it
can produce to 1 MiB minus 32 bytes. Geometry arithmetic is checked before
indexing. Supported offset/reference widths are 1, 2, 4 and 8 bytes. The object
spans must cover the object region without gaps or overlaps, and the offset
table must end exactly at the trailer. These are deliberately narrow layout
rules; unsupported input may still be a valid Apple item.

The metadata storage budget is for fixed descriptors and indices. It is not a
guarantee about every compiler-generated stack copy or peak stack usage on
all targets. No runtime allocator or post-free memory observation is implied
by the ownership contract.


Internet password projection
----------------------------

Structural parsing and semantic projection are separate. A narrow Internet
password candidate requires exact `class=inet`, a string account (which may
be empty), a nonempty string server, string protocol `http` or `htps`, and
Data `v_Data` password bytes. Password bytes may be empty, contain NUL or be
non-UTF-8. No lossy text conversion is performed.

Tombstone state distinguishes a missing field, integer zero and integer one.
Boolean/real/string lookalikes and other integers are not coerced. Missing or
deleted state must not silently become an active credential. Unknown record
classes, unsupported protocol representations and missing/wrong field types
remain distinguishable from malformed binary layout.

The raw entries remain available independently of that projection. Unknown
validated scalar fields are preserved with their original kind and encoding.
This does not interpret port/path semantics, normalize server names, construct
URLs/origins, select titles/notes, decode `binn`/`bini`/`bin0` through `bin3`,
or join sidecars. Plaintext UUID/PCS/sync fields do not replace caller-supplied
record identity or authentication evidence.


Provenance and verification boundary
------------------------------------

Apple Security revision `db15acbe6a7f257a859ad9a3bb86097bfe0679d9` provides
these observed facts:

 -  [CKKSItemEncrypter.m] serializes dictionaries as binary property lists,
    adds marker/zero padding, and removes it before reading on decryption.
 -  [CKKSOutgoingQueueEntry.m] chooses sync attributes and adds the class;
    UUID and PCS handling are separate from the plaintext dictionary.
 -  [SecItemSchema.c] and [SecDbItem.c] show that nominal schema types do not
    imply a single plaintext runtime type for every field.

Binary plist marker/count/offset/trailer facts come from [CFBinaryPList.c]
at CF revision `dc54c6bb1c1e5e0b9486c1d26dd5bef110b20bf3`. Only format and
field facts support this independently designed subset. Apple implementation,
schema declarations and tests are not copied or translated. Reference-only
implementations and proprietary binaries are not used.

The existing locked `plist` 1.10.0 reader is unsuitable for this secret path:
it allocates ordinary owned scalar buffers, and its successful UTF-16 path
can discard an intermediate buffer before the caller receives the event.
A bounded preflight cannot transfer ownership of that discarded buffer to a
zeroizing caller. The library remains in use for existing purposes; no vendor
patch or dependency change is part of this component.

Independent Python-generated and hand-checked synthetic fixtures are described
in [the fixture README](tests/fixtures/ckks-plaintext/README.md). They verify
the selected local format and projection policy. They are not captured Apple
credentials or evidence of live CKKS interoperability. The account-to-credential
API, complete website-record coverage and sidecar semantics remain unfinished.

[CKKSItemEncrypter.m]: https://github.com/apple-oss-distributions/Security/blob/db15acbe6a7f257a859ad9a3bb86097bfe0679d9/keychain/ckks/CKKSItemEncrypter.m
[CKKSOutgoingQueueEntry.m]: https://github.com/apple-oss-distributions/Security/blob/db15acbe6a7f257a859ad9a3bb86097bfe0679d9/keychain/ckks/CKKSOutgoingQueueEntry.m
[SecItemSchema.c]: https://github.com/apple-oss-distributions/Security/blob/db15acbe6a7f257a859ad9a3bb86097bfe0679d9/keychain/securityd/SecItemSchema.c
[SecDbItem.c]: https://github.com/apple-oss-distributions/Security/blob/db15acbe6a7f257a859ad9a3bb86097bfe0679d9/keychain/securityd/SecDbItem.c
[CFBinaryPList.c]: https://github.com/apple-oss-distributions/CF/blob/dc54c6bb1c1e5e0b9486c1d26dd5bef110b20bf3/CFBinaryPList.c
