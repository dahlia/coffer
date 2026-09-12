Offline CKKS plaintext fixtures
===============================

These files contain invented public data. They are not captured Apple records
and contain no account credentials. Codex (`gpt-6-astra`) independently wrote
the recipe and Rust tests from the format facts recorded in the coordinator's
CKKS plaintext decision and parser plan on 12 September 2026. No Apple,
`plist`, Python-library, rustpush, Sank6 or corecrypto implementation was read,
copied or translated during this implementation.

The format facts are attributed to Apple's public CF revision
`dc54c6bb1c1e5e0b9486c1d26dd5bef110b20bf3`, specifically the
[object format description] and [header/trailer definition]. The CKKS padding
and field facts are attributed to the decision report's Security revision
`db15acbe6a7f257a859ad9a3bb86097bfe0679d9`. Those are evidence pins, not source
code incorporated into this GPL-3.0-or-later implementation. The recipe uses
the [public Python plistlib API] and is newly written Coffer code, without
copying documentation examples or library internals.

[object format description]: https://raw.githubusercontent.com/apple-oss-distributions/CF/dc54c6bb1c1e5e0b9486c1d26dd5bef110b20bf3/CFBinaryPList.c
[header/trailer definition]: https://raw.githubusercontent.com/apple-oss-distributions/CF/dc54c6bb1c1e5e0b9486c1d26dd5bef110b20bf3/ForFoundationOnly.h
[public Python plistlib API]: https://docs.python.org/3/library/plistlib.html


Exact fixtures and expectations
-------------------------------

Both files are *unpadded* `bplist00`. Tests explicitly add `0x80` and trailing
zeros before invoking the private byte parser. Public parsing accepts only a
borrow of the existing `PayloadPlaintext` owner after successful decryption.

| File           | Bytes | SHA-256                                                            |
| -------------- | ----- | ------------------------------------------------------------------ |
| *small.bplist* | 51    | `9da3d3006e097a8f9ccc4ca9fa10b89a5aed734c3428fa8fe1cf599636a18ebd` |
| *inet.bplist*  | 230   | `fd475d545b0c946a5002a938b43e63f92b95f7823560f189c44a6acc724372b1` |

*small.bplist* represents one key `k` and Data bytes `00 ff`. Its byte layout
was calculated before implementation: header at bytes 0–7, root dictionary
`d1 01 02` at 8–10, ASCII `51 6b` at 11–12, Data `42 00 ff` at 13–15,
offsets `08 0b 0d` at 16–18, and the 32-byte trailer at 19–50. The trailer
has widths 1/1, object count 3, root index 0 and offset-table position 16.
The test checks every byte against that hand layout, independently of the
runtime test builder.

*inet.bplist* has eight fields defined in the recipe below. Its candidate has
account `fixture-reader-한😀`, server `login.example.invalid`, protocol `htps`,
password bytes `00 ff 80 00 41` and explicit integer-zero tomb. The account
exercises UTF-16 BMP and supplementary characters. `binn` remains opaque Data
even though its bytes start with `bplist00`; `unknown` remains an uninterpreted
text field. This synthetic subset provides no sidecar, metadata-join, complete
record-retrieval or live Apple interoperability evidence.


Independent recipe
------------------

Executed offline with Python 3.14.7. This is an opt-in reproduction recipe, not
new project tooling or a dependency of CI. From the repository root:

~~~~ python
from pathlib import Path
import hashlib
import plistlib

root = Path("crates/coffer-protocol/tests/fixtures/ckks-plaintext")
small = plistlib.dumps(
    {"k": bytes([0, 255])}, fmt=plistlib.FMT_BINARY, sort_keys=True
)
hand = bytes.fromhex(
    "62706c6973743030d10102516b4200ff080b0d"
    "0000000000000101000000000000000300000000000000000000000000000010"
)
assert small == hand and len(small) == 51
inet = plistlib.dumps(
    {
        "class": "inet",
        "acct": "fixture-reader-한😀",
        "srvr": "login.example.invalid",
        "ptcl": "htps",
        "v_Data": bytes([0, 255, 128, 0, 65]),
        "tomb": 0,
        "binn": b"bplist00\x00\xff",
        "unknown": "opaque-sentinel",
    },
    fmt=plistlib.FMT_BINARY,
    sort_keys=True,
)
for name, data in {"small.bplist": small, "inet.bplist": inet}.items():
    (root / name).write_bytes(data)
    print(name, len(data), hashlib.sha256(data).hexdigest())
~~~~


Validation boundaries
---------------------

Rust tests consume the static Python fixtures and use a separate hand-assembly
helper for policy boundaries and malformed inputs. They cover count markers,
reference/offset widths, nonzero roots and reordered IDs, gap-free disjoint
object spans, unsupported/unused objects, duplicate decoded keys, shared values,
UTF-16 surrogate failures, raw scalar fidelity and every local resource cap.
A late invalid object returns no partial view. The tomb tests distinguish
missing, integer zero and integer one; missing or integer one prevents candidate
projection. Unknown classes, wrong types and unsupported protocols remain
projection failures distinct from malformed binary layout.

A composition test encrypts invented plaintext using existing RustCrypto
primitives, calls the actual payload decrypt function, then explicitly parses
the returned owner. This is local composition evidence, not an independent
cryptographic oracle. Parsing failure leaves the owner unchanged, and the test
explicitly drops it. Authentication failure prevents the parser call.

The production parser/projection use fixed metadata and borrowed bytes. Their
source/type/API audit finds no dynamic allocation, owned text conversion or
recursive descent. A compile-time assertion checks the concrete view, object
descriptor and fixed sorting-index storage against 64 KiB. Tests do not install
a global allocator, add dependencies or weaken the prohibition on unsafe code.
Runtime allocation counting, compiler peak-stack measurement and erasure of
every compiler-generated copy are unverified. Rustdoc compile-fail examples
exercise the owner lifetime and absence of convenience exports.
