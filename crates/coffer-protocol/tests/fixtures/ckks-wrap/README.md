Synthetic CKKS wrapped-key vectors
==================================

These files are independently generated AES-256-SIV key-wrapping vectors, not
captured Apple records. They contain no real key, account, credential, nonce,
identifier, or response. Each hex file encodes 80 bytes, followed by a newline.

The selected protocol facts come from Apple's *CKKSSIV.h* and *CKKSSIV.m* at
[Security commit db15acbe][apple]: a 64-byte key, 80-byte wrapped key, and the
key-wrapping operation's absent nonce and associated-data list. Only those
facts were used. No Apple source/schema or reference-only implementation was
copied or translated. Item encryption is a different format and is excluded.

[RFC 5297] defines the SIV tag followed by ciphertext. The original wrapping
key is two 32-byte keys: MAC first, encryption second. An empty list of AD
components is not the same as one empty component. The API uses the former.

The synthetic keys are `A = 00..3f`, `B = 40..7f`, and `C = 80..bf`:

| File             | Wrapping key | Plaintext key | AD components             |
| ---------------- | ------------ | ------------- | ------------------------- |
| *child.hex*      | A            | B             | none                      |
| *grandchild.hex* | B            | C             | none                      |
| *self.hex*       | A            | A             | none                      |
| *with-ad.hex*    | A            | B             | one: ASCII `SYNTHETIC-AD` |

The last file is a negative vector for the no-AD primitive. Self-unwrapping
requires the existing key and does not bootstrap trust. The two-level vector
checks explicit crypto composition, not parent UUID/class/account validation.

The graph regression tests in *src/ckks/hierarchy/tests.rs* reuse these
unchanged bytes with independently invented metadata. Key A is the selected
self-wrapped TLK, B can be a historical TLK below A, and C a Class A/C key
below B. Other tests bind B directly as a Class A/C child of A. Record names
such as `root`, `old-tlk` and `old-class`, and every account/container/zone
value, are synthetic. No source implementation or captured metadata supplied
these graph fixtures. Rebinding tests deliberately reuse B under different
valid names/classes to show that no-AD authentication does not authenticate
those metadata claims. See [*CKKS.md*](../../../CKKS.md) for the bounded
offline graph contract.

Generation on 12 September 2026 used OpenSSL 3.5.8 (25 August 2026) through
Python ctypes and system libcrypto's EVP interface, independently of
RustCrypto. To reproduce each row, fetch `AES-256-SIV` with `EVP_CIPHER_fetch`,
create a fresh context, and call `EVP_EncryptInit_ex` with the 64-byte wrapping
key and NULL IV. For the negative vector only, call `EVP_EncryptUpdate` with
NULL output and the AD bytes once. For all rows, call `EVP_EncryptUpdate` with
the 64 plaintext bytes once, require 64 output bytes, then call
`EVP_EncryptFinal_ex` and require zero additional bytes. Obtain the 16-byte tag
using `EVP_CIPHER_CTX_ctrl` with `EVP_CTRL_AEAD_GET_TAG` (`0x10`), concatenate
tag then ciphertext, and encode as lowercase hex plus newline. Free the context
and fetched cipher. No empty AD or nonce update is made for positive vectors.
See the [OpenSSL AES documentation][openssl].

The library uses crates.io `aes-siv` 0.8.0 and `cmac` 0.8.0 with their
zeroization features, plus the existing AES implementation with zeroization.
The additional transitive package is `dbl` 0.5.0. Their licenses are
MIT/Apache-2.0. No existing package version changed. Although `aes-siv` defaults
are disabled, its internal `aead` default enables the already locked
`rand_core` 0.10.1 traits through `crypto-common`. Feature unification exposes
that dependency in the local anisette closure. Its reviewed crates.io package
has no dependencies, feature flags, or OS/network entropy backend; the graph
check permits this name while continuing to reject `getrandom` there. No
vendored source or provenance hash changed.

SHA-256 checksums:

 -  *child.hex*:
    `d51a986091b85f614b751b7edd7be2ccce1f8cd28c263b92b7322c40e35ec0c3`
 -  *grandchild.hex*:
    `8cf3bcd11e4df6eb09e2e7e350cb25ef3e51e10604d81babac9d7d5e6afa9b74`
 -  *self.hex*:
    `f8d849c7cb4dc9412fee86796a4b63ab0a9d1a96a21f63d811d5d7b3fc090d73`
 -  *with-ad.hex*:
    `dc176124ef46571f7a1295abefd8ec7a2458bc99f991f8dd756b907ff35e5bae`

The tests compare exact decrypted keys with the independent inputs, corrupt
every byte of a wrapped key, reject wrong keys and all truncated lengths, and
verify the caller's input remains unchanged. These vectors verify the chosen
RFC composition and implementation. They do not establish Apple corecrypto
interoperability or live CKKS compatibility.

[apple]: https://github.com/apple-oss-distributions/Security/blob/db15acbe6a7f257a859ad9a3bb86097bfe0679d9/keychain/ckks/CKKSSIV.m
[RFC 5297]: https://www.rfc-editor.org/rfc/rfc5297
[openssl]: https://docs.openssl.org/3.5/man7/EVP_CIPHER-AES/
