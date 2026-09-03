Authentication test fixtures
============================

Every file in this directory is synthetic. None was captured from a live
Apple Account, and none contains a real credential, token, identifier, or
anisette value. Values that look like tokens are labelled `SYNTHETIC` or
`not-real` in the data itself.


Provenance
----------

The wire shapes (property-list envelope, dictionary keys, `Status`
semantics, `spd` encryption) are protocol facts corroborated against
SideStore's MPL-2.0 `icloud-auth` and `omnisette` sources and against public
specifications (RFC 5054, RFC 2945, RFC 8018, Apple's public corecrypto
`ccsrp.h`). No fixture bytes were copied from any upstream repository.


How the fixtures were generated
-------------------------------

*tests/support/mod.rs*, module `vector`, defines fixed synthetic inputs (an
account name, a password, a 16-byte salt, an iteration count, and fixed 32-byte
SRP ephemerals `a` and `b`) and derives every output with the `srp` crate's
*server* side, which is an independent implementation of the arithmetic the
client under test relies on. The encrypted `spd` is produced by encrypting a
synthetic dictionary under the key and IV derived from `K`.

Regenerate the derived files by running the ignored test with an explicit
output directory. The generator never writes into the source tree on its own.
Cargo runs the test from the crate directory, so pass an absolute path:

~~~~ sh
COFFER_FIXTURE_OUT="$PWD/crates/coffer-protocol/tests/fixtures" \
  cargo test -p coffer-protocol --test wire_vectors -- --ignored write_fixtures
~~~~

The regular tests compare the committed files byte for byte against a fresh
computation, so a stale fixture fails the suite.


Files
-----

### *srp/apple\_srp\_vector.txt*

`name = hex` lines with the vector inputs and outputs: the `s2k` password key,
`A`, `B`, `M1`, `M2`, `K = H(S)`, the `spd` key and IV, and the `spd` plaintext
and ciphertext.

### *gsa/init\_request.plist*, *gsa/complete\_request.plist*

Golden request bodies for the `init` and `complete` GSA requests as this crate
serializes them for the vector above with the synthetic anisette data from
*tests/support/mod.rs*. Byte-exact.

### *gsa/init\_response.plist*

A successful `init` response carrying the vector's salt, `B`, iteration count,
and cookie.

### *gsa/init\_response\_error.plist*

An `init` response with HTTP-200 semantics but a non-zero `ec`. The code and
message are arbitrary synthetic values, not a recorded Apple error.

### *gsa/complete\_response\_authenticated.plist*

A successful `complete` response with `M2` and the encrypted `spd` and no
`au`, representing an account without a second factor.

### *gsa/complete\_response\_2fa.plist*

The same with `au = trustedDeviceSecondaryAuth`.

### *gsa/complete\_response\_unknown\_step.plist*

The same with a synthetic unknown `au` value.

### *gsa/validate\_ok.plist*, *gsa/validate\_rejected.plist*

Top-level `ec`/`em` responses of the validate endpoint. The rejection code is
synthetic.
