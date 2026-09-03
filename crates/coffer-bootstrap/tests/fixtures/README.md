Synthetic APK signing fixtures
==============================

The hexadecimal files in this directory are a 2048-bit RSA PKCS#1 private key
and its self-signed X.509 certificate.  They were generated specifically for
Coffer's deterministic APK Signature Scheme v2 tests and contain no Apple or
third-party bytes.

The fixtures are test-only.  Their private key provides no trust outside the
test suite, and production verification remains pinned to Apple's reviewed
certificate and SubjectPublicKeyInfo digests in *src/signature.rs*.

*independent-v2-valid.apk.hex* is a 1024-bit synthetic APK generated
independently during the 2026-09-04 signature audit with Python's standard ZIP
support, explicit format assembly, and OpenSSL.  It exercises the legacy RSA
key-size path and is kept separate from the Rust generator so an encoding
mistake shared by the generator and verifier cannot validate itself.  Its
decoded SHA-256 is
`226e762a935149fee428369eaeeb4623e784e19e1a7bb7085535da476167230c`.
