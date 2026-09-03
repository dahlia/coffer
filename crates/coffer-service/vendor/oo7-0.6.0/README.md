Vendored oo7 0.6.0
==================

This directory is a reproducible local vendor of the `oo7` 0.6.0 package from
crates.io.  The original package checksum is
`78f2bfed90f1618b4b48dcad9307f25e14ae894e2949642c87c351601d62cebd`, and its
upstream repository is <https://github.com/linux-credentials/oo7>.  The package
records upstream commit `9070389f33bec2e47048384e2fdbd7aab64e0df7` in
*.cargo\_vcs\_info.json*.

The upstream MIT license is preserved in *LICENSE*, the normalized and original
Cargo manifests are preserved, and the upstream README is preserved byte for
byte as *README.upstream*.

Coffer carries one narrow patch in *src/crypto/openssl.rs*.  The DH shared
secret and padded HKDF input use `Zeroizing<Vec<u8>>`, and the padded input is
allocated at its final capacity before secret bytes are appended.  This keeps
all shared-secret intermediates zeroized on success and early-return paths and
prevents a growing vector from releasing a prior allocation containing key
material.  No API, protocol, feature, or backend-selection behavior is changed.

The vendored build also carries a scoped deprecation allowance on oo7's
GVariant compatibility context.  The file backend is not selected by Coffer,
and the allowance keeps the path dependency warning-free without changing its
upstream file-format behavior.
