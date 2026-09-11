Synthetic service-token fixtures
================================

All fields are invented. No Apple response, account, anisette secret, or
keyring material was captured. These fixtures establish an offline contract,
not Apple interoperability.

*plaintext.plist* uses `t/com.apple.gs.xcode.auth/{token,expiry}` with the
invented token `SYNTHETIC-SERVICE-TOKEN` and epoch-millisecond expiry
`2000000000000`. *et.hex* is its encryption under the synthetic 32-byte key
`00,01,...,1f`, IV `00,01,...,0f`, and AAD `XYZ`, followed by a 16-byte tag.
*response.plist* wraps those encrypted bytes as `Response.et` and sets
`Response.Status.ec` to integer zero.

The encryption oracle was generated independently on 11 September 2026 with
OpenSSL 3.5.8 (25 August 2026), using the system libcrypto EVP interface via
Python ctypes. The generator called `EVP_aes_256_gcm`, set IV length 16 with
`EVP_CTRL_GCM_SET_IVLEN`, initialized the original key/IV, passed the three AAD
bytes to `EVP_EncryptUpdate` without output, encrypted the 257 plaintext bytes,
finalized, and fetched a 16-byte tag with `EVP_CTRL_GCM_GET_TAG`. Expected tag:
`b00863a52d8e410db1f1ed5d3ed06e59`. The resulting envelope is 292 bytes.
RustCrypto does not generate this fixture. RustCrypto encryption in negative
tests only makes authenticated malformed plaintexts; it is not the positive
interoperability oracle.

*request.plist* was assembled independently in Python from the explicit wire
fields and existing Coffer anisette fixture values. Its checksum uses Python
standard-library `hmac.new(bytes(range(32)), message, hashlib.sha256)`, where
`message` is the UTF-8 concatenation of `apptokens`, `SYNTHETIC-ADSID`, and
`com.apple.gs.xcode.auth`. Expected checksum:
`570ac6bc93250e307355eb4fb4fdc2b897e015d6d01b07765cae57c93296a9dd`.
The cookie is `00 ff 80 01`, exercising binary rather than string encoding.
The test separately checks RFC 4231 test case 1 for the HMAC primitive.

The protocol facts come from [SideStore's MPL-2.0 request implementation] at
`03beb1aa42991ccdad6214dee77e72282bef461f` and xtool's MIT [AEAD composition]
and [token schema] at `4208c77c8128568f8b938d0c67d2f4bdcf04e100`.
Only protocol facts were used; these files contain no adapted upstream code.

SHA-256 checksums (no trailing newline in XML files):

 -  *et.hex*: `53ef4cbcc5e963f8d8f9d32ee3d716734c2c9bcd46709531ae805f78853ad067`
 -  *plaintext.plist*:
    `f51d3a0eb8b02e83e7f1d6ab56a47c2d2b1b76eb3fe990c38c95a5cae4505a97`
 -  *request.plist*:
    `3dc14a63fee9be6c47d56b79af35fbef6bb3402d8b078c4e0a06b86342111b1f`
 -  *response.plist*:
    `070add35dbcfc7ceb9c3dbd69f7bd45eae576201892480031cac643fa79277f5`

[SideStore's MPL-2.0 request implementation]: https://github.com/SideStore/apple-private-apis/blob/03beb1aa42991ccdad6214dee77e72282bef461f/icloud-auth/src/client.rs
[AEAD composition]: https://github.com/xtool-org/xtool/blob/4208c77c8128568f8b938d0c67d2f4bdcf04e100/Sources/XKit/GrandSlam/Crypto/AppTokens.swift
[token schema]: https://github.com/xtool-org/xtool/blob/4208c77c8128568f8b938d0c67d2f4bdcf04e100/Sources/XKit/GrandSlam/Operations/GrandSlamFetchAppTokensOperation.swift
