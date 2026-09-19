Offline CKKS item AD fixtures
=============================

These fixtures contain invented public inputs, never captured credentials.
They exercise the closed v2 metadata subset through the existing payload
primitive. The item-opening tests also use the independent wrapped-key fixtures
from *../ckks-wrap/* to resolve B from A, unwrap C with B, and decrypt these
same envelopes. All hierarchy metadata is invented. No CloudKit transport or
live account is involved.

The synthetic AES-256-SIV key is the 64 bytes `80` through `bf`, matching the
public item-key pattern in the existing CKKS wrapped-key fixtures. The nonce
is 16 bytes with byte `i` equal to `0xd3 - 3*i`. The plaintext is the existing
230-byte *../ckks-plaintext/inet.bplist*, followed by `80` and nine zero bytes.
This explicit padding is accepted by the reader and makes no writer-policy
claim.

The handwritten AD has record name `item-a`, parent name `class-a`, version
2, generation `0x0102030405060708`, PCS service `0x01020304`, PCS public key
`10 20`, and PCS public identity `00 ff`. Integer components are little-endian
8-byte values. Sorted keys are `UUID`, `encver`, `gen`, `pcspublicidentity`,
`pcspublickey`, `pcsservice`, `wrappedkey`; the last component is the parent
name, not the wrapped ciphertext. *CKKS\_ITEM.md* records pinned protocol
evidence.

| File                  | Composition                                                |
| --------------------- | ---------------------------------------------------------- |
| *v2-all.bin*          | All three PCS fields                                       |
| *v2-none.bin*         | All PCS fields absent                                      |
| *v2-empty.bin*        | Both PCS Data fields present but empty; PCS service absent |
| *v2-nonce-last.bin*   | All fields, deliberately incorrect nonce-last order        |
| *v2-concatenated.bin* | All fields, deliberately concatenated AD values            |

Each file is 272 bytes: nonce, tag, then 240 ciphertext bytes. Empty AD calls
are omitted, so *v2-empty.bin* and *v2-none.bin* are identical. This tests the
existing adapter policy, not native OpenSSL empty-call semantics. The two
negative fixtures must fail authentication with the proper component list.


Reproduction
------------

The generator adapts Coffer's existing OpenSSL EVP recipe from
*../ckks-payload/README.md*. It implements no AES/SIV primitive. AD constants
are handwritten independently of the Rust builder. No Apple implementation,
schema or fixture was copied or translated; rustpush/Sank6 were not consulted.
Codex authored the recipe and tests. See the implementation handoff for the
model identity and verification commands.

Save the following block as *generate.c*. With an existing C compiler and
OpenSSL development headers, run these opt-in reproduction commands in this
fixture directory; they are not setup instructions or CI dependencies.
Normal Rust tests only consume the static files. The item-opening follow-up
reproduced all five envelopes byte for byte using this unchanged generator;
no new fixture format, primitive or captured record was introduced.

~~~~ sh
cc -std=c11 -Wall -Wextra -Werror generate.c -lcrypto -o /tmp/coffer-item-generate
/tmp/coffer-item-generate ../ckks-plaintext/inet.bplist
sha256sum *.bin
~~~~

~~~~ c
// Coffer: a native Linux client for Apple Passwords.
// Copyright (C) 2026  Hong Minhee
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

/* Synthetic fixture reproduction only. No cryptographic primitive is implemented. */
#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void require(int ok) {
    if (!ok) { fputs("fixture generation failed\n", stderr); exit(1); }
}
struct part { const unsigned char *bytes; int size; };
static void component(EVP_CIPHER_CTX *ctx, struct part p) {
    int written;
    if (p.size) require(EVP_EncryptUpdate(ctx, NULL, &written, p.bytes, p.size) == 1);
}
static void generate(const char *name, const unsigned char *plain, int mode) {
    unsigned char key[64], nonce[16], output[272], joined[64];
    const unsigned char version[] = {2,0,0,0,0,0,0,0};
    const unsigned char generation[] = {8,7,6,5,4,3,2,1};
    const unsigned char identity[] = {0,255}, public_key[] = {16,32};
    const unsigned char service[] = {4,3,2,1,0,0,0,0};
    /* Handwritten expected components, independent of the Rust builder. */
    const struct part all[] = {
        {(const unsigned char *)"item-a",6}, {version,8}, {generation,8},
        {identity,2}, {public_key,2}, {service,8}, {(const unsigned char *)"class-a",7}
    };
    int written = 0, final = 0, length = 0;
    for (int i = 0; i < 64; ++i) key[i] = (unsigned char)(128 + i);
    for (int i = 0; i < 16; ++i) output[i] = nonce[i] = (unsigned char)(0xd3 - 3 * i);
    EVP_CIPHER *cipher = EVP_CIPHER_fetch(NULL, "AES-256-SIV", NULL);
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    require(cipher != NULL && ctx != NULL);
    require(EVP_EncryptInit_ex2(ctx, cipher, key, NULL, NULL) == 1);
    if (mode != 3) component(ctx, (struct part){nonce,16});
    for (int i = 0; i < 7; ++i) {
        if ((mode == 1 || mode == 2) && i >= 3 && i <= 5) {
            if (mode == 2 && i < 5) component(ctx, (struct part){all[i].bytes,0});
            continue;
        }
        if (mode == 4) {
            require(length + all[i].size <= (int)sizeof(joined));
            memcpy(joined + length, all[i].bytes, (size_t)all[i].size);
            length += all[i].size;
        } else component(ctx, all[i]);
    }
    if (mode == 4) component(ctx, (struct part){joined,length});
    if (mode == 3) component(ctx, (struct part){nonce,16});
    require(EVP_EncryptUpdate(ctx, output + 32, &written, plain, 240) == 1);
    require(EVP_EncryptFinal_ex(ctx, output + 32 + written, &final) == 1);
    require(written + final == 240);
    require(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, output + 16) == 1);
    FILE *file = fopen(name, "wb"); require(file != NULL);
    require(fwrite(output, 1, sizeof(output), file) == sizeof(output));
    require(fclose(file) == 0);
    EVP_CIPHER_CTX_free(ctx); EVP_CIPHER_free(cipher);
}
int main(int argc, char **argv) {
    require(argc == 2);
    unsigned char plaintext[240] = {0};
    FILE *input = fopen(argv[1], "rb"); require(input != NULL);
    require(fread(plaintext, 1, 230, input) == 230);
    require(fgetc(input) == EOF && !ferror(input)); require(fclose(input) == 0);
    plaintext[230] = 0x80; /* Nine zero bytes follow, with no writer-policy claim. */
    generate("v2-all.bin", plaintext, 0);
    generate("v2-none.bin", plaintext, 1);
    generate("v2-empty.bin", plaintext, 2);
    generate("v2-nonce-last.bin", plaintext, 3);
    generate("v2-concatenated.bin", plaintext, 4);
    return 0;
}
~~~~


Reproduction identities
-----------------------

Generated with GCC `16.2.1 20260819 (Red Hat 16.2.1-2)` and OpenSSL
`3.5.8 25 Aug 2026`. The generator block, including its final newline, has
SHA-256 `0a13b22b1b41462165b1b2d094934b9c341ec4476a30b08c0edf25620dbe9646`.
The unpadded input plist has SHA-256
`fd475d545b0c946a5002a938b43e63f92b95f7823560f189c44a6acc724372b1`.

~~~~ text
f93065b3286fdb810aa2872c08d2077e00290202b8b0513895647b78c0a339e5  v2-all.bin
d3e99880f87ec845f89c591353cb085d986f9ac600ea1c59866d3865f4101342  v2-concatenated.bin
ace20ee9dc1642bf8d47ee1f267e70c7e89d43c8d5f4faca3a8c4c337d5da065  v2-empty.bin
66a4f39ee908a78978e2d82ca915339fd00c5f0420b9c8f0e9c6525763668717  v2-nonce-last.bin
ace20ee9dc1642bf8d47ee1f267e70c7e89d43c8d5f4faca3a8c4c337d5da065  v2-none.bin
~~~~
