Offline CKKS payload fixtures
=============================

These six static envelopes were generated independently with OpenSSL EVP
AES-256-SIV on 12 September 2026. Every key, nonce, AD value and plaintext
byte is invented public test data. No captured account material was used, so
no sanitization was needed. Default Rust tests read the binary files directly;
they do not invoke OpenSSL, a C compiler, a network endpoint or a secret store.

The recipe and adapter were authored for Coffer with Codex:gpt-6-astra.
No corecrypto implementation, header, test, binary or existing output was
accessed or copied to generate these fixtures. Neither rustpush nor Sank6
source was accessed. The generator only calls OpenSSL EVP; it contains no
implementation of AES, CMAC, S2V or CTR.


Composition and evidence boundary
---------------------------------

Each file contains a 16-byte nonce, a 16-byte SIV tag, and ciphertext.
The adapter passes the nonce first, then each nonempty AD value in caller
order as a separate EVP call. Empty AD values are omitted. The negative
fixture deliberately passes nonce last.

The composition follows the approved, independently reviewed observations in
*ckks-payload-plan.md*, *corecrypto-verification.md* and
*corecrypto-independent-rereview.md*, retained in the implementation handoff.
Those reports describe a bounded synthetic comparison and a separate source
observation of *CKKSSIV.m* at Apple Security revision
`db15acbe6a7f257a859ad9a3bb86097bfe0679d9`, SHA-256
`61fdef2d9c851903e13dadb08d4ac3d5b4119192ed840c859d778d758474ab8f`.
This worker used those reports, not Apple source or outputs.

Empty calls are omitted by this adapter; the fixture does not establish the
native behavior of OpenSSL empty AD. The report's all-inputs-absent discrepancy
cannot occur with this required 16-byte nonce, even for empty plaintext.
Inserting empty AD between nonempty values tests the chosen local adapter
policy, not an additional observation against Apple.

These are opaque byte vectors, not website-password records. They do not
verify Foundation metadata sorting/serialization, key/account/record binding,
CloudKit wire fields, sidecars, trust/key acquisition, remote credential
retrieval or live CKKS interoperability. Rust failure handling and zeroizing
ownership require review of the actual Rust path, independently of these
OpenSSL encryption outputs.


Public recipe
-------------

For zero-based byte index `i`, all arithmetic below is modulo 256:

 -  Key: 64 bytes, `7 * i + 19`.
 -  Nonce: 16 bytes, `0xd3 - 3 * i`.
 -  Plaintext: the requested number of bytes, `11 * i + 5`.
 -  First AD: ASCII `coffer-payload-public-alpha` without a terminator.
 -  Second AD: hex `00504144ff02`.

| File                  | Plaintext bytes | Supplied AD                              | Nonce position      |
| --------------------- | --------------: | ---------------------------------------- | ------------------- |
| *no-ad.bin*           |              32 | None                                     | First               |
| *multiple-ad.bin*     |              48 | First AD, second AD                      | First               |
| *empty-ad.bin*        |              48 | Empty, first AD, empty, second AD, empty | First               |
| *empty-plaintext.bin* |               0 | First AD, second AD                      | First               |
| *nonaligned.bin*      |              37 | First AD, second AD                      | First               |
| *nonce-last.bin*      |              37 | First AD, second AD                      | Last, negative case |

*empty-ad.bin* and *multiple-ad.bin* are identical by design.
*nonce-last.bin* must fail in the nonce-first decrypt API. Policy-boundary
unit tests separately use RustCrypto encryption for exact/over-limit inputs;
they are not independent interoperability vectors.


Reproduction
------------

The original generator is retained outside the repository as
*/tmp/coffer-m2-reports/ckks-payload-generator.c*. Its complete source is
included below so the fixture can be reproduced without that temporary file.
Save the code block verbatim as *generate.c*, including its final newline.
Its SHA-256 is
`3d82b213066ef7a20fd43c6a89ad95f50015b4df116a121e95806bb843ca647c`.

The recorded compiler was GCC `16.2.1 20260819 (Red Hat 16.2.1-2)`;
the executable linked OpenSSL `3.5.8 25 Aug 2026`. With OpenSSL development
headers and a C compiler already available, compile the generator and run
it in an empty output directory:

~~~~ sh
cc -std=c11 -Wall -Wextra -Werror generate.c -lcrypto -o generate
./generate
sha256sum *.bin
~~~~

These are opt-in fixture reproduction commands, not contributor setup or a
new project build task. The compile and generation each exited 0, with no
compiler diagnostic. The full source follows:

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

/* Independent public synthetic fixture recipe, using OpenSSL EVP only.
 * Run in an empty output directory. No Apple or RustCrypto code is used. */
#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>

static void require(int ok) {
    if (!ok) {
        fputs("fixture generation failed\n", stderr);
        exit(1);
    }
}

static void component(EVP_CIPHER_CTX *ctx, const unsigned char *bytes, int len) {
    int written;
    /* The adapter omits empty calls; it does not merge other components. */
    if (len != 0)
        require(EVP_EncryptUpdate(ctx, NULL, &written, bytes, len) == 1);
}

static void generate(const char *name, int length, int ad_mode, int nonce_last) {
    unsigned char key[64], nonce[16], plaintext[64], output[112];
    static const unsigned char first[] = "coffer-payload-public-alpha";
    static const unsigned char second[] = {0x00, 0x50, 0x41, 0x44, 0xff, 0x02};
    int written = 0, final = 0;
    for (int i = 0; i < 64; ++i) {
        key[i] = (unsigned char)(7 * i + 19);
        plaintext[i] = (unsigned char)(11 * i + 5);
    }
    for (int i = 0; i < 16; ++i) {
        nonce[i] = (unsigned char)(0xd3 - 3 * i);
        output[i] = nonce[i];
    }
    EVP_CIPHER *cipher = EVP_CIPHER_fetch(NULL, "AES-256-SIV", NULL);
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    require(cipher != NULL && ctx != NULL);
    require(EVP_EncryptInit_ex2(ctx, cipher, key, NULL, NULL) == 1);
    if (!nonce_last) component(ctx, nonce, 16);
    if (ad_mode == 2) component(ctx, first, 0);
    if (ad_mode != 0) {
        component(ctx, first, sizeof(first) - 1);
        if (ad_mode == 2) component(ctx, second, 0);
        component(ctx, second, sizeof(second));
    }
    if (ad_mode == 2) component(ctx, first, 0);
    if (nonce_last) component(ctx, nonce, 16);
    /* A non-NULL input distinguishes empty plaintext from another AD call. */
    require(EVP_EncryptUpdate(ctx, output + 32, &written, plaintext, length) == 1);
    require(EVP_EncryptFinal_ex(ctx, output + 32 + written, &final) == 1);
    require(written + final == length);
    require(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, output + 16) == 1);
    FILE *file = fopen(name, "wb");
    require(file != NULL);
    require(fwrite(output, 1, (size_t)length + 32, file) == (size_t)length + 32);
    require(fclose(file) == 0);
    EVP_CIPHER_CTX_free(ctx);
    EVP_CIPHER_free(cipher);
}

int main(void) {
    generate("no-ad.bin", 32, 0, 0);
    generate("multiple-ad.bin", 48, 1, 0);
    generate("empty-ad.bin", 48, 2, 0);
    generate("empty-plaintext.bin", 0, 1, 0);
    generate("nonaligned.bin", 37, 1, 0);
    generate("nonce-last.bin", 37, 1, 1);
    return 0;
}
~~~~


SHA-256 output identities
-------------------------

~~~~ text
98fab72beb3bae5522163984293a93b2931dad3636537f452b5157bc051bb627  empty-ad.bin
6acf46b0d040286e5e654cbb45ed9c60868a301b9e73d70b2b3db64d8afccc37  empty-plaintext.bin
98fab72beb3bae5522163984293a93b2931dad3636537f452b5157bc051bb627  multiple-ad.bin
273e7032a1fcc679cd609ed381ac62fd60dc5f9561e781eebe4af771c9a83bb3  no-ad.bin
57e113dcd255444948f900655553ca9a99077a15fd359e17469cc371d89aecd9  nonaligned.bin
c08d21d6b778556ea479ec38b5c7c7bc379f5c03bd0c4a692b7326c691d26302  nonce-last.bin
~~~~
