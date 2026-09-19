Octagon bottle fixtures
=======================

These are synthetic, independently authored wire messages signed and verified
with OpenSSL 3.5.8 (25 August 2026). The public test scalars are 1 through 4 on
P-384. Never use these keys for real data. No Apple account, captured record,
passcode, entropy, proprietary binary, or Apple fixture was used.

The field facts and signature contract are documented in
*../../../OCTAGON\_BOTTLE.md*. An independently written small wire encoder emits
minimal varints and length-delimited values without Apple schemas or codegen.
OpenSSL derives the points, serializes SPKI, and creates/verifies the
ECDSA/SHA-384 signatures. No production signing or key-generation API is added.

*original.bin* has four distinct embedded public keys, all seven known outer
fields, and opaque nested contents. Its top-level unknown fields cover wire
types 0/1/2/5 and repeated field numbers. Nested repeated unknown LEN values
include invalid protobuf bytes to confirm they remain uninterpreted.
*reordered.bin* contains the same values in a different outer order, with its
own signatures over those exact bytes. *replacement.bin* uses different IDs
and swaps the public keys and signers. It demonstrates that an attacker can
create an entirely new message which passes embedded-key consistency.

The ciphertext, tag, and IV are arbitrary synthetic bytes. They are not AEAD
outputs, encrypted private keys, or evidence of Apple recovery compatibility.
Both high-S and low-S versions of the original escrow signature are also
verified by OpenSSL. Their scalar transformation uses published ECDSA group
order arithmetic only in this fixture recipe; Coffer uses the existing
RustCrypto verifier and implements no cryptographic primitive.

All fixture messages and recipes are independently authored project test
material under GPL-3.0-or-later. No Apple source was copied, translated, or
adapted. Restricted rustpush, Sank6, and corecrypto sources were not consulted.


Reproduction
------------

Run this recipe from the repository root with Python 3 and OpenSSL installed.
It writes only to a new scratch directory and prints that path. It does not
overwrite golden fixtures. The message bytes reproduce exactly. ECDSA signing
uses random nonces, so new signatures need only verify; they need not match
the recorded signature hashes. Normal tests consume the fixed checked-in
bytes and never invoke OpenSSL or regenerate fixtures.

~~~~ python
from pathlib import Path
import hashlib
import re
import subprocess
import tempfile

out = Path(tempfile.mkdtemp(prefix='coffer-bottle-reproduction-'))

def run(*args):
    return subprocess.check_output(['openssl', *args], stderr=subprocess.DEVNULL)

def varint(n):
    b = bytearray()
    while n > 127:
        b.append((n & 127) | 128)
        n >>= 7
    return bytes(b) + bytes([n])

def field(n, b):
    return varint(n * 8 + 2) + varint(len(b)) + b

with tempfile.TemporaryDirectory(prefix='coffer-bottle-test-keys-') as tmp:
    t = Path(tmp)
    keys = []
    for scalar in (1, 2, 3, 4):
        conf = t / f'{scalar}.cnf'
        der = t / f'{scalar}.der'
        pem = t / f'{scalar}.pem'
        conf.write_text(
            'asn1=SEQUENCE:key\n[key]\nversion=INTEGER:1\n'
            'private=FORMAT:HEX,OCTETSTRING:' + scalar.to_bytes(48, 'big').hex()
            + '\nparameters=EXPLICIT:0,OID:secp384r1\n'
        )
        run('asn1parse', '-genconf', str(conf), '-out', str(der), '-noout')
        run('ec', '-inform', 'DER', '-in', str(der), '-out', str(pem))
        keys.append(run('pkey', '-in', str(pem), '-pubout', '-outform', 'DER'))
        (out / f'key-{scalar}-spki.der').write_bytes(keys[-1])
        (t / f'{scalar}-pub.pem').write_bytes(
            run('pkey', '-in', str(pem), '-pubout')
        )

    nested = (field(1, b'opaque synthetic ciphertext')
              + field(2, b'not-an-aead-tag') + field(3, b'iv')
              + field(21, b'\xff\x00') + field(21, b'\x80'))
    parts = [field(1, b'synthetic-peer'), field(2, b'synthetic-bottle'),
             field(8, keys[0]), field(9, keys[1]), field(10, keys[2]),
             field(11, keys[3]), field(12, nested)]
    unknown = (varint(30 * 8) + varint(2**64 - 1)
               + varint(31 * 8 + 1) + bytes(range(8))
               + varint(32 * 8 + 5) + bytes(range(4))
               + field(33, b'opaque-unknown') + field(33, b'\xff'))
    attacker = [field(1, b'attacker-peer'), field(2, b'attacker-bottle'),
                field(8, keys[2]), field(9, keys[3]), field(10, keys[0]),
                field(11, keys[1]), field(12, nested)]
    variants = {'original': b''.join(parts) + unknown,
                'reordered': unknown + b''.join(reversed(parts)),
                'replacement': b''.join(attacker)}
    golden = Path('crates/coffer-protocol/tests/fixtures/octagon-bottle')
    for name, data in variants.items():
        path = out / f'{name}.bin'
        path.write_bytes(data)
        assert data == (golden / path.name).read_bytes()
        signers = [('escrow', 3 if name == 'replacement' else 1),
                   ('peer', 1 if name == 'replacement' else 3)]
        for role, scalar in signers:
            sig = out / f'{name}-{role}.der'
            sig.write_bytes(run('dgst', '-sha384', '-sign',
                                str(t / f'{scalar}.pem'), str(path)))
            for candidate in (sig, golden / sig.name):
                assert run('dgst', '-sha384', '-verify',
                           str(t / f'{scalar}-pub.pem'), '-signature',
                           str(candidate), str(path)).strip() == b'Verified OK'

    parsed = run('asn1parse', '-inform', 'DER', '-in',
                 str(out / 'original-escrow.der')).decode()
    r, s = [int(v, 16) for v in re.findall(r'INTEGER\s+:([0-9A-F]+)', parsed)]
    order = int('ffffffffffffffffffffffffffffffffffffffffffffffff'
                'c7634d81f4372ddf581a0db248b0a77aecec196accc52973', 16)

    def integer(v):
        b = v.to_bytes((v.bit_length() + 7) // 8, 'big')
        if b[0] & 128:
            b = b'\x00' + b
        return b'\x02' + bytes([len(b)]) + b

    for label, value in [('low', min(s, order - s)),
                         ('high', max(s, order - s))]:
        body = integer(r) + integer(value)
        sig = out / f'original-escrow-{label}.der'
        sig.write_bytes(b'\x30' + bytes([len(body)]) + body)
        for candidate in (sig, golden / sig.name):
            assert run('dgst', '-sha384', '-verify', str(t / '1-pub.pem'),
                       '-signature', str(candidate),
                       str(out / 'original.bin')).strip() == b'Verified OK'

print(out)
for path in sorted(out.iterdir()):
    print(hashlib.sha256(path.read_bytes()).hexdigest(), path.name)
~~~~

SHA-256 of the fixed fixture inputs (the randomized signatures are fixed
inputs):

~~~~ text
29f8fe74f38c49d49810cec736a26732a30bff2e64827b709a1c63340d4f7181  key-1-spki.der
e04caab525cff38094dc994b28e8873b81fc5c8d1f4ce89413ff8fb31670fa82  key-2-spki.der
86d5eff39312850996dac2e1bc3297a9fe58aa656947f3c35348e50e6a59ba08  key-3-spki.der
63ecefee431d49523bc1136c4e72d0206a477086caf606cd5cf025686c109cf8  key-4-spki.der
037b404ed3c3671b3f9e28a4fa1aeb8687ea8042e46e767ff76343c54ddc116b  original-escrow-high.der
a837eb455d6bb34e6b6ee7d56e423e4aeb888b0a09a0a86de1b19e885d71661f  original-escrow-low.der
037b404ed3c3671b3f9e28a4fa1aeb8687ea8042e46e767ff76343c54ddc116b  original-escrow.der
63dd25dfb23449ce77b3ce5438b0396d2b6bee2680f7ebbc505b72126bbd1895  original-peer.der
0dfcf59808f722c9ff8e8443e5628d715c3889228a30ab3e2ed841ac87fbfff4  original.bin
f602af17b18cbc6e0c275420e3d90e983fc7d4b858cd9e46fdfccbaa5da11cf0  reordered-escrow.der
b0b2d39bc69400b09b6569d4f9e824923d8479c1af88cf473c77cd4087d3afd0  reordered-peer.der
b2b9480e98b27fc4bd81717635861e4cb4b637a792c1273d5d64229948b8db45  reordered.bin
6bf6df2ba0613a5b960e9a57366d348b6351746c398cbbc56d3afae51e3e269b  replacement-escrow.der
f7cbd3005b08e183aca3bff9ec0a3a1e13f009ed0dec1bce08e895a86b61e84f  replacement-peer.der
3730f754a83569ee44026233e2e59606aee55a38d1f7e6d877bf0c81586dd170  replacement.bin
~~~~
