Octagon key fixtures
====================

The original ten fixtures are synthetic, public test values generated with
OpenSSL 3.5.8 (25 August 2026). No Apple account, device, captured message, or
proprietary fixture was used. The private scalar is the public test value 1;
never use these keys for real data. The second P-384 key uses scalar 2 and the
P-256 key uses scalar 1. OpenSSL derives their points independently of
RustCrypto. The P-384 scalar-1 point also equals the published generator in
[SEC 2 v2.0 section 2.5.1].

OpenSSL serializes the named-curve SPKI and generates ECDSA/SHA-384 signatures.
The full private fixture joins its public point with the fixed 48-byte scalar,
following Apple's documented format. The fixture recipe selects one high-S
and one low-S signature and independently verifies both with OpenSSL.
The recipe classifies S using an integer comparison; it performs no
elliptic-curve arithmetic. The message is plain synthetic ASCII with one final
newline.

The synthetic fixtures and independently authored recipes are project test
material under GPL-3.0-or-later. The additional RFC fixtures below encode
published numerical test values. No Apple source, Apple fixture, or standards
prose was copied into them. OpenSSL is used as a local generation/verification
tool; it is not a new dependency of `coffer-protocol`.

[SEC 2 v2.0 section 2.5.1]: https://www.secg.org/sec2-v2.pdf


Reproduction
------------

The key encodings and message reproduce byte-for-byte. OpenSSL ECDSA signing
uses random nonces, so regenerating signatures produces different valid bytes.
The checked-in signatures and hashes below are fixed test inputs. Normal Rust
tests never regenerate fixtures or invoke external programs. Run this recipe
only in a scratch checkout when investigating the vectors; compare key bytes
and verify signatures instead of overwriting golden files to fix a test.

From the repository root, with OpenSSL 3.5.8 and Python 3 available:

~~~~ python
from pathlib import Path
import subprocess, re, hashlib
out=Path('crates/coffer-protocol/tests/fixtures/octagon-keys')
tmp=Path('/tmp/coffer-octagon-evidence')
tmp.mkdir(parents=True, exist_ok=True)
def run(*args):
 return subprocess.check_output(['openssl',*args],stderr=subprocess.DEVNULL)
for name,curve,width,scalar in [('p384','secp384r1',48,1),('p384-other','secp384r1',48,2),('p256','prime256v1',32,1)]:
 conf=tmp/(name+'.cnf')
 conf.write_text('asn1=SEQUENCE:key\n[key]\nversion=INTEGER:1\nprivate=FORMAT:HEX,OCTETSTRING:'+scalar.to_bytes(width,'big').hex()+'\nparameters=EXPLICIT:0,OID:'+curve+'\n')
 der=tmp/(name+'.der'); pem=tmp/(name+'.pem')
 run('asn1parse','-genconf',str(conf),'-out',str(der),'-noout')
 run('ec','-inform','DER','-in',str(der),'-out',str(pem))
 spki=run('pkey','-in',str(pem),'-pubout','-outform','DER')
 point=spki[-(width*2+1):]
 assert point[0]==4
 (out/(name+'-spki.der')).write_bytes(spki)
 (out/(name+'-public.sec1')).write_bytes(point)
 if name=='p384':
  (out/'p384-private.full').write_bytes(point+scalar.to_bytes(width,'big'))
 (tmp/(name+'-public.pem')).write_bytes(run('pkey','-in',str(pem),'-pubout'))
msg=b'Coffer offline Octagon key verification fixture\n'
(out/'message.bin').write_bytes(msg)
order=int('ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973',16)
for i in range(100):
 sig=run('dgst','-sha384','-sign',str(tmp/'p384.pem'),str(out/'message.bin'))
 (tmp/'signature.der').write_bytes(sig)
 parsed=run('asn1parse','-inform','DER','-in',str(tmp/'signature.der')).decode()
 s=int(re.findall(r'INTEGER\s+:([0-9A-F]+)',parsed)[1],16)
 label='high' if s>order//2 else 'low'
 (out/('signature-'+label+'.der')).write_bytes(sig)
 if all((out/('signature-'+x+'.der')).exists() for x in ['high','low']): break
for label in ['high','low']:
 print(run('dgst','-sha384','-verify',str(tmp/'p384-public.pem'),'-signature',str(out/('signature-'+label+'.der')),str(out/'message.bin')).decode().strip())
for p in sorted(out.iterdir()): print(hashlib.sha256(p.read_bytes()).hexdigest(),p.name)
~~~~

SHA-256 of the checked-in binary inputs:

~~~~ text
984521c2cf02455524e8e0a5548e61764939cbe8dbf5c96283a02e1f8ec57c6e  message.bin
698bea63dc44a344663ff1429aea10842df27b6b991ef25866b2c6c02cdcc5be  p256-public.sec1
5cd252fb0ce8932436faf8ccd1040981b89ee4ad6b9fe9e2a2b7e71aacb27cd3  p256-spki.der
a92a5efad5fe699f8a050ef1ee02dcad31f44942fe4885800588a491c3a52b00  p384-other-public.sec1
e04caab525cff38094dc994b28e8873b81fc5c8d1f4ce89413ff8fb31670fa82  p384-other-spki.der
a62a8b58e94f905c0a1edb13d579981c9ba3c4436ec85acdafbb9c524da8a060  p384-private.full
8c2eb3e0b8d6cc2a197a52c92860f7b1ba71c966e3c88ec6c81900a7308e6266  p384-public.sec1
29f8fe74f38c49d49810cec736a26732a30bff2e64827b709a1c63340d4f7181  p384-spki.der
c56a68aff46ac24764b08c1b5e3ced878b97bcf430b0affc9629401ecc9dacf7  signature-high.der
b5a7aeb3b730628f16a1ab991c5bec89bf33918ee2bdb42cfa2f12edde383618  signature-low.der
~~~~


Published RFC vectors
---------------------

The seven `rfc6979-*` inputs encode the public numerical test vectors from
[RFC 6979 Appendix A.2.6], using its P-384 key and the SHA-384 signatures for
`sample` and `test`. These messages have no final newline. The RFC private
scalar is public test data; it must never protect real secrets. This test
verifies signatures, not RFC 6979 nonce generation or signing.

The source was the RFC Editor's [plain-text RFC], with SHA-256
`456e8f17558fdbd206f968b96fc6f1b4a71ea331ab30ad17f711ab3adaa7d701`.
Reproduce the encodings by concatenating the two hexadecimal lines for each
48-byte `Ux`, `Uy`, and private `x` in A.2.6. The SEC1 point is
`04 || Ux || Uy`; the Apple full encoding appends `x`. Use OpenSSL
`asn1parse -genconf` to encode SPKI as a SEQUENCE containing the
AlgorithmIdentifier OIDs `1.2.840.10045.2.1` and `1.3.132.0.34`, followed by
the point as a BIT STRING with zero unused bits. For each SHA-384 case, encode
the published `r` and `s` as positive DER INTEGERs in a SEQUENCE. No
elliptic-curve arithmetic or signature generation is involved in converting
these published values.

Both resulting signatures were also verified independently with OpenSSL 3.5.8:

~~~~ sh
openssl dgst -sha384 -keyform DER -verify rfc6979-spki.der \
    -signature rfc6979-sample-signature.der rfc6979-sample-message.bin
openssl dgst -sha384 -keyform DER -verify rfc6979-spki.der \
    -signature rfc6979-test-signature.der rfc6979-test-message.bin
~~~~

SHA-256 of these additional fixed inputs:

~~~~ text
06a38483a204544e2982ad20e31c18514bf83c411299abd0c21d620d58e49a94  rfc6979-private.full
c8b9a8e7f164515be2e59bce8ef78d1fe1f5d605411be6cda64ef6bc050c192b  rfc6979-public.sec1
af2bdbe1aa9b6ec1e2ade1d694f41fc71a831d0268e9891562113d8a62add1bf  rfc6979-sample-message.bin
018a0800e0c72cd4a3b41abc53059c116e03a30d01560986db0f386e8cf38758  rfc6979-sample-signature.der
2f95601fa82060b909bfc6b979dbd303d34d34e0afb27ea496beac362f242a4b  rfc6979-spki.der
9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08  rfc6979-test-message.bin
3956a4336caf5729108d5e2cae87f5c4638c95765966857ac1bfebc19056fb35  rfc6979-test-signature.der
~~~~

[RFC 6979 Appendix A.2.6]: https://www.rfc-editor.org/rfc/rfc6979#appendix-A.2.6
[plain-text RFC]: https://www.rfc-editor.org/rfc/rfc6979.txt
