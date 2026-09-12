Offline CKKS key graphs
=======================

`coffer_protocol::ckks::hierarchy` validates one bounded key graph and unwraps
one explicitly selected target using the existing AES-256-SIV primitive.
The caller supplies the full scope, a complete typed key-record set and one
independently obtained anchor key. This API performs no I/O and has no access
to authentication, Secret Service, trust joining, escrow, or remote mutation.

Structural validation does not authenticate record metadata. CKKS key wrapping
in this subset has no associated data, so a valid ciphertext can still unwrap
after its record name or claimed class changes. A regression test demonstrates
that limitation. Anchor self-wrap success also does not establish trust in the
candidate key. Account binding, authorization, metadata authenticity,
collection completeness and freshness remain the caller's responsibility.


Using the offline API
---------------------

Build borrowed `KeyRecord` values from already bounded input. Each record and
parent reference carries a `KeyId`: account context, container, environment,
database, zone owner, zone name and exact record name. The account context is
an opaque identifier assigned by the caller, never a token. The environment and
database enums do not infer a CKKS endpoint or select a database.

The API compares identifiers exactly. It performs no trimming, UUID parsing,
case folding, Unicode normalization, or default-owner alias substitution.
`KeyClass::try_from` accepts only `tlk`, `classA` and `classC`. These are
claimed classes; Class A/C do not imply Linux lock protection. `parent: None`
means true absence in a complete typed record. An adapter must reject
malformed, truncated and duplicate wire fields before constructing these values.

Pass `InputCompleteness::Complete` only when the intended collection is
complete. This is a caller assertion, not evidence from CloudKit. Validation
rejects incomplete input before inspecting parent references. Validation never
refetches a missing parent or chooses a replacement from another scope.

~~~~ rust
use coffer_protocol::ckks::hierarchy::{
    AnchorInput, HierarchyError, HierarchyLimits, InputCompleteness,
    KeyGraph, KeyId, KeyRecord, KeyScope,
};

fn offline_example(
    scope: KeyScope<'_>,
    records: &[KeyRecord<'_>],
    anchor: &AnchorInput<'_>,
    target: KeyId<'_>,
) -> Result<(), HierarchyError> {
    let graph = KeyGraph::validate(
        scope, records, InputCompleteness::Complete,
        anchor.id, HierarchyLimits::default(),
    )?;
    let key = graph.unwrap_target(anchor, target)?;
    // Pass key.expose_secret() to the next explicit offline operation here.
    // Keep key.id() and key.class() as claims, not authenticated metadata.
    drop(key);
    Ok(())
}
~~~~

`KeyGraph` borrows the immutable input and stores only bounded indices and
references. `AnchorInput` owns a zeroizing `UnwrappingKey`; there is no trust
constructor or automatic key search. Each `unwrap_target` call checks the
anchor binding and target before cryptography, checks the anchor self-wrap
once, and unwraps each edge on the selected path once. A failure returns a
fixed error and no partial key. Repeated calls are separate bounded operations;
there is no cache or batch budget.

`ResolvedKey` retains the full claimed identity and class. It cannot outlive
the graph or supplied anchor, and provides neither cloning nor serialization.
Its explicit `expose_secret` method borrows bytes for a subsequent offline
operation. Drop the result promptly. Input metadata remains caller-owned and
is not wiped by this component. Graph, identity, record, anchor and result
`Debug` output is redacted; callers must also avoid logging individual fields
or exposed bytes.


Supported relationships and limits
----------------------------------

Every supplied node, including unselected branches, must reach the selected
anchor. The anchor must be a TLK whose parent is itself or truly absent. An
anchor with a non-self parent is rejected even if its name appears in a cycle.
A second TLK whose parent is itself or absent is rejected. All other supported
edges have a TLK parent: TLK-to-TLK and Class A/C-to-TLK. Other class
relationships are unsupported by this first subset, not declared universally
invalid in Apple CKKS. Shared parents are allowed. Current-key pointers do not
participate in target selection, so historical paths follow their actual parent
references.

Validation checks scope, lengths, aggregate input size and duplicates before
parent traversal. It checks every parent, class relationship, cycle and depth
before any unwrap. Traversal is iterative with cached depths. The selected
anchor's ciphertext must authenticate and produce a key that exactly matches
the candidate key. The comparison uses `subtle::ConstantTimeEq` on fixed
64-byte slices. The validated self-unwrapped key becomes the first working key
without making another copy. Only the requested branch is then decrypted. This
call checks the lengths of ciphertexts on other branches but does not
authenticate them.

`HierarchyLimits::new` accepts positive values up to these local hard caps:

| Resource                   | Hard cap |
| -------------------------- | -------- |
| Key records                | 1,024    |
| Bytes per identifier       | 1,024    |
| Aggregate input bytes      | 8 MiB    |
| Parent edges to the anchor | 64       |

Defaults use those caps. Aggregate accounting includes every occurrence of
each identifier, including repeated scopes and parents, two enum bytes per
scope, 80 wrapped bytes and two class/parent discriminator bytes per record.
The separate scope and selected anchor ID also count. Index/pointer storage is
bounded separately by node count. Counts and lengths are checked before
input-dependent allocation, and additions are checked for overflow. Caller
allocations and future wire parsing require their own bounds.

One unwrap operation performs at most 65 crypto attempts: one anchor check and
64 edges. It stops immediately on failure, with no alternative key, parent,
associated data, retry or fallback. At most two intermediate plaintext keys
coexist during a step; replacing or dropping one invokes the existing
zeroizing storage. Key material is never accumulated along the path. The
existing AES/SIV/CMAC zeroization features remain enabled. These measures do
not guarantee erasure of all compiler-generated copies or constant-time
execution in arbitrary debug builds, compilers and deployment environments.


Provenance and verification boundary
------------------------------------

The relationship policy uses facts recorded in the design report from Apple's
published Security revision `db15acbe6a7f257a859ad9a3bb86097bfe0679d9`:

 -  [*CKKSConstants.m*][constants] provides the three class literals.
 -  [*CKKSKey.m*][key] treats an absent parent reference as self-parent.
 -  [*CKKSKeychainBackedKey.m*][backed] checks self-unwrapped key equality.
 -  [*CKKSNewTLKOperation.m*][newtlk] creates self-wrapped TLKs, class keys
    below a TLK and historical TLKs rewrapped below a new TLK.
 -  [*CKKSProcessReceivedKeysOperation.m*][received] checks current Class A/C
    keys against their current TLK parent.

These observations support the limited local policy above, not a complete
private wire schema or historical class matrix. The implementation and graph
tests were written independently from that policy. No Apple implementation or
test source was copied or translated, and neither rustpush nor Sank6 source
was read or adapted for this work.

The graph tests reuse the independent OpenSSL vectors in
[*tests/fixtures/ckks-wrap/*](tests/fixtures/ckks-wrap/README.md), whose README
records the synthetic key values, [RFC 5297] composition and generation recipe.
All graph identifiers and relationships are invented local inputs. No new
cryptographic primitive or captured account data is introduced. Tests cover
historical paths, all input permutations of a three-node graph, malformed
inputs, full scope isolation, duplicate records, cycles, all limits, anchor
mismatch, every corrupted ciphertext byte and immediate failure without partial
output. Separate tests show that metadata rebinding can still decrypt.

This graph component does not implement a CloudKit/CKCode decoder, record
retrieval, current-key pointer semantics, item decryption, trust acquisition,
multiple anchors, revocation, or rollback protection. The vectors verify the
chosen composition and local graph policy; Apple corecrypto and live CKKS
interoperability remain unverified. This subset does not complete the M2
hierarchy-recovery or credential-decryption roadmap items.

A separate [offline payload primitive](CKKS_PAYLOAD.md) accepts an already
selected item key and ordered serialized AD. It returns authenticated opaque
bytes, not parsed credentials, and does not supply the missing key/record
adapter or establish graph trust. A separate [plaintext view](CKKS_PLAINTEXT.md)
explicitly interprets a restricted binary-plist dictionary borrowed from that
payload owner. Its narrow Internet password projection requires an explicit
non-tombstone value; it does not provide the missing remote record adapter.

[constants]: https://github.com/apple-oss-distributions/Security/blob/db15acbe6a7f257a859ad9a3bb86097bfe0679d9/keychain/ckks/CKKSConstants.m
[key]: https://github.com/apple-oss-distributions/Security/blob/db15acbe6a7f257a859ad9a3bb86097bfe0679d9/keychain/ckks/CKKSKey.m
[backed]: https://github.com/apple-oss-distributions/Security/blob/db15acbe6a7f257a859ad9a3bb86097bfe0679d9/keychain/ckks/CKKSKeychainBackedKey.m
[newtlk]: https://github.com/apple-oss-distributions/Security/blob/db15acbe6a7f257a859ad9a3bb86097bfe0679d9/keychain/ckks/CKKSNewTLKOperation.m
[received]: https://github.com/apple-oss-distributions/Security/blob/db15acbe6a7f257a859ad9a3bb86097bfe0679d9/keychain/ckks/CKKSProcessReceivedKeysOperation.m
[RFC 5297]: https://www.rfc-editor.org/rfc/rfc5297
