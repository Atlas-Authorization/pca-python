# Changelog

## 0.4.0 - 2026-10-11 (BREAKING)

- Depth / strict digests (security, parity): every protocol digest (`hash_canonical`: capability / grant hash, hop body digest, caveat comparison, params and conditions digests; Merkle leaves) now uses the STRICT canonical form like the reference (`hashCanonical` is `canonicalizeStrict`): nesting depth <= 32, safe integers only, plain decimals, no lone surrogates. It was the lenient form, so a correctly SIGNED hop carrying a depth-33 value, `1e300`, `2^53+2` or a lone surrogate verified although the reference refuses the chain (and the lenient form recursed without bound). Such hops are now refused (`hop N: malformed body`). `hash_canonical` raises `TypeError` on out-of-profile input, like the reference. `verify_leaf_suite` is total.
- R6-03 / R6-04 (security, parity): `verify_threshold_share` validates the WHOLE signer set like the TypeScript reference before looking at the share: unknown roles, non-canonical / non-32-byte public keys, and an empty, null, short or non-canonical `pq_pk` ANYWHERE in the set now refuse it; one key per role and one role per key; a duplicate (role, key) entry is accepted only with the same `pq_pk` (a conflicting one used to resolve first-wins); `t` must be 1, 2 or 3 (0..255 was accepted); `share.role` must equal the role. New corpus tables `threshold_set` / `signer_set_hash`.
- R6-05: `verify_chain`, `verify_threshold_share` and `verify_pcactn_core` are TOTAL: malformed input (non-object hop, missing or wrong-typed fields, truncated base64url, huge numbers) is a deny, never an exception. `verify_chain` also applies the reference hop type check (string id/issuer/holder/body_digest/sig, optional alg/pq_pk/pq_sig/holder_pq/parent absent or string, caveats a list of objects with a string `type`), so a correctly signed but ill-typed hop is now refused. New corpus table `malformed`.
- R6-02 (security): a signer-set role that registers a `pq_pk` now REQUIRES a PQ (pure or hybrid) threshold share; an ed25519-only share for that role is refused, so an Ed25519 break no longer forges a hybrid-registered role (parity with the TypeScript reference). Corpus: `agent-bound-signerset-with-pq-pk` is now `valid:false`; new positive `agent-hybrid-signerset-with-pq-pk`.
- R5-A1 (security): threshold-share verification is now signer-set PINNED, no longer self-vouched. The share must be for the one key the signer set registers for its role, a PQ/hybrid share verifies only under the set's registered `pq_pk` (a differing share `pq_pk` is refused), the share-suite tag is part of the signed bytes (a classical share cannot be relabelled hybrid), and the signer-set hash now includes a registered `pq_pk` (parity with the TypeScript reference). New corpus vectors: `agent-not-in-signer-set`, `agent-bound-signerset-with-pq-pk`, `agent-hybrid-relabel-*`.

- Suite policy defaults documented: no list = no restriction, an empty list refuses everything, and the hosted API defaults to ed25519 + Ed25519 hybrids (README lists the exact list to pass offline).

- R4-01: `verify_chain` now takes the root's PQ authority from the verifier, exactly like the TypeScript reference (R3-01). A non-ed25519 (pure `ml-dsa-65` or hybrid) ROOT hop is accepted only if the new `pq_pins` argument maps `root.issuer` to the root's own `pq_pk`, or the new `trusted_root` argument is the root itself (same content hash, i.e. the verifier's stored grant). Otherwise it is refused with `hop 0: root suite '<alg>' needs a PQ key pinned for the root issuer (policy.pqPins) or the verifier's stored grant (policy.trustedRoot); the root's own pq_pk proves nothing about who issued it (R3-01)`. Before, a pure-PQ root signed with the attacker's own ML-DSA key but naming a victim Ed25519 issuer verified. Callers of `verify_chain` on a root they did not load from their own store must now pass `pq_pins`. `verify_pcactn_core` is unchanged in behaviour (it passes its grant as `trusted_root`). Internally one `_resolve_pq_key` choke point mints the only key type `_verify_suite` accepts, so the PQ verify cannot be called with an artifact key.

- R3-03: the verifier now enforces the F-2 `holder_pq` binding exactly like the TypeScript reference. A hop (index >= 1) or the PCActn leaf signed under `ml-dsa-65` / `hybrid-ed25519-ml-dsa-65` is accepted only if its `pq_pk` hashes to the signer's `holder_pq` commitment; an unbound or attacker-chosen PQ key now fails (`chain` / `leaf_signature`). Hops may carry `holder_pq` (32-byte base64url, part of the signed body). New optional `allowed_suites` argument on `verify_pcactn_core` / `verify_chain` (a present list, even empty, enforces). Natives have no `allowUnboundPq` switch.

## 0.3.0

- Lockstep release with the `@atlasauth/pca*` family. No change to the verifier API or behaviour in this package. Aligns with the 0.3.0 conformance corpus and the fixed reference implementations; adapters now require `atlas-pca>=0.3.0,<0.4`. Upgrade together with the rest of the family.

## 0.2.0 (superseded by 0.3.0)

- New normative check `grant_ref_bound`: the signed `grant_ref` must equal `cap_chain[0].id`. Proofs that
  previously verified with a mismatched `grant_ref` are now rejected (behaviour change).
- Aligned with the 172-vector shared conformance corpus (strings ordered by UTF-8 bytes wherever they feed a
  hash or commitment).
- MIT license metadata and LICENSE file included in the distribution.

## 0.1.0

- Initial release.
