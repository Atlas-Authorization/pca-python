# Changelog

## Unreleased (0.5.0)

- Tier: production (pending CI), up from experimental: the full `authorize` pipeline is the default, and the README has a fail-closed table and a limits section. Version 0.5.0 in lockstep.
- **Breaking:** the default is the full `authorize` pipeline. A guard built without `authorize` options refuses every call with `authorize_config` (naming the missing store and revocation check); it never downgrades to signature-only. Signature-only is the explicit opt-in `signature_only=True` (`pca_guard(..., signature_only=True)`); combining it with `authorize` raises `ValueError`, and a custom `verifier=` needs `signature_only=True`.
- **Breaking:** the dependency range is `atlas-pca>=0.5,<0.6`. The check `counter` is `counter_format` in core verdicts and `replay` in `authorize` results; a replay refusal reads `replay: N is not greater than last seen M (replay)`. An unmet predicate limit is named in the refusal (`amount <= 100 not satisfied for payments.send on payments/acme`).
- **Breaking:** provenance by default. The agent's provenance bundle (request `_meta` `PCA-Provenance`, base64url JSON; the tool arguments are the fallback and the key is stripped before the tool runs) is forwarded to `authorize`, whose `provenance_flow` check refuses a sensitive call whose choice or arguments do not derive from the principal (`escalate`) or whose bundle is forged (`deny`); an undecodable bundle is refused. New `extract_provenance` / `PROV_META_KEY`, and `recorder=` on `pca_guard` for an agent running in the same process (it builds the bundle for a call that presents none and records every tool result as untrusted tool output). Pin the agent's mediator in `AuthorizeOptions(provenance_mediators=...)`.
- Added: `authorize=` (an `atlas_pca.AuthorizeOptions`) runs the full `atlas-pca` 0.5 pipeline for each tool call: the proof must be for exactly this call (the tool's capability with the call arguments as params), and the grant's predicates and caveats, revocation and the replay counter are enforced before the tool runs. `AuthorizeVerifier` is the verifier behind it. Needs `atlas-pca` 0.5.

## 0.4.1 - 2026-10-12

- Requires `atlas-pca>=0.4.1,<0.5`: the 0.4.1 verifier is a security release (root caveats are enforced). No API change in this adapter.

## 0.4.0 - 2026-10-11

- Requires `atlas-pca>=0.4.0,<0.5` (lockstep with the 0.4.0 verifier, which is breaking: strict canonical digests with a depth cap, full signer-set validation in threshold shares, the root PQ pin, caveat and document size caps). No API change in this adapter.

## 0.3.0

- Requires `atlas-pca>=0.3.0,<0.4`. 0.2.0 is superseded: it could not be used with current releases of the framework (see the fixes below).

- Added end-to-end tests against the real framework (FastMCP 4.1.0); run them with `make test-real`.
- Fix: A proof carried in tool arguments is now stripped after verification so a tool with a strict schema accepts the call.
- Optional `test-real` extra pins the framework version the end-to-end tests are validated against.

## 0.2.0 (superseded by 0.3.0)

- Tracks `atlas-pca` 0.2.0, which adds the `grant_ref_bound` verification check.
- Requires `atlas-pca>=0.2.0,<0.3`.
- MIT license metadata and LICENSE file included in the distribution.

## 0.1.0

- Initial release.
