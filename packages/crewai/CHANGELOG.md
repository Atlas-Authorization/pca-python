# Changelog

## Unreleased (0.5.0)

- **Breaking:** the default is the full `authorize` pipeline. A guard built without `authorize` options refuses every call with `authorize_config` (naming the missing store and revocation check); it never downgrades to signature-only. Signature-only is the explicit opt-in `signature_only=True` (`pca_tool(..., signature_only=True)`, `guard_crew(..., signature_only=True)`); combining it with `authorize` raises `ValueError`, and a custom `verifier=` needs `signature_only=True`.
- **Breaking:** the dependency range is `atlas-pca>=0.5,<0.6`. The check `counter` is `counter_format` in core verdicts and `replay` in `authorize` results; a replay refusal reads `replay: N is not greater than last seen M (replay)`. An unmet predicate limit is named in the refusal (`amount <= 100 not satisfied for payments.send on payments/acme`).
- Added: `authorize=` (an `atlas_pca.AuthorizeOptions`) runs the full `atlas-pca` 0.5 pipeline for each tool call: the proof must be for exactly this call (the tool's capability with the call arguments as params), and the grant's predicates and caveats, revocation and the replay counter are enforced before the tool runs. `AuthorizeVerifier` is the verifier behind it. Needs `atlas-pca` 0.5.
- The `test-real` extra now pins CrewAI 1.15.30 (was 1.15.26). 1.15.26 required `uv<0.12`, and uv before 0.13.4 trusts a revoked CA root (PYSEC-2026-4321); the `crewai` extra also carries a `uv>=0.13.4` floor. No change to the adapter's code or runtime dependencies.

## 0.4.1 - 2026-10-12

- Requires `atlas-pca>=0.4.1,<0.5`: the 0.4.1 verifier is a security release (root caveats are enforced). No API change in this adapter.

## 0.4.0 - 2026-10-11

- Requires `atlas-pca>=0.4.0,<0.5` (lockstep with the 0.4.0 verifier, which is breaking: strict canonical digests with a depth cap, full signer-set validation in threshold shares, the root PQ pin, caveat and document size caps). No API change in this adapter.

## 0.3.0

- Requires `atlas-pca>=0.3.0,<0.4`. 0.2.0 is superseded: it could not be used with current releases of the framework (see the fixes below).

- Added end-to-end tests against the real framework (CrewAI 1.15.26); run them with `make test-real`.
- Fix: The guarded tool is now a valid CrewAI tool (earlier builds failed to construct against current CrewAI), and an inline `pca_action` keyword now survives `BaseTool.run` argument validation.
- Optional `test-real` extra pins the framework version the end-to-end tests are validated against.

## 0.2.0 (superseded by 0.3.0)

- Tracks `atlas-pca` 0.2.0, which adds the `grant_ref_bound` verification check.
- Requires `atlas-pca>=0.2.0,<0.3`.
- MIT license metadata and LICENSE file included in the distribution.

## 0.1.0

- Initial release.
