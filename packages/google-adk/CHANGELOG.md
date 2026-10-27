# Changelog

## Unreleased (0.5.0)

- **Breaking:** the default is the full `authorize` pipeline. A guard built without `authorize` options refuses every call with `authorize_config` (naming the missing store and revocation check); it never downgrades to signature-only. Signature-only is the explicit opt-in `signature_only=True` (`pca_tool(..., signature_only=True)`, `pca_before_tool_callback(..., signature_only=True)`); combining it with `authorize` raises `ValueError`, and a custom `verifier=` needs `signature_only=True`.
- **Breaking:** the dependency range is `atlas-pca>=0.5,<0.6`. The check `counter` is `counter_format` in core verdicts and `replay` in `authorize` results; a replay refusal reads `replay: N is not greater than last seen M (replay)`. An unmet predicate limit is named in the refusal (`amount <= 100 not satisfied for payments.send on payments/acme`).
- Added: `authorize=` (an `atlas_pca.AuthorizeOptions`) runs the full `atlas-pca` 0.5 pipeline for each tool call: the proof must be for exactly this call (the tool's capability with the call arguments as params), and the grant's predicates and caveats, revocation and the replay counter are enforced before the tool runs. `AuthorizeVerifier` is the verifier behind it. Needs `atlas-pca` 0.5.

## 0.4.1 - 2026-10-12

- Requires `atlas-pca>=0.4.1,<0.5`: the 0.4.1 verifier is a security release (root caveats are enforced). No API change in this adapter.

## 0.4.0 - 2026-10-11

- Requires `atlas-pca>=0.4.0,<0.5` (lockstep with the 0.4.0 verifier, which is breaking: strict canonical digests with a depth cap, full signer-set validation in threshold shares, the root PQ pin, caveat and document size caps). No API change in this adapter.

## 0.3.0

- Requires `atlas-pca>=0.3.0,<0.4`. 0.2.0 is superseded: it could not be used with current releases of the framework (see the fixes below).

- Added end-to-end tests against the real framework (Google ADK 2.11.0); run them with `make test-real`.
- Fix: The guarded tool now asks ADK to inject the `ToolContext` even when the tool's own signature does not declare it, so a proof carried in session state is actually seen. Note that a denial raised by `pca_tool` aborts the agent run (fail closed); use `pca_before_tool_callback` to hand the model a deny result instead.
- Optional `test-real` extra pins the framework version the end-to-end tests are validated against.

## 0.2.0 (superseded by 0.3.0)

- Tracks `atlas-pca` 0.2.0, which adds the `grant_ref_bound` verification check.
- Requires `atlas-pca>=0.2.0,<0.3`.
- MIT license metadata and LICENSE file included in the distribution.

## 0.1.0

- Initial release.
