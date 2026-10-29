# Changelog

## Unreleased (0.5.0)

- Tier: production (pending CI), up from experimental: the full `authorize` pipeline is the default, and the README has a fail-closed table and a limits section. Version 0.5.0 in lockstep.
- **Breaking:** the default is the full `authorize` pipeline. A guard built without `authorize` options refuses every call with `authorize_config` (naming the missing store and revocation check); it never downgrades to signature-only. Signature-only is the explicit opt-in `signature_only=True` (`pca_tool(..., signature_only=True)`, `pca_before_tool_callback(..., signature_only=True)`); combining it with `authorize` raises `ValueError`, and a custom `verifier=` needs `signature_only=True`.
- **Breaking:** the dependency range is `atlas-pca>=0.5,<0.6`. The check `counter` is `counter_format` in core verdicts and `replay` in `authorize` results; a replay refusal reads `replay: N is not greater than last seen M (replay)`. An unmet predicate limit is named in the refusal (`amount <= 100 not satisfied for payments.send on payments/acme`).
- **Breaking:** provenance by default. Each tool call's provenance bundle is forwarded to `authorize`, whose `provenance_flow` check refuses a sensitive call whose choice or arguments do not derive from the principal (`escalate`) or whose bundle is forged (`deny`). New `provenance=` (a per-call bundle source) and `recorder=` (the agent session's `ProvenanceRecorder`: it builds the bundle for a call that presents none and records every allowed tool result as untrusted tool output) on `pca_tool` and `pca_before_tool_callback`; new `pca_tool_callbacks(..., recorder=...)` returns the before/after pair (the after-callback records each tool result, which a `before_tool_callback` never sees), and a before-callback whose recorder has no after-callback refuses every call; `pca_context(proof, provenance=bundle)` binds a bundle; `current_provenance()` reads it. Pin the recording mediator in `AuthorizeOptions(provenance_mediators=...)`.
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
