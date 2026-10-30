# atlas-pca-google-adk

> Maturity: **production** (supported for production use). See [maturity tiers](https://github.com/Atlas-Authorization/pca/blob/main/docs/maturity.md).

Google ADK guard for **Proof-Carrying Authority (PCA)**: make every Google ADK tool call proof-carrying and
gated. A tool only runs when the agent carries a valid proof (signatures, capability chain, plan inclusion,
audience, lifetime) whose signed verb and resource satisfy the capability the tool requires. The adapter delegates
all verification to [`atlas-pca`](https://pypi.org/project/atlas-pca/) and reimplements no cryptography.

By default the guard runs the full `atlas-pca` 0.5 `authorize` pipeline: the proof must be for exactly this call (the tool's capability with the call arguments as params), and the grant's predicates and caveats, revocation and the replay counter are enforced before the tool runs (risk scores and thresholds are not evaluated). A guard built without `authorize` options refuses every call with `authorize_config`; it never falls back to checking the signature only. Verifying the signature only is the explicit opt-in `signature_only=True`: then the tool's arguments are not compared with the signed parameters, and replay, revocation, the grant's caveats and limits and plan authorization are not evaluated (`counter_format: pass` is a format check, not replay protection). See Full authorization below.

> Status: **0.5.0.** The adapter delegates every check to `atlas-pca`; it reimplements no cryptography.

### What is tested

The default test suite runs without the framework, against the shared conformance proofs. A second suite, `make test-real` (needs the framework installed), runs against the real framework and is pinned to Google ADK 2.11.0. It covers a real `LlmAgent` run through a real `Runner` with a scripted offline model: proofs in session state, `FunctionTool` wrapping, `before_tool_callback` allow/deny (tampered proof, wrong audience), and the denied-tool path. Each denial test checks that the tool body never ran, and checks the refusal reason wherever the framework surfaces it.

Not covered: other framework versions (only the pinned one is exercised), live model providers (the models are scripted and offline), and any property of the underlying `atlas-pca` verifier beyond what it already documents. This package has not been independently audited.

## Install

```sh
pip install atlas-pca-google-adk
```

This installs `atlas-pca>=0.5,<0.6` as a dependency.

## Use

Entry points: `pca_tool / pca_before_tool_callback`.

```python
from atlas_pca_google_adk import pca_tool
```

See the module docstrings in `atlas_pca_google_adk` for the full API, and the PCA specification for the model.
The verifier applies the full check order, including `grant_ref_bound` (the signed `grant_ref` must equal
the root capability id), as of `atlas-pca` 0.2.0.

## Full authorization (the default, atlas-pca 0.5)

```python
from atlas_pca import AuthorizeOptions, SqliteStateStore, create_provenance_recorder
from atlas_pca_google_adk import pca_tool

# the agent session's provenance recorder, keyed with a secret the model cannot reach
recorder = create_provenance_recorder(mediator="my-agent", kid="k1", secret_key=mediator_seed)
authorize = AuthorizeOptions(state_store=SqliteStateStore("pca-replay.db"), is_revoked=is_revoked,
                             provenance_mediators=[recorder.pin])


@pca_tool("payments.send:payments/acme", audience="payments-rs", resolve_grant=resolve, authorize=authorize,
          recorder=recorder)
def send_payment(amount: float, currency: str) -> str:
    return "sent %s %s" % (amount, currency)
```

The proof must then be for exactly this call: the tool's `verb:resource` with its call arguments as the params. A
validly signed $400 payment under a $100 grant, a $50 proof used for $400, a proof for another tool, a replay or a
revoked grant are refused before the tool runs. `pca_before_tool_callback` takes the same option. Use one authorized
gate per tool, since each consumes the replay counter.

`is_revoked(pcactn, grant)` returns `True` for a revoked grant; `resolve(grant_ref)` returns the grant from your own
store. Every component is required: a missing one refuses the call. The replay counter is consumed only when every
other check passed. Not covered: the risk score, trust budget and threshold co-signature from the grant's
`risk_policy`; a grant that pins the agent (`agent_binding`) is refused.

## Provenance by default

`atlas-pca` 0.5 checks where every call comes from (check `provenance_flow`). A sensitive call whose choice or arguments do
not derive from the principal (an amount read out of an email, a recipient from a web page, or a call with no provenance at
all) is refused as `escalate` before the tool runs. A forged or tampered bundle is refused as `deny`. The gate cannot be
switched off in this adapter: the only opt-out is the grant's own signed `provenance: {"mode": "insecure_off"}`.

The guard forwards each call's provenance bundle to `authorize`, taken from the first of:

1. `provenance=` on `pca_tool`: `(operation) -> bundle | None`;
2. the bundle bound with `pca_context(proof, provenance=bundle)`;
3. `recorder=`: the agent session's `ProvenanceRecorder` builds it (`recorder.for_action(operation)`).

With `recorder=`, every result an allowed tool returns is also recorded as untrusted tool output, so a later call that
uses it escalates. Record the principal's own request yourself (`recorder.principal(text)`) where the agent receives it.
Pin the recording mediator in `AuthorizeOptions(provenance_mediators=[recorder.pin])` (or in the grant's
`provenance.mediators`); a bundle from an unpinned mediator counts as unlabelled. Use `provenance_actions` to declare
which actions are read-only; every unknown action is treated as sensitive. `pca_before_tool_callback` (a `before_tool_callback` never sees the tool's result, so build the pair with `before, after = pca_tool_callbacks(..., recorder=recorder)` and wire both; a before-callback whose recorder has no after-callback refuses every call) take the same `provenance` and `recorder`
options.

## Signature-only mode

To verify only the signature, chain, audience, validity and counter format, pass `signature_only=True` (`pca_tool(..., signature_only=True)`, `pca_before_tool_callback(..., signature_only=True)`). Passing it together with `authorize` raises `ValueError` at construction. In this mode the arguments are not bound, and replay, revocation, caveats and predicates are not checked, so do those in your tool code or a full verifier.

## Fail-closed behaviour

Every row is a call on which the tool does not run. Unless a row says otherwise it is refused in both the default (authorize) mode and `signature_only=True`.

| Missing or invalid | Result |
|---|---|
| No proof presented | Refused: `no proof-carrying action presented` |
| Proof that cannot be decoded (strict base64url or JSON profile) | Treated as no proof; refused |
| `resolve_grant` returns nothing for the proof's `grant_ref` | Refused: `grant_ref does not resolve to a known grant` |
| Bad signature, broken capability chain, wrong or missing audience, outside the validity window, bad counter format | Refused with the failing check named |
| Proof for another verb or resource than the tool requires | Refused: `insufficient capability` |
| A signed $400 call under a $100 grant, arguments that differ from the signed params, a replay, a revoked grant (default mode) | Refused before the tool runs |
| A sensitive call with no provenance bundle, or whose choice or arguments come from tool output, retrieved or web content (default mode) | Refused as `escalate` (`provenance_flow: escalate: ...`) |
| A provenance bundle that is forged, tampered with or bound to another call (default mode) | Refused as `deny` (`provenance_flow: <code>: ...`) |
| `pca_before_tool_callback(recorder=...)` without a `pca_after_tool_callback` for that recorder (use `pca_tool_callbacks`) | Every call refused: `provenance_flow: the recorder has no pca_after_tool_callback wired, ...` |
| The `provenance=` source or the recorder raises (default mode) | Refused: `provenance_flow: the provenance bundle could not be read or recorded (fail closed)` |
| Authorize options missing, or a missing `state_store` or `is_revoked` (default mode) | Every call refused with `authorize_config`; it never falls back to signature-only |
| A tool that declares no capability (default mode) | Refused (`operation`) |
| `authorize` together with `signature_only=True`; `verifier=` without `signature_only=True`; no `resolve_grant`; an empty `audience` | `ValueError` when the guard is built |
| `pca_before_tool_callback` denies a call | Returns a deny result dict (the tool never runs); with `raise_on_deny=True` raises `PcaToolDenied` |
| A tool is absent from the callback's `require` mapping (`signature_only=True`) | Needs only a valid proof for this audience; in default mode it is refused |
| Proof in none of the arguments, the session state or the context | Refused: `no proof-carrying action presented` |

## Limits

- With `signature_only=True`, a tool that `require` does not name needs only a valid proof, not a particular capability.
- Put the authorized gate on one of `pca_tool` or the callback per tool, since each consumes the replay counter.
- The guard checks the proof at the tool boundary of one process. It does not replace the resource server when a tool makes a remote call.
- Replay and trust-budget state live in the `state_store` you supply; a per-process store does not stop a replay across processes. Use a shared store.
- Not evaluated: the risk score, trust budget and threshold co-signature from the grant's `risk_policy`; a grant that pins the agent (`agent_binding`) is refused.
- `signature_only=True` does not bind the arguments or stop replay, revocation or caveat violations.
- The `is_revoked` and `resolve_grant` callbacks are trusted; this package does not authenticate them.
- All verification is delegated to `atlas-pca`; this package reimplements no cryptography. It has not been independently audited.

## Upgrading to 0.5

- **Breaking:** the default is the full `authorize` pipeline. Add `authorize=AuthorizeOptions(state_store=..., is_revoked=...)` (with `resolve_grant`), or `signature_only=True` to keep the old behaviour. A custom `verifier=` now also needs `signature_only=True`.
- **Breaking:** the check name `counter` is now `counter_format` (core verdict) and `replay` (the stateful check in `authorize`); a replay refusal reads `replay: N is not greater than last seen M (replay)`.
- An unmet predicate limit is named in the refusal, e.g. `amount <= 100 not satisfied for payments.send on payments/acme`.
- Requires `atlas-pca>=0.5,<0.6`.
- **Breaking:** provenance by default. A sensitive call now needs a provenance bundle that shows its choice and arguments come
  from the principal; pass `recorder=` (or `provenance=`, or bind it with `pca_context`) and pin the mediator in
  `provenance_mediators`. Without it the call escalates instead of running.

## Links

- Source: https://github.com/Atlas-Authorization/pca-python
- Specification and docs: https://github.com/Atlas-Authorization/pca

License: MIT
