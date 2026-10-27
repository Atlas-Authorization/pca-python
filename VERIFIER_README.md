# atlas-pca

> Maturity: **stable** (stable core). See [maturity tiers](https://github.com/Atlas-Authorization/pca/blob/main/docs/maturity.md).

Reference verifier for **Proof-Carrying Authority (PCA)**, an execution-authentication framework for
autonomous agents. With every action the agent presents a self-contained proof-carrying action
(PCActn); the resource server verifies the proof offline instead of trusting a bearer token.

> Status: **0.4.1, unaudited.** Not independently security-reviewed; evaluate before relying on it for
> production authorization decisions.

## Install

```sh
pip install atlas-pca
```

The verifier has no required dependencies. Optional extras: `atlas-pca[fast]` (native Ed25519 via
`cryptography`), `atlas-pca[pq]` (ML-DSA-65 post-quantum signatures via `dilithium-py`),
`atlas-pca[fastapi]`, `atlas-pca[django]`.

## Use

`verify_pcactn_core` is the **structural** verifier: it checks the proof's wire form, chain, signatures, plan
inclusion and validity against the grant you pass in. It does not evaluate the grant's predicates, limits or
caveats, plan authorization, revocation, the trust budget or the threshold, so a passing result is necessary but
not sufficient to perform the action. Pass the grant from your own store (never one the request carries), and take
the authorization decision with a full verifier (the Atlas server's action endpoint, or `verifyPCActn` /
`requirePCA` from `@atlasauth/pca`).

<!-- pca-core-verify: allow structural pre-check; the README states the authorization decision is the full verifier -->
```python
from atlas_pca import verify_pcactn_core

structural = verify_pcactn_core(pcactn, grant_from_your_store, audience="https://api.example.com")
if not structural.allow:
    raise PermissionError(f"authF failed: {structural.reason}")
# structurally valid: now ask the full verifier whether this action is inside the grant
```

## Authorize an operation (0.5)

`authorize` is the full decision for one operation. It runs the structural checks above, then:

- binds the proof to the operation your handler will execute: the signed verb, resource and params digest must equal
  it, and the grant's predicates and caveats are evaluated against those params (a proof signed for $50 cannot pay
  $400);
- evaluates the grant's envelope predicates (default deny), the envelope's caveats, caveats placed on the root grant
  and caveats added by delegation (`max_spend`, `predicates`, `tool_schema`, `expires`, `rate`, ...; an unknown type is
  refused);
- checks revocation with your `is_revoked`;
- consumes the replay counter through an atomic store, only when everything else passed.

Every component is required. Without `audience`, `resolve_grant`, `state_store`, `is_revoked` or the operation, the
call is refused and `result.missing` names what is absent.

<!-- pca-readme-sample: authorize -->
```python
from atlas_pca import SqliteStateStore, authorize

store = SqliteStateStore("pca-replay.db")  # one row per (grant, agent); safe across processes


def is_revoked(pcactn, grant):
    return grant["id"] in revoked_grant_ids  # your revocation list


result = authorize(
    pcactn,
    operation={"verb": "payments.send", "resource": "payments/acme", "params": body},  # what you will execute
    audience="payments-rs",
    resolve_grant=grants.get,  # grant_ref -> grant, from your own store
    state_store=store,
    is_revoked=is_revoked,
    plan="single-step",
)
if not result.allow:
    raise PermissionError(result.reason)  # e.g. "policy: caveat(s) not satisfied: max_spend"
send_payment(**body)
```

- `plan="single-step"` accepts a proof whose plan is this one operation. For a multi-step plan, pass
  `context=lambda pcactn: {"plan": nodes, "plan_authorized": True}` with the plan the principal authorized.
- `result.status` is 200, 401 (no proof, or one that fails authentication) or 403. `result.checks` lists every check;
  `result.operation` (on success) is the bound operation, and `is_authorized_for(result, operation)` re-checks it where
  the side effect runs.
- `MemoryStateStore` is for a single process. Your own store implements `claim(key, counter)` as one atomic operation
  (for example a conditional `UPDATE ... WHERE last_counter < :counter`), returning `ClaimResult(ok, last_counter)`.
- Not covered by `authorize` here: the risk score, trust budget and threshold co-signature from the grant's
  `risk_policy`, revocation epochs and liveness beacons. A grant that pins the agent (`agent_binding`) needs an
  attestation verifier and is refused, and so is a proof carrying `zk_compliance`. The TypeScript `authorize` covers
  these.

The guards run this pipeline by default. A guard built without `authorize` options refuses every request with
403 `authorize_config` (`missing` names the state store and revocation check you still have to supply); it never
falls back to checking the signature only.

```python
from atlas_pca import AuthorizeOptions, require_pca

guard = require_pca(
    audience="payments-rs",
    resolve_grant=grants.get,
    authorize=AuthorizeOptions(state_store=store, is_revoked=is_revoked),  # plan="single-step" by default
    operation=lambda headers, body: {"verb": "payments.send", "resource": "payments/acme", "params": json.loads(body)},
)
```

To verify the signature only (chain, audience, validity, counter format) and nothing else, opt in explicitly with
`signature_only=True` (FastAPI `RequirePCA(..., signature_only=True)`, Django `PCA_SIGNATURE_ONLY = True`). That guard
does not check policy, replay, revocation or the request body, so do those yourself. Passing `signature_only` together
with `authorize` is a configuration error and raises at construction (`ValueError`; Django `ImproperlyConfigured`).

### Check names and denial reasons

- `counter_format` is the stateless check that the counter is a non-negative safe integer; its failure reads
  `counter_format: missing or not a non-negative safe integer`. `replay` is the stateful check that the counter is
  strictly greater than the last one seen for the grant and holder; its failures read
  `replay: 3 is not greater than last seen 3 (replay)`, `replay: 3 was already claimed (replay)` and
  `replay: the replay store failed (fail closed)`. The name `counter` is no longer emitted; in `authorize(require=[...])`
  it is accepted as an alias of `replay`.
- When a predicate's verb and resource match the operation but a limit in its `where` is not met, the denial names the
  limit: `amount <= 100 not satisfied for payments.send on payments/acme`. Operands are spelled out for integers,
  booleans, `null`, short plain strings and short lists (`currency in ["usd", "eur"]`); anything else prints as
  `<number>` or `<value>`. When no predicate is in scope the reason stays `no predicate permits <verb> on <resource>`,
  and an empty list `envelope grants no predicates`.

FastAPI: `RequirePCA(..., authorize=AuthorizeOptions(...), operation=fn)`, where `fn(request, body)` (sync or async)
returns the operation the route executes; `pca.operation` is the bound operation. Django: `PCA_AUTHORIZE` (an
`AuthorizeOptions`, a dict of its fields, or a dotted path) and `PCA_OPERATION` (`fn(request)`, or a dotted path).
A denial happens before the route or view runs.

## Hardware attestation

The package checks hardware evidence itself: AMD SEV-SNP, Intel TDX (DCAP), Azure Attestation, Google Confidential Space and
NVIDIA GPU. Install the `attest` extra (it needs the `cryptography` package; the base package stays dependency-free), build a
verifier from a configuration and run it over the evidence for one action:

```python
from atlas_pca.attest import verifier_from_config

v = verifier_from_config(
    "amd-sev-snp",
    {"family": "genoa", "binding": "report-data", "policy": {"measurements": ["<hex of the 48-byte launch measurement>"]}},
    resolve_evidence=lambda document: document["evidence"],  # the vendor evidence for this action (the default)
)
res = v.verify(document, {"holderPub": key, "grantRef": "passport:" + pid, "epoch": 0, "nonce": nonce}, now_ms)
# res["ok"] and res["bound"]: the quote is genuine, bound to that holder, grant, epoch and nonce; res["measured"] is the measured identity
```

The configuration and the evidence of each vendor are the language-neutral ones of the shared conformance vectors (bytes are
standard base64 strings), and the verifiers answer exactly what the TypeScript verifiers answer, reason text included. They fail
closed: a missing allowlist, trust anchor, issuer, collateral or binding is a denial, never a pass, and a configuration that
would accept anything raises `AttestConstructError` at construction. They are classical (ECDSA, RSA), not post-quantum, and do
no network I/O: the evidence, the collateral (Intel PCS, NVIDIA reference manifests, CRLs, OCSP responses) and the trust anchors
are yours to supply.

To verify hardware-rooted passports with it, pass it as `default_verifier`; an `attest` callable you supply still wins:

```python
from atlas_pca import verify_passport

verify_passport(signed, issuers, now_ms, revoked=revoked, default_verifier=v)  # None, or the reason code
```

## Caveat enforcement (policy layer)

`verify_pcactn_core` (and the `require_pca` / FastAPI / Django guards in `signature_only` mode) does
**not** evaluate caveats. `authorize` above does. To evaluate caveats yourself, call the policy helpers with your own
action context:

```python
from atlas_pca import evaluate_caveats, policy_caveats

ok, failed = evaluate_caveats(policy_caveats(grant, pcactn["cap_chain"]), {
    "now": now_ms,
    "delegation_depth": len(pcactn["cap_chain"]) - 1,
    "action": {"verb": "pay", "resource": "invoice:42", "params": {"amount": 150, "currency": "usd"}},
})
if not ok:
    raise PermissionError(f"caveat(s) not satisfied: {', '.join(failed)}")
```

`policy_caveats(grant, chain)` is the grant's own caveats (the root's, without its first `envelope` caveat) followed by
the caveats the delegation hops appended. Since 0.4.1 the root's caveats are included: caveats placed on the root grant
outside the envelope are enforced exactly like delegated ones. `evaluate_caveats` implements `max_spend` (`{usd}`
against `action.params.amount`, currency absent or `"usd"`/`"USD"`), `expires`, `not_before`, `rate`,
`max_blast_radius`, `reversibility_max`, `delegation_depth` and `budget_alloc`; any other type is unsatisfied (fail
closed). It never raises.

The `PCA-Action` header is strict unpadded base64url of UTF-8 text (`decode_pca_header`): padding, the standard
alphabet, whitespace anywhere or invalid UTF-8 is a 401.

## Optimistic path and transparency ledger (0.5)

Verify what an operator of the optimistic fast path or of a transparency log publishes. All functions are total (they return a verdict, never raise) and accept Ed25519 signatures only.

```python
from atlas_pca import claim_check, settlement_wire_check, verify_tree_head, verify_ledger_consistency, verify_checkpoint_chain

claim_check(claim, pcactn_digest, agent_public, server_now_ms)      # "ok" or the first failing check
settlement_wire_check(record, guardian_public)                      # "ok", "shape", "split", "signature", ...
verify_tree_head(sth, guardian_public, {"witnessKeys": [...], "threshold": 1})   # guardian signature plus witness cosignatures
verify_checkpoint_chain([{"sth": a}, {"sth": b, "proof": proof}], guardian_public)  # {"ok": True} or {"ok": False, "at": i}
```

A log gives tamper evidence only when at least one independent witness cosigns its heads; pass a witness policy to require it.

## Checks

Verification is stateless, fail-closed and runs in a fixed, normative order:
`wire`, `version`, `audience`, `validity`, `chain`, `grant_ref_bound`, `plan_inclusion`,
`leaf_signature`, `counter_format`.

`grant_ref_bound` (new in 0.2.0) requires the signed `grant_ref` to equal the id of the root capability
(`cap_chain[0]`), so replay state cannot be keyed on an attacker-chosen value.

The package runs the shared PCA conformance corpus: 676 PCActn vectors (129 that must verify, 547 that must be
refused) and 984 primitive vectors (canonical JSON, base64url, JSON parsing, Merkle proofs, caveat evaluation,
threshold shares, chain pins and more). The cross-language gate also runs it against the full adversarial set of
4,358 PCActn vectors and 1,178 adversarial primitives. The TypeScript, Rust, Go and other verifiers run the same files. Vectors
that need a signature suite this package does not implement are skipped by the runner; the verifier refuses such a
suite with `unsupported_suite`.

## What a passing result does not cover

`counter_format: pass` is a format check: the counter is a non-negative integer. It does **not** mean the action was
not replayed. `verify_pcactn_core` is stateless by design: the resource server must persist, per grant and agent, the last
accepted counter and refuse anything not strictly greater, atomically across all of its processes. `authorize` does
this through its `state_store`.

By default, `require_pca` and the FastAPI / Django guards run `authorize` (see above), which checks replay,
revocation, caveats, envelope predicates, plan authorization and the request operation, but not risk or thresholds.
With `signature_only=True` they run `verify_pcactn_core` only: no replay, revocation, caveats, envelope predicates or
plan authorization check, and no comparison of the request body with the signed `params_digest`. Do those in your
handler, or delegate the decision to a full verifier.

## Upgrading to 0.5

- **Breaking:** `require_pca`, `RequirePCA` and `PCAMiddleware` run the full `authorize` pipeline by default. Pass
  `authorize=` (state store, revocation check) and an `operation` mapping, or add `signature_only=True` to keep the
  old signature-only behaviour. Without either, requests are refused with 403 `authorize_config`.
- **Breaking:** the core check `counter` is now `counter_format`, and the stateful check in `authorize` is `replay`.
  Rename any code that reads `verdict.checks["counter"]` or `result.checks["counter"]`.
- Denial reasons for an unmet predicate limit now name the limit instead of `no predicate permits ...`.
- Framework adapters (`atlas-pca-*`) require `atlas-pca>=0.5,<0.6`.

## Links

- Source: https://github.com/Atlas-Authorization/pca-python
- Specification and docs: https://github.com/Atlas-Authorization/pca

License: MIT

## Suite policy defaults

- No list (`allowed_suites=None`) means no restriction: the verifier accepts every signature suite it knows.
- An empty list (`allowed_suites=[]`) means refuse everything.
- The hosted API defaults to `ed25519` plus the hybrids that include Ed25519, and refuses the pure post-quantum suites (`ml-dsa-*`, `slh-dsa-*`, `fn-dsa-*`, `less-cat1`) unless the operator lists them. To match it offline, pass `allowed_suites` exactly: `ed25519`, `hybrid-ed25519-ml-dsa-65`, `hybrid-nested-ed25519-ml-dsa-65`, `hybrid-ed25519-ml-dsa-87`, `hybrid-ed25519-slh-dsa-sha2-128f`, `hybrid-ed25519-slh-dsa-sha2-256s`, `hybrid-ed25519-less-cat1`. The effective hosted list is readable at `GET /v1/pca/suites`; see the [wire formats reference](https://github.com/Atlas-Authorization/pca/blob/main/docs/reference/wire-formats.md).
