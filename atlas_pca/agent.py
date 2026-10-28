"""Agent / issuer side of PCA: produce the proofs the verifiers in this package check.

Same wire as the TypeScript reference (`mintGrant`, `delegate`, `buildPCActn`, `signEscalationAnswer`, `signDischarge`,
`signPassport`, `signWorkflow`, ...), BYTE-exact wherever the algorithm is deterministic (Ed25519, canonical JSON, digests,
chain structure): the shared producer vectors (`producer-vectors.json`, fixed keys/nonces/timestamps) pin this.

    from atlas_pca.agent import Agent, generate_keypair, mint_grant

An agent never needs a TypeScript process: the principal mints a root grant for the agent's public key, the agent builds
a signed PCActn per action and sends it in the `PCA-Action` header.

Signing is Ed25519 (the optional ``cryptography`` package when installed, else a built-in RFC 8032 signer that is NOT
constant time) plus ML-DSA-65 / ML-DSA-87 and their hybrid / nested-hybrid suites through ``dilithium-py`` (extra ``pq``).
Randomised PQ signatures are not byte-reproducible; they are checked by cross-verification. The other registered suites
(FN-DSA, LESS) are verify-only here and raise `UnsupportedSuite` when asked to sign; SLH-DSA signs through OpenSSL >= 3.5 (ctypes).
"""
import json
import os
import threading
import time
from typing import Any, Callable, Dict, List, Optional, Sequence

from . import ed25519 as _ed
from .pca import (
    REGISTERED_SUITES,
    CAP_DOMAIN,
    DEFAULT_REVERSIBILITY_CLASS,
    PCACTN_VERSION,
    SIG_DOMAIN,
    _SIG_SUITES,
    _build,
    _leaf_hash,
    _plan_leaf,
    _split,
    b64u,
    canonical_bytes_strict,
    canonicalize,
    cap_hash,
    conditions_digest,
    hash_canonical,
    holder_pq_commitment,
    params_digest,
    sha256,
    threshold_message,
    unb64u,
)

__all__ = [
    "Agent", "UnsupportedSuite", "KeyPair", "PqKeyPair", "generate_keypair", "keypair_from_seed", "generate_pq_keypair",
    "sign_with_suite", "sign_artifact", "goal_commit_of", "mint_root", "mint_grant", "delegate", "attenuate", "commit_plan",
    "build_pcactn", "sign_pcactn", "pca_headers", "PCA_HEADER", "escalation_policy_digest", "escalation_action_digest",
    "escalation_history_head", "build_escalation_request", "sign_escalation_answer", "discharge_action_digest", "discharge_digest",
    "needs_discharge_caveat", "sealed_caveat", "max_uses_caveat", "sign_discharge", "sign_narrow", "passport_fingerprint",
    "issue_passport", "sign_passport", "workflow_digest", "receipt_ref", "sign_workflow", "sign_step_receipt", "wf_output",
    "sign_read_grant", "sign_aggregate_grant", "sign_fresh_at", "DEFAULT_RISK_POLICY", "DEFAULT_TTL_MS",
]

PCA_HEADER = "PCA-Action"
DEFAULT_TTL_MS = 20 * 60_000
GOAL_DOMAIN = "atlas-pca/goal/v1\0"
DEFAULT_RISK_POLICY = {
    "weights": {"alpha": 0.25, "beta": 0.2, "gamma": 0.2, "delta": 0.2, "epsilon": 0.1, "zeta": 0.05},
    "theta1": 0.25, "theta2": 0.6, "kappa": 1, "lambda": 0.0005, "rho": 0.5, "bMax": 1,
}


class UnsupportedSuite(ValueError):
    """The suite is registered but this runtime cannot SIGN with it (no backend). Reason token `unsupported_suite: <alg>`."""


# ---- keys ------------------------------------------------------------------------------------------------------------------

def _ed_sign(seed: bytes, msg: bytes) -> bytes:
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    except ImportError:
        return _ed.sign(seed, msg)
    return Ed25519PrivateKey.from_private_bytes(seed).sign(msg)


class KeyPair:
    """An Ed25519 identity. `public` is the base64url key id every artifact names; `seed` is the 32-byte secret."""

    def __init__(self, seed: bytes):
        if not isinstance(seed, (bytes, bytearray)) or len(seed) != 32:
            raise ValueError("an Ed25519 seed is 32 bytes")
        self.seed = bytes(seed)
        self.public = b64u(_ed.public_key(self.seed))

    def sign(self, msg: bytes) -> bytes:
        return _ed_sign(self.seed, msg)

    def __repr__(self) -> str:  # never print the secret
        return "KeyPair(public=%r)" % self.public


def generate_keypair() -> KeyPair:
    return KeyPair(os.urandom(32))


def keypair_from_seed(seed: Any) -> KeyPair:
    """A key pair from 32 raw bytes or their base64url text."""
    return KeyPair(unb64u(seed) if isinstance(seed, str) else seed)


_ML_DSA = {}
try:  # dilithium-py >= 1.0 (FIPS 204 final); pure mode, empty context, interoperable with @noble/post-quantum
    from dilithium_py.ml_dsa import ML_DSA_65 as _M65, ML_DSA_87 as _M87
    _ML_DSA = {"ML-DSA-65": _M65, "ML-DSA-87": _M87}
except Exception:  # pragma: no cover - optional dependency
    pass


class PqKeyPair:
    """An ML-DSA key pair. `public` is the base64url `pq_pk` a suite binds into the signed body."""

    def __init__(self, family: str, public: bytes, secret: bytes):
        self.family, self.public_bytes, self.secret = family, public, secret
        self.public = b64u(public)

    def sign(self, msg: bytes) -> bytes:
        return _ML_DSA[self.family].sign(self.secret, msg)

    def __repr__(self) -> str:
        return "PqKeyPair(family=%r, public=%r...)" % (self.family, self.public[:12])


class _OsslPair:
    """SLH-DSA (and ML-DSA without dilithium-py) through OpenSSL >= 3.5 libcrypto (ctypes)."""

    def __init__(self, family: str):
        from .pq_backends import OpensslKey
        try:
            self._k = OpensslKey(family)
        except RuntimeError as e:
            raise UnsupportedSuite(str(e)) from None
        self.family, self.public_bytes = family, self._k.public
        self.public = b64u(self.public_bytes)

    def sign(self, msg: bytes) -> bytes:
        return self._k.sign(msg)

    def __repr__(self) -> str:
        return "PqKeyPair(family=%r, public=%r...)" % (self.family, self.public[:12])


def generate_pq_keypair(family: str = "ML-DSA-65", seed: Optional[bytes] = None):
    """A fresh (or seed-derived, 32 bytes) key pair of the family: ML-DSA-65 / ML-DSA-87 through dilithium-py (extra `pq`), and
    SLH-DSA-SHA2-128f / 256s (or ML-DSA when dilithium-py is absent) through OpenSSL >= 3.5. Raises UnsupportedSuite when neither backend exists."""
    impl = _ML_DSA.get(family)
    if impl is None:
        if seed is None and family in ("ML-DSA-65", "ML-DSA-87", "SLH-DSA-SHA2-128f", "SLH-DSA-SHA2-256s"):
            return _OsslPair(family)
        raise UnsupportedSuite("unsupported_suite: %s (install atlas-pca[pq] or use OpenSSL >= 3.5)" % family)
    if seed is None:
        pk, sk = impl.keygen()
    else:
        pk, sk = impl.key_derive(seed)
    return PqKeyPair(family, pk, sk)


def sign_with_suite(alg: Optional[str], ed: Optional[KeyPair], pq: Optional[PqKeyPair], msg: bytes) -> Dict[str, str]:
    """Signature parts of `msg` under `alg` (absent == ed25519): {"sig"} and, for a hybrid suite, {"pq_sig"}.
    Hybrid: `sig` is Ed25519 and `pq_sig` the PQ signature over the SAME message (nested: over msg || Ed25519 sig).
    A pure PQ suite puts the PQ signature in `sig`. Fail closed on an unknown suite or missing key material."""
    alg = alg or "ed25519"
    spec = _SIG_SUITES.get(alg)
    if spec is None:
        if alg in REGISTERED_SUITES:  # fn-dsa-*: registered, verified elsewhere, not signable here
            raise UnsupportedSuite("unsupported_suite: %s" % alg)
        raise ValueError("unknown signature alg %r" % (alg,))
    _, needs_pk, needs_pq_sig, key_type, nested = spec
    if not needs_pk:
        if ed is None:
            raise TypeError("'ed25519' needs an Ed25519 key")
        return {"sig": b64u(ed.sign(msg))}
    if key_type == "LESS-cat1":
        raise UnsupportedSuite("unsupported_suite: %s" % alg)
    if pq is None or pq.family != key_type:
        raise TypeError("'%s' needs a %s key pair" % (alg, key_type))
    if not needs_pq_sig:
        return {"sig": b64u(pq.sign(msg))}
    if ed is None:
        raise TypeError("'%s' needs an Ed25519 key" % alg)
    e = ed.sign(msg)
    return {"sig": b64u(e), "pq_sig": b64u(pq.sign(msg + e if nested else msg))}


def _bind_suite(body: dict, alg: Optional[str], pq: Optional[PqKeyPair]) -> dict:
    if not alg or alg == "ed25519":
        return dict(body)
    if pq is None:
        raise TypeError("'%s' needs a PQ key pair" % alg)
    out = dict(body)
    out["alg"] = alg
    out["pq_pk"] = pq.public
    return out


# ---- generic signed artifact (escalation answer, discharge, narrow, passport, workflow, read grant, ...) ---------------------

def sign_artifact(domain: str, body: dict, ed: KeyPair, alg: Optional[str] = None, pq: Optional[PqKeyPair] = None) -> dict:
    """`body` + `sig` (and `alg`/`pq_pk`/`pq_sig` for a non-default suite): the signature covers
    utf8(domain) || strictCanonical(body incl. alg/pq_pk, without sig/pq_sig)."""
    full = _bind_suite(body, alg, pq)
    parts = sign_with_suite(alg, ed, pq, domain.encode("utf-8") + canonical_bytes_strict(full))
    full.update(parts)
    return full


def _sign_body(ed: KeyPair, domain: str, body: Any) -> str:
    return b64u(ed.sign(domain.encode("utf-8") + canonical_bytes_strict(body)))


# ---- capability chain ------------------------------------------------------------------------------------------------------

def goal_commit_of(goal: str, salt: str) -> str:
    """Salted commitment to the plaintext goal: base64url(sha256(canonical({d, goal, salt})))."""
    return hash_canonical({"d": GOAL_DOMAIN, "goal": goal, "salt": salt})


def _clone(v: Any) -> Any:
    return json.loads(canonical_bytes_strict(v).decode("utf-8"))


def _seal(issuer: str, holder: str, caveats: list, parent: Optional[str], holder_pq: Optional[str], ed: KeyPair,
          alg: Optional[str], pq: Optional[PqKeyPair]) -> dict:
    body: Dict[str, Any] = {"issuer": issuer, "holder": holder, "caveats": caveats, "parent": parent}
    if holder_pq is not None:
        body["holder_pq"] = holder_pq
    signable = _bind_suite(body, alg, pq)
    body_digest = hash_canonical(signable)
    parts = sign_with_suite(alg, ed, pq, CAP_DOMAIN + unb64u(body_digest))
    cap: Dict[str, Any] = {"id": body_digest, "issuer": issuer, "holder": holder, "caveats": caveats, "body_digest": body_digest,
                           "sig": parts["sig"]}
    if parent is not None:
        cap["parent"] = parent
    if holder_pq is not None:
        cap["holder_pq"] = holder_pq
    if alg and alg != "ed25519":
        cap["alg"] = alg
        cap["pq_pk"] = pq.public
        if "pq_sig" in parts:
            cap["pq_sig"] = parts["pq_sig"]
    return cap


def mint_root(principal: KeyPair, holder: str, caveats: list, holder_pq: Optional[str] = None, alg: Optional[str] = None,
              pq: Optional[PqKeyPair] = None) -> dict:
    """A root capability signed by the principal. `holder_pq` is the holder's PQ public key (b64u), committed as `holder_pq`."""
    return _seal(principal.public, holder, _clone(caveats), None,
                 holder_pq_commitment(holder_pq) if holder_pq is not None else None, principal, alg, pq)


def delegate(parent: dict, signer: KeyPair, to_holder: Optional[str] = None, added_caveats: Sequence[dict] = (),
             holder_pq: Optional[str] = None, alg: Optional[str] = None, pq: Optional[PqKeyPair] = None) -> dict:
    """A child capability: caveats = parent.caveats ++ added (append-only, so never wider), signed by the parent's holder.
    `to_holder` rebinds the holder (a sub-agent); omitted, the holder is unchanged and keeps its `holder_pq`."""
    holder = parent["holder"] if to_holder is None else to_holder
    if holder_pq is not None:
        hpq: Optional[str] = holder_pq_commitment(holder_pq)
    else:
        hpq = parent.get("holder_pq") if holder == parent["holder"] else None
    return _seal(parent["holder"], holder, _clone(list(parent["caveats"])) + _clone(list(added_caveats)), cap_hash(parent), hpq,
                 signer, alg, pq)


def attenuate(parent: dict, added_caveats: Sequence[dict], signer: KeyPair, **kw: Any) -> dict:
    """Like `delegate` with the same holder."""
    return delegate(parent, signer, None, added_caveats, **kw)


def _risk_policy_error(p: Any) -> Optional[str]:
    if not isinstance(p, dict) or not isinstance(p.get("weights"), dict):
        return "risk_policy.weights missing"
    for k in ("alpha", "beta", "gamma", "delta", "epsilon", "zeta"):
        v = p["weights"].get(k)
        if isinstance(v, bool) or not isinstance(v, (int, float)) or v < 0:
            return "risk_policy.weights.%s must be finite and >= 0" % k
    for k in ("theta1", "theta2", "kappa", "lambda", "rho", "bMax"):
        v = p.get(k)
        if isinstance(v, bool) or not isinstance(v, (int, float)):
            return "risk_policy.%s must be finite" % k
    if p["theta1"] < 0 or p["theta2"] < p["theta1"]:
        return "risk_policy requires 0 <= theta1 <= theta2"
    if p["kappa"] <= 0:
        return "risk_policy.kappa must be > 0"
    if p["lambda"] < 0 or p["rho"] < 0 or p["bMax"] < 0:
        return "risk_policy lambda/rho/bMax must be >= 0"
    return None


_ENV_OPTIONAL = ("objective_risk", "progress", "units", "tighten", "model_polarity", "template_ref", "actions")


def mint_grant(principal: KeyPair, holder: str, envelope: dict, goal: str, salt: Optional[str] = None,
               holder_pq: Optional[str] = None, alg: Optional[str] = None, pq: Optional[PqKeyPair] = None) -> Dict[str, Any]:
    """Root Intent Grant: a root capability whose first caveat is the policy envelope (`predicates`, `caveats`, `agent_binding`,
    `risk_policy`, optional `units`/`tighten`/`actions`/...). Only the salted hash of `goal` goes in the grant. Returns
    {"grant", "goal_commit", "goal_salt"}. Shortcut: the optional envelope members (units, tighten, template_ref, actions) are
    signed as given, not shape-checked here: the verifier refuses a malformed one."""
    if not isinstance(goal, str) or not goal:
        raise ValueError("mint_grant: goal required")
    bad = _risk_policy_error(envelope.get("risk_policy"))
    if bad:
        raise ValueError("mint_grant: " + bad)
    if envelope.get("model_polarity") not in (None, "legacy"):
        raise ValueError("mint_grant: model_polarity must be 'legacy' when present")
    salt = salt if salt is not None else b64u(os.urandom(16))
    commit = goal_commit_of(goal, salt)
    env: Dict[str, Any] = {
        "goal_commit": commit,
        "predicates": envelope["predicates"],
        "caveats": envelope["caveats"],
        "agent_binding": envelope.get("agent_binding") or {},
        "risk_policy": envelope["risk_policy"],
    }
    for k in _ENV_OPTIONAL:
        if envelope.get(k) is not None:
            env[k] = envelope[k]
    env = _clone(env)  # strict-canonical-encodable or it raises: every PCActn embeds the grant in its signed body
    caveat = dict(env)
    caveat["type"] = "envelope"
    grant = mint_root(principal, holder, [caveat], holder_pq, alg, pq)
    return {"grant": grant, "goal_commit": commit, "goal_salt": salt}


# ---- plan + PCActn ---------------------------------------------------------------------------------------------------------

def _plan_leaves(nodes: Sequence[dict]) -> List[dict]:
    return [_plan_leaf(n["id"], n, conditions_digest(n.get("pre"), n.get("post"))) for n in nodes]


def _prove(hs: List[bytes], idx: int, out: List[dict]) -> None:
    if len(hs) == 1:
        return
    k = _split(len(hs))
    if idx < k:
        _prove(hs[:k], idx, out)
        out.append({"side": "R", "hash": b64u(_build(hs[k:]))})
    else:
        _prove(hs[k:], idx - k, out)
        out.append({"side": "L", "hash": b64u(_build(hs[:k]))})


def commit_plan(nodes: Sequence[dict]) -> Dict[str, Any]:
    """Merkle commitment (RFC 6962 shape, domain separated) of a plan. Returns {"root", "proof_for": f(node_id)}. A node is
    {"id", "verb", "resource", "params_digest"?, "reversibility_class"?, "pre"?, "post"?}; an omitted params digest commits
    as the digest of {}."""
    ids = set()
    for n in nodes:
        if n["id"] in ids:
            raise ValueError("commit_plan: duplicate node id %s" % n["id"])
        ids.add(n["id"])
    hs = [_leaf_hash(leaf) for leaf in _plan_leaves(nodes)]
    root = b64u(_build(hs))

    def proof_for(node_id: str) -> dict:
        for i, n in enumerate(nodes):
            if n["id"] == node_id:
                path: List[dict] = []
                _prove(hs, i, path)
                return {"index": i, "size": len(nodes), "path": path}
        raise ValueError("commit_plan: unknown node %s" % node_id)

    return {"root": root, "proof_for": proof_for}


def sign_pcactn(body: dict, leaf: KeyPair, alg: Optional[str] = None, pq: Optional[PqKeyPair] = None) -> dict:
    """Sign a PCActn body with the leaf holder's key (any supported suite: `alg`/`pq_pk` are bound into the signed body)."""
    full = _bind_suite(body, alg, pq)
    parts = sign_with_suite(alg, leaf, pq, threshold_message(full))
    full.update(parts)
    return full


def build_pcactn(grant: dict, chain: list, plan: Sequence[dict], node_id: str, counter: int, signer: KeyPair, aud: str,
                 params: Optional[dict] = None, now: Optional[int] = None, iat: Optional[int] = None, exp: Optional[int] = None,
                 ttl_ms: int = DEFAULT_TTL_MS, nonce: Optional[str] = None, caution: Optional[float] = None,
                 rationale_commitment: Optional[str] = None, progress_step: Optional[dict] = None,
                 prohibition_evidence: Any = None, tool_binding: Optional[str] = None, intent: Optional[dict] = None,
                 intent_session: Optional[dict] = None, fresh_at: Optional[dict] = None, provenance: Optional[dict] = None,
                 attestation: Optional[dict] = None, freshness: Optional[dict] = None, risk_claim: Optional[dict] = None,
                 alg: Optional[str] = None, pq: Optional[PqKeyPair] = None) -> dict:
    """A complete signed PCActn for plan node `node_id`: action = the node's verb/resource/reversibility class, params
    digest = digest of `params`, the signed freshness binding (`aud`, `iat`, `exp`, `nonce`) and the optional signed slots."""
    if not isinstance(aud, str) or not aud:
        raise ValueError("build_pcactn: aud (audience) is required")
    node = next((n for n in plan if n["id"] == node_id), None)
    if node is None:
        raise ValueError("build_pcactn: unknown plan node %s" % node_id)
    digest = params_digest(params)
    if node.get("params_digest") is not None and node["params_digest"] != digest:
        raise ValueError("build_pcactn: params do not match plan node %s's params_digest" % node_id)
    committed = commit_plan(plan)
    at = iat if iat is not None else (now if now is not None else int(time.time() * 1000))
    body: Dict[str, Any] = {
        "ver": PCACTN_VERSION,
        "action": {"verb": node["verb"], "resource": node["resource"], "params_digest": digest,
                   "reversibility_class": node.get("reversibility_class") or DEFAULT_REVERSIBILITY_CLASS},
        "grant_ref": grant["id"],
        "cap_chain": chain,
        "plan": {"root": committed["root"], "inclusion_proof": committed["proof_for"](node_id), "node_id": node_id,
                 "conditions_digest": conditions_digest(node.get("pre"), node.get("post"))},
        # Empty structure stubs when none are supplied: a verifier that enforces attestation / freshness / taint fails them closed.
        "attestation": attestation or {"quote_digest": "", "epoch": 0, "model_id": "unattested", "measurement": "", "operator": "unattested"},
        "provenance": provenance or {"causal_hash": "", "taint_level": 0, "trusted_refs": []},
        "freshness": freshness or {"beacon_ref": "", "epoch": 0, "accumulator_witness": ""},
        "counter": counter,
        "risk_claim": risk_claim or {"r": 0, "inputs": {}},
        "aud": aud,
        "iat": at,
        "exp": exp if exp is not None else at + ttl_ms,
    }
    for k, v in (("nonce", nonce), ("caution", caution), ("rationale_commitment", rationale_commitment),
                 ("progress_step", progress_step), ("prohibition_evidence", prohibition_evidence), ("tool_binding", tool_binding),
                 ("intent", intent), ("intent_session", intent_session), ("fresh_at", fresh_at)):
        if v is not None:
            body[k] = v
    return sign_pcactn(body, signer, alg, pq)


def pca_headers(pcactn: dict, discharges: Optional[Sequence[dict]] = None, narrow: Optional[dict] = None,
                escalation_answer: Optional[dict] = None, fresh_at: Optional[dict] = None) -> Dict[str, str]:
    """HTTP headers the native middleware reads: `PCA-Action` (base64url of the PCActn JSON), and when given
    `PCA-Discharges` (base64url JSON array), `PCA-Narrow`, `PCA-Escalation-Answer` (base64url JSON) and `pca-fresh-at` (JSON)."""
    h = {PCA_HEADER: b64u(canonicalize(pcactn).encode("utf-8"))}
    if discharges:
        h["PCA-Discharges"] = b64u(canonicalize(list(discharges)).encode("utf-8"))
    if narrow is not None:
        h["PCA-Narrow"] = b64u(canonicalize(narrow).encode("utf-8"))
    if escalation_answer is not None:
        h["PCA-Escalation-Answer"] = b64u(canonicalize(escalation_answer).encode("utf-8"))
    if fresh_at is not None:
        h["pca-fresh-at"] = canonicalize(fresh_at)
    return h


# ---- escalation answer -----------------------------------------------------------------------------------------------------

ESCALATION_ANSWER_DOMAIN = "atlas-pca/escalation-answer/v1\0"


def escalation_policy_digest(grant: dict) -> str:
    return hash_canonical({"d": "atlas-pca/escalation-policy/v1", "grant": grant})


def escalation_action_digest(pcactn: dict) -> str:
    return hash_canonical({"d": "atlas-pca/escalation-action/v1", "pcactn": pcactn})


def escalation_history_head(last_counter: Optional[int]) -> str:
    return hash_canonical({"d": "atlas-pca/escalation-history/v1", "last_counter": last_counter})


def build_escalation_request(aud: Optional[str], grant: dict, pcactn: dict, last_counter: Optional[int], reasons: Sequence[str],
                             now: int, ttl_ms: int = 3_600_000, render_digest: Optional[str] = None) -> dict:
    req = {
        "v": 1, "kind": "pca-escalation-request", "aud": aud if isinstance(aud, str) else "",
        "policy_digest": escalation_policy_digest(grant), "action_digest": escalation_action_digest(pcactn),
        "history_head": escalation_history_head(last_counter), "verb": str(pcactn["action"]["verb"]),
        "resource": str(pcactn["action"]["resource"]), "reasons": [str(r)[:512] for r in list(reasons)[:16]],
        "expires_at": now + ttl_ms,
    }
    if render_digest is not None:
        req["render_digest"] = render_digest
    return req


def sign_escalation_answer(principal: KeyPair, request_or_bindings: dict, decision: str, iat: int, expires_at: int,
                           nonce: Optional[str] = None, render_digest: Optional[str] = None, alg: Optional[str] = None,
                           pq: Optional[PqKeyPair] = None) -> dict:
    """The approving principal's signed answer to an escalation request (`decision` is "allow" or "deny"). The answer is bound
    to the request's `policy_digest`, `action_digest` and `history_head`, and (K7) to the approval render the principal saw."""
    if decision not in ("allow", "deny"):
        raise ValueError("decision must be 'allow' or 'deny'")
    body: Dict[str, Any] = {
        "v": 1, "kind": "pca-escalation-answer", "principal": principal.public,
        "policy_digest": request_or_bindings["policy_digest"], "action_digest": request_or_bindings["action_digest"],
        "history_head": request_or_bindings["history_head"], "decision": decision, "iat": iat, "expires_at": expires_at,
        "nonce": nonce if nonce is not None else b64u(os.urandom(16)),
    }
    rd = render_digest if render_digest is not None else request_or_bindings.get("render_digest")
    if rd is not None:
        body["render_digest"] = rd
    return sign_artifact(ESCALATION_ANSWER_DOMAIN, body, principal, alg, pq)


# ---- third-party caveats: discharge, narrow, sealed, max_uses --------------------------------------------------------------

DISCHARGE_DOMAIN = "atlas-pca/discharge/v1\0"
NARROW_DOMAIN = "atlas-pca/narrow/v1\0"


def discharge_action_digest(pcactn: dict) -> str:
    return hash_canonical({"d": "atlas-pca/discharge-action/v1", "pcactn": pcactn})


def discharge_digest(discharge: dict) -> str:
    return hash_canonical({"d": "atlas-pca/discharge-ref/v1", "discharge": discharge})


def needs_discharge_caveat(id: str, issuer: str, issuer_class: str, require: Sequence[dict], bind: str = "chain_hop",
                           ttl_ms: int = 300_000, issuer_spiffe: Optional[str] = None) -> dict:
    """A third-party caveat: the verifier's pin labelled `issuer` (of class `issuer_class`) must sign a discharge whose claims
    satisfy every `require` entry ({"claim", "op": eq|neq|gte|lte|in, "value"})."""
    c = {"type": "needs_discharge", "id": id, "issuer": issuer, "issuer_class": issuer_class, "bind": bind, "ttl_ms": ttl_ms,
         "require": list(require)}
    if issuer_spiffe is not None:
        c["issuer_spiffe"] = issuer_spiffe
    return c


def sealed_caveat() -> dict:
    """No hop may be appended below the hop that carries it."""
    return {"type": "sealed"}


def max_uses_caveat(id: str, n: int, until: int) -> dict:
    """A lifetime use count backed by the verifier's replay store (1..256 uses, expires at `until` epoch ms)."""
    return {"type": "max_uses", "id": id, "n": n, "until": until}


def sign_discharge(issuer: KeyPair, caveat_id: str, issuer_label: str, cap_hash_of_hop: str, claims: Dict[str, Any], iat: int,
                   not_after: int, bind: str = "chain_hop", action_digest: Optional[str] = None, nonce: Optional[str] = None,
                   alg: Optional[str] = None, pq: Optional[PqKeyPair] = None) -> dict:
    """The pinned third party's discharge of a `needs_discharge` caveat (`cap_hash_of_hop` = capHash of the hop carrying it;
    `bind` "action" also needs the `discharge_action_digest` of the exact PCActn)."""
    body: Dict[str, Any] = {"v": 1, "kind": "pca-discharge", "caveat_id": caveat_id, "issuer": issuer_label,
                            "cap_hash": cap_hash_of_hop, "bind": bind, "claims": claims, "iat": iat, "not_after": not_after,
                            "nonce": nonce if nonce is not None else b64u(os.urandom(16))}
    if action_digest is not None:
        body["action_digest"] = action_digest
    return sign_artifact(DISCHARGE_DOMAIN, body, issuer, alg, pq)


def sign_narrow(holder: KeyPair, leaf_cap_hash: str, caveats: Sequence[dict], iat: int, not_after: int,
                action_digest: Optional[str] = None, nonce: Optional[str] = None, alg: Optional[str] = None,
                pq: Optional[PqKeyPair] = None) -> dict:
    """The leaf holder's self-attenuation (per action when `action_digest` is set), presented beside the PCActn."""
    body: Dict[str, Any] = {"v": 1, "kind": "pca-narrow", "cap_hash": leaf_cap_hash, "holder": holder.public,
                            "caveats": list(caveats), "iat": iat, "not_after": not_after,
                            "nonce": nonce if nonce is not None else b64u(os.urandom(16))}
    if action_digest is not None:
        body["action_digest"] = action_digest
    return sign_artifact(NARROW_DOMAIN, body, holder, alg, pq)


# ---- passport --------------------------------------------------------------------------------------------------------------

PASSPORT_SIG_DOMAIN = "atlas-pca/passport-sig/v1\0"


def passport_fingerprint(p: dict) -> str:
    return hash_canonical({
        "d": "atlas-pca/passport/v1", "model_id": p["model_id"], "weights_digest": p.get("weights_digest"),
        "system_prompt_digest": p.get("system_prompt_digest"), "tool_manifest_digest": p.get("tool_manifest_digest"),
        "runtime_measurement": p.get("runtime_measurement"), "operator": p["operator"],
        "hardware_rooted": p["hardware_rooted"]})


def issue_passport(identity: dict) -> dict:
    """Fill `id` from the content fingerprint of the identity fields."""
    out = dict(identity)
    out["id"] = passport_fingerprint(identity)
    return out


def sign_passport(passport: dict, issuer: KeyPair, subject: str, exp: int, iat: Optional[int] = None, nbf: Optional[int] = None,
                  evidence: Optional[dict] = None, alg: Optional[str] = None, pq: Optional[PqKeyPair] = None) -> dict:
    """Sign a passport for the agent key `subject`. Fail closed: a hardware_rooted passport needs evidence."""
    if passport.get("id") != passport_fingerprint(passport):
        raise ValueError("sign_passport: passport.id is not the fingerprint of its identity (use issue_passport)")
    if passport.get("hardware_rooted") and not evidence:
        raise ValueError("sign_passport: hardware_rooted requires attestation evidence (fail closed)")
    at = iat if iat is not None else passport["issued_at"]
    nb = nbf if nbf is not None else at
    if exp <= nb:
        raise ValueError("sign_passport: exp must be after nbf")
    body: Dict[str, Any] = {"typ": "atlas-pca/passport", "ver": 1, "passport": passport, "iss": issuer.public, "sub": subject,
                            "iat": at, "nbf": nb, "exp": exp}
    if evidence:
        ev = dict(evidence)
        ev.setdefault("at", at)
        body["evidence"] = ev
    return sign_artifact(PASSPORT_SIG_DOMAIN, body, issuer, alg, pq)


# ---- workflow commitment + step receipts (resource-server side), read grants, aggregate grants, fresh_at -------------------

WORKFLOW_DOMAIN = "atlas-pca/workflow/v1\0"
WF_RECEIPT_DOMAIN = "atlas-pca/wf-receipt/v1\0"


def workflow_digest(body: dict) -> str:
    return hash_canonical({"d": "atlas-pca/workflow-ref/v1", "w": body})


def receipt_ref(receipt: dict) -> str:
    return hash_canonical({"d": "atlas-pca/wf-receipt-ref/v1", "r": receipt})


def sign_workflow(principal: KeyPair, body: dict) -> dict:
    """The principal's signed workflow commitment (a DAG of steps). The principal key must be `body["principal"]`."""
    if body.get("principal") != principal.public:
        raise ValueError("sign_workflow: principal is not the signer")
    return {"body": body, "sig": _sign_body(principal, WORKFLOW_DOMAIN, body)}


def wf_output(value: Any, labels: Optional[Sequence[str]] = None, unit: Optional[str] = None, num: bool = False) -> dict:
    """A receipt output for `value`; `num` is carried only for integers an edge may compare."""
    from .workflow import value_digest
    return {"digest": value_digest(value), "num": value if num and isinstance(value, int) and not isinstance(value, bool) else None,
            "unit": unit, "labels": sorted(labels or [])}


def sign_step_receipt(rs: KeyPair, workflow: dict, step: str, outcome: str, params_dig: str, outputs: Dict[str, dict],
                      issued_at: int, prev: Optional[dict] = None) -> dict:
    """The resource server's signed receipt for a workflow step (`prev` = the previous receipt of the same workflow)."""
    base = {"v": 1, "wf": workflow_digest(workflow), "step": step, "seq": prev["seq"] + 1 if prev else 0,
            "prev": receipt_ref(prev) if prev else None, "outcome": outcome, "params_digest": params_dig, "outputs": outputs,
            "issued_at": issued_at, "signer": rs.public}
    out = dict(base)
    out["sig"] = _sign_body(rs, WF_RECEIPT_DOMAIN, base)
    return out


def sign_read_grant(principal: KeyPair, body: dict) -> dict:
    """The principal's signed read grant ({"body", "sig"}); `body["principal"]` must be the signer."""
    if body.get("principal") != principal.public:
        raise ValueError("sign_read_grant: principal is not the signer")
    return {"body": body, "sig": _sign_body(principal, "atlas-pca/read-grant/v1\0", body)}


def sign_aggregate_grant(principal: KeyPair, body: dict) -> dict:
    if body.get("principal") != principal.public:
        raise ValueError("sign_aggregate_grant: principal is not the signer")
    return {"body": body, "sig": _sign_body(principal, "atlas-pca/aggregate-grant/v1\0", body)}


def sign_fresh_at(signer: KeyPair, scope: str, state: dict, issued_at: int) -> dict:
    """A signed consistency token: the high-water mark of the verifier-side state a write produced."""
    base = {"v": 1, "scope": scope, "revocation_epoch": state["revocation_epoch"], "ledger_tree_size": state["ledger_tree_size"],
            "budget_version": state["budget_version"], "policy_revision": state["policy_revision"],
            "policy_digest": state["policy_digest"], "issued_at": issued_at, "signer": signer.public}
    out = dict(base)
    out["sig"] = _sign_body(signer, "atlas-pca/fresh-at/v1\0", base)
    return out


# ---- the high-level client -------------------------------------------------------------------------------------------------

class Action:
    """One signed action: the `pcactn`, the `headers` to send and the plan node it was built for."""

    def __init__(self, pcactn: dict, headers: Dict[str, str], node_id: str):
        self.pcactn, self.headers, self.node_id = pcactn, headers, node_id


class Agent:
    """An agent holding a grant (or a delegated chain). It keeps the replay counter, picks nonces and builds the headers.

        agent = Agent(key, grant, aud="https://api.example.com")
        act = agent.act("refund", "orders/1", {"amount_cents": 500})
        requests.post(url, json=body, headers=act.headers)

    `chain` defaults to `[grant]`. `counter` is the last counter used (the next action uses counter + 1); persist it
    through `on_counter` if the process can restart (a lower counter is refused as a replay). Thread safe.
    """

    def __init__(self, key: KeyPair, grant: dict, aud: str, chain: Optional[list] = None, counter: int = 0,
                 clock: Callable[[], int] = lambda: int(time.time() * 1000), ttl_ms: int = DEFAULT_TTL_MS,
                 on_counter: Optional[Callable[[int], None]] = None, alg: Optional[str] = None, pq: Optional[PqKeyPair] = None):
        self.key, self.grant, self.aud = key, grant, aud
        self.chain = chain if chain is not None else [grant]
        self.counter, self.clock, self.ttl_ms, self.on_counter = counter, clock, ttl_ms, on_counter
        self.alg, self.pq = alg, pq
        self._plan: Optional[List[dict]] = None
        self._lock = threading.Lock()

    @property
    def public(self) -> str:
        return self.key.public

    def use_plan(self, nodes: Sequence[dict]) -> "Agent":
        """Commit to a multi-step plan; `act(..., node_id=...)` then signs against its node (and its Merkle proof)."""
        self._plan = list(nodes)
        return self

    def _next(self) -> int:
        with self._lock:
            self.counter += 1
            if self.on_counter is not None:
                self.on_counter(self.counter)
            return self.counter

    def act(self, verb: str, resource: str, params: Optional[dict] = None, node_id: Optional[str] = None,
            reversibility_class: Optional[str] = None, nonce: Optional[str] = None, **opts: Any) -> Action:
        """Build and sign the PCActn for one action. Without a committed plan this commits a one-node plan for the action.
        `opts` are `build_pcactn` keywords (caution, fresh_at, intent, ttl_ms, ...). Also returns the `PCA-Action` headers; pass
        `discharges=`, `narrow=` or `escalation_answer=` to add the headers that carry them."""
        hdr = {k: opts.pop(k) for k in ("discharges", "narrow", "escalation_answer") if k in opts}
        if self._plan is not None:
            plan = self._plan
            nid = node_id or next((n["id"] for n in plan if n["verb"] == verb and n["resource"] == resource), None)
            if nid is None:
                raise ValueError("act: no node of the committed plan matches %s %s" % (verb, resource))
        else:
            nid = node_id or "n1"
            node = {"id": nid, "verb": verb, "resource": resource, "params_digest": params_digest(params)}
            if reversibility_class:
                node["reversibility_class"] = reversibility_class
            plan = [node]
        opts.setdefault("ttl_ms", self.ttl_ms)
        counter = self._next()
        p = build_pcactn(self.grant, self.chain, plan, nid, counter, self.key, self.aud, params=params,
                         now=self.clock(), nonce=nonce if nonce is not None else b64u(os.urandom(16)),
                         alg=self.alg, pq=self.pq, **opts)
        return Action(p, pca_headers(p, **hdr), nid)

    def delegate(self, to: KeyPair, caveats: Sequence[dict] = (), holder_pq: Optional[str] = None) -> "Agent":
        """A sub-agent signing with `to`, holding this chain plus one narrower hop (caveats are only ever appended)."""
        cap = delegate(self.chain[-1], self.key, to.public, caveats, holder_pq=holder_pq, alg=self.alg, pq=self.pq)
        return Agent(to, self.grant, self.aud, self.chain + [cap], 0, self.clock, self.ttl_ms)

    def fetch(self, method: str, url: str, verb: str, resource: str, params: Optional[dict] = None, body: Optional[bytes] = None,
              headers: Optional[Dict[str, str]] = None, timeout: float = 30.0, **act_opts: Any):
        """Sign an action and send an HTTP request with the headers attached (standard library; returns the `urlopen`
        response). Use `act()` and your own client when you need more control."""
        import urllib.request
        a = self.act(verb, resource, params, **act_opts)
        h = dict(headers or {})
        h.update(a.headers)
        req = urllib.request.Request(url, data=body, method=method, headers=h)
        return urllib.request.urlopen(req, timeout=timeout)  # noqa: S310 - the caller chooses the URL scheme
