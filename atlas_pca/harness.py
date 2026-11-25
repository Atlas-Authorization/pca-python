"""Attest the mediator, not the weights. The trusted computing base is this small orchestration harness, not an opaque model: the
model is an UNTRUSTED ORACLE that proposes a candidate action, and the harness enforces plan inclusion, the taint fold and the
trust budget before any candidate becomes a signed PCActn. The oracle holds no signing key. Mirrors the TypeScript reference
(@atlasauth/pca-harness), including the resource-server hook that admits an allowlisted harness measurement.

``Harness.step`` takes a plain (synchronous) callable returning the candidate: an async model call is awaited by the caller.
"""
from __future__ import annotations

from ._fin import fin
import math
import threading
import time
from decimal import ROUND_HALF_UP, Decimal
from typing import Any, Callable, Dict, List, Optional, Sequence

from .agent import KeyPair, build_pcactn, commit_plan
from .pca import hash_canonical
from .predicates import _UNDEF, _js_number_string, _js_string
from .risk import DEFAULT_RISK_POLICY, cost, debit, leak, required_threshold, risk_score

# The ordered manifest of checks the harness enforces before signing; folded into the measurement.
ENFORCED_CHECKS = (
    "plan_inclusion_before_signing",
    "taint_provenance_fold",
    "trust_budget_debit",
    "pcactn_sign",
)

# Semantic version of the harness's policy-relevant surface. Bump changes the measurement.
HARNESS_VERSION = "0.1.0"

# The model id stamped into an emitted PCActn's attestation.model_id when attestation is enabled (the mediator, not an LLM).
HARNESS_MODEL_ID = "@atlasauth/pca-harness"

_DEFAULT_BASE_RISK = {"semanticDistance": 0.1, "reversibility": 1, "blastRadius": 0.1, "taint": 0, "confidence": 1, "age": 0}


def compute_harness_measurement(version: Any, enforced_checks: Any, policy: Any) -> str:
    """Pure self-measurement: base64url SHA-256 over the harness version, the enforced-checks manifest and the risk-policy
    identity (weights, theta1, theta2, kappa). A policy missing one of those raises, as the reference's strict canonical form
    refuses an undefined member."""
    if not isinstance(policy, dict):
        raise TypeError("computeHarnessMeasurement: policy is not an object")
    rp: Dict[str, Any] = {}
    for k in ("weights", "theta1", "theta2", "kappa"):
        if k not in policy:
            raise ValueError("canonicalize: unsupported type undefined")
        rp[k] = policy[k]
    return hash_canonical({"harness": HARNESS_MODEL_ID, "version": version, "enforces": enforced_checks, "risk_policy": rp})


# ---- allowlisting verifier ------------------------------------------------------------------------


def _member(v: Any, key: str) -> Any:
    """``v?.key`` for a decoded JSON value: only an object has members (_UNDEF otherwise)."""
    return v.get(key, _UNDEF) if isinstance(v, dict) else _UNDEF


def create_harness_attestation_verifier(config: Dict[str, Any]) -> Callable[[Any], Dict[str, Any]]:
    """The resource-server hook: ``ctx -> {"enforced", "ok"?, "reason"?}`` over ``ctx["pcactn"]["attestation"]``. Fail closed: an
    empty allowlist accepts nothing; an absent measurement fails unless ``required`` is False (then not enforced); a pinned
    ``expectedModelId`` must match; a present measurement outside the allowlist ALWAYS fails. ``config``: ``measurements`` (list of
    allowlisted measurement strings), ``required`` (default True), ``expectedModelId`` (True for the harness id, or a string).
    The measurement's integrity rests on the surrounding verdict requiring the leaf signature to verify."""
    ms = config.get("measurements")
    allow = {m for m in ms if isinstance(m, str) and m} if isinstance(ms, list) else set()
    required = config.get("required") is not False
    em = config.get("expectedModelId")
    expected = HARNESS_MODEL_ID if em is True else em if isinstance(em, str) and em else None

    def hook(ctx: Any) -> Dict[str, Any]:
        if not allow:
            return {"enforced": True, "ok": False, "reason": "harness attestation configured with an empty measurement allowlist (fail closed)"}
        att = _member(_member(ctx, "pcactn"), "attestation")
        m = _member(att, "measurement")
        measurement = m if isinstance(m, str) else ""
        if measurement == "":
            if required:
                return {"enforced": True, "ok": False,
                        "reason": "harness attestation required but the PCActn carries no harness measurement (fail closed)"}
            return {"enforced": False}
        if expected is not None:
            mid = _member(att, "model_id")
            if mid != expected:
                return {"enforced": True, "ok": False, "reason": "attestation.model_id '%s' is not the required harness identity '%s'"
                        % (_js_string(mid), expected)}
        if measurement not in allow:
            return {"enforced": True, "ok": False, "reason": "harness measurement is not in the allowlisted set (unattested or unknown mediator)"}
        return {"enforced": True, "ok": True}

    return hook


# ---- the harness ----------------------------------------------------------------------------------


def _fin(x: Any) -> bool:
    return isinstance(x, (int, float)) and not isinstance(x, bool) and fin(x)


def _js_round(x: float) -> float:
    """Math.round: nearest integer, ties toward +Infinity."""
    f = math.floor(x)
    return f + 1 if x - f >= 0.5 else f


def _to_fixed(x: float, digits: int) -> str:
    """Number.prototype.toFixed for the non-negative finite values the harness reports."""
    if not fin(x) or abs(x) >= 1e21:
        return _js_number_string(x)
    return str(Decimal(x).quantize(Decimal(1).scaleb(-digits), rounding=ROUND_HALF_UP))


def _refuse(reason: str, detail: str) -> Dict[str, Any]:
    return {"ok": False, "reason": reason, "detail": detail}


def _default_nonce() -> str:
    import secrets

    return secrets.token_hex(16)


class Harness:
    """The attested mediator: holds the principal's grant, the committed plan, the signing key and the trust budget, and wraps an
    untrusted model oracle. ``step`` is the ONLY path from an oracle proposal to a signed PCActn; it enforces plan inclusion, then
    the taint fold, then the budget, then signs.

    ``grant`` the principal-signed root capability; ``chain`` the chain ending at the leaf (default ``[grant]``); ``agent_secret``
    the 32-byte Ed25519 seed of the leaf holder (needs ``cryptography`` to sign, or ``allow_insecure_signer=True``); ``plan`` the
    committed plan nodes (non-empty); ``audience`` the resource-server id; ``budget`` ``{"B", "tau", "asOf"}``; ``policy`` a risk
    policy (default DEFAULT_RISK_POLICY); ``base_risk`` overrides of the base risk inputs; ``now`` a clock returning epoch ms;
    ``ttl_ms``; ``measurement_manifest``; ``nonce`` a nonce supplier (default 16 random bytes as hex); ``attestation``
    ``{"operator", "epoch"?}`` to stamp this harness's self-measurement into every emitted PCActn."""

    def __init__(self, grant: Dict[str, Any], agent_secret: bytes, plan: Sequence[Dict[str, Any]], audience: str,
                 budget: Dict[str, Any], chain: Optional[List[Any]] = None, policy: Optional[Dict[str, Any]] = None,
                 base_risk: Optional[Dict[str, Any]] = None, now: Optional[Callable[[], int]] = None,
                 ttl_ms: Optional[int] = None, measurement_manifest: Optional[Sequence[str]] = None,
                 nonce: Optional[Callable[[], str]] = None, attestation: Optional[Dict[str, Any]] = None,
                 allow_insecure_signer: bool = False) -> None:
        if not isinstance(audience, str) or not audience:
            raise ValueError("Harness: `audience` is required (the resource-server / instance id PCActns are for)")
        if not isinstance(agent_secret, (bytes, bytearray)) or len(agent_secret) != 32:
            raise ValueError("Harness: `agent_secret` must be a 32-byte Ed25519 secret key")
        if not isinstance(plan, list) or not plan:
            raise ValueError("Harness: `plan` must be a non-empty array (an empty plan authorises nothing)")
        if len({n["id"] for n in plan}) != len(plan):
            raise ValueError("Harness: plan node ids must be unique")
        if not isinstance(budget, dict) or not _fin(budget.get("B")) or budget["B"] < 0 or not _fin(budget.get("tau")) \
                or not _fin(budget.get("asOf")):
            raise ValueError("Harness: `budget` must have finite B >= 0, tau and asOf")
        self._grant = grant
        self._chain = chain if chain is not None else [grant]
        self._signer = KeyPair(bytes(agent_secret), allow_insecure_signer)
        self._plan = plan
        self._plan_index = {n["id"]: n for n in plan}
        # commit the principal-authorised plan ONCE; every emitted action carries an inclusion proof under this root
        self._committed = commit_plan(plan)
        self._audience = audience
        self._policy = policy if policy is not None else DEFAULT_RISK_POLICY
        self._base_risk = dict(_DEFAULT_BASE_RISK, **(base_risk or {}))
        self._now = now if now is not None else (lambda: int(time.time() * 1000))
        self._ttl_ms = ttl_ms
        self._manifest = measurement_manifest if measurement_manifest is not None else list(ENFORCED_CHECKS)
        self._nonce = nonce if nonce is not None else _default_nonce
        self._attest = attestation
        self._budget = budget
        self._counter = 0
        self._lock = threading.RLock()

    @property
    def plan_root(self) -> str:
        """The committed plan root the principal authorised."""
        return self._committed["root"]

    @property
    def budget(self) -> Dict[str, Any]:
        """The current (leaked-to-last-touch) trust budget."""
        return self._budget

    @property
    def counter(self) -> int:
        """Monotonic action counter: the number of PCActns this harness has emitted."""
        return self._counter

    def harness_measurement(self) -> str:
        """What a remote attestation of the MEDIATOR would cover, in place of the unmeasurable model weights."""
        return compute_harness_measurement(HARNESS_VERSION, self._manifest, self._policy)

    def step(self, propose_action: Callable[[], Any]) -> Dict[str, Any]:
        """Ask the untrusted oracle for a candidate ``{verb, resource, params?, nodeId, inputs?}`` and, only if it survives the
        gate, emit a signed PCActn: ``{"ok": True, "pcactn", "inclusionProof", "risk", "budget"}``, or a refusal ``{"ok": False,
        "reason": "out_of_plan" | "over_budget" | "bad_candidate", "detail", "requiredT"?, "budget"?}``. An oracle that raises, or
        returns a malformed candidate, is a refusal, never an exception."""
        with self._lock:
            return self._step(propose_action)

    def _step(self, propose_action: Callable[[], Any]) -> Dict[str, Any]:
        try:
            candidate = propose_action()
        except Exception as e:  # noqa: BLE001 - the oracle is a model call: any failure is a refusal
            return _refuse("bad_candidate", "oracle failed: %s" % (str(e) if str(e) or e.args else "unknown error"))

        # (0) the oracle is untrusted: validate the shape before use
        if (not isinstance(candidate, dict) or not isinstance(candidate.get("nodeId"), str)
                or not isinstance(candidate.get("verb"), str) or not isinstance(candidate.get("resource"), str)):
            return _refuse("bad_candidate", "oracle returned a malformed candidate")

        # (1) PLAN INCLUSION: reject out-of-plan BEFORE signing
        node = self._plan_index.get(candidate["nodeId"])
        if node is None:
            return _refuse("out_of_plan", "node '%s' is not in the committed plan" % candidate["nodeId"])
        if node.get("verb") != candidate["verb"] or node.get("resource") != candidate["resource"]:
            return _refuse("out_of_plan", "action %s %s does not match committed node '%s' (%s %s)"
                           % (candidate["verb"], candidate["resource"], node["id"], _js_string(node.get("verb", _UNDEF)),
                              _js_string(node.get("resource", _UNDEF))))
        inclusion_proof = self._committed["proof_for"](node["id"])

        # (2) TAINT FOLD: only a well-formed 'trusted' input is trusted; anything else counts as untrusted lineage
        if "inputs" in candidate and not isinstance(candidate["inputs"], list):
            return _refuse("bad_candidate", "candidate.inputs is not an array")
        inputs: List[Dict[str, Any]] = []
        for i in candidate.get("inputs") or []:
            if isinstance(i, dict) and i.get("provenance") == "trusted" and isinstance(i.get("ref"), str):
                inputs.append({"ref": i["ref"], "provenance": "trusted"})
            else:
                ref = i.get("ref") if isinstance(i, dict) else None
                inputs.append({"ref": ref if isinstance(ref, str) else "", "provenance": "untrusted"})
        taint = 1 if any(i["provenance"] == "untrusted" for i in inputs) else 0
        trusted_refs = [i["ref"] for i in inputs if i["provenance"] == "trusted"]
        risk_inputs = dict(self._base_risk, taint=taint)
        # rounded to 6 d.p. so the reported r, the signed risk_claim.r and the budget cost agree and stay canonical
        r = _js_round(risk_score(risk_inputs, self._policy["weights"]) * 1e6) / 1e6
        rt = required_threshold(r, self._policy, node.get("reversibility_class") == "irreversible")

        # (3) TRUST BUDGET: meter machine-only actions, leaking to now first
        now_ms = self._now()
        leaked = leak(self._budget, now_ms, self._policy.get("lambda"))
        c = cost(r, self._policy.get("kappa"))
        if rt["t"] < 3 and not leaked["B"] >= c:
            # the budget cannot cover even a low-risk in-plan action: escalate to a human, debit nothing, produce no PCActn
            self._budget = leaked
            out = _refuse("over_budget", "budget %s < cost %s; step up to a human co-sign" % (_to_fixed(leaked["B"], 4), _to_fixed(c, 4)))
            out["requiredT"] = 3
            out["budget"] = leaked
            return out

        # (4) SIGN
        provenance = {"causal_hash": hash_canonical(inputs), "taint_level": taint, "trusted_refs": trusted_refs}
        attestation = None
        if self._attest is not None:
            ep = self._attest.get("epoch")
            attestation = {"quote_digest": "", "epoch": ep if ep is not None else 0, "model_id": HARNESS_MODEL_ID,
                           "measurement": self.harness_measurement(), "operator": self._attest.get("operator")}
        kw: Dict[str, Any] = {}
        if attestation is not None:
            kw["attestation"] = attestation
        if self._ttl_ms is not None:
            kw["ttl_ms"] = self._ttl_ms
        nonce = self._nonce()
        try:
            pcactn = build_pcactn(self._grant, self._chain, self._plan, node["id"], self._counter + 1, self._signer, self._audience,
                                  params=candidate.get("params"), now=now_ms, nonce=nonce, provenance=provenance,
                                  risk_claim={"r": r, "inputs": dict(risk_inputs)}, **kw)
        except (ValueError, TypeError, KeyError) as e:
            # e.g. params do not match the node's committed params_digest: still never emits an out-of-plan action
            msg = str(e)
            if msg.startswith("build_pcactn:"):
                msg = "buildPCActn:" + msg[len("build_pcactn:"):]
            return _refuse("bad_candidate", "could not build PCActn: %s" % msg)

        # debit only a metered (machine-only, t < 3) action; commit the counter
        self._budget = debit(leaked, c) if rt["t"] < 3 else leaked
        self._counter += 1
        return {"ok": True, "pcactn": pcactn, "inclusionProof": inclusion_proof,
                "risk": {"r": r, "inputs": risk_inputs, "taint": taint, "t": rt["t"]}, "budget": self._budget}
