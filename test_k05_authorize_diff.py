"""k05 differential oracle: the authorize pipeline's 0.5 additions (atlas_pca.authorize: tool_schema validation and
evaluation, risk policy, envelope reading, and authorize() scenarios over provenance by default, fresh_at escalation,
escalation answers and undo admission) against the shared TS-generated testdata/k05-authorize.json.gz."""
import copy

import pytest

import importlib

Z = importlib.import_module("atlas_pca.authorize")  # the package re-exports the authorize() function under this name
from k05_oracle import load, run

COUNT, CASES = load("authorize")
_CALL_KEYS = {"toolSignatureDigest": "tool_signature_digest", "toolSignature": "tool_signature"}


def _evaluate(cav, call):
    if isinstance(call, dict):
        call = {_CALL_KEYS.get(k, k): v for k, v in call.items()}
    ok, reason = Z.evaluate_tool_schema(cav, call)
    return {"ok": True} if ok else {"ok": False, "reason": reason}


# the reference's projection of each step (generator scenario()): these checks, the reasons of the 0.5 checks only
KEY = ["wire", "version", "audience", "validity", "cap_chain", "grant_ref_bound", "plan_inclusion", "plan_root_authorized",
       "leaf_signature", "counter_format", "fresh_at", "attestation", "revocation", "grant_ref", "operation", "params_digest",
       "delegated_caveats", "policy", "replay", "provenance_flow", "undo_window", "escalation"]
OWN = ("provenance_flow: ", "undo_window: ", "escalation: ", "fresh_at: ")


def _ts_names(reason):
    """The reference names its options escalation.render / insecureUnboundApproval; this SDK's are its keyword arguments."""
    return reason.replace("(pass escalation_render, or insecure_unbound_approval=True)", "(set escalation.render, or insecureUnboundApproval)")


def _scenario(sc):
    """One createAuthorizer per scenario (fresh replay store), then each step through authorize()."""
    cfg, grant = sc["config"], sc["grant"]
    store, revoked = Z.MemoryStateStore(), [False]
    esc = cfg.get("escalation") or {}
    undo = cfg.get("undo")
    kw = dict(audience=cfg["audience"], resolve_grant=lambda ref: grant if ref == grant["id"] else None, state_store=store,
              is_revoked=lambda _p, _g: revoked[0], now=cfg["now"], plan="single-step",
              provenance_mediators=cfg["mediators"], fresh_at=cfg.get("freshAt"))
    if "actions" in cfg:
        kw["provenance_actions"] = lambda op: cfg["actions"].get(op["verb"])
    if "observed" in cfg:
        kw["provenance_observed"] = lambda *_a: cfg["observed"]
    if undo is not None:
        kw["undo_admit"] = lambda _p, _g, op: copy.deepcopy(undo[op["verb"]]) if op["verb"] in undo else None
    if cfg.get("escalation") is not None:
        kw["escalation_principals"] = esc["principals"]
        if esc.get("render_digest"):
            kw["escalation_render"] = lambda _p: esc["render_digest"]
        kw["insecure_unbound_approval"] = esc.get("insecureUnboundApproval") is True
    out = []
    for s in sc["steps"]:
        revoked[0] = s.get("revoked") is True
        r = Z.authorize(s["pcactn"], operation=s["operation"], provenance=s.get("provenance"),
                        escalation_answer=s.get("escalationAnswer"), **kw)
        checks = dict(r.checks)
        if "chain" in checks and "cap_chain" not in checks:
            checks["cap_chain"] = checks.pop("chain")  # this SDK's verdict names the chain check `chain`
        out.append({
            "allow": r.allow, "decision": r.decision, "status": r.status,
            "checks": {k: checks[k] for k in KEY if k in checks},
            "failed": [k for k in KEY if checks.get(k) == "fail"],
            "reasons": [_ts_names(x) for x in r.reasons if x.startswith(OWN)],
            "escalation": None if r.escalation is None else (r.escalation if r.allow else {"request": True}),
            "undo": r.undo,
        })
    return out


MAP = {
    "validateArgSchema": (Z.validate_arg_schema, {}),
    "evaluateToolSchema": (_evaluate, {}),
    "validateRiskPolicy": (Z._validate_risk_policy, {}),
    "readEnvelope": (Z.read_envelope, {}),
    "requiresAttestation": (Z._requires_attestation, {}),
    "authorize": (_scenario, {}),
}


def test_corpus_is_the_full_oracle():
    assert COUNT == 13320 and set(CASES) == set(MAP)


@pytest.mark.parametrize("fn", sorted(MAP))
def test_matches_the_reference(fn):
    call, kw = MAP[fn]
    run(CASES[fn], call, **kw)
