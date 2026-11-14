"""Runs one producer vector case (producer-vectors.json and producer-pq-vectors.json format) through this SDK's producers.

Shared by the producer tests and the cross-language driver: `run(case, keys, pq_keys)` returns the produced artifact, shaped
like the case's `expect` (the reference's member names), or raises what the producer raised. `keys` maps a key name to an
Ed25519 KeyPair, `pq_keys` a PQ key name to its seed entry ({family, seed}). An op this SDK does not know raises NotProduced.
"""
from typing import Any, Callable, Dict, Optional

from atlas_pca import contract_enforcer, contracts, prohibitions, undo
from atlas_pca.agent import (KeyPair, build_pcactn, commit_plan, delegate, discharge_digest, escalation_action_digest,
                             escalation_history_head, escalation_policy_digest, generate_pq_keypair, goal_commit_of,
                             issue_passport, keypair_from_seed, mint_grant, mint_root, pca_headers, sign_aggregate_grant,
                             sign_discharge, sign_escalation_answer, sign_fresh_at, sign_narrow, sign_passport, sign_pcactn,
                             sign_read_grant, sign_step_receipt, sign_with_suite, sign_workflow)
from atlas_pca.arg_provenance import create_provenance_recorder
from atlas_pca.facade import compile_policy, create_agent, parse_limit
from atlas_pca.pca import b64u, params_digest, unb64u
from atlas_pca import signers_more as S

# The reference names PQ families in lower case.
FAMILIES = {"ml-dsa-65": "ML-DSA-65", "ml-dsa-87": "ML-DSA-87", "slh-dsa-sha2-128f": "SLH-DSA-SHA2-128f",
            "slh-dsa-sha2-256s": "SLH-DSA-SHA2-256s", "fn-dsa-512": "FN-DSA-512", "fn-dsa-1024": "FN-DSA-1024"}

# Experimental artifacts this SDK does not verify, so it does not produce them either (they stay with the reference).


class NotProduced(Exception):
    """The op names an artifact this SDK does not produce."""


def keys_of(doc_keys: Dict[str, Any]) -> Dict[str, KeyPair]:
    return {n: keypair_from_seed(k["seed"]) for n, k in doc_keys.items()}


class PqKeys:
    """Lazily derived PQ key pairs by name (`<role>/<family>`), cached: seeded keygen is slow in pure Python."""

    def __init__(self, entries: Optional[Dict[str, Any]]):
        self._entries, self._cache = entries or {}, {}

    def __call__(self, name: Optional[str]):
        if name is None:
            return None
        if name not in self._cache:
            e = self._entries[name]
            self._cache[name] = generate_pq_keypair(FAMILIES.get(e["family"], e["family"]), unb64u(e["seed"]))
        return self._cache[name]


def _facade_act(a: dict, K: Dict[str, KeyPair]) -> dict:
    rec = K[a["recorder_key"]]
    h = create_agent(principal=K[a["principal"]], goal=a["goal"], permissions=a["permissions"], limits=a.get("limits"),
                     holder=K[a["holder"]], aud=a["aud"], now=a["now"], goal_salt=a["goal_salt"],
                     provenance={"secret_key": rec.seed, "session": a["session"], "now": lambda: a["now"]})
    grant = h.grant
    if "sub_agent" in a:
        h = h.sub_agent(holder=K[a["sub_agent"]["holder"]], added_caveats=a["sub_agent"]["added_caveats"])
    for t in a.get("principal_messages") or []:
        h.provenance.principal(t)
    act = a["act"]
    r = h.act(act["verb"], act["resource"], act.get("params"), counter=act["counter"], now=act["now"], nonce=act.get("nonce"))
    return {"grant": grant, "goal_commit": grant["caveats"][0]["goal_commit"], "chain": h.chain, "pcactn": r["pcactn"],
            "encoded": r["encoded"], "provenance": r["provenance"]}


def _prov_recorder(a: dict, K: Dict[str, KeyPair]) -> dict:
    clock = iter(a["clock"])
    r = create_provenance_recorder(mediator=a["mediator"], kid=a["kid"], secret_key=K[a["key"]].seed, session=a["session"],
                                   now=lambda: next(clock))
    outs = []
    for s in a["steps"]:
        k = s["kind"]
        if k == "principal":
            outs.append(r.principal(s["text"]))
        elif k == "tool":
            outs.append(r.tool(s["name"], s["output"]))
        elif k == "web":
            outs.append(r.web(s["url"], s["content"]))
        elif k == "retrieval":
            outs.append(r.retrieval(s["source"], s["content"]))
        else:
            outs.append(r.for_action(s["op"]))
    return {"pin": r.pin, "receipts": outs[:-1], "bundle": outs[-1]}


def _compile(a: dict) -> dict:
    p = compile_policy(a["permissions"], a.get("limits"), budget_model=a.get("budget_model"), now=a["now"])
    return {k: v for k, v in p.items() if k not in ("actions", "inputLimits")}


def _act(a: dict, K: Dict[str, KeyPair]) -> dict:
    p = build_pcactn(a["grant"], a["chain"], a["plan"], a["node_id"], a["counter"], K[a["signer"]], a["aud"],
                     params=a.get("params"), iat=a["iat"], exp=a["exp"], nonce=a.get("nonce"), caution=a.get("caution"),
                     rationale_commitment=a.get("rationale_commitment"), tool_binding=a.get("tool_binding"),
                     fresh_at=a.get("fresh_at"))
    return {"pcactn": p, "header": pca_headers(p)["PCA-Action"]}


def _artifact_suite(a: dict, K: Dict[str, KeyPair], PQ: PqKeys) -> dict:
    b, alg, pq = a["body"], a["alg"], PQ(a["pq"])
    if a["kind"] == "escalation_answer":
        return sign_escalation_answer(K[a["signer"]], b, b["decision"], b["iat"], b["expires_at"], b["nonce"],
                                      b.get("render_digest"), alg=alg, pq=pq)
    return S.sign_revocation_epoch(K[a["signer"]], b, alg, pq)


def run(case: dict, K: Dict[str, KeyPair], PQ: Optional[PqKeys] = None) -> Any:
    a, op = case["args"], case["op"]
    PQ = PQ or PqKeys(None)
    ops: Dict[str, Callable[[], Any]] = {
        # ---- producer-vectors.json: Ed25519 -------------------------------------------------------------------------------
        "ed25519_sign": lambda: (lambda k: {"public": k.public, "sig": b64u(k.sign(a["message_utf8"].encode("utf-8")))})(
            keypair_from_seed(a["seed"])),
        "goal_commit": lambda: {"commit": goal_commit_of(a["goal"], a["salt"])},
        "params_digest": lambda: {"digest": params_digest(a["params"])},
        "plan_commit": lambda: (lambda p: {"root": p["root"], "proofs": {n["id"]: p["proof_for"](n["id"]) for n in a["nodes"]}})(
            commit_plan(a["nodes"])),
        "mint_grant": lambda: mint_grant(K[a["principal"]], K[a["holder"]].public, a["envelope"], a["goal"], a["salt"]),
        "delegate": lambda: delegate(a["parent"], K[a["signer"]], K[a["to_holder"]].public if a["to_holder"] else None,
                                     a["added_caveats"]),
        "act": lambda: _act(a, K),
        "fresh_at": lambda: sign_fresh_at(K[a["signer"]], a["scope"], a["state"], a["issued_at"]),
        "escalation_digests": lambda: {"policy_digest": escalation_policy_digest(a["grant"]),
                                       "action_digest": escalation_action_digest(a["pcactn"]),
                                       "history_head": escalation_history_head(a["last_counter"])},
        "sign_escalation_answer": lambda: sign_escalation_answer(K[a["signer"]], a["body"], a["body"]["decision"],
                                                                 a["body"]["iat"], a["body"]["expires_at"], a["body"]["nonce"],
                                                                 a["body"].get("render_digest")),
        "sign_discharge": lambda: (lambda b: sign_discharge(K[a["signer"]], b["caveat_id"], b["issuer"], b["cap_hash"],
                                                            b["claims"], b["iat"], b["not_after"], b["bind"],
                                                            b.get("action_digest"), b["nonce"]))(a["body"]),
        "discharge_digest": lambda: {"digest": discharge_digest(a["discharge"])},
        "sign_narrow": lambda: (lambda b: sign_narrow(K[a["signer"]], b["cap_hash"], b["caveats"], b["iat"], b["not_after"],
                                                      b.get("action_digest"), b["nonce"]))(a["body"]),
        "sign_passport": lambda: (lambda pp: {"passport": pp, "signed": sign_passport(pp, K[a["issuer"]], K[a["subject"]].public,
                                                                                      a["exp"])})(issue_passport(a["identity"])),
        "sign_workflow": lambda: sign_workflow(K[a["signer"]], a["body"]),
        "sign_step_receipt": lambda: sign_step_receipt(K[a["signer"]], a["workflow"], a["step"], a["outcome"],
                                                       a["params_digest"], a["outputs"], a["issued_at"], a.get("prev")),
        "sign_read_grant": lambda: sign_read_grant(K[a["signer"]], a["body"]),
        "sign_aggregate_grant": lambda: sign_aggregate_grant(K[a["signer"]], a["body"]),
        "sign_revocation_epoch": lambda: S.sign_revocation_epoch(K[a["signer"]], a["body"]),
        "sign_undo_token": lambda: undo.sign_undo_token(a["record"], K[a["signer"]].seed),
        "sign_undo_receipt": lambda: undo.sign_undo_receipt(a["body"], K[a["signer"]].seed),
        "sign_contract": lambda: contracts.sign_contract(a["contract"], K[a["signer"]].seed),
        "sign_contract_reset": lambda: {"sig": contract_enforcer.sign_contract_reset(K[a["signer"]].seed, a["contract_id"],
                                                                                    a["seq"])},
        "sign_constitution": lambda: prohibitions.sign_constitution(a["constitution"], K[a["signer"]].seed),
        "sign_safety_evidence": lambda: prohibitions.sign_safety_evidence(a["evidence"], K[a["signer"]].seed,
                                                                          K[a["signer"]].public),
        "sign_threshold_share": lambda: S.sign_threshold_share(a["role"], K[a["signer"]], unb64u(a["message"]),
                                                               a["signer_set"], a["t"]),
        "sign_prepared_share": lambda: S.sign_prepared_share(a["role"], K[a["signer"]], unb64u(a["prepared"])),
        "sign_pq_binding": lambda: S.sign_pq_binding(K[a["signer"]], a["pq_pk"], a["epoch"], a["aud"]),
        "sign_caution": lambda: S.sign_caution(a["body"], K[a["signer"]]),
        "sign_heartbeat": lambda: S.sign_heartbeat(a["body"], K[a["signer"]]),
        "prov_recorder": lambda: _prov_recorder(a, K),
        "sign_mesh_action": lambda: {"sig": S.sign_mesh_action(a["chain"], a["action"], K[a["signer"]])},
        "sign_session_root": lambda: S.sign_session_root(a["body"], K[a["signer"]]),
        "mint_session_grant": lambda: S.mint_session_grant(
            K[a["principal"]], K[a["holder"]].public, a["session"], a["seq"], a["root"], a["map_digest"], a["predicates"],
            prev=a.get("prev"), map_form=a.get("map_form"), caveats=a.get("caveats"), salt=a.get("salt")),
        "sign_action_schema": lambda: S.sign_action_schema(a["doc"], a["kid"], K[a["signer"]]),
        "sign_labels": lambda: S.sign_labels(a["body"], K[a["signer"]]),
        "sign_intent_required": lambda: S.sign_intent_required(a["body"], a["kid"], K[a["signer"]]),
        "sign_progress_step": lambda: S.sign_progress_step(a["step"], K[a["signer"]]),
        "sign_fact": lambda: S.sign_fact(a["body"], K[a["signer"]]),
        "sign_offer_set": lambda: S.sign_offer_set(a["body"], K[a["signer"]]),
        "sign_read_receipt": lambda: S.sign_read_receipt(K[a["signer"]], a["grant"], a["verb"], a["resource"], a["purpose"],
                                                         a["fields"], a["labels"], a["issued_at"], a.get("prev")),
        "sign_template": lambda: S.sign_template(a["def"], K[a["signer"]]),
        "sign_tighten": lambda: S.sign_tighten(a["overlay"], K[a["signer"]]),
        "parse_limit": lambda: parse_limit(a["limit"]),
        "compile_policy": lambda: _compile(a),
        "facade_act": lambda: _facade_act(a, K),
        # ---- producer-pq-vectors.json: every suite --------------------------------------------------------------------------
        "pq_keygen": lambda: {"public": PQ.__class__({"k": a})("k").public},
        "suite_sign": lambda: sign_with_suite(a["alg"], K[a["ed"]] if a.get("ed") else None, PQ(a["pq"]),
                                              a["message_utf8"].encode("utf-8")),
        "mint_root_suite": lambda: mint_root(K[a["principal"]], K[a["holder"]].public, a["caveats"],
                                             holder_pq=PQ(a["holder_pq"]).public if a.get("holder_pq") else None,
                                             alg=a["alg"], pq=PQ(a["pq"])),
        "delegate_suite": lambda: delegate(a["parent"], K[a["signer"]], K[a["to_holder"]].public if a.get("to_holder") else None,
                                           a["added_caveats"],
                                           holder_pq=PQ(a["holder_pq"]).public if a.get("holder_pq") else None,
                                           alg=a["alg"], pq=PQ(a["pq"])),
        "sign_pcactn_suite": lambda: {"pcactn": sign_pcactn(a["body"], K[a["signer"]], a["alg"], PQ(a["pq"]))},
        "sign_artifact_suite": lambda: _artifact_suite(a, K, PQ),
    }
    fn = ops.get(op)
    if fn is None:
        raise NotProduced(op)
    return fn()
