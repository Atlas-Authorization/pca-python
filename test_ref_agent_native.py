"""Replays the TS-reference oracle of the agent-native surface (testdata/ref-agent-native.json.gz, 1632 cases): caution
attestation, rationale binding, the tool-schema firewall, envelope introspection and the authority lease. Every fn of the corpus
must have a handler (an unhandled fn fails the test). Encodings: {"$num": "NaN" | "Infinity" | "-Infinity"}; {"$bytes": {"$seed":
label}} is the 32-byte Ed25519 secret sha256("atlas-pca-conformance/" + label); an out of {"$throws": ...} must be a native raise
(the message is not compared); every other reason string is compared exactly."""
import gzip
import hashlib
import json
import math
import os

import pytest

from atlas_pca import agent_native as an
from atlas_pca.agent import keypair_from_seed

HERE = os.path.dirname(os.path.abspath(__file__))
CORPUS = os.path.join(HERE, "testdata", "ref-agent-native.json.gz")


def _parse_int(t):
    # a JSON number is an IEEE double: -0 keeps its sign and an integer beyond 2^53 is the double it rounds to
    if t == "-0":
        return -0.0
    n = int(t)
    return float(n) if abs(n) > 2 ** 53 else n


def _dec(v):
    if isinstance(v, dict):
        if set(v) == {"$num"}:
            return {"NaN": math.nan, "Infinity": math.inf, "-Infinity": -math.inf}[v["$num"]]
        if set(v) == {"$bytes"} and isinstance(v["$bytes"], dict) and set(v["$bytes"]) == {"$seed"}:
            return keypair_from_seed(hashlib.sha256(("atlas-pca-conformance/" + v["$bytes"]["$seed"]).encode("utf-8")).digest(),
                                     allow_insecure_signer=True)
        return {k: _dec(x) for k, x in v.items()}
    if isinstance(v, list):
        return [_dec(x) for x in v]
    return v


def _same(a, b):
    if isinstance(a, bool) or isinstance(b, bool):
        return isinstance(a, bool) and isinstance(b, bool) and a == b
    if isinstance(a, (int, float)) and isinstance(b, (int, float)):
        return (math.isnan(a) and math.isnan(b)) or float(a) == float(b)
    if isinstance(a, dict) and isinstance(b, dict):
        return set(a) == set(b) and all(_same(a[k], b[k]) for k in a)
    if isinstance(a, (list, tuple)) and isinstance(b, (list, tuple)):
        return len(a) == len(b) and all(_same(x, y) for x, y in zip(a, b))
    return type(a) is type(b) and a == b


def _pad(args, n):
    return list(args) + [None] * (n - len(args))


def _judge(spec):
    def throw(_r, _a):
        raise RuntimeError("judge")

    def verb(want):
        def j(_r, a):
            if a is None:
                raise TypeError("action is null")
            return isinstance(a, dict) and a.get("verb") == want
        return j

    if spec == "true":
        return lambda r, a: True
    if spec == "false":
        return lambda r, a: False
    if spec == "throw":
        return throw
    if spec == "truthy":
        return lambda r, a: "yes"
    if spec.startswith("contains:"):
        return lambda r, a: spec[len("contains:"):] in r
    if spec.startswith("action-verb:"):
        return verb(spec[len("action-verb:"):])
    raise AssertionError("unknown judge spec " + spec)


def _verify_rationale(*a):
    return an.verify_rationale(*a)  # 2 args = no action; a given null is hashed as null


def _constants():
    names = ("CAVEAT_ENVELOPE CAVEAT_EXPIRES CAVEAT_NOT_BEFORE CAVEAT_RATE CAVEAT_MAX_BLAST_RADIUS CAVEAT_REVERSIBILITY_MAX "
             "CAVEAT_DELEGATION_DEPTH CAVEAT_PREDICATES CAVEAT_TOOL_SCHEMA CAVEAT_MAX_SPEND MAX_CAUTION_REASON_LEN MIN_SALT_BYTES "
             "MIN_SALT_DISTINCT_BYTES MAX_RATIONALE_LEN MAX_SCHEMA_DEPTH MAX_SCHEMA_NODES MAX_OBJECT_PROPS MAX_ENUM_VALUES "
             "DEFAULT_MAX_ARRAY_ITEMS ABSOLUTE_MAX_ARRAY_ITEMS DEFAULT_MAX_STRING_LEN ABSOLUTE_MAX_STRING_LEN MAX_VALUE_NODES "
             "HEARTBEAT_SKEW_MS MAX_LEASE_TTL_MS").split()
    return {n: getattr(an, n) for n in names}


HANDLERS = {
    "signCaution": lambda body, key: an.sign_caution(body, key),
    "verifyCaution": lambda *a: an.verify_caution(*_pad(a, 3)),
    "combineCaution": lambda *a: an.combine_caution(*a),
    "combineSignedCaution": lambda *a: an.combine_signed_caution(*_pad(a, 4)),
    "checkCautionMonotone": lambda grid: an.check_caution_monotone(grid),
    "isStrongSalt": lambda s: an.is_strong_salt(s),
    "bindRationale": lambda *a: an.bind_rationale(*a),
    "verifyRationale": _verify_rationale,
    "auditRationale": lambda c, a, r, j: an.audit_rationale(c, a, r, _judge(j)),
    "validateArgSchema": lambda s: an.validate_arg_schema(s),
    "toolSchemaCaveat": lambda sig, schema: an.tool_schema_caveat(sig, schema),
    "evaluateToolSchema": lambda c, call: an.evaluate_tool_schema(c, call),
    "toolSchemaEvaluator": lambda c, ctx: an.tool_schema_evaluator(c, ctx),
    "predicatesCaveat": lambda allow: an.predicates_caveat(allow),
    "actionSpendUsd": lambda a: an.action_spend_usd(a),
    "agentNativeCaveatEvaluator": lambda c, ctx: an.agent_native_caveat_evaluator(c, ctx),
    "describeEnvelope": lambda *a: an.describe_envelope(*_pad(a, 4)),
    "envelopePermits": lambda *a: an.envelope_permits(*_pad(a, 5)),
    "envelopePermitsToolCall": lambda env, call: an.envelope_permits_tool_call(env, call),
    "grantLease": lambda args: an.grant_lease(args),
    "leaseState": lambda lease, now: an.lease_state(lease, now),
    "signHeartbeat": lambda body, key: an.sign_heartbeat(body, key),
    "renewLease": lambda lease, hb, now: an.renew_capability_lease(lease, hb, now),
    "constants": lambda: _constants(),
}


def _cases():
    with gzip.open(CORPUS, "rt", encoding="utf-8") as fh:
        d = json.load(fh, parse_int=_parse_int)
    assert len(d["cases"]) == d["count"] == 1632
    return d["cases"]


CASES = _cases()


def test_every_fn_of_the_corpus_has_a_handler():
    assert {c["fn"] for c in CASES} <= set(HANDLERS)
    assert {c["fn"] for c in CASES} == set(HANDLERS)  # and every handler is exercised


@pytest.mark.parametrize("fn", sorted(HANDLERS))
def test_replay(fn):
    bad = []
    mine = [c for c in CASES if c["fn"] == fn]
    assert mine
    for c in mine:
        out, args = _dec(c["out"]), _dec(c["args"])
        try:
            got = HANDLERS[c["fn"]](*args)
        except Exception as e:  # noqa: BLE001 - a native refusal is compared with the reference's throw
            if not (isinstance(out, dict) and "$throws" in out):
                bad.append((c["name"], "raised %s: %s" % (type(e).__name__, e)))
            continue
        if isinstance(out, dict) and "$throws" in out:
            bad.append((c["name"], "returned %r, the reference throws" % (got,)))
        elif not _same(got, out):
            bad.append((c["name"], "got %s, reference %s" % (json.dumps(got, default=str)[:300], json.dumps(out, default=str)[:300])))
    assert not bad, "%d of %d differ from the reference:\n%s" % (len(bad), len(mine), "\n".join("  %s: %s" % b for b in bad[:25]))
