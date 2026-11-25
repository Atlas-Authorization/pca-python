"""Differential replay of the Transaction Token profile (atlas_pca.txn_tokens) against the vectors generated from the
TypeScript reference (@atlasauth/pca-txn-tokens). Issued tokens are random (iat, jti, txn): the replay compares the header and
the claims with iat / exp turned into the lifetime and the generated ids into `true`, as the generator does."""
import json
import re

import pytest

from atlas_pca import txn_tokens as T
from base_oracle import b64d, load_ref, run

COUNT, CASES = load_ref("txn-tokens")


def snake(o):
    return {re.sub(r"([A-Z])", lambda m: "_" + m.group(1).lower(), k): v for k, v in o.items()}


def _issue(a):
    a = dict(a)
    seed = b64d(a.pop("seed"))
    args = snake(a)
    args["issuer_key"] = seed
    tok = T.to_transaction_token(args)
    header, p = [json.loads(b64d(s)) for s in tok.split(".")[:2]]
    claims = {k: v for k, v in p.items() if k not in ("iat", "exp", "jti", "txn")}
    claims["ttl"] = p["exp"] - p["iat"]
    if "jti" in p:
        claims["jti"] = True
    if "txn" in p:
        claims["txn"] = p["txn"] if "txn" in a else True
    return {"header": header, "claims": claims}


def _verify(jwt, pk, w):
    o = {}
    for k in ("profile", "audience"):
        if k in w:
            o[k] = w[k]
    if "clockToleranceSec" in w:
        o["clock_tolerance_sec"] = w["clockToleranceSec"]
    if w.get("nowMs") is not None:
        o["now"] = w["nowMs"] / 1000
    if w.get("seen") is not None:
        seen = set(w["seen"])
        o["seen_txn"] = lambda ident, exp: ident in seen
    if w.get("unchecked"):
        o["replay_check"] = "unchecked"
    r = T.from_transaction_token(jwt, b64d(pk), o)
    return {k: v for k, v in r.items() if not (k == "action" and v is None)}  # JSON drops the reference's undefined action


MAP = {
    "subActChain": T.sub_act_chain,
    "actDepth": T.act_depth,
    "toRfc8693Act": T.to_rfc8693_act,
    "toTransactionToken": _issue,
    "fromTransactionToken": _verify,
}


def test_every_oracle_function_is_replayed():
    assert set(CASES) == set(MAP)


@pytest.mark.parametrize("fn", sorted(MAP))
def test_matches_the_reference(fn):
    run(CASES[fn], MAP[fn])
