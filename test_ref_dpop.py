"""Differential replay of the DPoP / mTLS package (atlas_pca.dpop) against the vectors generated from the TypeScript
reference (@atlasauth/pca-dpop)."""
import importlib.util
import os
import re
import threading

import pytest

from atlas_pca import dpop as D
from base_oracle import HERE, b64d, load_ref, run

COUNT, CASES = load_ref("dpop")
HAVE_CRYPTO = importlib.util.find_spec("cryptography") is not None
T0 = 1_800_000_000


def snake(o):
    return {re.sub(r"([A-Z])", lambda m: "_" + m.group(1).lower(), k): v for k, v in o.items()}


class _Seen:
    """An insertion-ordered jti set (the reference reports the set after the call)."""

    def __init__(self, items):
        self.items = list(items)

    def __contains__(self, k):
        return k in self.items

    def add(self, k):
        if k not in self.items:
            self.items.append(k)


class _Const:
    def __init__(self, result):
        self.result = result

    def add_if_absent(self, key, exp, now):
        if self.result is None:
            raise RuntimeError("boom")
        return self.result


def _store(s):
    if s["kind"] == "memory":
        st = D.create_in_memory_dpop_replay_store(s.get("maxEntries"))
        for k, e, n in s.get("preload", []):
            st.add_if_absent(k, e, n)
        return st
    return _Const({"true": True, "false": False}.get(s["kind"]))


def _adapt(opts):
    o = dict(opts)
    seen = None
    if "seenJti" in o:
        seen = _Seen(o.pop("seenJti"))
    store = o.pop("replayStore", None)
    ni = o.pop("nonceIssuer", None)
    out = snake(o)
    if seen is not None:
        out["seen_jti"] = seen
    if store is not None:
        out["replay_store"] = _store(store)
    if ni is not None:
        out["nonce_issuer"] = D.create_dpop_nonce_issuer(b64d(ni["secret"]), ni.get("ttl"))
    return out, seen


def _with_seen(r, seen):
    out = {"claims": r["claims"], "jwk": r["jwk"], "jkt": r["jkt"]}
    if seen is not None:
        out["seen"] = list(seen.items)
    return out


def _verify(proof, opts):
    o, seen = _adapt(opts)
    return _with_seen(D.verify_dpop_proof(proof, o), seen)


def _assert(p, proof, opts):
    o, seen = _adapt(opts)
    return _with_seen(D.assert_pca_dpop(p, proof, o), seen)


def _create(i):
    return D.create_dpop_proof(i["method"], i["url"], i["privateKey"], i["publicJwk"], i.get("nonce"), i.get("ath"), i.get("iat"), i.get("jti"))


def _create_then_verify(i, vo):
    proof = _create(i)
    base = {"method": i["method"], "url": i["url"], "maxAgeSec": 300, "nowSec": (T0 if i.get("iat") is None else i["iat"]) + 1, "seenJti": []}
    base.update(vo)
    return _verify(proof, base)


def _nonce_script(secret, ttl, ops):
    iss = D.create_dpop_nonce_issuer(b64d(secret) if secret is not None else None, ttl)
    issued, out = [], []
    for op in ops:
        if op["op"] == "issue":
            n = iss.issue(op.get("now"))
            issued.append(n)
            out.append(n)
        else:
            n = op["nonce"]
            if isinstance(n, dict) and "$issued" in n:
                n = issued[n["$issued"]]
            out.append(iss.check(n, op.get("now")))
    return out


def _store_script(max_entries, ops):
    st = D.create_in_memory_dpop_replay_store(max_entries)
    out = []
    for op in ops:
        try:
            out.append(st.add_if_absent(op["key"], op["exp"], op["now"]))
        except Exception:  # noqa: BLE001 - a full store raises; the reference reports "throws"
            out.append("throws")
    return out


class _NoExpiry:
    def __init__(self):
        self.seen, self.lock = set(), threading.Lock()

    def add_if_absent(self, key, exp, now):
        with self.lock:
            if key in self.seen:
                return False
            self.seen.add(key)
            return True


def _conformance(kind):
    make = {"memory": D.create_in_memory_dpop_replay_store, "alwaysTrue": lambda: _Const(True), "alwaysFalse": lambda: _Const(False), "noExpiry": _NoExpiry}[kind]
    return D.run_dpop_replay_store_conformance(make)


def _constants():
    return {"allowedAlgs": list(D.DPOP_ALLOWED_ALGS), "typ": D.DPOP_JWT_TYP, "defaultMaxAgeSec": D.DPOP_DEFAULT_MAX_AGE_SEC,
            "clockSkewSec": D.DPOP_CLOCK_SKEW_SEC, "maxProofBytes": D.DPOP_MAX_PROOF_BYTES, "inMemoryMaxEntries": D.DPOP_INMEMORY_MAX_ENTRIES}


MAP = {
    "constants": _constants,
    "jwkThumbprint": lambda j, d=None: D.jwk_thumbprint(j, d),
    "dpopAlgForJwk": D.dpop_alg_for_jwk,
    "dpopAlgMatchesJwk": D.dpop_alg_matches_jwk,
    "normalizeHtu": D.normalize_htu,
    "athFor": D.ath_for,
    "nonceIssuer": _nonce_script,
    "replayStore": _store_script,
    "replayConformance": _conformance,
    "createDpopProof": _create,
    "createThenVerify": _create_then_verify,
    "verifyDpopProof": _verify,
    "mtlsCnf": D.mtls_cnf,
    "mtlsThumbprint": D.mtls_thumbprint,
    "assertMtlsBound": D.assert_mtls_bound,
    "leafHolderJwk": D.leaf_holder_jwk,
    "bindPcaToDpop": D.bind_pca_to_dpop,
    "assertPcaDpop": _assert,
}

_NEEDS_CRYPTO = re.compile(r"ed448|es256|es384|es512|ps256|rs256|rsa|high-s|ec proof", re.I)


def _skip(c):
    """ES / PS / RS / Ed448 keys and X.509 parsing need the optional `cryptography` package."""
    if HAVE_CRYPTO:
        return None
    if c["fn"] in ("mtlsThumbprint", "assertMtlsBound") or _NEEDS_CRYPTO.search(c["name"]):
        return "needs cryptography"
    return None


def test_every_oracle_function_is_replayed():
    assert set(CASES) == set(MAP)


@pytest.mark.parametrize("fn", sorted(MAP))
def test_matches_the_reference(fn):
    run(CASES[fn], MAP[fn], skip=_skip)


def test_absent_max_age_is_the_default_and_non_finite_bounds_are_refused():
    import base64
    import hashlib
    from atlas_pca import ed25519
    seed = hashlib.sha256(b"dpop-non-finite").digest()
    x = base64.urlsafe_b64encode(ed25519.public_key(seed)).rstrip(b"=").decode()
    url = "https://rs.example/r"
    proof = D.create_dpop_proof("GET", url, seed, {"kty": "OKP", "crv": "Ed25519", "x": x}, iat=1_800_000_000)
    base = {"method": "GET", "url": url, "require_replay_store": False}

    def code(**o):
        try:
            D.verify_dpop_proof(proof, dict(base, **o))
            return "ok"
        except D.DpopVerificationError as e:
            return e.code

    assert code(now_sec=1_800_000_001) == "ok"
    assert code(now_sec=1_800_000_301) == "iat_stale"  # absent max_age_sec = 300 s
    for v in (float("inf"), float("-inf"), float("nan"), "300", True):
        assert code(now_sec=1_800_000_001, max_age_sec=v) == "max_age", v
        assert code(now_sec=v) == "now", v


def test_rsa_corpus():
    """The RSA DPoP cases: ref-dpop-rsa.json.gz, generated by CI (never committed), same case format and function table."""
    path = os.environ.get("PCA_DPOP_RSA_CORPUS") or os.path.join(HERE, "test-data", "ref-dpop-rsa.json.gz")
    if not os.path.exists(path):
        msg = "ref-dpop-rsa.json.gz not found at %s (generate with .github/scripts/dpop-rsa-corpus.sh or set PCA_DPOP_RSA_CORPUS)" % path
        if os.environ.get("CI") in ("true", "1"):
            pytest.fail(msg)
        pytest.skip(msg)
    _, cases = load_ref("dpop-rsa", path)
    assert set(cases) <= set(MAP)
    for fn, cs in cases.items():
        run(cs, MAP[fn], skip=_skip)
