"""Replays the TS-reference oracle of the agent passport (testdata/ref-passport.json.gz, 516 cases): the content fingerprint and issuance, the match against
a grant's agent binding (reasons and their order), the registry, the trust score, the evidence binding, signing (every suite, every refusal), the
verifier (every reason code and detail, the time window, revocation, the post-quantum pins, the hardware evidence rules) and the assurance label. Every fn has a
handler and the totals are asserted; a reference refusal needs a native exception. The verdict of a case that the reference accepts ONLY through the
legacy ``allowUnboundPq`` option is asserted REFUSED (``bad_signature``): that option is not offered (count asserted)."""
import math
import os

import pytest

from atlas_pca import agent as A
from atlas_pca import passport as P
from atlas_pca.agent import KeyPair, generate_pq_keypair
from atlas_pca.authorize import set_assurance_label
from base_oracle import HERE, canon, dec, load, run

COUNT, CASES = load("passport", os.path.join(HERE, "testdata", "ref-passport.json.gz"))
NUM = {"NaN": math.nan, "Infinity": math.inf, "-Infinity": -math.inf}


def _num(v):
    if isinstance(v, dict):
        if set(v) == {"$num"}:
            return NUM[v["$num"]]
        return {k: _num(x) for k, x in v.items()}
    return [_num(x) for x in v] if isinstance(v, list) else v


def _registry(passports, ops):
    r = P.build_registry(passports)
    out = []
    for op in ops:
        out.append(r.get(op[1]) if op[0] == "get" else r.has(op[1]) if op[0] == "has" else r.all())
    return out


def _sign(passport, o):
    o = _num(o)
    suite = o.get("suite")
    alg = suite["alg"] if suite else None
    pq = generate_pq_keypair("ML-DSA-65", suite["pqSeed"]) if suite and suite.get("pqSeed") is not None else None
    return A.sign_passport(passport, KeyPair(o["issuerSecret"], allow_insecure_signer=True), o.get("subject"), o.get("exp"), o.get("iat"), o.get("nbf"),
                           o.get("evidence"), alg, pq)


def _verifier(spec):
    def verify(document, expected, now_ms=None):
        if "throws" in spec:
            raise RuntimeError(spec["throws"])
        return spec["result"]
    return verify


def _revocation(spec):
    if spec in (None, "none"):
        return None
    if spec == "throws":
        def boom(_p):
            raise RuntimeError("rev")
        return boom
    if "revokedIds" in spec:
        return lambda p: p["id"] in spec["revokedIds"]
    return lambda _p: spec["revoked"]


def _verify(sp, o):
    o = _num(o)
    opts = {k: v for k, v in o.items() if k not in ("revocation", "hardware", "allowUnboundPq")}
    opts["revocation"] = _revocation(o.get("revocation"))
    if o.get("hardware"):
        opts["attestationVerifier"] = _verifier(o["hardware"])
    return P.verify_passport_verdict(_num(sp), opts)


class _Verifier:
    pass


def _assurance(verdict, label):
    if label == "no-verifier":
        return P.passport_assurance(verdict)
    v = _Verifier()
    if label is not None:
        set_assurance_label(v, label["level"], vendor=label.get("vendor"))
    return P.passport_assurance(verdict, v)


HANDLERS = {
    "passportFingerprint": A.passport_fingerprint,
    "issuePassport": A.issue_passport,
    "matchesBinding": P.matches_binding,
    "registry": _registry,
    "trustScore": lambda p, opts: P.trust_score(p, (opts or {}).get("knownOperators")),
    "passportEvidenceBinding": P.passport_evidence_binding,
    "signPassport": _sign,
    "verifyPassport": _verify,
    "passportAssurance": _assurance,
    "constants": lambda: {"PASSPORT_SIG_DOMAIN": A.PASSPORT_SIG_DOMAIN, "PASSPORT_VERSION": P.PASSPORT_VERSION,
                          "DEFAULT_PASSPORT_EVIDENCE_AGE_MS": P.DEFAULT_PASSPORT_EVIDENCE_AGE_MS},
}
TOTALS = {"passportFingerprint": 13, "issuePassport": 12, "matchesBinding": 267, "registry": 4, "trustScore": 67, "passportEvidenceBinding": 5,
          "signPassport": 30, "verifyPassport": 109, "passportAssurance": 8, "constants": 1}


def _unbound(c):
    return c["fn"] == "verifyPassport" and bool(c["args"][1].get("allowUnboundPq"))


def test_every_corpus_fn_has_a_handler_and_the_total_is_pinned():
    assert COUNT == 516 and set(CASES) == set(HANDLERS)
    assert {fn: len(cs) for fn, cs in CASES.items()} == TOTALS


def test_the_legacy_unbound_pq_acceptance_is_refused():
    """The reference accepts a post-quantum passport without an issuer pin only through ``allowUnboundPq``; this verifier never does."""
    cases = [c for c in CASES["verifyPassport"] if _unbound(c)]
    assert len(cases) == 1
    for c in cases:
        assert c["out"]["ok"] is True
        got = HANDLERS["verifyPassport"](*dec(c["args"]))
        assert got == {"ok": False, "reason": "bad_signature"}


@pytest.mark.parametrize("fn", sorted(HANDLERS))
def test_passport_replay(fn):
    ran, skipped = run(CASES[fn], HANDLERS[fn], skip=lambda c: "unbound-pq" if _unbound(c) else None)
    assert (ran, skipped) == (TOTALS[fn] - (1 if fn == "verifyPassport" else 0), 1 if fn == "verifyPassport" else 0)
