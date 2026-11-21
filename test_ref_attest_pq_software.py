"""Replays the TS-reference oracle of the post-quantum software attestation root (testdata/ref-attest-pq-software.json.gz, 137 cases): statement minting
under PQ and hybrid suites (byte-exact), attestor construction and the verifier's scenarios and construction refusals. Keys are label seeds (an
Ed25519 secret and the ML-DSA keygen seed); SLH-DSA statements are verify-only inputs. Every fn has a handler and the totals are asserted; a reference
refusal needs a native exception. The case "wrong-key-family" gives ML-DSA-65 key material
to an ML-DSA-87 attestor (the corpus carries only the seed): the harness derives each key from the family of the label its seed came from."""
import base64
import hashlib
import os

import pytest

from atlas_pca import attest_pq_software as Q
from atlas_pca import pq_backends
from atlas_pca.agent import generate_pq_keypair
from atlas_pca.pca import _SIG_SUITES
from base_oracle import HERE, canon, load, run

COUNT, CASES = load("attest-pq-software", os.path.join(HERE, "testdata", "ref-attest-pq-software.json.gz"))
FAMILY = {"ML-DSA-65": ("mlDsa", "ML-DSA-65"), "ML-DSA-87": ("mlDsa87", "ML-DSA-87")}


def _seed(label_alg):  # the generator derives each key's seed from its label alg
    d = hashlib.sha256(("atlas-pca-conformance/pq-software/%s/pq" % label_alg).encode()).digest()
    return base64.urlsafe_b64encode(d).rstrip(b"=").decode()


# the key family follows the label the seed came from, as in the generator (the spec's own alg may name another family)
SEED_FAMILY = {_seed(a): FAMILY[_SIG_SUITES[a][3]] for a in _SIG_SUITES if _SIG_SUITES[a][3] in FAMILY}


def _b64d(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _keys(spec):
    k = {"alg": spec.get("alg")}
    if "edSecret" in spec:
        k["edSecret"] = _b64d(spec["edSecret"])
    suite = _SIG_SUITES.get(spec.get("alg", "ed25519"))
    if "seed" in spec and suite is not None and suite[3] in FAMILY:
        member, family = SEED_FAMILY.get(spec["seed"], FAMILY[suite[3]])
        k[member] = generate_pq_keypair(family, _b64d(spec["seed"]))
    return k


def _attestor_out(t, **extra):
    out = {"pqPublicKey": t.pq_public_key}
    if t.ed25519_public_key:
        out["ed25519PublicKey"] = t.ed25519_public_key
    out.update(extra)
    return out


def _attest(spec, claims):
    t = Q.create_pq_software_attestor(_keys(spec))
    return _attestor_out(t, statement=t.attest(claims))


def _build_attestor(spec):
    return _attestor_out(Q.create_pq_software_attestor(_keys(spec)))


def _config(c, evidence):
    cfg = {k: v for k, v in c.items() if k not in ("noEvidenceSeam",)}
    if not c.get("noEvidenceSeam"):
        cfg["resolveEvidence"] = lambda doc, ctx: evidence
    return cfg


def _verify(sc):
    inp = {"document": {}, "ctx": {}, "nowMs": sc["input"]["nowMs"]}
    if sc["input"].get("expected") is not None:
        inp["expected"] = sc["input"]["expected"]
    return Q.create_pq_software_verifier(_config(sc["config"], sc["evidence"])).verify(inp)


def _build_verifier(c):
    Q.create_pq_software_verifier(_config(c, None))
    return {"built": True}


HANDLERS = {"constants": lambda: {"PQ_ATTEST_DOMAIN": Q.PQ_ATTEST_DOMAIN}, "attest": _attest, "buildAttestor": _build_attestor,
            "verifyPq": _verify, "buildVerifier": _build_verifier}
TOTALS = {"constants": 1, "attest": 29, "buildAttestor": 9, "verifyPq": 90, "buildVerifier": 8}


def test_every_corpus_fn_has_a_handler_and_the_total_is_pinned():
    assert COUNT == 137 and set(CASES) == set(HANDLERS)
    assert {fn: len(cs) for fn, cs in CASES.items()} == TOTALS
    assert sum(1 for cs in CASES.values() for c in cs if isinstance(c["out"], dict) and "$throws" in c["out"]) == 19


@pytest.mark.parametrize("fn", sorted(HANDLERS))
def test_pq_software_replay(fn):
    # SLH-DSA statements verify only through OpenSSL >= 3.5 (no audited pure-Python SLH-DSA): where it is absent their positive cases are
    # not runnable, never reported as passed
    no_slh = not pq_backends.openssl_available("SLH-DSA-SHA2-128f")
    skip = (lambda c: "needs OpenSSL >= 3.5 for SLH-DSA" if "slh-dsa" in c["name"] and "/ok-" in c["name"] else None) if no_slh else None
    nskip = sum(1 for c in CASES[fn] if skip and skip(c))
    assert run(CASES[fn], HANDLERS[fn], skip=skip) == (TOTALS[fn] - nskip, nskip)
