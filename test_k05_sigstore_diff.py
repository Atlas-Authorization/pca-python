"""k05 differential oracle: offline Sigstore bundle verification (atlas_pca.sigstore_bundle) against the shared TS-generated
testdata/k05-sigstore.json.gz: a deterministic synthetic PKI, the published conformance bundles and their structural / DER
mutations. Roots are the parseTrustedRoot/<id> cases; other cases name one as {"$root": id}. Bytes travel as standard
base64. A "fail closed: <exception>" detail is language-specific: only that prefix is compared. Needs `cryptography`."""
import base64

import pytest

from k05_oracle import canon, load, run

pytest.importorskip("cryptography")  # optional `sigstore` extra (the dependency-free CI job skips this file)
from atlas_pca import sigstore_bundle as S  # noqa: E402

COUNT, CASES = load("sigstore")
FAIL_CLOSED = "fail closed: "


def _parse(doc):
    try:
        return S.parse_trusted_root(doc)
    except ValueError as e:
        return e


ROOTS = {c["name"].split("/", 1)[1]: _parse(c["args"][0]) for c in CASES["parseTrustedRoot"]}


def _roots(ref):
    r = ROOTS.get(ref["$root"]) if isinstance(ref, dict) else None
    if r is None or isinstance(r, Exception):
        raise ValueError("bad root ref")
    return r


def _ms(v):
    return None if v == float("inf") else v


def _summary(r):
    lg = lambda l: {"keyId": base64.b64encode(l.key_id).decode(), "start": l.valid.start, "end": _ms(l.valid.end), "v2": l.v2_name}  # noqa: E731
    ca = lambda c: {"chain": len(c.chain), "start": c.valid.start, "end": _ms(c.valid.end)}  # noqa: E731
    return {"tlogs": [lg(x) for x in r.tlogs], "ctlogs": [lg(x) for x in r.ctlogs], "cas": [ca(x) for x in r.cas], "tsas": [ca(x) for x in r.tsas]}


def _core(b, ref):
    r = S.verify_sigstore_bundle_core(b, _roots(ref))
    return {"ok": True, "core": r["core"]} if r["ok"] else {"ok": False, "code": r["code"], "detail": r["detail"]}


def _verdict_eq(got, out, _c):
    """Exact, except a caught-exception detail compares up to its "fail closed: " prefix."""
    if not out.get("ok") and isinstance(out.get("detail"), str) and out["detail"].startswith(FAIL_CLOSED):
        return got.get("ok") is False and got.get("code") == out["code"] and str(got.get("detail", "")).startswith(FAIL_CLOSED)
    return canon(got) == canon(out)


def _parse_summary(doc):
    r = S.parse_trusted_root(doc)
    return _summary(r)


MAP = {
    "parseTrustedRoot": (_parse_summary, {}),
    "verifySigstoreBundleCore": (_core, {"compare": _verdict_eq}),
    "verifySigstoreBundle": (lambda b, ref: S.verify_sigstore_bundle(b, _roots(ref)), {"compare": _verdict_eq}),
    "verifyRfc3161": (lambda t, d, ref: S.verify_rfc3161(base64.b64decode(t), base64.b64decode(d), _roots(ref).tsas), {}),
    "dssePae": (lambda t, p: S.dsse_pae(t, base64.b64decode(p)), {}),
}


def test_corpus_is_the_full_oracle():
    assert COUNT == 7005 and set(CASES) == set(MAP)


@pytest.mark.parametrize("fn", sorted(MAP))
def test_matches_the_reference(fn):
    call, kw = MAP[fn]
    run(CASES[fn], call, **kw)
