"""Differential replay of the SD-JWT serialization against the TypeScript reference (@atlasauth/pca-sdjwt)."""
import json

import pytest

from atlas_pca import ed25519, sdjwt as S
from atlas_pca.sdjwt_jws import b64u, node_b64url_decode, sha256_ascii_b64u
from base_oracle import canon, load_ref, run

COUNT, CASES = load_ref("sdjwt")

# A reason that is this package's own (or the canonical gate's) must match exactly; a reason that is the JOSE library's
# own wording only has to be a refusal.
_OWN_PREFIXES = ("pca-sdjwt:", "non-canonical compact JWS", "required disclosure", "KB-JWT ", "cnf key does not", "key binding required",
                 "duplicate disclosure", "unsupported _sd_alg", "a presented disclosure", "a digest appears", "an array", "an object-property",
                 "disclosure claim", "_sd must be", "'")


def _clip_bad_json(reason):
    return reason.split(" (")[0] if reason.startswith("non-canonical compact JWS: bad-json") else reason


def _cmp_verify(got, out, _c):
    if out.get("ok") is False:
        if got.get("ok") is not False:
            return False
        r = out["reason"]
        if r.startswith("KB-JWT signature/claims invalid"):
            return got["reason"].startswith("KB-JWT signature/claims invalid")
        if r.startswith(_OWN_PREFIXES):
            return _clip_bad_json(got["reason"]) == _clip_bad_json(r)
        return True
    return canon(got) == canon(out)


def _cmp_recovered(got, out, _c):
    if got.get("allow") != out.get("allow"):
        return False
    r = out.get("reason")
    return not (isinstance(r, str) and r.startswith("pca-sdjwt:")) or got.get("reason") == r


def _jwk_public(k):
    """The reference imports a JWK into a key object first (private members and alg hints play no part)."""
    return {m: v for m, v in k.items() if m in ("kty", "crv", "x", "y", "n", "e")} if isinstance(k, dict) else k


def _needs_cryptography(c):
    try:
        import cryptography  # noqa: F401
        return None
    except ImportError:
        return "needs the optional 'cryptography' package" if "es256" in c["name"] else None


def _issue(pc, o):
    m = {"issuer_key": S.import_ed25519_private_key(o["issuer_seed"])}
    for k in ("disclosable", "iss", "sub", "typ", "signing_alg", "key_binding"):
        if k in o:
            m[k] = o[k]
    sd = S.issue_pca_sd_jwt(pc, m)
    parts = sd.split("~")
    ds = parts[1:-1]
    h, p = [json.loads(node_b64url_decode(x).decode("utf-8")) for x in parts[0].split(".")[:2]]
    disc = [json.loads(node_b64url_decode(d).decode("utf-8")) for d in ds]
    sdl = sorted(p.get("_sd") or [])
    rest = {k: v for k, v in p.items() if k != "_sd"}
    ver = S.verify_pca_sd_jwt(sd, {"issuer_key": ed25519.public_key(o["issuer_seed"]), "now": p["iat"] * 1000})
    return {"end": parts[-1], "header": h, "payload": rest, "n": len(ds), "digestsOk": sorted(sha256_ascii_b64u(d) for d in ds) == sdl,
            "disclosures": sorted(([d[1], d[2]] for d in disc), key=lambda x: x[0]), "verified": ver["ok"]}


def _verify(sd, o):
    ik = o["issuer_key"]
    m = {"issuer_key": S.import_ed25519_public_key(ik) if isinstance(ik, (bytes, bytearray)) else _jwk_public(ik)}
    for k, v in o.items():
        if k not in ("issuer_key", "issuer_jwk_alg"):
            m[k] = v
    return S.verify_pca_sd_jwt(sd, m)


def _present(sd, sel, o=None):
    m = {}
    if o is not None and "key_binding" in o:
        kb = dict(o["key_binding"])
        kb["holder_key"] = S.import_ed25519_private_key(kb.pop("holder_seed"))
        m["key_binding"] = kb
    return S.present(sd, sel, m)


def _recovered(res, o):
    core = {"grant": o["grant"]}
    if "audience" in o:
        core["audience"] = o["audience"]
    if "now" in o:
        core["now"] = o["now"]
    if "insecure_skip_plan_root_check" in o:
        core["insecure_skip_plan_root_check"] = o["insecure_skip_plan_root_check"]
    v = S.verify_recovered(res, core)
    return {"allow": v.allow, "reason": v.reason}


def _ok(f):
    return lambda raw: (f(raw), "ok")[1]


MAP = {
    "constants": (lambda: {"SD_ALG": S.SD_ALG, "PCA_SD_JWT_TYP": S.PCA_SD_JWT_TYP, "KB_JWT_TYP": S.KB_JWT_TYP,
                           "DEFAULT_SIGNING_ALG": S.DEFAULT_SIGNING_ALG, "PCA_CAPABILITY_CLAIMS": list(S.PCA_CAPABILITY_CLAIMS)}, {}),
    "ed25519PublicJwk": (S.ed25519_public_jwk, {}),
    "importEd25519PrivateKey": (_ok(S.import_ed25519_private_key), {}),
    "importEd25519PublicKey": (_ok(S.import_ed25519_public_key), {}),
    "issuePcaSdJwt": (_issue, {}),
    "verifyPcaSdJwt": (_verify, {"compare": _cmp_verify, "skip": _needs_cryptography}),
    "present": (_present, {}),
    "verifyRecovered": (_recovered, {"compare": _cmp_recovered,
                                      "skip": lambda c: "the Python core has no audience opt-out (audience=None denies)" if c["name"].endswith("audience null") else None}),
}


def test_corpus_is_the_full_oracle():
    assert COUNT == sum(len(v) for v in CASES.values()) and set(CASES) == set(MAP)


@pytest.mark.parametrize("fn", sorted(MAP))
def test_matches_the_reference(fn):
    call, kw = MAP[fn]
    run(CASES[fn], call, **kw)


def test_b64u_helper_is_the_urlsafe_alphabet():
    assert b64u(b"\xfb\xff") == "-_8"
