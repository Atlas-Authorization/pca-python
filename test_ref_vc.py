"""Differential replay of the agent-passport credentials, did:key and RFC 9421 signatures against the TypeScript reference
(@atlasauth/pca-vc)."""
import json

import pytest

from atlas_pca import ed25519, vc as V
from atlas_pca.sdjwt_jws import node_b64url_decode, sha256_ascii_b64u
from base_oracle import load_ref, run

COUNT, CASES = load_ref("vc")
NOW = 1_700_000_100_000  # the clock the vectors were produced under
P1 = ed25519.public_key(bytes([1]) * 32)


def _norm_vc(sd):
    parts = sd.split("~")
    ds = parts[1:-1]
    h, p = [json.loads(node_b64url_decode(x).decode("utf-8")) for x in parts[0].split(".")[:2]]
    cs = (p.get("vc") or {}).get("credentialSubject") if isinstance(p.get("vc"), dict) else None
    sdl = sorted(cs.get("_sd") or []) if isinstance(cs, dict) else []
    if isinstance(cs, dict):
        cs.pop("_sd", None)
    try:
        V.verify_passport_vc(sd, P1, {"now": NOW})
        verified = True
    except Exception:  # noqa: BLE001 - a refusal of any kind
        verified = False
    disc = [json.loads(node_b64url_decode(d).decode("utf-8")) for d in ds]
    return {"end": parts[-1], "header": h, "payload": p, "n": len(ds), "digestsOk": sorted(sha256_ascii_b64u(d) for d in ds) == sdl,
            "disclosures": sorted(([d[1], d[2]] for d in disc), key=lambda x: x[0]), "verified": verified}


def _passport_to_vc(passport, a):
    m = {"issuer_key": a["issuer_seed"], "now": NOW}
    for k in ("issuer_did", "subject_did", "ttl_sec"):
        if k in a:
            m[k] = a[k]
    return _norm_vc(V.passport_to_vc(passport, m))


def _verify_passport(vc, key, opts=None):
    o = {"now": NOW}
    if opts is not None and "expectedIssuerDid" in opts:
        o["expected_issuer_did"] = opts["expectedIssuerDid"]
    return V.verify_passport_vc(vc, key, o)


MAP = {
    "base58btcEncode": V.base58btc_encode,
    "base58btcDecode": V.base58btc_decode,
    "didKeyFromEd25519": V.did_key_from_ed25519,
    "ed25519FromDidKey": V.ed25519_from_did_key,
    "constants": lambda: {"VC_CONTEXT": V.VC_CONTEXT, "AGENT_PASSPORT_CONTEXT": V.AGENT_PASSPORT_CONTEXT,
                          "AGENT_PASSPORT_VC_TYPE": V.AGENT_PASSPORT_VC_TYPE, "AGENT_PASSPORT_CONTEXT_DIGEST": V.AGENT_PASSPORT_CONTEXT_DIGEST,
                          "AGENT_PASSPORT_CONTEXT_DOC": V.AGENT_PASSPORT_CONTEXT_DOC},
    "resolveAgentPassportContext": V.resolve_agent_passport_context,
    "passportToVC": _passport_to_vc,
    "verifyPassportVC": _verify_passport,
    "signRequestMessage": lambda a: V.sign_request_message(dict(a, now=NOW)),
    "verifyRequestSignature": V.verify_request_signature,
}


def test_corpus_is_the_full_oracle():
    assert COUNT == sum(len(v) for v in CASES.values()) and set(CASES) == set(MAP)


@pytest.mark.parametrize("fn", sorted(MAP))
def test_matches_the_reference(fn):
    run(CASES[fn], MAP[fn])
