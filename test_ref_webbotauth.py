"""Differential oracle: Web Bot Auth (RFC 9421 message signatures in the web-bot-auth profile, signed key directory, Content-Digest,
PCA proof binding; atlas_pca.webbotauth) against the vectors generated from the TypeScript reference (@atlasauth/pca-webbotauth)."""
import re

import pytest

from atlas_pca import webbotauth as W
from atlas_pca.agent import KeyPair
from base_oracle import b64d, load_ref, run

COUNT, CASES = load_ref("webbotauth")


def _key(k):
    return KeyPair(b64d(k["secretKey"]), True)


def _with_key(x):
    return dict(x, key=_key(x["key"])) if isinstance(x, dict) and isinstance(x.get("key"), dict) else x


def _resolver(spec):
    def resolve(kid):
        v = spec.get(kid)
        if isinstance(v, dict) and v.get("$throw"):
            raise RuntimeError("resolver down")
        return v
    return resolve


class _Fixed:
    def __init__(self, result):
        self._r = result

    def claim(self, key, expires, now):
        if self._r == "throw":
            raise RuntimeError("cache down")
        return self._r


def _cache(spec):
    if spec == "always":
        return _Fixed(True)
    if spec == "never":
        return _Fixed(False)
    if spec == "throw":
        return _Fixed("throw")
    if spec == "memory":
        return W.memory_replay_cache()
    if isinstance(spec, str) and spec.startswith("memory:"):
        return W.memory_replay_cache(int(spec[7:]))
    return spec


def _opts(op):
    o = dict(op)
    if isinstance(o.get("resolveKey"), dict):
        o["resolveKey"] = _resolver(o["resolveKey"])
    if o.get("maxLifetimeSec") == "Infinity":
        o["maxLifetimeSec"] = float("inf")
    if "replayCache" in o:
        o["replayCache"] = _cache(o["replayCache"])
    return o


def _norm(r):
    r = dict(r)
    if isinstance(r.get("reason"), str):
        r["reason"] = re.sub(r"^(invalid PCActn in PCA-Action): .*\Z", r"\1", r["reason"], flags=re.S)
    return r


def _verify(req, op, times=1):
    vo = _opts(op)
    rs = [_norm(W.verify_signed_request(req, vo)) for _ in range(times)]
    return rs[0] if times == 1 else rs


def _verify_proof(req, op):
    return _norm(W.verify_signed_request_with_proof(req, _opts(op)))


def _constants():
    return {"tag": W.WEB_BOT_AUTH_TAG, "alg": W.WEB_BOT_AUTH_ALG, "path": W.WELL_KNOWN_DIRECTORY_PATH, "ct": W.DIRECTORY_CONTENT_TYPE,
            "label": W.DEFAULT_SIGNATURE_LABEL, "exp": W.DEFAULT_EXPIRES_SEC, "agent": W.SIGNATURE_AGENT_HEADER, "pca": W.PCA_HEADER,
            "comp": W.PCA_PROOF_COMPONENT, "cd": W.CONTENT_DIGEST_HEADER, "algs": list(W.CONTENT_DIGEST_ALGS), "dtag": W.DIRECTORY_SIGNATURE_TAG}


def _cache_run(mx, ops):
    c = W.memory_replay_cache(mx)
    out = []
    for k, e, n in ops:
        try:
            out.append(c.claim(k, e, n))
        except Exception:  # noqa: BLE001 - the reference records a throwing claim as "throw"
            out.append("throw")
    return out


def _handler_run(keys, paths):
    h = W.directory_handler(keys)
    return [h(p) for p in paths]


class _Res:
    def __init__(self, r):
        self.status = r["status"]
        self.headers = _Headers(r.get("headers") or {})
        self._body = r["body"]

    def text(self):
        return self._body


class _Headers:
    def __init__(self, h):
        self._h = h

    def get(self, name):
        return self._h.get(name.lower())


def _fetch_run(url, spec):
    called = []
    res = spec["response"]

    def fetch(u, init):
        called.append({"url": u, "headers": init["headers"], "redirect": init["redirect"]})
        if res == "throw":
            raise RuntimeError("network down")
        return _Res(res)

    try:
        d = W.fetch_key_directory(url, dict(spec.get("options") or {}, fetch=fetch))
        return {"directory": d, "called": called[0] if called else None}
    except Exception as e:  # noqa: BLE001 - compared by message class, as the reference does
        msg = str(e)
        if msg.startswith("directory ") or msg.startswith("Invalid URL"):
            msg = re.sub(r"^(directory signature): .*\Z", r"\1", msg, flags=re.S)
        else:
            msg = "other"
        return {"error": True, "message": msg, "called": called[0] if called else None}


def _sd_input(i):
    return dict(i, keys=[_key(k) for k in i["keys"]])


MAP = {
    "constants": _constants,
    "jwkThumbprint": W.jwk_thumbprint,
    "signRequest": lambda i: W.sign_request(_with_key(i)),
    "verifySignedRequest": _verify,
    "buildKeyDirectory": W.build_key_directory,
    "resolveFromDirectory": W.resolve_from_directory,
    "directoryHandler": _handler_run,
    "memoryReplayCache": _cache_run,
    "proofHeaders": W.proof_headers,
    "decodeProofHeader": W.decode_proof_header,
    "signRequestWithProof": lambda i: W.sign_request_with_proof(_with_key(i)),
    "verifySignedRequestWithProof": _verify_proof,
    "contentDigestBytes": W.content_digest_bytes,
    "contentDigestHeader": W.content_digest_header,
    "verifyContentDigest": W.verify_content_digest,
    "parseContentDigest": W.parse_content_digest,
    "parseKeyDirectory": W.parse_key_directory,
    "signDirectoryResponse": lambda i: W.sign_directory_response(_sd_input(i)),
    "verifyDirectoryResponse": W.verify_directory_response,
    "fetchKeyDirectory": _fetch_run,
}


def test_corpus_is_the_full_oracle():
    assert COUNT == sum(len(v) for v in CASES.values()) and set(CASES) == set(MAP)


@pytest.mark.parametrize("fn", sorted(MAP))
def test_matches_the_reference(fn):
    ran, _ = run(CASES[fn], MAP[fn])
    assert ran == len(CASES[fn])


def test_async_verifier_awaits_a_resolver_and_a_cache():
    import asyncio

    seed = bytes([7]) * 32
    key = KeyPair(seed, True)
    req = {"method": "GET", "url": "https://example.com/a", "headers": {}}
    out = W.sign_request({"method": "GET", "url": "https://example.com/a", "key": key, "keyid": "k", "created": 1000})
    req["headers"] = out["headers"]

    async def resolver(kid):
        return bytes.fromhex(W.ed25519.public_key(seed).hex())

    class Cache:
        async def claim(self, k, e, n):
            return True

    opts = {"resolveKey": resolver, "replayCache": Cache(), "now": 1010}
    assert asyncio.run(W.verify_signed_request_async(req, opts))["valid"] is True
    r = W.verify_signed_request(req, opts)
    assert r["valid"] is False and "fail closed" in r["reason"]
