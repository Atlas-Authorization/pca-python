"""Differential replay of the SPIFFE / SPIRE bridge (atlas_pca.spiffe) against the TypeScript reference (@atlasauth/pca-spiffe).

Two corpora: the first (SPIFFE IDs, X.509 / JWT-SVID verification, holder binding, scripted caches) and the shared one
(parsing, DER facts, verification, scripted sessions). A reference refusal that is not a SPIFFE error (a JOSE error, a type error)
is code "jose" in the second corpus, which is how the wrappers below name every non-SPIFFE refusal there."""
import base64
import pytest

pytest.importorskip("cryptography")

from types import SimpleNamespace

from atlas_pca import spiffe as S
from base_oracle import b64d, load_ref, run

ID = "spiffe://example.org/workload/db"
HOLDER = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE"
COUNT_A, A = load_ref("spiffe-svid")
COUNT_B, B = load_ref("spiffe")


class _Coded(Exception):
    def __init__(self, code, msg):
        super().__init__(msg)
        self.code = code


def _jose(fn):
    """Every non-SPIFFE refusal becomes code "jose" (the second corpus' name for them)."""
    def w(*a):
        try:
            return fn(*a)
        except S.SpiffeError:
            raise
        except Exception as e:  # noqa: BLE001
            raise _Coded("jose", str(e))
    return w


def _id(i):
    return {"id": i.id, "trustDomain": i.trust_domain, "path": i.path}


def _holder(h):
    return {"holder": h.holder, "spiffeId": h.spiffe_id, "trustDomain": h.trust_domain, "path": h.path}


def _cam_x(s):
    return {"spiffeId": s["spiffe_id"], "serialNumber": s["serial_number"], "fingerprint256": s["fingerprint256"], "position": s["position"], "isLeaf": s["is_leaf"]}


def _cam_j(s):
    d = {"spiffeId": s["spiffe_id"]}
    if "jti" in s:
        d["jti"] = s["jti"]
    d["expiresAt"] = s["expires_at"]
    d["tokenHash"] = s["token_hash"]
    return d


def _mk_rev(mode, calls, cam):
    """A revocation check named by its mode; None / "notfn" is present but not callable."""
    if mode is None or mode == "notfn":
        return "notfn"
    at = int(mode.split("@")[1]) if "@" in mode else int(mode[3:]) if mode.startswith("at:") else -1

    def f(s):
        calls.append(cam(s))
        if mode == "throw":
            raise RuntimeError("backend down")
        if mode == "nonbool":
            return "no"
        if mode == "one":
            return 1
        if mode == "undef":
            return None
        if mode == "promise":
            return object()  # a pending result is not the boolean the check requires
        if mode == "true":
            return True
        if at >= 0:
            return s["position"] == at
        return False
    return f


def _bundle_in(b):
    if isinstance(b, dict):
        return {("x509_authorities" if k == "x509Authorities" else k): v for k, v in b.items()}
    return b


def _bind(b):
    if b is None:
        return {}
    return {("accept_unbound_jwt_holder" if k == "acceptUnboundJwtHolder" else k): v for k, v in b.items()}


def _x509_opts(vo, calls):
    o = {"trust_domain": vo.get("trustDomain"), "roots": list(vo.get("roots") or [])}
    if "nowMs" in vo:
        o["now"] = vo["nowMs"] / 1000
    if "maxChainLength" in vo:
        o["max_chain_length"] = vo["maxChainLength"]
    if "revocation" in vo:
        o["revocation"] = _mk_rev(vo["revocation"], calls, _cam_x)
    return o


def _jwt_opts(vo, calls):
    o = {"audience": vo.get("audience"), "trust_domain": vo.get("trustDomain")}
    key = vo.get("key")
    if isinstance(key, dict):
        if "jwk" in key:
            o["key"] = key["jwk"]
        elif "jwks" in key:
            o["key"] = S.create_local_jwk_set(key["jwks"])
        elif "bundle" in key:
            bundle = _bundle_in(key["bundle"])
            o["key"] = S.create_trust_bundle_source({"fetch": lambda: bundle, "refresh_ms": 1000, "max_stale_ms": 5000}).jwt_key
    cur = vo.get("currentSec", vo["currentDateMs"] / 1000 if "currentDateMs" in vo else None)
    if cur is not None:
        o["current_date"] = cur
    if "algorithms" in vo:
        o["algorithms"] = vo["algorithms"]
    if "clockTolerance" in vo:
        o["clock_tolerance"] = vo["clockTolerance"]
    if "revocation" in vo:
        o["revocation"] = _mk_rev(vo["revocation"], calls, _cam_j)
    return o


def _x509_out(s, calls):
    return dict(_id(s.spiffe_id), publicKeyDer=s.public_key_der, calls=calls)


def _jwt_out(s, calls):
    return {"spiffeId": _id(s.spiffe_id), "claims": s.claims, "audience": s.audience, "expiresAt": s.expires_at, "calls": calls}


def _verify_x509(chain, vo):
    calls = []
    return _x509_out(S.verify_x509_svid(chain, _x509_opts(vo, calls)), calls)


def _verify_x509_b(chain, vo):  # the shared corpus nests the identity under spiffeId
    calls = []
    r = S.verify_x509_svid(chain, _x509_opts(vo, calls))
    return {"spiffeId": _id(r.spiffe_id), "publicKeyDer": r.public_key_der, "calls": calls}


def _verify_jwt(token, vo):
    calls = []
    return _jwt_out(S.verify_jwt_svid(token, _jwt_opts(vo, calls)), calls)


def _x509_verified(chain, vo):
    return S.verify_x509_svid(chain, _x509_opts(vo, []))


def _parse_x509(c):
    s = S.parse_x509_svid(c)
    return {"spiffeId": _id(s.spiffe_id), "publicKeyDer": s.public_key_der}


def _facts(der_b64u):
    f = S.read_cert_facts(b64d(der_b64u))
    return {"basicConstraintsPresent": f.basic_constraints_present, "isCa": f.is_ca, "pathLen": f.path_len, "keyUsagePresent": f.key_usage_present,
            "digitalSignature": f.digital_signature, "keyCertSign": f.key_cert_sign, "crlSign": f.crl_sign, "uriSans": f.uri_sans, "unknownCritical": f.unknown_critical}


# ---- scripted caches (both corpora) ---------------------------------------------------------------------------------------------

def _fetch_value(cur):
    if isinstance(cur, dict) and cur.get("$throw"):
        raise RuntimeError(cur["$throw"])
    if isinstance(cur, dict) and cur.get("$spiffe"):
        raise S.SpiffeError(cur["$spiffe"], "x")
    return cur


def _list_in(v):
    if isinstance(v, dict):
        return {{"spiffeIds": "spiffe_ids", "tokenHashes": "token_hashes"}.get(k, k): x for k, x in v.items()}
    return v


def _subject(s):
    d = {"spiffe_id": s["spiffeId"]}
    if "serialNumber" in s:
        d.update(serial_number=s["serialNumber"], fingerprint256=s["fingerprint256"], position=s["position"], is_leaf=s["isLeaf"])
    else:
        if "jti" in s:
            d["jti"] = s["jti"]
        d.update(expires_at=s["expiresAt"], token_hash=s["tokenHash"])
    return d


def _tb_scenario(opts, steps):
    st = {"t": 0, "cur": None, "n": 0}

    def fetch():
        st["n"] += 1
        return _bundle_in(_fetch_value(st["cur"]))
    try:
        src = S.create_trust_bundle_source({"fetch": fetch, "refresh_ms": opts.get("refreshMs"), "max_stale_ms": opts.get("maxStaleMs"), "now": lambda: st["t"]})
    except S.SpiffeError as e:
        return {"ctor": e.code}
    out = []
    for s in steps:
        st["t"], st["cur"], st["n"] = s["at"], s.get("fetch"), 0
        try:
            if s["op"] == "x509Roots":
                out.append({"ok": src.x509_roots(), "fetches": st["n"]})
            else:
                h = s.get("header")
                src.jwt_key({"alg": "ES256"} if h is None else h, "tok")
                out.append({"ok": "key", "fetches": st["n"]})
        except Exception as e:  # noqa: BLE001
            out.append({"code": getattr(e, "code", None), "fetches": st["n"]})
    return {"steps": out}


def _rv_scenario(opts, steps):
    st = {"t": 0, "cur": None, "n": 0}

    def fetch():
        st["n"] += 1
        return _list_in(_fetch_value(st["cur"]))
    try:
        src = S.create_revocation_source({"fetch": fetch, "refresh_ms": opts.get("refreshMs"), "max_stale_ms": opts.get("maxStaleMs"), "now": lambda: st["t"]})
    except S.SpiffeError as e:
        return {"ctor": e.code}
    out = []
    for s in steps:
        st["t"], st["cur"], st["n"] = s["at"], s.get("fetch"), 0
        try:
            v = None
            if s["op"] == "ensureFresh":
                src.ensure_fresh()
            elif s["op"] == "refresh":
                src.refresh()
            elif s["op"] == "x509":
                v = src.x509(_subject(s["subject"]))
            else:
                v = src.jwt(_subject(s["subject"]))
            out.append({"ok": v, "fetches": st["n"]})
        except Exception as e:  # noqa: BLE001
            out.append({"code": getattr(e, "code", None), "fetches": st["n"]})
    return {"steps": out}


def _proj(jwk):
    return {k: jwk[k] for k in ("kty", "crv", "x", "n") if k in jwk}


def _session_code(e):
    return e.code if isinstance(e, S.SpiffeError) else "jose"


def _bundle_session(a):
    st = {"t": a["start"], "n": 0}
    fetches = a["fetches"]

    def fetch():
        f = fetches[min(st["n"], len(fetches) - 1)]
        st["n"] += 1
        if "throw" in f:
            raise RuntimeError("fetch failed")
        return _bundle_in(f["list"])
    try:
        src = S.create_trust_bundle_source({"fetch": fetch, "refresh_ms": a["refreshMs"], "max_stale_ms": a["maxStaleMs"], "now": lambda: st["t"]})
    except S.SpiffeError:
        raise  # a refused configuration carries the source's own code (trust_bundle_unavailable)
    out = []
    for s in a["steps"]:
        try:
            if s["op"] == "adv":
                st["t"] += s["ms"]
                v = st["t"]
            elif s["op"] == "x509Roots":
                v = src.x509_roots()
            else:
                v = _proj(src.jwt_key(s["header"], "tok")[0])
        except Exception as e:  # noqa: BLE001
            out.append({"code": _session_code(e)})
            continue
        out.append({"v": v})
    return {"steps": out, "fetchCalls": st["n"]}


def _revocation_session(a):
    st = {"t": a["start"], "n": 0}
    fetches = a["fetches"]

    def fetch():
        f = fetches[min(st["n"], len(fetches) - 1)]
        st["n"] += 1
        if "throw" in f:
            raise RuntimeError("fetch failed")
        return _list_in(f["list"])
    try:
        src = S.create_revocation_source({"fetch": fetch, "refresh_ms": a["refreshMs"], "max_stale_ms": a["maxStaleMs"], "now": lambda: st["t"]})
    except S.SpiffeError:
        raise  # a refused configuration carries the source's own code (revocation_unavailable)
    out = []
    for s in a["steps"]:
        try:
            v = None
            if s["op"] == "adv":
                st["t"] += s["ms"]
                v = st["t"]
            elif s["op"] == "ensureFresh":
                src.ensure_fresh()
            elif s["op"] == "refresh":
                src.refresh()
            elif s["op"] == "x509":
                v = src.x509(_subject(s["subject"]))
            else:
                v = src.jwt(_subject(s["subject"]))
        except Exception as e:  # noqa: BLE001
            out.append({"code": _session_code(e)})
            continue
        out.append({"v": v})
    return {"steps": out, "fetchCalls": st["n"]}


# ---- holder binding sessions (second corpus) ------------------------------------------------------------------------------------

def _unverified(kind, a):
    if kind == "x509-parsed":
        return S.parse_x509_svid(a["chain"])
    if kind == "string":
        return ID
    if kind == "parsed-id":
        return S.parse_spiffe_id(ID)
    if kind == "hand-built":
        return S.X509Svid(S.parse_spiffe_id(ID), SimpleNamespace(), "x")
    return None


def _holder_session(a):
    kind = a["svid"]
    if kind == "x509":
        svid = S.verify_x509_svid(a["chain"], {"trust_domain": "example.org", "roots": a["roots"], "now": a["nowMs"] / 1000})
    elif kind == "jwt":
        j = a["jwt"]
        svid = S.verify_jwt_svid(j["token"], {"audience": j["audience"], "key": j["jwk"], "trust_domain": j["trustDomain"], "current_date": j["currentDateMs"] / 1000})
    else:
        svid = _unverified(kind, a)
    bind = {}
    if "proof" in a:
        bind["proof"] = a["proof"]
    if "acceptUnbound" in a:
        bind["accept_unbound_jwt_holder"] = a["acceptUnbound"]
    hk = a.get("holderKey")
    if "holderKey" in a and hk is None:
        hk = object()  # an explicit null is a holder key (not an absent one) and is refused
    elif a["op"] == "forHolder" and isinstance(hk, (bytes, bytearray)):
        hk = {"$bytes": base64.urlsafe_b64encode(bytes(hk)).rstrip(b"=").decode()}  # spiffeIdForHolder takes a string; the generator's byte value is an object there
    if a["op"] == "holder":
        return {"holder": _holder(S.svid_to_holder(svid, hk, bind))}
    if a["op"] == "forHolder":
        return {"spiffeId": S.spiffe_id_for_holder(svid, hk, bind)}
    return {"pin": S.workload_discharge_pin(a.get("label"), svid)}


_KNOWN = {"malformed_spiffe_id", "empty_trust_domain", "trust_domain_too_long", "invalid_trust_domain", "invalid_path", "id_too_long", "missing_audience",
          "missing_exp", "malformed_token", "invalid_subject", "trust_domain_mismatch", "no_uri_san", "multiple_uri_san", "invalid_holder_key", "unverified_svid",
          "missing_trust_domain", "holder_binding_failed", "malformed_certificate", "leaf_is_ca", "leaf_no_digital_signature", "leaf_cert_sign", "leaf_crl_sign",
          "leaf_root_path", "unsupported_critical_extension", "forbidden_algorithm", "invalid_typ", "chain_empty", "chain_trust_domain_mismatch", "chain_signature",
          "chain_not_ca", "chain_no_key_cert_sign", "chain_path_len", "chain_expired", "chain_untrusted_root", "chain_too_long", "trust_bundle_unavailable",
          "trust_bundle_invalid", "svid_revoked", "chain_revoked", "revocation_unavailable", "SVID is bound to a different key"}


def _admission_b(a):
    r = _admission_b_raw(a)
    return dict(r, reason=r["reason"] if r["reason"] in _KNOWN else "other") if "reason" in r else r  # the generator reports any other failure as "other"


def _admission_b_raw(a):
    if a["kind"] == "x509":
        e = {"kind": "x509", "chain": a["chain"], "verify": {"trust_domain": "example.org", "roots": a["roots"], "now": a["nowMs"] / 1000}}
    else:
        e = {"kind": "jwt", "token": a["token"], "verify": {"audience": "api", "key": a["jwk"], "trust_domain": "example.org", "current_date": 1800000060}}
    if "bind" in a:
        e["bind"] = _bind(a["bind"])
    return S.spiffe_admission_evidence(e, a["instanceKey"])


def _admission_a(e, key):
    calls = []
    ee = {"kind": e["kind"]}
    if e["kind"] == "x509":
        ee.update(chain=e["chain"], verify=_x509_opts(e["verify"], calls))
    else:
        ee.update(token=e["token"], verify=_jwt_opts(e["verify"], calls))
    if "bind" in e:
        ee["bind"] = _bind(e["bind"])
    return S.spiffe_admission_evidence(ee, key)


# ---- the first corpus ----------------------------------------------------------------------------------------------------------

def _holder_x509(chain, vo, hk, bind):
    return _holder(S.svid_to_holder(_x509_verified(chain, vo), hk, _bind(bind)))


def _holder_jwt(token, vo, hk, bind):
    return _holder(S.svid_to_holder(S.verify_jwt_svid(token, _jwt_opts(vo, [])), hk, _bind(bind)))


def _holder_unverified(kind, pem):
    v = (ID if kind == "string" else {"spiffe_id": S.parse_spiffe_id(ID)} if kind == "object" else None if kind == "null" else 5 if kind == "number"
         else S.JwtSvid(S.parse_spiffe_id(ID), {}, [], 1) if kind == "parsed jwt-like" else S.parse_x509_svid(pem))
    return _holder(S.svid_to_holder(v, HOLDER, {}))


MAP_A = {
    "parseSpiffeId": lambda s: _id(S.parse_spiffe_id(s)),
    "parseX509Svid": _parse_x509,
    "verifyX509Svid": _verify_x509,
    "verifyJwtSvid": _verify_jwt,
    "svidToHolderX509": _holder_x509,
    "svidToHolderJwt": _holder_jwt,
    "svidToHolderUnverified": _holder_unverified,
    "spiffeIdForHolder": lambda chain, vo, h, b: S.spiffe_id_for_holder(_x509_verified(chain, vo), h, _bind(b)),
    "workloadDischargePin": lambda label, chain, vo: S.workload_discharge_pin(label, _x509_verified(chain, vo)),
    "holderToSpiffeId": lambda h: S.holder_to_spiffe_id(SimpleNamespace(spiffe_id=h.get("spiffeId"))),
    "holderBindingMessage": S.holder_binding_message,
    "spiffeAdmissionEvidence": _admission_a,
    "trustBundleScenario": _tb_scenario,
    "revocationScenario": _rv_scenario,
    "constants": lambda: {"jwtSvidAlgorithms": list(S.JWT_SVID_ALGORITHMS)},
}


def test_first_corpus_is_the_full_oracle():
    assert COUNT_A == sum(len(v) for v in A.values()) and set(A) == set(MAP_A)


@pytest.mark.parametrize("fn", sorted(MAP_A))
def test_matches_the_reference(fn):
    run(A[fn], MAP_A[fn])


# ---- the second corpus ---------------------------------------------------------------------------------------------------------

def _skip_async(c):
    """An asynchronous revocation check has no synchronous analogue in this port."""
    a = c["args"][0] if c["fn"] == "jwtSession" and c["args"] else {}
    return "asynchronous revocation check" if str(a.get("revocation", "")).startswith("async-") else None


def _jwt_session(a):
    return _jose(_verify_jwt)(a["token"], a)


MAP_B = {
    "parseSpiffeId": lambda s: _id(S.parse_spiffe_id(s)),
    "readCertFacts": _facts,
    "parseX509Svid": _parse_x509,
    "verifyX509Svid": _verify_x509_b,
    "holderToSpiffeId": lambda h: S.holder_to_spiffe_id(SimpleNamespace(spiffe_id=h.get("spiffeId"))),
    "holderBindingMessage": S.holder_binding_message,
    "constants": lambda: {"JWT_SVID_ALGORITHMS": list(S.JWT_SVID_ALGORITHMS)},
    "jwtSession": _jwt_session,
    "holderSession": _jose(_holder_session),
    "admission": _admission_b,
    "bundleSession": _bundle_session,
    "revocationSession": _revocation_session,
}


def test_second_corpus_is_the_full_oracle():
    assert COUNT_B == sum(len(v) for v in B.values()) and set(B) == set(MAP_B)


@pytest.mark.parametrize("fn", sorted(MAP_B))
def test_matches_the_shared_reference_corpus(fn):
    run(B[fn], MAP_B[fn], skip=_skip_async)


def test_only_asynchronous_revocation_cases_are_skipped():
    skipped = sum(1 for c in B["jwtSession"] if _skip_async(c))
    assert skipped == 3
