"""The software attestation layer: the binding hash, the dev attestor and its documents, the document registry, the bounded nonce store and the
nonce entropy gate, the agent-binding match, ``verify_attestation`` and its hook, the multi-root (threshold over independent roots) verifier and
evidence anchoring. A port of the reference ``attestation`` module; its decisions are the proved ones (stage order, first failure wins, the
single-use nonce rule, the N-of-M reconciliation), so the same facts give the same verdict and the same reason text.

Documents, bindings and claims are dicts in the reference's member names. A hardware verifier is any object with ``verify(input) -> dict``
(``{"ok", "reason"?, "measured"?, "bound"?, "hostAsserted"?}``); a nonce store is any object with ``consume(nonce) -> bool``. Everything is
synchronous. The legacy ``allowUnboundPq`` opt-out is not offered: a PQ or hybrid attestation verifies only under a pinned key."""
from __future__ import annotations

import math
from ._fin import fin
import re
import time
from typing import Any, Callable, Dict, List, Optional

from .agent import KeyPair
from .attest_common import attestation_binding
from .authorize import read_envelope
from .intent_v2 import _UNDEF, _bind_suite_fields, _pinned_suite_error, suite_capability_error
from .intent_wb import _js_str
from .ledger import sign_tree_head
from .ledger_proofs import TransparencyLedger
from .pca import b64u, canonical_bytes_strict, hash_canonical
from .pq_suites import sign_suite_artifact, suite_pq_public_key

__all__ = ["ATTEST_BIND_DOMAIN", "MAX_ATTESTATION_AGE_MS", "DEFAULT_NONCE_RETENTION_MS", "MIN_ATTESTATION_NONCE_BYTES", "ATTEST_ANCHOR_DOMAIN",
           "attestation_binding_b64u", "create_dev_attestor", "attestation_digest", "attestation_registry", "memory_nonce_store", "nonce_entropy_ok",
           "requires_attestation", "nonce_binds", "match_agent_binding", "verify_attestation", "create_attestation_verifier",
           "create_multi_root_verifier", "attestation_evidence_digest", "anchor_attestation_evidence"]

_DOMAIN = "atlas-pca/attest/v1\0"
ATTEST_BIND_DOMAIN = "atlas-pca/attest-bind/v1\0"
ATTEST_ANCHOR_DOMAIN = "atlas-pca/attest-anchor/v1\0"
MAX_ATTESTATION_AGE_MS = 5 * 60_000
DEFAULT_NONCE_RETENTION_MS = 60 * 60 * 1000
MIN_ATTESTATION_NONCE_BYTES = 16
_MAX_SAFE = 9007199254740991


def _is_num(x: Any) -> bool:
    return isinstance(x, (int, float)) and not isinstance(x, bool)


def _fin(x: Any) -> bool:
    return _is_num(x) and fin(x)


def _safe_int(x: Any) -> bool:
    return _fin(x) and x == math.floor(x) and abs(x) <= _MAX_SAFE


def _g(o: Any, k: str) -> Any:
    """``o?.k``: a missing member, or an object that has none, is the marker ``_UNDEF``."""
    return o.get(k, _UNDEF) if isinstance(o, dict) else _UNDEF


def _path(o: Any, *keys: str) -> Any:
    for k in keys:
        o = _g(o, k)
        if o is _UNDEF:
            return _UNDEF
    return o


def _seq(a: Any, b: Any) -> bool:
    """Strict equality of two JSON values (a number never equals a boolean or a string)."""
    if _is_num(a) and _is_num(b):
        return a == b
    return type(a) is type(b) and a == b


def _truthy(x: Any) -> bool:
    """JavaScript truthiness (an empty object or array is truthy)."""
    return not (x is None or x is _UNDEF or x is False or (_is_num(x) and (x == 0 or x != x)) or x == "")


def _msg(e: BaseException) -> str:
    return str(e) or "unknown"


def attestation_binding_b64u(exp: Any) -> str:
    """The base64url form of the binding hash (SHA-512 over domain, holder, grant, epoch and nonce, each length-prefixed)."""
    return b64u(attestation_binding(exp))


# ---- the dev attestor and documents ----

def _attest_message(body: dict) -> bytes:
    return _DOMAIN.encode("utf-8") + canonical_bytes_strict(body)


def _alg_known(alg: Any) -> bool:
    return suite_capability_error(alg) is None


def _need(claims: Any, k: str) -> Any:
    if not isinstance(claims, dict) or k not in claims:
        raise TypeError("canonicalize: undefined member %s" % k)  # an absent claim has no canonical form
    return claims[k]


def create_dev_attestor(secret: bytes, suite: Optional[dict] = None) -> Any:
    """A development attestor: signs software attestation documents. ``suite`` ({"alg", "pq"}) selects a signature suite. Returns an object with
    ``public_key`` and ``attest(claims)``."""
    ed = KeyPair(bytes(secret), allow_insecure_signer=True)
    alg = (suite or {}).get("alg", _UNDEF)
    if not _alg_known(alg):
        raise ValueError("createDevAttestor: unknown signature alg '%s'" % _js_str(alg))
    pq = (suite or {}).get("pq")
    real_alg = None if alg is _UNDEF else alg
    pq_pk = suite_pq_public_key(real_alg, pq)

    class _Attestor:
        public_key = ed.public

        @staticmethod
        def attest(claims: dict) -> Dict[str, Any]:
            body: Dict[str, Any] = {"model_id": _need(claims, "model_id"), "weights_digest": _need(claims, "weights_digest"),
                                    "runtime_measurement": _need(claims, "runtime_measurement"), "operator": _need(claims, "operator"),
                                    "nonce": _need(claims, "nonce"), "issued_at": _need(claims, "issued_at"), "expires_at": _need(claims, "expires_at"),
                                    "attestor": ed.public, "mode": "software"}
            for k in ("system_prompt_digest", "tool_manifest_digest"):
                if k in claims:
                    body[k] = claims[k]
            if "holder_pub" in claims and "grant_ref" in claims and "epoch" in claims:
                body["binding"] = attestation_binding_b64u({"holderPub": claims["holder_pub"], "grantRef": claims["grant_ref"], "epoch": claims["epoch"],
                                                            "nonce": claims["nonce"]})
            signed = _bind_suite_fields(body, alg, _UNDEF if pq_pk is None else pq_pk)
            return dict(signed, **sign_suite_artifact(real_alg, ed, pq, _attest_message(signed)))

    return _Attestor()


def attestation_digest(doc: Any) -> str:
    """The strict content hash of a document."""
    return hash_canonical(doc)


def attestation_registry(docs: Any) -> Callable[[Any], Optional[dict]]:
    """A resolver over a document list, keyed by the document's NONCE (the last document of a nonce wins): the document whose nonce is the
    PCActn's ``attestation.quote_digest``."""
    by_nonce: Dict[str, dict] = {}
    for d in docs if isinstance(docs, list) else []:
        if isinstance(d, dict) and isinstance(d.get("nonce"), str):
            by_nonce[d["nonce"]] = d

    def resolve(ctx: Any) -> Optional[dict]:
        key = _path(ctx, "pcactn", "attestation", "quote_digest")
        return by_nonce.get(key) if isinstance(key, str) else None
    return resolve


# ---- the nonce store and its entropy gate ----

def memory_nonce_store(max_entries: Any = 100_000, opts: Optional[dict] = None) -> Any:
    """A bounded single-use store: a consumed nonce is refused for ``retentionMs``; a full store refuses (it never evicts a live entry); only
    aged-out entries are dropped. The clock (``opts["now"]``) must answer safe integer milliseconds, anything else fails closed."""
    opts = opts or {}
    if not _safe_int(max_entries) or max_entries < 1:
        raise TypeError("memoryNonceStore: max must be a positive integer (a store that retains nothing gives no replay protection)")
    retention = opts.get("retentionMs")
    retention = DEFAULT_NONCE_RETENTION_MS if retention is None else retention
    if not _safe_int(retention) or retention <= 0:
        raise TypeError("memoryNonceStore: retentionMs must be a positive integer (ms)")
    clock = opts.get("now") or (lambda: int(time.time() * 1000))
    seen: Dict[str, Any] = {}  # nonce -> time consumed (insertion order == time order)

    class _Store:
        @staticmethod
        def consume(nonce: Any) -> bool:
            if not isinstance(nonce, str):
                return False
            t = clock()
            if not _safe_int(t):
                return False
            if nonce in seen:
                if t - seen[nonce] < retention:
                    return False  # retained: a replay
                del seen[nonce]  # aged out of retention: treated as new
            if len(seen) >= max_entries:
                for k, at in list(seen.items()):
                    if t - at < retention:
                        break
                    del seen[k]
                if len(seen) >= max_entries:
                    return False  # full of live nonces: fail closed
            seen[nonce] = t
            return True

    return _Store()


def nonce_entropy_ok(nonce: Any, min_bytes: Any = None) -> bool:
    """At least 128 bits (or ``min_bytes``, never fewer) in hex or base64url, with at least 8 distinct characters."""
    if not isinstance(nonce, str):
        return False
    from .risk import _js_num
    mb = MIN_ATTESTATION_NONCE_BYTES if min_bytes is None else _js_num(min_bytes)
    need = math.nan if mb != mb else max(mb, MIN_ATTESTATION_NONCE_BYTES)
    is_hex = re.fullmatch(r"[0-9a-fA-F]+", nonce) is not None
    is_b64 = re.fullmatch(r"[A-Za-z0-9_-]+", nonce) is not None
    if not is_hex and not is_b64:
        return False
    nbytes = len(nonce) / 2 if is_hex else (len(nonce) * 3) // 4
    if nbytes < need:
        return False
    return len(set(nonce)) >= 8


# ---- the agent-binding match ----

_SVN_TEXT = re.compile(r"(?:0|[1-9][0-9]*)")


def _is_svn_bound(x: Any) -> bool:
    return _is_num(x) and _safe_int(x) and x >= 0 and not (isinstance(x, float) and math.copysign(1, x) < 0)


def _svn_spec(mm: Any) -> bool:
    return isinstance(mm, dict) and list(mm.keys()) == ["svn"] and _is_svn_bound(mm["svn"])


def _measured_svn(runtime: Any) -> Optional[int]:
    if not isinstance(runtime, str) or _SVN_TEXT.fullmatch(runtime) is None:
        return None
    n = int(runtime)
    return n if n <= _MAX_SAFE else None


def _nonempty_list(x: Any) -> bool:
    return isinstance(x, list) and len(x) > 0


def requires_attestation(binding: Any) -> bool:
    """Does anything pin the agent's identity (so a missing document is a deny)? A malformed ``min_measurement`` counts: it fails closed."""
    b = binding if isinstance(binding, dict) else {}
    mm = b.get("min_measurement", _UNDEF)
    has_min = mm is not _UNDEF and mm != ""
    return bool(_nonempty_list(b.get("model_allowlist")) or has_min or (isinstance(b.get("operator"), str) and len(b["operator"]) > 0)
                or _nonempty_list(b.get("weights_allowlist")) or _nonempty_list(b.get("system_prompt_allowlist"))
                or _nonempty_list(b.get("tool_manifest_allowlist")) or b.get("require_hardware") is True or b.get("require_measured_weights") is True)


def _member(lst: Any, x: Any) -> bool:
    return isinstance(lst, list) and any(_seq(e, x) for e in lst)


def match_agent_binding(ident: Any, binding: Any) -> Optional[str]:
    """The first constraint of ``binding`` that the measured identity violates (None when it satisfies every pinned one). A pinned digest that
    the identity does not carry fails closed; a malformed ``min_measurement`` is never satisfied."""
    if ident is None:
        raise TypeError("Cannot read properties of null (reading 'runtime_measurement')")
    b = binding if isinstance(binding, dict) else {}
    i = ident
    mm = b.get("min_measurement", _UNDEF)
    runtime = _g(i, "runtime_measurement")
    if _nonempty_list(b.get("model_allowlist")) and not _member(b["model_allowlist"], _g(i, "model_id")):
        return "model_id %s not in model_allowlist" % _js_str(_g(i, "model_id"))
    if mm is not _UNDEF and mm != "":
        if isinstance(mm, str):
            if not _seq(runtime, mm):
                return "runtime_measurement does not match required min_measurement"
        elif not _svn_spec(mm):
            return "min_measurement is malformed: it must be a non-empty string or {svn: n} with n a non-negative safe integer (fail closed)"
        else:
            got = _measured_svn(runtime)
            if got is None:
                return "runtime_measurement %s is not an integer SVN (required min svn %s)" % (_js_str(runtime), _js_str(mm["svn"]))
            if got < mm["svn"]:
                return "runtime_measurement svn %s is below required min svn %s" % (got, _js_str(mm["svn"]))
    if isinstance(b.get("operator"), str) and len(b["operator"]) > 0 and not _seq(_g(i, "operator"), b["operator"]):
        return "operator %s is not the bound operator" % _js_str(_g(i, "operator"))
    if b.get("require_measured_weights") is True and _g(i, "weights_measured") is not True:
        return "weights_digest is not hardware-measured (require_measured_weights: self-asserted or host-asserted weights rejected)"
    if _nonempty_list(b.get("weights_allowlist")) and not _member(b["weights_allowlist"], _g(i, "weights_digest")):
        return "weights_digest not in weights_allowlist (model swap / fine-tune?)"
    if _nonempty_list(b.get("system_prompt_allowlist")):
        sp = _g(i, "system_prompt_digest")
        if not isinstance(sp, str) or not _member(b["system_prompt_allowlist"], sp):
            return "system_prompt_digest not in system_prompt_allowlist (instructions changed / prompt injection?)"
    if _nonempty_list(b.get("tool_manifest_allowlist")):
        tm = _g(i, "tool_manifest_digest")
        if not isinstance(tm, str) or not _member(b["tool_manifest_allowlist"], tm):
            return "tool_manifest_digest not in tool_manifest_allowlist (tools changed?)"
    return None


def nonce_binds(doc: Any, ctx: Any) -> bool:
    """Is the document's nonce the PCActn's ``attestation.quote_digest``?"""
    n = _g(doc, "nonce")
    return isinstance(n, str) and n == _path(ctx, "pcactn", "attestation", "quote_digest")


# ---- verify_attestation ----

def _nonce_age_reason(issued: Any, now_ms: Any, skew: Any, max_age: Any) -> Optional[str]:
    if not _fin(issued):
        return "server nonce issue time unknown (cannot establish freshness)"
    if not (now_ms + skew >= issued):
        return "nonce issued in the future"
    if not (now_ms - issued <= max_age + skew):
        return "attestation nonce expired (stale quote)"
    return None


def _window(now_ms: Any, skew: Any, iat: Any, exp: Any) -> str:
    if not _fin(iat) or not _fin(exp):
        return "malformed"
    if exp < iat:
        return "malformed"
    if not (now_ms + skew >= iat):
        return "notyet"
    if not (now_ms - skew <= exp):
        return "expired"
    return "valid"


def _order(has_hw: bool) -> List[str]:
    head = ["KPresent", "KBindingConstructible", "KGrantRef", "KEpoch", "KQuote", "KDocNonce", "KReqHwVerifier", "KReqHwMode"]
    mid = (["KHwNonceAge", "KHwOk", "KHwBound", "KHwMeasured"] if has_hw else
           ["KSoftMode", "KAttestorTrusted", "KAlgKnown", "KSigOk", "KBindingPresent", "KBindingEq", "KWindowWellFormed", "KNotYetValid", "KExpired",
            "KSoftNonceAge"])
    return head + mid + ["KAgentBinding"]


def _software_identity(d: Any) -> Dict[str, Any]:
    out = {k: d.get(k) for k in ("model_id", "weights_digest", "runtime_measurement", "operator")} if isinstance(d, dict) else {}
    if isinstance(d, dict):
        for k in ("system_prompt_digest", "tool_manifest_digest"):
            if isinstance(d.get(k), str):
                out[k] = d[k]
    return out


def verify_attestation(inp: dict) -> Dict[str, Any]:
    """Verify the document for one action: ``{"ok", "present", "bound", "reason"?, "identity"?}``. Input: document, ctx, expected (the server-issued
    binding), nowMs, trustedAttestorKeys, pqPins?, hardwareVerifier?, maxNonceAgeMs?, clockSkewMs?. The stages run in a fixed order and the first
    failure wins; a hardware route needs the verifier to report ok, bound and a measured identity, a software route a trusted attestor, a known
    alg, a verifying signature, a binding equal to the expected one and a live validity window; the agent_binding match always runs last."""
    doc = inp.get("document")
    present = isinstance(doc, (dict, list))

    def fail(reason: str) -> Dict[str, Any]:
        return {"ok": False, "present": present, "bound": False, "reason": reason}

    try:
        ctx, expected, now_ms = inp.get("ctx"), inp.get("expected"), inp.get("nowMs")
        if not _fin(now_ms):
            return fail("verifier clock is not a finite time (fail closed)")
        trusted = set(inp.get("trustedAttestorKeys") or ())
        cs = inp.get("clockSkewMs")
        skew = max(0, cs) if _fin(cs) else 0
        ma = inp.get("maxNonceAgeMs")
        max_age = min(ma if _fin(ma) and ma > 0 else MAX_ATTESTATION_AGE_MS, MAX_ATTESTATION_AGE_MS)
        hw_verifier = inp.get("hardwareVerifier")
        has_hw = bool(hw_verifier)
        state: Dict[str, Any] = {}
        d = doc if isinstance(doc, dict) else {}

        def env() -> Any:
            if "env" not in state:
                if ctx is None:
                    raise TypeError("Cannot read properties of null (reading 'grant')")
                state["env"] = read_envelope(_g(ctx, "grant"))
            return state["env"]

        def require_hw() -> bool:
            return _path(env(), "agent_binding", "require_hardware") is True

        def win() -> str:
            if "win" not in state:
                state["win"] = _window(now_ms, skew, d.get("issued_at"), d.get("expires_at"))
            return state["win"]

        def stage(k: str) -> Any:
            if k == "KPresent":
                return present, "no attestation document for this action"
            if k == "KBindingConstructible":
                try:
                    state["binding"] = attestation_binding_b64u(expected)
                    return True, ""
                except Exception as e:  # noqa: BLE001
                    return False, "attestation binding not constructible: %s" % (_msg(e) if str(e) else "invalid")
            if k == "KGrantRef":
                return _seq(_path(ctx, "pcactn", "grant_ref"), _g(expected, "grantRef")), "attestation binding: PCActn grant_ref differs from expected grant"
            if k == "KEpoch":
                return (_seq(_path(ctx, "pcactn", "attestation", "epoch"), _g(expected, "epoch")),
                        "attestation binding: PCActn attestation epoch differs from expected epoch")
            if k == "KQuote":
                return _seq(_path(ctx, "pcactn", "attestation", "quote_digest"), _g(expected, "nonce")), "attestation nonce does not bind to this PCActn"
            if k == "KDocNonce":
                return _seq(d.get("nonce", _UNDEF), _g(expected, "nonce")), "attestation nonce does not match the server-issued nonce"
            if k == "KReqHwVerifier":
                return (not require_hw()) or has_hw, "agent_binding.require_hardware: no hardware verifier is configured (fail closed)"
            if k == "KReqHwMode":
                return (not require_hw()) or d.get("mode") == "hardware", "agent_binding.require_hardware: attestation document is not hardware-rooted (software mode)"
            if k == "KHwNonceAge":
                r = _nonce_age_reason(_g(expected, "nonceIssuedAt"), now_ms, skew, max_age)
                return r is None, r or ""
            if k == "KSoftMode":
                return d.get("mode") == "software", "document mode %s needs a hardwareVerifier" % _js_str(d.get("mode", _UNDEF))
            if k == "KAttestorTrusted":
                return isinstance(d.get("attestor"), str) and d["attestor"] in trusted, "attestor key is not trusted"
            if k == "KAlgKnown":
                return _alg_known(d.get("alg", _UNDEF)), "attestation declares an unknown signature alg"
            if k == "KSigOk":
                sig = d.get("sig")
                ok = False
                if isinstance(sig, str):
                    body = {kk: v for kk, v in d.items() if kk not in ("sig", "pq_sig")}
                    pins = inp.get("pqPins")
                    ok = _pinned_suite_error(d.get("alg", _UNDEF), d.get("attestor"), d.get("pq_pk", _UNDEF), _attest_message(body), sig,
                                             d.get("pq_sig", _UNDEF), pins) is None
                return ok, "attestation signature does not verify"
            if k == "KBindingPresent":
                return isinstance(d.get("binding"), str) and len(d["binding"]) > 0, "attestation is not bound (binding absent)"
            if k == "KBindingEq":
                return _seq(d.get("binding", _UNDEF), state["binding"]), "attestation binding mismatch (holder/grant/epoch/nonce)"
            if k == "KWindowWellFormed":
                return win() != "malformed", "malformed attestation validity window"
            if k == "KNotYetValid":
                return win() != "notyet", "attestation not yet valid"
            if k == "KExpired":
                return win() != "expired", "attestation expired"
            if k == "KSoftNonceAge":
                issued = _g(expected, "nonceIssuedAt")
                if not _is_num(issued):
                    return True, ""
                r = _nonce_age_reason(issued, now_ms, skew, max_age)
                return r is None, r or ""
            if k == "KAgentBinding":
                state["agent_err"] = match_agent_binding(state["identity"], _path(env(), "agent_binding") if env() is not None else None)
                return state["agent_err"] is None, state["agent_err"] or ""
            raise ValueError("unknown stage %s" % k)

        hw: Any = None
        for k in _order(has_hw):
            if k == "KHwOk":
                hw = hw_verifier.verify({"document": doc, "ctx": ctx, "nowMs": now_ms, "expected": expected})
                if hw is None:
                    raise TypeError("Cannot read properties of null (reading 'ok')")
            if k == "KAgentBinding" and "identity" not in state:
                state["identity"] = _g(hw, "measured") if has_hw else _software_identity(d)
            if k == "KHwOk":
                holds, why = _truthy(_g(hw, "ok")), "hardware attestation rejected: %s" % (
                    _js_str(_g(hw, "reason")) if _g(hw, "reason") not in (_UNDEF, None) else "invalid")
            elif k == "KHwBound":
                holds, why = _g(hw, "bound") is True, "hardware verifier did not confirm report_data binding"
            elif k == "KHwMeasured":
                m = _g(hw, "measured")
                holds, why = _truthy(m), "hardware verifier returned no measured identity"
            else:
                holds, why = stage(k)
            if not holds:
                return fail(why)
        return {"ok": True, "present": True, "bound": True, "identity": state["identity"]}
    except Exception as e:  # noqa: BLE001
        return fail("attestation verification error (fail closed): %s" % _msg(e))


def create_attestation_verifier(opts: dict) -> Callable[[Any], Dict[str, Any]]:
    """The attestation hook for ``verify``/``authorize``: ``hook(ctx)`` -> ``{"enforced": True, "ok", "reason"?, "present", "bound"}``. Options:
    trustedAttestorKeys, nonceStore, minNonceBytes, hardwareVerifier, resolveDocument(ctx), expectedBinding(ctx), insecure_selfDeclaredNonce,
    maxNonceAgeMs, now() (ms), clockSkewMs, pqPins. Without ``expectedBinding`` the hook is closed (no server-issued nonce); an ok and bound
    verdict also needs the store's single-use answer when a store is configured."""
    o = dict(opts)
    trusted = list(o["trustedAttestorKeys"]) if isinstance(o.get("trustedAttestorKeys"), list) else []
    resolve = o.get("resolveDocument") or (lambda ctx: None)
    clock = o.get("now") or (lambda: int(time.time() * 1000))
    store = o.get("nonceStore")

    def fin(v: dict) -> Dict[str, Any]:
        out: Dict[str, Any] = {"enforced": True, "ok": v["ok"]}
        if v.get("reason"):
            out["reason"] = v["reason"]
        out["present"], out["bound"] = v["present"], v["bound"]
        return out

    def hook(ctx: Any) -> Dict[str, Any]:
        try:
            document = resolve(ctx)
            expected = None
            if o.get("expectedBinding"):
                expected = o["expectedBinding"](ctx)
            elif o.get("insecure_selfDeclaredNonce") is True:
                chain = _path(ctx, "pcactn", "cap_chain")
                leaf = chain[-1] if isinstance(chain, list) and chain else _g(ctx, "grant")
                holder = _g(leaf, "holder")
                expected = {"holderPub": holder if isinstance(holder, str) else "", "grantRef": _path(ctx, "pcactn", "grant_ref"),
                            "epoch": _path(ctx, "pcactn", "attestation", "epoch"), "nonce": _path(ctx, "pcactn", "attestation", "quote_digest")}
                expected = {k: v for k, v in expected.items() if v is not _UNDEF}
            if not _truthy(expected):
                return fin({"ok": False, "present": _truthy(document), "bound": False, "reason": "no server-issued attestation nonce/binding available (fail closed)"})
            if o.get("insecure_selfDeclaredNonce") is not True and not nonce_entropy_ok(_g(expected, "nonce") if _g(expected, "nonce") is not _UNDEF else None,
                                                                                         o.get("minNonceBytes")):
                return fin({"ok": False, "present": _truthy(document), "bound": False,
                            "reason": "attestation nonce has less than 128 bits of entropy (F-5; use a CSPRNG nonce of >= 16 bytes)"})
            verdict = verify_attestation({"document": document, "ctx": ctx, "expected": expected, "nowMs": clock(), "trustedAttestorKeys": trusted,
                                          "pqPins": o.get("pqPins"), "hardwareVerifier": o.get("hardwareVerifier"),
                                          "maxNonceAgeMs": o.get("maxNonceAgeMs"), "clockSkewMs": o.get("clockSkewMs")})
            if verdict["ok"] and verdict["bound"] and store is not None:
                if not store.consume(_g(expected, "nonce")):
                    return fin({"ok": False, "present": verdict["present"], "bound": False, "reason": "attestation nonce already consumed (replay)"})
            return fin(verdict)
        except Exception as e:  # noqa: BLE001
            return fin({"ok": False, "present": False, "bound": False, "reason": "attestation verification error (fail closed): %s" % _msg(e)})

    return hook


# ---- the multi-root verifier ----

_IDENT_FIELDS = ("model_id", "weights_digest", "runtime_measurement", "operator", "system_prompt_digest", "tool_manifest_digest")


def _sid(v: Any) -> Optional[str]:
    return v if isinstance(v, str) and len(v) > 0 else None


def _reconcile(passed: List[tuple]) -> Dict[str, Any]:
    merged: Dict[str, Any] = {}
    for f, name in enumerate(_IDENT_FIELDS):
        chosen, who = None, -1
        for idx, m in passed:
            v = _sid(_g(m, name))
            if v is None:
                continue
            if chosen is None:
                chosen, who = v, idx
            elif chosen != v:
                return {"clash": (name, who, idx)}
        merged[name] = chosen
    w = merged["weights_digest"]
    measured = w is not None and any(_g(m, "weights_measured") is True and _sid(_g(m, "weights_digest")) == w for _, m in passed)
    return {"merged": merged, "measured": measured}


def create_multi_root_verifier(policy: dict) -> Any:
    """A hardware verifier that needs ``threshold`` of the independent ``roots`` to corroborate (every ``required`` root must pass, and the passing
    roots' identities must not conflict). Roots: ``{"id", "verifier", "required"?, "suite"?}``. Construction errors raise TypeError."""
    roots = policy.get("roots") if isinstance(policy, dict) else None
    threshold = policy.get("threshold") if isinstance(policy, dict) else None
    roots = [dict(r) if isinstance(r, dict) else r for r in roots] if isinstance(roots, list) else roots
    if not isinstance(roots, list) or len(roots) == 0:
        raise TypeError("createMultiRootVerifier: at least one attestation root is required")
    if not _fin(threshold) or threshold != math.floor(threshold) or threshold < 1 or threshold > len(roots):
        raise TypeError("createMultiRootVerifier: threshold must be an integer in [1, roots.length]")
    ids = set()
    for r in roots:
        if not isinstance(r, dict) or not isinstance(r.get("id"), str) or len(r["id"]) == 0:
            raise TypeError("createMultiRootVerifier: each root needs a non-empty id")
        if r["id"] in ids:
            raise TypeError("createMultiRootVerifier: duplicate root id '%s'" % r["id"])
        ids.add(r["id"])

    class _Verifier:
        @staticmethod
        def verify(inp: dict) -> Dict[str, Any]:
            try:
                results: List[Any] = []
                passed: List[tuple] = []
                host: Dict[str, Any] = {}
                for i, root in enumerate(roots):
                    try:
                        res = root["verifier"].verify(inp)
                    except Exception as e:  # noqa: BLE001
                        res = {"ok": False, "reason": "root '%s' threw (fail closed): %s" % (root["id"], _msg(e))}
                    results.append(res)
                    ok = isinstance(res, dict) and res.get("ok") is True and res.get("bound") is True and _truthy(res.get("measured"))
                    if ok:
                        passed.append((i, res["measured"]))
                        if res.get("hostAsserted"):
                            for k, v in res["hostAsserted"].items():
                                host["%s.%s" % (root["id"], k)] = v
                    elif root.get("required") is True:
                        why = ("root '%s' returned a malformed result (fail closed)" % root["id"]) if not isinstance(res, dict) else (res.get("reason") or "invalid")
                        return {"ok": False, "reason": "required attestation root '%s' failed: %s" % (root["id"], why)}
                if len(passed) < threshold:
                    return {"ok": False, "reason": "multi-root attestation below threshold (%d/%s independent roots corroborated)" % (len(passed), _js_str(threshold))}
                rec = _reconcile(passed)
                if "clash" in rec:
                    name, a, b = rec["clash"]
                    return {"ok": False, "reason": "multi-root attestation identity conflict: roots '%s' and '%s' disagree on %s" % (roots[a]["id"], roots[b]["id"], name)}
                m = rec["merged"]
                measured: Dict[str, Any] = {"model_id": m["model_id"] or "", "weights_digest": m["weights_digest"] or "", "weights_measured": rec["measured"],
                                            "runtime_measurement": m["runtime_measurement"] or "", "operator": m["operator"] or ""}
                for k in ("system_prompt_digest", "tool_manifest_digest"):
                    if m[k]:
                        measured[k] = m[k]
                out: Dict[str, Any] = {"ok": True, "bound": True, "measured": measured}
                if host:
                    out["hostAsserted"] = host
                return out
            except Exception as e:  # noqa: BLE001
                return {"ok": False, "reason": "multi-root attestation error (fail closed): %s" % _msg(e)}

    return _Verifier()


# ---- evidence anchoring ----

def attestation_evidence_digest(ev: dict) -> str:
    """The strict digest of verified attestation evidence (what is anchored in the transparency ledger)."""
    ident, binding = ev["identity"], ev["binding"]

    def opt(k: str) -> Any:
        v = ident.get(k)
        return "" if v is None else v
    return hash_canonical({"domain": ATTEST_ANCHOR_DOMAIN, "holder": binding["holderPub"], "grant": binding["grantRef"], "epoch": binding["epoch"],
                           "nonce": binding["nonce"], "model_id": ident["model_id"], "weights_digest": ident["weights_digest"],
                           "weights_measured": ident.get("weights_measured") is True, "runtime_measurement": ident["runtime_measurement"],
                           "operator": ident["operator"], "system_prompt_digest": opt("system_prompt_digest"), "tool_manifest_digest": opt("tool_manifest_digest"),
                           "roots": sorted(ev.get("rootIds") or [], key=lambda s: s.encode("utf-16-be", "surrogatepass")),
                           "suite": ev.get("suite") if ev.get("suite") is not None else "", "verified_at": ev["verifiedAt"]})


def anchor_attestation_evidence(ev: dict, opts: Optional[dict]) -> Dict[str, Any]:
    """Append the evidence digest to the transparency ledger and, with a guardian key, sign the new tree head. ``{"index", "commit", "sth"?}``;
    raises (fail closed) with no ledger, and with ``required`` when the head cannot be signed."""
    def fail(msg: str) -> Any:
        raise ValueError("attestation anchoring (fail closed): %s" % msg)

    required = isinstance(opts, dict) and opts.get("required") is True
    if not isinstance(opts, dict) or not isinstance(opts.get("ledger"), TransparencyLedger):
        return fail("no transparency ledger available")
    secret = opts.get("guardianSecret")
    has_key = isinstance(secret, (bytes, bytearray))
    if required and not has_key:
        return fail("required anchoring needs a guardian secret to sign the tree head")
    ledger = opts["ledger"]
    commit = attestation_evidence_digest(ev)
    prev_root = ledger.head()["root"]
    index = ledger.append_commitment(commit)["index"]
    head = ledger.head()
    sth = None
    if has_key:
        now = (opts.get("now") or (lambda: int(time.time() * 1000)))()
        try:
            sth = sign_tree_head(KeyPair(bytes(secret), allow_insecure_signer=True),
                                 {"instance_id": opts.get("instanceId") if opts.get("instanceId") is not None else "", "principal": ledger.principal,
                                  "size": head["size"], "root": head["root"], "prev_root": prev_root, "timestamp": now},
                                 (opts.get("suite") or {}).get("alg"), (opts.get("suite") or {}).get("pq"))
        except Exception as e:  # noqa: BLE001
            if required:
                return fail("tree-head signing failed: %s" % _msg(e))
    out: Dict[str, Any] = {"index": index, "commit": commit}
    if sth:
        out["sth"] = sth
    return out
