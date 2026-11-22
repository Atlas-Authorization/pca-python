"""Rotation-safe trust in Azure MAA token-signing keys. ``evaluate_maa_jwks`` validates every key of a ``<issuer>/certs`` JWKS (a self-signed instance
certificate must carry exactly ``CN=<issuer URL>``, be genuinely self-signed, inside its window and not older than ``maxKeyAgeMs``; a Microsoft-chained
key is used only through a pinned chain root and, when pinned, a pinned intermediate), ``create_maa_key_trust`` derives the anchors a MAA verifier needs
under an explicit rotation policy (the built-in release-signed pins as the baseline, at most ``maxNewKeysPerFetch`` unseen keys per fetch, overlap with
the previous set, an operator-signed re-pin manifest to approve or revoke keys, a TTL cache with bounded staleness, a monotone persisted state) and
``corroborate_maa_key_sets`` accepts a first-use set only when k distinct vantages saw the identical keys. A port of the reference ``attest-maa-keys``
module. The network is an INJECTED ``fetch(url, init) -> {"status", "url"?, "headers"?, "body": bytes}`` (init: ``redirect`` "error", ``headers``,
``timeoutMs``); shortcut: the timeout is passed to the transport, not enforced here, add a watchdog if a transport cannot honour it."""
from __future__ import annotations

import copy
import json
import math
import re
from typing import Any, Callable, Dict, List, Optional

from ._fin import fin
from .attest_allowlist import _safe_int, project_allowlist, verify_allowlist_manifest
from .attest_cert import Cert
from .attest_common import key_type, node_b64decode, node_curve, rsa_key_ok, spki_sha
from .attest_der import der_validity_ms, strict_chain_error
from .attest_maa_pins import BUILTIN_CHAIN_LEAF_CN, load_builtin_maa_pins

__all__ = ["create_memory_maa_key_state_store", "durable_maa_key_state_store", "fetch_maa_certs", "evaluate_maa_jwks", "create_maa_key_trust",
           "corroborate_maa_key_sets"]

_HOUR = 3_600_000
_DAY = 24 * _HOUR
_ISSUER_URL = re.compile(r"https://[a-z0-9]([a-z0-9.-]*[a-z0-9])?(:[0-9]{1,5})?")
_HEX64 = re.compile(r"[0-9a-f]{64}")
_MAX_JWKS_KEYS = 32
_MAX_X5C = 8
_MAX_X5C_B64 = 131_072
_EC_CURVES = ("prime256v1", "secp384r1", "secp521r1")
_KINDS = ("self-signed", "chained-root", "chained-intermediate")


def _issuer_ok(x: Any) -> bool:
    return isinstance(x, str) and _ISSUER_URL.fullmatch(x) is not None


def _u16len(s: str) -> int:
    return len(s.encode("utf-16-le")) // 2


def _msg(e: BaseException, default: str) -> str:
    return str(e) or default


class _MemoryStore:
    def __init__(self) -> None:
        self._m: Dict[str, Any] = {}

    def get(self, issuer: str) -> Any:
        return self._m.get(issuer)

    def set(self, issuer: str, state: Any) -> None:
        self._m[issuer] = copy.deepcopy(state)

    def snapshot(self) -> Dict[str, Any]:
        return dict(self._m)


def create_memory_maa_key_state_store() -> _MemoryStore:
    """An in-memory key-state store (``get(issuer)``: the state or None, ``set(issuer, state)``, ``snapshot()``): tests / a single process."""
    return _MemoryStore()


def _no_neg_zero(n: Any) -> bool:
    return not (isinstance(n, float) and n == 0 and math.copysign(1, n) < 0)


def _parse_state(x: Any, issuer: str) -> Optional[Dict[str, Any]]:
    if not isinstance(x, dict) or x.get("v") != 1 or isinstance(x.get("v"), bool) or x.get("issuer") != issuer:
        return None
    f = x.get("fetchedAtMs")
    if not _safe_int(f) or not _no_neg_zero(f) or not isinstance(x.get("anchors"), list):
        return None
    anchors: List[Dict[str, Any]] = []
    for a in x["anchors"]:
        if not isinstance(a, dict) or not isinstance(a.get("spki"), str) or _HEX64.fullmatch(a["spki"]) is None or a.get("kind") not in _KINDS:
            return None
        if not all(_safe_int(a.get(k)) and _no_neg_zero(a.get(k)) for k in ("notBeforeMs", "notAfterMs", "firstSeenMs")):
            return None
        anchors.append({"spki": a["spki"], "kind": a["kind"], "notBeforeMs": a["notBeforeMs"], "notAfterMs": a["notAfterMs"], "firstSeenMs": a["firstSeenMs"]})
    return {"v": 1, "issuer": issuer, "fetchedAtMs": f, "anchors": anchors}


class _DurableStore:
    def __init__(self, kv: Any) -> None:
        self._kv = kv

    @staticmethod
    def _k(issuer: str) -> str:
        return "maa-keys/%s" % issuer

    def get(self, issuer: str) -> Any:
        return self._kv.get(self._k(issuer))

    def set(self, issuer: str, state: Any) -> None:
        def update(prev: Any) -> Any:
            p = None if prev is None else _parse_state(prev, issuer)
            return None if p and p["fetchedAtMs"] > state["fetchedAtMs"] else state  # monotone: a stale writer never moves the state back
        self._kv.update(self._k(issuer), update)


def durable_maa_key_state_store(kv: Any) -> _DurableStore:
    """Persist the accepted key sets in a durable key/value store (``get`` / ``update``), atomically and MONOTONE in ``fetchedAtMs``. A corrupt stored
    record is returned as-is, so the trust store fails closed (``corrupt-state``)."""
    return _DurableStore(kv)


# ---- guarded fetch ----

def _parse_jwks(x: Any) -> Dict[str, Any]:
    if not isinstance(x, dict) or not isinstance(x.get("keys"), list):
        raise ValueError("MAA certs: response has no keys array")
    raw = x["keys"]
    if len(raw) > _MAX_JWKS_KEYS:
        raise ValueError("MAA certs: too many keys")
    keys = []
    for k in raw:
        if not isinstance(k, (dict, list)):
            raise ValueError("MAA certs: malformed key entry")
        r = k if isinstance(k, dict) else {}
        x5c = r.get("x5c")
        if not isinstance(x5c, list) or not x5c or len(x5c) > _MAX_X5C or any(not isinstance(c, str) or not c or _u16len(c) > _MAX_X5C_B64 for c in x5c):
            raise ValueError("MAA certs: key without a well-formed x5c")
        key: Dict[str, Any] = {}
        for m in ("kid", "kty", "alg"):
            if isinstance(r.get(m), str):
                key[m] = r[m]
        key["x5c"] = list(x5c)
        keys.append(key)
    return {"keys": keys}


def _no_constant(name: str) -> Any:
    raise ValueError("bad JSON constant %s" % name)


def fetch_maa_certs(issuer: str, opts: dict) -> Dict[str, Any]:
    """Fetch ``<issuer>/certs`` over the injected transport: HTTPS issuers only, no redirects (a response URL that differs refuses), a declared or
    actual body over ``maxBytes`` (default 1 MiB) refuses, strict UTF-8 JSON. Returns ``{"keys": [{kid?, kty?, alg?, x5c}]}`` (at most 32 keys, 8
    certificates each); RAISES on any problem."""
    fetch = opts.get("fetch") if isinstance(opts, dict) else None
    if not callable(fetch):
        raise TypeError("fetchMaaCerts: a fetch implementation must be injected")
    if not _issuer_ok(issuer):
        raise TypeError("fetchMaaCerts: issuer must be an https origin URL (no path, no trailing slash)")
    timeout_ms = 10_000 if opts.get("timeoutMs") is None else opts["timeoutMs"]
    max_bytes = 1_048_576 if opts.get("maxBytes") is None else opts["maxBytes"]
    url = "%s/certs" % issuer
    res = fetch(url, {"redirect": "error", "headers": {"accept": "application/json"}, "timeoutMs": timeout_ms})
    status = res.get("status")
    if not (isinstance(status, int) and 200 <= status < 300):
        raise RuntimeError("MAA certs fetch failed: HTTP %s" % status)
    if res.get("url") and res["url"] != url:
        raise RuntimeError("MAA certs fetch: response URL differs from the request (redirect)")
    hv = (res.get("headers") or {}).get("content-length")
    try:
        declared = 0.0 if hv is None or str(hv).strip() == "" else float(str(hv).strip())
    except ValueError:
        declared = math.nan
    if fin(declared) and declared > max_bytes:
        raise RuntimeError("MAA certs response exceeds the size limit")
    body = bytes(res.get("body") or b"")
    if len(body) > max_bytes:
        raise RuntimeError("MAA certs response exceeds the size limit")
    try:
        text = body.decode("utf-8")
        parsed = json.loads(text[1:] if text.startswith("﻿") else text, parse_constant=_no_constant)  # a fatal TextDecoder drops one BOM
    except ValueError:
        raise RuntimeError("MAA certs response is not valid UTF-8 JSON") from None
    return _parse_jwks(parsed)


# ---- JWKS evaluation ----

def _sole_cn(subject: str) -> Optional[str]:
    lines = [l for l in subject.split("\n") if l]
    if len(lines) != 1:
        return None
    return lines[0][3:] if lines[0].startswith("CN=") else None


def _leaf_cn(subject: str) -> Optional[str]:
    for l in subject.split("\n"):
        if l.startswith("CN="):
            return l[3:]
    return None


def _key_strength_error(c: Cert) -> Optional[str]:
    pk = c.public_key
    t = key_type(pk)
    if t == "rsa":
        bits = pk.key_size
        if not (2048 <= bits <= 8192):
            return "RSA key size %d outside 2048..8192" % bits
        return None if rsa_key_ok(pk) else "RSA public exponent must be odd, at least 3 and at most 32 bits"
    if t == "ec":
        curve = node_curve(pk) or ""
        return None if curve in _EC_CURVES else "EC curve '%s' not allowed" % curve
    return "key type '%s' not allowed" % t


def _safe_verify(c: Cert, k: Any) -> bool:
    try:
        return (key_type(k) not in ("rsa", "rsa-pss") or rsa_key_ok(k)) and c.verify(k)
    except Exception:  # noqa: BLE001
        return False


def _spki(c: Cert) -> str:
    return spki_sha(c.public_key, "sha256")


def _validity(c: Cert) -> tuple:
    return der_validity_ms(c.raw)


def evaluate_maa_jwks(jwks: Any, issuer: str, policy: dict, now_ms: Any) -> Dict[str, Any]:
    """Validate every key of a JWKS against the policy at ``now_ms``: ``{"accepted": [{spki, kind, notBeforeMs, notAfterMs}], "rejected": [{kid,
    reason}]}``. A reason that starts ``error:`` is the certificate reader's own text. Never raises for a bad key."""
    skew = 60_000 if policy.get("clockSkewMs") is None else policy["clockSkewMs"]
    max_age = 400 * _DAY if policy.get("maxKeyAgeMs") is None else policy["maxKeyAgeMs"]
    roots = {s.lower() for s in policy.get("chainRootSpkiSha256") or []}
    inters = {s.lower() for s in policy.get("chainIntermediateSpkiSha256") or []}
    accepted: Dict[str, Dict[str, Any]] = {}
    rejected: List[Dict[str, Any]] = []
    for i, key in enumerate((jwks or {}).get("keys") or []):
        kid = key.get("kid") if key.get("kid") is not None else "#%d" % i
        try:
            x5c = key.get("x5c")
            if not isinstance(x5c, list) or not x5c:
                rejected.append({"kid": kid, "reason": "no x5c"})
                continue
            certs = [Cert(node_b64decode(b)) for b in x5c]
            leaf = certs[0]
            for j, c in enumerate(certs):
                lo, hi = _validity(c)
                if lo is None or hi is None:
                    raise ValueError("cert %d: unparsable validity" % j)
                if not (fin(now_ms, skew) and now_ms + skew >= lo):
                    raise ValueError("cert %d: not yet valid" % j)
                if not (now_ms - skew <= hi):
                    raise ValueError("cert %d: expired" % j)
            lv_from, lv_to = _validity(leaf)
            strength = _key_strength_error(leaf)
            if strength:
                raise ValueError(strength)
            if len(certs) == 1:
                if not (now_ms - lv_from <= max_age):
                    raise ValueError("key older than maxKeyAgeMs")
                cn = _sole_cn(leaf.subject)
                if cn is None:
                    raise ValueError("subject is not a single CN")
                if "*" in cn:
                    raise ValueError("wildcard CN rejected")
                if cn != issuer:
                    raise ValueError("subject CN does not equal the issuer URL")
                if leaf.issuer != leaf.subject or not _safe_verify(leaf, leaf.public_key):
                    raise ValueError("not a genuine self-signed cert")
                spki = _spki(leaf)
                accepted[spki] = {"spki": spki, "kind": "self-signed", "notBeforeMs": lv_from, "notAfterMs": lv_to}
                continue
            # a chained key: only under an explicitly pinned root (and, when configured, a pinned intermediate)
            if not roots:
                raise ValueError("chained key ignored (no chainRootSpkiSha256 configured)")
            for j in range(len(certs) - 1):
                if not _safe_verify(certs[j], certs[j + 1].public_key):
                    raise ValueError("chain link %d is not signed by the next cert" % j)
            profile = strict_chain_error([c.raw for c in certs])
            if profile:
                raise ValueError("chain profile: %s" % profile)
            top = certs[-1]
            if top.issuer != top.subject or not _safe_verify(top, top.public_key):
                raise ValueError("chain does not end in a self-signed root")
            root_spki = _spki(top)
            if root_spki not in roots:
                raise ValueError("chain root is not pinned")
            if policy.get("chainLeafCn") is not None and (_leaf_cn(leaf.subject) or "\u0000") not in policy["chainLeafCn"]:
                raise ValueError("chained leaf CN not allowed")
            anchor_spki, anchor_kind = root_spki, "chained-root"
            anchor_from, anchor_to = _validity(top)
            if inters:
                # the pinned intermediate must sit strictly between leaf and root; it (not the shared root) becomes the anchor
                mid = next((c for c in certs[1:-1] if _spki(c) in inters), None)
                if mid is None:
                    raise ValueError("chain does not pass through a pinned intermediate")
                anchor_spki, anchor_kind = _spki(mid), "chained-intermediate"
                anchor_from, anchor_to = _validity(mid)
            prev = accepted.get(anchor_spki)
            accepted[anchor_spki] = {"spki": anchor_spki, "kind": anchor_kind,
                                     "notBeforeMs": min(prev["notBeforeMs"], anchor_from) if prev else anchor_from,
                                     "notAfterMs": min(anchor_to, max(prev["notAfterMs"] if prev else 0, lv_to))}
        except Exception as e:  # noqa: BLE001
            rejected.append({"kid": kid, "reason": _msg(e, "invalid key")})
    return {"accepted": list(accepted.values()), "rejected": rejected}


# ---- trust store ----

def create_maa_key_trust(opts: dict) -> Any:
    """A key trust over ``opts`` = ``{"policy", "store", "fetch"}``: ``get_trust_anchors(issuer, {"nowMs", "repin"?}) -> {"ok": True, trustAnchors:
    {rootSpkiSha256}, source, anchors, newKeys, removedKeys, rejected}`` or ``{"ok": False, code, reason}`` (codes untrusted-issuer, corrupt-state,
    clock-regression, fetch-failed, stale-exceeded, no-valid-keys, no-baseline, too-many-new-keys, no-overlap, repin-invalid, builtin-pins-invalid).
    Network access happens only inside ``get_trust_anchors``. Policy: see the reference ``MaaKeyPolicy`` (trustedIssuers, ttlMs, maxStaleMs,
    maxNewKeysPerFetch, maxInitialKeys, maxKeyAgeMs, requireOverlap, allowTrustOnFirstUse, initialPins, chainRootSpkiSha256,
    chainIntermediateSpkiSha256, chainLeafCn, builtinPins, clockSkewMs, fetchTimeoutMs, maxBodyBytes). Construction refusals raise TypeError."""
    policy = copy.deepcopy(opts.get("policy")) if isinstance(opts, dict) else None  # freeze the policy: later edits must not change what is enforced
    store, fetch = opts.get("store"), opts.get("fetch")
    if not callable(fetch):
        raise TypeError("createMaaKeyTrust: fetch must be injected")
    ti = policy.get("trustedIssuers") if isinstance(policy, dict) else None
    if not isinstance(ti, list) or not ti or any(not _issuer_ok(i) for i in ti):
        raise TypeError("createMaaKeyTrust: policy.trustedIssuers must be a non-empty list of https origin URLs")
    trusted = set(ti)

    def _num(k: str, d: Any) -> Any:
        return d if policy.get(k) is None else policy[k]
    ttl, max_stale = _num("ttlMs", _HOUR), _num("maxStaleMs", _DAY)
    max_new, max_initial = _num("maxNewKeysPerFetch", 2), _num("maxInitialKeys", 8)
    skew, require_overlap = _num("clockSkewMs", 60_000), _num("requireOverlap", True)
    # an infinite or NaN window would admit every expired key or stale cache; a count or max-stale may be +Infinity (no cap) but never NaN
    def _isnum(v: Any) -> bool:
        return isinstance(v, (int, float)) and not isinstance(v, bool)
    if not (_isnum(ttl) and math.isfinite(ttl) and _isnum(skew) and math.isfinite(skew)) \
            or any(not _isnum(v) or v != v for v in (max_stale, max_new, max_initial)):
        raise TypeError("createMaaKeyTrust: ttlMs and clockSkewMs must be finite; maxStaleMs and the key-count limits must not be NaN")

    def fail(code: str, reason: str) -> Dict[str, Any]:
        return {"ok": False, "code": code, "reason": reason}

    def live(a: list, now_ms: Any) -> list:
        return [r for r in a if fin(now_ms, skew) and now_ms - skew <= r["notAfterMs"] and now_ms + skew >= r["notBeforeMs"]]

    def build(source: str, anchors: list, new_keys: list, removed: list, rejected: list) -> Dict[str, Any]:
        spkis = sorted({a["spki"] for a in anchors})
        if not spkis:
            return fail("no-valid-keys", "no unexpired, un-revoked signing keys remain")
        return {"ok": True, "trustAnchors": {"rootSpkiSha256": spkis}, "source": source, "anchors": anchors, "newKeys": new_keys,
                "removedKeys": removed, "rejected": rejected}

    class _Trust:
        @staticmethod
        def get_trust_anchors(issuer: Any, call: dict) -> Dict[str, Any]:
            now_ms, repin = call.get("nowMs"), call.get("repin")
            try:
                if issuer not in trusted:
                    return fail("untrusted-issuer", "issuer is not in policy.trustedIssuers")
                if not _safe_int(now_ms):
                    return fail("clock-regression", "nowMs must be an integer")
                # operator approvals / revocations (the re-pin manifest)
                approved: set = set()
                denied: set = set()
                if repin:
                    v = verify_allowlist_manifest(repin.get("manifest"), dict(repin.get("verify") or {}, nowMs=now_ms))
                    if not v["ok"]:
                        return fail("repin-invalid", "%s: %s" % (v["code"], v["reason"]))
                    p = project_allowlist(v, now_ms)
                    approved = set(p["maaSigningSpkis"].get(issuer) or [])
                    denied = {r["value"] for r in p["revoked"] if r["kind"] == "maa-signing-spki" and r["label"] == issuer}
                # the built-in release-signed pins (default on): the offline root of the first accepted set
                eff = policy
                builtin_baseline: List[str] = []
                builtin_reason: Optional[str] = None
                if policy.get("builtinPins") is not False:
                    lo: Dict[str, Any] = {"nowMs": now_ms}
                    if isinstance(policy.get("builtinPins"), dict):
                        lo["source"] = policy["builtinPins"]
                    b = load_builtin_maa_pins(lo)
                    if b["ok"]:
                        builtin_baseline = list(b["maaSigningSpkis"].get(issuer) or [])
                        denied.update(b["revokedSigningSpkis"].get(issuer) or [])
                        eff = dict(policy)
                        eff["chainRootSpkiSha256"] = b["maaChainRootSpkis"] if policy.get("chainRootSpkiSha256") is None else policy["chainRootSpkiSha256"]
                        eff["chainIntermediateSpkiSha256"] = (b["maaChainIntermediateSpkis"] if policy.get("chainIntermediateSpkiSha256") is None
                                                              else policy["chainIntermediateSpkiSha256"])
                        eff["chainLeafCn"] = list(BUILTIN_CHAIN_LEAF_CN) if policy.get("chainLeafCn") is None else policy["chainLeafCn"]
                        # the pinned Microsoft intermediate only counts for issuers the release actually pinned
                        if builtin_baseline:
                            builtin_baseline = builtin_baseline + list(b["maaChainIntermediateSpkis"])
                    else:
                        builtin_reason = b["reason"]

                def allow(a: list) -> list:
                    return [r for r in a if r["spki"] not in denied]

                raw_state = store.get(issuer)
                state: Optional[Dict[str, Any]] = None
                if raw_state is not None:
                    state = _parse_state(raw_state, issuer)
                    if state is None:
                        return fail("corrupt-state", "persisted MAA key state failed validation")
                    if not (now_ms >= state["fetchedAtMs"] - skew):
                        return fail("clock-regression", "clock is behind the last persisted fetch time")
                # 1. a fresh cache
                if state and now_ms - state["fetchedAtMs"] < ttl and now_ms >= state["fetchedAtMs"]:
                    a = allow(live(state["anchors"], now_ms))
                    if a:
                        return build("cache", a, [], [], [])
                # 2. refresh
                try:
                    fo: Dict[str, Any] = {"fetch": fetch}
                    if policy.get("fetchTimeoutMs") is not None:
                        fo["timeoutMs"] = policy["fetchTimeoutMs"]
                    if policy.get("maxBodyBytes") is not None:
                        fo["maxBytes"] = policy["maxBodyBytes"]
                    jwks = fetch_maa_certs(issuer, fo)
                except Exception as e:  # noqa: BLE001
                    why = _msg(e, "fetch error")
                    if state is None:
                        return fail("fetch-failed", "%s; no cached key set" % why)
                    if not (now_ms - state["fetchedAtMs"] <= max_stale):
                        return fail("stale-exceeded", "%s; cached set is older than maxStaleMs" % why)
                    a = allow(live(state["anchors"], now_ms))
                    if not a:
                        return fail("stale-exceeded", "%s; every cached key has expired or been revoked" % why)
                    return build("stale-cache", a, [], [], [])
                ev = evaluate_maa_jwks(jwks, issuer, eff, now_ms)
                accepted = [r for r in ev["accepted"] if r["spki"] not in denied]
                if not accepted:
                    detail = "; ".join("%s: %s" % (r["kid"], r["reason"]) for r in ev["rejected"]) or "empty JWKS"
                    return fail("no-valid-keys", "no JWKS key passed validation (%s)" % detail)
                # 3. the rotation policy
                prev = live(state["anchors"], now_ms) if state else []
                baseline: Dict[str, None] = dict.fromkeys(a["spki"] for a in prev)
                if not state:
                    for pin in (policy.get("initialPins") or {}).get(issuer) or []:
                        baseline[pin.lower()] = None
                    for pin in builtin_baseline:
                        baseline[pin] = None
                approved.update(builtin_baseline)
                accepted_set = list(dict.fromkeys(a["spki"] for a in accepted))
                approved_here = [s for s in accepted_set if s in approved]
                unapproved_new = [s for s in accepted_set if s not in baseline and s not in approved]
                if not baseline:
                    if not approved_here and not policy.get("allowTrustOnFirstUse"):
                        if builtin_reason is not None:
                            return fail("builtin-pins-invalid", "built-in pins unusable (%s); no persisted state, no initialPins, no signed re-pin; "
                                                                "refusing trust-on-first-use" % builtin_reason)
                        return fail("no-baseline", "no persisted state, no built-in pin for this issuer, no initialPins and no signed re-pin: "
                                                   "refusing trust-on-first-use")
                    if len(accepted_set) > max_initial and len(approved_here) < len(accepted_set):
                        return fail("too-many-new-keys", "initial set of %d keys exceeds maxInitialKeys" % len(accepted_set))
                else:
                    if len(unapproved_new) > max_new:
                        return fail("too-many-new-keys", "%d new keys exceed maxNewKeysPerFetch=%s" % (len(unapproved_new), _js_num(max_new)))
                    overlap = any(s in baseline for s in accepted_set) or bool(approved_here)
                    if require_overlap and not overlap:
                        return fail("no-overlap", "the new key set shares no key with the previous set and is not covered by a signed re-pin")
                # 4. persist (monotone fetchedAtMs) and return
                first_seen = {a["spki"]: a["firstSeenMs"] for a in (state["anchors"] if state else [])}
                records = [dict(a, firstSeenMs=first_seen.get(a["spki"], now_ms)) for a in accepted]
                fetched_at = max(state["fetchedAtMs"], now_ms) if state else now_ms
                store.set(issuer, {"v": 1, "issuer": issuer, "fetchedAtMs": fetched_at, "anchors": records})
                new_keys = [r["spki"] for r in records if r["spki"] not in baseline]
                removed = [s for s in baseline if s not in accepted_set]
                return build("fetched", records, new_keys, removed, ev["rejected"])
            except Exception as e:  # noqa: BLE001
                return fail("fetch-failed", _msg(e, "unexpected error"))

    return _Trust()


def _js_num(n: Any) -> str:
    return str(int(n)) if isinstance(n, (int, float)) and not isinstance(n, bool) and n == math.floor(n) else str(n)


# ---- multi-vantage corroboration ----

def corroborate_maa_key_sets(sets: Any, k: Any, opts: dict) -> Dict[str, Any]:
    """Accept a FIRST-USE key set only if at least ``k`` (>= 2) DISTINCT vantages observed the issuer and ALL observations validate to the IDENTICAL SPKI
    set: ``{"ok": True, issuer, spkis, vantages, k}`` or ``{"ok": False, code, reason}`` (malformed, insufficient-vantages, vantage-disagreement,
    no-valid-keys). ``sets`` = ``[{"vantage", "issuer", "jwks"}]``; ``opts`` = ``{"issuer", "nowMs", "policy"?}``. Independence is the caller's
    claim, not proven here."""
    def bad(code: str, reason: str) -> Dict[str, Any]:
        return {"ok": False, "code": code, "reason": reason}
    try:
        if not _safe_int(k) or k < 2:
            return bad("malformed", "k must be an integer >= 2")
        issuer = opts.get("issuer") if isinstance(opts, dict) else None
        if not _issuer_ok(issuer) or not _safe_int(opts.get("nowMs")):
            return bad("malformed", "issuer/nowMs invalid")
        if not isinstance(sets, list):
            return bad("malformed", "sets must be an array")
        policy = dict({"trustedIssuers": [issuer]}, **(opts.get("policy") or {}))
        by_vantage: Dict[str, str] = {}
        for o in sets:
            v = o.get("vantage") if isinstance(o, dict) else None
            if not isinstance(v, str) or not v or _u16len(v) > 100:
                return bad("malformed", "vantage label must be a non-empty string")
            if o.get("issuer") != issuer:
                return bad("malformed", "observation from '%s' is for a different issuer" % v)
            ev = evaluate_maa_jwks(o.get("jwks"), issuer, policy, opts["nowMs"])
            if not ev["accepted"]:
                return bad("no-valid-keys", "vantage '%s' observed no valid key (%s)" % (v, "; ".join(r["reason"] for r in ev["rejected"]) or "empty"))
            fp = ",".join(sorted(a["spki"] for a in ev["accepted"]))
            if v in by_vantage and by_vantage[v] != fp:
                return bad("vantage-disagreement", "vantage '%s' supplied two different key sets" % v)
            by_vantage[v] = fp
        if len(by_vantage) < k:
            return bad("insufficient-vantages", "%d distinct vantage(s) < k=%s" % (len(by_vantage), _js_num(k)))
        distinct = list(dict.fromkeys(by_vantage.values()))
        if len(distinct) != 1:
            return bad("vantage-disagreement", "vantages disagree: %s" % " | ".join(
                "%s=%s" % (v, "+".join(x[:8] for x in f.split(","))) for v, f in by_vantage.items()))
        return {"ok": True, "issuer": issuer, "spkis": distinct[0].split(","), "vantages": sorted(by_vantage), "k": k}
    except Exception as e:  # noqa: BLE001
        return bad("malformed", _msg(e, "corroboration error"))
