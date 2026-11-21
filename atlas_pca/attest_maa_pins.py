"""The built-in, release-signed pins for the Azure MAA token-signing keys: the offline root of the first accepted key set. A signed allowlist manifest
(shipped with the package, verified against the release issuer key embedded here) carries the pins of the self-signed per-instance keys, the pins of the
Microsoft chain root and of the attestation intermediate that chained keys must pass through, and a signed corroboration record of how many independent
network vantages saw identical key material (at least 3). A port of the reference ``attest-maa-pins`` module. The pins expire and cannot be rolled back
below the shipped version floor (fail closed); a compromised release key, or an attacker who controlled every vantage at signing time, defeats them."""
from __future__ import annotations

import copy
import re
from typing import Any, Dict, Optional

from . import _maa_pins_data as _D
from .attest_allowlist import _safe_int, project_allowlist, verify_allowlist_manifest

__all__ = ["BUILTIN_CHAIN_LEAF_CN", "BUILTIN_MAA_PINS_ISSUER_ID", "BUILTIN_MAA_PINS_ISSUER_KEYS", "load_builtin_maa_pins"]

BUILTIN_CHAIN_LEAF_CN = ("Microsoft Azure Attestation 2020",)
BUILTIN_MAA_PINS_ISSUER_ID = _D.BUILTIN_PINS_ISSUER_ID
BUILTIN_MAA_PINS_ISSUER_KEYS = {_D.BUILTIN_PINS_ISSUER_ID: _D.BUILTIN_PINS_ISSUER_KEY}

_MAX_LIFETIME_MS = 400 * 24 * 3_600_000
_MIN_VANTAGES = 3
_CORROBORATION = re.compile(r"vantages=([0-9]+);method=([^\n\r  ]*)")  # `.` of the reference: no line terminator
_default: Dict[str, Any] = {}


def _evaluate(src: dict, now_ms: Any) -> Dict[str, Any]:
    # signature and structure are checked at a time inside the window; the window itself is re-checked on every call
    man = src.get("manifest")
    body = man.get("body") if isinstance(man, dict) else None
    nb = body.get("notBefore") if isinstance(body, dict) else None
    v0 = verify_allowlist_manifest(man, {"issuerKeys": src.get("issuerKeys"), "nowMs": now_ms if nb is None else nb,
                                         "minVersion": 1 if src.get("minVersion") is None else src["minVersion"], "maxLifetimeMs": _MAX_LIFETIME_MS})
    if not v0["ok"]:
        return {"ok": False, "reason": "%s: %s" % (v0["code"], v0["reason"])}
    p = project_allowlist(v0, v0["body"]["notBefore"])
    corr = p["corroboration"]
    if len(corr) != 1:
        return {"ok": False, "reason": "manifest must carry exactly one attest-corroboration entry"}
    m = _CORROBORATION.fullmatch(corr[0]["label"])
    vantages = int(m.group(1)) if m else 0
    if not m or vantages < _MIN_VANTAGES:
        return {"ok": False, "reason": "corroboration records %d vantages < required %d" % (vantages, _MIN_VANTAGES)}
    if not p["maaSigningSpkis"]:
        return {"ok": False, "reason": "manifest pins no MAA signing key"}
    if not p["maaChainRootSpkis"] or not p["maaChainIntermediateSpkis"]:
        return {"ok": False, "reason": "manifest lacks the Microsoft chain root / intermediate pins"}
    revoked: Dict[str, list] = {}
    for r in p["revoked"]:
        if r["kind"] == "maa-signing-spki":
            revoked.setdefault(r["label"], []).append(r["value"])
    return {"ok": True, "notBefore": v0["body"]["notBefore"], "expiresAt": v0["body"]["expiresAt"],
            "value": {"ok": True, "version": v0["version"], "digest": v0["digest"], "expiresAt": v0["body"]["expiresAt"],
                      "maaSigningSpkis": p["maaSigningSpkis"], "revokedSigningSpkis": revoked, "maaChainRootSpkis": p["maaChainRootSpkis"],
                      "maaChainIntermediateSpkis": p["maaChainIntermediateSpkis"], "vantages": vantages, "method": m.group(2)}}


def load_builtin_maa_pins(opts: dict) -> Dict[str, Any]:
    """Load and verify the built-in pin set at ``opts["nowMs"]``: ``{"ok": True, version, digest, expiresAt, maaSigningSpkis, revokedSigningSpkis,
    maaChainRootSpkis, maaChainIntermediateSpkis, vantages, method}`` or ``{"ok": False, "reason"}``. ``opts["source"]`` (``{manifest, issuerKeys,
    minVersion?}``) substitutes another signed pin source. Never raises. The signature check of the shipped manifest is memoised."""
    try:
        now_ms = opts.get("nowMs")
        if not _safe_int(now_ms):
            return {"ok": False, "reason": "nowMs must be an integer"}
        source = opts.get("source")
        if source is not None:
            r: Optional[Dict[str, Any]] = _evaluate(source, now_ms)
        else:
            if "r" not in _default:
                _default["r"] = _evaluate({"manifest": _D.BUILTIN_PINS_MANIFEST, "issuerKeys": BUILTIN_MAA_PINS_ISSUER_KEYS,
                                           "minVersion": _D.BUILTIN_PINS_MIN_VERSION}, now_ms)
            r = _default["r"]
        if not r["ok"]:
            return r
        if now_ms < r["notBefore"]:
            return {"ok": False, "reason": "built-in pins are not yet valid (clock behind the release)"}
        if now_ms > r["expiresAt"]:
            return {"ok": False, "reason": "built-in pins expired; update the package or pass explicit initialPins"}
        return copy.deepcopy(r["value"])
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "reason": str(e) or "built-in pins error"}
