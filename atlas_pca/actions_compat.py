"""Migration shims between the old, disagreeing action vocabularies and the one ActionDef vocabulary (native port of compat.ts of the
TypeScript reference @atlasauth/pca-actions). Every conversion is total and fails closed."""
from ._fin import fin
import math
import re
from typing import Any, Dict, List, Optional

from .actions import BLAST_PPM, BLAST_RADII, PPM_MAX, REV_RANK
from .intent_wb import _utf16_len


def normalize_reversibility(x: Any) -> str:
    """Any old reversibility word to the canonical class; anything unknown is irreversible (fail closed)."""
    if not isinstance(x, str):
        return "irreversible"
    if x in ("reversible", "read"):
        return "reversible"
    if x in ("rate_limited", "costly"):
        return "rate_limited"
    return "irreversible"


def legacy_operations_class(r: str) -> str:
    """The operations-side word for the revocation staleness table (rate_limited -> costly)."""
    return "costly" if r == "rate_limited" else r


def max_rev_of(a: str, b: str) -> str:
    return a if REV_RANK[a] >= REV_RANK[b] else b


def unit_tag_of(u: dict) -> Optional[dict]:
    """The schema `units` entry / envelope UnitTag of a def's unit; None for a money unit whose currency is a parameter reference."""
    if u["kind"] != "money":
        return {"kind": u["kind"]}
    if not isinstance(u.get("ccy"), str):
        return None
    out = {"kind": "money", "currency": u["ccy"]}
    if "exp" in u:
        out["exponent"] = u["exp"]
    return out


def _js_round(v: float) -> int:
    f = math.floor(v)
    return f + 1 if v - f >= 0.5 else f


def _ppm_of(x: Any) -> int:
    finite = isinstance(x, (int, float)) and not isinstance(x, bool) and fin(x)
    return min(PPM_MAX, max(0, _js_round((x if finite else 1) * 1_000_000)))


def blast_of_float(x: Any) -> dict:
    """The smallest radius whose default covers the float, and the integer ppm."""
    ppm = _ppm_of(x)
    return {"radius": next((r for r in BLAST_RADII if BLAST_PPM[r] >= ppm), "global"), "ppm": ppm}


def blast_exact_of_float(x: Any) -> dict:
    """A legacy float kept exactly: the largest radius whose default does not exceed it, the ppm override carrying the exact value."""
    ppm = _ppm_of(x)
    return {"radius": next((r for r in reversed(BLAST_RADII) if BLAST_PPM[r] <= ppm), "one"), "ppm": ppm}


_READ_RE = re.compile(r"(?:read|get|list|view|search|fetch|head)(?:_|\Z)")
_DELETE_RE = re.compile(r"(?:\A|_)(?:delete|remove|destroy|drop|purge)(?:_|\Z)")
_SEND_RE = re.compile(r"(?:\A|_)(?:send|post|publish|notify|email|sms)(?:_|\Z)")


def from_catalog_spec(s: dict, o: Optional[dict] = None) -> dict:
    """Convert an old catalog entry: effects inferred conservatively from the action name (an unknown write is `update`, never `read`);
    an amountField becomes a bounded money.amount parameter; the result is `authored`. o: {ccy, exp, maxAmount}."""
    o = o or {}
    has_amount = "amountField" in s
    effects: List[str] = []
    if has_amount:
        effects.append("pay")
    if _READ_RE.match(s["action"]):
        effects.append("read")
    if _DELETE_RE.search(s["action"]):
        effects.append("delete")
    if _SEND_RE.search(s["action"]):
        effects.append("send")
    if not effects:
        effects.append("update")
    params: Dict[str, Any] = {}
    if has_amount:
        params[s["amountField"]] = {
            "type": "integer", "role": "money.amount", "min": 0, "max": o["maxAmount"] if o.get("maxAmount") is not None else 100_000_000_000,
            "unit": {"kind": "money", "ccy": o["ccy"] if o.get("ccy") is not None else "USD", "exp": o["exp"] if o.get("exp") is not None else 2},
        }
        params["idempotency_key"] = {"type": "string", "max_len": 128}
    b = blast_of_float(s["blastRadius"])
    wildcard = "resource" not in s or s["resource"] == "*"
    desc = s["description"]
    title = (desc.encode("utf-16-le", "surrogatepass")[:117 * 2].decode("utf-16-le", "surrogatepass") + "...") if _utf16_len(desc) > 120 else desc
    out: Dict[str, Any] = {
        "v": 1, "kind": "pca-action-def", "verb": s["verb"], "title": title, "description": desc, "effects": effects,
        "resource": {"type": s["connector"], "id": "*" if wildcard else {"prefix": "", "class": "any_safe", "len": [1, 128]}, "scope": "set" if wildcard else "one"},
        "params": params, "reversibility": normalize_reversibility(s["reversibility"]), "blast": {"radius": b["radius"], "ppm": b["ppm"]},
    }
    if has_amount:
        out["idempotency"] = {"mode": "key_param", "param": "idempotency_key"}
    out["review"] = {"state": "authored"}
    return out


def from_catalog(specs: List[dict], o: Optional[dict] = None) -> List[dict]:
    return [from_catalog_spec(s, o) for s in specs]
