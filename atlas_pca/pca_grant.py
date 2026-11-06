"""The ``pca_grant`` OAuth authorization-details type (RFC 9396): validation and the resource-server presentation check.
A pointer to a PCA grant, not authority: the per-action PCActn is still required. Total functions; no signatures verified here.

Detail: ``{type: "pca_grant", chain_digest, chain_len, chain_ref?, bundle_revision?, locations?}``. Results are
``{"ok": True, ...}`` / ``{"ok": False, "code": ...}`` and ``{"allow": True, "index": i}`` / ``{"allow": False, "code": ...}``."""
from typing import Any, Dict, List, Sequence

from .pca import decode_b64u_strict, hash_canonical

PCA_GRANT_TYPE = "pca_grant"
PCA_GRANT_DOMAIN = "atlas-pca/pca-grant-chain/v1"
MAX_DETAILS = 16
MAX_CHAIN_LEN = 16
_MAX_URL = 2048
_MAX_LOCATIONS = 8
_MEMBERS = frozenset(("type", "chain_digest", "chain_len", "chain_ref", "bundle_revision", "locations"))
_REFUSED = frozenset(("actions", "datatypes", "identifier", "privileges"))


def _is_int(x: Any) -> bool:
    return isinstance(x, int) and not isinstance(x, bool)


def is_https_url(u: Any) -> bool:
    if not isinstance(u, str) or len(u) > _MAX_URL or not u.startswith("https://"):
        return False
    if any(ord(c) < 0x21 or ord(c) > 0x7E or c in "#\\" for c in u):
        return False
    rest = u[8:]
    cut = [i for i in (rest.find("/"), rest.find("?")) if i != -1]
    authority = rest[: min(cut)] if cut else rest
    return len(authority) > 0 and "@" not in authority


def chain_digest(cap_ids: Sequence[str]) -> str:
    return hash_canonical({"d": PCA_GRANT_DOMAIN, "ids": list(cap_ids)})


def validate_detail(x: Any) -> Dict[str, Any]:
    if not isinstance(x, dict):
        return {"ok": False, "code": "bad_entry"}
    if x.get("type") != PCA_GRANT_TYPE:
        return {"ok": False, "code": "bad_type"}
    for k in x:
        if k in _REFUSED:
            return {"ok": False, "code": "refused_member"}
        if k not in _MEMBERS:
            return {"ok": False, "code": "unknown_member"}
    d = x.get("chain_digest")
    if not isinstance(d, str) or decode_b64u_strict(d, 32) is None:
        return {"ok": False, "code": "bad_chain_digest"}
    n = x.get("chain_len")
    if not _is_int(n) or n < 1 or n > MAX_CHAIN_LEN:
        return {"ok": False, "code": "bad_chain_len"}
    if "chain_ref" in x and not is_https_url(x["chain_ref"]):
        return {"ok": False, "code": "bad_chain_ref"}
    if "bundle_revision" in x and not (_is_int(x["bundle_revision"]) and x["bundle_revision"] >= 0):
        return {"ok": False, "code": "bad_bundle_revision"}
    if "locations" in x:
        loc = x["locations"]
        if not isinstance(loc, list) or not 0 < len(loc) <= _MAX_LOCATIONS or not all(is_https_url(u) for u in loc):
            return {"ok": False, "code": "bad_locations"}
    return {"ok": True, "detail": x}


def parse_details(arr: Any) -> Dict[str, Any]:
    if not isinstance(arr, list):
        return {"ok": False, "code": "not_an_array"}
    if len(arr) > MAX_DETAILS:
        return {"ok": False, "code": "too_many_details"}
    out: List[Dict[str, Any]] = []
    for e in arr:
        if not isinstance(e, dict) or not isinstance(e.get("type"), str):
            return {"ok": False, "code": "bad_entry"}
        if e["type"] != PCA_GRANT_TYPE:
            continue
        r = validate_detail(e)
        if not r["ok"]:
            return r
        out.append(r["detail"])
    return {"ok": True, "details": out}


def check_presentation(details: Sequence[Dict[str, Any]], resource: str, chain_ids: Sequence[str], proof_verified: Any) -> Dict[str, Any]:
    """Allow only with a verified per-action proof and a detail naming a prefix of the presented chain (and this resource)."""
    if len(details) == 0:
        return {"allow": False, "code": "no_detail"}
    if proof_verified is not True:
        return {"allow": False, "code": "proof_required"}
    reason = "chain_mismatch"
    for i, d in enumerate(details):
        n = d["chain_len"]
        if len(chain_ids) < n or chain_digest(chain_ids[:n]) != d["chain_digest"]:
            continue
        loc = d.get("locations")
        if loc is not None and resource not in loc:
            reason = "wrong_location"
            continue
        return {"allow": True, "index": i}
    return {"allow": False, "code": reason}
