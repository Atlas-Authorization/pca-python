"""Agent blueprints: a fleet ceiling and a group kill (verification side). A blueprint is a signed record by an operator for a
blueprint KEY; an instance is a chain with a hop issued by that key. The verifier keeps the newest record per key
(``BlueprintRegistry``: pinned operators, strictly higher epoch replaces, same epoch with different content is a fork) and gates
a chain with ``check_blueprints`` (status, expiry, depth, link, optional staleness epoch). A non-empty ceiling is evaluated only
by a caller-supplied ``evaluate_ceiling(ceiling, blueprint) -> {"ok": bool, "failed": [...]}``; without one it denies
(``ceiling_unevaluable``), so a native verifier never allows past a ceiling it cannot read. Total: no function raises."""
from typing import Any, Callable, Dict, List, Optional

from .k3 import is_obj, is_str, is_uint, is_one, verify_body

AGENT_BLUEPRINT_DOMAIN = "atlas-pca/agent-blueprint/v1\0"
_MAX_CEILING = 32


def _well_formed(b: Any) -> bool:
    if not is_obj(b) or not is_one(b.get("v")) or not (is_str(b.get("id"), 128) and is_str(b.get("key"), 128) and is_str(b.get("operator"), 128)):
        return False
    if not (is_uint(b.get("epoch")) and is_uint(b.get("issued_at"))) or b.get("status") not in ("active", "disabled"):
        return False
    if "max_depth" in b and not (is_uint(b["max_depth"]) and b["max_depth"] >= 1):
        return False
    if "expires_at" in b and not is_uint(b["expires_at"]):
        return False
    c = b.get("ceiling")
    return isinstance(c, list) and len(c) <= _MAX_CEILING and all(is_obj(x) and isinstance(x.get("type"), str) for x in c)


def _body(b: dict) -> dict:
    keys = ["v", "id", "key", "ceiling", "max_depth", "expires_at", "epoch", "status", "issued_at", "operator"]
    return {k: b[k] for k in keys if k in b}


def verify_blueprint(b: Any) -> bool:
    """Well formed and signed by its ``operator`` over exactly its content."""
    return _well_formed(b) and verify_body(AGENT_BLUEPRINT_DOMAIN, _body(b), b["operator"], b.get("sig"))


class BlueprintRegistry:
    def __init__(self, operators: List[str], store: Optional[Dict[str, dict]] = None) -> None:
        self.operators = list(operators)
        self.store: Dict[str, dict] = store if store is not None else {}

    def accept(self, b: Any) -> dict:
        if not verify_blueprint(b):
            return {"ok": False, "code": "bad_record"}
        if b["operator"] not in self.operators:
            return {"ok": False, "code": "unknown_operator"}
        cur = self.store.get(b["key"])
        if cur is not None:
            if cur["operator"] != b["operator"]:
                return {"ok": False, "code": "operator_changed"}
            if b["epoch"] < cur["epoch"]:
                return {"ok": False, "code": "stale_epoch"}
            if b["epoch"] == cur["epoch"]:
                return {"ok": True, "replaced": False} if cur["sig"] == b["sig"] else {"ok": False, "code": "epoch_fork"}
        self.store[b["key"]] = b
        return {"ok": True, "replaced": True}

    def epoch(self) -> int:
        return max((r["epoch"] for r in self.store.values()), default=0)


def _deny(code: str, **extra: Any) -> dict:
    return {"decision": "deny", "code": code, **extra}


def check_blueprints(chain: Any, registry: BlueprintRegistry, now: Any, mode: str, min_epoch: Any = None,
                     evaluate_ceiling: Optional[Callable[[list, dict], dict]] = None) -> dict:
    ok_chain = isinstance(chain, list) and len(chain) > 0 and all(is_obj(h) and is_str(h.get("issuer"), 128) and is_str(h.get("holder"), 128) for h in chain)
    if not ok_chain or not is_uint(now):
        return _deny("bad_input")
    try:
        if min_epoch is not None:
            have = registry.epoch()
            if have < min_epoch:
                return {"decision": "escalate", "code": "stale_blueprint_state", "have": have, "need": min_epoch}
        governed: List[str] = []
        for i, hop in enumerate(chain):
            bp = registry.store.get(hop["issuer"])
            if bp is None:
                continue
            if i == 0 or chain[i - 1]["holder"] != bp["key"]:
                return _deny("broken_link", blueprint=bp["id"])
            if bp["status"] != "active":
                return _deny("blueprint_disabled", blueprint=bp["id"])
            if "expires_at" in bp and now >= bp["expires_at"]:
                return _deny("blueprint_expired", blueprint=bp["id"])
            if "max_depth" in bp and len(chain) - i > bp["max_depth"]:
                return _deny("too_deep", blueprint=bp["id"])
            if len(bp["ceiling"]) > 0:
                r = evaluate_ceiling(bp["ceiling"], bp) if evaluate_ceiling is not None else None
                if r is None:
                    return _deny("ceiling_unevaluable", blueprint=bp["id"])
                if not r.get("ok"):
                    return _deny("ceiling_violated", blueprint=bp["id"], failed=list(r.get("failed", [])))
            governed.append(bp["id"])
        if not governed and mode == "require":
            return _deny("no_blueprint")
        return {"decision": "allow", "governed": governed}
    except Exception:
        return _deny("store_unreachable")
