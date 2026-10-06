"""Reference verifier for the CORE PCActn checks (M0-M3); byte-matches @atlasauth/pca."""
import base64
import hashlib
import json
import math
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from . import ed25519

SIG_DOMAIN = b"atlas-pca/actn/v1\x00"
CAP_DOMAIN = b"atlas-pca/cap/v1\x00"
DEFAULT_REVERSIBILITY_CLASS = "reversible"


def b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def unb64u(s: str) -> bytes:
    if not isinstance(s, str) or "=" in s or not all(c.isalnum() or c in "-_" for c in s):
        raise ValueError("bad base64url")
    if len(s) % 4 == 1:
        raise ValueError("bad base64url length")
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def sha256(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()


# ---- canonicalization ----------------------------------------------------------------

def _utf16_key(s: str) -> bytes:
    return s.encode("utf-16-be", "surrogatepass")


def _num(v) -> str:
    if isinstance(v, int):
        return str(v)
    if math.isnan(v) or math.isinf(v):
        raise TypeError("canonicalize: non-finite number")
    if v == 0:
        return "0"
    if v == math.trunc(v) and abs(v) < 1e21:
        return str(int(v))
    return repr(v)


def canonicalize(v: Any) -> str:
    """Keys sorted by UTF-16 code units (recursively), compact, JS-style string escaping."""
    if v is None:
        return "null"
    if v is True:
        return "true"
    if v is False:
        return "false"
    if isinstance(v, str):
        return json.dumps(v, ensure_ascii=False)
    if isinstance(v, (int, float)):
        return _num(v)
    if isinstance(v, (list, tuple)):
        return "[" + ",".join(canonicalize(x) for x in v) + "]"
    if isinstance(v, dict):
        keys = sorted(v.keys(), key=_utf16_key)
        return "{" + ",".join(json.dumps(k, ensure_ascii=False) + ":" + canonicalize(v[k]) for k in keys) + "}"
    raise TypeError("canonicalize: unsupported type %s" % type(v).__name__)


def canonical_bytes(v: Any) -> bytes:
    return canonicalize(v).encode("utf-8", "surrogatepass")


def hash_canonical(v: Any) -> str:
    return b64u(sha256(canonical_bytes(v)))


# ---- Merkle --------------------------------------------------------------------------

def _leaf_hash(leaf: Any) -> bytes:
    return sha256(b"\x00" + canonical_bytes(leaf))


def _node_hash(l: bytes, r: bytes) -> bytes:
    return sha256(b"\x01" + l + r)


def _split(n: int) -> int:
    k = 1
    while k * 2 < n:
        k *= 2
    return k


def _build(hs: List[bytes]) -> bytes:
    if len(hs) == 1:
        return hs[0]
    k = _split(len(hs))
    return _node_hash(_build(hs[:k]), _build(hs[k:]))


def merkle_root(leaves: List[Any]) -> str:
    if not leaves:
        raise ValueError("merkle_root: empty leaf set")
    return b64u(_build([_leaf_hash(x) for x in leaves]))


def verify_inclusion(root: Any, proof: Any, leaf: Any) -> bool:
    try:
        if not isinstance(proof, dict) or not isinstance(proof.get("path"), list):
            return False
        h = _leaf_hash(leaf)
        for step in proof["path"]:
            side = step.get("side")
            if side not in ("L", "R"):
                return False
            sib = unb64u(step["hash"])
            h = _node_hash(sib, h) if side == "L" else _node_hash(h, sib)
        return b64u(h) == root
    except Exception:
        return False


def params_digest(params: Any = None) -> str:
    return hash_canonical({} if params is None else params)


EMPTY_PARAMS_DIGEST = params_digest()


def conditions_digest(pre: Any = None, post: Any = None) -> str:
    return hash_canonical({"pre": pre, "post": post})


def _plan_leaf(node_id: Any, action: dict, cond: str) -> dict:
    if node_id is None:
        raise ValueError("missing node_id")
    pd = action.get("params_digest")
    rc = action.get("reversibility_class")
    return {
        "node_id": node_id,
        "verb": action["verb"],
        "resource": action["resource"],
        "params_digest": EMPTY_PARAMS_DIGEST if pd is None else pd,
        "reversibility_class": DEFAULT_REVERSIBILITY_CLASS if rc is None else rc,
        "conditions": cond,
    }


# ---- keys / capability chain ---------------------------------------------------------

def _verify_b64u(pub: Any, msg: bytes, sig: Any) -> bool:
    try:
        return ed25519.verify(unb64u(pub), msg, unb64u(sig))
    except Exception:
        return False


def cap_hash(c: dict) -> str:
    return hash_canonical(c)


def _body_of(c: dict) -> dict:
    return {"issuer": c.get("issuer"), "holder": c.get("holder"), "caveats": c.get("caveats"), "parent": c.get("parent")}


def _check_sig(c: dict, signer: Any, label: str) -> Optional[str]:
    try:
        digest = hash_canonical(_body_of(c))
    except Exception:
        return label + ": malformed body"
    if digest != c.get("body_digest") or c.get("id") != c.get("body_digest"):
        return label + ": body digest mismatch"
    try:
        msg = CAP_DOMAIN + unb64u(c["body_digest"])
    except Exception:
        return label + ": bad signature (not signed by expected key)"
    if not _verify_b64u(signer, msg, c.get("sig")):
        return label + ": bad signature (not signed by expected key)"
    return None


def verify_chain(chain: list, expected_root_issuer: Optional[str] = None):
    """Returns (ok, reason)."""
    if not isinstance(chain, list) or not chain:
        return False, "empty chain"
    root = chain[0]
    if "parent" in root:
        return False, "hop 0: root must not have a parent"
    if expected_root_issuer is not None and root.get("issuer") != expected_root_issuer:
        return False, "hop 0: root issuer is not the expected principal"
    err = _check_sig(root, root.get("issuer"), "hop 0")
    if err:
        return False, err
    for i in range(1, len(chain)):
        parent, c, label = chain[i - 1], chain[i], "hop %d" % i
        if c.get("parent") != cap_hash(parent):
            return False, label + ": broken parent link"
        if c.get("issuer") != parent.get("holder"):
            return False, label + ": issuer is not the parent's bound holder"
        err = _check_sig(c, parent.get("holder"), label)
        if err:
            return False, err
        pc, cc = parent["caveats"], c["caveats"]
        if len(cc) < len(pc):
            return False, label + ": drops parent caveat(s)"
        for j in range(len(pc)):
            if hash_canonical(cc[j]) != hash_canonical(pc[j]):
                return False, "%s: caveat %d altered or reordered" % (label, j)
    return True, None


# ---- PCActn --------------------------------------------------------------------------

def threshold_message(p: dict) -> bytes:
    """SIG_DOMAIN || sha256(canonical(pcactn without `sig` and `threshold`))."""
    body = {k: v for k, v in p.items() if k not in ("sig", "threshold")}
    return SIG_DOMAIN + sha256(canonical_bytes(body))


@dataclass
class Verdict:
    allow: bool
    checks: Dict[str, bool] = field(default_factory=dict)  # chain, plan_inclusion, leaf_signature, counter
    reason: Optional[str] = None


def verify_pcactn_core(p: dict, grant: dict) -> Verdict:
    checks = {"chain": False, "plan_inclusion": False, "leaf_signature": False, "counter": False}
    state = {"failed": False, "reason": None}

    def fail(name: str, why: str) -> None:
        state["failed"] = True
        checks[name] = False
        if state["reason"] is None:
            state["reason"] = "%s: %s" % (name, why)

    try:
        if p.get("ver") == 1 and not isinstance(p.get("ver"), bool):
            pass
        else:
            fail("version", "unsupported ver")

        chain = p.get("cap_chain")
        if not isinstance(chain, list) or not chain:
            fail("chain", "empty chain")
        elif cap_hash(chain[0]) != cap_hash(grant):
            fail("chain", "chain root is not the grant")
        else:
            ok, why = verify_chain(chain, grant.get("issuer"))
            if ok:
                checks["chain"] = True
            else:
                fail("chain", why or "invalid")

        plan = p.get("plan") or {}
        cond = plan.get("conditions_digest")
        if not isinstance(cond, str):
            cond = conditions_digest()
        leaf = _plan_leaf(plan.get("node_id"), p["action"], cond)
        if verify_inclusion(plan.get("root"), plan.get("inclusion_proof"), leaf):
            checks["plan_inclusion"] = True
        else:
            fail("plan_inclusion", "action is not a node of the committed plan")

        leaf_cap = chain[-1] if isinstance(chain, list) and chain else None
        sig = p.get("sig")
        if leaf_cap and isinstance(sig, str) and _verify_b64u(leaf_cap.get("holder"), threshold_message(p), sig):
            checks["leaf_signature"] = True
        else:
            fail("leaf_signature", "signature does not verify under the leaf holder key")

        c = p.get("counter")
        if isinstance(c, int) and not isinstance(c, bool) and c >= 0:
            checks["counter"] = True
        else:
            fail("counter", "missing or not a non-negative integer")
    except Exception as e:  # malformed input never raises; it simply denies
        state["failed"] = True
        if state["reason"] is None:
            state["reason"] = "malformed PCActn: %s" % e
    return Verdict(allow=not state["failed"], checks=checks, reason=state["reason"])
