"""Signed per-definition changes between two versions of a pack (native port of evolve.ts of the TypeScript reference
@atlasauth/pca-actions): the unsigned records, Ed25519 registry signing and the whole-change consistency check. Record shape and
signature verification are in actions_registry.py."""
from typing import Any, Callable, Dict, List, Optional

from .actions import CORE_REGISTRY, ActionKitError, _u16key, def_digest
from .actions_diff import diff_defs
from .actions_registry import EVOLUTION_DOMAIN, EVOLUTION_RECORD_KIND, evolution_diff_digest, evolution_record_error, verify_evolution_record
from .agent import KeyPair
from .intent_wb import _js_str
from .pca import b64u, canonical_bytes_strict


def _by_verb(defs: List[dict]) -> Dict[str, dict]:
    m: Dict[str, dict] = {}
    for d in defs:
        if d["verb"] in m:
            raise ActionKitError("duplicate_def", "verb '%s' appears twice" % d["verb"])
        m[d["verb"]] = d
    return m


def evolution_records(ns: str, prev: List[dict], nxt: List[dict], reg: Optional[Dict[str, dict]] = None,
                      attestation_verified: Optional[Callable[[dict], Any]] = None) -> List[dict]:
    """The unsigned records that take `prev` to `nxt` (sorted by verb). A verb rename is `removed` + `added`."""
    reg = CORE_REGISTRY if reg is None else reg
    a, b = _by_verb(prev), _by_verb(nxt)
    out: List[dict] = []
    for verb in sorted(set(a) | set(b), key=_u16key):
        o, n = a.get(verb), b.get(verb)
        base = {"v": 1, "kind": EVOLUTION_RECORD_KIND, "ns": ns, "verb": verb}
        if o is None:
            out.append({**base, "from": None, "to": def_digest(n), "class": "added", "reasons": []})
        elif n is None:
            out.append({**base, "from": def_digest(o), "to": None, "class": "removed", "reasons": []})
        else:
            f, t = def_digest(o), def_digest(n)
            if f == t:
                continue
            d = diff_defs(o, n, reg, attestation_verified)
            out.append({**base, "from": f, "to": t, "class": d["class"], "reasons": d["reasons"]})
    return out


def sign_evolution(records: List[dict], kid: str, secret: bytes) -> List[dict]:
    """Sign the records as the registry (Ed25519 over the evolution domain and the strict canonical record)."""
    kp = KeyPair(bytes(secret))
    out = []
    for r in records:
        bad = evolution_record_error(r, False)
        if bad:
            raise ValueError("signEvolutionRecord: %s" % bad)
        sig = kp.sign(EVOLUTION_DOMAIN.encode("utf-8") + canonical_bytes_strict(r))
        out.append({**r, "sig": {"alg": "ed25519", "kid": kid, "value": b64u(sig)}})
    return out


def _key(r: dict) -> str:
    return "%s|%s|%s|%s|%s" % (_js_str(r["verb"]), _js_str(r["from"]), _js_str(r["to"]), _js_str(r["class"]), evolution_diff_digest(r))


def evolution_error(ns: str, prev: List[dict], nxt: List[dict], records: List[Any], keys: Any, reg: Optional[Dict[str, dict]] = None,
                    attestation_verified: Optional[Callable[[dict], Any]] = None) -> Optional[str]:
    """Does `records` EXACTLY describe the change from prev to nxt? Every record verifies under the pinned registry keys and names `ns`;
    none is missing or extra; each class is the one the diff computes. None = consistent, else the reason."""
    try:
        for r in records:
            v = verify_evolution_record(r, keys)
            if not v["ok"]:
                return "evolution record: %s" % v["reason"]
            if r["ns"] != ns:
                return "evolution record names namespace '%s', not '%s'" % (_js_str(r["ns"]), ns)
        want = sorted((_key(r) for r in evolution_records(ns, prev, nxt, reg, attestation_verified)), key=_u16key)
        have = sorted((_key({k: x for k, x in r.items() if k != "sig"}) for r in records), key=_u16key)
        if len(want) != len(have):
            return "evolution has %d records, the change needs %d" % (len(have), len(want))
        for w, h in zip(want, have):
            if w != h:
                return "evolution records do not match the computed change (a missing, extra or mis-classified record)"
        return None
    except Exception as e:  # noqa: BLE001
        return "evolution error: %s" % e
