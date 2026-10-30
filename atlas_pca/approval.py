"""What you see is what you sign (track K7): a port of packages/pca/src/approval-render.ts (render shape, H(R), the approval
challenge, the speakable match code) and packages/pca-actions/src/approval-render.ts + approval-profiles.ts (the canonical render of an
action, the PSD2 RTS Art. 5 linking view, the batch commitment). Every function is total over hostile input in the sense the reference
is: a render that cannot be made completely raises ``ActionKitError`` rather than returning something partial."""
import hashlib
from typing import Any, Dict, List, Optional

from .actions import ActionKitError, def_digest, normalize
from .pca import b64u, decode_b64u_strict, hash_canonical, merkle_root

__all__ = [
    "APPROVAL_RENDER_DOMAIN", "APPROVAL_CHALLENGE_DOMAIN", "APPROVAL_BATCH_DOMAIN", "BINDING_WORDS", "approval_render_shape_error", "approval_render_digest",
    "approval_challenge", "binding_words", "render_approval", "psd2_linking", "minor_to_decimal", "approval_batch",
]

APPROVAL_RENDER_DOMAIN = "atlas-pca/approval-render/v1"
APPROVAL_CHALLENGE_DOMAIN = "atlas-pca/approval-challenge/v1\0"
APPROVAL_BATCH_DOMAIN = "atlas-pca/approval-batch/v1"
_ITEM_DOMAIN = "atlas-pca/approval-batch-item/v1"
_PAYEE_DOMAIN = "atlas-pca/approval-payee/v1"
MAX_RENDER_FIELDS = 64
MAX_PARAM_PATH_DEPTH = 3

BINDING_WORDS = (
    "able", "acid", "aged", "also", "area", "army", "atom", "aunt",
    "away", "baby", "back", "ball", "band", "bank", "base", "bath",
    "bear", "beat", "beef", "bell", "belt", "bend", "bird", "blue",
    "boat", "body", "bold", "bone", "book", "boot", "born", "both",
    "bowl", "bulb", "burn", "bush", "busy", "cafe", "cake", "calm",
    "camp", "card", "care", "cart", "case", "cash", "cast", "cave",
    "cell", "chat", "chef", "chip", "city", "clay", "clip", "club",
    "coal", "coat", "code", "coin", "cold", "cook", "cool", "cope",
    "copy", "cord", "core", "cost", "crew", "crop", "dark", "data",
    "date", "dawn", "deal", "dear", "deck", "deep", "deer", "desk",
    "dial", "dice", "diet", "dish", "dive", "door", "dose", "down",
    "draw", "drop", "drum", "duck", "dust", "duty", "each", "earn",
    "east", "easy", "edge", "echo", "else", "even", "ever", "exit",
    "face", "fact", "fair", "fall", "farm", "fast", "fate", "fern",
    "file", "fill", "film", "find", "fine", "fire", "firm", "fish",
    "five", "flag", "flat", "flow", "foam", "fold", "folk", "food",
    "foot", "fork", "form", "fort", "four", "free", "frog", "fuel",
    "full", "fund", "gain", "game", "gate", "gear", "gift", "girl",
    "glad", "glow", "goat", "gold", "golf", "good", "grab", "gray",
    "grid", "grip", "grow", "gulf", "hair", "half", "hall", "hand",
    "hard", "harp", "hawk", "head", "heat", "help", "herb", "hill",
    "hint", "hold", "hole", "home", "hood", "hook", "hope", "horn",
    "host", "hour", "huge", "hunt", "idea", "inch", "iron", "isle",
    "item", "jade", "jazz", "join", "joke", "jump", "jury", "just",
    "keen", "keep", "kind", "king", "kite", "knee", "knot", "lake",
    "lamp", "land", "lane", "last", "late", "lawn", "lead", "leaf",
    "lean", "left", "lens", "less", "lift", "lime", "line", "link",
    "lion", "list", "live", "load", "loan", "lock", "logo", "long",
    "loop", "lord", "loud", "love", "luck", "lung", "made", "mail",
    "main", "mask", "mass", "mate", "meal", "melt", "menu", "mild",
    "milk", "mind", "mint", "mole", "moon", "more", "moss", "move",
    "much", "nail", "navy", "neat", "neck", "nest", "news", "nice",
)


def _is_digest(v: Any) -> bool:
    return isinstance(v, str) and decode_b64u_strict(v, 32) is not None


def _safe_int(v: Any) -> bool:
    if isinstance(v, bool):
        return False
    if isinstance(v, int):
        return abs(v) <= 2 ** 53 - 1
    if isinstance(v, float):
        return v == v and abs(v) != float("inf") and v == int(v) and abs(v) <= 2 ** 53 - 1 and not (v == 0 and str(v).startswith("-"))
    return False


def _bounded(v: Any, n: int) -> bool:
    return isinstance(v, str) and 0 < len(v.encode("utf-8", "surrogatepass")) <= n


def _closed(o: dict, required, optional=()) -> Optional[str]:
    for k in o:
        if k not in required and k not in optional:
            return "unknown member '%s'" % k
    for k in required:
        if k not in o:
            return "missing member '%s'" % k
    return None


def approval_render_shape_error(r: Any) -> Optional[str]:
    """Null if ``r`` is a well-formed render (closed members, sorted unique ids, bounded)."""
    if not isinstance(r, dict):
        return "render must be an object"
    e = _closed(r, ("v", "kind", "verb", "def_digest", "unreviewed", "fields"))
    if e:
        return e
    if r["v"] != 1 or isinstance(r["v"], bool) or r["kind"] != "pca-approval-render":
        return "not a pca-approval-render v1"
    if not _bounded(r["verb"], 128):
        return "verb must be a bounded string"
    if not _is_digest(r["def_digest"]):
        return "def_digest must be canonical base64url (32 bytes)"
    if not isinstance(r["unreviewed"], bool):
        return "unreviewed must be a boolean"
    if not isinstance(r["fields"], list) or len(r["fields"]) > MAX_RENDER_FIELDS:
        return "fields must be an array of at most %d" % MAX_RENDER_FIELDS
    prev = None
    for f in r["fields"]:
        if not isinstance(f, dict):
            return "a field must be an object"
        e = _closed(f, ("id", "class", "value"), ("unit",))
        if e:
            return e
        if not _bounded(f["id"], 192) or not _bounded(f["class"], 128):
            return "field id and class must be bounded strings"
        if prev is not None and not _u16(prev) < _u16(f["id"]):
            return "fields must be sorted by id and unique"
        prev = f["id"]
        if "unit" in f:
            u = f["unit"]
            if not isinstance(u, dict):
                return "unit must be an object"
            if u.get("kind") == "money":
                if _closed(u, ("kind", "ccy", "exp")) or not _bounded(u["ccy"], 16) or not _safe_int(u["exp"]) or u["exp"] < 0 or u["exp"] > 18:
                    return "a money unit needs ccy and exp"
            elif u.get("kind") not in ("count", "bytes", "duration", "ratio") or _closed(u, ("kind",)):
                return "unknown unit"
    return None


def _u16(s: str) -> bytes:
    return s.encode("utf-16-be", "surrogatepass")


def approval_render_digest(render: Any) -> str:
    e = approval_render_shape_error(render)
    if e:
        raise ValueError("approvalRenderDigest: " + e)
    return hash_canonical({"d": APPROVAL_RENDER_DOMAIN, "render": render})


def approval_challenge(action_digest: Any, render_digest: Any) -> str:
    """b64u(SHA-256(domain || action_digest || H(R))); both digests must be canonical 32-byte values."""
    a = decode_b64u_strict(action_digest, 32) if isinstance(action_digest, str) else None
    r = decode_b64u_strict(render_digest, 32) if isinstance(render_digest, str) else None
    if a is None or r is None:
        raise ValueError("approvalChallenge: both digests must be canonical 32-byte values")
    return b64u(hashlib.sha256(APPROVAL_CHALLENGE_DOMAIN.encode("utf-8") + a + r).digest())


def binding_words(render_digest: str) -> str:
    r = decode_b64u_strict(render_digest, 32) if isinstance(render_digest, str) else None
    if r is None:
        raise ValueError("bindingWords: render digest must be a canonical 32-byte value")
    return "-".join(BINDING_WORDS[b] for b in r[:6])


# ---- the render --------------------------------------------------------------------------------------------------------------

def _flatten(params: dict) -> Dict[str, Any]:
    out: Dict[str, Any] = {}

    def walk(prefix: str, depth: int, v: Any) -> None:
        if isinstance(v, dict) and depth < MAX_PARAM_PATH_DEPTH and len(v) > 0:
            for k, x in v.items():
                if "." in k:
                    raise ActionKitError("render_bad_params", "the parameter key '%s' contains a dot" % k)
                walk(k if prefix == "" else prefix + "." + k, depth + 1, x)
        else:
            out[prefix] = v

    for k, v in params.items():
        if "." in k:
            raise ActionKitError("render_bad_params", "the parameter key '%s' contains a dot" % k)
        walk(k, 1, v)
    return out


def _lone(s: str) -> bool:
    return any(0xD800 <= ord(c) <= 0xDFFF for c in s)


def _leaf(v: Any) -> bool:
    if isinstance(v, str):
        return not _lone(v)
    if isinstance(v, bool):
        return True
    if isinstance(v, list):
        return all(_leaf(x) for x in v)
    return _safe_int(v)


def _value_ok(t: str, v: Any) -> bool:
    if t in ("integer", "duration"):
        return _safe_int(v)
    if t == "boolean":
        return isinstance(v, bool)
    if t in ("string", "date", "datetime", "object_ref"):
        return isinstance(v, str) and not _lone(v)
    if t in ("set", "array"):
        return isinstance(v, list) and all(_leaf(x) for x in v)
    return False


def _as_int(v: Any) -> Any:
    return int(v) if isinstance(v, float) and not isinstance(v, bool) else v


def render_approval(d: dict, params: Any, confirmed: bool = False) -> dict:
    """The canonical approval render of ``d`` for ``params``. ``confirmed`` is whether the definition carries a valid signed confirmation
    (the caller decides, as for ``effective``); unconfirmed renders carry ``unreviewed: true``."""
    if not isinstance(params, dict):
        raise ActionKitError("render_bad_params", "params must be an object")
    n = normalize(d)
    flat = _flatten(params)
    for k in flat:
        if k not in n["params"]:
            raise ActionKitError("render_undeclared_param", "'%s' is not a parameter of %s" % (k, n["verb"]))
    for k, p in n["params"].items():
        if p["required"] and k not in flat:
            raise ActionKitError("render_missing_param", "required parameter '%s' of %s is missing" % (k, n["verb"]))
    fields: List[dict] = []
    for fid in sorted(flat, key=_u16):
        p = n["params"][fid]
        if not _value_ok(p["type"], flat[fid]):
            raise ActionKitError("render_bad_value", "'%s' is not a %s in the canonical domain" % (fid, p["type"]))
        f: Dict[str, Any] = {"id": fid, "class": p.get("role", "param"), "value": _as_int(flat[fid])}
        u = p.get("unit")
        if u is not None:
            if u["kind"] == "money":
                ccy = u["ccy"] if isinstance(u["ccy"], str) else flat.get(u["ccy"]["from"])
                if not isinstance(ccy, str) or len(ccy) == 0:
                    raise ActionKitError("render_unresolved_currency", "the currency of '%s' is not a string" % fid)
                f["unit"] = {"kind": "money", "ccy": ccy, "exp": u["exp"]}
            else:
                f["unit"] = {"kind": u["kind"]}
        fields.append(f)
    return {"v": 1, "kind": "pca-approval-render", "verb": n["verb"], "def_digest": def_digest(d), "unreviewed": not confirmed, "fields": fields}


# ---- PSD2 RTS Art. 5 ---------------------------------------------------------------------------------------------------------

def psd2_linking(r: dict) -> dict:
    if r["unreviewed"]:
        raise ActionKitError("psd2_unlinkable", "an unreviewed definition cannot be a payment approval")
    amts = [f for f in r["fields"] if f["class"] == "money.amount"]
    if len(amts) != 1:
        raise ActionKitError("psd2_unlinkable", "a payment approval needs exactly one money.amount parameter")
    a = amts[0]
    if a.get("unit", {}).get("kind") != "money":
        raise ActionKitError("psd2_unlinkable", "the money.amount parameter has no money unit")
    if not _safe_int(a["value"]) or a["value"] < 0:
        raise ActionKitError("psd2_unlinkable", "the amount must be a non-negative integer in minor units")
    payees = [f for f in r["fields"] if f["class"] == "party.payee"]
    if len(payees) != 1 or not isinstance(payees[0]["value"], str) or payees[0]["value"] == "":
        raise ActionKitError("psd2_unlinkable", "a payment approval needs exactly one non-empty party.payee parameter")
    return {"amount_minor": a["value"], "currency": a["unit"]["ccy"], "exp": a["unit"]["exp"], "payee": payees[0]["value"]}


def minor_to_decimal(minor: int, exp: int) -> str:
    if not _safe_int(minor) or minor < 0 or not _safe_int(exp) or exp < 0 or exp > 18:
        raise ActionKitError("psd2_unlinkable", "minor units must be a non-negative safe integer")
    if exp == 0:
        return str(minor)
    s = str(minor).rjust(exp + 1, "0")
    return s[:-exp] + "." + s[-exp:]


def approval_batch(items: list) -> dict:
    if len(items) == 0:
        raise ActionKitError("psd2_unlinkable", "a batch needs at least one payment")
    totals: Dict[str, dict] = {}
    payees = set()
    for it in items:
        link = psd2_linking(it["render"])
        t = totals.get(link["currency"])
        if t is not None and t["exp"] != link["exp"]:
            raise ActionKitError("psd2_unlinkable", "currency %s appears with two exponents" % link["currency"])
        minor = (t["minor"] if t else 0) + link["amount_minor"]
        if minor > 2 ** 53 - 1:
            raise ActionKitError("psd2_unlinkable", "the batch total exceeds the safe integer range")
        totals[link["currency"]] = {"exp": link["exp"], "minor": minor}
        payees.add(link["payee"])
    batch = {
        "v": 1, "kind": "pca-approval-batch", "n": len(items),
        "totals": [{"ccy": c, "exp": totals[c]["exp"], "minor": totals[c]["minor"]} for c in sorted(totals, key=_u16)],
        "payees_root": merkle_root([{"d": _PAYEE_DOMAIN, "payee": p} for p in sorted(payees, key=_u16)]),
        "items_root": merkle_root([{"d": _ITEM_DOMAIN, "a": it["action_digest"], "r": approval_render_digest(it["render"])} for it in items]),
    }
    rd = hash_canonical({"d": APPROVAL_BATCH_DOMAIN, "batch": batch})
    return {"batch": batch, "action_digest": batch["items_root"], "render_digest": rd, "challenge": approval_challenge(batch["items_root"], rd), "words": binding_words(rd)}
