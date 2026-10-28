"""Read-side authorization (K5, verification side): ``redact_read`` applies a signed read grant to one response (every field is
shown, masked or dropped), ``check_sink`` decides whether data read under a chain of read receipts may reach a sink. Total, pure
functions shaped like the shared vectors (``readside-vectors.json``); anything malformed, unsigned, unknown or out of scope denies.
Tighten-only: a caller may ask for a STRICTER mode than the grant gives, never a weaker one."""
import re
from typing import Any, Dict, Optional

from .k3 import is_obj, is_str, u16len, verify_body
from .pca import hash_canonical
from .workflow import ID_RE, LABEL_RE, NAME_RE, is_b32, is_scalar_map, is_uint, only_keys, rx, sorted_unique

READ_GRANT_DOMAIN = "atlas-pca/read-grant/v1\0"
READ_RECEIPT_DOMAIN = "atlas-pca/read-receipt/v1\0"
_RG_REF = "atlas-pca/read-grant-ref/v1"
_RR_REF = "atlas-pca/read-receipt-ref/v1"
_RH = "atlas-pca/read-hash/v1"
_RT = "atlas-pca/read-token/v1"
_RV = "atlas-pca/read-value/v1"
_RANK = {"show": 0, "last4": 1, "bucket": 2, "token": 3, "hash": 4, "drop": 5}
_MODE_RE = re.compile(r"show|last4|hash|token|drop|bucket:[1-9][0-9]{0,8}")
_SALT_MIN = 16


def _is_mode(x: Any) -> bool:
    return isinstance(x, str) and _MODE_RE.fullmatch(x) is not None


def _rank(m: str) -> int:
    return _RANK["bucket" if m.startswith("bucket:") else m]


def _valid_entry(e: Any) -> bool:
    if not (is_obj(e) and only_keys(e, ("verb", "resource_prefix", "purposes", "modes", "default_mode")) and is_str(e["verb"], 128)
            and is_str(e["resource_prefix"], 512) and sorted_unique(e["purposes"], ID_RE, 16) and len(e["purposes"]) > 0):
        return False
    m = e["modes"]
    return is_obj(m) and len(m) <= 32 and all(rx(LABEL_RE, k) and _is_mode(v) for k, v in m.items()) and _is_mode(e["default_mode"])


def valid_read_grant_body(b: Any) -> bool:
    """Shape of a read grant body (no signature)."""
    if not is_obj(b) or not only_keys(b, ("v", "id", "principal", "issued_at", "expires_at", "reads", "caps", "sinks")):
        return False
    if not (isinstance(b["v"], int) and not isinstance(b["v"], bool) and b["v"] == 1):
        return False
    if not (rx(ID_RE, b["id"]) and is_b32(b["principal"]) and is_uint(b["issued_at"]) and is_uint(b["expires_at"])):
        return False
    reads = b["reads"]
    if not isinstance(reads, list) or not 0 < len(reads) <= 32 or not all(_valid_entry(e) for e in reads):
        return False
    caps = b["caps"]
    if not is_obj(caps) or len(caps) > 32 or not all(rx(LABEL_RE, k) and is_uint(v) for k, v in caps.items()):
        return False
    s = b["sinks"]
    if not is_obj(s) or len(s) > 16:
        return False
    return all(rx(ID_RE, k) and is_obj(v) and only_keys(v, ("allow", "escalate")) and sorted_unique(v["allow"], LABEL_RE, 16)
               and sorted_unique(v["escalate"], LABEL_RE, 16) and not any(lb in v["escalate"] for lb in v["allow"]) for k, v in s.items())


def read_grant_digest(b: dict) -> str:
    return hash_canonical({"d": _RG_REF, "g": b})


_RR_KEYS = ("v", "grant", "verb", "resource", "purpose", "seq", "prev", "fields", "labels", "issued_at", "signer")


def read_receipt_ref(r: dict) -> str:
    return hash_canonical({"d": _RR_REF, "r": r})


def _out(decision: str, code: Optional[str], counts: Optional[dict] = None) -> dict:
    return {"decision": decision, "code": code, "view": {}, "fields": {}, "labels": [], "counts": dict(counts or {})}


def _bmp(s: str) -> bool:
    return all(ord(c) < 0x10000 for c in s)


def _grade_grant(g: Any, principal: Any, now: Any):
    """(body, None) or (None, code)."""
    if not is_b32(principal) or not is_uint(now):
        return None, "bad_request"
    if not is_obj(g) or not only_keys(g, ("body", "sig")) or not valid_read_grant_body(g["body"]):
        return None, "bad_grant"
    b = g["body"]
    if b["principal"] != principal or not verify_body(READ_GRANT_DOMAIN, b, principal, g["sig"]):
        return None, "bad_signature"
    if now < b["issued_at"]:
        return None, "not_yet"
    if now >= b["expires_at"]:
        return None, "expired"
    return b, None


def redact_read(inp: Any) -> dict:
    """Apply a read grant to one response. ``inp``: grant, principal, now, verb, resource, purpose, schema, record, tighten, salt, counts."""
    try:
        g, code = _grade_grant(inp.get("grant"), inp.get("principal"), inp.get("now"))
        if code is not None:
            return _out("deny", code)
        sc, counts_in, record, tighten, salt = inp.get("schema"), inp.get("counts"), inp.get("record"), inp.get("tighten"), inp.get("salt")
        verb, resource, purpose = inp.get("verb"), inp.get("resource"), inp.get("purpose")
        if not (is_b32(inp.get("principal")) and is_uint(inp.get("now")) and is_str(verb, 128) and is_str(resource, 512) and rx(ID_RE, purpose)
                and isinstance(salt, str) and u16len(salt) >= _SALT_MIN):
            return _out("deny", "bad_request")
        if not (is_obj(sc) and is_obj(sc.get("fields")) and all(rx(NAME_RE, k) and rx(LABEL_RE, v) for k, v in sc["fields"].items())
                and isinstance(sc.get("required"), list) and all(isinstance(p, str) and p in sc["fields"] for p in sc["required"])):
            return _out("deny", "bad_request")
        if not is_scalar_map(record) or not is_obj(tighten) or not all(rx(LABEL_RE, k) and _is_mode(v) for k, v in tighten.items()):
            return _out("deny", "bad_request")
        if not is_obj(counts_in) or not all(rx(LABEL_RE, k) and is_uint(v) for k, v in counts_in.items()):
            return _out("deny", "bad_request")
        # ordinal (code point = byte-wise for valid text) prefix
        entry = next((e for e in g["reads"] if e["verb"] == verb and resource.startswith(e["resource_prefix"]) and purpose in e["purposes"]), None)
        if entry is None:
            return _out("deny", "no_read_scope", counts_in)
        fields: Dict[str, dict] = {}
        view: Dict[str, Any] = {}
        used: Dict[str, int] = {}
        for path in sorted(record):
            v = record[path]
            cls = sc["fields"].get(path)
            vd = hash_canonical({"d": _RV, "salt": salt, "p": path, "v": v})
            if cls is None:  # a field the schema does not classify is never shown
                fields[path] = {"class": "unclassified", "action": "dropped", "kind": None, "vd": vd}
                continue
            mode = entry["modes"].get(cls, entry["default_mode"])
            t = tighten.get(cls)
            if t is not None and _rank(t) > _rank(mode):
                mode = t
            shown: Any = None
            action = "masked"
            kind: Optional[str] = "bucket" if mode.startswith("bucket:") else mode
            if mode == "show":
                shown, action, kind = v, "shown", None
            elif mode == "last4":
                if isinstance(v, str) and _bmp(v) and len(v) > 4:
                    shown = "****" + v[-4:]
            elif mode.startswith("bucket:"):
                n = int(mode[7:])
                if is_uint(v):
                    shown = v - (v % n)
            elif mode == "hash":
                shown = hash_canonical({"d": _RH, "salt": salt, "c": cls, "v": v})
            elif mode == "token":
                shown = "tok_" + hash_canonical({"d": _RT, "salt": salt, "c": cls, "v": v})[:22]
            if shown is None:
                fields[path] = {"class": cls, "action": "dropped", "kind": None, "vd": vd}
                continue
            fields[path] = {"class": cls, "action": action, "kind": kind, "vd": vd}
            view[path] = shown
            used[cls] = used.get(cls, 0) + 1
        counts = dict(counts_in)
        for c, n in used.items():
            counts[c] = counts.get(c, 0) + n
            cap = g["caps"].get(c)
            if cap is not None and counts[c] > cap:
                return _out("deny", "read_cap", counts_in)
        if any(p not in view for p in sc["required"]):
            return _out("escalate", "required_dropped", counts_in)
        labels = sorted({f["class"] for f in fields.values() if f["action"] != "dropped"})
        return {"decision": "allow", "code": None, "view": view, "fields": fields, "labels": labels, "counts": counts}
    except Exception:
        return _out("deny", "bad_request")


def _valid_read_receipt(r: Any) -> bool:
    if not is_obj(r) or not only_keys(r, _RR_KEYS + ("sig",)) or not (isinstance(r["v"], int) and not isinstance(r["v"], bool) and r["v"] == 1):
        return False
    if not (is_b32(r["grant"]) and is_str(r["verb"], 128) and is_str(r["resource"], 512) and rx(ID_RE, r["purpose"]) and is_uint(r["seq"])
            and (r["prev"] is None or is_b32(r["prev"])) and (r["seq"] == 0) == (r["prev"] is None)):
        return False
    if not (is_uint(r["issued_at"]) and is_b32(r["signer"]) and isinstance(r["sig"], str) and sorted_unique(r["labels"], LABEL_RE, 32)
            and is_obj(r["fields"]) and len(r["fields"]) <= 64):
        return False
    return all(rx(NAME_RE, k) and is_obj(f) and only_keys(f, ("class", "action", "kind", "vd")) and isinstance(f["class"], str)
               and (f["class"] == "unclassified" or rx(LABEL_RE, f["class"])) and f["action"] in ("shown", "masked", "dropped")
               and (f["kind"] is None or isinstance(f["kind"], str)) and is_b32(f["vd"]) for k, f in r["fields"].items())


def read_chain_labels(receipts: Any, rs_signer: Any, grant_digest: Any, now: Any) -> dict:
    """The labels carried by a verified, unbroken chain of read receipts (``{"labels"}``), or ``{"code", "at"}``."""
    if not isinstance(receipts, list):
        return {"code": "bad_receipt", "at": 0}
    allv = set()
    prev = None
    for i, r in enumerate(receipts):
        if not _valid_read_receipt(r) or r["signer"] != rs_signer or r["grant"] != grant_digest or r["seq"] != i or r["issued_at"] > now:
            return {"code": "bad_receipt", "at": i}
        if (r["prev"] is not None if prev is None else r["prev"] != read_receipt_ref(prev)) \
                or not verify_body(READ_RECEIPT_DOMAIN, {k: r[k] for k in _RR_KEYS}, rs_signer, r["sig"]):
            return {"code": "bad_receipt", "at": i}
        # the receipt's labels must be exactly the classes of its non-dropped fields: an understated list would launder data
        if sorted({f["class"] for f in r["fields"].values() if f["action"] != "dropped"}) != r["labels"]:
            return {"code": "bad_receipt", "at": i}
        allv.update(r["labels"])
        prev = r
    return {"labels": sorted(allv)}


def check_sink(inp: Any) -> dict:
    """May data read under these receipts reach ``sink``? ``inp``: grant, principal, rs_signer, now, sink, receipts."""
    def no(code: str) -> dict:
        return {"decision": "deny", "code": code, "labels": []}
    try:
        g, code = _grade_grant(inp.get("grant"), inp.get("principal"), inp.get("now"))
        if code is not None:
            return no(code)
        if not is_b32(inp.get("rs_signer")) or not isinstance(inp.get("sink"), str):
            return no("bad_request")
        rule = g["sinks"].get(inp["sink"])
        if rule is None:
            return no("unknown_sink")
        c = read_chain_labels(inp.get("receipts"), inp["rs_signer"], read_grant_digest(g), inp["now"])
        if "code" in c:
            return no(c["code"])
        if any(lb not in rule["allow"] and lb not in rule["escalate"] for lb in c["labels"]):
            return {"decision": "deny", "code": "label_flow", "labels": c["labels"]}
        if any(lb in rule["escalate"] for lb in c["labels"]):
            return {"decision": "escalate", "code": "label_escalate", "labels": c["labels"]}
        return {"decision": "allow", "code": None, "labels": c["labels"]}
    except Exception:
        return no("bad_request")
