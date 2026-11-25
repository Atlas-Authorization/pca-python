"""PCA layer: a capability as a multi-message BBS credential with selective disclosure. The message vector is iss, sub, then one
message per caveat named "cav:<i>:<type>" whose value is the strict-canonical JSON of the caveat; each message's octets are
utf8(name) || 0x00 || utf8(value). Credentials, attributes and presentations are dicts with the same member names as the
TypeScript types."""
from __future__ import annotations

from ._fin import fin
import math
import re
from typing import Any, Dict, List, Optional, Sequence

from . import bbs as Bbs
from .bls12 import Bls12LibraryMissing
from .pca import _num, b64u, canonicalize_strict, decode_b64u_strict

_LONE_SURROGATE = re.compile(rb"\xED[\xA0-\xBF][\x80-\xBF]")


def _utf8(s: str) -> bytes:
    """UTF-8 octets, U+FFFD for an unpaired surrogate (what a JavaScript TextEncoder produces)."""
    return _LONE_SURROGATE.sub(b"\xEF\xBF\xBD", s.encode("utf-8", "surrogatepass"))


def encode_attribute(name: Any, value: Any) -> bytes:
    if not isinstance(name, str) or not isinstance(value, str):
        raise ValueError("attribute name and value must be strings")
    if "\0" in name:
        raise ValueError("attribute name must not contain NUL")
    return _utf8(name) + b"\0" + _utf8(value)


def encode(attr: Any) -> bytes:
    if not isinstance(attr, dict):
        raise ValueError("not an object")
    return encode_attribute(attr.get("name"), attr.get("value"))


def encode_all(attrs: Any) -> List[bytes]:
    if not isinstance(attrs, list):
        raise ValueError("not an array")
    return [encode(a) for a in attrs]


def _js_str(v: Any) -> str:
    """JavaScript String(x) for the values a caveat type can hold."""
    if isinstance(v, str):
        return v
    if v is None:
        return "null"
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, (int, float)):
        return _num(v, False)
    if isinstance(v, list):
        return ",".join("" if x is None else _js_str(x) for x in v)
    return "[object Object]"


def capability_attributes(capability: Any) -> List[Dict[str, Any]]:
    """The ordered attribute vector for a capability: issuer, holder, then each caveat."""
    if not isinstance(capability, dict):
        raise ValueError("capability must be an object")
    attrs: List[Dict[str, Any]] = [
        {"index": 0, "name": "iss", "value": capability.get("issuer")},
        {"index": 1, "name": "sub", "value": capability.get("holder")},
    ]
    caveats = capability.get("caveats")
    if not isinstance(caveats, list):
        caveats = []
    for i, cv in enumerate(caveats):
        if not isinstance(cv, dict):
            raise TypeError("caveat must be an object")
        typ = _js_str(cv["type"]) if "type" in cv else "undefined"
        attrs.append({"index": i + 2, "name": "cav:%d:%s" % (i, typ), "value": canonicalize_strict(cv)})
    return attrs


def issue_capability_credential(capability: Any, sk: int, pk: bytes, header: Optional[bytes] = None) -> Dict[str, Any]:
    """Sign a capability's attributes as a BBS credential; header is optional application context (None = empty)."""
    attributes = capability_attributes(capability)
    hdr = bytes(header or b"")
    signature = Bbs.sign(sk, pk, hdr, encode_all(attributes))
    return {"issuerPublicKey": b64u(pk), "header": b64u(hdr), "attributes": attributes, "signature": b64u(signature)}


def verify_credential(cred: Any) -> bool:
    """Verify a whole credential against its issuer key (every attribute). Never raises (except a missing library)."""
    try:
        pk = decode_b64u_strict(cred["issuerPublicKey"])
        header = decode_b64u_strict(cred["header"])
        signature = decode_b64u_strict(cred["signature"])
        if pk is None or header is None or signature is None:
            return False
        return Bbs.verify(pk, signature, header, encode_all(cred["attributes"]))
    except Bls12LibraryMissing:
        raise
    except Exception:  # noqa: BLE001 - fail closed
        return False


def _index_of(attr: Any) -> int:
    """An integral JSON number as an int; raises otherwise."""
    if not isinstance(attr, dict):
        raise ValueError("not an object")
    i = attr.get("index")
    ok = (isinstance(i, int) and not isinstance(i, bool)) or (
        isinstance(i, float) and fin(i) and i == math.floor(i) and abs(i) <= 2 ** 31)
    if not ok:
        raise ValueError("attribute index is not an integer")
    return int(i)


def present_credential(cred: Dict[str, Any], disclose: Sequence[str], presentation_header: Optional[bytes] = None) -> Dict[str, Any]:
    """Selective-disclosure presentation revealing only the named attributes; presentation_header binds it to a context
    (None = empty). The proof is randomized."""
    pk = decode_b64u_strict(cred["issuerPublicKey"])
    header = decode_b64u_strict(cred["header"])
    signature = decode_b64u_strict(cred["signature"])
    if pk is None:
        raise ValueError("bad issuer key")
    if header is None:
        raise ValueError("bad header")
    if signature is None:
        raise ValueError("bad signature")
    ph = bytes(presentation_header or b"")
    wanted = list(dict.fromkeys(disclose))
    messages = encode_all(cred["attributes"])
    idx: List[int] = []
    disclosed: List[Dict[str, Any]] = []
    for a in cred["attributes"]:
        if a["name"] not in wanted:
            continue
        idx.append(_index_of(a))
        disclosed.append(a)
    missing = sorted(w for w in wanted if not any(d["name"] == w for d in disclosed))
    if missing:
        raise ValueError("presentCredential: unknown attribute(s): " + ", ".join(missing))
    proof = Bbs.proof_gen(pk, signature, header, ph, messages, idx)
    return {"issuerPublicKey": cred["issuerPublicKey"], "header": cred["header"], "presentationHeader": b64u(ph),
            "messageCount": len(cred["attributes"]), "disclosed": disclosed, "proof": b64u(proof)}


def verify_presentation(pres: Any, pk: Optional[bytes] = None, disclosed: Optional[Any] = None,
                        presentation_header: Optional[bytes] = None) -> bool:
    """Check a presentation. pk, disclosed and presentation_header default (when None) to the values the presentation carries; pass
    them to assert the verifier's own expectations. Never raises (except a missing library)."""
    try:
        pkb = pk if pk is not None else decode_b64u_strict(pres["issuerPublicKey"])
        header = decode_b64u_strict(pres["header"])
        proof = decode_b64u_strict(pres["proof"])
        if pkb is None or header is None or proof is None:
            return False
        if pk is not None and b64u(pk) != pres["issuerPublicKey"]:
            return False
        ph = presentation_header if presentation_header is not None else decode_b64u_strict(pres["presentationHeader"])
        if ph is None:
            return False
        if presentation_header is not None and len(presentation_header) > 0 and b64u(ph) != pres["presentationHeader"]:
            return False
        return _verify_inner(pres, pkb, header, proof, ph, disclosed)
    except Bls12LibraryMissing:
        raise
    except Exception:  # noqa: BLE001 - fail closed
        return False


def _disclosure_key(x: Any) -> str:
    if not isinstance(x, dict):
        raise ValueError("not an object")
    return "%d\0%s\0%s" % (_index_of(x), x.get("name"), x.get("value"))


def _same_disclosure(a: Any, b: Any) -> bool:
    if not (isinstance(a, list) and isinstance(b, list) and len(a) == len(b)):
        return False
    return sorted(_disclosure_key(x) for x in a) == sorted(_disclosure_key(x) for x in b)


def _verify_inner(pres: Dict[str, Any], pk: bytes, header: bytes, proof: bytes, ph: bytes, opts_disclosed: Optional[Any]) -> bool:
    disclosed = opts_disclosed if opts_disclosed is not None else pres["disclosed"]
    if opts_disclosed is not None and not _same_disclosure(opts_disclosed, pres["disclosed"]):
        return False
    if not isinstance(disclosed, list):
        raise ValueError("not an array")
    for o in disclosed:
        _index_of(o)  # an attribute without an integer index fails closed
    ordered = [t[2] for t in sorted(((_index_of(o), k, o) for k, o in enumerate(disclosed)), key=lambda t: (t[0], t[1]))]
    msgs = [encode(o) for o in ordered]
    idx = [_index_of(o) for o in ordered]
    count = pres.get("messageCount")
    if isinstance(count, bool) or not isinstance(count, (int, float)):
        count = None
    if any(i < 0 or (count is not None and i >= count) for i in idx):
        return False
    return Bbs.proof_verify(pk, proof, header, ph, msgs, idx)
