"""Signed Agent Cards plus AgentFacts attested by PCA, the well-known hosting handlers and the registry entry. The card side
(RFC 8785 canonical bytes, the A2A 1.0 schema check, signing) is the one in ``a2a_card``: a card issued here verifies there and
back. Results are dicts shaped like the TypeScript reference (``@atlasauth/pca-agentcard``); handlers are plain functions over a
request path. Everything fails closed: a missing signature, an unresolvable key, a tampered body, a bad or expired attestation or
an attestation about another subject is refused.

shortcut: validity windows are parsed as ISO 8601 (``YYYY[-MM[-DD]]`` with an optional ``THH:mm[:ss[.fff]]`` and ``Z`` or
``+HH:mm``); a time without an offset reads as UTC and the legacy free-form date spellings a JavaScript runtime also accepts are
refused as not a valid date. Widen it if attestations come from issuers that use those."""
import re
from typing import Any, Callable, Dict, List, Optional

from . import a2a_card as _card
from ._fin import fin
from .a2a import iso_from_ms
from .a2a_card import UNDEFINED, jcs_bytes, spread, validate_agent_card1  # noqa: F401 - re-exported, as the reference does
from .oauth import _pct, _parse_url
from .oidc import create_local_jwk_set
from .pca import canonical_bytes_strict
from .sdjwt_jws import assert_canonical_jws_segments, js_json, js_to_string, jws_sign, node_b64url_decode, truthy

DEFAULT_ALG = "EdDSA"
AGENT_FACTS_CONTEXT = ("https://www.w3.org/ns/did/v1", "https://nanda.ai/agentfacts/v1")
PCA_ATTESTOR_ID = "did:atlas:pca-attestor"
WELL_KNOWN_AGENT_CARD_PATH = "/.well-known/agent-card.json"
WELL_KNOWN_AGENT_FACTS_PATH = "/.well-known/agent-facts.json"
_ATTESTATION_DOMAIN = "atlas-pca/agentfacts/attestation/v1"


def _get(o: Any, k: str) -> Any:
    if o is None or o is UNDEFINED:
        raise TypeError("Cannot read properties of %s (reading '%s')" % ("null" if o is None else "undefined", k))
    return o.get(k, UNDEFINED) if isinstance(o, dict) else UNDEFINED


def _present(o: Any, k: str) -> bool:
    return isinstance(o, dict) and k in o


def _nullish(v: Any, default: Any) -> Any:
    return default if v is None or v is UNDEFINED else v


# ---- detached JWS core -------------------------------------------------------------------------------------------------

def _sign_detached(payload: bytes, key: Any, alg: Any, kid: Any, header: Optional[dict], standard_payload: bool = False) -> Dict[str, str]:
    alg = DEFAULT_ALG if alg is None or alg is UNDEFINED else alg
    k = _card._signing_key(key, alg)
    h: Dict[str, Any] = {"alg": alg}
    if standard_payload:
        h["typ"] = "JOSE"
    else:
        h["b64"] = False
        h["crit"] = ["b64"]
    if kid is not UNDEFINED:
        h["kid"] = kid
    h.update(header or {})
    prot = _card._b64u(_card.js_json_bytes(h))
    body = _card._b64u(payload).encode("ascii") if standard_payload else payload
    return {"protected": prot, "signature": _card._b64u(jws_sign(alg, k, prot.encode("ascii") + b"." + body))}


def _resolve_verify_key(opts: dict) -> Dict[str, Any]:
    """{"key", "resolver"} or {"error"}: a JWKS (kid resolved) or a single key, never both."""
    try:
        if truthy(opts.get("jwks")):
            return {"key": create_local_jwk_set(opts["jwks"]), "resolver": True}
        if "key" in opts:
            k = opts["key"]
            alg = opts["alg"] if opts.get("alg") is not None else DEFAULT_ALG
            return {"key": _card._import_verify_key(k, alg) if _card._is_jwk(k) else k, "resolver": False}
        return {"error": "no verification key or JWKS supplied"}
    except Exception as e:  # noqa: BLE001 - an unusable key is a refusal, with the library's own words
        return {"error": "could not resolve verification key: %s" % e}


def _verify_detached(payload: bytes, sig: Any, resolved: dict) -> Dict[str, Any]:
    if sig is None or sig is UNDEFINED:
        raise TypeError("Cannot read properties of %s (reading 'protected')" % ("null" if sig is None else "undefined"))
    if not isinstance(sig, dict) or not isinstance(sig.get("protected"), str) or not isinstance(sig.get("signature"), str):
        return {"ok": False, "reason": "signature is malformed"}
    try:
        assert_canonical_jws_segments(sig["protected"], sig["signature"])  # canonical-spelling gate BEFORE the signature check
        header = _card._payload_header(sig["protected"])
        body: Any = payload if header.get("b64") is False else _card._b64u(payload)
        return {"ok": True, "protectedHeader": _card._flattened_verify(sig["protected"], body, sig["signature"], resolved["key"], resolved["resolver"])}
    except Exception as e:  # noqa: BLE001 - every refusal reads the same
        return {"ok": False, "reason": str(e)}


# ---- signed Agent Card -------------------------------------------------------------------------------------------------

def _passport_ref(p: Any, uri: Any) -> Dict[str, Any]:
    if not isinstance(p, dict):
        raise TypeError("Cannot use 'in' operator on a non-object")
    out: Dict[str, Any] = {}
    if "id" in p:
        out["id"] = p["id"]
    if "model_id" in p:  # a full AgentPassport: its own uri is not carried
        if uri is not UNDEFINED:
            out["uri"] = uri
    elif "uri" in p:
        out["uri"] = p["uri"]
    elif uri is not UNDEFINED:
        out["uri"] = uri
    return out


def build_agent_card(passport: Any, opts: dict) -> Dict[str, Any]:
    """An unsigned Agent Card whose metadata points at the PCA passport (``pcaPassport``) and, when given, the live proof
    endpoint (``pcaProof``). ``passport`` is a full passport or a bare ``{id, uri?}`` reference."""
    card: Dict[str, Any] = {}
    if "name" in opts:
        card["name"] = opts["name"]
    for k in ("description", "url", "version", "skills"):
        if k in opts:
            card[k] = opts[k]
    card["pcaPassport"] = _passport_ref(passport, opts.get("passportUri", UNDEFINED))
    if "pcaProofRef" in opts:
        card["pcaProof"] = opts["pcaProofRef"]
    return card


def issue_signed_agent_card(card: dict, signing_key: Any, opts: Optional[dict] = None) -> Dict[str, Any]:
    """Sign a card: the passport reference is embedded and committed in the protected header, the canonical card (minus
    ``signatures``) is signed and the detached-payload signature appended. Wire-identical to ``a2a_card.issue_signed_agent_card``."""
    return _card.issue_signed_agent_card(card, signing_key, opts)


def verify_agent_card(card: Any, opts: dict) -> Dict[str, Any]:
    """Validate a card against its signature(s): no signatures, an unresolvable key or ANY signature that does not verify over
    the canonical card (minus ``signatures``) refuses. ``opts``: ``jwks``, ``key``, ``alg``, ``schema``. On success the result names
    the passport id the signature commits to and the passport and proof pointers from the card body."""
    if card is None or not isinstance(card, (dict, list)):
        return {"ok": False, "reason": "agent card is not an object"}
    signatures = card.get("signatures") if isinstance(card, dict) else None
    if not isinstance(signatures, list) or len(signatures) == 0:
        return {"ok": False, "reason": "agent card carries no signatures"}
    if opts.get("schema") == "a2a-1.0":
        problems = validate_agent_card1(card)
        if problems:
            return {"ok": False, "reason": "agent card does not match the A2A 1.0 schema: " + "; ".join(problems)}
    resolved = _resolve_verify_key(opts)
    if "error" in resolved:
        return {"ok": False, "reason": resolved["error"]}
    try:
        payload = _card._card_bytes(card)
    except TypeError as e:
        return {"ok": False, "reason": "agent card has no canonical form: %s" % e}
    passport_ref: Optional[str] = None
    for i, sig in enumerate(signatures):
        if not truthy(sig):
            return {"ok": False, "reason": "signature %d is missing" % i}
        res = _verify_detached(payload, sig, resolved)
        if not res["ok"]:
            return {"ok": False, "reason": "signature %d did not verify: %s" % (i, res["reason"])}
        ref = res["protectedHeader"].get(_card.PCA_PASSPORT_HEADER)
        if isinstance(ref, str) and passport_ref is None:
            passport_ref = ref
    out: Dict[str, Any] = {"ok": True}
    if passport_ref is not None:
        out["passportRef"] = passport_ref
    if truthy(card.get("pcaPassport")):
        out["passport"] = card["pcaPassport"]
    if truthy(card.get("pcaProof")):
        out["pcaProof"] = card["pcaProof"]
    return out


# ---- dates -------------------------------------------------------------------------------------------------------------

_ISO = re.compile(r"([+-]\d{6}|\d{4})(?:-(\d{2})(?:-(\d{2}))?)?"
                  r"(?:T(\d{2}):(\d{2})(?::(\d{2})(?:\.(\d+))?)?(Z|[+-]\d{2}:\d{2})?)?")


def _days_from_civil(y: int, m: int, d: int) -> int:
    y -= m <= 2
    era = y // 400
    yoe = y - era * 400
    doy = (153 * (m + (-3 if m > 2 else 9)) + 2) // 5 + d - 1
    return era * 146097 + yoe * 365 + yoe // 4 - yoe // 100 + doy - 719468


def date_parse(s: Any) -> Optional[float]:
    """``Date.parse`` for the ISO 8601 spellings (epoch milliseconds), None for anything else (``NaN`` in the reference)."""
    if not isinstance(s, str):
        return None
    m = _ISO.fullmatch(s)
    if m is None:
        return None
    ys, mo, d, hh, mi, ss, frac, tz = m.groups()
    y = int(ys)
    if ys == "-000000":
        return None
    mo_i, d_i = int(mo) if mo else 1, int(d) if d else 1
    h_i, mi_i, s_i = int(hh) if hh else 0, int(mi) if mi else 0, int(ss) if ss else 0
    ms = int((frac + "00")[:3]) if frac else 0
    if not 1 <= mo_i <= 12 or not 1 <= d_i <= 31 or mi_i > 59 or s_i > 59 or h_i > 24 or (h_i == 24 and (mi_i or s_i or ms)):
        return None
    off = 0
    if tz and tz != "Z":
        oh, om = int(tz[1:3]), int(tz[4:6])
        if oh > 23 or om > 59:
            return None
        off = (oh * 60 + om) * (1 if tz[0] == "+" else -1)
    t = (_days_from_civil(y, mo_i, d_i) * 86400 + h_i * 3600 + mi_i * 60 + s_i) * 1000 + ms - off * 60000
    return float(t) if abs(t) <= 8.64e15 else None


# ---- AgentFacts --------------------------------------------------------------------------------------------------------

def _statement_bytes(a: dict) -> bytes:
    return canonical_bytes_strict({"d": _ATTESTATION_DOMAIN, "issuer": a.get("issuer", UNDEFINED), "subject": a.get("subject", UNDEFINED),
                                   "attests": a.get("attests", UNDEFINED), "validFrom": a.get("validFrom", UNDEFINED),
                                   "validUntil": a["validUntil"] if "validUntil" in a else None})


def _sign_attestation(statement: dict, key: Any, opts: dict) -> Dict[str, Any]:
    sig = _sign_detached(_statement_bytes(statement), key, opts.get("alg"), opts["kid"] if "kid" in opts else UNDEFINED,
                         {"attestor": statement["issuer"]})
    return dict(statement, signature=sig)


def _statement(issuer: Any, subject: Any, opts: dict) -> Dict[str, Any]:
    valid_from = opts.get("validFrom", UNDEFINED)
    if valid_from is None or valid_from is UNDEFINED:
        valid_from = iso_from_ms(_nullish(opts.get("now", UNDEFINED), _now_ms()))
    st: Dict[str, Any] = {"issuer": issuer, "subject": subject, "attests": opts.get("attests", UNDEFINED), "validFrom": valid_from}
    if "validUntil" in opts:
        st["validUntil"] = opts["validUntil"]
    return st


def _now_ms() -> int:
    import time
    return int(time.time() * 1000)


def issue_agent_facts(passport: Any, opts: dict) -> Dict[str, Any]:
    """An AgentFacts document with PCA as the THIRD-PARTY ATTESTOR: the agent's ``selfAsserted`` claims are carried verbatim and
    unsigned, the ``attests`` claims are wrapped in a signed statement (issuer, subject, validity). ``opts``: ``attestorKey``,
    ``attests``, ``selfAsserted``, ``attestorId``, ``agentId``, ``alg``, ``kid``, ``validFrom``, ``validUntil``, ``now``, ``context``."""
    agent_id = opts.get("agentId", UNDEFINED)
    if agent_id is None or agent_id is UNDEFINED:
        agent_id = _get(passport, "id")
    st = _statement(_nullish(opts.get("attestorId", UNDEFINED), PCA_ATTESTOR_ID), agent_id, opts)
    att = _sign_attestation(st, opts.get("attestorKey"), opts)
    out: Dict[str, Any] = {"@context": list(_nullish(opts.get("context", UNDEFINED), AGENT_FACTS_CONTEXT)), "id": agent_id,
                           "type": "AgentFacts", "selfAsserted": _nullish(opts.get("selfAsserted", UNDEFINED), {}), "attestations": [att]}
    return {k: v for k, v in out.items() if v is not UNDEFINED}


def add_attestation(facts: Any, opts: dict) -> Dict[str, Any]:
    """A copy of an AgentFacts document with one more third-party attestation (several attestors vouch for different claims)."""
    st = _statement(_nullish(opts.get("attestorId", UNDEFINED), PCA_ATTESTOR_ID), _get(facts, "id"), opts)
    att = _sign_attestation(st, opts.get("attestorKey"), opts)
    existing = _get(facts, "attestations")
    if isinstance(existing, list):
        prior: List[Any] = list(existing)
    elif isinstance(existing, str):
        prior = list(spread(existing).values())
    else:
        raise TypeError("facts.attestations is not iterable")
    out = spread(facts)
    out["attestations"] = prior + [att]
    return out


def _missing_check(a: Any) -> Dict[str, Any]:
    issuer = a["issuer"] if isinstance(a, dict) and isinstance(a.get("issuer"), str) else "<unknown>"
    return {"issuer": issuer, "ok": False, "reason": "no verification key or JWKS supplied"}


def _verify_one(a: Any, doc_id: Any, now: Any, resolved: Optional[dict]) -> Dict[str, Any]:
    issuer = a["issuer"] if isinstance(a, dict) and isinstance(a.get("issuer"), str) else "<unknown>"
    if not isinstance(a, dict) or not isinstance(a.get("subject"), str) or not isinstance(a.get("attests"), dict) or not isinstance(a.get("validFrom"), str):
        return {"issuer": issuer, "ok": False, "reason": "attestation is malformed"}
    if a["subject"] != doc_id or not isinstance(doc_id, str):
        return {"issuer": issuer, "ok": False,
                "reason": "attestation subject '%s' does not match agent id '%s'" % (a["subject"], "undefined" if doc_id is UNDEFINED else js_to_string(doc_id))}
    start = date_parse(a["validFrom"])
    if start is None:
        return {"issuer": issuer, "ok": False, "reason": "attestation validFrom is not a valid date"}
    if not (fin(now) and now >= start):
        return {"issuer": issuer, "ok": False, "reason": "attestation is not yet valid"}
    if "validUntil" in a:
        until = date_parse(a["validUntil"])
        if until is None:
            return {"issuer": issuer, "ok": False, "reason": "attestation validUntil is not a valid date"}
        if not (fin(now) and now <= until):
            return {"issuer": issuer, "ok": False, "reason": "attestation has expired"}
    if resolved is None:
        return {"issuer": issuer, "ok": False, "reason": "no verification key or JWKS supplied"}
    res = _verify_detached(_statement_bytes(a), a.get("signature", UNDEFINED), resolved)
    if not res["ok"]:
        return {"issuer": issuer, "ok": False, "reason": "signature did not verify: %s" % res["reason"]}
    return {"issuer": issuer, "ok": True, "attests": a["attests"]}


def verify_agent_facts(facts: Any, opts: dict) -> Dict[str, Any]:
    """Verify an AgentFacts document, failing closed: an attestation about another subject, outside its validity window or whose
    detached signature does not verify refuses, and any one failure fails the whole document. On success the result separates the
    claims a third party ATTESTS from those only SELF-ASSERTED (flagged, never promoted). ``opts``: ``jwks``, ``key``, ``alg``,
    ``now`` (epoch ms)."""
    sa_raw = _get(facts, "selfAsserted")
    self_asserted = sa_raw if isinstance(sa_raw, dict) else {}
    now = _nullish(opts.get("now", UNDEFINED), _now_ms())
    doc_id = _get(facts, "id")
    base: Dict[str, Any] = {"ok": False, "attestations": [], "attested": {}, "selfAsserted": self_asserted, "claims": {}}
    if doc_id is not UNDEFINED:
        base["agentId"] = doc_id
    lst = _get(facts, "attestations")
    if not isinstance(lst, list):
        return dict(base, reason="agent facts has no attestations array")
    resolved: Optional[dict] = None
    if lst:
        r = _resolve_verify_key(opts)
        if "error" in r:
            return dict(base, reason=r["error"], attestations=[_missing_check(a) for a in lst])
        resolved = r
    checks: List[dict] = []
    attested: Dict[str, Any] = {}
    all_ok = True
    for a in lst:
        c = _verify_one(a, doc_id, now, resolved)
        checks.append(c)
        if not c["ok"]:
            all_ok = False
            continue
        attested.update(c["attests"])
    claims: Dict[str, str] = {k: "self-asserted" for k in self_asserted}
    claims.update({k: "attested" for k in attested})  # attested wins on overlap
    out = dict(base, ok=all_ok, attestations=checks, attested=attested, claims=claims)
    if not all_ok:
        out["reason"] = "one or more attestations did not verify"
    return out


# ---- well-known hosting ------------------------------------------------------------------------------------------------

def _json_response(value: Any) -> Dict[str, Any]:
    return {"status": 200, "headers": {"content-type": "application/json", "cache-control": "no-store"}, "body": js_json(value)}


def _normalize_path(path: str) -> str:
    q = path.find("?")
    no_query = path if q == -1 else path[:q]
    return no_query[:-1] if len(no_query) > 1 and no_query.endswith("/") else no_query


def _handler(value: Any, path: str) -> Callable[[str], Optional[Dict[str, Any]]]:
    target = _normalize_path(path)
    response = _json_response(value)
    return lambda req_path: response if _normalize_path(req_path) == target else None


def agent_card_handler(card: Any, path: str = WELL_KNOWN_AGENT_CARD_PATH) -> Callable[[str], Optional[Dict[str, Any]]]:
    """A handler serving the signed card at the well-known path; it returns None for any other path so it composes in a router."""
    return _handler(card, path)


def agent_facts_handler(facts: Any, path: str = WELL_KNOWN_AGENT_FACTS_PATH) -> Callable[[str], Optional[Dict[str, Any]]]:
    """A handler serving the AgentFacts document at the well-known path; None for any other path."""
    return _handler(facts, path)


# ---- registry entry ----------------------------------------------------------------------------------------------------

_SPECIAL = ("ftp", "file", "http", "https", "ws", "wss")
_USERINFO_ENC = "\"<>`{}?/:;=@[\\]^|"


def _well_known_url(service_url: Any, path: str) -> Optional[str]:
    """``new URL(path, serviceUrl).toString()`` for an absolute path: the base's scheme, credentials and host with the path; None
    where the platform URL class would refuse (an invalid base, or one that cannot be a base)."""
    if not isinstance(service_url, str):
        return None
    r = _parse_url(service_url)
    if r is None:
        return None
    text = re.sub(r"[\t\n\r]", "", re.sub(r"^[\x00-\x20]+|[\x00-\x20]+$", "", service_url))
    scheme = r["scheme"]
    rest = text[text.index(":") + 1:]
    special = scheme in _SPECIAL
    if not special and not rest.startswith("//"):
        return None
    body = re.sub(r"^[/\\]+", "", rest) if special and scheme != "file" else rest[2:]
    authority = re.split(r"[/\\?#]", body, maxsplit=1)[0] if special else re.split(r"[/?#]", body, maxsplit=1)[0]
    userinfo = ""
    if "@" in authority and scheme != "file":
        user, sep, pw = authority.rpartition("@")[0].partition(":")
        userinfo = _pct(user, _USERINFO_ENC) + (":" + _pct(pw, _USERINFO_ENC) if pw else "") + "@"
        if not user and not pw:
            userinfo = ""
    return "%s://%s%s%s" % (scheme, userinfo, r["host"], path)


def to_registry_entry(card: Any, facts: Any) -> Dict[str, Any]:
    """The entry for an A2A registry or NANDA index from a signed card and an AgentFacts document, with the split of claim names a
    third party ATTESTS from those only SELF-ASSERTED. Purely structural: a registry re-verifies on ingest."""
    attested: Dict[str, None] = {}
    atts = _get(facts, "attestations")
    if atts is None or atts is UNDEFINED:
        atts = []
    if isinstance(atts, str):
        atts = []  # a string iterates characters, none of which carries claims
    if not isinstance(atts, list):
        raise TypeError("facts.attestations is not iterable")
    for a in atts:
        if truthy(a) and isinstance(a, dict) and isinstance(a.get("attests"), dict):
            for k in a["attests"]:
                attested[k] = None
    sa = _get(facts, "selfAsserted")
    self_only = [k for k in (sa if isinstance(sa, dict) else {}) if k not in attested]
    url = _get(card, "url")
    card_url = _well_known_url(url, WELL_KNOWN_AGENT_CARD_PATH) if url is not UNDEFINED else None
    entry: Dict[str, Any] = {"id": _get(facts, "id"), "name": _get(card, "name")}
    for k in ("url", "version", "skills"):
        v = _get(card, k)
        entry[k] = v
    for k, out in (("pcaPassport", "passport"), ("pcaProof", "pcaProof")):
        v = _get(card, k)
        if v is not UNDEFINED and truthy(v):  # an absent member is undefined
            entry[out] = v
    entry["card"] = card
    if card_url is not None:
        entry["agentCardUrl"] = card_url
    entry["facts"] = facts
    entry["attestedClaims"] = list(attested)
    entry["selfAssertedClaims"] = self_only
    return {k: v for k, v in entry.items() if v is not UNDEFINED}
