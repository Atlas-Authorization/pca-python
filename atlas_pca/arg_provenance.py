"""PROVENANCE BY DEFAULT (argument provenance): an agent cannot be steered by injected content into choosing who, where or
how much. Port of the TypeScript reference ``arg-provenance.ts`` (the decision order, the boundaries and the escalate reason
text are normative; ``conformance/arg-provenance-vectors.json`` pins them).

The model is CaMeL's (control flow and the values that reach a sensitive sink must derive from the principal, never from tool
output). The unit of provenance is a SEGMENT of the agent's context window:

  * a MEDIATOR (the agent harness, a gateway, an MCP client: whatever sees the bytes enter the context and holds a key the
    model cannot reach) appends one signed receipt per segment to a per-session hash chain: the principal's own message
    (``principal``), a tool result (``tool``), a retrieved document (``retrieval``), a fetched page (``web``), and finally the
    action the model chose (``action``, bound to the exact operation digest). :class:`ProvenanceRecorder` is that mediator side;
  * the verifier re-derives every label from that chain (:func:`decide_arg_provenance`). A receipt that does not verify under a
    pinned mediator key, a chain with a gap, or no chain at all leaves every value at ``agent`` (the top);
  * a value is TRUSTED when the context that produced it was purely principal, when it occurs verbatim (as a whole token) in a
    principal message whose bytes the receipt binds, or when the principal authorized the exact operation (a plan node);
  * the CHOICE of the action is trusted only when the context was purely principal or the principal committed to the step.

An action is SENSITIVE unless its facts say it only reads (effects exactly ``read``, traits within ``READ_SAFE_TRAITS``); an
unknown action is sensitive. A sensitive action whose choice or any sink argument is not trusted is ``escalate``; a forged
chain is ``deny``. ``authorize()`` runs this gate by default as check ``provenance_flow`` (distinct from the Intent v2 rule 17
check ``provenance``); the only opt-out is the grant envelope's signed ``provenance: {"mode": "insecure_off"}``.

Strings are compared in UTF-16 code units where the reference does (``occurs_as_token`` converts Python code points to UTF-16
code units first). Every decide function is total: malformed input fails closed.
"""
import json
import os
import re
import time
from typing import Any, Callable, Dict, List, Mapping, Optional

from .agent import KeyPair, PqKeyPair, generate_keypair, sign_artifact
from .intent_wb import (SUITE_MEMBERS, _closed_members, _is_bounded_string, _is_digest, _is_safe_int, _js_keys,
                        _sorted_utf8, _utf8_len, artifact_ref, artifact_suite_error, pin_pq_ok, _UNDEF, _get,
                        verify_artifact_sig)
from .pca import b64u, canonicalize_strict, hash_canonical, strict_parse

__all__ = [
    "PROV_RECEIPT_DOMAIN", "PROV_RECEIPT_REF_DOMAIN", "PROV_ACTION_DOMAIN", "PROV_HEADER", "PROV_BODY_MEMBER",
    "MAX_PROV_RECEIPTS", "MAX_PROV_CONTENT_BYTES", "MAX_PROV_LEAVES", "PROV_ORIGINS", "PROV_LEVELS", "READ_SAFE_TRAITS",
    "prov_action_digest", "prov_receipt_ref", "is_prov_mediator_pin", "prov_receipt_wire_error", "prov_action_info_error",
    "is_read_only_action", "occurs_as_token", "prov_leaves", "decide_arg_provenance", "prov_envelope_error",
    "ProvenanceRecorder", "create_provenance_recorder", "principal_direct_provenance", "read_provenance_bundle",
]

PROV_RECEIPT_DOMAIN = "atlas-pca/prov-receipt/v1\x00"
PROV_RECEIPT_REF_DOMAIN = "atlas-pca/prov-receipt-ref/v1"
PROV_ACTION_DOMAIN = "atlas-pca/prov-action/v1"
#: Request header carrying a bundle (base64url of its JSON); the JSON body member is ``pca_provenance``.
PROV_HEADER = "PCA-Provenance"
PROV_BODY_MEMBER = "pca_provenance"
MAX_PROV_RECEIPTS = 256
#: Largest principal message a bundle may carry (UTF-8 bytes).
MAX_PROV_CONTENT_BYTES = 65_536
#: Leaves examined per parameter; a larger value is not examined and keeps the context label.
MAX_PROV_LEAVES = 4096
_MAX_DEPTH = 32

PROV_ORIGINS = ("principal", "tool", "retrieval", "web", "action")
#: The label lattice: trusted < first_party < tool < web < agent.
PROV_LEVELS = ("trusted", "first_party", "tool", "web", "agent")
_RANK = {k: i for i, k in enumerate(PROV_LEVELS)}
#: The level a segment of each origin carries (``action`` contributes nothing: it is the model's own output).
_ORIGIN_LEVEL = {"principal": "trusted", "tool": "tool", "retrieval": "tool", "web": "web"}
_FLOORS = ("first_party", "tool", "agent")
#: Traits a read-only action may carry and still be non-sensitive.
READ_SAFE_TRAITS = ("pca.financial_data_read", "pca.pii_access", "pca.regulated_data")
_CONTENT_KEY_RE = re.compile(r"0|[1-9][0-9]{0,8}")  # always fullmatch


def _join(a: str, b: str) -> str:
    return a if _RANK[a] >= _RANK[b] else b


def _sort_u(xs) -> List[str]:
    return _sorted_utf8(set(xs))


# ---- wire --------------------------------------------------------------------------------------------------------------

def prov_action_digest(op: Mapping[str, Any]) -> str:
    """The digest an ``action`` receipt binds: the exact operation (verb, resource, params). Raises on a non-canonical op."""
    return hash_canonical({"d": PROV_ACTION_DOMAIN, "verb": op["verb"], "resource": op["resource"], "params": op["params"]})


def prov_receipt_ref(r: Any) -> str:
    """Content address of a receipt (signature included)."""
    return artifact_ref(PROV_RECEIPT_REF_DOMAIN, "r", r)


def is_prov_mediator_pin(k: Any) -> bool:
    """A well-formed mediator pin ``{mediator, kid, pk, pq_pk?}``."""
    return (isinstance(k, dict) and _closed_members(k, ("mediator", "kid", "pk"), ("pq_pk",)) is None
            and _is_bounded_string(k["mediator"], 256) and _is_bounded_string(k["kid"], 64) and _is_digest(k["pk"])
            and pin_pq_ok(_get(k, "pq_pk")))


_RECEIPT_FIELDS = ("v", "kind", "mediator", "kid", "session", "seq", "prev", "origin", "source", "content_digest", "issued_at",
                   "sig")


def prov_receipt_wire_error(r: Any) -> Optional[str]:
    """Wire validation of one receipt. None = well-formed."""
    if not isinstance(r, dict):
        return "a receipt must be an object"
    m = _closed_members(r, _RECEIPT_FIELDS, SUITE_MEMBERS, "receipt")
    if m:
        return m
    if not (r["v"] == 1 and not isinstance(r["v"], bool)) or r["kind"] != "pca-prov":
        return 'a receipt must be {v: 1, kind: "pca-prov"}'
    if not _is_bounded_string(r["mediator"], 256):
        return "'mediator' must be a non-empty string (<= 256 bytes)"
    if not _is_bounded_string(r["kid"], 64):
        return "'kid' must be a non-empty string (<= 64 bytes)"
    if not _is_digest(r["session"]):
        return "'session' must be canonical base64url (32 bytes)"
    if not _is_safe_int(r["seq"]) or r["seq"] < 0:
        return "'seq' must be a non-negative safe integer"
    if r["prev"] is not None and not _is_digest(r["prev"]):
        return "'prev' must be null or canonical base64url (32 bytes)"
    if not isinstance(r["origin"], str) or r["origin"] not in PROV_ORIGINS:
        return "'origin' must be one of %s" % ", ".join(PROV_ORIGINS)
    if not _is_bounded_string(r["source"], 256):
        return "'source' must be a non-empty string (<= 256 bytes)"
    if not _is_digest(r["content_digest"]):
        return "'content_digest' must be canonical base64url (32 bytes)"
    if not _is_safe_int(r["issued_at"]) or r["issued_at"] < 0:
        return "'issued_at' must be a non-negative safe integer"
    if not isinstance(r["sig"], str):
        return "'sig' must be a string"
    return artifact_suite_error(r)


def prov_action_info_error(a: Any) -> Optional[str]:
    """Validate action facts ``{effects?, traits?, params?}``. None = well-formed."""
    if not isinstance(a, dict):
        return "action info must be an object"
    m = _closed_members(a, (), ("effects", "traits", "params"), "action info")
    if m:
        return m
    for k in ("effects", "traits"):
        if k in a:
            v = a[k]
            if not (isinstance(v, list) and len(v) <= 64 and all(_is_bounded_string(x, 128) for x in v)):
                return "action info '%s' must be a list of strings" % k
    if "params" in a:
        if not isinstance(a["params"], dict):
            return "action info 'params' must be an object"
        for k in _js_keys(a["params"]):
            v = a["params"][k]
            if not _is_bounded_string(k, 128) or not isinstance(v, str) or v not in _FLOORS:
                return "action info param '%s' must map to first_party | tool | agent" % k
    return None


def is_read_only_action(a: Any) -> bool:
    """Is an action with these facts non-sensitive (it only reads)? Unknown facts (None) are sensitive."""
    if not isinstance(a, dict):
        return False
    effects = a.get("effects")
    if not isinstance(effects, list) or len(effects) == 0:
        return False
    if not all(e == "read" for e in effects):
        return False
    traits = a.get("traits")
    traits = [] if traits is None else traits
    return isinstance(traits, list) and all(isinstance(t, str) and t in READ_SAFE_TRAITS for t in traits)


# ---- tokens ------------------------------------------------------------------------------------------------------------

def _units(s: str) -> str:
    """The UTF-16 code units of a JS string, one Python character each (an astral character becomes its surrogate pair)."""
    if all(ord(c) < 0x10000 for c in s):
        return s
    out = []
    for c in s:
        o = ord(c)
        if o < 0x10000:
            out.append(c)
        else:
            o -= 0x10000
            out.append(chr(0xD800 + (o >> 10)))
            out.append(chr(0xDC00 + (o & 0x3FF)))
    return "".join(out)


def _is_word(c: str) -> bool:
    """ASCII letters, digits, ``_``, and every non-ASCII code unit (fail closed: fewer matches)."""
    o = ord(c)
    return 48 <= o <= 57 or 65 <= o <= 90 or 97 <= o <= 122 or o == 95 or o >= 0x80


def occurs_as_token(text: Any, needle: Any) -> bool:
    """Does ``needle`` occur in ``text`` as a whole token? An occurrence counts when the code unit before it is not a word
    character (or the needle starts with a non-word character), and likewise after it. Exact, case-sensitive, over UTF-16 code
    units; no normalization. An empty needle never occurs."""
    if not isinstance(text, str) or not isinstance(needle, str) or len(needle) == 0:
        return False
    t, n = _units(text), _units(needle)
    head_word, tail_word = _is_word(n[0]), _is_word(n[-1])
    i = t.find(n)
    while i >= 0:
        end = i + len(n)
        ok_b = not head_word or i == 0 or not _is_word(t[i - 1])
        ok_a = not tail_word or end == len(t) or not _is_word(t[end])
        if ok_b and ok_a:
            return True
        i = t.find(n, i + 1)
    return False


def prov_leaves(v: Any) -> Optional[List[str]]:
    """The text of every leaf of a value (strings as is, other scalars in strict canonical form, object keys included, JSON
    member order); None when deeper than 32, more than 4096 leaves, or not strict-canonical."""
    out: List[str] = []

    def walk(x: Any, depth: int) -> bool:
        if depth > _MAX_DEPTH or len(out) > MAX_PROV_LEAVES:
            return False
        if isinstance(x, str):
            out.append(x)
        elif isinstance(x, list):
            for y in x:
                if not walk(y, depth + 1):
                    return False
        elif isinstance(x, dict):
            for k in _js_keys(x):
                out.append(k)
                if not walk(x[k], depth + 1):
                    return False
        else:
            try:
                out.append(canonicalize_strict(x))
            except Exception:  # noqa: BLE001 - not canonical: the value is not examined
                return False
        return len(out) <= MAX_PROV_LEAVES

    return out if walk(v, 0) else None


# ---- decision ----------------------------------------------------------------------------------------------------------

def _operation_ok(op: Any) -> bool:
    return (isinstance(op, dict) and _is_bounded_string(op.get("verb"), 256) and isinstance(op.get("resource"), str)
            and isinstance(op.get("params"), dict))


def _verify_chain(bundle: Any, op: dict, pins: list) -> dict:
    """{"verified", "context", "path", "texts"} or {"code", "reason"} (a deny)."""
    unverified = {"verified": False, "context": "agent", "path": ["unlabelled"], "texts": []}
    if bundle is None or bundle is _UNDEF:
        return unverified

    def bad(code: str, reason: str) -> dict:
        return {"code": code, "reason": reason}

    if not isinstance(bundle, dict):
        return bad("malformed_bundle", "the bundle must be an object")
    m = _closed_members(bundle, ("v", "kind", "receipts"), ("contents",), "bundle")
    if m:
        return bad("malformed_bundle", m)
    if not (bundle["v"] == 1 and not isinstance(bundle["v"], bool)) or bundle["kind"] != "pca-provenance":
        return bad("malformed_bundle", 'the bundle must be {v: 1, kind: "pca-provenance"}')
    rs = bundle["receipts"]
    if not isinstance(rs, list) or len(rs) == 0 or len(rs) > MAX_PROV_RECEIPTS:
        return bad("malformed_bundle", "the bundle must hold 1..%d receipts" % MAX_PROV_RECEIPTS)
    for i, r in enumerate(rs):
        e = prov_receipt_wire_error(r)
        if e:
            return bad("malformed_bundle", "receipt %d: %s" % (i, e))
    contents = bundle["contents"] if "contents" in bundle else {}
    if not isinstance(contents, dict):
        return bad("malformed_bundle", "'contents' must be an object")
    first = rs[0]
    for i, r in enumerate(rs):
        if r["seq"] != i:
            return bad("broken_chain", "receipt %d has seq %s" % (i, r["seq"]))
        if r["session"] != first["session"] or r["mediator"] != first["mediator"] or r["kid"] != first["kid"]:
            return bad("broken_chain", "receipt %d belongs to another session or mediator" % i)
        if (r["prev"] is not None) if i == 0 else (r["prev"] != prov_receipt_ref(rs[i - 1])):
            return bad("broken_chain", "receipt %d does not link to its predecessor" % i)
        if i > 0 and r["issued_at"] < rs[i - 1]["issued_at"]:
            return bad("broken_chain", "receipt %d is older than its predecessor" % i)
    last = rs[-1]
    if last["origin"] != "action" or last["source"] != op["verb"] or last["content_digest"] != prov_action_digest(op):
        return bad("unbound_action", "the last receipt is not the action receipt of this operation")
    texts: List[str] = []
    for k in _js_keys(contents):
        text = contents[k]
        r = rs[int(k)] if _CONTENT_KEY_RE.fullmatch(k) and int(k) < len(rs) else None
        if r is None or r["origin"] != "principal":
            return bad("malformed_bundle", "contents '%s' does not name a principal receipt" % k)
        if not isinstance(text, str) or _utf8_len(text) > MAX_PROV_CONTENT_BYTES:
            return bad("malformed_bundle", "contents '%s' must be a string of at most %d bytes" % (k, MAX_PROV_CONTENT_BYTES))
        try:
            d = hash_canonical(text)
        except Exception:  # noqa: BLE001 - a lone surrogate is not canonical text
            return bad("content_mismatch", "contents '%s' is not canonical text" % k)
        if d != r["content_digest"]:
            return bad("content_mismatch", "contents '%s' does not hash to its receipt" % k)
        texts.append(text)
    pin = next((p for p in pins if p["mediator"] == first["mediator"] and p["kid"] == first["kid"]), None)
    # a chain from a mediator this verifier does not pin vouches for nothing: every value stays at the top (escalate, never allow)
    if pin is None:
        return unverified
    for i, r in enumerate(rs):
        if not verify_artifact_sig(PROV_RECEIPT_DOMAIN, r, pin):
            return bad("bad_signature", "receipt %d does not verify under the pinned mediator key" % i)
    before = [r for r in rs[:-1] if r["origin"] != "action"]
    context = "agent" if not before else "trusted"
    path: List[str] = []
    for r in before:
        context = _join(context, _ORIGIN_LEVEL[r["origin"]])
        if r["origin"] != "principal":
            path.append("%s:%s" % (r["origin"], r["source"]))
    if not before:
        path.append("unlabelled")
    return {"verified": True, "context": context, "path": _sort_u(path), "texts": texts}


def _obs_ok(o: Any) -> bool:
    return isinstance(o, dict) and o.get("origin") in ("tool", "retrieval", "web") and _is_bounded_string(o.get("source"), 256)


def decide_arg_provenance(input: Any) -> dict:
    """The provenance decision for one operation. ``input``: ``{"bundle"?, "operation": {verb, resource, params},
    "mediators": [pin], "action"?: facts (absent = unknown, sensitive), "principal_plan"?: bool, "principal_control"?: bool,
    "observed"?: [{origin, source}]}``. Returns ``{"outcome": pass|escalate|deny, "code"?, "reason"?, "sensitive", "verified",
    "control", "labels", "tainted", "path"}``. Steps, first failure wins:

      0. inputs well-formed, else ``deny`` (malformed_config / malformed_operation / malformed_action);
      1. the bundle (when present): wire, chain (contiguous seq, prev links, one session and mediator, non-decreasing
         issued_at), the last receipt is the ``action`` receipt of this operation, every principal content hashes to its
         receipt, every signature verifies under the pinned (mediator, kid). A failure is ``deny``. An unpinned mediator's
         chain is ignored (no trust). context = join of the non-action segments before the action (``agent`` when none);
      2. server observations join into context (raise only);
      3. control = ``trusted`` with principal_plan or principal_control, else context;
      4. each parameter: ``trusted`` with principal_plan; else the join over its leaves (a leaf the principal typed as a whole
         token is ``trusted``); no leaves is ``trusted``; too large to examine is context;
      5. floors: the facts' params[p], else ``first_party`` for a sensitive action and ``agent`` otherwise;
      6. a sensitive action whose control is not ``trusted``, or any tainted parameter, is ``escalate``; otherwise ``pass``.
    Never raises."""
    base: Dict[str, Any] = {"sensitive": True, "verified": False, "control": "agent", "labels": {}, "tainted": [], "path": []}

    def deny(code: str, reason: str) -> dict:
        return {**base, "outcome": "deny", "code": code, "reason": reason}

    try:
        if not isinstance(input, dict):
            return deny("malformed_config", "input must be an object")
        pins = input.get("mediators")
        if not isinstance(pins, list) or not all(is_prov_mediator_pin(p) for p in pins):
            return deny("malformed_config", "mediator pins must be a list of {mediator, kid, pk, pq_pk?}")
        op = input.get("operation")
        if not _operation_ok(op):
            return deny("malformed_operation", "the operation needs a verb, a resource and a params object")
        has_action = "action" in input
        action = input.get("action")
        if has_action:
            e = prov_action_info_error(action)
            if e:
                return deny("malformed_action", e)
        obs = input.get("observed")
        obs = [] if obs is None else obs
        if not isinstance(obs, list) or not all(_obs_ok(o) for o in obs):
            return deny("malformed_config", "observations must be a list of {origin, source}")
        sensitive = not is_read_only_action(action if has_action else None)
        base["sensitive"] = sensitive
        ch = _verify_chain(input.get("bundle"), op, pins)
        if "code" in ch:
            return deny(ch["code"], ch["reason"])
        base["verified"] = ch["verified"]
        context = ch["context"]
        path = list(ch["path"])
        for o in obs:
            context = _join(context, _ORIGIN_LEVEL[o["origin"]])
            path.append("%s:%s" % (o["origin"], o["source"]))
        base["path"] = _sort_u(path)
        plan = input.get("principal_plan") is True
        control = "trusted" if plan or input.get("principal_control") is True else context
        base["control"] = control
        labels: Dict[str, str] = {}
        params = op["params"]
        for p in _sort_u(params.keys()):
            if plan:
                labels[p] = "trusted"
                continue
            leaves = prov_leaves(params[p])
            if leaves is None:
                labels[p] = context
                continue
            lv = "trusted"
            for leaf in leaves:
                # a leaf the principal typed verbatim is the principal's choice whatever else the context held
                trusted = context == "trusted" or any(occurs_as_token(t, leaf) for t in ch["texts"])
                lv = _join(lv, "trusted" if trusted else context)
            labels[p] = lv
        base["labels"] = dict(labels)
        floors = (action.get("params") if has_action else None) or {}
        tainted = []
        for p in labels:
            f = floors[p] if p in floors else ("first_party" if sensitive else "agent")
            if _RANK[labels[p]] > _RANK[f]:
                tainted.append(p)
        base["tainted"] = _sort_u(tainted)
        # no segment origin maps to first_party, so a control label is trusted or untrusted
        bad_control = sensitive and control != "trusted"
        if not bad_control and not base["tainted"]:
            return {**base, "outcome": "pass"}
        where = " [%s]" % ", ".join(base["path"]) if base["path"] else ""
        code = ("untrusted_control_and_args" if bad_control and base["tainted"] else
                "untrusted_control" if bad_control else "untrusted_args")
        parts = []
        if bad_control:
            parts.append("the choice of %s derives from untrusted content" % op["verb"])
        if base["tainted"]:
            parts.append("%s %s from untrusted content" % (", ".join(base["tainted"]),
                                                            "derives" if len(base["tainted"]) == 1 else "derive"))
        return {**base, "outcome": "escalate", "code": code,
                "reason": "%s%s: the principal must confirm (prompt-injection path)" % ("; ".join(parts), where)}
    except Exception as e:  # noqa: BLE001 - total: fail closed
        return deny("malformed_config", "evaluation error (fail closed): %s" % type(e).__name__)


# ---- envelope ----------------------------------------------------------------------------------------------------------

def prov_envelope_error(p: Any) -> Optional[str]:
    """The grant envelope member ``provenance`` ``{mode?: "enforce" | "insecure_off", mediators?: [pin] (<= 16)}`` (signed by
    the principal with the rest of the grant). ``mediators`` are keys the PRINCIPAL designates; ``mode: "insecure_off"`` is the
    documented dangerous opt-out (the gate is not evaluated for this grant). None when well-formed."""
    if not isinstance(p, dict):
        return "provenance must be an object"
    m = _closed_members(p, (), ("mode", "mediators"), "provenance")
    if m:
        return m
    if "mode" in p and p["mode"] not in ("enforce", "insecure_off"):
        return "provenance.mode must be 'enforce' or 'insecure_off'"
    if "mediators" in p and not (isinstance(p["mediators"], list) and len(p["mediators"]) <= 16
                                 and all(is_prov_mediator_pin(x) for x in p["mediators"])):
        return "provenance.mediators must be at most 16 {mediator, kid, pk, pq_pk?}"
    return None


# ---- mediator side -----------------------------------------------------------------------------------------------------

def _text_of(c: Any) -> str:
    # shortcut: a non-string segment is recorded as compact JSON text; only principal text is ever compared across languages
    if isinstance(c, str):
        return c
    try:
        return json.dumps(c, separators=(",", ":"), ensure_ascii=False)
    except Exception:  # noqa: BLE001
        return str(c)


def _clip(s: str) -> str:
    """The reference's clip: halve by UTF-16 code units until <= 256 UTF-8 bytes; '' -> '-'. A cut inside a surrogate pair
    leaves a lone surrogate the strict canonicalizer refuses, so it raises (the receipt cannot be signed)."""
    while _utf8_len(s) > 256:
        n, u, out = max(1, sum(2 if ord(c) > 0xFFFF else 1 for c in s) // 2), 0, []
        for c in s:
            w = 2 if ord(c) > 0xFFFF else 1
            if u + w > n:
                if u < n:
                    raise ValueError("provenance: the source cannot be clipped without splitting a surrogate pair")
                break
            out.append(c)
            u += w
        s = "".join(out)
    return s if s else "-"


class ProvenanceRecorder:
    """The mediator side: one recorder per agent session. Run it where the bytes enter the model's context (the harness that
    builds the prompt, a gateway, an MCP client) with a key the model cannot reach. ``pin`` is what a verifier (or the
    principal's grant envelope, member ``provenance.mediators``) must carry for this recorder.

        rec = create_provenance_recorder(mediator="my-harness", kid="k1", secret_key=seed)
        rec.principal("Email the Q3 report to bob@acme.example")
        rec.tool("gmail.read", output)
        bundle = rec.for_action({"verb": "email.send", "resource": "mail", "params": {...}})   # send as PCA-Provenance
    """

    def __init__(self, mediator: str, kid: str, secret_key: Optional[bytes] = None, *, session: Optional[str] = None,
                 now: Optional[Callable[[], Any]] = None, alg: Optional[str] = None, pq: Optional[PqKeyPair] = None):
        if not _is_bounded_string(mediator, 256) or not _is_bounded_string(kid, 64):
            raise ValueError("ProvenanceRecorder: mediator (<= 256 bytes) and kid (<= 64 bytes) are required")
        self._key = KeyPair(secret_key) if secret_key is not None else generate_keypair()
        self.session = session if session is not None else b64u(os.urandom(32))
        if not _is_digest(self.session):
            raise ValueError("ProvenanceRecorder: session must be canonical base64url of 32 bytes")
        self._mediator, self._kid, self._alg, self._pq = mediator, kid, alg, pq
        self._now = now if now is not None else (lambda: int(time.time() * 1000))
        self._chain: List[dict] = []
        self._contents: Dict[str, str] = {}
        self.pin: Dict[str, str] = {"mediator": mediator, "kid": kid, "pk": self._key.public}
        if alg and alg != "ed25519":
            if pq is None:
                raise ValueError("ProvenanceRecorder: suite '%s' needs a PQ key pair" % alg)
            self.pin["pq_pk"] = pq.public

    def _append(self, origin: str, source: str, digest: str) -> dict:
        prev = self._chain[-1] if self._chain else None
        issued = max(prev["issued_at"] if prev else 0, int(self._now()))
        body = {"v": 1, "kind": "pca-prov", "mediator": self._mediator, "kid": self._kid, "session": self.session,
                "seq": len(self._chain), "prev": prov_receipt_ref(prev) if prev else None, "origin": origin,
                "source": _clip(source), "content_digest": digest, "issued_at": issued}
        r = sign_artifact(PROV_RECEIPT_DOMAIN, body, self._key, self._alg, self._pq)
        self._chain.append(r)
        return r

    def _segment(self, origin: str, source: str, content: Any) -> dict:
        text = _text_of(content)
        r = self._append(origin, source, hash_canonical(text))
        if origin == "principal" and _utf8_len(text) <= MAX_PROV_CONTENT_BYTES:
            self._contents[str(r["seq"])] = text
        return r

    def principal(self, text: str) -> dict:
        """The principal's own message (TRUSTED)."""
        return self._segment("principal", "user", text)

    def tool(self, name: str, output: Any) -> dict:
        """A tool result (UNTRUSTED). Non-string output is recorded as its JSON text."""
        return self._segment("tool", name, output)

    def retrieval(self, source: str, content: Any) -> dict:
        """A retrieved document (UNTRUSTED)."""
        return self._segment("retrieval", source, content)

    def web(self, url: str, content: Any) -> dict:
        """A fetched web page or HTTP response (UNTRUSTED)."""
        return self._segment("web", url, content)

    def for_action(self, op: Mapping[str, Any]) -> dict:
        """Record the chosen action and return the bundle to present with it (header ``PCA-Provenance`` or body member
        ``pca_provenance``, or ``authorize(provenance=...)``)."""
        if len(self._chain) >= MAX_PROV_RECEIPTS:
            raise ValueError("provenance: the session holds %d receipts; start a new session with the principal's message"
                             % MAX_PROV_RECEIPTS)
        self._append("action", op["verb"], prov_action_digest(op))
        out: Dict[str, Any] = {"v": 1, "kind": "pca-provenance", "receipts": list(self._chain)}
        if self._contents:
            out["contents"] = dict(self._contents)
        return out

    def receipts(self) -> List[dict]:
        return list(self._chain)


def create_provenance_recorder(*, mediator: str, kid: str, secret_key: Optional[bytes] = None, session: Optional[str] = None,
                               now: Optional[Callable[[], Any]] = None, alg: Optional[str] = None,
                               pq: Optional[PqKeyPair] = None) -> ProvenanceRecorder:
    """A :class:`ProvenanceRecorder` (``createProvenanceRecorder``). A fresh key when ``secret_key`` (32 bytes) is absent."""
    return ProvenanceRecorder(mediator, kid, secret_key, session=session, now=now, alg=alg, pq=pq)


def principal_direct_provenance(recorder: ProvenanceRecorder, op: Mapping[str, Any]) -> dict:
    """The bundle for an operation that came straight from the principal (the application's own UI acting on the user's
    explicit input, no model in between): one principal segment holding the operation, then the action."""
    recorder.principal(canonicalize_strict({"verb": op["verb"], "resource": op["resource"], "params": op["params"]}))
    return recorder.for_action(op)


def read_provenance_bundle(headers: Any, body: Any) -> Any:
    """The default bundle reader: header ``PCA-Provenance`` (strict base64url JSON; a header that does not decode or parse
    RAISES ``ValueError``: the gate then refuses, fail closed), else the JSON body member ``pca_provenance`` (an unparsable body
    is no bundle). None when absent."""
    from .server import _get_header, _to_text  # deferred: server imports authorize, which imports this module
    from .pca import decode_pca_header
    h = _get_header(headers, PROV_HEADER)
    if h is not None and h != "":
        return strict_parse(decode_pca_header(h))
    text = _to_text(body)
    if text is None:
        return None
    try:
        env = strict_parse(text)
    except Exception:  # noqa: BLE001
        return None
    return env.get(PROV_BODY_MEMBER) if isinstance(env, dict) else None
