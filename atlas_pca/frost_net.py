"""Networked FROST(Ed25519) signing, the pure parts: the ALLOW TOKEN (a policy authority's Ed25519 signature over the canonical JSON of a body that binds
sha256(message), the group key and an optional window), the signer PROOF OF POSSESSION (a Schnorr proof under the verification share, domain
``pca.frost.signer-pop.v1``, that gates enrollment and stops a rogue key), the EQUIVOCATION GUARD (a second different message for the same session / round /
signer is refused) and the strict wire decoders. A port of the reference ``frost-net`` module. The signer service and the coordinator are the same module's
second half. Randomness (a default allow-token nonce, a PoP nonce) comes from the ``random_bytes`` argument (default ``os.urandom``)."""
from __future__ import annotations

import hashlib
import math
from ._fin import fin
import os
import threading
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Callable, Dict, List, Optional

from . import frost as F
from .agent import KeyPair
from .intent_v2 import _UNDEF, _js_string
from .pca import b64u, canonical_bytes_strict, decode_b64u_strict, verify_b64u

__all__ = ["ALLOW_TOKEN_TYP", "SIGNER_POP_DST", "MAX_FROST_SIGNING_SET", "frost_action_digest", "issue_allow_token", "verify_allow_token", "create_signer_pop",
           "verify_signer_pop", "PoPError", "enroll_verification_shares", "EquivocationError", "EquivocationGuard", "decode_commitment", "decode_commitments",
           "decode_verification_shares", "GuardianSignerService", "NetworkCoordinator", "CoordinatorError", "CoordinatorTimeoutError"]

ALLOW_TOKEN_TYP = "pca.frost.allow.v1"
SIGNER_POP_DST = "pca.frost.signer-pop.v1"
MAX_FROST_SIGNING_SET = 256
_ZERO = bytes(32)


def _is_id(x: Any) -> bool:
    return not isinstance(x, bool) and isinstance(x, int) and 0 < x <= 9007199254740991


def _is_bytes32(x: Any) -> bool:
    return isinstance(x, (bytes, bytearray)) and len(x) == 32


def frost_action_digest(message: bytes) -> str:
    """base64url(sha256(message)): what an allow token authorises."""
    if not isinstance(message, (bytes, bytearray)):
        raise TypeError("frostActionDigest: message must be bytes")
    return b64u(hashlib.sha256(bytes(message)).digest())


def issue_allow_token(policy_secret: bytes, opts: dict, random_bytes: Callable[[int], bytes] = os.urandom) -> Dict[str, Any]:
    """An allow token signed by the policy authority: ``{"body": {typ, action_digest, group_pk, nonce, not_before?, expires_at?}, "authority", "sig"}``.
    ``opts``: ``message`` or ``frostActionDigest``, ``groupPublicKey``, ``nonce`` (default one 32-byte random draw), ``notBefore``, ``expiresAt``."""
    digest = opts.get("frostActionDigest")
    if digest is None:
        digest = frost_action_digest(opts["message"]) if opts.get("message") is not None else None
    if not digest:
        raise ValueError("issueAllowToken: provide message or frostActionDigest")
    nonce = opts.get("nonce")
    body: Dict[str, Any] = {"typ": ALLOW_TOKEN_TYP, "action_digest": digest, "group_pk": b64u(bytes(opts["groupPublicKey"])),
                            "nonce": nonce if nonce is not None else b64u(random_bytes(32))}
    if opts.get("notBefore") is not None:
        body["not_before"] = opts["notBefore"]
    if opts.get("expiresAt") is not None:
        body["expires_at"] = opts["expiresAt"]
    ed = KeyPair(bytes(policy_secret), allow_insecure_signer=True)
    return {"body": body, "authority": ed.public, "sig": b64u(ed.sign(canonical_bytes_strict(body)))}


def verify_allow_token(token: Any, expect: dict) -> Dict[str, Any]:
    """Check an allow token under the TRUSTED policy authority key (never under ``token.authority``): shape, typ, signature, group key, action digest, time
    window. ``expect`` = {policyAuthorityPublicKey, groupPublicKey, message, now}. ``{"ok": True}`` or ``{"ok": False, "reason"}``; never raises."""
    try:
        if not isinstance(token, (dict, list)):
            return {"ok": False, "reason": "allow token missing or malformed"}
        t = token if isinstance(token, dict) else {}
        body = t.get("body")
        if not isinstance(body, (dict, list)):
            return {"ok": False, "reason": "allow token has no body"}
        b = body if isinstance(body, dict) else {}
        if b.get("typ") != ALLOW_TOKEN_TYP:
            return {"ok": False, "reason": "allow token wrong typ (%s)" % _js_string(b.get("typ", _UNDEF))}
        if not isinstance(t.get("sig"), str):
            return {"ok": False, "reason": "allow token missing signature"}
        sig = decode_b64u_strict(t["sig"], 64)
        if sig is None:
            return {"ok": False, "reason": "allow token signature not canonical base64url"}
        try:
            trusted = verify_b64u(b64u(bytes(expect["policyAuthorityPublicKey"])), canonical_bytes_strict(body), b64u(sig))
        except Exception:  # noqa: BLE001
            trusted = False
        if not trusted:
            return {"ok": False, "reason": "allow token not signed by the trusted policy authority"}
        if b.get("group_pk") != b64u(bytes(expect["groupPublicKey"])):
            return {"ok": False, "reason": "allow token authorizes a different group key"}
        if b.get("action_digest") != frost_action_digest(expect["message"]):
            return {"ok": False, "reason": "allow token authorizes a different action digest"}
        now = expect["now"]
        if isinstance(now, bool) or not isinstance(now, (int, float)) or not fin(now):
            return {"ok": False, "reason": "invalid verification time"}
        if b.get("not_before") is not None and now < b["not_before"]:
            return {"ok": False, "reason": "allow token not yet valid"}
        if b.get("expires_at") is not None and now >= b["expires_at"]:
            return {"ok": False, "reason": "allow token expired"}
        return {"ok": True}
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "reason": "allow token verification error (fail closed): %s" % (str(e) or "unknown")}


# ---- signer proof of possession ----

def _pop_challenge(group_public_key: bytes, identifier: int, pk: bytes, r: bytes) -> bytes:
    e = F.reduce_bytes(hashlib.sha512(SIGNER_POP_DST.encode("utf-8") + bytes(group_public_key) + F.int_scalar(identifier) + pk + r).digest())
    return F.int_scalar(1) if e == _ZERO else e


def create_signer_pop(identifier: Any, share: Any, opts: dict, random_bytes: Callable[[int], bytes] = os.urandom) -> Dict[str, Any]:
    """The signer's proof of possession of its verification share's secret: ``{"identifier", "publicKey", "R", "s"}`` (base64url). ``opts``: ``groupPublicKey``
    and ``nonce`` (a fixed 32-byte nonce for reproducible vectors; random otherwise, redrawn while it reduces to zero)."""
    if not _is_id(identifier):
        raise ValueError("createSignerPoP: identifier must be a positive integer")
    if not _is_bytes32(share):
        raise ValueError("createSignerPoP: share must be 32 bytes")
    gpk = opts.get("groupPublicKey")
    if not _is_bytes32(gpk):
        raise ValueError("createSignerPoP: groupPublicKey must be 32 bytes")
    x = F.bytes_to_scalar(share)
    pk = F._enc(F._mul_base(x))
    k = F.bytes_to_scalar(opts["nonce"]) if opts.get("nonce") is not None else _ZERO
    while k == _ZERO:
        k = F.bytes_to_scalar(random_bytes(32))
    r = F._enc(F._mul_base(k))
    e = _pop_challenge(bytes(gpk), identifier, pk, r)
    s = F.sc_add(k, F.sc_mul(e, x))
    return {"identifier": identifier, "publicKey": b64u(pk), "R": b64u(r), "s": b64u(s)}


def verify_signer_pop(pop: Any, expect: dict) -> bool:
    """Verify a proof of possession against the group key: strict point decoding of the key and R, a canonical s, then s*B == R + e*PK. Never raises."""
    try:
        if not pop or not isinstance(pop, dict):
            return False
        if not _is_id(pop.get("identifier")):
            return False
        gpk = expect.get("groupPublicKey")
        if not _is_bytes32(gpk):
            return False
        pk, rb, sb = (decode_b64u_strict(pop.get(k), 32) for k in ("publicKey", "R", "s"))
        if pk is None or rb is None or sb is None:
            return False
        pk_pt, r_pt = F.decode_safe_point(pk), F.decode_safe_point(rb)
        if not F.is_canonical_scalar(sb):
            return False  # s and s + L must not both verify
        e = _pop_challenge(bytes(gpk), pop["identifier"], pk, rb)
        lhs = F._mul_base(F.bytes_to_scalar(sb))
        rhs = F._padd(r_pt, F._mul_pt(pk_pt, e))
        return lhs == rhs
    except Exception:  # noqa: BLE001
        return False


class PoPError(Exception):
    """An enrollment refused: ``identifier`` names the signer (when one is to blame)."""

    def __init__(self, message: str, identifier: Optional[int] = None) -> None:
        super().__init__(message)
        if identifier is not None:
            self.identifier = identifier


def enroll_verification_shares(enrollments: Any, expect: dict) -> List[Dict[str, Any]]:
    """The verification shares of a signer set, each admitted only with a valid proof of possession (a rogue key is refused). ``enrollments`` =
    [{"identifier", "publicKey" (32 bytes), "pop"}]. Raises :class:`PoPError` naming the identifier."""
    if not isinstance(enrollments, list) or len(enrollments) == 0:
        raise PoPError("enrollVerificationShares: no signer enrollments")
    gpk = expect.get("groupPublicKey")
    if not _is_bytes32(gpk):
        raise PoPError("enrollVerificationShares: groupPublicKey must be 32 bytes")
    out: List[Dict[str, Any]] = []
    seen = set()
    for e in enrollments:
        if not e or not _is_id(e.get("identifier") if isinstance(e, dict) else None):
            raise PoPError("enrollVerificationShares: enrollment with invalid identifier")
        i = e["identifier"]
        if i in seen:
            raise PoPError("enrollVerificationShares: duplicate enrollment for signer %d" % i, i)
        seen.add(i)
        if not _is_bytes32(e.get("publicKey")):
            raise PoPError("enrollVerificationShares: signer %d verification share must be 32 bytes" % i, i)
        pop = e.get("pop")
        if not pop or not isinstance(pop, dict) or pop.get("identifier") != i or pop.get("publicKey") != b64u(bytes(e["publicKey"])):
            raise PoPError("enrollVerificationShares: signer %d missing or mismatched proof-of-possession (rogue key rejected)" % i, i)
        if not verify_signer_pop(pop, {"groupPublicKey": gpk}):
            raise PoPError("enrollVerificationShares: signer %d invalid proof-of-possession (rogue key rejected)" % i, i)
        out.append({"identifier": i, "publicKey": bytes(e["publicKey"])})
    return out


# ---- equivocation guard ----

class EquivocationError(Exception):
    """A signer sent two different messages for the same session and round."""

    def __init__(self, session_id: str, round_: int, identifier: int, previous_digest: str, offending_digest: str) -> None:
        super().__init__("equivocation: signer %d sent two different messages for session '%s' round %d" % (identifier, session_id, round_))
        self.session_id, self.round, self.identifier = session_id, round_, identifier
        self.previousDigest, self.offendingDigest = previous_digest, offending_digest


class EquivocationGuard:
    """Remembers the digest of the first message seen per (session, round, signer): the same message again is fine, a different one raises and stays
    refused. ``forget(session_id)`` clears a finished session."""

    def __init__(self) -> None:
        self._seen: Dict[str, str] = {}

    def observe(self, session_id: Any, round_: Any, identifier: Any, message: Any) -> None:
        if not isinstance(session_id, str) or not session_id:
            raise ValueError("EquivocationGuard: session_id must be a non-empty string")
        if isinstance(round_, bool) or not isinstance(round_, int) or round_ < 1:
            raise ValueError("EquivocationGuard: round must be a positive integer")
        if not _is_id(identifier):
            raise ValueError("EquivocationGuard: identifier must be a positive integer")
        key = "%s\u0000%d\u0000%d" % (session_id, round_, identifier)
        digest = b64u(hashlib.sha256(canonical_bytes_strict(message)).digest())
        prev = self._seen.get(key)
        if prev is None:
            self._seen[key] = digest
        elif prev != digest:
            raise EquivocationError(session_id, round_, identifier, prev, digest)

    def forget(self, session_id: str) -> None:
        prefix = "%s\u0000" % session_id
        for k in [k for k in self._seen if k.startswith(prefix)]:
            del self._seen[k]


# ---- wire decoding ----

def decode_commitment(w: Any) -> Dict[str, Any]:
    """A round-1 commitment from its wire form {identifier, hiding, binding} (base64url, 32 bytes each; not validated as points here)."""
    if not w or not isinstance(w, dict):
        raise ValueError("bad commitment")
    hiding, binding = decode_b64u_strict(w.get("hiding"), 32), decode_b64u_strict(w.get("binding"), 32)
    if not _is_id(w.get("identifier")):
        raise ValueError("bad commitment identifier")
    if hiding is None or binding is None:
        raise ValueError("bad commitment point encoding")
    return {"identifier": w["identifier"], "hiding": hiding, "binding": binding}


def decode_commitments(lst: Any) -> List[Dict[str, Any]]:
    if not isinstance(lst, list):
        raise ValueError("commitments must be a list")
    if len(lst) > MAX_FROST_SIGNING_SET:
        raise ValueError("commitments list exceeds the maximum signing set")
    return [decode_commitment(w) for w in lst]


def decode_verification_shares(lst: Any) -> List[Dict[str, Any]]:
    if not isinstance(lst, list):
        raise ValueError("verification_shares must be a list")
    if len(lst) > MAX_FROST_SIGNING_SET:
        raise ValueError("verification_shares list exceeds the maximum signing set")
    out = []
    for v in lst:
        if not v or not isinstance(v, dict):
            raise ValueError("bad verification share")
        pk = decode_b64u_strict(v.get("publicKey"), 32)
        if not _is_id(v.get("identifier")):
            raise ValueError("bad verification-share identifier")
        if pk is None:
            raise ValueError("bad verification-share key encoding")
        out.append({"identifier": v["identifier"], "publicKey": pk})
    return out


# ---- guardian signer service ----

def _num(x: Any) -> bool:
    return not isinstance(x, bool) and isinstance(x, (int, float))


def _encode_commitment(c: Dict[str, Any]) -> Dict[str, Any]:
    return {"identifier": c["identifier"], "hiding": b64u(c["hiding"]), "binding": b64u(c["binding"])}


class GuardianSignerService:
    """One guardian's side of a two-round FROST signing session. Round 1 draws fresh nonces, keeps them (optionally in a durable nonce store) and returns the
    commitment with the proof of possession; round 2 signs ONLY when the request names this group key, carries a valid allow token from the trusted policy
    authority for exactly this message, lists this signer's own round-1 commitment unchanged, and the session is neither stale nor already signed. A nonce
    pair signs once: the store records it spent BEFORE the signature share is computed, so a crash cannot lose the one-shot guard. Every failure is a
    refusal value (``{"ok": False, ..., "reason"}``), never a raise. ``nonce_store`` (create / load / spend / drop / is_spent) makes sessions survive a restart;
    ``now`` is the clock in milliseconds; ``random_bytes`` the randomness seam (nonces and the proof-of-possession nonce)."""

    def __init__(self, identifier: Any, share: Any, group_public_key: Any, threshold: Any, policy_authority_public_key: Any,
                 session_ttl_ms: Any = None, now: Optional[Callable[[], float]] = None, nonce_store: Any = None,
                 random_bytes: Callable[[int], bytes] = os.urandom) -> None:
        if not _is_id(identifier):
            raise ValueError("GuardianSignerService: identifier must be a positive integer")
        if not _is_bytes32(share):
            raise ValueError("GuardianSignerService: share must be 32 bytes")
        if not _is_bytes32(group_public_key):
            raise ValueError("GuardianSignerService: groupPublicKey must be 32 bytes")
        if isinstance(threshold, bool) or not isinstance(threshold, int) or not (1 <= threshold <= 9007199254740991):
            raise ValueError("GuardianSignerService: threshold must be a positive integer")
        if not _is_bytes32(policy_authority_public_key):
            raise ValueError("GuardianSignerService: policyAuthorityPublicKey must be 32 bytes")
        if session_ttl_ms is not None and (not _num(session_ttl_ms) or not fin(session_ttl_ms) or session_ttl_ms <= 0):
            raise ValueError("GuardianSignerService: sessionTtlMs must be a positive finite number")
        self.identifier = identifier
        self._share = bytes(share)
        self._gpk = bytes(group_public_key)
        self._threshold = threshold
        self._policy = bytes(policy_authority_public_key)
        self._ttl = session_ttl_ms
        self._now = now if now is not None else (lambda: __import__("time").time() * 1000)
        if nonce_store is not None:
            for m, js in (("create", "create"), ("load", "load"), ("spend", "spend"), ("drop", "drop"), ("is_spent", "isSpent")):
                if not callable(getattr(nonce_store, m, None)):
                    raise ValueError("GuardianSignerService: nonceStore.%s must be a function" % js)
        self._store = nonce_store
        self._random = random_bytes
        self._sessions: Dict[str, Dict[str, Any]] = {}
        self._spent: set = set()
        self.verification_share = F.verifying_share(self._share)
        self._pop = create_signer_pop(identifier, self._share, {"groupPublicKey": self._gpk}, random_bytes)

    @property
    def proof_of_possession(self) -> Dict[str, Any]:
        return self._pop

    def enrollment(self) -> Dict[str, Any]:
        """What the coordinator enrolls: the verification share with its proof of possession."""
        return {"identifier": self.identifier, "publicKey": self.verification_share, "pop": self._pop}

    def round1(self, req: Any) -> Dict[str, Any]:
        try:
            sid = req.get("session_id") if isinstance(req, dict) else None
            if not isinstance(req, dict) or req.get("typ") != "pca.frost.round1.v1" or not isinstance(sid, str) or len(sid) == 0:
                return {"ok": False, "identifier": self.identifier, "reason": "malformed round-1 request"}
            if sid in self._spent or (self._store is not None and self._store.is_spent(sid)):
                return {"ok": False, "identifier": self.identifier, "reason": "session already signed"}
            if sid in self._sessions or (self._store is not None and self._store.load(sid)):
                return {"ok": False, "identifier": self.identifier, "reason": "duplicate round-1 for session"}
            c = F.commit({"identifier": self.identifier, "share": self._share}, self._random(32), self._random(32))
            created = self._now()
            if self._store is not None:
                self._store.create(sid, {"hiding": c["hidingNonce"], "binding": c["bindingNonce"], "hidingCommitment": c["commitment"]["hiding"],
                                         "bindingCommitment": c["commitment"]["binding"], "createdAt": created})
            self._sessions[sid] = {"nonces": {"hiding": c["hidingNonce"], "binding": c["bindingNonce"]}, "commitment": c["commitment"], "createdAt": created}
            return {"ok": True, "identifier": self.identifier, "commitment": _encode_commitment(c["commitment"]), "pop": self._pop}
        except Exception as e:  # noqa: BLE001
            return {"ok": False, "identifier": self.identifier, "reason": str(e) or "round-1 error"}

    def round2(self, req: Any) -> Dict[str, Any]:
        def refuse(reason: str) -> Dict[str, Any]:
            return {"ok": False, "identifier": self.identifier, "refused": True, "reason": reason}
        try:
            sid = req.get("session_id") if isinstance(req, dict) else None
            if not isinstance(req, dict) or req.get("typ") != "pca.frost.round2.v1" or not isinstance(sid, str):
                return refuse("malformed round-2 request")
            if sid in self._spent or (self._store is not None and self._store.is_spent(sid)):
                return refuse("session already signed (one-shot)")
            state = self._sessions.get(sid)
            if state is None and self._store is not None:
                rec = self._store.load(sid)
                if rec:
                    state = {"nonces": {"hiding": rec["hiding"], "binding": rec["binding"]},
                             "commitment": {"identifier": self.identifier, "hiding": rec["hidingCommitment"], "binding": rec["bindingCommitment"]},
                             "createdAt": rec["createdAt"]}
                    self._sessions[sid] = state
            if state is None:
                return refuse("no round-1 state for this session")
            now_, created = self._now(), state["createdAt"]
            age = now_ - created if fin(now_, created) else math.nan
            if self._ttl is not None and not (fin(age) and age <= self._ttl):
                self._sessions.pop(sid, None)
                if self._store is not None:
                    self._store.drop(sid)
                return refuse("session expired (stale-session guard: round-1 older than %sms)" % _js_string(self._ttl))
            message = decode_b64u_strict(req.get("message"))
            if message is None:
                return refuse("message not canonical base64url")
            if req.get("group_pk") != b64u(self._gpk):
                return refuse("request names a different group key")
            allow = verify_allow_token(req.get("allow"), {"policyAuthorityPublicKey": self._policy, "groupPublicKey": self._gpk, "message": message, "now": self._now()})
            if not allow["ok"]:
                return refuse("policy authorization failed: %s" % allow["reason"])
            commitments = decode_commitments(req["commitments"] if req.get("commitments") is not None else [])
            if len(commitments) < self._threshold:
                return refuse("signing set below threshold t=%d" % self._threshold)
            own = next((c for c in commitments if c["identifier"] == self.identifier), None)
            if own is None:
                return refuse("our commitment is not in the signing set")
            if own["hiding"] != state["commitment"]["hiding"] or own["binding"] != state["commitment"]["binding"]:
                return refuse("equivocation detected: our commitment in the signing set differs from our round-1 commitment")
            vshares = decode_verification_shares(req.get("verification_shares"))
            if self._store is not None:
                self._store.spend(sid)
            sig = F.sign(self.identifier, self._share, self._gpk, state["nonces"], message, commitments, self._threshold, self.verification_share, vshares)
            self._sessions.pop(sid, None)
            self._spent.add(sid)
            return {"ok": True, "identifier": self.identifier, "sig_share": b64u(sig["sigShare"])}
        except Exception as e:  # noqa: BLE001
            return refuse(str(e) or "round-2 error")


# ---- coordinator ----

class CoordinatorError(Exception):
    """A signing session that could not reach the threshold; ``refusals`` lists each signer's refusal ({identifier, reason})."""

    def __init__(self, message: str, refusals: Optional[List[Dict[str, Any]]] = None) -> None:
        super().__init__(message)
        self.refusals = refusals if refusals is not None else []


class CoordinatorTimeoutError(CoordinatorError):
    """The session did not reach the threshold inside its window."""

    def __init__(self, message: str, timeout_ms: Any, refusals: Optional[List[Dict[str, Any]]] = None) -> None:
        super().__init__(message, refusals)
        self.timeoutMs = timeout_ms


class NetworkCoordinator:
    """Drives two-round FROST signing across signer transports (objects with ``identifier``, ``round1(req)`` and ``round2(req)`` returning the wire
    response dicts; a transport that raises counts as a refusal). The coordinator trusts no response: a signer is counted only with a valid proof of
    possession under the verification share on record, its round-1 commitment and round-2 share are each equivocation-checked, every share is verified
    before aggregation, and ``sign`` raises :class:`CoordinatorError` unless t shares aggregate to a signature that verifies under the group key. A call
    (or constructor) ``timeout_ms`` bounds the whole session (a timed-out session raises :class:`CoordinatorTimeoutError`; a late signer response is
    ignored); NaN, infinity or a non-positive call window means no deadline."""

    def __init__(self, group_public_key: Any, threshold: Any, signers: List[Any], verification_shares: Any = None, enroll: Any = None,
                 timeout_ms: Any = None, new_session_id: Optional[Callable[[], str]] = None, random_bytes: Callable[[int], bytes] = os.urandom) -> None:
        if not _is_bytes32(group_public_key):
            raise ValueError("NetworkCoordinator: groupPublicKey must be 32 bytes")
        if isinstance(threshold, bool) or not isinstance(threshold, int) or not (1 <= threshold <= 9007199254740991):
            raise ValueError("NetworkCoordinator: threshold must be a positive integer")
        if timeout_ms is not None and (not _num(timeout_ms) or not fin(timeout_ms) or timeout_ms <= 0):
            raise ValueError("NetworkCoordinator: timeoutMs must be a positive finite number")
        self._gpk = bytes(group_public_key)
        self._threshold = threshold
        self._signers = list(signers)
        if enroll is not None:
            self._vshares = enroll_verification_shares(enroll, {"groupPublicKey": self._gpk})
        elif verification_shares is not None:
            self._vshares = list(verification_shares)
        else:
            raise ValueError("NetworkCoordinator: provide verificationShares or enroll")
        self._pk_by_id = {v["identifier"]: b64u(v["publicKey"]) for v in self._vshares}
        self._equivocation = EquivocationGuard()
        self._new_session_id = new_session_id if new_session_id is not None else (lambda: b64u(random_bytes(32)))
        self._timeout_ms = timeout_ms

    def sign(self, message: Any, allow: Any, signer_ids: Optional[List[Any]] = None, timeout_ms: Any = None) -> Dict[str, Any]:
        window = timeout_ms if timeout_ms is not None else self._timeout_ms
        if not _num(window) or not (0 < window and fin(window)):
            return self._drive(message, allow, signer_ids)
        box: Dict[str, Any] = {}

        def work() -> None:
            try:
                box["v"] = self._drive(message, allow, signer_ids)
            except BaseException as e:  # noqa: BLE001
                box["e"] = e
        t = threading.Thread(target=work, daemon=True)
        t.start()
        t.join(window / 1000.0)
        if t.is_alive():
            raise CoordinatorTimeoutError("coordinator: signing session did not reach threshold within %sms" % _js_string(window), window)
        if "e" in box:
            raise box["e"]
        return box["v"]

    @staticmethod
    def _call(fn: Callable[[Any], Any], req: Any, identifier: Any, refused: bool) -> Dict[str, Any]:
        try:
            return fn(req)
        except Exception as e:  # noqa: BLE001
            out = {"ok": False, "identifier": identifier}
            if refused:
                out["refused"] = True
            out["reason"] = str(e) or "unreachable"
            return out

    def _drive(self, message: Any, allow: Any, signer_ids: Optional[List[Any]]) -> Dict[str, Any]:
        if not isinstance(message, (bytes, bytearray)):
            raise ValueError("coordinator.sign: message must be bytes")
        message = bytes(message)
        chosen = [s for s in self._signers if s.identifier in signer_ids] if signer_ids is not None else self._signers[:self._threshold]
        if len(chosen) < self._threshold:
            raise CoordinatorError("coordinator: only %d signer(s) selected, need t=%d" % (len(chosen), self._threshold))
        sid = self._new_session_id()
        with ThreadPoolExecutor(max_workers=max(1, len(chosen))) as pool:
            r1 = list(pool.map(lambda s: (s, self._call(s.round1, {"typ": "pca.frost.round1.v1", "session_id": sid}, s.identifier, False)), chosen))
        refusals: List[Dict[str, Any]] = []
        committed: List[tuple] = []
        for s, resp in r1:
            if not resp.get("ok"):
                refusals.append({"identifier": resp.get("identifier"), "reason": resp.get("reason")})
                continue
            rid = resp.get("identifier")
            expected = self._pk_by_id.get(rid) if isinstance(rid, int) else None
            if expected is None:
                refusals.append({"identifier": rid, "reason": "no verification share on record for this signer"})
                continue
            pop = resp.get("pop")
            if not isinstance(pop, dict) or pop.get("identifier") != rid or pop.get("publicKey") != expected or not verify_signer_pop(pop, {"groupPublicKey": self._gpk}):
                refusals.append({"identifier": rid, "reason": "invalid or missing proof-of-possession (rogue-key defense)"})
                continue
            try:
                if "commitment" not in resp:
                    raise ValueError("undefined is not canonical")
                self._equivocation.observe(sid, 1, rid, resp["commitment"])
            except Exception as e:  # noqa: BLE001
                refusals.append({"identifier": rid, "reason": str(e) if isinstance(e, EquivocationError) else "equivocation check failed"})
                continue
            committed.append((s, resp["commitment"]))
        if len(committed) < self._threshold:
            raise CoordinatorError("coordinator: round 1 produced %d commitment(s), need t=%d" % (len(committed), self._threshold), refusals)
        chosen_set = committed[:self._threshold]
        commitments = [c for _, c in chosen_set]
        set_ids = {c.get("identifier") for c in commitments}
        vshares = [{"identifier": v["identifier"], "publicKey": b64u(v["publicKey"])} for v in self._vshares if v["identifier"] in set_ids]
        if len(vshares) != len(chosen_set):
            raise CoordinatorError("coordinator: missing a verification share for a signer in the set")
        req2 = {"typ": "pca.frost.round2.v1", "session_id": sid, "message": b64u(message), "group_pk": b64u(self._gpk), "commitments": commitments,
                "verification_shares": vshares, "allow": allow}
        with ThreadPoolExecutor(max_workers=max(1, len(chosen_set))) as pool:
            r2 = list(pool.map(lambda sc: self._call(sc[0].round2, dict(req2), sc[0].identifier, True), chosen_set))
        shares: List[Dict[str, Any]] = []
        for resp in r2:
            if not resp.get("ok"):
                refusals.append({"identifier": resp.get("identifier"), "reason": resp.get("reason")})
                continue
            rid = resp.get("identifier")
            try:
                if "sig_share" not in resp:
                    raise ValueError("undefined is not canonical")
                self._equivocation.observe(sid, 2, rid, {"sig_share": resp["sig_share"]})
            except Exception as e:  # noqa: BLE001
                refusals.append({"identifier": rid, "reason": str(e) if isinstance(e, EquivocationError) else "equivocation check failed"})
                continue
            sb = decode_b64u_strict(resp["sig_share"], 32)
            if sb is None:
                refusals.append({"identifier": rid, "reason": "malformed signature share"})
            else:
                shares.append({"identifier": rid, "sigShare": sb})
        if len(shares) < self._threshold:
            raise CoordinatorError("coordinator: round 2 produced %d share(s), need t=%d" % (len(shares), self._threshold), refusals)
        agg_commitments = [decode_commitment(c) for c in commitments]
        signature = F.aggregate(message, agg_commitments, shares, self._gpk, [v for v in self._vshares if v["identifier"] in set_ids], self._threshold)
        return {"signature": signature, "sessionId": sid, "signers": [c["identifier"] for c in commitments]}
