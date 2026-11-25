"""FROST distributed key generation (Pedersen / Feldman VSS with a proof of knowledge, signed shares, non-repudiable complaints, blame resolution, echo-broadcast
agreement and a verified finalize), no trusted dealer. A port of the reference ``frost-dkg`` module.

Round 1: each participant i draws a degree t-1 polynomial f_i, broadcasts the Feldman commitments C_i,k = a_i,k * B and a Schnorr proof of knowledge of a_i,0
(domain separated, bound to the session and the identifier). Round 2: i sends f_i(j) to every j, signed under a_i,0 (a Schnorr signature verified against
C_i,0), so a recipient can PROVE a bad share to everyone without being framed. Blame: a complaint carries the accused-signed share; it is justified only
if that share fails VSS against the accused's broadcast commitments. Echo broadcast: every qualified party signs off on the same transcript digest before
finalize, so an equivocating dealer is detected. Finalize: the signing share is the sum of the received shares, the group key the sum of the constant
commitments, and the result is checked against the group verifying share.

Scalars are 32-byte little-endian strings and points 32-byte encodings (None is the identity), the representation :mod:`atlas_pca.frost` uses; every wire
member is base64url. Every verifier that returns a boolean or a verdict is total (any malformed input is a refusal value); the producing functions raise.
Randomness (coefficients, the proof nonce, a simulated session id) comes from the ``random_bytes`` argument (default ``os.urandom``)."""
from __future__ import annotations

from ._fin import fin
import hashlib
import os
import re
from typing import Any, Callable, Dict, List, Optional, Sequence

from . import frost as F
from .intent_v2 import _js_string
from .pca import b64u, decode_b64u_strict, hash_canonical

__all__ = ["dkg_round1", "dkg_verify_round1", "dkg_sign_share", "dkg_round2", "dkg_verify_share", "dkg_file_complaint", "dkg_verify_complaint", "dkg_rebut",
           "dkg_resolve_blame", "dkg_qualified_set", "dkg_transcript_digest", "dkg_echo", "dkg_check_echoes", "dkg_finalize", "frost_dkg_simulate"]

_CTX = b"FROST-ED25519-SHA512-v1"
_POP_DST = b"dkg-pop"
_SHARE_DST = b"dkg-share"
_SHARE_NONCE_DST = b"dkg-share-nonce"
_L = 2 ** 252 + 27742317777372353535851937790883648493


# ---- JavaScript value semantics ----------------------------------------------------------------------------------------

def _isint(x: Any) -> bool:
    """Number.isInteger."""
    return not isinstance(x, bool) and (isinstance(x, int) or (isinstance(x, float) and fin(x) and x == int(x)))


def _safe_pos(x: Any) -> bool:
    """A positive safe integer (Number.isSafeInteger(x) && x > 0)."""
    return _isint(x) and 0 < x <= 9007199254740991


def _big(x: Any) -> int:
    """BigInt(x): a whole number or a decimal / hex string; a fraction, null or an object throws."""
    if isinstance(x, bool):
        return int(x)
    if isinstance(x, int):
        return x
    if isinstance(x, float):
        if fin(x) and x == int(x):
            return int(x)
        raise ValueError("BigInt: not an integer")
    if isinstance(x, str):
        s = x.strip()
        if s == "":
            return 0
        if re.fullmatch(r"[+-]?[0-9]+", s):
            return int(s)
        if re.fullmatch(r"0[xX][0-9a-fA-F]+|0[oO][0-7]+|0[bB][01]+", s):
            return int(s, 0)
        raise ValueError("BigInt: not a number")
    raise TypeError("BigInt: cannot convert")


def _scalar_of(x: Any) -> bytes:
    """scalarToBytes(BigInt(x))."""
    return F.int_scalar(_big(x))


def _seq(a: Any, b: Any) -> bool:
    """JavaScript ``===`` for JSON values."""
    if isinstance(a, bool) or isinstance(b, bool):
        return isinstance(a, bool) and isinstance(b, bool) and a == b
    if isinstance(a, (int, float)) and isinstance(b, (int, float)):
        return a == b
    if type(a) is not type(b):
        return False
    return a == b if isinstance(a, (str, type(None))) else a is b


def _g(o: Any, k: str) -> Any:
    """``o[k]``: reading a member of null throws, of any other primitive is undefined (None here)."""
    if o is None:
        raise TypeError("cannot read properties of null")
    return o.get(k) if isinstance(o, dict) else None


def _arr(x: Any) -> list:
    """Something the reference iterates with a for-of / map / find: a list (or tuple); anything else throws."""
    if isinstance(x, (list, tuple)):
        return list(x)
    raise TypeError("not iterable")


def _bs(x: Any) -> bytes:
    if isinstance(x, (bytes, bytearray)):
        return bytes(x)
    raise TypeError("expected bytes")


def _unb64u(s: Any) -> bytes:
    r = decode_b64u_strict(s)
    if r is None:
        raise ValueError("base64url decode failed")
    return r


def _canonical_scalar(b: Any) -> bytes:
    if not F.is_canonical_scalar(b):
        raise ValueError("dkg: scalar must be 32 bytes and < the group order")
    return bytes(b)


def _hash_to_scalar(*parts: bytes) -> bytes:
    return F.reduce_bytes(hashlib.sha512(b"".join(parts)).digest())


def _commit_vec(commitments: Any) -> tuple:
    """(first commitment point, length-prefixed concatenation of the commitment encodings); every commitment must be a safe point."""
    if not isinstance(commitments, (list, tuple)) or len(commitments) == 0:
        raise ValueError("dkg: empty commitment vector")
    pts = [F.decode_safe_point(_unb64u(c)) for c in commitments]
    return pts[0], len(pts).to_bytes(4, "big") + b"".join(pts)


def _eval_poly(coeffs: List[bytes], x: int) -> bytes:
    xb = F.int_scalar(x)
    acc = bytes(32)
    for c in reversed(coeffs):
        acc = F.sc_add(F.sc_mul(acc, xb), c)
    return acc


def _vss_check(share: bytes, commitments: Any, at_id: Any) -> bool:
    if len(commitments) == 0:
        return False
    lhs = F._mul_base(share)
    rhs = None
    x = _big(at_id)
    xk = 1
    for c in commitments:
        rhs = F._padd(rhs, F._mul_pt(F.decode_safe_point(_unb64u(c)), F.int_scalar(xk)))
        xk = xk * x % _L
    return lhs == rhs


def _pop_challenge(session_id: bytes, identifier: Any, cv: tuple, r: Optional[bytes]) -> bytes:
    return _hash_to_scalar(_CTX, _POP_DST, session_id, _scalar_of(identifier), cv[1], F._enc(r))


def _share_challenge(session_id: bytes, frm: Any, to: Any, share: bytes, cv: tuple, rs: Optional[bytes]) -> bytes:
    return _hash_to_scalar(_CTX, _SHARE_DST, session_id, _scalar_of(frm), _scalar_of(to), _bs(share), cv[1], F._enc(rs))


def _share_nonce(a0: bytes, session_id: bytes, frm: Any, to: Any, share: bytes, cv: tuple) -> bytes:
    return _hash_to_scalar(_CTX, _SHARE_NONCE_DST, a0, session_id, _scalar_of(frm), _scalar_of(to), _bs(share), cv[1])


def _sign_share_scalar(a0: bytes, cv: tuple, session_id: bytes, frm: Any, to: Any, share: Any) -> str:
    k = _share_nonce(a0, session_id, frm, to, share, cv)
    rs = F._mul_base(k)
    e = _share_challenge(session_id, frm, to, share, cv, rs)
    s = F.sc_add(k, F.sc_mul(a0, e))
    return b64u(F._enc(rs) + s)


def _verify_share_sig(sig: Any, session_id: bytes, frm: Any, to: Any, share: Any, cv: tuple) -> bool:
    try:
        raw = _unb64u(sig)
        if len(raw) != 64:
            return False
        rs = F.decode_safe_point(raw[:32])
        s = _canonical_scalar(raw[32:])
        e = _share_challenge(session_id, frm, to, share, cv, rs)
        return F._mul_base(s) == F._padd(rs, F._mul_pt(cv[0], e))
    except Exception:  # noqa: BLE001
        return False


def _verify_share_sig_against_package(sig: Any, session_id: bytes, frm: Any, to: Any, share: Any, sender_package: Any) -> bool:
    try:
        commitments = _g(sender_package, "coefficientCommitments")
        if not isinstance(sig, str) or not isinstance(commitments, (list, tuple)) or len(commitments) == 0:
            return False
        return _verify_share_sig(sig, session_id, frm, to, share, _commit_vec(commitments))
    except Exception:  # noqa: BLE001
        return False


# ---- round 1 -----------------------------------------------------------------------------------------------------------

def dkg_sign_share(state: dict, to: Any, share: Any) -> str:
    """The participant's signature (under its constant coefficient) over a share it sends to ``to``; any share bytes can be signed (a cheater's too)."""
    a0 = F.reduce_bytes(state["coefficients"][0])
    cv = _commit_vec(state["package"]["coefficientCommitments"])
    return _sign_share_scalar(a0, cv, state["sessionId"], state["identifier"], to, share)


def dkg_round1(identifier: Any, t: Any, n: Any, session_id: Any, opts: Optional[dict] = None, random_bytes: Callable[[int], bytes] = os.urandom) -> Dict[str, Any]:
    """Round 1 of participant ``identifier``: ``{"package", "state"}``. ``opts``: ``coefficients`` (t fixed 32-byte scalars) and ``popNonce`` (a fixed
    proof nonce) for reproducible vectors; otherwise t coefficients and then the nonce are drawn from ``random_bytes``."""
    opts = opts or {}
    if not _isint(identifier) or identifier <= 0:
        raise ValueError("dkgRound1: identifier must be a positive integer")
    if not _isint(t) or not _isint(n) or t < 1 or n < t:
        raise ValueError("dkgRound1: need 1 <= t <= n (got t=%s, n=%s)" % (_js_string(t), _js_string(n)))
    if not isinstance(session_id, (bytes, bytearray)) or len(session_id) == 0:
        raise ValueError("dkgRound1: sessionId must be a non-empty byte string")
    session_id = bytes(session_id)
    identifier, t, n = int(identifier), int(t), int(n)
    coeffs: List[bytes] = []
    if opts.get("coefficients") is not None:
        if len(opts["coefficients"]) != t:
            raise ValueError("dkgRound1: coefficients.length must equal t (%d)" % t)
        coeffs = [F.reduce_bytes(_bs(c)) for c in opts["coefficients"]]
    else:
        coeffs = [F.reduce_bytes(random_bytes(32)) for _ in range(t)]
    commitment_points = [F._mul_base(a) for a in coeffs]
    commitments = [b64u(F._enc(p)) for p in commitment_points]
    a0 = coeffs[0]
    cv = _commit_vec(commitments)
    k = F.reduce_bytes(_bs(opts["popNonce"])) if opts.get("popNonce") is not None else F.reduce_bytes(random_bytes(32))
    r = F._mul_base(k)
    c = _pop_challenge(session_id, identifier, cv, r)
    mu = F.sc_add(k, F.sc_mul(a0, c))
    pkg = {"identifier": identifier, "sessionId": b64u(session_id), "coefficientCommitments": commitments, "proofOfKnowledge": {"R": b64u(F._enc(r)), "mu": b64u(mu)}}
    return {"package": pkg, "state": {"identifier": identifier, "t": t, "n": n, "sessionId": session_id, "coefficients": coeffs, "package": pkg}}


def dkg_verify_round1(from_identifier: Any, pkg: Any, session_id: Any) -> bool:
    """Verify a round-1 package: it names this session and its constant commitment is proven known by the Schnorr proof bound to ``from_identifier``."""
    try:
        if _g(pkg, "sessionId") != b64u(session_id):
            return False
        commitments = _g(pkg, "coefficientCommitments")
        if not isinstance(commitments, (list, tuple)) or len(commitments) == 0:
            return False
        cv = _commit_vec(commitments)
        pok = _g(pkg, "proofOfKnowledge")
        r = F.decode_safe_point(_unb64u(_g(pok, "R")))
        mu = _canonical_scalar(_unb64u(_g(pok, "mu")))
        c = _pop_challenge(session_id, from_identifier, cv, r)
        return F._mul_base(mu) == F._padd(r, F._mul_pt(cv[0], c))
    except Exception:  # noqa: BLE001
        return False


# ---- round 2 -----------------------------------------------------------------------------------------------------------

def dkg_round2(state: dict, all_round1_packages: Any) -> List[Dict[str, Any]]:
    """The signed shares this participant sends: one per other package, in package order. Packages are not validated here (see :func:`dkg_verify_round1`)."""
    pkgs = _arr(all_round1_packages)
    ids = [_g(p, "identifier") for p in pkgs]
    if len(set(map(repr, ids))) != len(ids):
        raise ValueError("dkgRound2: duplicate identifiers in round-1 packages")
    if not any(_seq(i, state["identifier"]) for i in ids):
        raise ValueError("dkgRound2: my own round-1 package is missing")
    sid_b64 = b64u(state["sessionId"])
    for p in pkgs:
        if _g(p, "sessionId") != sid_b64:
            raise ValueError("dkgRound2: participant %s round-1 package is from a different session" % _js_string(_g(p, "identifier")))
    coeffs = [F.reduce_bytes(c) for c in state["coefficients"]]
    a0 = coeffs[0]
    cv = _commit_vec(state["package"]["coefficientCommitments"])
    out = []
    for j in ids:
        if _seq(j, state["identifier"]):
            continue
        share = _eval_poly(coeffs, _big(j))
        sig = _sign_share_scalar(a0, cv, state["sessionId"], state["identifier"], j, share)
        out.append({"from": state["identifier"], "to": j, "sessionId": sid_b64, "share": share, "sig": sig})
    return out


def dkg_verify_share(received: Any, sender_package: Any, my_identifier: Any, session_id: Any) -> bool:
    """A received share is accepted only if the sender's package verifies, the share is signed by the sender for THIS recipient and session, and it passes
    Feldman VSS against the sender's broadcast commitments."""
    try:
        if not isinstance(received, dict) or not isinstance(received.get("share"), (bytes, bytearray)):
            return False
        if not dkg_verify_round1(_g(sender_package, "identifier"), sender_package, session_id):
            return False
        if not _verify_share_sig_against_package(received.get("sig"), session_id, received.get("from"), my_identifier, received["share"], sender_package):
            return False
        return _vss_check(_canonical_scalar(received["share"]), _g(sender_package, "coefficientCommitments"), my_identifier)
    except Exception:  # noqa: BLE001
        return False


# ---- blame -------------------------------------------------------------------------------------------------------------

def dkg_file_complaint(params: dict) -> Dict[str, Any]:
    """A complaint carrying the accused-signed share the accuser received. It is only a claim until :func:`dkg_verify_complaint` adjudicates it."""
    accused, accuser = params.get("accused"), params.get("accuser")
    share_sig, session_id = params.get("shareSig"), params.get("sessionId")
    if not _isint(accused) or accused <= 0:
        raise ValueError("dkgFileComplaint: accused must be a positive integer")
    if not _isint(accuser) or accuser <= 0:
        raise ValueError("dkgFileComplaint: accuser must be a positive integer")
    if accused == accuser:
        raise ValueError("dkgFileComplaint: cannot file a complaint against yourself")
    if not isinstance(share_sig, str) or len(share_sig) == 0:
        raise ValueError("dkgFileComplaint: shareSig (the accused-signed share) is required")
    if not isinstance(session_id, (bytes, bytearray)) or len(session_id) == 0:
        raise ValueError("dkgFileComplaint: sessionId must be a non-empty byte string")
    return {"accused": accused, "accuser": accuser, "sessionId": b64u(bytes(session_id)),
            "revealedShare": b64u(F.reduce_bytes(_bs(params.get("receivedShare")))), "shareSig": share_sig}


def _find_package(packages: Any, identifier: Any) -> Any:
    for p in _arr(packages):
        if _seq(_g(p, "identifier"), identifier):
            return p
    return None


def dkg_verify_complaint(complaint: Any, round1_packages: Any) -> Dict[str, Any]:
    """Adjudicate a complaint against the accused's broadcast package: justified only when the accused SIGNED a share that FAILS VSS; a share the accused
    never signed is inadmissible (it cannot frame an honest party) and a valid signed share is a false accusation (the accuser is at fault)."""
    try:
        accused_pkg = _find_package(round1_packages, _g(complaint, "accused"))
        if accused_pkg is None:
            return {"justified": False, "reason": "accused %s has no round-1 package to adjudicate against" % _js_string(_g(complaint, "accused"))}
        if _g(accused_pkg, "sessionId") != _g(complaint, "sessionId"):
            return {"justified": False, "reason": "complaint sessionId does not match the accused round-1 package session"}
        sid = _unb64u(_g(complaint, "sessionId"))
        share = _unb64u(_g(complaint, "revealedShare"))
        if not _verify_share_sig_against_package(_g(complaint, "shareSig"), sid, _g(complaint, "accused"), _g(complaint, "accuser"), share, accused_pkg):
            return {"justified": False, "atFault": _g(complaint, "accuser"),
                    "reason": "revealed share is not validly signed by the accused — inadmissible (cannot frame an honest party)"}
        valid = _vss_check(_canonical_scalar(share), _g(accused_pkg, "coefficientCommitments"), _g(complaint, "accuser"))
        if valid:
            return {"justified": False, "atFault": _g(complaint, "accuser"), "reason": "accused-signed share is VALID against the accused commitments — false accusation"}
        return {"justified": True, "disqualify": _g(complaint, "accused"),
                "reason": "accused non-repudiably signed a share that FAILS VSS against its broadcast commitments"}
    except Exception:  # noqa: BLE001
        return {"justified": False, "reason": "malformed complaint"}


def dkg_rebut(accused: Any, complaint: Any, my_round2_state: dict) -> Dict[str, Any]:
    """The accused's rebuttal to a complaint: the share it owes the accuser, recomputed from its own polynomial and freshly signed."""
    if not _seq(my_round2_state["identifier"], accused):
        raise ValueError("dkgRebut: myRound2State is not the accused")
    if not _seq(_g(complaint, "accused"), accused):
        raise ValueError("dkgRebut: complaint does not name this accused")
    if b64u(my_round2_state["sessionId"]) != _g(complaint, "sessionId"):
        raise ValueError("dkgRebut: complaint is scoped to a different session than my state")
    coeffs = [F.reduce_bytes(c) for c in my_round2_state["coefficients"]]
    share = _eval_poly(coeffs, _big(_g(complaint, "accuser")))
    share_sig = dkg_sign_share(my_round2_state, _g(complaint, "accuser"), share)
    return {"accused": accused, "accuser": _g(complaint, "accuser"), "sessionId": _g(complaint, "sessionId"), "presentedShare": b64u(share), "shareSig": share_sig}


def dkg_resolve_blame(complaint: Any, rebuttal: Any, round1_packages: Any) -> Dict[str, Any]:
    """Who is guilty after a complaint and the accused's optional rebuttal: ``{"guilty", "reason"}``. Total."""
    try:
        accused_pkg = _find_package(round1_packages, _g(complaint, "accused"))
        if accused_pkg is None:
            return {"guilty": _g(complaint, "accused"), "reason": "accused %s has no round-1 package to defend with" % _js_string(_g(complaint, "accused"))}
        if _g(accused_pkg, "sessionId") != _g(complaint, "sessionId"):
            return {"guilty": _g(complaint, "accuser"), "reason": "complaint names a session the accused did not run — inadmissible"}
        sid = _unb64u(_g(complaint, "sessionId"))
        share = _unb64u(_g(complaint, "revealedShare"))
        admissible = _verify_share_sig_against_package(_g(complaint, "shareSig"), sid, _g(complaint, "accused"), _g(complaint, "accuser"), share, accused_pkg)
        if admissible:
            valid = _vss_check(_canonical_scalar(share), _g(accused_pkg, "coefficientCommitments"), _g(complaint, "accuser"))
            if not valid:
                return {"guilty": _g(complaint, "accused"), "reason": "accused non-repudiably signed a share that fails VSS"}
            return {"guilty": _g(complaint, "accuser"), "reason": "accused-signed share is valid against its commitments — false accusation"}
        if (rebuttal is not None and _seq(_g(rebuttal, "accused"), _g(complaint, "accused")) and _seq(_g(rebuttal, "accuser"), _g(complaint, "accuser"))
                and _g(rebuttal, "sessionId") == _g(complaint, "sessionId")):
            r_share = _unb64u(_g(rebuttal, "presentedShare"))
            ok = (_verify_share_sig_against_package(_g(rebuttal, "shareSig"), sid, _g(complaint, "accused"), _g(complaint, "accuser"), r_share, accused_pkg)
                  and _vss_check(_canonical_scalar(r_share), _g(accused_pkg, "coefficientCommitments"), _g(complaint, "accuser")))
            if ok:
                return {"guilty": _g(complaint, "accuser"),
                        "reason": "accused produced a validly-signed, VSS-correct share for the recipient — the non-receipt/fabrication complaint is refuted"}
            return {"guilty": _g(complaint, "accused"), "reason": "accused could not present a validly-signed, VSS-correct share on rebuttal"}
        return {"guilty": _g(complaint, "accuser"),
                "reason": "complaint carries no accused-signed share and the accused offered no rebuttal — inadmissible, cannot frame the accused"}
    except Exception:  # noqa: BLE001
        return {"guilty": _g(complaint, "accuser") if isinstance(complaint, dict) else None, "reason": "malformed complaint — inadmissible"}


def dkg_qualified_set(participants: Any, complaints: Any, round1_packages: Any, rebuttals: Any = None) -> List[Any]:
    """The qualified participants, ascending: those with a valid round-1 package from the run's own session (the plurality session, first seen on a tie) not
    found guilty by :func:`dkg_resolve_blame`."""
    rebuttals = [] if rebuttals is None else rebuttals
    pkgs = _arr(round1_packages)
    by_id: Dict[Any, Any] = {}
    for p in pkgs:
        by_id[_g(p, "identifier")] = p
    counts: Dict[Any, int] = {}
    for p in pkgs:
        s = _g(p, "sessionId")
        counts[s] = counts.get(s, 0) + 1
    run_session, best = "", -1
    for s, c in counts.items():
        if c > best:
            best, run_session = c, s
    qualified: List[Any] = []
    for p in _arr(participants):
        pkg = by_id.get(p)
        if pkg is None:
            continue
        if _g(pkg, "sessionId") != run_session:
            continue
        try:
            sid = _unb64u(_g(pkg, "sessionId"))
        except Exception:  # noqa: BLE001
            continue
        if dkg_verify_round1(p, pkg, sid) and p not in qualified:
            qualified.append(p)
    for c in _arr(complaints):
        reb = next((r for r in _arr(rebuttals) if _seq(_g(r, "accused"), _g(c, "accused")) and _seq(_g(r, "accuser"), _g(c, "accuser"))
                    and _g(r, "sessionId") == _g(c, "sessionId")), None)
        res = dkg_resolve_blame(c, reb, pkgs)
        if _seq(res["guilty"], _g(c, "accused")):
            qualified = [q for q in qualified if not _seq(q, res["guilty"])]
    return sorted(qualified)


# ---- echo broadcast agreement ------------------------------------------------------------------------------------------

def _round1_digest(p: Any) -> str:
    pok = _g(p, "proofOfKnowledge")
    return hash_canonical({"identifier": _g(p, "identifier"), "sessionId": _g(p, "sessionId"), "coefficientCommitments": _g(p, "coefficientCommitments"),
                           "proofOfKnowledge": {"R": _g(pok, "R"), "mu": _g(pok, "mu")}})


def _complaint_digest(c: Any) -> str:
    return hash_canonical({"accused": _g(c, "accused"), "accuser": _g(c, "accuser"), "sessionId": _g(c, "sessionId"), "revealedShare": _g(c, "revealedShare"),
                           "shareSig": _g(c, "shareSig")})


def dkg_transcript_digest(args: dict) -> str:
    """The digest of a participant's view of the ceremony (round-1 packages, complaints, the qualified set, the session), each list in a canonical order."""
    round1 = sorted(_round1_digest(p) for p in _arr(args["round1Packages"]))
    complaints = sorted(_complaint_digest(c) for c in _arr(args["complaints"]))
    qualified = sorted(_arr(args["qualified"]))
    return hash_canonical({"sessionId": b64u(args["sessionId"]), "round1": round1, "complaints": complaints, "qualified": qualified})


def dkg_echo(args: dict) -> Dict[str, Any]:
    """The echo a participant broadcasts: its transcript digest, bound to the session."""
    return {"identifier": args["identifier"], "sessionId": b64u(args["sessionId"]), "transcriptDigest": dkg_transcript_digest(args)}


def dkg_check_echoes(qualified: Any, echoes: Any, session_id: Any) -> Dict[str, Any]:
    """Agreement across the qualified set: one echo each, all for this session, all carrying the same digest. ``{"agreed": True, "digest"}`` or
    ``{"agreed": False, "reason"}``. Total."""
    try:
        sid_b64 = b64u(session_id)
        q_list: List[Any] = []
        for x in (_arr(qualified) if qualified is not None else []):
            if not any(_seq(x, y) for y in q_list):
                q_list.append(x)
        by_id: List[tuple] = []
        for e in _arr(echoes):
            ident = _g(e, "identifier")
            if not any(_seq(ident, q) for q in q_list):
                continue
            if _g(e, "sessionId") != sid_b64:
                return {"agreed": False, "reason": "echo from %s is bound to a different session" % _js_string(ident)}
            if any(_seq(ident, k) for k, _ in by_id):
                return {"agreed": False, "reason": "duplicate echo from qualified participant %s" % _js_string(ident)}
            by_id.append((ident, e))
        agreed: Any = None
        have = False
        for j in q_list:
            e = next((v for k, v in by_id if _seq(k, j)), None)
            if e is None:
                return {"agreed": False, "reason": "missing echo from qualified participant %s" % _js_string(j)}
            digest = _g(e, "transcriptDigest")
            if not have:
                agreed, have = digest, True
            elif not _seq(digest, agreed):
                return {"agreed": False, "reason": "qualified participant %s echoed a DIFFERENT transcript (equivocation detected)" % _js_string(j)}
        if not have:
            return {"agreed": False, "reason": "no qualified echoes to agree on"}
        return {"agreed": True, "digest": agreed}
    except Exception:  # noqa: BLE001
        return {"agreed": False, "reason": "malformed echoes"}


# ---- finalize ----------------------------------------------------------------------------------------------------------

def dkg_finalize(my_identifier: Any, my_state: dict, received_shares: Any, all_commitments: Any, qualified: Any = None, agreement: Any = None) -> Dict[str, Any]:
    """Combine the received shares into this participant's key package: the signing share, the group public key and every qualified verifying share, with
    the echo-broadcast agreement checked when given. Raises on any inconsistency (a bad dealer share, a missing share, a diverging transcript)."""
    if not _seq(my_state["identifier"], my_identifier):
        raise ValueError("dkgFinalize: myState.identifier != myIdentifier")
    pkgs = _arr(all_commitments)
    ids = [_g(p, "identifier") for p in pkgs]
    if len(set(map(repr, ids))) != len(ids):
        raise ValueError("dkgFinalize: duplicate identifiers in commitments")
    if not any(_seq(i, my_identifier) for i in ids):
        raise ValueError("dkgFinalize: my own package is missing from allCommitments")
    sid_b64 = b64u(my_state["sessionId"])
    for p in pkgs:
        if _g(p, "sessionId") != sid_b64:
            raise ValueError("dkgFinalize: participant %s round-1 package is from a different session" % _js_string(_g(p, "identifier")))
    source = ids if qualified is None else _arr(qualified)
    qset = [x for x in source if any(_seq(x, i) for i in ids)]

    def in_q(x: Any) -> bool:
        return any(_seq(x, q) for q in qset)
    distinct: List[Any] = []
    for x in qset:
        if not any(_seq(x, d) for d in distinct):
            distinct.append(x)
    if not in_q(my_identifier):
        raise ValueError("dkgFinalize: myIdentifier is not in the qualified set")
    if len(distinct) < my_state["t"]:
        raise ValueError("dkgFinalize: qualified set (%d) is smaller than the threshold t=%d" % (len(distinct), my_state["t"]))
    t = my_state["t"]
    for p in pkgs:
        if not in_q(_g(p, "identifier")):
            continue
        if len(_g(p, "coefficientCommitments")) != t:
            raise ValueError("dkgFinalize: participant %s committed to the wrong number of coefficients, expected t=%d" % (_js_string(_g(p, "identifier")), t))
    if agreement is not None and isinstance(agreement, dict) and "echoes" in agreement:
        qsorted = sorted(distinct)
        check = dkg_check_echoes(qsorted, agreement["echoes"], my_state["sessionId"])
        if not check["agreed"]:
            raise ValueError("dkgFinalize: echo-broadcast agreement failed — %s" % check["reason"])
        comp = agreement.get("complaints")
        my_digest = dkg_transcript_digest({"round1Packages": pkgs, "complaints": comp if comp is not None else [], "qualified": qsorted,
                                           "sessionId": my_state["sessionId"]})
        if check["digest"] != my_digest:
            raise ValueError("dkgFinalize: echo-broadcast agreement failed — my transcript view diverges from the agreed echo digest (equivocation)")
    recv_by: List[tuple] = []
    for r in _arr(received_shares):
        frm = _g(r, "from")
        if _seq(frm, my_identifier):
            continue
        if not in_q(frm):
            continue
        if _g(r, "sessionId") != sid_b64:
            raise ValueError("dkgFinalize: received share from %s is from a different session" % _js_string(frm))
        if any(_seq(frm, k) for k, _ in recv_by):
            raise ValueError("dkgFinalize: duplicate received share from %s" % _js_string(frm))
        recv_by.append((frm, _g(r, "share")))
    for j in qset:
        if _seq(j, my_identifier):
            continue
        if not any(_seq(j, k) for k, _ in recv_by):
            raise ValueError("dkgFinalize: missing received share from qualified participant %s" % _js_string(j))
    my_coeffs = [F.reduce_bytes(c) for c in my_state["coefficients"]]
    signing_share = _eval_poly(my_coeffs, _big(my_identifier))
    for _, share in recv_by:
        signing_share = F.sc_add(signing_share, F.reduce_bytes(_bs(share)))
    group_points: List[Optional[bytes]] = []
    for k_idx in range(t):
        acc = None
        for p in pkgs:
            if not in_q(_g(p, "identifier")):
                continue
            acc = F._padd(acc, F.decode_safe_point(_unb64u(_g(p, "coefficientCommitments")[k_idx])))
        group_points.append(acc)
    group_public_key = F._enc(group_points[0])
    group_commitment = [F._enc(pt) for pt in group_points]
    verifying_shares = []
    for j in qset:
        acc = None
        x = _big(j)
        xk = 1
        for phi in group_points:
            acc = F._padd(acc, F._mul_pt(phi, F.int_scalar(xk)))
            xk = xk * x % _L
        verifying_shares.append({"identifier": j, "publicKey": F._enc(acc)})
    verifying_share = F._enc(F._mul_base(signing_share))
    mine = next((v for v in verifying_shares if _seq(v["identifier"], my_identifier)), None)
    if mine is None or F._mul_base(signing_share) != F.decode_safe_point(mine["publicKey"]):
        raise ValueError("dkgFinalize: signing share is inconsistent with the group verifying share (bad dealer share)")
    return {"identifier": my_identifier, "signingShare": signing_share, "groupPublicKey": group_public_key, "verifyingShare": verifying_share,
            "publicKeyPackage": {"groupPublicKey": group_public_key, "groupCommitment": group_commitment, "verifyingShares": verifying_shares}}


# ---- in-process simulation ---------------------------------------------------------------------------------------------

def frost_dkg_simulate(t: Any, n: Any, opts: Optional[dict] = None, random_bytes: Callable[[int], bytes] = os.urandom) -> Dict[str, Any]:
    """Run a whole ceremony in process (tests, dealerless key generation on one host): every participant, every message, the blame round and the echo check.
    ``opts``: ``identifiers``, ``coefficientsByParticipant``, ``sessionId``, ``cheaters`` (identifiers whose shares are corrupted), ``equivocateEchoFor``."""
    opts = opts or {}
    if not _isint(t) or not _isint(n) or t < 1 or n < t:
        raise ValueError("frostDkgSimulate: need 1 <= t <= n (got t=%s, n=%s)" % (_js_string(t), _js_string(n)))
    t, n = int(t), int(n)
    ids = list(opts["identifiers"]) if opts.get("identifiers") is not None else list(range(1, n + 1))
    if len(ids) != n:
        raise ValueError("frostDkgSimulate: identifiers.length must equal n")
    if len(set(map(repr, ids))) != n:
        raise ValueError("frostDkgSimulate: identifiers must be distinct")
    if any(not _isint(x) or x <= 0 for x in ids):
        raise ValueError("frostDkgSimulate: identifiers must be positive integers")
    session_id = _bs(opts["sessionId"]) if opts.get("sessionId") is not None else random_bytes(32)
    cheaters = list(opts.get("cheaters") or [])
    by_participant = opts.get("coefficientsByParticipant")
    states = [dkg_round1(i, t, n, session_id, {"coefficients": by_participant[idx] if by_participant is not None and idx < len(by_participant) else None},
                         random_bytes)["state"] for idx, i in enumerate(ids)]
    round1_packages = [st["package"] for st in states]
    for pkg in round1_packages:
        if not dkg_verify_round1(pkg["identifier"], pkg, session_id):
            raise ValueError("frostDkgSimulate: PoP verification failed for participant %s" % _js_string(pkg["identifier"]))
    inbox: Dict[Any, List[dict]] = {i: [] for i in ids}
    complaints: List[dict] = []
    state_by_id = {st["identifier"]: st for st in states}
    for st in states:
        for outgoing in dkg_round2(st, round1_packages):
            share, share_sig = outgoing["share"], outgoing["sig"]
            if outgoing["from"] in cheaters:
                bad = bytearray(outgoing["share"])
                bad[0] ^= 0x01
                share = bytes(bad)
                share_sig = dkg_sign_share(st, outgoing["to"], share)
            sender_pkg = next(p for p in round1_packages if p["identifier"] == outgoing["from"])
            if dkg_verify_share({"from": outgoing["from"], "share": share, "sig": share_sig}, sender_pkg, outgoing["to"], session_id):
                inbox[outgoing["to"]].append({"from": outgoing["from"], "sessionId": outgoing["sessionId"], "share": share, "sig": share_sig})
            else:
                complaints.append(dkg_file_complaint({"accused": outgoing["from"], "accuser": outgoing["to"], "receivedShare": share, "shareSig": share_sig,
                                                      "senderCommitments": sender_pkg["coefficientCommitments"], "sessionId": session_id}))
    rebuttals = [dkg_rebut(c["accused"], c, state_by_id[c["accused"]]) for c in complaints]
    qualified = dkg_qualified_set(ids, complaints, round1_packages, rebuttals)
    if len(qualified) < t:
        raise ValueError("frostDkgSimulate: only %d qualified participants (< t=%d) after the blame round" % (len(qualified), t))
    equivocator = opts.get("equivocateEchoFor")
    echoes = []
    for i in qualified:
        view = [q for q in qualified if q != qualified[-1]] if equivocator is not None and i == equivocator else qualified
        echoes.append(dkg_echo({"identifier": i, "round1Packages": round1_packages, "complaints": complaints, "qualified": view, "sessionId": session_id}))
    key_packages = [dkg_finalize(st["identifier"], st, inbox[st["identifier"]], round1_packages, qualified, {"echoes": echoes, "complaints": complaints})
                    for st in states if st["identifier"] in qualified]
    group_public_key = key_packages[0]["groupPublicKey"]
    for kp in key_packages:
        if kp["groupPublicKey"] != group_public_key:
            raise ValueError("frostDkgSimulate: participants disagree on the group public key")
    return {"groupPublicKey": group_public_key,
            "participantShares": [{"identifier": kp["identifier"], "share": kp["signingShare"], "publicKey": kp["verifyingShare"]} for kp in key_packages],
            "groupCommitment": key_packages[0]["publicKeyPackage"]["groupCommitment"], "keyPackages": key_packages, "round1Packages": round1_packages,
            "qualified": qualified, "complaints": complaints, "rebuttals": rebuttals, "echoes": echoes, "sessionId": session_id}
