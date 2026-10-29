"""Verifier-side revocation staleness (T9; the TypeScript ``RevocationStalenessPolicy`` and the staleness branch of
``createRevocationChecker``). The signer chooses an epoch's ``not_after``; this lets the VERIFIER cap how old
(``now - issued_at``) the revocation state may be, with a stricter window for actions that cannot be undone. The action's
class is the stricter of the server's authoritative class and the PCActn's signed ``reversibility_class``; a missing or
unknown class counts as irreversible (fail closed).

Off unless a :class:`RevocationStaleness` is given (``authorize(revocation_staleness=...)``)."""
from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Any, Callable, Mapping, Optional

from .intent_v2 import _UNDEF, check_revocation_age, check_revocation_epoch, verify_non_membership

REVOCATION_EPOCH_REFRESH_MS = 60_000
REVOCATION_EPOCH_VALIDITY_MS = 5 * 60_000
#: default window for an irreversible action: two refresh periods
REVOCATION_IRREVERSIBLE_MAX_AGE_MS = 2 * REVOCATION_EPOCH_REFRESH_MS

#: severity over both vocabularies a verifier sees (the RS strictness enum and the caveat enum); unknown = most restrictive
CLASS_RANK = {"reversible": 0, "rate_limited": 1, "costly": 1, "irreversible": 2}


def class_rank(c: Any) -> int:
    return CLASS_RANK.get(c, 2) if isinstance(c, str) else 2


def _positive_ms(v: Any) -> bool:
    return isinstance(v, (int, float)) and not isinstance(v, bool) and math.isfinite(v) and v > 0


@dataclass
class RevocationStaleness:
    """The staleness policy. Every window is a positive number of milliseconds (a malformed one raises ``ValueError`` at
    construction, never at request time).

    ``max_revocation_age_ms``  maximum age for any action (default 5 minutes).
    ``staleness``              per-class windows ``{"irreversible": ms, "rate_limited": ms}`` (``costly`` is the old name of ``rate_limited``), each capped by
                               ``max_revocation_age_ms`` (defaults: irreversible 2 minutes; rate_limited = the maximum).
    ``allow_unsigned_root_for_irreversible``  accept state that is not guardian-signed (a bare root) for an irreversible
                               action (default False: an unsigned root can be any root the verifier was handed).
    ``guardian_public``        the pinned guardian key (b64u) a signed epoch must verify under; ``pq_pins`` pins a PQ suite.
    ``ids``                    ``(pcactn) -> [capability id]``: which capabilities need a non-membership proof (default: every
                               ``id`` in the PCActn's ``cap_chain``, so a revoked ancestor kills its descendants).
    ``proof_for``              ``(capability id, pcactn) -> non-membership proof | None``: the proof source. A missing proof
                               denies (fail closed), so without it every request that has a capability chain is denied.
    ``on_epoch_accepted``      ``(epoch, pcactn) -> None``, called after an admitted action whose epoch passed every check
                               (persist it as the new ``last_accepted_epoch``).
    """

    max_revocation_age_ms: Optional[float] = None
    staleness: Optional[Mapping[str, float]] = None
    allow_unsigned_root_for_irreversible: bool = False
    guardian_public: Optional[str] = None
    pq_pins: Optional[Mapping[str, Any]] = None
    on_epoch_accepted: Optional[Callable[[dict, dict], None]] = None
    ids: Optional[Callable[[dict], Any]] = None
    proof_for: Optional[Callable[[str, dict], Any]] = None

    def __post_init__(self) -> None:
        if self.max_revocation_age_ms is not None and not _positive_ms(self.max_revocation_age_ms):
            raise ValueError("max_revocation_age_ms must be a positive number of milliseconds")
        if self.staleness is not None:
            if not isinstance(self.staleness, Mapping):
                raise ValueError("staleness must be a mapping")
            for k in ("irreversible", "rate_limited", "costly"):
                if k in self.staleness and not _positive_ms(self.staleness[k]):
                    raise ValueError("staleness.%s must be a positive number of milliseconds" % k)


def effective_reversibility(server_class: Any, signed_class: Any) -> str:
    """The stricter of the server's class and the signed one. Unknown or missing = irreversible."""
    rank = max(0 if server_class is None else class_rank(server_class), class_rank(signed_class))
    return "irreversible" if rank >= 2 else "rate_limited" if rank == 1 else "reversible"


def revocation_max_age_ms(policy: RevocationStaleness, cls: str) -> float:
    """The maximum age of revocation state the policy allows for an action of `cls`."""
    mx = REVOCATION_EPOCH_VALIDITY_MS if policy.max_revocation_age_ms is None else policy.max_revocation_age_ms
    st = policy.staleness or {}
    if cls == "irreversible":
        return min(mx, st.get("irreversible", REVOCATION_IRREVERSIBLE_MAX_AGE_MS))
    if cls in ("rate_limited", "costly"):
        return min(mx, st.get("rate_limited", st.get("costly", mx)))
    return mx


def check_revocation_state(policy: Optional[RevocationStaleness], state: Any, *, now: Any, grant_ref: Any = _UNDEF,
                           signed_class: Any = None, server_class: Any = None, pcactn_epoch: Any = _UNDEF,
                           guardian_public: Any = None, ids: Any = None, proof_for: Any = None) -> dict:
    """The revocation-state gate (``createRevocationChecker``). Returns
    ``{"ok": True, "epoch"?}`` or ``{"ok": False, "reason"}``. `state` is the revocation state this verification relies on:

    * ``{"kind": "epoch", "epoch": <guardian-signed epoch>, "root"?: str, "last_accepted_epoch"?: int}`` - checked against
      ``guardian_public`` (default ``policy.guardian_public``; signature, grant binding, expiry, rollback, the PCActn's ``freshness.epoch``) and, with a
      policy, the per-class age cap; a given ``root`` must equal the epoch's;
    * ``{"kind": "root", "root": str, "issued_at": ms | None}`` - state that is not signed: with a policy it is refused
      for an irreversible action (unless allowed) and held to the same age cap via the time YOUR trusted source issued it
      (`None` = unknown = denied);
    * ``None``: no signed epoch (denied).

    After the freshness step, every capability id in `ids` (default: none to prove) needs a valid non-membership proof from
    `proof_for(id)` against the epoch's (or bare) root: a missing proof is ``no non-membership proof for <id>``, a revoked id
    or invalid proof ``capability <id> is revoked or proof invalid``.

    `policy` None = staleness off: a signed epoch is still verified, with no verifier-side cap. Total."""
    try:
        cls = max_age = None
        if policy is not None:
            cls = effective_reversibility(server_class, signed_class)
            max_age = revocation_max_age_ms(policy, cls)
        st = state if isinstance(state, Mapping) else {}
        kind = st.get("kind")
        root = st.get("root")
        accepted = None
        if kind == "epoch":
            ep = st.get("epoch")
            gp = guardian_public if guardian_public is not None else (policy.guardian_public if policy is not None else None)
            if not isinstance(ep, dict) or not isinstance(gp, str) or gp == "":
                return {"ok": False, "reason": "no signed revocation epoch"}
            kw = {} if max_age is None else {"max_age_ms": max_age}
            chk = check_revocation_epoch(ep, gp, now, grant_ref, st.get("last_accepted_epoch", _UNDEF), pcactn_epoch,
                                         dict(policy.pq_pins) if policy is not None and policy.pq_pins else None, **kw)
            if not chk["ok"]:
                return chk
            if root is not None and root != ep.get("root"):
                return {"ok": False, "reason": "revocation root does not match the signed epoch"}
            root, accepted = ep.get("root"), ep
        elif kind == "root":
            if policy is not None:
                if cls == "irreversible" and not policy.allow_unsigned_root_for_irreversible:
                    return {"ok": False, "reason": "unsigned revocation root refused for an irreversible action "
                                                   "(needs a guardian-signed epoch)"}
                age = check_revocation_age(st.get("issued_at"), now, max_age, "revocation root")
                if not age["ok"]:
                    return age
        else:
            return {"ok": False, "reason": "no signed revocation epoch"}
        if not root:
            return {"ok": False, "reason": "no revocation root"}
        for rid in ids or ():
            proof = proof_for(rid) if proof_for is not None else None
            if proof is None:
                return {"ok": False, "reason": "no non-membership proof for %s" % (rid,)}
            if not verify_non_membership(root, proof, rid):
                return {"ok": False, "reason": "capability %s is revoked or proof invalid" % (rid,)}
        return {"ok": True, "epoch": accepted} if accepted is not None else {"ok": True}
    except Exception:  # noqa: BLE001 - fail closed
        return {"ok": False, "reason": "revocation state check error (fail closed)"}
