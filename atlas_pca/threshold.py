"""Risk-adaptive threshold signatures (the TypeScript ``threshold``): a t-of-n co-signature over a PCActn, where each role (``agent``,
``guardian``, ``principal``) signs a share bound to its role, the signer set, the threshold and the suite. The share signers are in
``atlas_pca.signers_more`` (:func:`sign_threshold_share`, :func:`sign_prepared_share`); the per-share check is
:func:`atlas_pca.pca.verify_threshold_share`; this module is the t-of-n verifier and the ``threshold`` hook for :func:`authorize`.

A signer set is ``[{"role", "publicKey", "pq_pk"?}]`` and a threshold signature ``{"shares": [...]}``."""
from typing import Any, Callable, Dict, List, Optional

from .authorize import is_awaiting_audit_scheme, set_assurance_label
from .gnap import _verify_threshold
from .pca import AGENT_LEAF_SHARE_BINDING_VERSION, VALID_THRESHOLDS, share_message, signer_set_hash, threshold_message  # noqa: F401
from .signers_more import sign_prepared_share, sign_threshold_share

__all__ = ["VALID_THRESHOLDS", "AGENT_LEAF_SHARE_BINDING_VERSION", "signer_set_hash", "share_message", "sign_share", "sign_prepared_share",
           "assemble_threshold", "verify_threshold", "create_threshold_verifier"]


def sign_share(role: str, key: Any, message: bytes, signer_set: List[dict], t: int, alg: Optional[str] = None, pq: Any = None) -> Dict[str, str]:
    """A role's explicit threshold share over the role, signer-set and t-bound share message (the reference's ``signShare``). `key` is the
    role's :class:`atlas_pca.agent.KeyPair`; `alg` / `pq` make the share post-quantum."""
    return sign_threshold_share(role, key, message, signer_set, t, alg, pq)


def assemble_threshold(shares: List[dict]) -> Dict[str, Any]:
    """Collect shares into a threshold signature (defensively copied)."""
    return {"shares": list(shares) if isinstance(shares, list) else []}


def verify_threshold(sig: Any, message: bytes, signer_set: Any, t: Any, baseline: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Verify a t-of-n multi-signature over `message` (the PCActn's :func:`threshold_message`): ``{"ok", "count", "roles", "reason"?}``.

    The signer set is validated FIRST and the verification fails closed if it is malformed (every role known, one key per role, one role per
    key, well-formed keys); `t` must be 1, 2 or 3. A share counts iff its role and key are registered and its signature verifies over that
    role's signer-set and t-bound share message (a bare agent share is rejected); the count is of DISTINCT keys. `baseline` admits the PCActn
    leaf signature as the agent's effective-t=1 share: ``{"holder", "sig", "alg"?, "pq_pk"?, "pq_sig"?, "holder_pq"?}``. Total: never raises."""
    return _verify_threshold(sig, message, signer_set, t, baseline)


def create_threshold_verifier(signer_set: List[dict], *, t: Optional[int] = None, required_t: Optional[Callable[[dict], int]] = None,
                              scheme: str = "multisig") -> Callable[..., Dict[str, Any]]:
    """The ``threshold`` hook for :func:`authorize` (and ``verify_pcactn_core(threshold_hook=...)``). It recomputes the PCActn's threshold
    message, verifies the explicit shares in ``pcactn["threshold"]``, admits the PCActn leaf signature as the agent's effective-t=1 baseline,
    and returns ``{"enforced": True, "ok", "reason"?, "t"}`` where ``t`` is the threshold it enforced.

    Exactly one of `t` (fixed by the server) / `required_t` (``ctx -> t`` from SERVER-held data only, never from the PCActn's ``risk_claim``)
    is mandatory: a default derived from the agent's own claim would let a compromised agent claim r=0 (finding F-1). The hook is called as
    ``hook(pcactn, grant, required)`` (the ``authorize`` form; ``ctx`` is then ``{"pcactn", "grant", "required"}``) or ``hook(ctx)`` with a
    ``{"pcactn", "grant"}`` dict. `scheme` labels how the signer keys are held: ``multisig`` (default), ``frost``, ``frost_dkg`` or ``mpc``
    (the last three are reported as awaiting audit)."""
    if required_t is None and t is None:
        raise TypeError("create_threshold_verifier: supply `t` or `required_t` derived from SERVER-held data (the agent's risk_claim is never "
                        "a source for the threshold)")
    ss = [dict(s) if isinstance(s, dict) else s for s in signer_set] if isinstance(signer_set, list) else signer_set
    resolve = required_t if required_t is not None else (lambda _ctx: t)

    def hook(*args: Any) -> Dict[str, Any]:
        ctx = args[0] if len(args) == 1 and isinstance(args[0], dict) and "pcactn" in args[0] else \
            {"pcactn": args[0], "grant": args[1] if len(args) > 1 else None, "required": args[2] if len(args) > 2 else None}
        p = ctx["pcactn"]
        message = threshold_message(p)
        thr = p.get("threshold")
        explicit = thr.get("shares") if isinstance(thr, dict) and isinstance(thr.get("shares"), list) else []
        chain = p.get("cap_chain")
        leaf = chain[-1] if isinstance(chain, list) and chain else None
        baseline = None
        if isinstance(leaf, dict) and isinstance(leaf.get("holder"), str) and isinstance(p.get("sig"), str):
            baseline = {"holder": leaf["holder"], "sig": p["sig"], "holder_pq": leaf.get("holder_pq")}
            for k in ("alg", "pq_pk", "pq_sig"):
                if k in p:
                    baseline[k] = p[k]
        want = resolve(ctx)
        v = verify_threshold({"shares": explicit}, message, ss, want, baseline)
        return {"enforced": True, "ok": True, "t": want} if v["ok"] else \
            {"enforced": True, "ok": False, "reason": v.get("reason") or "threshold not met", "t": want}

    return set_assurance_label(hook, scheme, awaiting_audit=True if is_awaiting_audit_scheme(scheme) else None)
