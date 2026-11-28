"""``protect()``: the secure defaults for a resource server, in one call.

    p = protect(audience="ins_acme", grants=[grant],
                operation=lambda request, body: {"verb": "stripe.refund", "resource": "charge:ch_1", "params": {...}})
    guard = RequirePCA(**p.options)           # FastAPI; Django: PCA_AUDIENCE = p.options["audience"], and so on
    p.revoke(grant["id"])                     # later: every action under that grant is refused

It fills in the parts every server otherwise wires by hand, and nothing else: the grant lookup (your own list or function,
never the request), a replay store (in memory unless you pass ``state_store``), a revocation source, ``plan="single-step"``
(the grant alone limits what runs). Everything is still ``authorize()``: bound to the operation your route executes,
default-deny. Any ``authorize`` field you pass wins over the default.

Not carried over from the TypeScript ``protect()``: server-side risk from the connector catalog (``catalogRisk``). This
verifier does not compute the risk score or threshold step-up (see the README), so there is nothing for it to feed.
"""
from dataclasses import dataclass
from typing import Any, Callable, Dict, Optional, Set, Union

from .authorize import AuthorizeOptions, MemoryStateStore


@dataclass
class Protected:
    #: keyword arguments for ``RequirePCA(**options)`` (``audience``, ``resolve_grant``, ``authorize``, ``operation``,
    #: ``now`` when given); the same values feed the Django ``PCA_*`` settings.
    options: Dict[str, Any]
    revoked: Set[str]

    def revoke(self, grant_id: str) -> None:
        """Refuse every further action under this grant id."""
        self.revoked.add(grant_id)


def protect(audience: str, grants: Union[list, Callable[[Optional[str]], Optional[dict]]],
            operation: Optional[Callable[..., Any]] = None, *, now: Optional[int] = None,
            is_revoked: Optional[Callable[[dict, dict], bool]] = None, **authorize: Any) -> Protected:
    """Build the guard options. ``grants``: a list of grant dicts (looked up by ``id``) or a function from ``grant_ref``
    to a grant. ``is_revoked(pcactn, grant)`` is an extra revocation source, consulted in addition to ``revoke()``.
    Remaining keyword arguments are :class:`AuthorizeOptions` fields (``state_store``, ``require``, ``context``, ...) and
    override the defaults."""
    revoked: Set[str] = set()
    if callable(grants):
        resolve = grants
    else:
        by_id = {g["id"]: g for g in grants}
        resolve = lambda ref: by_id.get(ref)  # noqa: E731  (a non-string ref is simply unknown)

    def revoked_check(pcactn: dict, grant: dict) -> bool:
        return grant.get("id") in revoked or (is_revoked is not None and is_revoked(pcactn, grant) is True)

    fields: Dict[str, Any] = {"state_store": MemoryStateStore(), "is_revoked": revoked_check, "plan": "single-step"}
    fields.update(authorize)
    opts: Dict[str, Any] = {"audience": audience, "resolve_grant": resolve, "authorize": AuthorizeOptions(**fields)}
    if operation is not None:
        opts["operation"] = operation
    if now is not None:
        opts["now"] = now
    return Protected(options=opts, revoked=revoked)
