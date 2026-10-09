"""The verification seam the tool guard depends on.

The guard never calls crypto directly; it calls a :class:`Verifier`. :class:`CoreVerifier` is the
default, wrapping :func:`atlas_pca.pca.verify_pcactn_core` (the shared reference verifier: the 8 offline
checks — wire, version, audience, validity, chain, plan inclusion, leaf signature, counter) and adding
the one thing a resource server must supply itself, a ``grant_ref -> grant`` resolver.

Swapping in a different :class:`Verifier` (e.g. one that also consults a revocation beacon, or a remote
attestation service) needs no change to the guard.
"""
from dataclasses import dataclass
from typing import Any, Callable, Dict, Optional

from atlas_pca.pca import Verdict, verify_pcactn_core

# A PCActn is an arbitrary JSON object; its field values are genuinely heterogeneous JSON.
PCActn = Dict[str, Any]
# A root grant is likewise a JSON object (the capability-chain root).
Grant = Dict[str, Any]
# ``grant_ref -> grant | None``. ``None`` means the grant is unknown (fail-closed).
GrantResolver = Callable[[Optional[str]], Optional[Grant]]


class Verifier:
    """Protocol: turn a parsed PCActn into a :class:`~atlas_pca.pca.Verdict` for this audience."""

    def verify(self, pcactn: PCActn, *, audience: str, now: Optional[int] = None) -> Verdict:
        raise NotImplementedError


@dataclass
class CoreVerifier(Verifier):
    """Default verifier: resolve the grant, then run the shared core verifier.

    ``resolve_grant`` maps the PCActn's ``grant_ref`` to its root grant; returning ``None`` yields a
    denying verdict (``reason="unknown_grant"``). ``now`` fixes the validity clock (epoch ms) and is
    useful in tests; left ``None`` the core verifier uses wall-clock time.
    """

    resolve_grant: GrantResolver
    now: Optional[int] = None

    def verify(self, pcactn: PCActn, *, audience: str, now: Optional[int] = None) -> Verdict:
        grant_ref = pcactn.get("grant_ref") if isinstance(pcactn, dict) else None
        grant = self.resolve_grant(grant_ref if isinstance(grant_ref, str) else None)
        if not isinstance(grant, dict):
            return Verdict(allow=False, checks={}, reason="unknown_grant")
        clock = now if now is not None else self.now
        return verify_pcactn_core(pcactn, grant, now=clock, audience=audience)
