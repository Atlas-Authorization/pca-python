"""Differential replay of the TypeScript reference (@atlasauth/pca-rotate): key rotation, subtree re-issue, atomic applyRotation."""
import time

from atlas_pca import rotate as T
from atlas_pca.agent import keypair_from_seed
from atlas_pca.revoke import RevocationRegistry
from base_oracle import load_ref, near_clock, reference_clock_ms, run

COUNT, BY_FN = load_ref("rotate")
CLOCK = reference_clock_ms(BY_FN)
PRE_REVOKED_AT = 1_800_000_000_000  # the generator's own stamp on the records its scenarios start with (scenario data, not its clock: every expected pre entry carries it)


def key(seed):
    return None if seed is None else keypair_from_seed(seed, allow_insecure_signer=True)


def now_of(o):
    """Absent -> the clock; present but not a finite number -> NaN, which the reference refuses."""
    if "now" not in o:
        return None
    v = o["now"]
    ok = isinstance(v, (int, float)) and not isinstance(v, bool)
    return v if ok else float("nan")


def norm(v):
    """A revokedAt within two minutes of the wall clock is printed "<now>" (the reference does the same; its generation clock is frozen at the corpus header's clockMs, so that instant counts as now too)."""
    if isinstance(v, list):
        return [norm(x) for x in v]
    if isinstance(v, dict):
        return {k: ("<now>" if k == "revokedAt" and isinstance(x, (int, float)) and not isinstance(x, bool)
                    and near_clock(x, CLOCK) else norm(x)) for k, x in v.items()}
    return v


def agent(chain, op):
    return norm(T.rotate_agent_key(chain, key(op.get("oldSeed")), key(op.get("newSeed")), op.get("reason"), now_of(op)))


def principal(o):
    hs = o.get("holderSeeds")
    return norm(T.rotate_principal_key(key(o.get("oldSeed")), key(o.get("newSeed")), o.get("chain"), o.get("oldRoot"),
                                       None if hs is None else [key(s) for s in hs], o.get("reason"), now_of(o)))


def reissue(fn):
    return lambda chain, holder, op: norm(fn(chain, holder, key(op.get("newSeed")), key(op.get("ancestorSeed")), op.get("reason"), now_of(op)))


def apply_scenario(spec):
    reg = RevocationRegistry()
    for i in spec.get("pre") or []:
        reg.revoke({"kind": "cap", "value": i, "reason": "pre", "revokedAt": PRE_REVOKED_AT})
    calls = [0]

    class Sink:
        def revoke(self, inp):
            calls[0] += 1
            if spec.get("failAt") == calls[0]:
                raise RuntimeError("sink down")
            return reg.revoke(inp)

        def unrevoke(self, k):
            if spec.get("failUnrevoke"):
                raise RuntimeError("unrevoke down")
            return reg.unrevoke(k)

        def lookup(self, k, v):
            return reg.lookup(k, v)

    try:
        result = T.apply_rotation(Sink(), spec.get("records"), spec.get("reissued"))
    except Exception:  # noqa: BLE001 - only the refusal is compared
        result = {"$err": True}
    return {"result": result, "list": norm(reg.list())}


MAP = {
    "rotateAgentKey": agent,
    "rotatePrincipalKey": principal,
    "revokeAndReissueSubtree": reissue(T.revoke_and_reissue_subtree),
    "compromisedKeyFlow": reissue(T.compromised_key_flow),
    "applyRotationScenario": apply_scenario,
}


def test_every_function_is_covered():
    assert set(BY_FN) == set(MAP) and COUNT == sum(len(v) for v in BY_FN.values())


def test_rotate_agent_key():
    run(BY_FN["rotateAgentKey"], MAP["rotateAgentKey"])


def test_rotate_principal_key():
    run(BY_FN["rotatePrincipalKey"], MAP["rotatePrincipalKey"])


def test_revoke_and_reissue_subtree():
    run(BY_FN["revokeAndReissueSubtree"], MAP["revokeAndReissueSubtree"])


def test_compromised_key_flow():
    run(BY_FN["compromisedKeyFlow"], MAP["compromisedKeyFlow"])


def test_apply_rotation():
    run(BY_FN["applyRotationScenario"], MAP["applyRotationScenario"])
