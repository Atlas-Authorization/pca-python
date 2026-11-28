"""Differential replay of the SCIM 2.0 /Agents server, the passport mapping and the push adapters (atlas_pca.scim) against the
vectors generated from the TypeScript reference (@atlasauth/pca-scim). The option and fake-fetch tables mirror the generator's."""
import pytest

from atlas_pca import scim as S
from base_oracle import load_ref, run

COUNT, CASES = load_ref("scim")
T0 = 1_700_000_000_000
BASE = "https://scim.acme.com/scim/v2"


def _raise(*_a):
    raise RuntimeError("x")


def _tick_opts():
    n = [0]

    def now():
        n[0] += 1
        return T0 + 1000 * (n[0] - 1)
    return {"baseUrl": "https://x.example", "now": now, "authenticate": lambda r: True}


OPTS = {
    "open": lambda: {"baseUrl": BASE, "now": lambda: T0, "authenticate": lambda r: True},
    "slash": lambda: {"baseUrl": BASE + "///", "now": lambda: T0, "authenticate": lambda r: True},
    "nobase": lambda: {"now": lambda: T0, "allowUnauthenticated": True},
    "tick": _tick_opts,
    "deny": lambda: {"now": lambda: T0, "authenticate": lambda r: False},
    "throwauth": lambda: {"now": lambda: T0, "authenticate": _raise},
    "truthy": lambda: {"now": lambda: T0, "authenticate": lambda r: "yes"},
    "noauth": lambda: {"now": lambda: T0},
    "notfn": lambda: {"now": lambda: T0, "authenticate": "yes"},
}


def _session(opts, setup, reqs):
    h = S.scim_handler(S.create_memory_store(), OPTS[opts]())
    for r in setup:
        h(r)
    return [h(r) for r in reqs]


def _registry(ps, id):
    r = S.build_registry(ps)
    return {"all": r.all(), "has": r.has(id), "get": r.get(id)}


def _fake_fetch(mode, calls):
    def fetch(url, init):
        calls.append({"url": url, "init": init})
        if mode == "badjson":
            return {"ok": True, "status": 204, "json": _raise}
        ok, status, body = {"ok201": (True, 201, {"id": "obj-1"}), "err500": (False, 500, {"detail": "x"}), "nullbody": (True, 200, None)}[mode]
        return {"ok": ok, "status": status, "json": lambda: body}
    return fetch


def _push(fn, agent, mode):
    calls = []
    target = {"endpoint": "https://dir.example/scim/Agents", "token": "TOK", "fetch": _fake_fetch(mode, calls)}
    result = (S.push_to_entra if fn == "pushToEntra" else S.push_to_okta)(agent, target)
    return {"result": result, "calls": calls}


def _push_provision(agent, mode):
    calls = []
    result = S.push_provision(S.to_entra_agent_payload(agent), {"endpoint": "e", "token": "t", "fetch": _fake_fetch(mode, calls)})
    return {"result": result, "calls": calls}


MAP = {
    "scimSession": _session,
    "passportFingerprint": S.passport_fingerprint,
    "issuePassport": S.issue_passport,
    "passportToScim": S.passport_to_scim,
    "scimToProvisioningRequest": S.scim_to_provisioning_request,
    "parseFilter": S.parse_filter,
    "scimError": S.scim_error,
    "scimListResponse": S.scim_list_response,
    "registry": _registry,
    "toEntraAgentPayload": S.to_entra_agent_payload,
    "toOktaScimPayload": S.to_okta_scim_payload,
    "pushToEntra": lambda n, a, m: _push(n, a, m),  # the corpus carries the function's own name as the first argument
    "pushToOkta": lambda n, a, m: _push(n, a, m),
    "pushProvision": _push_provision,
}


def _call(fn):
    f = MAP[fn]
    if fn == "passportToScim":
        # the generator drives some cases through a fixed clock: [passport, proj, nowMs] instead of [passport, proj, meta]
        return lambda p, pr, m: f(p, pr, {"now": (lambda: m)} if isinstance(m, (int, float)) and not isinstance(m, bool) else m)
    return f


def test_every_oracle_function_is_replayed():
    assert set(CASES) == set(MAP) and COUNT == sum(len(v) for v in CASES.values())


@pytest.mark.parametrize("fn", sorted(MAP))
def test_matches_the_reference(fn):
    run(CASES[fn], _call(fn))
