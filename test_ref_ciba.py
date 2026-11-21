"""Differential replay of the CIBA bridge (atlas_pca.ciba, ciba_store, ciba_testing, ciba_client) against vectors generated from the
TypeScript reference (@atlasauth/pca-ciba), plus unit tests of the client, the stores and the store-conformance runner."""
import json
import os
import re
import tempfile

import pytest

from atlas_pca import ciba as C
from atlas_pca import ciba_client as CC
from atlas_pca import ciba_conformance as CF
from atlas_pca import ciba_store as S
from atlas_pca import ciba_testing as T
from base_oracle import load_ref, run

COUNT, CASES = load_ref("ciba")


def _snake(o):
    return {re.sub(r"([A-Z])", lambda m: "_" + m.group(1).lower(), k): v for k, v in o.items()}


def _opts(o):
    if not isinstance(o, dict):
        return o
    a = _snake(o)
    if isinstance(a.get("binding_message"), dict):
        a["binding_message"] = _snake(a["binding_message"])
    return a


def _mask(v, id_):
    return json.loads(json.dumps(v), object_hook=lambda d: {k: ("ID" if x == id_ and id_ is not None else x) for k, x in d.items()}) if v is not None else None


def _lifecycle(kind, ops):
    t = {"v": 1_000_000}
    now = lambda: t["v"]  # noqa: E731
    b = T.create_ciba_broker(now=now, on_complete=lambda s: None) if kind == "memory" else S.create_durable_ciba_broker(T.create_memory_approval_store(), now=now, decision_ttl_sec=100)
    out = []
    ident = None
    for op in ops:
        if op["op"] == "now":
            t["v"] = op["t"]
            out.append(None)
            continue
        try:
            if op["op"] == "start":
                v = dict(b.start(op.get("stepUp") or _SU, _opts(op.get("opts"))))
                ident = v["auth_req_id"]
                v["auth_req_id"] = "ID"
            elif op["op"] == "poll":
                v = b.poll(ident)
            elif op["op"] == "token":
                v = b.token(ident)
            elif op["op"] == "resolve":
                v = b.resolve(ident, op["decision"], op["by"])
            elif op["op"] == "get":
                v = b.get(ident)
            else:
                v = getattr(b, op["fn"])(*(("nope", "approve", "x") if op["fn"] == "resolve" else ("nope",)))
            out.append({"ok": True, "value": _mask(v, ident)})
        except Exception:
            out.append({"ok": False})
    return out


_SU = {"id": "su1", "verb": "stripe.payout", "resource": "acct:1", "params": {"amount": 80, "currency": "USD", "payee": "bob"}, "tier": 3,
       "reason": "r", "goalCommit": "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopq", "goal": "pay suppliers", "lineage": {}, "r": 0.5, "requestedAt": 1}


def _ping(inp, flow):
    return CC.verify_ping_callback(inp, {"auth_req_id": flow.get("authReqId"), "client_notification_token": flow.get("clientNotificationToken")})


MAP = {
    "cibaActionFromStepUp": C.ciba_action_from_step_up,
    "asciiForm": C.ascii_form,
    "toCibaAuthRequest": lambda s, o=None: C.to_ciba_auth_request(s, _opts(o)),
    "requiresCiba": C.requires_ciba,
    "cibaDecisionToCosign": lambda d, b, p, n, o=None: C.ciba_decision_to_cosign(d, b, p, n, bool((o or {}).get("full"))),
    "verifyPingCallback": _ping,
    "lifecycle": _lifecycle,
}


def test_every_fn_is_mapped():
    assert set(CASES) == set(MAP)
    assert COUNT == sum(len(v) for v in CASES.values())


@pytest.mark.parametrize("fn", sorted(MAP))
def test_replay(fn):
    run(CASES[fn], MAP[fn])


# ---- client, stores, conformance ---------------------------------------------------------------------------------------------

def _client(responses, **kw):
    calls = []
    q = list(responses)

    def fetch(url, headers, body, timeout_ms):
        calls.append((url, headers, body))
        return q.pop(0) if len(q) > 1 else q[0]

    sleeps = []
    clock = {"t": 0}
    c = CC.create_ciba_client(backchannel_authentication_endpoint="https://op/bc", token_endpoint="https://op/token", client_id="id", client_secret="s e",
                              fetch=fetch, sleep=lambda ms: (sleeps.append(ms), clock.__setitem__("t", clock["t"] + ms)), now=lambda: clock["t"], **kw)
    return c, calls, sleeps


def _ok(body):
    return {"status": 200, "body": json.dumps(body)}


def _err(status, error):
    return {"status": status, "body": json.dumps({"error": error})}


def test_client_initiate_and_poll_discipline():
    c, calls, sleeps = _client([_ok({"auth_req_id": "r1", "expires_in": 120, "interval": 2}), _err(400, "authorization_pending"), _err(400, "slow_down"),
                                _ok({"access_token": "a", "token_type": "Bearer"})])
    flow = c.initiate(_SU, {"login_hint": "alice", "delivery": "ping"})
    assert flow.auth_req_id == "r1" and flow.interval_sec == 2 and flow.client_notification_token
    assert "client_notification_token=" in calls[0][2] and "login_hint=alice" in calls[0][2]
    assert calls[0][1]["authorization"] == "Basic " + __import__("base64").b64encode(b"id:s%20e").decode()
    p = c.poller(flow)
    r = p.wait()
    assert r["status"] == "approved" and r["tokens"]["access_token"] == "a"
    assert sleeps == [2000, 2000, 7000]
    assert p.wait() == r and len(calls) == 4


def test_client_refusals():
    c, _, _ = _client([_ok({})])
    with pytest.raises(ValueError):
        c.initiate(_SU, {})
    with pytest.raises(ValueError):
        c.initiate(_SU, {"login_hint": "a", "login_hint_token": "b"})
    with pytest.raises(ValueError):
        c.initiate(_SU, {"login_hint": "a", "client_notification_token": "short"})
    with pytest.raises(CC.CibaProviderError):
        c.initiate(_SU, {"login_hint": "a"})
    with pytest.raises(ValueError):
        CC.create_ciba_client(backchannel_authentication_endpoint="http://op/bc", token_endpoint="https://op/t", client_id="i", client_secret="s")


def test_ping_callback():
    flow = {"auth_req_id": "r1", "client_notification_token": "t" * 30}
    assert CC.verify_ping_callback({"authorization": "Bearer " + "t" * 30, "body": {"auth_req_id": "r1"}}, flow) == "r1"
    with pytest.raises(ValueError):
        CC.verify_ping_callback({"authorization": "Bearer nope", "body": {"auth_req_id": "r1"}}, flow)


def _stores(name, d):
    if name == "memory":
        return T.create_memory_approval_store, None

    def make_file():
        path = os.path.join(tempfile.mkdtemp(dir=d), "a.json")
        s = S.create_file_approval_store(path)
        s.path = path
        return s

    def make_dir():
        where = tempfile.mkdtemp(dir=d)
        s = S.create_kv_approval_store(S.create_directory_kv(where))
        s.where = where
        return s

    if name == "file":
        return make_file, lambda prev: S.create_file_approval_store(prev.path)
    if name == "kv-memory":
        return (lambda: S.create_kv_approval_store(T.create_memory_kv())), None
    return make_dir, lambda prev: S.create_kv_approval_store(S.create_directory_kv(prev.where))


@pytest.mark.parametrize("name", ["memory", "file", "kv-memory", "kv-directory"])
def test_store_conformance(name):
    make, reopen = _stores(name, tempfile.mkdtemp())
    report = CF.run_approval_store_conformance(make, reopen)
    assert report.ok, report.render()


def test_directory_kv_reopen_and_corrupt():
    d = tempfile.mkdtemp()
    kv = S.create_directory_kv(d)
    st = S.create_kv_approval_store(kv)
    assert st.cas("k", 0, {"v": 1})
    again = S.create_kv_approval_store(S.create_directory_kv(d))
    assert again.get("k") == {"version": 1, "value": {"v": 1}}
    kv.put_if_equals("bad", None, "not json")
    with pytest.raises(S.ApprovalStoreError):
        st.get("bad")
    with pytest.raises(S.ApprovalStoreError):
        kv.get("")
