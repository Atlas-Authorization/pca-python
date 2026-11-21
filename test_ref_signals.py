"""Differential replay of the Shared Signals Framework / CAEP port (atlas_pca.signals) against the TypeScript reference
(@atlasauth/pca-signals): token build and verification, revocation state, replay store, receiver, adapters, stream health,
verification, poll queue, push response, CAEP builders and the stream management API. Scenario fns replay the reference's
scripted operations over the native API."""
import base64
import copy
import hashlib
import json
import re
import time

import pytest

from atlas_pca import ed25519
from atlas_pca import signals as S
from base_oracle import b64d, load_ref, near_clock, reference_clock_ms, run

COUNT, CASES = load_ref("signals")
CLOCK = reference_clock_ms(CASES)
ET = S.EVENT_TYPES


@pytest.fixture(autouse=True, scope="module")
def _pure_signer():
    ed25519.allow_insecure_signer(True)  # throwaway test keys only
    yield
    ed25519.allow_insecure_signer(False)


def seed(label):
    return hashlib.sha256(("atlas-pca-conformance/" + label).encode()).digest()


K1_SEED = seed("ref-signals/tx")
K1_PUB = ed25519.public_key(K1_SEED)
T = 1_800_000_000


class Coded(Exception):
    def __init__(self, code, msg):
        super().__init__(msg)
        self.code = code


def pub(jwk):
    """The reference imports a public JWK through the platform crypto; a malformed one is refused with a platform code."""
    if isinstance(jwk, dict):
        if jwk.get("kty") != "OKP" or jwk.get("crv") != "Ed25519" or not isinstance(jwk.get("x"), str):
            raise Coded("ERR_CRYPTO_INVALID_JWK", "Invalid JWK")
        return b64d(jwk["x"])
    return jwk


def priv(jwk):
    if isinstance(jwk, dict):
        if jwk.get("kty") != "OKP" or not isinstance(jwk.get("d"), str):
            raise Coded("ERR_CRYPTO_INVALID_JWK", "JWK does not contain private key material")
        return b64d(jwk["d"])
    return jwk


def jsonof(v):
    return json.loads(json.dumps(None if v is None else v))


def err_out(e):
    c = getattr(e, "code", None)
    out = {"$err": True}
    if isinstance(c, str) and not c.startswith("ERR_") and not c.startswith("N"):
        out["code"] = c
    return out


def state_out(st):
    return {"grants": [[k, v] for k, v in st.revoked_grants.items()], "agents": [[k, v] for k, v in st.killed_agents.items()],
            "intents": None if st.revoked_intent_ids is None else [[k, v] for k, v in st.revoked_intent_ids.items()]}


def shape(set_):
    h, p, s = set_.split(".")
    header = json.loads(b64d(h))
    payload = json.loads(b64d(p))
    if isinstance(payload.get("iat"), (int, float)) and near_clock(payload["iat"] * 1000, CLOCK):
        payload["iat"] = "<now>"
    if isinstance(payload.get("jti"), str) and re.fullmatch(r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}", payload["jti"]):
        payload["jti"] = "<uuid>"
    return {"header": header, "payload": payload, "sigOk": ed25519.verify(K1_PUB, (h + "." + p).encode(), b64d(s))}


def parsed_out(r):
    out = {"events": r["events"], "iss": r["iss"], "jti": r["jti"], "payload": r["payload"]}
    if "sub" in r:
        out["sub"] = r["sub"]
    return out


# ---- scripted function options -----------------------------------------------------------------------------------------------

def _boom(_s):
    raise RuntimeError("x")


MAPPERS = {
    "email": lambda s: s["email"] if s.get("format") == "email" and isinstance(s.get("email"), str) else None,
    "throws": _boom, "empty": lambda s: "", "num": lambda s: 5,
    "id": lambda s: s["id"] if isinstance(s.get("id"), str) else None,
    "prefixed": lambda s: "agent:" + s["id"] if isinstance(s.get("id"), str) else None,
}


def std_opts(sp):
    if sp is None:
        return None
    o = {}
    if sp.get("mapper") and sp["mapper"] != "default":
        o["subjectToAgent"] = MAPPERS[sp["mapper"]]
    if "fail" in sp:
        o["failOnUnmapped"] = sp["fail"]
    return o


def _grant_id(ctx):
    g = ctx["grant"]
    return g.get("id") if isinstance(g, dict) else None


AGENTS = {"throws": lambda ctx: _boom(ctx), "empty": lambda ctx: "", "num": lambda ctx: 5, "grantId": _grant_id}


def agent_of(name):
    if name is None or name == "leaf":
        return None
    if isinstance(name, str) and name.startswith("const:"):
        return lambda ctx: name[6:]
    return AGENTS.get(name)


# ---- fns --------------------------------------------------------------------------------------------------------------------

def constants():
    return {"SET_TYP": S.SET_TYP, "SET_ALG": S.SET_ALG, "EVENT_TYPES": S.EVENT_TYPES, "RISC_EVENT_TYPES": S.RISC_EVENT_TYPES,
            "SET_INMEMORY_MAX_ENTRIES": S.SET_INMEMORY_MAX_ENTRIES, "DELIVERY_PUSH": S.DELIVERY_PUSH,
            "DELIVERY_POLL": S.DELIVERY_POLL, "STREAM_STATUSES": S.STREAM_STATUSES}


def verify_set(set_, key, op):
    opts = dict(op) if isinstance(op, dict) else op
    if isinstance(opts, dict) and "currentDate" not in opts:
        opts["currentDate"] = CLOCK  # the reference corpus was generated with its clock frozen
    return parsed_out(S.verify_set(set_, pub(key), opts))


def build_set_shape(a):
    seed_ = priv(a.get("keyJwk"))
    return shape(S.build_set(a.get("events"), a.get("issuer"), a.get("audience"), seed_, subject=a.get("subject")))


def state_scenario(spec):
    st = S.create_revocation_state()
    out = []
    for s in spec["ops"]:
        try:
            target = {} if s.get("badState") else st
            op = s["op"]
            if op == "apply":
                S.apply_set(st, s.get("parsed"))
                r = state_out(st)
            elif op == "applyStd":
                r = {"plan": S.apply_standard_revocations(target, s.get("parsed"), std_opts(s.get("std"))), "state": state_out(st)}
            elif op == "plan":
                r = S.plan_standard_revocations(s.get("parsed"), std_opts(s.get("std")))
            elif op == "isRevoked":
                r = S.is_revoked(st, s["grant"], s.get("agent"))
            elif op == "isIntentRevoked":
                r = S.is_intent_revoked(st, s["id"])
            elif op == "stream":
                r = state_out(S.stream_processor(s.get("sets"), st if s.get("useState") else None))
            elif op == "snapshot":
                r = S.snapshot_revocation_state(target)
            elif op == "restore":
                into = S._DEFAULT if s.get("fresh") else (None if s.get("nullInto") else target)
                r = state_out(S.restore_revocation_state(s.get("snapshot"), into))
            else:
                raise ValueError("bad op")
            out.append(jsonof(r))
        except Exception as e:  # noqa: BLE001
            out.append(err_out(e))
    out.append(state_out(st))
    return out


def replay_scenario(spec):
    try:
        store = S.create_in_memory_set_replay_store(spec.get("opts", S._DEFAULT))
    except Exception as e:  # noqa: BLE001
        return [err_out(e)]
    out = []
    for jti, exp, now in spec["ops"]:
        try:
            out.append(store.add_if_absent(jti, exp, now))
        except Exception:  # noqa: BLE001
            out.append({"$err": True})
    return out


class _Const:
    def __init__(self, v):
        self.v = v

    def add_if_absent(self, jti, exp, now):
        return self.v


class _NoExpiry:
    def __init__(self):
        self.seen = set()

    def add_if_absent(self, jti, exp, now):
        if jti in self.seen:
            return False
        self.seen.add(jti)
        return True


class _Throws:
    def add_if_absent(self, jti, exp, now):
        raise RuntimeError("boom")


def replay_conformance(spec):
    def make():
        k = spec.get("store")
        if k == "alwaysTrue":
            return _Const(True)
        if k == "alwaysFalse":
            return _Const(False)
        if k == "noExpiry":
            return _NoExpiry()
        return S.create_in_memory_set_replay_store(spec.get("opts", S._DEFAULT))

    return S.run_set_replay_store_conformance(make)


def receive_scenario(spec):
    st = S.create_revocation_state()
    k = spec.get("store")
    store = _Throws() if k == "throws" else _Const(False) if k == "false" else \
        S.create_in_memory_set_replay_store({"maxEntries": 1}) if k == "mem1" else S.create_in_memory_set_replay_store()
    out = []
    for d in spec["deliveries"]:
        op = dict(d.get("opts") or {})
        if not d.get("noStore"):
            op["replayStore"] = store
        if not d.get("noState"):
            op["state"] = st
        if d.get("std") is not None:
            op["standardRevocations"] = std_opts(d["std"])
        try:
            key = d["key"] if "key" in d else None
            r = S.receive_set(d.get("set"), pub(key) if key is not None else K1_PUB, None if d.get("noOpts") else op)
        except Exception:  # noqa: BLE001
            r = {"$err": True}
        if r.get("ok") is False and r.get("code") == "verify_failed" and not str(r.get("reason")).startswith("SET invalid:"):
            r = dict(r, reason="<jose>")
        out.append(jsonof({"ok": True, "parsed": parsed_out(r["parsed"])} if r.get("ok") is True else r))
    out.append(state_out(st))
    return out


def adapter_scenario(spec):
    out = []
    try:
        if "badState" in spec:
            st = None if spec["badState"] == "null" else {}
        else:
            st = S.restore_revocation_state({"v": 1, "grants": spec.get("grants", []), "agents": spec.get("agents", []), "intents": []})
        opts = {"agentOf": agent_of(spec.get("agentOf"))}
        hook = S.create_revocation_hook(st, opts)
        is_rev = S.create_is_revoked(st, opts)
    except Exception as e:  # noqa: BLE001
        return [err_out(e)]
    for c in spec["calls"]:
        try:
            a = hook({"pcactn": c.get("pcactn"), "grant": c.get("grant")})
        except Exception:  # noqa: BLE001
            a = {"$err": True}
        try:
            b = is_rev(c.get("grant"), c.get("pcactn"))
        except Exception:  # noqa: BLE001
            b = {"$err": True}
        out.append({"hook": jsonof(a), "isRevoked": b})
    return out


CFG = {"stream_id": "s1", "iss": "https://tx.example", "aud": "rx", "events_supported": [ET["grantRevoked"], ET["killSwitch"]],
       "events_delivered": [ET["grantRevoked"]], "delivery": {"method": S.DELIVERY_POLL, "endpoint_url": "https://tx.example/poll/s1"},
       "min_verification_interval": 30, "description": "d"}


def health_scenario(spec):
    h = S.StreamHealth(spec.get("config") or CFG, spec.get("opts"))
    issued = []
    out = []
    for s in spec["ops"]:
        try:
            op = s["op"]
            r = None
            if op == "status":
                h.set_status(s.get("v"))
            elif op == "event":
                h.record_event(s["now"])
            elif op == "request":
                r = h.request_verification(s["now"])
                if isinstance(r, str):
                    issued.append(r)
                    r = "<state:%d>" % (len(issued) - 1)
            elif op == "ack":
                state = (issued[s["ref"]] if 0 <= s["ref"] < len(issued) else None) if "ref" in s else s.get("state")
                r = h.ack_verification(state, s["now"])
            elif op == "report":
                r = h.report(s["now"])
            elif op == "fresh":
                r = h.revocation_fresh_within(s["max"], s["now"])
            else:
                raise ValueError("bad op")
            out.append(jsonof(r))
        except Exception:  # noqa: BLE001
            out.append({"$err": True})
    return out


def verification_scenario(spec):
    streams = copy.deepcopy(spec.get("streams") or {})
    out = []
    for s in spec["ops"]:
        try:
            r = S.handle_verification_request(streams, s.get("req"), s["now"], None if s.get("noKey") else K1_SEED)
            if r["status"] == 204:
                r = {"status": 204, "set": shape(r["set"])}
        except Exception:  # noqa: BLE001
            r = {"$err": True}
        out.append(jsonof(r))
    out.append({k: v.get("lastVerification") for k, v in streams.items()})
    return out


def poll_scenario(spec):
    q = S.PollQueue()
    out = []
    for s in spec["ops"]:
        try:
            if "enqueue" in s:
                q.enqueue(s["enqueue"][0], s["enqueue"][1])
                r = None
            elif s.get("depth"):
                r = q.depth
            else:
                r = q.poll(s.get("poll"))
            out.append(jsonof(r))
        except Exception:  # noqa: BLE001
            out.append({"$err": True})
    out.append({"depth": q.depth, "errors": jsonof(q.errors)})
    return out


def caep_set(a):
    args = {"issuer": a.get("issuer"), "audience": a.get("audience"), "key": priv(a.get("keyJwk")), "event": a.get("event"),
            "order": a.get("order")}
    return shape(S.risk_level_change_set(args) if a["kind"] == "risk" else S.assurance_level_change_set(args))


def manage_scenario(spec):
    store = S.MemoryStreamStore()
    delivered = []
    ids = [0]
    cur = {}

    def new_id():
        ids[0] += 1
        return "s%d" % ids[0]

    def auth(_req):
        if cur["rcv"] == "throws":
            raise RuntimeError("auth")
        return cur["rcv"]

    opts = {"store": store, "issuer": "https://tx.example",
            "eventsSupported": spec.get("eventsSupported", [ET["grantRevoked"], ET["killSwitch"], ET["sessionRevoked"]]),
            "pollEndpoint": lambda i: "https://tx.example/poll/%s" % i, "signingKey": K1_SEED,
            "deliver": lambda stream, set_: delivered.append({"stream": copy.deepcopy(stream), "set": shape(set_)}),
            "now": lambda: cur["now"], "newId": new_id}
    opts.update(spec.get("options") or {})
    h = S.ssf_management_handler(opts, auth)
    out = []
    for st in spec["steps"]:
        cur.clear()
        cur.update({"now": st.get("now", 1000), "rcv": st["rcv"] if "rcv" in st else {"id": "rx1", "aud": "rx"}})
        try:
            r = h(st.get("req"))
        except Exception:  # noqa: BLE001
            r = {"$err": True}
        out.append(jsonof(r))
    dump = {rid: jsonof(store.list_by_receiver(rid)) for rid in spec.get("receivers", ["rx1", "rx2"])}
    out.append({"delivered": jsonof(delivered), "store": dump})
    return out


MAP = {
    "constants": constants,
    "verifySET": verify_set,
    "buildSETShape": build_set_shape,
    "stateScenario": state_scenario,
    "replayScenario": replay_scenario,
    "replayConformance": replay_conformance,
    "receiveScenario": receive_scenario,
    "adapterScenario": adapter_scenario,
    "validateStreamConfig": S.validate_stream_config,
    "healthScenario": health_scenario,
    "verificationScenario": verification_scenario,
    "pollScenario": poll_scenario,
    "pushResponse": S.push_response,
    "caepSET": caep_set,
    "manageScenario": manage_scenario,
    "transmitterMetadata": S.transmitter_metadata,
}


def test_corpus_is_the_full_oracle():
    assert COUNT == 2465 and set(CASES) == set(MAP)


@pytest.mark.parametrize("fn", sorted(MAP))
def test_matches_the_reference(fn):
    run(CASES[fn], MAP[fn])


def test_built_token_verifies_and_is_single_use_under_the_receiver():
    st = S.create_revocation_state()
    store = S.create_in_memory_set_replay_store()
    now = int(time.time())
    tok = S.build_set({ET["grantRevoked"]: {"grant_ref": "g", "reason": "r", "event_timestamp": now}}, "iss", "aud", K1_SEED)
    o = {"issuer": "iss", "audience": "aud", "replayStore": store, "state": st, "maxAgeSec": 300}
    assert S.receive_set(tok, K1_PUB, o)["ok"] is True and S.is_revoked(st, "g")
    assert S.receive_set(tok, K1_PUB, o)["code"] == "replay"
