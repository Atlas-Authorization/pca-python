"""Differential replay of the TypeScript reference (@atlasauth/pca-events): step-up events, signed webhooks, verify_delivery."""
import re

from atlas_pca import events as E
from atlas_pca.authorize import MemoryStateStore
from base_oracle import load_ref, run

COUNT, BY_FN = load_ref("events")
SECRET = "whsec_0123456789abcdef0123456789"
_KNOWN = re.compile(r"^(a replay store|bad signature|replayed|replay store|parseEvent: )")


class _Throws:
    def consume_once(self, *_a):
        raise RuntimeError("down")


class _Refuses:
    def consume_once(self, *_a):
        return False


def _opts(o):
    return o or {}


def delivery_scenario(spec):
    kind = spec.get("store")
    store = _Throws() if kind == "throws" else _Refuses() if kind == "refuses" else MemoryStateStore()
    out = []
    for d in spec["deliveries"]:
        secret = d["secret"] if d.get("secret") is not None else SECRET
        if spec.get("noOpts"):
            opts = None
        else:
            opts = {} if spec.get("noReplay") else {"replay": store}
            opts.update(d.get("opts") or {})
        if opts is None:
            v = E.verify_delivery(secret, d["payload"], d["header"], None)
        else:
            v = E.verify_delivery(secret, d["payload"], d["header"], opts.get("replay"), opts.get("toleranceSec"), opts.get("now"))
        r = v.get("reason")
        if v["ok"] is False and isinstance(r, str):
            # the texts of a JSON syntax error and of a canonicalisation error are engine specific
            if r.startswith("canonicalize:"):
                v = dict(v, reason="<canonicalize>")
            elif not _KNOWN.match(r):
                v = dict(v, reason="<json>")
        out.append(v)
    return out


MAP = {
    "buildStepUpEvent": E.build_step_up_event,
    "serializeEvent": E.serialize_event,
    "parseEvent": E.parse_event,
    "signWebhook": lambda s, p, o: E.sign_webhook(s, p, _opts(o).get("timestamp")),
    "webhookHeaders": lambda s, p, o: E.webhook_headers(s, p, _opts(o).get("timestamp")),
    "verifyWebhook": lambda s, p, h, o: E.verify_webhook(s, p, h, _opts(o).get("toleranceSec"), _opts(o).get("now")),
    "deliveryScenario": delivery_scenario,
    "minSecretBytes": lambda: E.MIN_SECRET_BYTES,
}


def test_every_function_is_covered():
    assert set(BY_FN) == set(MAP) and COUNT == sum(len(v) for v in BY_FN.values())


def _make(fn):
    def t():
        run(BY_FN[fn], MAP[fn])
    t.__name__ = "test_" + fn
    return t


for _fn in MAP:
    globals()["test_" + _fn] = _make(_fn)
