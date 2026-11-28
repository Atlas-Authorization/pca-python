"""Differential replay: the Cloudflare Worker adapter logic of the gateway (injected next / respond) against the reference."""
from atlas_pca import gateway as G
from base_oracle import load_ref, run
from test_ref_gateway import _build, _mask

COUNT, CASES = load_ref("gateway-worker-py")


class GetOnly:
    """A header object that can look a name up but not enumerate (a Fetch Headers without forEach)."""

    def __init__(self, h):
        self.h = {k.lower(): v for k, v in h.items()}

    def get(self, name):
        return self.h.get(name.lower())


def _scenario(a):
    names = lambda r: sorted(k.lower() for k in r["headers"]) if isinstance(r["headers"], dict) else []  # noqa: E731
    req = dict(a["req"], headers=GetOnly(a["req"]["headers"]) if a["mode"] == "getonly" else a["req"]["headers"])
    # the reference scenario supplies its own rewrite for the plain and get-only modes: the request again with the dropped names filtered out of the original headers
    kw = {"rewrite_request": None} if a["mode"] == "norewrite" else {"rewrite_request": lambda r, drop: {
        "method": r["method"], "url": r["url"], "headers": {k: v for k, v in a["req"]["headers"].items() if k.lower() not in drop}}}
    try:
        mw = G.cloudflare_worker(_build(a["spec"]), lambda r: ["next", r["method"], r["url"], names(r)],
                                 lambda body, init: ["respond", _mask(body), init["status"], init["headers"]], **kw)
    except (TypeError, ValueError) as e:
        return {"create": str(e)}
    return mw(req)


def test_matches_the_reference():
    ran, _ = run(CASES["workerScenario"], _scenario)
    assert ran == COUNT


def test_default_rewrite_drops_forged_headers():
    out = []
    spec = CASES["workerScenario"][0]["args"][0]["spec"]
    mw = G.cloudflare_worker(_build(spec), lambda r: out.append(sorted(r["headers"])) or "ok", lambda b, i: "deny")
    hdrs = CASES["workerScenario"][0]["args"][0]["req"]["headers"]
    r = mw({"method": "POST", "url": "https://h.example/refunds", "headers": dict(hdrs, **{"X-PCA-Evil": "1"})})
    assert r in ("ok", "deny") and all(not k.lower().startswith("x-pca-") for h in out for k in h)
