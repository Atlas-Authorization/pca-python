"""Call the server in-process with a pre-signed proof: one allowed action, one refusal with a doc link."""
import base64
import json
import os

from fastapi.testclient import TestClient

from atlas_pca import create_provenance_recorder, principal_direct_provenance
from app import create_app

with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "vectors.json"), encoding="utf-8") as f:
    v = json.load(f)

# The refund form acts on the user's own input (no model in between), so it records a principal-direct provenance bundle
# under a key the server pins. Keep this key where the model cannot reach it.
KEY = os.urandom(32)
PIN = create_provenance_recorder(mediator="refund-form", kid="k1", secret_key=KEY).pin
client = TestClient(create_app(v["grant"], v["audience"], [PIN], now=v["now"]))


def provenance(body):
    rec = create_provenance_recorder(mediator="refund-form", kid="k1", secret_key=KEY)
    bundle = principal_direct_provenance(rec, {"verb": "payments.send", "resource": "payments/acme", "params": body})
    return base64.urlsafe_b64encode(json.dumps(bundle).encode()).rstrip(b"=").decode()


def post(case):
    body = v[case]["body"]
    return client.post("/refunds", content=json.dumps(body), headers={
        "PCA-Action": v[case]["header"], "PCA-Provenance": provenance(body), "Content-Type": "application/json"})


r = post("allow")
assert r.status_code == 200 and r.json() == {"refunded": 50, "currency": "usd"}, r.text

r = post("refuse")  # a validly signed proof for a 400 payment, over the grant's limit of 100
assert r.status_code == 403 and r.json()["detail"].startswith("policy:"), r.text
assert r.json()["doc"].endswith("/reference/refusals.md#policy"), r.text

r = client.post("/refunds", content=json.dumps(v["allow"]["body"]), headers={"Content-Type": "application/json"})
assert r.status_code == 401 and "doc" in r.json(), r.text
print("ok: allowed, refused with doc, unauthenticated refused")
