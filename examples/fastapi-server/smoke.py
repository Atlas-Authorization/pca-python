"""Call the server in-process with a pre-signed proof: one allowed action, one refusal with a doc link."""
import json
import os

from fastapi.testclient import TestClient

from app import create_app

with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "vectors.json"), encoding="utf-8") as f:
    v = json.load(f)

client = TestClient(create_app(v["grant"], v["audience"], now=v["now"]))


def post(case):
    return client.post("/refunds", content=json.dumps(v[case]["body"]), headers={"PCA-Action": v[case]["header"], "Content-Type": "application/json"})


r = post("allow")
assert r.status_code == 200 and r.json() == {"refunded": 50, "currency": "usd"}, r.text

r = post("refuse")  # a validly signed proof for a 400 payment, over the grant's limit of 100
assert r.status_code == 403 and r.json()["detail"].startswith("policy:"), r.text
assert r.json()["doc"].endswith("/reference/refusals.md#policy"), r.text

r = client.post("/refunds", content=json.dumps(v["allow"]["body"]), headers={"Content-Type": "application/json"})
assert r.status_code == 401 and "doc" in r.json(), r.text
print("ok: allowed, refused with doc, unauthenticated refused")
