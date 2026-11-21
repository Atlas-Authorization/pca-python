"""Replay of the TypeScript reference's adapter helpers (message segments, provenance headers, recorder flow) from
test-data/ref-adapters.json.gz: fixed key, session and clock, so the signed bundles are byte-identical."""
from types import SimpleNamespace

from base_oracle import load_ref, run

from atlas_pca import adapters
from atlas_pca.arg_provenance import create_provenance_recorder
from atlas_pca.pca import b64u
import hashlib


def _seed(label):
    return hashlib.sha256(("atlas-pca-conformance/" + label).encode()).digest()


SK = _seed("ref-adapters/recorder")
SESSION = b64u(_seed("ref-adapters/session"))


def flow(a):
    rec = create_provenance_recorder(mediator="harness", kid="k1", secret_key=SK, session=SESSION, now=lambda: 1_800_000_000_000)
    agent = SimpleNamespace(provenance=rec)
    bundles = []
    for st in a["steps"]:
        op = st["op"]
        if op == "messages":
            adapters.record_messages(agent, st["messages"])
        elif op == "input":
            adapters.record_input(agent, st["input"])
        elif op == "principal":
            adapters.record_principal(agent, st["text"])
        elif op == "tool":
            adapters.record_tool_result(agent, st["tool"], st["output"])
        elif op == "act":
            bundles.append(rec.for_action(st["action"]))
    return {"bundles": bundles, "receipts": rec.receipts()}


def test_adapters_vectors():
    count, by_fn = load_ref("adapters")
    assert count >= 70
    assert set(by_fn) == {"messageSegments", "provenanceHeaders", "recordFlow"}
    run(by_fn["messageSegments"], lambda m: adapters.message_segments(m))
    run(by_fn["provenanceHeaders"], lambda b: adapters.provenance_headers(b))
    run(by_fn["recordFlow"], flow)
