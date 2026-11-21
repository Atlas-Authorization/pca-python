"""K5 vault and aggregate reads (C-315..C-319): replays packages/pca/conformance/vault-aggregate-vectors.json (a missing file FAILS)."""
import json
import os
import unittest

from atlas_pca.read_vault import (aggregate_read, detokenize, discrete_laplace, empty_aggregate_state, memory_vault,
                                  redact_read_with_vault, seeded_draws)

_P = os.path.join(os.path.dirname(os.path.abspath(__file__)), "conformance", "vault-aggregate-vectors.json")
with open(_P, encoding="utf-8") as f:  # no skip: an absent file is an error
    VA = json.load(f)

_DEFAULTS = {"principal": VA["keys"]["principal"], "now": 1_800_000_000_000, "verb": "orders.stats", "resource": "orders/eu",
             "purpose": "analytics", "fn": "sum", "values": [10, 20, 500, -900], "salt": "a-per-read-secret-salt", "noise": "seeded"}


class SamplerVectors(unittest.TestCase):
    def test_streams(self):
        for u in VA["sampler"]["uniform"]:
            d = seeded_draws(u["seed"])
            self.assertEqual([d.uniform(n) for n in u["bounds"]], u["draws"])
        for l in VA["sampler"]["laplace"]:
            d = seeded_draws(l["seed"])
            self.assertEqual([discrete_laplace(d, l["s"], l["t"]) for _ in l["values"]], l["values"])


class VaultVectors(unittest.TestCase):
    def test_cases(self):
        self.assertGreater(len(VA["vault"]), 0)
        for c in VA["vault"]:
            with self.subTest(c["name"]):
                store = memory_vault()
                red = redact_read_with_vault({**c["redact"], "grant": VA["grants"]["vault"][c["redact_grant"]]}, store)
                token = c["token"] if c.get("token") is not None else red["view"].get(c.get("field"))
                got = detokenize({"grant": VA["grants"]["vault"][c["detok_grant"]], **c["detok"], "token": token, "store": store})
                self.assertEqual(got, c["expect"])

    def test_total(self):
        for x in (None, 1, "x", {}, {"grant": 1}):
            self.assertEqual(detokenize(x)["decision"], "deny")


class AggregateVectors(unittest.TestCase):
    def test_scenarios(self):
        self.assertGreater(len(VA["aggregate"]), 0)
        for c in VA["aggregate"]:
            with self.subTest(c["name"]):
                state = c["initial_state"]
                for s in c["steps"]:
                    r = aggregate_read({**_DEFAULTS, **s["input"], "grant": VA["grants"]["aggregate"][s["input"]["grant"]], "state": state})
                    self.assertEqual(r, s["expect"])
                    state = r["state"]

    def test_strict_and_total(self):
        g = VA["grants"]["aggregate"]["main"]
        base = {**_DEFAULTS, "grant": g, "state": empty_aggregate_state()}
        for bad in ({"values": [1.5, 2, 3]}, {"values": [True, 2, 3]}, {"values": ["1", 2, 3]}):
            self.assertEqual(aggregate_read({**base, **bad})["code"], "bad_request")
        for bad in (None, 1, {}, {**base, "state": {"spent_micro": 0.0, "queries": 0, "answered": {}}}):
            r = aggregate_read(bad)
            self.assertEqual((r["decision"], r["code"], r["state"]), ("deny", "bad_request", empty_aggregate_state()))

    def test_secure_noise_differs(self):
        g = VA["grants"]["aggregate"]["main"]
        outs = {aggregate_read({**_DEFAULTS, "grant": g, "state": empty_aggregate_state(), "noise": "secure", "fn": "count", "values": [0, 1, 2]})["value"]
                for _ in range(40)}
        self.assertGreater(len(outs), 1)  # fresh randomness per call (values themselves are not asserted)


if __name__ == "__main__":
    unittest.main()
