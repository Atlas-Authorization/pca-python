"""Characterization snapshots for mutation testing: collect(), the verifier's observable outputs (verdict reasons, strict-parse error
text, number-error text, chain verdicts) over the shared conformance corpus (core + adversarial). test_mutation_snapshots.py pins them
against testdata/mutation-snapshots.json.gz. Regenerate deliberately with:  python mutation_snapshots.py  (review the diff!)."""
import copy
import gzip
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from atlas_pca import StrictJsonError, canonicalize_strict, strict_parse, verify_pcactn_core
from atlas_pca.pca import decode_b64u_strict, strict_number_error, verify_chain
from test_conformance import DIR, DOC, _terminal_wire_false, _unsupported_suite

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "testdata", "mutation-snapshots.json.gz")
EXTRA_JSON = [
    "", " ", "{", "}", "[", "]", "[1,]", "[,1]", "{,}", '{"a"}', '{"a":}', '{"a":1,}', '{"a":1 "b":2}', '{a:1}', "{'a':1}", "nul", "tru", "fals",
    "null x", "01", "-", "-0", "+1", "1.", ".5", "1e", "1e+", "1E5", "1.5e3", "0.0", "-0.0", "9007199254740993", "-9007199254740993", "1e400",
    "123456789012345678901234567890", "NaN", "Infinity", "-Infinity", '"abc', '"a\\x"', '"\\u12"', '"\\u12G4"', '"\\ud800"', '"\\udc00"',
    '"\\ud800\\udc00"', '"\\ud83d\\ude00"', '"\\ud800a"', '"\\udc00\\ud800"', '"\\ud800\\ud800"', '"\u0001"', '"\t"', '"\\t\\n\\r\\b\\f\\/\\\\\\""',
    '{"a":1,"a":2}', '{"a":{"b":1,"b":2}}', '{"__proto__":1}', '[[[[[[[[[[1]]]]]]]]]]', '  [ 1 , 2 ]  ', "﻿[1]", "[1]\n", "[1]x", "é", '"é"',
    '"\\u0000"', '{"a":[1,{"b":null}],"c":true}', '{"b":1,"a":2}', "1 2", "[1 2]", "{\"a\" 1}", '{"a":1 ', '[1,', '"', "\\", "tr", "n", "-a", "0x10", "1_0",
] + ["[" * n + "]" * n for n in (1, 5, 20, 33, 64, 65, 100, 200)] + ["1" * n for n in (15, 16, 17, 20)]
NUMS = [True, False, None, "1", [], {}, 0, 1, -1, 2 ** 53 - 1, 2 ** 53, -(2 ** 53), -(2 ** 53) + 1, 2 ** 63, 0.0, -0.0, 0.5, 1.0, 1e21, 1e-7, 123456.789,
        float("nan"), float("inf"), float("-inf"), 1.7976931348623157e308, 5e-324, 2.5, 100.0, 1e15, 1e16, 9007199254740992.0, -1e21]


def load_adv():
    with gzip.open(os.path.join(DIR, "vectors-adversarial.json.gz"), "rt", encoding="utf-8") as f:
        return json.load(f)


def parse_outcome(s):
    try:
        return ["ok", canonicalize_strict(strict_parse(s))]
    except StrictJsonError as e:
        return ["err", str(e)]
    except Exception as e:  # noqa: BLE001 - the exact exception type is part of the contract being pinned
        return ["exc", type(e).__name__, str(e)]


def collect():
    adv = load_adv()
    out = {"vectors": {}, "parse": {}, "nums": {}, "chains": {}, "b64u": {}}
    for src, vs in (("core", DOC["vectors"]), ("adv", adv["vectors"])):
        for v in vs:
            suite = _unsupported_suite(v)
            if suite is not None and not _terminal_wire_false(v):
                continue
            raw = v["pcactn_json"] if "pcactn_json" in v else v["pcactn"]
            ctx = v["context"]
            got = verify_pcactn_core(raw, v["grant"], now=ctx["now"], audience=ctx["aud"], allowed_suites=ctx.get("allowed_suites"))
            out["vectors"][src + ":" + v["name"]] = [got.allow, got.checks, got.reason]
            p = v.get("pcactn")
            chain = p.get("cap_chain") if isinstance(p, dict) else None
            if isinstance(chain, list):
                for tag, kw in (("plain", {}), ("root", {"expected_root_issuer": (chain[0] or {}).get("issuer") if chain and isinstance(chain[0], dict) else None}),
                                ("wrongroot", {"expected_root_issuer": "x"})):
                    try:
                        r = verify_chain(copy.deepcopy(chain), **kw)
                        out["chains"][f"{src}:{v['name']}:{tag}"] = [r[0], r[1]]
                    except Exception as e:  # noqa: BLE001
                        out["chains"][f"{src}:{v['name']}:{tag}"] = ["exc", type(e).__name__, str(e)]
    inputs = list(EXTRA_JSON)
    for d in (DOC["primitives"], adv["primitives"]):
        inputs += [c["input"] for c in d.get("json_parse", [])]
    for s in inputs:
        out["parse"][s] = parse_outcome(s)
    for i, n in enumerate(NUMS):
        out["nums"][str(i)] = strict_number_error(n)
    for d in (DOC["primitives"], adv["primitives"]):
        for c in d.get("b64u", []):
            r = decode_b64u_strict(c["input"], c.get("len"))
            out["b64u"][f"{c['input']}|{c.get('len')}"] = None if r is None else r.hex() if isinstance(r, (bytes, bytearray)) else repr(r)
    return out


if __name__ == "__main__":
    data = collect()
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with gzip.GzipFile(OUT, "wb", mtime=0) as f:
        f.write(json.dumps(data, sort_keys=True, ensure_ascii=True, separators=(",", ":")).encode())
    print({k: len(v) for k, v in data.items()}, os.path.getsize(OUT))
