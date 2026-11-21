"""Replays the TS-reference oracle of the measurement-allowlist manifests and their transparency anchor (testdata/ref-attest-allowlist.json.gz, 959
cases): verify (every suite, every window and version rule), durable verify over one in-memory key/value store, create / sign / revoke, the driver
version slot, the projection and the per-vendor policy fields, the anchor commit and entry, the operator log (anchor, refresh, evidence) and
verify-anchored. Every fn has a handler and the totals are asserted; a reference refusal needs a native exception. A refused result is compared by its
`code` (the reason text is not part of the contract); a refused op inside a result list is {"$throws": message}: the native must refuse there too."""
import base64
import math
import os

import pytest

from atlas_pca import attest_allowlist as AL
from atlas_pca import pq_backends
from atlas_pca import attest_allowlist_anchor as AN
from atlas_pca.agent import generate_pq_keypair
from atlas_pca.durable_state import create_memory_durable_kv
from atlas_pca.pca import _SIG_SUITES
from base_oracle import HERE, canon, load, run

COUNT, CASES = load("attest-allowlist", os.path.join(HERE, "testdata", "ref-attest-allowlist.json.gz"))
FAMILY = {"ML-DSA-65": ("mlDsa", "ML-DSA-65"), "ML-DSA-87": ("mlDsa87", "ML-DSA-87")}


def _dec(v):
    if isinstance(v, dict):
        if set(v) == {"$num"}:
            return {"NaN": math.nan, "Infinity": math.inf, "-Infinity": -math.inf}[v["$num"]]
        return {k: _dec(x) for k, x in v.items()}
    return [_dec(x) for x in v] if isinstance(v, list) else v


def _b64d(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _secrets(spec):
    k = {}
    if "edSecret" in spec:
        k["edSecret"] = _b64d(spec["edSecret"])
    suite = _SIG_SUITES.get(spec["alg"])
    if "seed" in spec and suite is not None and suite[3] in FAMILY:
        member, family = FAMILY[suite[3]]
        k[member] = generate_pq_keypair(family, _b64d(spec["seed"]))
    return k


def _durable(args):
    kv = create_memory_durable_kv()
    for k, v in (args.get("initial") or {}).items():
        kv.set(k, v)
    results = [AL.verify_allowlist_durable(step, args["opts"], kv) for step in args["steps"]]
    return {"results": results, "kv": kv.snapshot()}


def _sign(body, o):
    return AL.sign_allowlist_manifest(body, o["issuer"], o["alg"], _secrets(o["keySpec"]))


def _policy(fn, projection):
    return {"azureMaaPolicyFields": AL.azure_maa_policy_fields, "intelDcapPolicyFields": AL.intel_dcap_policy_fields,
            "sevSnpPolicyFields": AL.sev_snp_policy_fields, "gcpCsPolicyFields": AL.gcp_cs_policy_fields,
            "nvidiaCcPolicyFields": AL.nvidia_cc_policy_fields}[fn](projection)


def _anchor_ops(a):
    log = AN.create_allowlist_anchor_log(a["instanceId"], a["principal"])
    secret = _b64d(a["secret"])
    out = []
    for op in a["ops"]:
        try:
            if "anchor" in op:
                out.append(AN.anchor_allowlist_head(log, op["anchor"], secret, op["nowMs"]))
            elif "refresh" in op:
                out.append(AN.refresh_anchor_head(log, secret, op["refresh"]))
            elif "evidenceFor" in op:
                out.append(AN.evidence_for(log, op["evidenceFor"], op.get("cached")))
            elif op.get("latest"):
                out.append(log.latest())
            elif op.get("entries"):
                out.append(log.entries())
            else:
                raise ValueError("bad op")
        except Exception as e:  # noqa: BLE001 - a refused op: {"$throws": message}
            out.append({"$throws": str(e)})
    return out


HANDLERS = {
    "constants": lambda: {"ALLOWLIST_KINDS": AL.ALLOWLIST_KINDS, "DOMAIN": "pca-attest-allowlist/v1\n"},
    "verifyAllowlistManifest": AL.verify_allowlist_manifest, "verifyAllowlistDurable": _durable, "createAllowlistManifest": AL.create_allowlist_manifest,
    "signAllowlistManifest": _sign, "revokeAllowlistEntry": AL.revoke_allowlist_entry, "driverVersionSlotHex": AL.driver_version_slot_hex,
    "projectAllowlist": lambda v, o: AL.project_allowlist(v, o["nowMs"]), "policyFields": _policy,
    "anchorCommit": AN.allowlist_anchor_commit, "anchorEntryOf": AN.anchor_entry_of, "anchorOps": _anchor_ops,
    "verifyAnchored": lambda a: AN.verify_allowlist_anchored_result(a["verified"], a["evidence"], a["opts"]),
}
TOTALS = {"constants": 1, "verifyAllowlistManifest": 744, "verifyAllowlistDurable": 23, "createAllowlistManifest": 6, "signAllowlistManifest": 10,
          "revokeAllowlistEntry": 11, "driverVersionSlotHex": 13, "projectAllowlist": 9, "policyFields": 45, "anchorCommit": 4, "anchorEntryOf": 1,
          "anchorOps": 20, "verifyAnchored": 72}


def _same(got, out, _case):
    if isinstance(out, dict) and out.get("ok") is False and "code" in out:
        return isinstance(got, dict) and got.get("ok") is False and got.get("code") == out["code"]
    if isinstance(out, dict) and set(out) == {"$throws"}:
        return isinstance(got, dict) and set(got) == {"$throws"}
    if isinstance(out, dict) and isinstance(got, dict):
        return set(out) == set(got) and all(_same(got[k], out[k], None) for k in out)
    if isinstance(out, list) and isinstance(got, list):
        return len(out) == len(got) and all(_same(g, o, None) for g, o in zip(got, out))
    return canon(got) == canon(out)


def test_every_corpus_fn_has_a_handler_and_the_total_is_pinned():
    assert COUNT == 959 and set(CASES) == set(HANDLERS)
    assert {fn: len(cs) for fn, cs in CASES.items()} == TOTALS
    assert sum(1 for cs in CASES.values() for c in cs if isinstance(c["out"], dict) and "$throws" in c["out"]) == 17


@pytest.mark.parametrize("fn", sorted(HANDLERS))
def test_attest_allowlist_replay(fn):
    # SLH-DSA manifests verify only through OpenSSL >= 3.5 (no audited pure-Python SLH-DSA): where it is absent their positive cases are
    # not runnable, never reported as passed
    no_slh = not pq_backends.openssl_available("SLH-DSA-SHA2-128f")
    skip = (lambda c: "needs OpenSSL >= 3.5 for SLH-DSA" if "slh-dsa" in c["name"] and "/ok-" in c["name"] else None) if no_slh else None
    nskip = sum(1 for c in CASES[fn] if skip and skip(c))
    assert run(CASES[fn], lambda *a: HANDLERS[fn](*_dec(list(a))), compare=_same, skip=skip) == (TOTALS[fn] - nskip, nskip)
