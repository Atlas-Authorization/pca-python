"""Differential oracle: atlas_pca.sandbox (policy compile, OS profile generators, runtime-claim signing / verification, receipt
hash chains, capability handle table, egress admission policy, private-address check, reference tools) against the vectors
generated from the TypeScript reference (@atlasauth/pca-sandbox)."""
import hashlib

import pytest

from atlas_pca import ed25519, sandbox as S
from atlas_pca.pca import hash_canonical
from atlas_pca.sdjwt_jws import js_json
from base_oracle import canon, load_ref, run

COUNT, BY_FN = load_ref("sandbox")


@pytest.fixture(autouse=True, scope="module")
def _signer():
    ed25519.allow_insecure_signer(True)  # deterministic test keys derived from labels
    yield


def _seed(label):
    return hashlib.sha256(("atlas-pca-conformance/" + label).encode()).digest()


def _res(allow, bind):
    r = {"allow": allow}
    if bind:
        r["operation"] = {"verb": bind["verb"], "resource": bind["resource"], "params_digest": hash_canonical(bind["params"]),
                          "id": bind["id"] if bind.get("id") is not None else "op"}
    return r


def _receipt_log(spec):
    t = [0]
    log = S.ReceiptLog(now=lambda: t[0], sign=(lambda d: "sig:" + d) if spec["sign"] else None)
    outs = []
    for a in spec["appends"]:
        t[0] = a["t"]
        try:
            outs.append(log.append(a["rc"], a["body"]))
        except Exception:  # noqa: BLE001
            outs.append({"$err": True})
    return outs


def _verify_chain(receipts, mode):
    return S.verify_receipt_chain(receipts, (lambda d, s: s == "sig:" + d) if mode == "tag" else None)


def _policy_from_needs(needs, port=None):
    return S.policy_from_needs(needs, port)


def _compile(spec):
    items = [{"result": _res(it["allow"], it.get("bind")), "operation": it["operation"]} for it in spec["items"]]
    return S.compile_policy(items, lambda op: spec["needs"].get("%s %s" % (op["verb"], op["resource"])), spec.get("proxyPort"))


def _sign_rc(key, pub, c):
    sk = _seed(key) if isinstance(key, str) else bytes(key["short"])
    return S.sign_runtime_claim(sk, ed25519.public_key(_seed(pub if isinstance(pub, str) else "x")), c)


def _egress(spec):
    t = [0]
    p = S.EgressPolicy(lambda: t[0])
    outs = []
    for st in spec["steps"]:
        try:
            if st["op"] == "now":
                t[0] = st["t"]
                outs.append(None)
            elif st["op"] == "admit":
                p.admit(_res(st["allow"], st.get("bind")), st["operation"], lambda _op, tpl=st["template"]: tpl, st.get("opts") or {})
                outs.append("ok")
            else:
                req = {"method": st["req"]["method"]}
                if "url" in st["req"]:
                    req["url"] = st["req"]["url"]
                if "body" in st["req"]:
                    req["body"] = st["req"]["body"]
                outs.append(p.claim(req))
        except Exception:  # noqa: BLE001
            outs.append({"$err": True})
    return outs


def _throw(_op):
    raise RuntimeError("boom")


EXEC = {"fs.read": lambda _op: bytes([1, 2, 3]), "fs.echo": lambda op: js_json(op).encode("utf-8"), "fs.throw": _throw,
        "fs.notbytes": lambda _op: "nope"}


def _handles(spec):
    t = [0]
    log = S.ReceiptLog(now=lambda: t[0])
    table = S.HandleTable(spec["cls"], log, EXEC, lambda: t[0])
    outs = []
    for st in spec["steps"]:
        try:
            k = st["op"]
            if k == "now":
                t[0] = st["t"]
                outs.append(None)
            elif k == "mint":
                bind = st["bind"] if "bind" in st else dict(st["operation"], id=st.get("id", "op-h"))
                outs.append(table.mint(_res(st.get("allow", True), bind), st["operation"], st.get("opts") or {}))
            elif k == "attenuate":
                outs.append(table.attenuate(st["index"], st.get("narrower") or {}))
            elif k == "revoke":
                table.revoke(st["index"])
                outs.append(None)
            elif k == "use":
                outs.append(table.use(st["index"]))
            elif k == "verbOf":
                outs.append(table.verb_of(st["index"]))
            elif k == "size":
                outs.append(table.size)
        except Exception:  # noqa: BLE001
            outs.append({"$err": True})
    return {"outs": outs, "log": log.entries}


def _consts():
    return {"IMPORT_MODULE": S.IMPORT_MODULE, "ALLOWED_IMPORTS": S.ALLOWED_IMPORTS, "USE_ERR": S.USE_ERR, "GENESIS": S.GENESIS,
            "RUNTIME_CLASSES": S.RUNTIME_CLASSES, "DOMAIN": S.RUNTIME_CLAIM_DOMAIN}


MAP = {
    "moduleConsts": _consts,
    "satisfiesRuntimeClass": S.satisfies_runtime_class,
    "receiptLog": _receipt_log,
    "verifyReceiptChain": _verify_chain,
    "policyFromNeeds": _policy_from_needs,
    "compilePolicy": _compile,
    "seccompProfile": S.seccomp_profile,
    "landlockRuleset": S.landlock_ruleset,
    "macosProfile": S.macos_profile,
    "confineArgs": S.confine_args,
    "isPrivateAddress": S.is_private_address,
    "egress": _egress,
    "handles": _handles,
    "signRuntimeClaim": _sign_rc,
    "verifiedRuntimeClass": S.verified_runtime_class,
    "passportDigest": S.passport_digest,
    "evidenceDigest": S.evidence_digest,
    "buildTool": S.build_tool,
    "buildProbeTool": lambda cap=64: S.build_probe_tool(cap),
    "referenceComponentWat": lambda o=None: S.reference_component_wat(o),
}


def test_corpus_is_the_full_oracle():
    assert COUNT == sum(len(v) for v in BY_FN.values()) and set(BY_FN) == set(MAP)


def _cmp(got, out, c):
    return canon(got) == canon(out)


def _refused(got, c):
    return c["fn"] == "isPrivateAddress" and not isinstance(c["args"][0], str) and got is True


def test_no_address_the_reference_calls_public_is_private_here():
    misses = {c["args"][0] for c in BY_FN["isPrivateAddress"] if c["out"] is False and S.is_private_address(c["args"][0])}
    assert misses == set()


@pytest.mark.parametrize("fn", sorted(MAP))
def test_matches_the_reference(fn):
    ran, _skipped = run(BY_FN[fn], MAP[fn], compare=_cmp, refused=_refused)
    assert ran == len(BY_FN[fn])


def test_runtime_claim_strict_form():
    """Negative times and empty or over-long digests are none even when correctly signed and trusted."""
    sk = _seed("strict-attestor")
    pub = ed25519.public_key(sk)

    def run_one(over, t_over):
        c = S.sign_runtime_claim(sk, pub, dict({"class": "os_confined", "passport_digest": "pd", "evidence_digest": "ev", "iat": 0, "exp": 100}, **over))
        t = dict({"pinnedAttestors": [c["attestor"]], "passportDigest": c["passport_digest"], "verifiedEvidenceDigests": [c["evidence_digest"]], "now": 50}, **t_over)
        return S.verified_runtime_class(c, t)

    assert run_one({}, {}) == "os_confined"
    for over, t_over in [({"iat": -5}, {}), ({"iat": -10, "exp": -1}, {"now": -5}), ({"iat": -10}, {"now": -1}),
                         ({"evidence_digest": ""}, {}), ({"passport_digest": ""}, {}),
                         ({"evidence_digest": "d" * 129}, {}), ({"passport_digest": "d" * 129}, {}), ({}, {"now": 2 ** 53})]:
        assert run_one(over, t_over) == "none", (over, t_over)
    assert run_one({"evidence_digest": "d" * 128, "passport_digest": "p" * 128}, {}) == "os_confined"


def test_private_address_classifies_the_parsed_address():
    priv = ["0:0:0:0:0:0:0:1", "0::1", "::ffff:7f00:1", "::FFFF:7F00:0001", "::127.0.0.1", "::7f00:1", "64:ff9b::7f00:1", "64:ff9b::10.0.0.1",
            "::1%eth0", "fe80::1%25eth0", "2606:4700::1111%eth0", "FE80::1", "fc::1", "fec0::1", "1fff::1", "4000::1", "1::2::3", "::00001",
            "::01.2.3.4", "[::1]", " ::1", None, 1]
    for ip in priv:
        assert S.is_private_address(ip) is True, ip
    for ip in ["2606:4700:0:0:0:0:0:1111", "2001:DB8::1", "::ffff:808:808", "::ffff:8.8.8.8", "64:ff9b::8.8.8.8", "2000::", "3fff::1", "8.8.8.8"]:
        assert S.is_private_address(ip) is False, ip
