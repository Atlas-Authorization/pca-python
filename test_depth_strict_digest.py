"""Protocol digests use the STRICT canonical form, like the reference (hash.ts canonicalBytes == canonicalizeStrict):
nesting depth <= MAX_JSON_DEPTH (32, same counting), safe integers only, no lone surrogates. A hop whose body is out of
profile is refused even when it is correctly signed over a lenient digest (the reference cannot hash it: TS refuses the
chain, so a lenient native would accept a chain the reference rejects). No exception or RecursionError escapes."""
import copy
import hashlib

from atlas_pca import ed25519 as E
from atlas_pca.pca import (
    CAP_DOMAIN,
    MAX_JSON_DEPTH,
    b64u,
    canonicalize,
    hash_canonical,
    sha256,
    strict_parse,
    unb64u,
    verify_chain,
    verify_inclusion,
    verify_pcactn_core,
    verify_threshold_share,
)


# ---- a tiny RFC 8032 signer over the verifier's own curve arithmetic (tests only) -----------------------------
def _enc(P):
    zi = E._inv(P[2])
    x, y = P[0] * zi % E._p, P[1] * zi % E._p
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


def _keys(label):
    h = hashlib.sha512(hashlib.sha256(label.encode()).digest()).digest()
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    return a, h[32:], _enc(E._mul(a, E._G))


def _sign(k, msg):
    a, prefix, A = k
    r = int.from_bytes(hashlib.sha512(prefix + msg).digest(), "little") % E._q
    R = _enc(E._mul(r, E._G))
    h = int.from_bytes(hashlib.sha512(R + A + msg).digest(), "little") % E._q
    return R + ((r + h * a) % E._q).to_bytes(32, "little")


def _lenient_digest(v):
    # what an attacker holding a delegation key can compute for an out-of-profile body
    return b64u(sha256(canonicalize(v).encode("utf-8", "surrogatepass")))


PRINCIPAL, AGENT, SUB = _keys("principal"), _keys("agent"), _keys("sub")


def _hop(issuer_k, holder_k, caveats, parent=None):
    body = {"issuer": b64u(issuer_k[2]), "holder": b64u(holder_k[2]), "caveats": caveats, "parent": parent}
    d = _lenient_digest(body)
    hop = {"id": d, "issuer": body["issuer"], "holder": body["holder"], "caveats": caveats, "body_digest": d,
           "sig": b64u(_sign(issuer_k, CAP_DOMAIN + unb64u(d)))}
    if parent is not None:
        hop["parent"] = parent
    return hop


def _nest(k):
    v = 1
    for _ in range(k):
        v = [v]
    return v


ROOT = _hop(PRINCIPAL, AGENT, [{"type": "max_spend", "usd": 100}])


def _chain_with(extra_caveat):
    hop1 = _hop(AGENT, SUB, ROOT["caveats"] + [extra_caveat], parent=hash_canonical(ROOT))
    return [ROOT, hop1]


def test_baseline_chain_verifies():
    assert verify_chain([ROOT], b64u(PRINCIPAL[2])) == (True, None)
    assert verify_chain(_chain_with({"type": "resource_prefix", "prefix": "db/"}), b64u(PRINCIPAL[2])) == (True, None)


def test_hop_depth_limit_minus_one_and_limit_accepted():
    # body {.. caveats: [ {type, v: nest(k)} ]}: body=1, caveats=2, caveat=3, nest(k) adds k -> deepest container 3+k
    for k in (MAX_JSON_DEPTH - 4, MAX_JSON_DEPTH - 3):  # depth 31, 32
        ok, why = verify_chain(_chain_with({"type": "x", "v": _nest(k)}), b64u(PRINCIPAL[2]))
        assert ok, (k, why)


def test_hop_depth_limit_plus_one_refused():
    ok, why = verify_chain(_chain_with({"type": "x", "v": _nest(MAX_JSON_DEPTH - 2)}), b64u(PRINCIPAL[2]))  # depth 33
    assert ok is False and why


def test_hop_very_deep_is_a_clean_refusal():
    deep = 1
    for _ in range(100_000):
        deep = [deep]
    ch = [ROOT, {**_chain_with({"type": "x"})[1], "caveats": ROOT["caveats"] + [{"type": "x", "v": deep}]}]
    ok, why = verify_chain(ch, b64u(PRINCIPAL[2]))
    assert ok is False and why


def test_hop_out_of_profile_numbers_and_surrogates_refused():
    for cav in ({"type": "x", "v": 1e300}, {"type": "x", "v": 9007199254740993}, {"type": "x", "v": 0.1234567890123456},
                {"type": "x", "v": "\ud800"}, {"type": "\ud800"}):
        ok, why = verify_chain(_chain_with(cav), b64u(PRINCIPAL[2]))
        assert ok is False and why, cav


def test_parent_out_of_profile_root_refused():
    root = _hop(PRINCIPAL, AGENT, [{"type": "max_spend", "usd": 100, "deep": _nest(MAX_JSON_DEPTH)}])
    hop1 = _hop(AGENT, SUB, copy.deepcopy(root["caveats"]), parent=_lenient_digest(root))
    ok, why = verify_chain([root, hop1], b64u(PRINCIPAL[2]))
    assert ok is False and why


def test_inclusion_leaf_is_strict():
    for leaf in ({"x": 1e300}, {"x": _nest(MAX_JSON_DEPTH)}):
        root = b64u(sha256(b"\x00" + canonicalize(leaf).encode()))
        assert verify_inclusion(root, {"index": 0, "size": 1, "path": []}, leaf) is False
    leaf = {"x": _nest(MAX_JSON_DEPTH - 1)}  # object=1 + 31 arrays = depth 32 -> in profile
    root = b64u(sha256(b"\x00" + canonicalize(leaf).encode()))
    assert verify_inclusion(root, {"index": 0, "size": 1, "path": []}, leaf) is True


def test_strict_parse_depth_boundaries():
    for n, ok in ((MAX_JSON_DEPTH - 1, True), (MAX_JSON_DEPTH, True), (MAX_JSON_DEPTH + 1, False), (100_000, False)):
        try:
            strict_parse("[" * n + "]" * n)
            got = True
        except Exception as e:  # must be the strict error, never RecursionError
            assert not isinstance(e, RecursionError)
            got = False
        assert got is ok, n


def test_entry_points_total_on_very_deep_values():
    deep = 1
    for _ in range(100_000):
        deep = [deep]
    assert verify_threshold_share({"role": "agent", "t": 1, "signer_set": deep, "threshold_message": "AA", "share": deep}) is False
    assert verify_threshold_share(deep) is False
    v = verify_pcactn_core({"ver": 2, "x": deep}, ROOT, 0, "aud")
    assert v.allow is False
    assert verify_chain([deep], None)[0] is False


def test_leaf_and_artifact_suite_total():
    from atlas_pca.pca import verify_artifact_suite, verify_leaf_suite
    for p in (None, 5, "x", [], [1]):
        assert verify_leaf_suite(p, "x", b"m") is False
        assert verify_artifact_suite(p) is False
    assert verify_leaf_suite({"alg": "ed25519", "sig": "x"}, 5, None) is False
    assert verify_artifact_suite({"message": 5, "ed_pub": []}) is False
