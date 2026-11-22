"""The PCA Capability Ratchet: puncturable forward-secure one-time capability keys (a GGM tree of Ed25519 leaf keys under a
Merkle-root commitment), the verifier-side spent-leaf and attested-risk bindings, and the adapters to the PCActn counter and
the risk budget. The homomorphic accumulator lives in ratchet_accumulator and is re-exported here.

Mirrors the TypeScript reference (@atlasauth/pca-ratchet). Wire shapes are the reference's JSON shapes (camelCase members);
a ratchet state is a dict {depth, leafCount, rootCommitment, leafPubKeys, covering} whose covering maps "level:node" to
{level, nodeIndex, seed}. Leaf signing uses the `cryptography` package (constant time) when installed, else the pure signer
after atlas_pca.ed25519.allow_insecure_signer()."""
from ._fin import fin
import hashlib
import hmac
import math
import re
from typing import Any, Dict, List, Optional, Sequence

from . import ed25519 as _ed
from .pca import _build, _leaf_hash, _node_hash, _split, _verify_b64u, b64u, merkle_root, sha256, verify_inclusion
from .ratchet_accumulator import (  # noqa: F401  (re-exported)
    MAX_PROVABLE_CEILING, N_BITS, AccumulatorError, add_commitments, commit_risk, open_commitment, prove_budget,
    prove_risk_range, verify_bounded_budget, verify_budget, verify_risk_range,
)
from .ratchet_group import utf8

MAX_RATCHET_DEPTH = 20
RISK_SCALE = 1000


class RatchetError(Exception):
    """code: invalid_depth | invalid_seed | leaf_out_of_range | leaf_punctured."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


# ---- helpers mirroring JS number semantics ------------------------------------------------------------------------------

def _is_integer(x: Any) -> bool:
    if isinstance(x, bool):
        return False
    return isinstance(x, int) or (isinstance(x, float) and fin(x) and x == math.floor(x))


def _is_safe_integer(x: Any) -> bool:
    return _is_integer(x) and abs(x) <= 2 ** 53 - 1


def _is_neg_zero(x: Any) -> bool:
    return isinstance(x, float) and x == 0 and math.copysign(1.0, x) < 0


def _bigint(x: Any) -> int:
    """JS BigInt(x) for the JSON types: an integer (or integral number), a boolean, or a numeric string; anything else raises."""
    if isinstance(x, bool):
        return int(x)
    if isinstance(x, int):
        return x
    if isinstance(x, float):
        if not _is_integer(x):
            raise ValueError("BigInt: not an integer")
        return int(x)
    if isinstance(x, str):
        s = x.strip()
        if s == "":
            return 0
        return int(s, 0) if s[:2].lower() in ("0x", "0o", "0b") else int(s, 10)
    raise TypeError("BigInt: cannot convert")


_JS_DEC = re.compile(r"[+-]?(?:\d+\.?\d*(?:[eE][+-]?\d+)?|\.\d+(?:[eE][+-]?\d+)?)")


def _to_number(x: Any) -> float:
    """JS ToNumber for the JSON types (null 0, true 1, numeric strings, one-element arrays), NaN otherwise."""
    if x is None:
        return 0.0
    if isinstance(x, bool):
        return 1.0 if x else 0.0
    if isinstance(x, int):
        try:
            return float(x)
        except OverflowError:
            return math.inf if x > 0 else -math.inf
    if isinstance(x, float):
        return x
    if isinstance(x, str):
        s = x.strip()
        if s == "":
            return 0.0
        if _JS_DEC.fullmatch(s):
            return float(s)
        if s in ("Infinity", "+Infinity"):
            return math.inf
        if s == "-Infinity":
            return -math.inf
        if s[:2].lower() in ("0x", "0o", "0b"):
            try:
                return float(int(s, 0))
            except ValueError:
                return math.nan
        return math.nan
    if isinstance(x, list):
        if not x:
            return 0.0
        if len(x) == 1 and not isinstance(x[0], (list, dict)):
            e = x[0]
            return _to_number("" if e is None else ("true" if e is True else "false" if e is False else e if isinstance(e, str) else repr(e)))
    return math.nan


def _u64(x: int) -> bytes:
    return (x & 0xFFFFFFFFFFFFFFFF).to_bytes(8, "big")


# ---- GGM puncturable PRF tree --------------------------------------------------------------------------------------------

_PRG_DOMAIN = utf8("atlas-pca-ratchet/ggm-prg/v1")
_LEAFKEY_DOMAIN = utf8("atlas-pca-ratchet/ggm-leafkey/v1")
_ROOT_DOMAIN = utf8("atlas-pca-ratchet/ggm-root/v1")


def _hmac(key: bytes, msg: bytes) -> bytes:
    return hmac.new(bytes(key), msg, hashlib.sha256).digest()


def _prg_left(seed: bytes) -> bytes:
    return _hmac(seed, _PRG_DOMAIN + b"\x00")


def _prg_right(seed: bytes) -> bytes:
    return _hmac(seed, _PRG_DOMAIN + b"\x01")


def root_seed(seed: bytes) -> bytes:
    return _hmac(seed, _ROOT_DOMAIN)


def leaf_signing_seed(leaf_seed: bytes) -> bytes:
    return _hmac(leaf_seed, _LEAFKEY_DOMAIN)


def _ed_public(seed: bytes) -> bytes:
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    except ImportError:
        if not _ed._ALLOW_INSECURE:
            raise RuntimeError(_ed.INSECURE_SIGNER_REFUSED) from None
        return _ed.public_key(seed)
    return Ed25519PrivateKey.from_private_bytes(bytes(seed)).public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def leaf_public_key(leaf_seed: bytes) -> str:
    return b64u(_ed_public(leaf_signing_seed(leaf_seed)))


def covers(level: int, node_index: int, leaf_index: Any, depth: int) -> bool:
    # JS semantics: floor(leaf / 2^k) with the leaf coerced to a number (a fraction or a numeric string still lands in a subtree)
    q = _to_number(leaf_index) / (2 ** (depth - level))
    return fin(q) and math.floor(q) == node_index


def _descend_bit(level: int, leaf_index: int, depth: int) -> int:
    return (leaf_index // (2 ** (depth - level - 1))) % 2  # only reached with a validated integer leaf


def derive_leaf_seed(node: Dict[str, Any], leaf_index: int, depth: int) -> bytes:
    seed = node["seed"]
    for level in range(node["level"], depth):
        seed = _prg_left(seed) if _descend_bit(level, leaf_index, depth) == 0 else _prg_right(seed)
    return seed


def puncture_siblings(node: Dict[str, Any], leaf_index: int, depth: int) -> List[Dict[str, Any]]:
    """The off-path siblings covering every leaf under `node` except `leaf_index`; on-path seeds are dropped."""
    out: List[Dict[str, Any]] = []
    seed = node["seed"]
    node_index = node["nodeIndex"]
    for level in range(node["level"], depth):
        bit = _descend_bit(level, leaf_index, depth)
        left = _prg_left(seed)
        right = _prg_right(seed)
        child_base = node_index * 2
        out.append({"level": level + 1, "nodeIndex": child_base + (1 - bit), "seed": right if bit == 0 else left})
        seed = left if bit == 0 else right
        node_index = child_base + bit
    return out


def all_leaf_public_keys(root: bytes, depth: int) -> List[str]:
    out: List[Optional[str]] = [None] * (2 ** depth)

    def recurse(seed: bytes, level: int, base: int) -> None:
        if level == depth:
            out[base] = leaf_public_key(seed)
            return
        half = 2 ** (depth - level - 1)
        recurse(_prg_left(seed), level + 1, base)
        recurse(_prg_right(seed), level + 1, base + half)

    recurse(root, 0, 0)
    return out  # type: ignore[return-value]


def cover_key(level: int, node_index: int) -> str:
    return "%d:%d" % (level, node_index)


# ---- ratchet -------------------------------------------------------------------------------------------------------------

_NULLIFIER_DOMAIN = utf8("atlas-pca-ratchet/nullifier/v1\0")
_SIG_DOMAIN = utf8("atlas-pca-ratchet/leaf-sig/v1\0")


def leaf_nullifier(root_commitment: str, leaf_index: Any) -> str:
    """b64u(sha256(domain || len32(root) || root || index64)): what a verifier records to detect leaf reuse."""
    root = utf8(root_commitment)
    out = _NULLIFIER_DOMAIN + len(root).to_bytes(4, "big") + root + _u64(_bigint(leaf_index))
    return b64u(sha256(out))


def _leaf_sig_message(leaf_index: Any, message: bytes) -> bytes:
    return _SIG_DOMAIN + _u64(_bigint(leaf_index)) + bytes(message)


def derive_ratchet_root(seed: bytes, depth: Any) -> Dict[str, Any]:
    """Build a ratchet from >= 32 bytes of entropy and a tree depth in [1, MAX_RATCHET_DEPTH]: {rootCommitment, state}."""
    if not _is_integer(depth) or depth < 1 or depth > MAX_RATCHET_DEPTH:
        raise RatchetError("invalid_depth", "depth must be an integer in [1, %d]" % MAX_RATCHET_DEPTH)
    if not isinstance(seed, (bytes, bytearray)) or len(seed) < 32:
        raise RatchetError("invalid_seed", "seed must be bytes of at least 32 bytes")
    depth = int(depth)
    root = root_seed(bytes(seed))
    leaf_pub_keys = all_leaf_public_keys(root, depth)
    root_commitment = merkle_root(list(leaf_pub_keys))
    covering = {cover_key(0, 0): {"level": 0, "nodeIndex": 0, "seed": root}}
    return {
        "rootCommitment": root_commitment,
        "state": {"depth": depth, "leafCount": 2 ** depth, "rootCommitment": root_commitment,
                  "leafPubKeys": leaf_pub_keys, "covering": covering},
    }


def _find_covering(state: Dict[str, Any], leaf_index: int) -> Optional[Dict[str, Any]]:
    for node in state["covering"].values():
        if covers(node["level"], node["nodeIndex"], leaf_index, state["depth"]):
            return node
    return None


def _merkle_proof(leaves: List[Any], index: int) -> Dict[str, Any]:
    if len(leaves) == 0:
        raise ValueError("merkle proof: no leaves")  # the recursion would never reach a single leaf
    path: List[Dict[str, str]] = []

    def prove(hs: List[bytes], idx: int) -> None:
        if len(hs) == 1:
            return
        k = _split(len(hs))
        if idx < k:
            prove(hs[:k], idx)
            path.append({"side": "R", "hash": b64u(_build(hs[k:]))})
        else:
            prove(hs[k:], idx - k)
            path.append({"side": "L", "hash": b64u(_build(hs[:k]))})

    prove([_leaf_hash(x) for x in leaves], index)
    return {"index": index, "size": len(leaves), "path": path}


def sign_at_leaf(state: Dict[str, Any], leaf_index: Any, message: bytes) -> Dict[str, Any]:
    """Sign at a leaf, then puncture it: {signature, newState}. Raises RatchetError for an out-of-range or spent leaf."""
    if not _is_integer(leaf_index) or leaf_index < 0 or leaf_index >= state["leafCount"]:
        raise RatchetError("leaf_out_of_range", "leaf %s is out of range [0, %s)" % (leaf_index, state["leafCount"]))
    leaf_index = int(leaf_index)
    node = _find_covering(state, leaf_index)
    if node is None:
        raise RatchetError("leaf_punctured", "leaf %d is already punctured (spent) and cannot sign" % leaf_index)
    leaf_seed = derive_leaf_seed(node, leaf_index, state["depth"])
    signing_seed = leaf_signing_seed(leaf_seed)
    ed_sig = b64u(_ed.sign_secret(signing_seed, _leaf_sig_message(leaf_index, message)))
    leaf_pub = leaf_public_key(leaf_seed)
    merkle_path = _merkle_proof(list(state["leafPubKeys"]), leaf_index)
    covering = dict(state["covering"])
    del covering[cover_key(node["level"], node["nodeIndex"])]
    for sib in puncture_siblings(node, leaf_index, state["depth"]):
        covering[cover_key(sib["level"], sib["nodeIndex"])] = sib
    new_state = dict(state)
    new_state["covering"] = covering
    return {
        "signature": {"edSig": ed_sig, "leafPubKey": leaf_pub, "merklePath": merkle_path,
                      "nullifier": leaf_nullifier(state["rootCommitment"], leaf_index)},
        "newState": new_state,
    }


def verify_leaf_signature(root_commitment: Any, leaf_index: Any, message: bytes, signature: Any) -> bool:
    """Offline check against the root commitment; never raises, malformed input is False."""
    try:
        if not isinstance(signature, dict):
            return False
        ed_sig = signature.get("edSig")
        leaf_pub = signature.get("leafPubKey")
        merkle_path = signature.get("merklePath")
        nullifier = signature.get("nullifier")
        if not isinstance(nullifier, str) or nullifier != leaf_nullifier(root_commitment, leaf_index):
            return False
        if not isinstance(ed_sig, str) or not isinstance(leaf_pub, str) or not isinstance(merkle_path, dict):
            return False
        mp_index = merkle_path.get("index")
        if isinstance(mp_index, bool) or isinstance(leaf_index, bool) or not isinstance(mp_index, (int, float)) \
                or not isinstance(leaf_index, (int, float)) or mp_index != leaf_index:
            return False
        # the root commits under sha256: a proof naming any other hash suite cannot belong to it (the core verifier ignores the member)
        if merkle_path.get("hash_suite", "sha256") != "sha256":
            return False
        if not _verify_b64u(leaf_pub, _leaf_sig_message(leaf_index, message), ed_sig):
            return False
        return verify_inclusion(root_commitment, merkle_path, leaf_pub)
    except Exception:
        return False


def available_leaves(state: Dict[str, Any]) -> List[int]:
    out: List[int] = []
    for node in state["covering"].values():
        span = 2 ** (state["depth"] - node["level"])
        base = node["nodeIndex"] * span
        out.extend(range(base, base + span))
    return sorted(out)


def is_leaf_available(state: Dict[str, Any], leaf_index: int) -> bool:
    return _find_covering(state, leaf_index) is not None


# ---- adapters: ratchet leaf <-> PCActn counter, accumulator units <-> RiskPolicy budget ----------------------------------

def counter_to_leaf_index(counter: Any, depth: Any) -> int:
    if not _is_integer(depth) or depth < 1 or depth > MAX_RATCHET_DEPTH:
        raise RatchetError("invalid_depth", "depth must be an integer in [1, %d]" % MAX_RATCHET_DEPTH)
    if not _is_safe_integer(counter) or _is_neg_zero(counter) or counter < 0:
        raise RatchetError("leaf_out_of_range", "counter must be a non-negative safe integer")
    if counter >= 2 ** depth:
        raise RatchetError("leaf_out_of_range", "counter %s exceeds the ratchet capacity 2^%s" % (counter, depth))
    return int(counter)


def leaf_index_to_counter(leaf_index: Any) -> int:
    if not _is_safe_integer(leaf_index) or _is_neg_zero(leaf_index) or leaf_index < 0:
        raise RatchetError("leaf_out_of_range", "leafIndex must be a non-negative safe integer")
    return int(leaf_index)


def leaf_index_for_action(actn: Dict[str, Any], depth: Any) -> int:
    return counter_to_leaf_index(actn.get("counter"), depth)


def _js_round(v: float) -> int:
    f = math.floor(v)
    return int(f) + 1 if v - f >= 0.5 else int(f)


def risk_to_units(r: Any) -> int:
    """Quantize a risk score to integer accumulator units, rounding UP so the sum never under-counts (float noise tolerated)."""
    if isinstance(r, bool) or not isinstance(r, (int, float)) or not fin(r) or r < 0:
        raise AccumulatorError("invalid_value", "risk must be a finite number >= 0")
    v = r * RISK_SCALE
    nearest = _js_round(v)
    if abs(v - nearest) <= 1e-9 * max(1, v):
        return nearest
    return int(math.ceil(v))


_NANO = 1_000_000


class RiskQuantizer:
    """Carry-forward quantizer: the running total of emitted units is always ceil(sum(true risk) * SCALE)."""

    def __init__(self) -> None:
        self._nano = 0
        self._emitted = 0

    def next(self, r: Any) -> int:
        if isinstance(r, bool) or not isinstance(r, (int, float)) or not fin(r) or r < 0:
            raise AccumulatorError("invalid_value", "risk must be a finite number >= 0")
        self._nano += int(math.ceil(r * RISK_SCALE * 1e6 - 1e-3))
        total = (self._nano + _NANO - 1) // _NANO
        out = total - self._emitted
        self._emitted = total
        return out

    @property
    def total_units(self) -> int:
        return self._emitted


def budget_ceiling_units(policy: Dict[str, Any]) -> int:
    """The accumulator ceiling in units: floor(safety_bound(policy) * RISK_SCALE)."""
    if not isinstance(policy, dict):
        raise TypeError("policy must be an object")
    # JS arithmetic on the members: a missing or non-numeric bMax is NaN (refused below), a missing kappa is not > 0 (bound 0)
    b_max = _to_number(policy["bMax"]) if "bMax" in policy else math.nan
    kappa = _to_number(policy["kappa"]) if "kappa" in policy else math.nan
    bound = (math.nan if b_max != b_max else max(0.0, b_max)) / kappa if kappa > 0 else 0.0
    if not fin(bound) or bound < 0:
        raise AccumulatorError("invalid_value", "safety bound (bMax/kappa) must be finite and >= 0")
    return int(math.floor(bound * RISK_SCALE))


# ---- verifier-side bindings ----------------------------------------------------------------------------------------------

class MemorySpentLeafStore:
    """In-process spent-leaf store (first claim wins); use a shared store for a verifier fleet."""

    def __init__(self) -> None:
        self._seen: Dict[str, str] = {}

    def claim(self, nullifier: str, record: str) -> Dict[str, Any]:
        prev = self._seen.get(nullifier)
        if prev is not None:
            return {"first": False, "record": prev}
        self._seen[nullifier] = record
        return {"first": True}


def memory_spent_leaf_store() -> MemorySpentLeafStore:
    return MemorySpentLeafStore()


def _message_digest(leaf_index: Any, message: bytes) -> str:
    idx = int(leaf_index) if _is_integer(leaf_index) else leaf_index
    return b64u(sha256(bytes(message))) + "@" + str(idx)


def verify_leaf_signature_once(root_commitment: Any, leaf_index: Any, message: bytes, signature: Any, store: Any) -> Dict[str, Any]:
    """Verify a leaf signature and enforce one-time use: a second signature at a leaf is `replay` (same message) or
    `equivocation` (different message). Fail closed: a store that raises denies with `store-error`."""
    if not verify_leaf_signature(root_commitment, leaf_index, message, signature):
        return {"ok": False, "reason": "invalid"}
    nullifier = leaf_nullifier(root_commitment, leaf_index)
    mine = _message_digest(leaf_index, message)
    try:
        r = store.claim(nullifier, mine)
        if r["first"]:
            return {"ok": True}
        if r["record"] == mine:
            return {"ok": False, "reason": "replay", "nullifier": nullifier}
        return {"ok": False, "reason": "equivocation", "nullifier": nullifier,
                "firstMessageDigest": r["record"], "secondMessageDigest": mine}
    except Exception:
        return {"ok": False, "reason": "store-error"}


_ATTEST_DOMAIN = utf8("atlas-pca-ratchet/risk-attestation/v1\0")


def _attest_message(action_digest: str, commitment: str) -> bytes:
    a = utf8(action_digest)
    c = utf8(commitment)
    return _ATTEST_DOMAIN + len(a).to_bytes(4, "big") + a + len(c).to_bytes(4, "big") + c


def issue_risk_commitment(risk: Any, action_digest: str, authority_secret_key: bytes) -> Dict[str, Any]:
    """Risk authority side: commit to the risk, prove its range, and sign (action_digest, commitment)."""
    c = commit_risk(risk)
    range_proof = prove_risk_range(risk, c["blinding"])
    sig = b64u(_ed.sign_secret(bytes(authority_secret_key), _attest_message(action_digest, c["commitment"])))
    return {"commitment": c["commitment"], "blinding": c["blinding"], "rangeProof": range_proof,
            "attestation": {"actionDigest": action_digest, "sig": sig}}


def verify_risk_attestation(commitment: Any, attestation: Any, authority_public_key: Any) -> bool:
    try:
        if not isinstance(attestation, dict):
            return False
        digest, sig = attestation.get("actionDigest"), attestation.get("sig")
        if not isinstance(digest, str) or not isinstance(sig, str):
            return False
        return _verify_b64u(authority_public_key, _attest_message(digest, commitment), sig)
    except Exception:
        return False


def verify_attested_budget(items: Any, expected_action_digests: Any, authority_public_key: Any, b_max: Any,
                           budget_proof: Any) -> bool:
    """Every item must carry a valid authority attestation for exactly the expected digest and commitment, then the
    bounded-budget proof must hold. Never raises."""
    try:
        if not isinstance(items, list) or not isinstance(expected_action_digests, list) \
                or len(items) != len(expected_action_digests):
            return False
        for i, it in enumerate(items):
            att = it.get("attestation")
            if not isinstance(att, dict) or att.get("actionDigest") != expected_action_digests[i]:
                return False
            if not verify_risk_attestation(it.get("commitment"), att, authority_public_key):
                return False
        return verify_bounded_budget([i.get("commitment") for i in items], [i.get("rangeProof") for i in items],
                                     b_max, budget_proof)
    except Exception:
        return False
