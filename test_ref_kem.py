"""Replays the TS-reference oracle of the hybrid KEM module (testdata/ref-kem.json.gz, 464 cases): X25519 + ML-KEM-768 / -1024, X-Wing
(draft-connolly-cfrg-xwing-kem-09, with the three Appendix C vectors), the FIPS 203 key checks and the base64url wire helpers. Every fn of the
corpus has a handler (an unhandled fn fails) and the case total is asserted. The corpus carries no secret key: {"$bytes": {"$seed": label}} is
sha256("atlas-pca-conformance/" + label); {"$hybridSk": ...} and {"$mlkemDk": ...} are keys this test rebuilds from their seeds; the random
stream of the reference is pinned as `rng`, replayed through the module's derandomised entry points. A reference throw must be a native raise.
Needs libsodium through pysodium and OpenSSL >= 3.5 (PCA_LIBCRYPTO may name the library); with PCA_MPC_REQUIRE_MLKEM=1 a missing one fails."""
import hashlib
import os

import pytest

from atlas_pca import kem as K
from atlas_pca.mpc_libcrypto import MlKem1024, MlKem768Level, mlkem_available
from base_oracle import HERE, load, run

COUNT, CASES = load("kem", os.path.join(HERE, "testdata", "ref-kem.json.gz"))
SUITES = {"768": K._S768, "1024": K._S1024}


def _need_backends():
    if mlkem_available():
        try:
            K._sodium()
            return
        except RuntimeError as e:
            why = str(e)
    else:
        why = "OpenSSL >= 3.5 (ML-KEM) not available"
    if os.environ.get("PCA_MPC_REQUIRE_MLKEM") == "1":
        pytest.fail(why)
    pytest.skip(why)


def _rng(v):
    return b"".join(v) if isinstance(v, list) else v


def _expanded_dk(level, d, z):
    lv = {"768": MlKem768Level, "1024": MlKem1024}[str(level)]
    return bytearray(lv.secret_key_bytes(lv.keygen(d + z).secret_key))


def _key(v):
    """A corpus key form -> bytes (anything else passes through)."""
    if isinstance(v, dict) and set(v) == {"$hybridSk"}:
        o = v["$hybridSk"]
        sk = bytearray(o["x"]) + _expanded_dk(o["level"], o["d"], o["z"])
        if o.get("trim"):
            del sk[len(sk) - o["trim"]:]
        sk += bytes(o.get("pad", 0))
        for off, b in o.get("set", []):
            sk[off] = b
        return bytes(sk)
    if isinstance(v, dict) and set(v) == {"$mlkemDk"}:
        o = v["$mlkemDk"]
        k = 3 if str(o["level"]) == "768" else 4
        dk = _expanded_dk(o["level"], o["d"], o["z"])
        for off, b in o.get("set", []):
            dk[off] = b
        if o.get("rehash"):
            dk[768 * k + 32:768 * k + 64] = hashlib.sha3_256(bytes(dk[384 * k:768 * k + 32])).digest()
        return bytes(dk)
    return v


def _pair(p):
    return {"publicKey": p.public_key, "secretKeySha256": hashlib.sha256(p.secret_key).hexdigest(), "secretKeyLen": len(p.secret_key)}


def _enc(e):
    return {"ciphertext": e.ciphertext, "sharedSecret": e.shared_secret}


def _hybrid(tag, suffix=""):
    s = SUITES[tag]
    return {
        "hybridKem%sKeygen" % suffix: lambda rng: _pair(K._hybrid_keygen(s, _rng(rng))),
        "hybridEncapsulate" + suffix: lambda pk, rng: _enc(K._hybrid_encapsulate(s, pk, _rng(rng), "hybrid_encapsulate")),
        "hybridDecapsulate" + suffix: lambda ct, sk: K._hybrid_decapsulate(s, ct, _key(sk), "hybrid_decapsulate"),
    }


HANDLERS = {
    "constants": lambda: {n: getattr(K, n) for n in (
        "HYBRID_PUBLIC_KEY_LEN", "HYBRID_CIPHERTEXT_LEN", "HYBRID_SHARED_SECRET_LEN", "HYBRID_KEM_SUITE", "XWING_SUITE", "XWING_SEED_LEN",
        "XWING_SECRET_KEY_LEN", "XWING_PUBLIC_KEY_LEN", "XWING_CIPHERTEXT_LEN", "XWING_SHARED_SECRET_LEN", "XWING_ESEED_LEN", "XWING_LABEL",
        "HYBRID1024_PUBLIC_KEY_LEN", "HYBRID1024_CIPHERTEXT_LEN", "HYBRID1024_SHARED_SECRET_LEN", "HYBRID1024_KEM_SUITE")},
    **_hybrid("768"),
    **_hybrid("1024", "1024"),
    "xwingKeygen": lambda seed: _pair(K.xwing_keygen(K._bytes(seed, "xwing_keygen"))),  # a null seed is a refusal in the reference
    "xwingEncapsulateDerand": lambda pk, eseed: _enc(K.xwing_encapsulate_derand(pk, _rng(eseed))),
    "xwingEncapsulate": lambda pk, rng: _enc(K.xwing_encapsulate_derand(pk, _rng(rng))),
    "xwingDecapsulate": K.xwing_decapsulate,
    "mlKemEncapsulationKeyCheck": lambda level, ek: K.ml_kem_encapsulation_key_check(level, _key(ek)),
    "mlKemDecapsulationKeyCheck": lambda level, dk: K.ml_kem_decapsulation_key_check(level, _key(dk)),
    "encodeHybridPublicKey": K.encode_hybrid_public_key, "decodeHybridPublicKey": K.decode_hybrid_public_key,
    "encodeHybridCiphertext": K.encode_hybrid_ciphertext, "decodeHybridCiphertext": K.decode_hybrid_ciphertext,
    "encodeXWingPublicKey": K.encode_xwing_public_key, "decodeXWingPublicKey": K.decode_xwing_public_key,
    "encodeXWingCiphertext": K.encode_xwing_ciphertext, "decodeXWingCiphertext": K.decode_xwing_ciphertext,
}


def test_every_corpus_fn_has_a_handler_and_the_total_is_pinned():
    assert COUNT == 464
    assert set(CASES) == set(HANDLERS), sorted(set(CASES) ^ set(HANDLERS))


@pytest.mark.parametrize("fn", sorted(HANDLERS))
def test_kem_replay(fn):
    if fn.startswith(("hybrid", "xwing", "mlKemDecapsulation")):
        _need_backends()
    ran, skipped = run(CASES[fn], HANDLERS[fn])
    assert ran == len(CASES[fn]) and skipped == 0


def test_randomised_entry_points_round_trip():
    _need_backends()
    for keygen, enc, dec, pk_len, ct_len in (
            (K.hybrid_kem_keygen, K.hybrid_encapsulate, K.hybrid_decapsulate, K.HYBRID_PUBLIC_KEY_LEN, K.HYBRID_CIPHERTEXT_LEN),
            (K.hybrid_kem1024_keygen, K.hybrid_encapsulate1024, K.hybrid_decapsulate1024, K.HYBRID1024_PUBLIC_KEY_LEN, K.HYBRID1024_CIPHERTEXT_LEN),
            (K.xwing_keygen, K.xwing_encapsulate, K.xwing_decapsulate, K.XWING_PUBLIC_KEY_LEN, K.XWING_CIPHERTEXT_LEN)):
        pair = keygen()
        e1, e2 = enc(pair.public_key), enc(pair.public_key)
        assert len(pair.public_key) == pk_len and len(e1.ciphertext) == ct_len and len(e1.shared_secret) == 32
        assert dec(e1.ciphertext, pair.secret_key) == e1.shared_secret
        assert e1.ciphertext != e2.ciphertext and e1.shared_secret != e2.shared_secret


def test_damaged_decapsulation_key_import_does_not_disturb_the_default_context():
    """The pairwise-test switch lives on a private library context: keys made in the default one still work next to an imported one."""
    _need_backends()
    pair = MlKem768Level.keygen(bytes(64))
    dk = bytearray(MlKem768Level.secret_key_bytes(pair.secret_key))
    dk[10] = (dk[10] & 0xF0) | (0 if dk[10] & 0x0F else 1)  # another, still reduced, coefficient of the decryption half
    enc = MlKem768Level.encapsulate(pair.public_key, bytes(32))
    damaged = MlKem768Level.decapsulate(enc.cipher_text, MlKem768Level.import_secret_key(bytes(dk)))
    assert len(damaged) == 32 and damaged != enc.shared_secret  # the implicit-rejection secret, not a refusal at import
    assert MlKem768Level.decapsulate(enc.cipher_text, pair.secret_key) == enc.shared_secret
