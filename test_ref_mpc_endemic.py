"""Differential replay of the endemic LWE base OT (atlas_pca.mpc_lwe_ot, Kyber-768 K-PKE through liblweot) against the TypeScript reference
corpus. Needs liblweot (ATLAS_PCA_LIBLWEOT); with ATLAS_PCA_LIBLWEOT_REQUIRED=1 (the lwe-ot workflow) its absence fails instead of skipping."""
import hashlib
import os

import pytest

from atlas_pca import mpc_lwe_ot as E
from base_oracle import load_ref, run

if not E.available():
    if os.environ.get("ATLAS_PCA_LIBLWEOT_REQUIRED") == "1":
        raise RuntimeError("liblweot must load (ATLAS_PCA_LIBLWEOT)")
    pytest.skip("liblweot not available", allow_module_level=True)

COUNT, CASES = load_ref("mpc-endemic")


def seed(label):
    return hashlib.sha256(("atlas-pca-conformance/" + label).encode("utf-8")).digest()


def rng(s):
    return E.SplitMix64(int(s))


def flip(b):
    return bytes(x ^ 1 for x in b)


def fill(n, k):
    return bytes((i * 31 + k * 7 + (i >> 3)) & 255 for i in range(n))


def test_lwe_keygen_fips():
    def call(label):
        pk, sk = E.kpke_keygen_fips203(seed(label))
        return {"pk": pk, "skSha256": hashlib.sha256(sk).hexdigest()}
    run(CASES["lweKeygenFips"], call)


def test_lwe_keygen():
    def call(label):
        pk, sk = E.kpke_keygen(seed(label))
        return {"pk": pk, "skSha256": hashlib.sha256(sk).hexdigest()}
    run(CASES["lweKeygen"], call)


def test_lwe_enc():
    run(CASES["lweEnc"], lambda label, msg, coins: E.kpke_enc(E.kpke_keygen(seed(label))[0], msg, coins))


def test_lwe_dec():
    run(CASES["lweDec"], lambda label, ct: E.kpke_dec(E.kpke_keygen(seed(label))[1], ct))


def test_lwe_ring():
    run(CASES["lweRing"], lambda op, a, b: E.ring_add(a, b) if op == "add" else E.ring_sub(a, b))


def test_lwe_hash():
    run(CASES["lweHash"], E.hash_to_ring)


def test_random_ot():
    def call(choices, rs, ss):
        msg, st = E.receive(choices, rng(rs))
        sm = E.send_random(msg, rng(ss))
        return {"rn": msg.rn, "points": msg.points, "rhos": msg.rhos, "ciphertexts": sm.ciphertexts, "senderPads": sm.sender_pads,
                "recvPads": E.recover_random(st, sm)}
    run(CASES["randomOt"], call)


def test_random_ot_tamper():
    def call(choices, rs, ss):
        msg, st = E.receive(choices, rng(rs))
        sm = E.send_random(msg, rng(ss), lambda c: c[0].__setitem__(0, c[0][0][:1087]))
        return E.recover_random(st, sm)
    run(CASES["randomOtTamper"], call)


def test_base_ot():
    def call(messages, choices, sd, tamper):
        one = rng(sd)
        t = None
        if tamper == "enc":
            t = lambda e: e[0].__setitem__(0, flip(e[0][0]))  # noqa: E731
        elif tamper == "encChosen":
            c0 = choices[0] & 1
            t = lambda e: e[0].__setitem__(c0, flip(e[0][c0]))  # noqa: E731
        received, tr = E.base_ot([tuple(p) for p in messages], choices, one, one, t)  # one generator serves the receiver, then the sender
        return {"received": received, "ciphertexts": tr.ciphertexts, "encrypted": tr.encrypted, "commitments": tr.commitments}
    run(CASES["baseOt"], call)


def test_send_malformed():
    def call(kind):
        m, _ = E.receive([0, 1], rng("77"))
        rn, points, rhos = m.rn, list(m.points), list(m.rhos)
        if kind == "nonce":
            rn = fill(31, 1)
        if kind == "count":
            rhos = rhos[1:]
        if kind == "point":
            points[1] = (fill(1151, 1), points[1][1])
        if kind == "rho":
            rhos[0] = fill(33, 1)
        return len(E.send_random(E.ReceiverMessage(rn, points, rhos), rng("78")).ciphertexts)
    run(CASES["sendMalformed"], call)
