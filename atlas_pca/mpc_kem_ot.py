"""Post-quantum base OT from ML-KEM-768 (FIPS 203, OpenSSL >= 3.5 through mpc_libcrypto.MlKem768): the receiver publishes a public-key pair with a
known secret key for only its chosen slot, the sender encapsulates to both and pads each message with the shared secret. Variants: the
semi-honest transfer (``KemOt.kem_base_ot``), the commit-then-open malicious-secure transfer with a session id (``KemOt.kem_base_ot_mal``), and the
random-OT form that outputs fixed-width secrets for the hybrid base OT (``KemOt.kem_base_ot_mal_random``). ``HybridOt`` runs the elliptic-curve
random OT and the ML-KEM random OT side by side and folds BOTH secrets into every transfer key, so the transfer is secure if either the classical
or the post-quantum assumption holds."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, List, Optional

from .mpc_ec import Ec
from .mpc_libcrypto import MlKem768
from .mpc_ot import BaseOtTamper, Ot

TAG_KEMOT = b"atlas-pca-mpc/kem-ot-pad"
TAG_KEMOT_COMMIT = b"atlas-pca-mpc/kem-ot-commit"
TAG_KEMOT_SID = b"atlas-pca-mpc/kem-ot-sid"
TAG_KEMOT_MALPAD = b"atlas-pca-mpc/kem-ot-mal-pad"
TAG_KEMOT_MALSECRET = b"atlas-pca-mpc/kem-ot-mal-secret"
TAG_HYBRID_SID = b"atlas-pca-mpc/hybrid-ot-sid"
TAG_HYBRID_KEY = b"atlas-pca-mpc/hybrid-ot-transfer-key"
TAG_HYBRID_COMMIT = b"atlas-pca-mpc/hybrid-ot-msg-commit"
NONCE_BYTES = 32
KEM_OT_SECRET_BYTES = 32
MlKem = MlKem768


class KemBaseOtAbort(Exception):
    """A KEM base OT aborted: the opened keys do not match the receiver's commitment."""


class HybridOtAbort(Exception):
    """A hybrid base OT aborted: the sender's ciphertext is inconsistent with its commitment."""


@dataclass
class KemMalTamper:
    """TEST-ONLY injection points for a malicious sender or receiver (None = honest); each is a callable."""

    tamper_opened_keys: Optional[Callable] = None
    tamper_receiver_sid: Optional[Callable] = None


@dataclass
class KemOtReceiverState:
    choices: list
    secret_keys: list


@dataclass
class KemOtReceiverMessage:
    public_keys: list


@dataclass
class KemOtSenderMessage:
    ciphertexts: list
    encrypted: list


@dataclass
class KemBaseOtTranscript:
    public_keys: list
    ciphertexts: list
    encrypted: list


@dataclass
class KemBaseOtResult:
    received: list
    transcript: KemBaseOtTranscript


@dataclass
class ReceiverStep:
    message: KemOtReceiverMessage
    state: KemOtReceiverState


@dataclass
class KemMalCommitMessage:
    rn: bytes
    commitments: list


@dataclass
class KemMalOpenMessage:
    public_keys: list


@dataclass
class KemMalSenderNonce:
    sn: bytes


@dataclass
class KemMalSenderMessage:
    ciphertexts: list
    encrypted: list


@dataclass
class KemMalReceiverState:
    choices: list
    secret_keys: list
    public_keys: list
    rn: bytes


@dataclass
class KemMalTranscript:
    rn: bytes
    commitments: list
    sn: bytes
    public_keys: list
    ciphertexts: list
    encrypted: list


@dataclass
class KemBaseOtMalResult:
    received: list
    transcript: KemMalTranscript


@dataclass
class CommitStep:
    message: KemMalCommitMessage
    state: KemMalReceiverState


@dataclass
class KemMalRandomSenderMessage:
    ciphertexts: list
    sender_secrets: list


@dataclass
class KemMalRandomTranscript:
    rn: bytes
    commitments: list
    sn: bytes
    public_keys: list
    ciphertexts: list


@dataclass
class KemBaseOtMalRandomResult:
    sender_secrets: list
    recv_secrets: list
    sid: bytes
    transcript: KemMalRandomTranscript


def _sha256(*chunks: bytes) -> bytes:
    return Ot.sha256(*chunks)


def _u32(x: int) -> bytes:
    return Ot.u32(x)


def _xor(a: bytes, b: bytes) -> bytes:
    if len(a) != len(b):
        raise ValueError("kem-ot: XOR length mismatch")
    return Ot.xor_bytes(a, b)


def _expand(tag: bytes, prefix, index: int, slot: int, shared_secret: bytes, n: int) -> bytes:
    out = bytearray()
    ctr = 0
    while len(out) < n:
        out += _sha256(tag, *prefix, _u32(index), bytes([slot & 1]), _u32(ctr), shared_secret)
        ctr += 1
    return bytes(out[:n])


def _len_ok(n) -> bool:
    return isinstance(n, int) and not isinstance(n, bool) and 0 <= n <= 1 << 20


class KemOt:
    KemBaseOtAbort = KemBaseOtAbort
    KemMalTamper = KemMalTamper
    NONCE_BYTES = NONCE_BYTES
    KEM_OT_SECRET_BYTES = KEM_OT_SECRET_BYTES
    MlKem = MlKem768

    @staticmethod
    def kem_ot_pad(index: int, slot: int, shared_secret: bytes, length: int) -> bytes:
        """Pad of length bytes (at most 1 MiB) from the shared secret: SHA-256 in counter mode."""
        if not _len_ok(length):
            raise ValueError("kemOtPad: length must be an integer in [0, 1 MiB]")
        return _expand(TAG_KEMOT, [], index, slot, shared_secret, length)

    @staticmethod
    def keypair_for(rng, choice: int):
        chosen = MlKem768.keygen(rng.bytes(MlKem768.SEED_BYTES))
        other = MlKem768.keygen(rng.bytes(MlKem768.SEED_BYTES))
        pks = [chosen.public_key, other.public_key] if choice == 0 else [other.public_key, chosen.public_key]
        return pks, chosen.secret_key

    @staticmethod
    def kem_base_ot_receive(choices, rng=None) -> ReceiverStep:
        rng = rng or Ot.secure_ot_random()
        public_keys, secret_keys, retained = [], [], []
        for ch in choices:
            c = ch & 1
            pks, sk = KemOt.keypair_for(rng, c)
            public_keys.append(pks)
            secret_keys.append(sk)
            retained.append(c)
        return ReceiverStep(KemOtReceiverMessage(public_keys), KemOtReceiverState(retained, secret_keys))

    @staticmethod
    def kem_base_ot_send(messages, receiver_message: KemOtReceiverMessage, rng=None) -> KemOtSenderMessage:
        rng = rng or Ot.secure_ot_random()
        public_keys = receiver_message.public_keys
        if len(messages) != len(public_keys):
            raise ValueError("kemBaseOtSend: messages/publicKeys length mismatch")
        cts, encrypted = [], []
        for i, (m0, m1) in enumerate(messages):
            if len(m0) != len(m1):
                raise ValueError("kemBaseOtSend (index %d): the two messages must be equal length" % i)
            e0 = MlKem768.encapsulate(public_keys[i][0], rng.bytes(MlKem768.MSG_BYTES))
            e1 = MlKem768.encapsulate(public_keys[i][1], rng.bytes(MlKem768.MSG_BYTES))
            cts.append([e0.cipher_text, e1.cipher_text])
            encrypted.append([_xor(m0, KemOt.kem_ot_pad(i, 0, e0.shared_secret, len(m0))), _xor(m1, KemOt.kem_ot_pad(i, 1, e1.shared_secret, len(m1)))])
        return KemOtSenderMessage(cts, encrypted)

    @staticmethod
    def kem_base_ot_open(state: KemOtReceiverState, sender_message: KemOtSenderMessage) -> list:
        n = len(state.choices)
        if len(sender_message.ciphertexts) != n or len(sender_message.encrypted) != n:
            raise ValueError("kemBaseOtOpen: transcript/state length mismatch")
        out = []
        for i in range(n):
            c = state.choices[i] & 1
            ss = MlKem768.decapsulate(sender_message.ciphertexts[i][c], state.secret_keys[i])
            e = sender_message.encrypted[i][c]
            out.append(_xor(e, KemOt.kem_ot_pad(i, c, ss, len(e))))
        return out

    @staticmethod
    def kem_base_ot(messages, choices, rng=None) -> KemBaseOtResult:
        rng = rng or Ot.secure_ot_random()
        if len(messages) != len(choices):
            raise ValueError("kemBaseOT: messages/choices length mismatch")
        r = KemOt.kem_base_ot_receive(choices, rng)
        s = KemOt.kem_base_ot_send(messages, r.message, rng)
        received = KemOt.kem_base_ot_open(r.state, s)
        return KemBaseOtResult(received, KemBaseOtTranscript(r.message.public_keys, s.ciphertexts, s.encrypted))

    @staticmethod
    def with_kem_base_ot() -> Callable:
        """The semi-honest KEM OT as a pluggable base OT for OtChannel."""
        return lambda m, c, r: KemOt.kem_base_ot(m, c, r).received

    # ---- malicious-secure (commit-then-open, session id) ----

    @staticmethod
    def kem_mal_commit(rn: bytes, index: int, pk0: bytes, pk1: bytes) -> bytes:
        return _sha256(TAG_KEMOT_COMMIT, rn, _u32(index), pk0, pk1)

    @staticmethod
    def kem_mal_sid(rn: bytes, sn: bytes) -> bytes:
        return _sha256(TAG_KEMOT_SID, rn, sn)

    @staticmethod
    def kem_ot_mal_pad(sid: bytes, com: bytes, index: int, slot: int, ss: bytes, length: int) -> bytes:
        return _expand(TAG_KEMOT_MALPAD, [sid, com], index, slot, ss, length)

    @staticmethod
    def kem_ot_mal_secret(sid: bytes, com: bytes, index: int, slot: int, ss: bytes) -> bytes:
        return _sha256(TAG_KEMOT_MALSECRET, sid, com, _u32(index), bytes([slot & 1]), ss)[:KEM_OT_SECRET_BYTES]

    @staticmethod
    def kem_base_ot_mal_commit(choices, rng=None) -> CommitStep:
        rng = rng or Ot.secure_ot_random()
        rn = rng.bytes(NONCE_BYTES)
        public_keys, secret_keys, retained, commitments = [], [], [], []
        for i, ch in enumerate(choices):
            c = ch & 1
            pks, sk = KemOt.keypair_for(rng, c)
            public_keys.append(pks)
            secret_keys.append(sk)
            retained.append(c)
            commitments.append(KemOt.kem_mal_commit(rn, i, pks[0], pks[1]))
        return CommitStep(KemMalCommitMessage(rn, commitments), KemMalReceiverState(retained, secret_keys, public_keys, rn))

    @staticmethod
    def kem_base_ot_mal_sender_nonce(rng=None) -> KemMalSenderNonce:
        return KemMalSenderNonce((rng or Ot.secure_ot_random()).bytes(NONCE_BYTES))

    @staticmethod
    def kem_base_ot_mal_open(state: KemMalReceiverState) -> KemMalOpenMessage:
        """The receiver's opening: a copy of its public-key pairs."""
        return KemMalOpenMessage([list(p) for p in state.public_keys])

    @staticmethod
    def check_opening(commit: KemMalCommitMessage, public_keys, i: int) -> bytes:
        com = KemOt.kem_mal_commit(commit.rn, i, public_keys[i][0], public_keys[i][1])
        if not Ot.ct_eq(com, commit.commitments[i]):
            raise KemBaseOtAbort("kem base OT (index %d): opened public keys do not match the receiver's commitment; aborting" % i)
        return com

    @staticmethod
    def kem_base_ot_mal_send(messages, commit: KemMalCommitMessage, sender_nonce: KemMalSenderNonce, opening: KemMalOpenMessage,
                             rng=None) -> KemMalSenderMessage:
        rng = rng or Ot.secure_ot_random()
        public_keys = opening.public_keys
        if len(messages) != len(public_keys) or len(commit.commitments) != len(public_keys):
            raise ValueError("kemBaseOtMalSend: messages/commitments/publicKeys length mismatch")
        sid = KemOt.kem_mal_sid(commit.rn, sender_nonce.sn)
        cts, encrypted = [], []
        for i, (m0, m1) in enumerate(messages):
            if len(m0) != len(m1):
                raise ValueError("kemBaseOtMalSend (index %d): the two messages must be equal length" % i)
            com = KemOt.check_opening(commit, public_keys, i)
            e0 = MlKem768.encapsulate(public_keys[i][0], rng.bytes(MlKem768.MSG_BYTES))
            e1 = MlKem768.encapsulate(public_keys[i][1], rng.bytes(MlKem768.MSG_BYTES))
            cts.append([e0.cipher_text, e1.cipher_text])
            encrypted.append([_xor(m0, KemOt.kem_ot_mal_pad(sid, com, i, 0, e0.shared_secret, len(m0))),
                              _xor(m1, KemOt.kem_ot_mal_pad(sid, com, i, 1, e1.shared_secret, len(m1)))])
        return KemMalSenderMessage(cts, encrypted)

    @staticmethod
    def receiver_sid(state: KemMalReceiverState, sender_nonce: KemMalSenderNonce, tamper: Optional[KemMalTamper]) -> bytes:
        sid = KemOt.kem_mal_sid(state.rn, sender_nonce.sn)
        return tamper.tamper_receiver_sid(sid) if tamper is not None and tamper.tamper_receiver_sid else sid

    @staticmethod
    def kem_base_ot_mal_recover(state: KemMalReceiverState, sender_nonce: KemMalSenderNonce, sender_message: KemMalSenderMessage,
                                tamper: Optional[KemMalTamper] = None) -> list:
        n = len(state.choices)
        if len(sender_message.ciphertexts) != n or len(sender_message.encrypted) != n:
            raise ValueError("kemBaseOtMalRecover: transcript/state length mismatch")
        sid = KemOt.receiver_sid(state, sender_nonce, tamper)
        out = []
        for i in range(n):
            c = state.choices[i] & 1
            com = KemOt.kem_mal_commit(state.rn, i, state.public_keys[i][0], state.public_keys[i][1])
            ss = MlKem768.decapsulate(sender_message.ciphertexts[i][c], state.secret_keys[i])
            e = sender_message.encrypted[i][c]
            out.append(_xor(e, KemOt.kem_ot_mal_pad(sid, com, i, c, ss, len(e))))
        return out

    @staticmethod
    def kem_base_ot_mal(messages, choices, rng=None, tamper: Optional[KemMalTamper] = None) -> KemBaseOtMalResult:
        rng = rng or Ot.secure_ot_random()
        if len(messages) != len(choices):
            raise ValueError("kemBaseOtMal: messages/choices length mismatch")
        cs = KemOt.kem_base_ot_mal_commit(choices, rng)
        nonce = KemOt.kem_base_ot_mal_sender_nonce(rng)
        opening = KemOt.kem_base_ot_mal_open(cs.state)
        if tamper is not None and tamper.tamper_opened_keys:
            tamper.tamper_opened_keys(opening.public_keys)
        sm = KemOt.kem_base_ot_mal_send(messages, cs.message, nonce, opening, rng)
        received = KemOt.kem_base_ot_mal_recover(cs.state, nonce, sm, tamper)
        return KemBaseOtMalResult(received, KemMalTranscript(cs.message.rn, cs.message.commitments, nonce.sn, opening.public_keys, sm.ciphertexts,
                                                              sm.encrypted))

    @staticmethod
    def with_kem_base_ot_mal() -> Callable:
        """The malicious-secure KEM OT as a pluggable base OT for OtChannel."""
        return lambda m, c, r: KemOt.kem_base_ot_mal(m, c, r, None).received

    # ---- random-OT form (fixed-width secrets, for the hybrid base OT) ----

    @staticmethod
    def kem_base_ot_mal_random_send(commit: KemMalCommitMessage, sender_nonce: KemMalSenderNonce, opening: KemMalOpenMessage,
                                    rng=None) -> KemMalRandomSenderMessage:
        rng = rng or Ot.secure_ot_random()
        public_keys = opening.public_keys
        if len(commit.commitments) != len(public_keys):
            raise ValueError("kemBaseOtMalRandomSend: commitments/publicKeys length mismatch")
        sid = KemOt.kem_mal_sid(commit.rn, sender_nonce.sn)
        cts, secrets_ = [], []
        for i in range(len(public_keys)):
            com = KemOt.check_opening(commit, public_keys, i)
            e0 = MlKem768.encapsulate(public_keys[i][0], rng.bytes(MlKem768.MSG_BYTES))
            e1 = MlKem768.encapsulate(public_keys[i][1], rng.bytes(MlKem768.MSG_BYTES))
            cts.append([e0.cipher_text, e1.cipher_text])
            secrets_.append([KemOt.kem_ot_mal_secret(sid, com, i, 0, e0.shared_secret), KemOt.kem_ot_mal_secret(sid, com, i, 1, e1.shared_secret)])
        return KemMalRandomSenderMessage(cts, secrets_)

    @staticmethod
    def kem_base_ot_mal_random_recover(state: KemMalReceiverState, sender_nonce: KemMalSenderNonce, sender_message: KemMalRandomSenderMessage,
                                       tamper: Optional[KemMalTamper] = None) -> list:
        n = len(state.choices)
        if len(sender_message.ciphertexts) != n:
            raise ValueError("kemBaseOtMalRandomRecover: transcript/state length mismatch")
        sid = KemOt.receiver_sid(state, sender_nonce, tamper)
        out = []
        for i in range(n):
            c = state.choices[i] & 1
            com = KemOt.kem_mal_commit(state.rn, i, state.public_keys[i][0], state.public_keys[i][1])
            out.append(KemOt.kem_ot_mal_secret(sid, com, i, c, MlKem768.decapsulate(sender_message.ciphertexts[i][c], state.secret_keys[i])))
        return out

    @staticmethod
    def kem_base_ot_mal_random(choices, rng=None, tamper: Optional[KemMalTamper] = None) -> KemBaseOtMalRandomResult:
        rng = rng or Ot.secure_ot_random()
        cs = KemOt.kem_base_ot_mal_commit(choices, rng)
        nonce = KemOt.kem_base_ot_mal_sender_nonce(rng)
        opening = KemOt.kem_base_ot_mal_open(cs.state)
        if tamper is not None and tamper.tamper_opened_keys:
            tamper.tamper_opened_keys(opening.public_keys)
        sm = KemOt.kem_base_ot_mal_random_send(cs.message, nonce, opening, rng)
        recv = KemOt.kem_base_ot_mal_random_recover(cs.state, nonce, sm, tamper)
        return KemBaseOtMalRandomResult(sm.sender_secrets, recv, KemOt.kem_mal_sid(cs.message.rn, nonce.sn),
                                        KemMalRandomTranscript(cs.message.rn, cs.message.commitments, nonce.sn, opening.public_keys, sm.ciphertexts))


@dataclass
class HybridSenderMessage:
    encrypted: list
    commitments: list


@dataclass
class HybridBaseOtTamper:
    """TEST-ONLY injection points (None = honest)."""

    ec: Optional[BaseOtTamper] = None
    kem: Optional[KemMalTamper] = None
    tamper_encrypted: Optional[Callable] = None


@dataclass
class HybridBaseOtTranscript:
    sid: bytes
    ec_s: object
    kem_sid: bytes
    encrypted: list
    commitments: list


@dataclass
class HybridBaseOtResult:
    received: list
    transcript: HybridBaseOtTranscript


class HybridOt:
    HybridOtAbort = HybridOtAbort
    HybridBaseOtTamper = HybridBaseOtTamper

    @staticmethod
    def hybrid_session_id(kem_sid: bytes, ec_s) -> bytes:
        return Ot.sha256(TAG_HYBRID_SID, kem_sid, Ec.encode_point(ec_s))

    @staticmethod
    def hybrid_transfer_key(sid: bytes, index: int, slot: int, ss_ec: bytes, ss_kem: bytes, length: int) -> bytes:
        if not _len_ok(length):
            raise ValueError("hybridTransferKey: length must be an integer in [0, 1 MiB]")
        out = bytearray()
        ctr = 0
        while len(out) < length:
            out += Ot.sha256(TAG_HYBRID_KEY, sid, Ot.u32(index), bytes([slot & 1]), Ot.u32(ctr), ss_ec, ss_kem)
            ctr += 1
        return bytes(out[:length])

    @staticmethod
    def hybrid_commit(sid: bytes, index: int, slot: int, msg: bytes, key: bytes) -> bytes:
        return Ot.sha256(TAG_HYBRID_COMMIT, sid, Ot.u32(index), bytes([slot & 1]), msg, key)

    @staticmethod
    def hybrid_sender_encrypt(sid: bytes, messages, ec_secrets, kem_secrets) -> HybridSenderMessage:
        if len(messages) != len(ec_secrets) or len(messages) != len(kem_secrets):
            raise ValueError("hybridSenderEncrypt: messages/ecSecrets/kemSecrets length mismatch")
        encrypted, commitments = [], []
        for i, (m0, m1) in enumerate(messages):
            if len(m0) != len(m1):
                raise ValueError("hybridSenderEncrypt (index %d): the two messages must be equal length" % i)
            k0 = HybridOt.hybrid_transfer_key(sid, i, 0, ec_secrets[i][0], kem_secrets[i][0], len(m0))
            k1 = HybridOt.hybrid_transfer_key(sid, i, 1, ec_secrets[i][1], kem_secrets[i][1], len(m1))
            encrypted.append([_xor(m0, k0), _xor(m1, k1)])
            commitments.append([HybridOt.hybrid_commit(sid, i, 0, m0, k0), HybridOt.hybrid_commit(sid, i, 1, m1, k1)])
        return HybridSenderMessage(encrypted, commitments)

    @staticmethod
    def hybrid_receiver_recover(sid: bytes, choices, sender: HybridSenderMessage, ec_recv, kem_recv) -> list:
        n = len(choices)
        if len(sender.encrypted) != n or len(sender.commitments) != n or len(ec_recv) != n or len(kem_recv) != n:
            raise ValueError("hybridReceiverRecover: length mismatch")
        out = []
        for i in range(n):
            c = choices[i] & 1
            e = sender.encrypted[i][c]
            key = HybridOt.hybrid_transfer_key(sid, i, c, ec_recv[i], kem_recv[i], len(e))
            m = _xor(e, key)
            if not Ot.ct_eq(HybridOt.hybrid_commit(sid, i, c, m, key), sender.commitments[i][c]):
                raise HybridOtAbort("hybrid base OT (index %d): sender ciphertext inconsistent with its commitment; aborting" % i)
            out.append(m)
        return out

    @staticmethod
    def hybrid_base_ot(messages, choices, rng=None, tamper: Optional[HybridBaseOtTamper] = None) -> HybridBaseOtResult:
        rng = rng or Ot.secure_ot_random()
        if len(messages) != len(choices):
            raise ValueError("hybridBaseOT: messages/choices length mismatch")
        ec = Ot.mal_base_random_ot(choices, rng, tamper.ec if tamper is not None else None, None)
        kem = KemOt.kem_base_ot_mal_random(choices, rng, tamper.kem if tamper is not None else None)
        sid = HybridOt.hybrid_session_id(kem.sid, ec.s)
        sender = HybridOt.hybrid_sender_encrypt(sid, messages, ec.sender_pads, kem.sender_secrets)
        if tamper is not None and tamper.tamper_encrypted:
            tamper.tamper_encrypted(sender.encrypted)
        received = HybridOt.hybrid_receiver_recover(sid, choices, sender, ec.recv_pads, kem.recv_secrets)
        return HybridBaseOtResult(received, HybridBaseOtTranscript(sid, ec.s, kem.sid, sender.encrypted, sender.commitments))

    @staticmethod
    def with_hybrid_base_ot() -> Callable:
        """The hybrid base OT as a pluggable base OT for OtChannel."""
        return lambda m, c, r: HybridOt.hybrid_base_ot(m, c, r, None).received
