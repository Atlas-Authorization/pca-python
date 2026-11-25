"""Vetted-library helpers of the OT stack: the SHAKE256 extendable-output function (hashlib), AES-128 ECB and CTR (the ``cryptography`` package)
and ML-KEM-768 (FIPS 203) through ctypes to OpenSSL >= 3.5 with a caller-supplied key-generation seed (the EVP_PKEY "seed" parameter) and
encapsulation message (the "ikme" parameter), so the OT transcripts are reproducible from a seeded stream. Nothing is written out here.
``PCA_LIBCRYPTO`` overrides the libcrypto name; ML-KEM raises ``LibcryptoUnavailable`` when the library is missing or older than 3.5."""

from __future__ import annotations

import ctypes
import ctypes.util
import hashlib
import os
import threading
from typing import Any, List, Optional


class LibcryptoUnavailable(RuntimeError):
    """OpenSSL libcrypto (>= 3.5 for ML-KEM) or the ``cryptography`` package could not be loaded."""


def shake256(data: bytes, outlen: int) -> bytes:
    """SHAKE256(data) squeezed to outlen bytes."""
    if outlen < 0:
        raise ValueError("shake256: negative output length")
    return hashlib.shake_256(bytes(data)).digest(outlen) if outlen else b""


def _aes():
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    except ImportError as e:  # pragma: no cover - environment
        raise LibcryptoUnavailable("the OT stack needs the 'cryptography' package for AES: %s" % e) from e
    return Cipher, algorithms, modes


def aes128_ecb(key: bytes, data: bytes) -> bytes:
    """AES-128 in ECB mode, no padding (the fixed-key permutation of the correlation-robust hash)."""
    Cipher, algorithms, modes = _aes()
    if len(data) == 0:
        return b""
    enc = Cipher(algorithms.AES(bytes(key)), modes.ECB()).encryptor()
    return enc.update(bytes(data)) + enc.finalize()


def aes128_ctr_zeros(key: bytes, iv: bytes, n: int) -> bytes:
    """n bytes of the AES-128-CTR keystream (encryption of zeros) from the 16-byte initial counter block iv."""
    Cipher, algorithms, modes = _aes()
    if n == 0:
        return b""
    enc = Cipher(algorithms.AES(bytes(key)), modes.CTR(bytes(iv))).encryptor()
    return enc.update(bytes(n)) + enc.finalize()


# ---- ML-KEM-768 through ctypes ---------------------------------------------------------------------------------------------------------

_LOCK = threading.Lock()
_lib: Optional[ctypes.CDLL] = None
_OCTET_STRING = 5  # OSSL_PARAM_OCTET_STRING
_KEYPAIR = 0x87  # EVP_PKEY_KEYPAIR
_UNMODIFIED = (1 << 64) - 1


class _OsslParam(ctypes.Structure):
    _fields_ = [("key", ctypes.c_char_p), ("data_type", ctypes.c_uint), ("data", ctypes.c_void_p), ("data_size", ctypes.c_size_t),
                ("return_size", ctypes.c_size_t)]


def _candidates() -> List[str]:
    out = [os.environ.get("PCA_LIBCRYPTO"), "libcrypto.so.3", "/opt/homebrew/opt/openssl@3/lib/libcrypto.3.dylib",
           "/usr/local/opt/openssl@3/lib/libcrypto.3.dylib", "libcrypto.3.dylib", "libcrypto-3-x64.dll", "libcrypto-3.dll",
           ctypes.util.find_library("crypto")]
    # macOS: the system libcrypto.dylib is a stub that aborts the process when loaded (Fatal Python error: Aborted), never a candidate
    return [c for c in out if c and not (c == "libcrypto.dylib" or c.startswith("/usr/lib/libcrypto"))]


def _bind(lib: ctypes.CDLL) -> None:
    P, I, S, U = ctypes.c_void_p, ctypes.c_int, ctypes.c_size_t, ctypes.c_uint
    PS = ctypes.POINTER(ctypes.c_size_t)
    PP = ctypes.POINTER(ctypes.c_void_p)
    protos = {
        "OPENSSL_version_major": (U, []), "OPENSSL_version_minor": (U, []),
        "EVP_PKEY_CTX_new_from_name": (P, [P, ctypes.c_char_p, P]), "EVP_PKEY_CTX_new_from_pkey": (P, [P, P, P]),
        "EVP_PKEY_CTX_free": (None, [P]), "EVP_PKEY_CTX_set_params": (I, [P, P]), "EVP_PKEY_keygen_init": (I, [P]),
        "EVP_PKEY_keygen": (I, [P, PP]), "EVP_PKEY_free": (None, [P]), "EVP_PKEY_get_raw_public_key": (I, [P, P, PS]),
        "EVP_PKEY_new_raw_public_key_ex": (P, [P, ctypes.c_char_p, P, P, S]), "EVP_PKEY_encapsulate_init": (I, [P, P]),
        "EVP_PKEY_encapsulate": (I, [P, P, PS, P, PS]), "EVP_PKEY_decapsulate_init": (I, [P, P]),
        "EVP_PKEY_decapsulate": (I, [P, P, PS, P, S]), "ERR_get_error": (ctypes.c_ulong, []),
        "ERR_error_string_n": (None, [ctypes.c_ulong, P, S]),
        "EVP_PKEY_fromdata_init": (I, [P]), "EVP_PKEY_fromdata": (I, [P, PP, I, P]),
        "EVP_PKEY_get_octet_string_param": (I, [P, ctypes.c_char_p, P, S, PS]),
    }
    for name, (res, args) in protos.items():
        fn = getattr(lib, name)
        fn.restype, fn.argtypes = res, args


def lib() -> ctypes.CDLL:
    """The bound libcrypto (raises LibcryptoUnavailable)."""
    global _lib
    if _lib is not None:
        return _lib
    with _LOCK:
        if _lib is not None:
            return _lib
        last: Optional[Exception] = None
        for name in _candidates():
            try:
                cand = ctypes.CDLL(name)
                _bind(cand)
            except (OSError, AttributeError) as e:
                last = e
                continue
            _lib = cand
            return cand
        raise LibcryptoUnavailable("the OT stack needs OpenSSL libcrypto 3.x (set PCA_LIBCRYPTO): %s" % last)


def mlkem_available() -> bool:
    """Whether the loaded libcrypto is OpenSSL >= 3.5 (ML-KEM in the default provider)."""
    try:
        l = lib()
    except LibcryptoUnavailable:
        return False
    major, minor = l.OPENSSL_version_major(), l.OPENSSL_version_minor()
    return major > 3 or (major == 3 and minor >= 5)


_MINTED: set = set()  # the EVP_PKEY handles this module created and still owns: a pointer handed in from outside is never passed to OpenSSL


def _handle(pkey: Any) -> int:
    if not isinstance(pkey, int) or isinstance(pkey, bool) or pkey not in _MINTED:
        raise RuntimeError("ML-KEM: not a key this module created")
    return pkey


class MlKemSecretKey:
    """A decapsulation key: owns its EVP_PKEY and frees it with the object."""

    def __init__(self, pkey: int, libctx: Optional[int] = None, _owned: bool = False):
        # only a handle this module minted is freed: a caller-supplied integer is never a pointer to release (the free segfaulted)
        self.pkey = pkey
        self._owned = _owned
        if _owned and pkey:
            _MINTED.add(pkey)
        self.libctx = libctx  # the OpenSSL library context the key lives in (None: the process default)

    def __del__(self):
        try:
            if self.pkey and self._owned:
                _MINTED.discard(self.pkey)
                lib().EVP_PKEY_free(self.pkey)
                self.pkey = None
        except Exception:  # noqa: BLE001 - interpreter shutdown
            pass


class MlKemKeyPair:
    def __init__(self, public_key: bytes, secret_key: MlKemSecretKey):
        self.public_key = public_key
        self.secret_key = secret_key


class MlKemEncapsulation:
    def __init__(self, cipher_text: bytes, shared_secret: bytes):
        self.cipher_text = cipher_text
        self.shared_secret = shared_secret


class MlKem768:
    """ML-KEM-768 (FIPS 203): key generation from a 64-byte seed (d || z) and encapsulation from a 32-byte message m."""

    PK_BYTES = 1184
    CT_BYTES = 1088
    SS_BYTES = 32
    SEED_BYTES = 64
    MSG_BYTES = 32
    SecretKey = MlKemSecretKey
    KeyPair = MlKemKeyPair
    Encapsulation = MlKemEncapsulation

    @staticmethod
    def _err(what: str) -> RuntimeError:
        l = lib()
        msgs = []
        while True:
            e = l.ERR_get_error()
            if e == 0:
                break
            buf = ctypes.create_string_buffer(256)
            l.ERR_error_string_n(e, buf, 256)
            msgs.append(buf.value.decode("utf-8", "replace"))
        return RuntimeError("ML-KEM: %s failed%s" % (what, " (%s)" % "; ".join(msgs) if msgs else ""))

    @staticmethod
    def _octet_param(name: bytes, data: bytes):
        """A one-entry OSSL_PARAM array holding an octet string, plus the objects that must stay alive during the call."""
        buf = ctypes.create_string_buffer(bytes(data), len(data))
        arr = (_OsslParam * 2)()
        arr[0].key = name
        arr[0].data_type = _OCTET_STRING
        arr[0].data = ctypes.addressof(buf)
        arr[0].data_size = len(data)
        arr[0].return_size = _UNMODIFIED
        return arr, buf

    @staticmethod
    def check_available() -> None:
        if not mlkem_available():
            raise LibcryptoUnavailable("ML-KEM-768 needs OpenSSL >= 3.5")

    @staticmethod
    def keygen(seed64: bytes) -> MlKemKeyPair:
        MlKem768.check_available()
        if not isinstance(seed64, (bytes, bytearray)) or len(seed64) != MlKem768.SEED_BYTES:
            raise ValueError("ml-kem keygen: seed must be exactly 64 bytes")
        l = lib()
        ctx = l.EVP_PKEY_CTX_new_from_name(None, b"ML-KEM-768", None)
        if not ctx:
            raise MlKem768._err("EVP_PKEY_CTX_new_from_name")
        try:
            if l.EVP_PKEY_keygen_init(ctx) != 1:
                raise MlKem768._err("EVP_PKEY_keygen_init")
            params, keep = MlKem768._octet_param(b"seed", seed64)
            if l.EVP_PKEY_CTX_set_params(ctx, params) != 1:
                raise MlKem768._err("EVP_PKEY_CTX_set_params(seed)")
            out = ctypes.c_void_p()
            if l.EVP_PKEY_keygen(ctx, ctypes.byref(out)) != 1 or not out.value:
                raise MlKem768._err("EVP_PKEY_keygen")
            del keep
            sk = MlKemSecretKey(out.value, _owned=True)
            return MlKemKeyPair(MlKem768._raw_public_key(sk.pkey), sk)
        finally:
            l.EVP_PKEY_CTX_free(ctx)

    @staticmethod
    def _raw_public_key(pkey: int) -> bytes:
        l = lib()
        pkey = _handle(pkey)
        n = ctypes.c_size_t(MlKem768.PK_BYTES)
        buf = ctypes.create_string_buffer(MlKem768.PK_BYTES)
        if l.EVP_PKEY_get_raw_public_key(pkey, buf, ctypes.byref(n)) != 1:
            raise MlKem768._err("EVP_PKEY_get_raw_public_key")
        if n.value != MlKem768.PK_BYTES:
            raise RuntimeError("ML-KEM: unexpected public key length")
        return buf.raw

    @staticmethod
    def encapsulate(public_key: bytes, msg32: bytes) -> MlKemEncapsulation:
        MlKem768.check_available()
        if not isinstance(msg32, (bytes, bytearray)) or len(msg32) != MlKem768.MSG_BYTES:
            raise ValueError("ml-kem encapsulate: message must be exactly 32 bytes")
        if not isinstance(public_key, (bytes, bytearray)) or len(public_key) != MlKem768.PK_BYTES:
            raise ValueError("ml-kem encapsulate: bad public key length")
        l = lib()
        pk_buf = ctypes.create_string_buffer(bytes(public_key), MlKem768.PK_BYTES)
        pkey = l.EVP_PKEY_new_raw_public_key_ex(None, b"ML-KEM-768", None, pk_buf, MlKem768.PK_BYTES)
        if not pkey:
            raise MlKem768._err("EVP_PKEY_new_raw_public_key_ex")
        ctx = l.EVP_PKEY_CTX_new_from_pkey(None, pkey, None)
        if not ctx:
            l.EVP_PKEY_free(pkey)
            raise MlKem768._err("EVP_PKEY_CTX_new_from_pkey")
        try:
            params, keep = MlKem768._octet_param(b"ikme", msg32)
            if l.EVP_PKEY_encapsulate_init(ctx, params) != 1:
                raise MlKem768._err("EVP_PKEY_encapsulate_init")
            ct = ctypes.create_string_buffer(MlKem768.CT_BYTES)
            ss = ctypes.create_string_buffer(MlKem768.SS_BYTES)
            ctlen = ctypes.c_size_t(MlKem768.CT_BYTES)
            sslen = ctypes.c_size_t(MlKem768.SS_BYTES)
            if l.EVP_PKEY_encapsulate(ctx, ct, ctypes.byref(ctlen), ss, ctypes.byref(sslen)) != 1:
                raise MlKem768._err("EVP_PKEY_encapsulate")
            if ctlen.value != MlKem768.CT_BYTES or sslen.value != MlKem768.SS_BYTES:
                raise RuntimeError("ML-KEM: unexpected ciphertext or secret length")
            del keep
            return MlKemEncapsulation(ct.raw, ss.raw)
        finally:
            l.EVP_PKEY_CTX_free(ctx)
            l.EVP_PKEY_free(pkey)

    @staticmethod
    def decapsulate(cipher_text: bytes, secret_key: MlKemSecretKey) -> bytes:
        """ML-KEM decapsulation never fails on a well-sized ciphertext (a wrong one yields the implicit-rejection secret)."""
        MlKem768.check_available()
        if not isinstance(cipher_text, (bytes, bytearray)) or len(cipher_text) != MlKem768.CT_BYTES:
            raise ValueError("ml-kem decapsulate: bad ciphertext length")
        l = lib()
        ctx = l.EVP_PKEY_CTX_new_from_pkey(None, _handle(getattr(secret_key, "pkey", None)), None)
        if not ctx:
            raise MlKem768._err("EVP_PKEY_CTX_new_from_pkey")
        try:
            if l.EVP_PKEY_decapsulate_init(ctx, None) != 1:
                raise MlKem768._err("EVP_PKEY_decapsulate_init")
            ct = ctypes.create_string_buffer(bytes(cipher_text), MlKem768.CT_BYTES)
            ss = ctypes.create_string_buffer(MlKem768.SS_BYTES)
            sslen = ctypes.c_size_t(MlKem768.SS_BYTES)
            if l.EVP_PKEY_decapsulate(ctx, ss, ctypes.byref(sslen), ct, MlKem768.CT_BYTES) != 1:
                raise MlKem768._err("EVP_PKEY_decapsulate")
            return ss.raw
        finally:
            l.EVP_PKEY_CTX_free(ctx)


def _params(*items):
    """An OSSL_PARAM array (terminated) of (name, type, bytes) entries, plus the objects that must stay alive during the call."""
    arr = (_OsslParam * (len(items) + 1))()
    keep = []
    for i, (name, kind, data) in enumerate(items):
        buf = ctypes.create_string_buffer(bytes(data), len(data))
        arr[i].key = name
        arr[i].data_type = kind
        arr[i].data = ctypes.addressof(buf)
        arr[i].data_size = len(data)
        arr[i].return_size = _UNMODIFIED
        keep.append((name, buf))
    return arr, keep


_import_ctx: Optional[int] = None


def _import_libctx() -> int:
    """A private OpenSSL library context whose default provider has ``ml-kem.import_pct_type = none``. That switch is a PROVIDER configuration
    parameter (a fromdata parameter of that name is ignored), so it is set on a context of our own and the process-wide one keeps its default."""
    global _import_ctx
    l = lib()
    with _LOCK:
        if _import_ctx is None:
            P, C = ctypes.c_void_p, ctypes.c_char_p
            try:
                l.OSSL_LIB_CTX_new.restype, l.OSSL_LIB_CTX_new.argtypes = P, []
                l.OSSL_LIB_CTX_free.restype, l.OSSL_LIB_CTX_free.argtypes = None, [P]
                l.OSSL_PROVIDER_load.restype, l.OSSL_PROVIDER_load.argtypes = P, [P, C]
                l.OSSL_PROVIDER_add_conf_parameter.restype, l.OSSL_PROVIDER_add_conf_parameter.argtypes = ctypes.c_int, [P, C, C]
            except AttributeError as e:
                raise LibcryptoUnavailable("ML-KEM key import needs OpenSSL >= 3.5: %s" % e) from e
            ctx = l.OSSL_LIB_CTX_new()
            prov = l.OSSL_PROVIDER_load(ctx, b"default") if ctx else None
            if not prov or l.OSSL_PROVIDER_add_conf_parameter(prov, b"ml-kem.import_pct_type", b"none") != 1:
                if ctx:
                    l.OSSL_LIB_CTX_free(ctx)
                raise MlKem768._err("OSSL_PROVIDER_add_conf_parameter(ml-kem.import_pct_type)")
            _import_ctx = ctx  # kept for the life of the process
    return _import_ctx


class MlKemLevel:
    """ML-KEM (FIPS 203) at one parameter set (768 or 1024) through OpenSSL >= 3.5: key generation from a 64-byte seed (d || z), derandomised
    encapsulation from a 32-byte message, decapsulation, and import of an expanded FIPS 203 decapsulation key. The import runs no pairwise
    test, so a damaged key is answered with the implicit-rejection secret (as the reference does) and not refused at import."""

    SS_BYTES = 32
    SEED_BYTES = 64
    MSG_BYTES = 32

    def __init__(self, bits: int):
        k, ct = {768: (3, 1088), 1024: (4, 1568)}[bits]
        self.name = "ML-KEM-%d" % bits
        self.k = k
        self.PK_BYTES = 384 * k + 32
        self.DK_BYTES = 768 * k + 96
        self.CT_BYTES = ct

    def _check(self) -> None:
        if not mlkem_available():
            raise LibcryptoUnavailable("%s needs OpenSSL >= 3.5" % self.name)

    def _public_bytes(self, pkey: int) -> bytes:
        l = lib()
        pkey = _handle(pkey)
        n = ctypes.c_size_t(self.PK_BYTES)
        buf = ctypes.create_string_buffer(self.PK_BYTES)
        if l.EVP_PKEY_get_raw_public_key(pkey, buf, ctypes.byref(n)) != 1:
            raise MlKem768._err("EVP_PKEY_get_raw_public_key")
        if n.value != self.PK_BYTES:
            raise RuntimeError("ML-KEM: unexpected public key length")
        return buf.raw

    def keygen(self, seed64: bytes) -> MlKemKeyPair:
        self._check()
        if not isinstance(seed64, (bytes, bytearray)) or len(seed64) != self.SEED_BYTES:
            raise ValueError("ml-kem keygen: seed must be exactly 64 bytes")
        l = lib()
        ctx = l.EVP_PKEY_CTX_new_from_name(None, self.name.encode(), None)
        if not ctx:
            raise MlKem768._err("EVP_PKEY_CTX_new_from_name")
        try:
            if l.EVP_PKEY_keygen_init(ctx) != 1:
                raise MlKem768._err("EVP_PKEY_keygen_init")
            params, keep = _params((b"seed", _OCTET_STRING, seed64))
            if l.EVP_PKEY_CTX_set_params(ctx, params) != 1:
                raise MlKem768._err("EVP_PKEY_CTX_set_params(seed)")
            out = ctypes.c_void_p()
            if l.EVP_PKEY_keygen(ctx, ctypes.byref(out)) != 1 or not out.value:
                raise MlKem768._err("EVP_PKEY_keygen")
            del keep
            sk = MlKemSecretKey(out.value, _owned=True)
            return MlKemKeyPair(self._public_bytes(sk.pkey), sk)
        finally:
            l.EVP_PKEY_CTX_free(ctx)

    def secret_key_bytes(self, secret_key: MlKemSecretKey) -> bytes:
        """The FIPS 203 expanded decapsulation key (dkPKE || ek || H(ek) || z) of a key."""
        l = lib()
        n = ctypes.c_size_t(0)
        buf = ctypes.create_string_buffer(self.DK_BYTES)
        if l.EVP_PKEY_get_octet_string_param(_handle(getattr(secret_key, "pkey", None)), b"priv", buf, self.DK_BYTES, ctypes.byref(n)) != 1:
            raise MlKem768._err("EVP_PKEY_get_octet_string_param(priv)")
        if n.value != self.DK_BYTES:
            raise RuntimeError("ML-KEM: unexpected decapsulation key length")
        return buf.raw

    def _reduce_dkpke(self, dk: bytes) -> bytes:
        """dk with every 12-bit coefficient of its dkPKE part reduced mod q = 3329 (FIPS 203 ByteDecode12)."""
        out = bytearray(dk)
        for i in range(0, 384 * self.k, 3):
            x = out[i] | out[i + 1] << 8 | out[i + 2] << 16
            lo, hi = (x & 0xFFF) % 3329, (x >> 12) % 3329
            out[i], out[i + 1], out[i + 2] = lo & 0xFF, (lo >> 8) | (hi & 0xF) << 4, hi >> 4
        return bytes(out)

    def import_secret_key(self, dk: bytes) -> MlKemSecretKey:
        """A decapsulation key from its expanded FIPS 203 form; the embedded H(ek) is checked, the pairwise test is not run."""
        self._check()
        if not isinstance(dk, (bytes, bytearray)) or len(dk) != self.DK_BYTES:
            raise ValueError("ml-kem: decapsulation key must be exactly %d bytes" % self.DK_BYTES)
        l = lib()
        libctx = _import_libctx()
        ctx = l.EVP_PKEY_CTX_new_from_name(libctx, self.name.encode(), None)
        if not ctx:
            raise MlKem768._err("EVP_PKEY_CTX_new_from_name")
        try:
            if l.EVP_PKEY_fromdata_init(ctx) != 1:
                raise MlKem768._err("EVP_PKEY_fromdata_init")
            params, keep = _params((b"priv", _OCTET_STRING, dk))
            out = ctypes.c_void_p()
            if l.EVP_PKEY_fromdata(ctx, ctypes.byref(out), _KEYPAIR, params) != 1 or not out.value:
                # OpenSSL refuses a dkPKE coefficient >= q; FIPS 203 ByteDecode12 reduces it mod q (the reference does), so retry reduced
                red = self._reduce_dkpke(bytes(dk))
                if red == bytes(dk):
                    raise MlKem768._err("EVP_PKEY_fromdata")
                if l.EVP_PKEY_fromdata_init(ctx) != 1:
                    raise MlKem768._err("EVP_PKEY_fromdata_init")
                params, keep = _params((b"priv", _OCTET_STRING, red))
                out = ctypes.c_void_p()
                if l.EVP_PKEY_fromdata(ctx, ctypes.byref(out), _KEYPAIR, params) != 1 or not out.value:
                    raise MlKem768._err("EVP_PKEY_fromdata")
            del keep
            return MlKemSecretKey(out.value, libctx, _owned=True)
        finally:
            l.EVP_PKEY_CTX_free(ctx)

    def encapsulate(self, public_key: bytes, msg32: bytes) -> MlKemEncapsulation:
        self._check()
        if not isinstance(msg32, (bytes, bytearray)) or len(msg32) != self.MSG_BYTES:
            raise ValueError("ml-kem encapsulate: message must be exactly 32 bytes")
        if not isinstance(public_key, (bytes, bytearray)) or len(public_key) != self.PK_BYTES:
            raise ValueError("ml-kem encapsulate: bad public key length")
        l = lib()
        pk_buf = ctypes.create_string_buffer(bytes(public_key), self.PK_BYTES)
        pkey = l.EVP_PKEY_new_raw_public_key_ex(None, self.name.encode(), None, pk_buf, self.PK_BYTES)
        if not pkey:
            raise MlKem768._err("EVP_PKEY_new_raw_public_key_ex")
        ctx = l.EVP_PKEY_CTX_new_from_pkey(None, pkey, None)
        if not ctx:
            l.EVP_PKEY_free(pkey)
            raise MlKem768._err("EVP_PKEY_CTX_new_from_pkey")
        try:
            params, keep = _params((b"ikme", _OCTET_STRING, msg32))
            if l.EVP_PKEY_encapsulate_init(ctx, params) != 1:
                raise MlKem768._err("EVP_PKEY_encapsulate_init")
            ct = ctypes.create_string_buffer(self.CT_BYTES)
            ss = ctypes.create_string_buffer(self.SS_BYTES)
            ctlen = ctypes.c_size_t(self.CT_BYTES)
            sslen = ctypes.c_size_t(self.SS_BYTES)
            if l.EVP_PKEY_encapsulate(ctx, ct, ctypes.byref(ctlen), ss, ctypes.byref(sslen)) != 1:
                raise MlKem768._err("EVP_PKEY_encapsulate")
            if ctlen.value != self.CT_BYTES or sslen.value != self.SS_BYTES:
                raise RuntimeError("ML-KEM: unexpected ciphertext or secret length")
            del keep
            return MlKemEncapsulation(ct.raw, ss.raw)
        finally:
            l.EVP_PKEY_CTX_free(ctx)
            l.EVP_PKEY_free(pkey)

    def decapsulate(self, cipher_text: bytes, secret_key: MlKemSecretKey) -> bytes:
        """Never fails on a well-sized ciphertext (a wrong one yields the implicit-rejection secret)."""
        self._check()
        if not isinstance(cipher_text, (bytes, bytearray)) or len(cipher_text) != self.CT_BYTES:
            raise ValueError("ml-kem decapsulate: bad ciphertext length")
        l = lib()
        ctx = l.EVP_PKEY_CTX_new_from_pkey(secret_key.libctx, _handle(getattr(secret_key, "pkey", None)), None)  # the key's own context: moving it would re-import it, pairwise test included
        if not ctx:
            raise MlKem768._err("EVP_PKEY_CTX_new_from_pkey")
        try:
            if l.EVP_PKEY_decapsulate_init(ctx, None) != 1:
                raise MlKem768._err("EVP_PKEY_decapsulate_init")
            ct = ctypes.create_string_buffer(bytes(cipher_text), self.CT_BYTES)
            ss = ctypes.create_string_buffer(self.SS_BYTES)
            sslen = ctypes.c_size_t(self.SS_BYTES)
            if l.EVP_PKEY_decapsulate(ctx, ss, ctypes.byref(sslen), ct, self.CT_BYTES) != 1:
                raise MlKem768._err("EVP_PKEY_decapsulate")
            return ss.raw
        finally:
            l.EVP_PKEY_CTX_free(ctx)


MlKem768Level = MlKemLevel(768)
MlKem1024 = MlKemLevel(1024)


class Libcrypto:
    """Ruby-shaped namespace: ``Libcrypto.shake256``, ``Libcrypto.mlkem_available``, ``Libcrypto.MlKem768``."""

    shake256 = staticmethod(shake256)
    mlkem_available = staticmethod(mlkem_available)
    lib = staticmethod(lib)
    aes128_ecb = staticmethod(aes128_ecb)
    aes128_ctr_zeros = staticmethod(aes128_ctr_zeros)
    MlKem768 = MlKem768
    MlKem1024 = MlKem1024
    MlKemLevel = MlKemLevel
