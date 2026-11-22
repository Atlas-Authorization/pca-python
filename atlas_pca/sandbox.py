"""Policy logic of the PCA sandbox: runtime classes and signed runtime claims, the receipt hash chain, the capability handle table,
the egress admission policy, the OS-profile generators (seccomp / Landlock / macOS) and the reference WebAssembly tool builders.
Port of the TypeScript reference (@atlasauth/pca-sandbox); outputs are byte-identical.

The egress proxy server is in ``atlas_pca.sandbox_egress``.

Not ported: the WebAssembly / component hosts (they run wasmtime) and the attestation-verifier glue
(``trust_from_attestation``): each needs a runtime this module does not carry. A class is a claim by the host operator;
nothing here proves an OS profile was applied.
"""
from __future__ import annotations

import copy
import hashlib
import ipaddress
import inspect
import math
import re
import time
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Set

from . import ed25519
from .pca import b64u, canonical_bytes_strict, decode_b64u_strict, hash_canonical, _verify_b64u
from .sdjwt_jws import js_json, js_to_string

IMPORT_MODULE = "pca:act"
ALLOWED_IMPORTS = ("invoke", "handle_count", "handle_verb")
USE_ERR = {"unknown_handle": -1, "spent": -2, "out_too_small": -3, "bad_memory": -4, "executor_error": -5, "no_executor": -6}
RUNTIME_CLASSES = ("none", "os_confined", "egress_default_deny", "wasi_no_ambient")
GENESIS = "genesis"
RUNTIME_CLAIM_DOMAIN = "atlas-pca/runtime-class-claim/v1\0"

_U: Any = object()  # JS `undefined`


# ---------------------------------------------------------------------------------------------------- JS helpers
def _get(o: Any, k: str) -> Any:
    return o.get(k, _U) if isinstance(o, dict) else _U


def _nullish(v: Any) -> bool:
    return v is None or v is _U


def _isint(v: Any) -> bool:
    """Number.isInteger."""
    return isinstance(v, (int, float)) and not isinstance(v, bool) and (isinstance(v, int) or float(v).is_integer())


def _is_neg_zero(v: Any) -> bool:
    return isinstance(v, float) and v == 0 and math.copysign(1.0, v) < 0


def _jt(v: Any) -> bool:
    if v is None or v is _U or v is False or v == "":
        return False
    if isinstance(v, (int, float)) and not isinstance(v, bool):
        return v == v and v != 0
    return True


def _text(v: Any) -> str:
    """String(v) for a JSON value (a missing member is "undefined")."""
    return "undefined" if v is _U else js_to_string(v)


def _u16len(s: str) -> int:
    return len(s.encode("utf-16-le", "surrogatepass")) // 2


def _iterate(x: Any) -> List[Any]:
    """`for (const v of x ?? [])`: an array or a string iterates, any other value is not iterable."""
    if _nullish(x):
        return []
    if isinstance(x, list):
        return x
    if isinstance(x, str):
        return list(x)
    raise TypeError("not iterable")


def _attr(o: Any, k: str) -> Any:
    if isinstance(o, dict):
        return o.get(k, _U)
    return getattr(o, k, _U)


# ---------------------------------------------------------------------------------------------------- runtime classes / receipts
def satisfies_runtime_class(attested: Any, required: Any) -> bool:
    """True only when both names are known and `attested` is at least `required`. An unknown name never satisfies."""
    a = RUNTIME_CLASSES.index(attested) if isinstance(attested, str) and attested in RUNTIME_CLASSES else -1
    r = RUNTIME_CLASSES.index(required) if isinstance(required, str) and required in RUNTIME_CLASSES else -1
    return a >= 0 and r >= 0 and a >= r


def _now_ms() -> int:
    return int(time.time() * 1000)


class ReceiptLog:
    """Append-only hash chain of use receipts: every handle use and every egress decision, refusals included."""

    def __init__(self, now: Optional[Callable[[], Any]] = None, sign: Optional[Callable[[str], str]] = None) -> None:
        self.entries: List[Dict[str, Any]] = []
        self._now = now or _now_ms
        self._sign = sign

    def append(self, runtime_class: str, body: Dict[str, Any]) -> Dict[str, Any]:
        unsigned: Dict[str, Any] = {"v": 1, "seq": len(self.entries), "prev": self.entries[-1]["digest"] if self.entries else GENESIS,
                                    "at": self._now(), "runtime_class": runtime_class}
        unsigned.update(body)  # the body is spread last, as in the reference
        digest = hash_canonical(unsigned)
        r = dict(unsigned, digest=digest)
        if self._sign is not None:
            r["sig"] = self._sign(digest)
        self.entries.append(r)
        return r


def verify_receipt_chain(receipts: Any, verify_sig: Optional[Callable[[str, Any], bool]] = None) -> Dict[str, Any]:
    """Recompute the chain. Fails on a bad digest, a broken link, a gap, a reorder, or (with `verify_sig`) a bad signature."""
    if not isinstance(receipts, list):
        raise TypeError("receipts is not iterable")
    prev = GENESIS
    for i, r in enumerate(receipts):
        if r is None:
            raise TypeError("receipt is null")
        v, seq = _get(r, "v"), _get(r, "seq")
        one = isinstance(v, (int, float)) and not isinstance(v, bool) and v == 1
        if not one or not (isinstance(seq, (int, float)) and not isinstance(seq, bool) and seq == i):
            return {"ok": False, "at": i, "reason": "bad_seq"}
        p = _get(r, "prev")
        if not isinstance(p, str) or p != prev:
            return {"ok": False, "at": i, "reason": "broken_link"}
        digest, sig = r.get("digest", _U), r.get("sig", _U)
        rest = {k: x for k, x in r.items() if k not in ("digest", "sig")}
        if not isinstance(digest, str) or hash_canonical(rest) != digest:
            return {"ok": False, "at": i, "reason": "bad_digest"}
        if verify_sig is not None and (not isinstance(sig, str) or not verify_sig(digest, sig)):
            return {"ok": False, "at": i, "reason": "bad_sig"}
        prev = digest
    return {"ok": True}


# ---------------------------------------------------------------------------------------------------- authorized operations
def _is_authorized_for(result: Any, operation: Any) -> bool:
    """True only if `result` allowed exactly this operation (verb, resource, params digest). `result` is an AuthorizeResult, or
    any object / dict with `allow` (or `ok`) and a bound `operation` {verb, resource, params_digest}."""
    allow = _attr(result, "allow")
    ok = _attr(result, "ok") if allow is _U else allow
    bound = _attr(result, "operation")
    o = operation if isinstance(operation, dict) else None
    valid = (o is not None and isinstance(o.get("verb"), str) and o["verb"] != "" and isinstance(o.get("resource"), str)
             and o["resource"] != "" and isinstance(o.get("params"), dict))
    if not _jt(ok) or not _jt(bound) or not valid:
        return False
    try:
        return (_attr(bound, "verb") == o["verb"] and _attr(bound, "resource") == o["resource"]
                and _attr(bound, "params_digest") == hash_canonical(o["params"]))
    except Exception:  # noqa: BLE001
        return False


# ---------------------------------------------------------------------------------------------------- OS policy
_PATH_RE = re.compile(r"/[A-Za-z0-9._+@=,:~ /-]*")
_HOST_RE = re.compile(r"[a-z0-9]([a-z0-9.-]*[a-z0-9])?")


def _check_path(p: Any) -> str:
    # absolute, normalized, and only characters that need no escaping in a seccomp / Landlock / SBPL string: refuse, never escape
    if not isinstance(p, str) or not _PATH_RE.fullmatch(p) or "//" in p or (len(p) > 1 and p.endswith("/")) \
            or any(s in (".", "..") for s in p.split("/")):
        raise ValueError("bad_path: %s" % (js_json(p)[:80] if isinstance(p, str) else "undefined"))
    return p


def policy_from_needs(needs: Any, proxy_port: Any = None) -> Dict[str, Any]:
    """Validate, merge and sort the needs of the authorized operations into a sandbox policy {v, fs: {read, write, exec},
    net: {proxy, hosts}}. `write` implies read of the same path; network access exists only through the egress proxy."""
    if not isinstance(needs, list):
        raise TypeError("needs is not iterable")
    read: Set[str] = set()
    write: Set[str] = set()
    ex: Set[str] = set()
    hosts: Set[str] = set()
    for n in needs:
        if n is None:
            raise TypeError("need is null")
        for f in _iterate(_get(n, "fs")):
            if f is None:
                raise TypeError("fs entry is null")
            p = _check_path(_get(f, "path"))
            mode = _get(f, "mode")
            if mode == "x":
                ex.add(p)
            elif mode in ("r", "rw"):
                read.add(p)
                if mode == "rw":
                    write.add(p)
            else:
                raise ValueError("bad_mode")
        for h in _iterate(_get(n, "net")):
            if h is None:
                raise TypeError("net entry is null")
            host, port = _get(h, "host"), _get(h, "port")
            text = _text(host)
            if not _HOST_RE.fullmatch(text) or not _isint(port) or port < 1 or port > 65535:
                raise ValueError("bad_net_need")
            hosts.add("%s:%s" % (text, js_to_string(port)))
    if hosts and proxy_port is None:
        raise ValueError("net_needs_proxy: network access exists only through the egress proxy; pass its port")
    if proxy_port is not None and (not _isint(proxy_port) or proxy_port < 1 or proxy_port > 65535):
        raise ValueError("bad_proxy_port")
    return {"v": 1, "fs": {"read": sorted(read), "write": sorted(write), "exec": sorted(ex)},
            "net": {"proxy": None if proxy_port is None else {"host": "127.0.0.1", "port": proxy_port}, "hosts": sorted(hosts)}}


def compile_policy(items: Iterable[Dict[str, Any]], needs_of: Callable[[Any], Any], proxy_port: Any = None) -> Dict[str, Any]:
    """Compile the OS policy from what was actually authorized: only operations that `is_authorized_for` allows contribute.
    `items` are {"result", "operation"}; `needs_of(operation)` is the tool author's mapping (a falsy value contributes nothing)."""
    needs: List[Any] = []
    for it in items:
        result, operation = it["result"], it["operation"]
        if not _is_authorized_for(result, operation):
            raise ValueError("not_authorized: result does not allow exactly this operation")
        n = needs_of(operation)
        if _jt(n):
            needs.append(n)
    return policy_from_needs(needs, proxy_port)


_BASE = ["read", "write", "close", "fstat", "newfstatat", "statx", "lseek", "mmap", "mprotect", "munmap", "mremap", "brk", "madvise",
         "rt_sigaction", "rt_sigprocmask", "rt_sigreturn", "sigaltstack", "pread64", "pwrite64", "readv", "writev", "openat", "getdents64",
         "fcntl", "getcwd", "readlink", "readlinkat", "dup", "dup3", "pipe2", "poll", "ppoll", "epoll_create1", "epoll_ctl", "epoll_pwait",
         "eventfd2", "futex", "set_tid_address", "set_robust_list", "rseq", "arch_prctl", "prlimit64", "sched_yield", "nanosleep",
         "clock_nanosleep", "clock_gettime", "gettimeofday", "getrandom", "getpid", "gettid", "getuid", "geteuid", "getgid", "getegid",
         "uname", "tgkill", "exit", "exit_group"]
_NET = ["connect", "getsockopt", "setsockopt", "getsockname", "getpeername", "sendto", "recvfrom", "sendmsg", "recvmsg", "shutdown"]
_EXEC = ["execve", "execveat"]
_AF_INET, _AF_INET6 = 2, 10


def seccomp_profile(p: Dict[str, Any]) -> Dict[str, Any]:
    """Docker / OCI-format seccomp profile: deny by default; network syscalls only when the policy has a proxy; `socket` only for
    AF_INET / AF_INET6; exec only when the grant names a binary. seccomp cannot see paths or addresses: pair it with Landlock."""
    syscalls: List[Dict[str, Any]] = [{"names": sorted(_BASE), "action": "SCMP_ACT_ALLOW"}]
    if p["net"]["proxy"]:
        syscalls.append({"names": sorted(_NET), "action": "SCMP_ACT_ALLOW"})
        for d in (_AF_INET, _AF_INET6):
            syscalls.append({"names": ["socket"], "action": "SCMP_ACT_ALLOW", "args": [{"index": 0, "value": d, "op": "SCMP_CMP_EQ"}]})
    if len(p["fs"]["exec"]) > 0:
        syscalls.append({"names": list(_EXEC), "action": "SCMP_ACT_ALLOW"})
    return {"defaultAction": "SCMP_ACT_ERRNO", "defaultErrnoRet": 1,
            "archMap": [{"architecture": "SCMP_ARCH_X86_64", "subArchitectures": []},
                        {"architecture": "SCMP_ARCH_AARCH64", "subArchitectures": []}],
            "syscalls": syscalls}


_FS_HANDLED = ["EXECUTE", "WRITE_FILE", "READ_FILE", "READ_DIR", "REMOVE_DIR", "REMOVE_FILE", "MAKE_CHAR", "MAKE_DIR", "MAKE_REG",
               "MAKE_SOCK", "MAKE_FIFO", "MAKE_BLOCK", "MAKE_SYM", "REFER", "TRUNCATE"]


def landlock_ruleset(p: Dict[str, Any]) -> Dict[str, Any]:
    """Landlock ruleset (access-right names from the kernel UAPI; network rules need ABI 4): handle every right, allow only what
    the grant names."""
    fs_p = p["fs"]
    fs = []
    for path in sorted(set(fs_p["read"]) | set(fs_p["write"]) | set(fs_p["exec"])):
        access: List[str] = []
        if path in fs_p["exec"]:
            access += ["EXECUTE", "READ_FILE"]  # execve opens the binary for reading, so the kernel also demands READ_FILE
        if path in fs_p["read"]:
            access += ["READ_FILE", "READ_DIR"]
        if path in fs_p["write"]:
            access += ["WRITE_FILE", "TRUNCATE", "MAKE_REG", "MAKE_DIR", "REMOVE_FILE", "REMOVE_DIR"]
        fs.append({"path": path, "access": ["LANDLOCK_ACCESS_FS_" + x for x in dict.fromkeys(access)]})
    proxy = p["net"]["proxy"]
    return {"v": 1, "abi_min": 4, "handled_access_fs": ["LANDLOCK_ACCESS_FS_" + x for x in _FS_HANDLED],
            "handled_access_net": ["LANDLOCK_ACCESS_NET_BIND_TCP", "LANDLOCK_ACCESS_NET_CONNECT_TCP"],
            "rules": {"fs": fs, "net": [{"port": proxy["port"], "access": ["LANDLOCK_ACCESS_NET_CONNECT_TCP"]}] if proxy else []}}


def macos_profile(p: Dict[str, Any]) -> str:
    """macOS sandbox profile (SBPL for sandbox-exec(1)): deny by default; paths were validated to need no escaping."""
    def q(s: Any) -> str:
        return '"%s"' % js_to_string(s)

    lines = ["(version 1)", "(deny default)", "(allow sysctl-read)", "(allow process-fork)", "(allow mach-lookup)",
             "(allow file-read-metadata)",
             '(allow file-read* (literal "/") (literal "/dev/null") (literal "/dev/urandom") (subpath "/usr/lib") '
             '(subpath "/System/Library") (subpath "/private/var/db/dyld") (subpath "/System/Volumes/Preboot/Cryptexes"))']
    for x in p["fs"]["exec"]:
        lines += ["(allow process-exec (literal %s))" % q(x), "(allow file-read* (literal %s))" % q(x)]
    for r in p["fs"]["read"]:
        lines.append("(allow file-read* (subpath %s))" % q(r))
    for w in p["fs"]["write"]:
        lines.append("(allow file-write* (subpath %s))" % q(w))
    if p["net"]["proxy"]:
        lines.append("(allow network-outbound (remote tcp %s))" % q("localhost:%s" % js_to_string(p["net"]["proxy"]["port"])))
    return "\n".join(lines) + "\n"


def confine_args(policy: Dict[str, Any]) -> List[str]:
    """Flatten the generated seccomp and Landlock profiles into the flags of a reference `pca-confine <flags> -- <command>` helper,
    so what the helper enforces is exactly what the generators produced."""
    ll = landlock_ruleset(policy)
    sc = seccomp_profile(policy)

    def short(n: str) -> str:
        return n[len("LANDLOCK_ACCESS_"):] if n.startswith("LANDLOCK_ACCESS_") else n

    args: List[str] = ["--fs-handled", ",".join(short(x) for x in ll["handled_access_fs"])]
    if len(ll["rules"]["net"]) > 0 or policy["net"]["proxy"]:
        args += ["--net-handled", ",".join(short(x) for x in ll["handled_access_net"])]
    for r in ll["rules"]["fs"]:
        args += ["--fs", "%s:%s" % (r["path"], ",".join(short(x) for x in r["access"]))]
    for r in ll["rules"]["net"]:
        args += ["--net", "%s:%s" % (js_to_string(r["port"]), ",".join(short(x) for x in r["access"]))]
    for s in sc["syscalls"]:
        if s.get("args"):
            for a in s["args"]:
                for n in s["names"]:
                    args += ["--allow-arg", "%s:%s:%s" % (n, a["index"], a["value"])]
        else:
            for n in s["names"]:
                args += ["--allow", n]
    return args


# ---------------------------------------------------------------------------------------------------- runtime claims
_CLAIM_KEYS = ("v", "class", "passport_digest", "evidence_digest", "iat", "exp", "attestor", "sig")


def _claim_body(c: Dict[str, Any]) -> bytes:
    return RUNTIME_CLAIM_DOMAIN.encode("utf-8") + canonical_bytes_strict(c)


def sign_runtime_claim(secret_key: bytes, public_key: bytes, c: Dict[str, Any]) -> Dict[str, Any]:
    """A signed statement that a sandbox runs at `class`, bound to the signed passport (by digest) of the agent it contains. The
    signer is an attestor the verifier pins. Signs `domain || canonical(claim without sig)` with Ed25519; raises on a key that is
    not a 32-byte seed or a claim outside the strict canonical profile."""
    unsigned = dict({"v": 1}, **c)
    unsigned["attestor"] = b64u(bytes(public_key))
    return dict(unsigned, sig=b64u(ed25519.sign_secret(bytes(secret_key), _claim_body(unsigned))))


def _includes(coll: Any, x: Any) -> bool:
    if isinstance(coll, list):
        return any(_same(x, y) for y in coll)
    if isinstance(coll, str):
        return isinstance(x, str) and x in coll
    raise TypeError("includes is not a function")


def _same(a: Any, b: Any) -> bool:
    if isinstance(a, bool) or isinstance(b, bool):
        return isinstance(a, bool) and isinstance(b, bool) and a == b
    if isinstance(a, (int, float)) and isinstance(b, (int, float)):
        return a == b
    return type(a) is type(b) and a == b and not isinstance(a, (dict, list))


def _nat(v: Any) -> bool:
    """A safe integer >= 0, never -0: a negative time is never valid."""
    return _isint(v) and not _is_neg_zero(v) and 0 <= v <= 9007199254740991


def _str128(v: Any) -> bool:
    """A non-empty string of at most 128 UTF-16 code units."""
    return isinstance(v, str) and 0 < _u16len(v) <= 128


def verified_runtime_class(claim: Any, trust: Any) -> str:
    """The class the claim proves, or `none` for anything missing, unsigned, unpinned, expired, for another passport, over evidence
    nobody verified, or malformed. `trust` is {pinnedAttestors, passportDigest, verifiedEvidenceDigests, now}. Total."""
    try:
        c = claim
        if not isinstance(c, dict) or len(c) != len(_CLAIM_KEYS) or any(k not in _CLAIM_KEYS for k in c):
            return "none"
        v = c.get("v")
        if not (isinstance(v, (int, float)) and not isinstance(v, bool) and v == 1) or c.get("class") not in RUNTIME_CLASSES \
                or not isinstance(c.get("class"), str):
            return "none"
        if not isinstance(c.get("sig"), str) or not _str128(c.get("attestor")) or not _str128(c.get("passport_digest")) \
                or not _str128(c.get("evidence_digest")) or not _includes(_get(trust, "pinnedAttestors"), c["attestor"]):
            return "none"
        now = _get(trust, "now")
        iat, exp = c.get("iat"), c.get("exp")
        if c.get("passport_digest") != _get(trust, "passportDigest") or not _nat(iat) or not _nat(exp) or not _nat(now) \
                or now < iat or now >= exp:
            return "none"
        if not isinstance(c.get("evidence_digest"), str) or not _includes(_get(trust, "verifiedEvidenceDigests"), c["evidence_digest"]) \
                or not isinstance(c.get("passport_digest"), str) or decode_b64u_strict(c["attestor"], 32) is None:
            return "none"
        rest = {k: x for k, x in c.items() if k != "sig"}
        sig = c["sig"]
        if decode_b64u_strict(sig, 64) is None:
            return "none"
        return c["class"] if _verify_b64u(c["attestor"], _claim_body(rest), sig) else "none"
    except Exception:  # noqa: BLE001
        return "none"


def passport_digest(signed_passport: Any) -> str:
    return hash_canonical(signed_passport)


def evidence_digest(document: Any) -> str:
    """The digest a claim's `evidence_digest` must equal for this attestation document."""
    return hash_canonical(document)


# ---------------------------------------------------------------------------------------------------- capability handles
def _deep_copy(x: Any) -> Any:
    return copy.deepcopy(x)


class HandleTable:
    """A per-sandbox capability table: indices are small integers meaningful only inside one table, like file descriptors. A slot
    exists only because a verified PCActn authorized exactly that operation, derivation is monotone (a child can only hold what the
    parent gave up) and revoking a slot revokes everything derived from it. `executors` maps a verb to
    ``fn(op) -> bytes`` (the op is a private copy); the executor gets the signed params, never the guest's."""

    def __init__(self, runtime_class: str, log: ReceiptLog, executors: Dict[str, Callable[[Dict[str, Any]], Any]],
                 now: Optional[Callable[[], Any]] = None) -> None:
        self.runtime_class = runtime_class
        self._log = log
        self._executors = executors
        self._now = now or _now_ms
        self._slots: List[Dict[str, Any]] = []

    def mint(self, result: Any, operation: Dict[str, Any], opts: Optional[Dict[str, Any]] = None) -> int:
        """Mint a handle for the operation `result` allowed. Raises (fail closed) if `result` does not allow exactly `operation`."""
        opts = opts or {}
        if opts.get("requires") is not None and not satisfies_runtime_class(self.runtime_class, opts["requires"]):
            raise ValueError("runtime_class_too_weak: table is %s, grant requires %s" % (self.runtime_class, opts["requires"]))
        if not _is_authorized_for(result, operation):
            raise ValueError("not_authorized: result does not allow exactly this operation")
        bound = _attr(result, "operation")
        uses = 1 if _nullish(opts.get("uses")) else opts["uses"]
        if not _isint(uses) or uses < 1 or uses > 1_000_000:
            raise ValueError("bad_uses")
        op = _deep_copy({"verb": operation["verb"], "resource": operation["resource"], "params": operation["params"]})
        bid = _attr(bound, "id")
        exp = opts.get("expiresAt")
        return self._push({"op": op, "params_digest": hash_canonical(op["params"]), "op_id": "" if _nullish(bid) else bid, "uses": uses,
                           "expiresAt": math.inf if _nullish(exp) else exp, "revoked": False, "children": []})

    def attenuate(self, index: Any, narrower: Optional[Dict[str, Any]] = None) -> int:
        """Derive a narrower handle: takes `uses` from the parent (never more than it has) and an expiry no later than its."""
        narrower = narrower or {}
        p = self._live(index)
        if p is None:
            raise ValueError("unknown_handle")
        uses = p["uses"] if _nullish(narrower.get("uses")) else narrower["uses"]
        if not _isint(uses) or uses < 1 or uses > p["uses"]:
            raise ValueError("attenuate_widens")
        expires = p["expiresAt"] if _nullish(narrower.get("expiresAt")) else narrower["expiresAt"]
        if not (isinstance(expires, (int, float)) and not isinstance(expires, bool) and expires <= p["expiresAt"]):
            raise ValueError("attenuate_widens")
        p["uses"] -= uses
        child = self._push(dict(p, op=_deep_copy(p["op"]), uses=uses, expiresAt=expires, revoked=False, children=[]))
        p["children"].append(child)
        return child

    def revoke(self, index: Any) -> None:
        """Revoke a handle and, transitively, every handle derived from it."""
        s = self._slot(index)
        if s is None or s["revoked"]:
            return
        s["revoked"] = True
        for c in s["children"]:
            self.revoke(c)

    @property
    def size(self) -> int:
        return len(self._slots)

    def verb_of(self, index: Any) -> Optional[str]:
        s = self._slot(index)
        return None if s is None else s["op"]["verb"]

    def use(self, index: Any) -> Dict[str, Any]:
        """Run the executor on the authorized operation and record a receipt. A use is consumed before the executor runs and stays
        consumed if it raises (a failed side effect needs a new authorization, not a retry on the old one)."""
        b = self._begin(index)
        if "ok" in b:
            return b
        try:
            result = b["exec"](_deep_copy(b["s"]["op"]))
            if inspect.isawaitable(result):
                getattr(result, "close", lambda: None)()  # a coroutine on the sync path is an error; its use is already spent
                return self._finish(b["s"], {"ok": False, "reason": "executor_error"})
            if not isinstance(result, (bytes, bytearray)):
                return self._finish(b["s"], {"ok": False, "reason": "executor_error"})
            return self._finish(b["s"], {"ok": True, "result": bytes(result)})
        except Exception:  # noqa: BLE001
            return self._finish(b["s"], {"ok": False, "reason": "executor_error"})

    async def use_async(self, index: Any) -> Dict[str, Any]:
        """`use` for an executor that may return an awaitable."""
        b = self._begin(index)
        if "ok" in b:
            return b
        try:
            result = b["exec"](_deep_copy(b["s"]["op"]))
            if inspect.isawaitable(result):
                result = await result
            if isinstance(result, (bytes, bytearray)):
                return self._finish(b["s"], {"ok": True, "result": bytes(result)})
            return self._finish(b["s"], {"ok": False, "reason": "executor_error"})
        except Exception:  # noqa: BLE001
            return self._finish(b["s"], {"ok": False, "reason": "executor_error"})

    def _begin(self, index: Any) -> Dict[str, Any]:
        s = self._slot(index)
        if s is None:
            self._log.append(self.runtime_class, {"kind": "handle_use", "subject": {"op_id": "", "verb": "", "resource": "", "params_digest": ""},
                                                  "outcome": "refused", "reason": "unknown_handle"})
            return {"ok": False, "reason": "unknown_handle"}
        live = self._live(index)
        if live is None:
            return self._finish(s, {"ok": False, "reason": "spent"})
        ex = self._executors.get(s["op"]["verb"])
        if not ex:
            return self._finish(s, {"ok": False, "reason": "no_executor"})
        live["uses"] -= 1
        return {"s": s, "exec": ex}

    def _finish(self, s: Dict[str, Any], r: Dict[str, Any]) -> Dict[str, Any]:
        outcome = "ok" if r["ok"] else "error" if r["reason"] == "executor_error" else "refused"
        self._log.append(self.runtime_class, {"kind": "handle_use", "subject": {"op_id": s["op_id"], "verb": s["op"]["verb"],
                                                                                  "resource": s["op"]["resource"], "params_digest": s["params_digest"]},
                                              "outcome": outcome, "reason": "used" if r["ok"] else r["reason"]})
        return r

    def _slot(self, index: Any) -> Optional[Dict[str, Any]]:
        if isinstance(index, (int, float)) and not isinstance(index, bool) and _isint(index) and 1 <= index <= len(self._slots):
            return self._slots[int(index) - 1]
        return None

    def _live(self, index: Any) -> Optional[Dict[str, Any]]:
        s = self._slot(index)
        return s if s is not None and not s["revoked"] and s["uses"] > 0 and self._now() < s["expiresAt"] else None

    def _push(self, s: Dict[str, Any]) -> int:
        self._slots.append(s)
        return len(self._slots)


# ---------------------------------------------------------------------------------------------------- egress
_DEFAULT_PORT = {"http": 80, "https": 443}
_EGRESS_HOST_RE = re.compile(r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*")
_V4_SEG = r"(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])"
_V4 = r"(?:%s\.){3}%s" % (_V4_SEG, _V4_SEG)
_V4_RE = re.compile(_V4)
_V6_SEG = r"(?:[0-9a-fA-F]{1,4})"
_V6_RE = re.compile(
    r"(?:"
    r"(?:%(s)s:){7}(?:%(s)s|:)|"
    r"(?:%(s)s:){6}(?:%(v4)s|:%(s)s|:)|"
    r"(?:%(s)s:){5}(?::%(v4)s|(?::%(s)s){1,2}|:)|"
    r"(?:%(s)s:){4}(?:(?::%(s)s){0,1}:%(v4)s|(?::%(s)s){1,3}|:)|"
    r"(?:%(s)s:){3}(?:(?::%(s)s){0,2}:%(v4)s|(?::%(s)s){1,4}|:)|"
    r"(?:%(s)s:){2}(?:(?::%(s)s){0,3}:%(v4)s|(?::%(s)s){1,5}|:)|"
    r"(?:%(s)s:){1}(?:(?::%(s)s){0,4}:%(v4)s|(?::%(s)s){1,6}|:)|"
    r"(?::(?:(?::%(s)s){0,5}:%(v4)s|(?::%(s)s){1,7}|:))"
    r")(?:%%[0-9a-zA-Z-.:]{1,})?" % {"s": _V6_SEG, "v4": _V4})


def _is_ipv4(s: str) -> bool:
    return _V4_RE.fullmatch(s) is not None


def _is_ipv6(s: str) -> bool:
    return _V6_RE.fullmatch(s) is not None


def _is_private_v4(a: int, b: int) -> bool:
    return (a == 0 or a == 10 or a == 127 or (a == 169 and b == 254) or (a == 172 and 16 <= b <= 31) or (a == 192 and b == 168)
            or (a == 100 and 64 <= b <= 127) or a >= 224)


def is_private_address(ip: Any) -> bool:
    """Loopback, link-local, private, CGNAT, multicast, reserved and unspecified addresses, classified on the parsed address, not
    its spelling. IPv6: only global unicast (2000::/3) is public; an IPv4-mapped, IPv4-compatible or NAT64 (64:ff9b::/96) address
    follows its embedded IPv4 address; a zoned address (``%id``) is link-scoped, so private. Anything that is not an IP literal
    (or not a string) counts as private (refused)."""
    if not isinstance(ip, str):
        return True
    if _is_ipv4(ip):
        a, b = (int(x) for x in ip.split(".")[:2])
        return _is_private_v4(a, b)
    if "%" in ip or not _is_ipv6(ip):
        return True
    try:
        g = ipaddress.IPv6Address(ip).packed
    except ValueError:
        return True
    w = [int.from_bytes(g[i:i + 2], "big") for i in range(0, 16, 2)]
    zero80 = w[0] == 0 and w[1] == 0 and w[2] == 0 and w[3] == 0 and w[4] == 0
    nat64 = w[0] == 0x64 and w[1] == 0xff9b and w[2] == 0 and w[3] == 0 and w[4] == 0 and w[5] == 0
    if (zero80 and w[5] in (0, 0xffff)) or nat64:
        return _is_private_v4(w[6] >> 8, w[6] & 0xff)
    return w[0] < 0x2000 or w[0] >= 0x4000


def sha256_b64u(b: bytes) -> str:
    return b64u(hashlib.sha256(b).digest())


def _is_ip(host: str) -> bool:
    return _is_ipv4(host) or _is_ipv6(host)


_ENC_PATH_RE = re.compile(r"%2e|%2f|%5c|\\", re.I | re.A)
_BAD_TEMPLATE_PATH_RE = re.compile(r"[?#\\]|%2e|%2f|%5c|(^|/)\.\.?(/|\Z)", re.I | re.A)
_CONNECT_RE = re.compile(r"([a-z0-9.-]+|\[[0-9a-f:]+\]):(\d{1,5})", re.I | re.A)


def _url_extras(url: str) -> Dict[str, Any]:
    """What the WHATWG URL class reports beyond the parse: whether the userinfo or the fragment is non-empty (http / https)."""
    s = re.sub(r"[\t\n\r]", "", re.sub(r"^[\x00-\x20]+|[\x00-\x20]+$", "", url))
    m = re.match(r"[A-Za-z][A-Za-z0-9+.\-]*:", s)
    rest = s[m.end():] if m else s
    frag = rest.find("#")
    hash_set = frag >= 0 and len(rest) > frag + 1
    if frag >= 0:
        rest = rest[:frag]
    q = rest.find("?")
    if q >= 0:
        rest = rest[:q]
    rest = re.sub(r"^[/\\]+", "", rest)
    cut = re.search(r"[/\\]", rest)
    authority = rest[: cut.start()] if cut else rest
    user = pw = ""
    if "@" in authority:
        info = authority.rpartition("@")[0]
        user, _, pw = info.partition(":")
    return {"userinfo": user != "" or pw != "", "hash": hash_set}


def _parse_target(req: Dict[str, Any]) -> Dict[str, Any]:
    from .oauth import _parse_url  # the platform-URL-class model shared with the OAuth helpers

    method = req["method"].upper()
    url = _get(req, "url")
    if method == "CONNECT":
        m = _CONNECT_RE.fullmatch(_text(url))
        if not m:
            return {"reason": "bad_connect_target"}
        host = re.sub(r"^\[|\]$", "", m.group(1)).lower()
        return {"connect": True, "scheme": "https", "host": host, "port": int(m.group(2)), "path": "", "query": ""}
    text = _text(url)
    u = _parse_url(text)
    if u is None:
        return {"reason": "not_absolute_url"}
    scheme = u["scheme"]
    if scheme not in ("http", "https"):
        return {"reason": "bad_url"}
    ex = _url_extras(text)
    if ex["userinfo"] or ex["hash"]:
        return {"reason": "bad_url"}
    # encoded dots and slashes are how a prefix match is walked out of: refuse rather than decode
    if _ENC_PATH_RE.search(u["pathname"]):
        return {"reason": "encoded_path"}
    hostport = u["host"]
    if hostport.startswith("["):
        end = hostport.index("]")
        host, port_text = hostport[1:end], hostport[end + 2:]
    else:
        host, _, port_text = hostport.partition(":")
    return {"connect": False, "scheme": scheme, "host": host.lower(), "port": int(port_text) if port_text else _DEFAULT_PORT[scheme],
            "path": u["pathname"], "query": re.sub(r"^\?", "", u["search"])}


class EgressPolicy:
    """Default deny. The only way a request is allowed is by matching a template admitted from a verified operation. The template
    is the one outbound request an operation maps to: ``{method, scheme, host, port?, path, path_prefix?, query?, body_sha256?,
    tunnel?}``, exact host, port and method; the path exact unless `path_prefix`; the query must equal `query` (absent = none); a
    request with a body must match `body_sha256`; `tunnel` admits a CONNECT to host:port instead."""

    def __init__(self, now: Optional[Callable[[], Any]] = None) -> None:
        self._admissions: List[Dict[str, Any]] = []
        self._now = now or _now_ms

    def admit(self, result: Any, operation: Dict[str, Any], to_request: Callable[[Any], Any], opts: Optional[Dict[str, Any]] = None) -> None:
        """Admit the request `operation` maps to. Raises unless `result` allows exactly `operation` and the template is well formed."""
        opts = opts or {}
        if not _is_authorized_for(result, operation):
            raise ValueError("not_authorized: result does not allow exactly this operation")
        t = to_request(operation)
        if not _jt(t):
            raise ValueError("no_egress_for_operation")
        if not isinstance(t, dict):
            raise TypeError("template is not an object")
        host = t.get("host")
        if not isinstance(host, str):
            raise TypeError("host.toLowerCase is not a function")
        if not (_is_ip(host) or _EGRESS_HOST_RE.fullmatch(host)) or host != host.lower():
            raise ValueError("bad_template_host")
        scheme = t.get("scheme")
        if scheme != "http" and scheme != "https":
            raise ValueError("bad_template_scheme")
        port = _DEFAULT_PORT[scheme] if _nullish(t.get("port")) else t["port"]
        if not _isint(port) or port < 1 or port > 65535:
            raise ValueError("bad_template_port")
        method = t.get("method")
        if not isinstance(method, str) or not re.fullmatch(r"[A-Z]+", method):
            raise ValueError("bad_template_method")
        path = t.get("path")
        if not isinstance(path, str):
            raise TypeError("t.path.startsWith is not a function")
        if not path.startswith("/") or _BAD_TEMPLATE_PATH_RE.search(path):
            raise ValueError("bad_template_path")
        uses = 1 if _nullish(opts.get("uses")) else opts["uses"]
        if not _isint(uses) or uses < 1:
            raise ValueError("bad_uses")
        bound = _attr(result, "operation")
        bid = _attr(bound, "id")
        exp = opts.get("expiresAt")
        self._admissions.append({"op_id": "" if _nullish(bid) else bid, "op": operation, "template": dict(t, host=host, port=port),
                                 "uses": uses, "expiresAt": math.inf if _nullish(exp) else exp})

    def claim(self, req: Dict[str, Any]) -> Dict[str, Any]:
        """Decide and, if allowed, spend one use of the matching admission. Anything not matched is denied with a reason."""
        parsed = _parse_target(req)
        if "reason" in parsed:
            return {"allow": False, "reason": parsed["reason"]}
        body = req.get("body") or b""
        why = "no_admission"
        for a in self._admissions:
            t = a["template"]
            if parsed["connect"] != (t.get("tunnel") is True):
                continue
            if t["method"] != req["method"].upper() and not parsed["connect"]:
                continue
            if parsed["scheme"] != t["scheme"] and not parsed["connect"]:
                continue
            if parsed["host"] != t["host"] or parsed["port"] != t["port"]:
                continue
            if not parsed["connect"]:
                if _jt(t.get("path_prefix")):
                    prefix = t["path"] if t["path"].endswith("/") else t["path"] + "/"
                    ok = parsed["path"] == t["path"] or parsed["path"].startswith(prefix)
                else:
                    ok = parsed["path"] == t["path"]
                if not ok:
                    continue
                if parsed["query"] != ("" if _nullish(t.get("query")) else t["query"]):
                    why = "query_mismatch"
                    continue
                bh = t.get("body_sha256", _U)
                if len(body) > 0 and (bh is _U or sha256_b64u(body) != bh):
                    why = "body_mismatch"
                    continue
                if len(body) == 0 and bh is not _U and bh != sha256_b64u(body):
                    why = "body_mismatch"
                    continue
            if a["uses"] < 1 or self._now() >= a["expiresAt"]:  # reported only when the request would otherwise have matched
                why = "spent"
                continue
            a["uses"] -= 1
            return {"allow": True, "op_id": a["op_id"],
                    "admission": {"verb": a["op"]["verb"], "resource": a["op"]["resource"], "params_digest": hash_canonical(a["op"]["params"])}}
        return {"allow": False, "reason": why}


# ---------------------------------------------------------------------------------------------------- reference WebAssembly tools
def _u(n: int) -> List[int]:
    out: List[int] = []
    while True:
        b = n & 0x7F
        n //= 128
        if n > 0:
            b |= 0x80
        out.append(b)
        if n <= 0:
            return out


def _s(x: str) -> List[int]:
    return _u(_u16len(x)) + list(x.encode("utf-8", "replace"))


def _section(i: int, body: List[int]) -> List[int]:
    return [i] + _u(len(body)) + body


def _vec(items: Sequence[List[int]]) -> List[int]:
    return _u(len(items)) + [b for it in items for b in it]


def _sleb(n: int) -> List[int]:
    n = ((n + 2 ** 31) % 2 ** 32) - 2 ** 31  # the reference shifts int32 values
    out: List[int] = []
    while True:
        b = n & 0x7F
        n >>= 7
        if (n == 0 and (b & 0x40) == 0) or (n == -1 and (b & 0x40) != 0):
            return out + [b]
        out.append(b | 0x80)


def _i32c(n: int) -> List[int]:
    return [0x41] + _sleb(n)


def build_tool(spec: Dict[str, Any]) -> bytes:
    """A hand-assembled core-WebAssembly module that calls `pca:act.invoke(handle, ptr, cap)` for each given call and returns
    either the last call's return code or the first byte of linear memory. `spec`: {calls: [{handle, ptr, cap}], returns?:
    'last' | 'byte0', extraImports?: [{module, name}], memory?: {min, max}, spin?: bool}."""
    extra = spec.get("extraImports") or []
    types = _vec([[0x60, 3, 0x7F, 0x7F, 0x7F, 1, 0x7F], [0x60, 0, 1, 0x7F], [0x60, 4, 0x7F, 0x7F, 0x7F, 0x7F, 1, 0x7F]])
    imports = _vec([_s("pca:act") + _s("invoke") + [0, 0]] + [_s(e["module"]) + _s(e["name"]) + [0, 2] for e in extra])
    mem = spec.get("memory") or {"min": 1, "max": 1}
    memory = _vec([[0] + _u(mem["min"]) if mem.get("max") is None else [1] + _u(mem["min"]) + _u(mem["max"])])
    run_index = 1 + len(extra)
    calls = spec["calls"]
    returns = spec.get("returns") or "last"
    body: List[int] = [0]
    for i, c in enumerate(calls):
        body += _i32c(c["handle"]) + _i32c(c["ptr"]) + _i32c(c["cap"]) + [0x10, 0]
        if not (i == len(calls) - 1 and returns == "last"):
            body.append(0x1A)
    if spec.get("spin"):
        body += [0x03, 0x40, 0x0C, 0x00, 0x0B]
    if spec.get("returns") == "byte0":
        body += _i32c(0) + [0x2D, 0, 0]
    if len(calls) == 0:
        body += _i32c(0)
    body.append(0x0B)
    out = ([0, 0x61, 0x73, 0x6D, 1, 0, 0, 0] + _section(1, types) + _section(2, imports) + _section(3, _vec([[1]])) + _section(5, memory)
           + _section(7, _vec([_s("memory") + [2, 0], _s("run") + [0] + _u(run_index)])) + _section(10, _vec([_u(len(body)) + body])))
    return bytes(b & 0xFF for b in out)


def build_probe_tool(cap: int = 64) -> bytes:
    """A tool that asks the table what it holds: returns `handle_count() * 256 + first byte of handle 1's verb`."""
    types = _vec([[0x60, 3, 0x7F, 0x7F, 0x7F, 1, 0x7F], [0x60, 0, 1, 0x7F]])
    imports = _vec([_s("pca:act") + _s("invoke") + [0, 0], _s("pca:act") + _s("handle_count") + [0, 1], _s("pca:act") + _s("handle_verb") + [0, 0]])
    body = [0] + _i32c(1) + _i32c(0) + _i32c(cap) + [0x10, 2, 0x1A, 0x10, 1] + _i32c(256) + [0x6C] + _i32c(0) + [0x2D, 0, 0, 0x6A, 0x0B]
    out = ([0, 0x61, 0x73, 0x6D, 1, 0, 0, 0] + _section(1, types) + _section(2, imports) + _section(3, _vec([[1]])) + _section(5, _vec([[1, 1, 1]]))
           + _section(7, _vec([_s("memory") + [2, 0], _s("run") + [0, 3]])) + _section(10, _vec([_u(len(body)) + body])))
    return bytes(b & 0xFF for b in out)


def reference_component_wat(o: Optional[Dict[str, Any]] = None) -> str:
    """The reference tool as a component in the WebAssembly text format: imports only `pca:act/invoke@0.1.0` and exports
    `run: func() -> s32`. Options: {handle?: default 1, spin?: loop forever, extraImport?: an import the host must refuse}."""
    o = o or {}
    imp = o.get("extraImport")
    extra = '(import "%s" (instance (export "get-arguments" (func (result (list string))))))' % imp if _jt(imp) else ""
    handle = 1 if _nullish(o.get("handle")) else o["handle"]
    if _jt(o.get("spin")):
        body = "(loop $l (br $l)) (i32.const 0)"
    else:
        body = ("(call $invoke (i32.const %s) (i32.const 16))\n"
                "       (if (result i32) (i32.load8_u (i32.const 16))\n"
                "         (then (i32.load (i32.const 20)))\n"
                "         (else (i32.load8_u (i32.load (i32.const 20)))))" % js_to_string(handle))
    return ("(component\n"
            '  (import "pca:act/invoke@0.1.0" (instance $inv\n'
            '    (export "handle-count" (func (result u32)))\n'
            '    (export "invoke" (func (param "handle" u32) (result (result (list u8) (error s32)))))))\n'
            "  " + extra + "\n"
            "  (core module $libc\n"
            '    (memory (export "memory") 1 1)\n'
            "    (global $bump (mut i32) (i32.const 1024))\n"
            '    (func (export "realloc") (param $old i32) (param $oldsz i32) (param $align i32) (param $new i32) (result i32)\n'
            "      (local $p i32)\n"
            "      (local.set $p (global.get $bump))\n"
            "      (global.set $bump (i32.add (local.get $p) (local.get $new)))\n"
            "      (local.get $p)))\n"
            "  (core instance $libc (instantiate $libc))\n"
            '  (alias core export $libc "memory" (core memory $mem))\n'
            '  (alias core export $libc "realloc" (core func $realloc))\n'
            '  (core func $count (canon lower (func $inv "handle-count")))\n'
            '  (core func $invoke (canon lower (func $inv "invoke") (memory $mem) (realloc $realloc)))\n'
            "  (core module $main\n"
            '    (import "libc" "memory" (memory 1))\n'
            '    (import "host" "count" (func $count (result i32)))\n'
            '    (import "host" "invoke" (func $invoke (param i32 i32)))\n'
            '    (func (export "run") (result i32)\n'
            "      " + body + "))\n"
            '  (core instance $host (export "count" (func $count)) (export "invoke" (func $invoke)))\n'
            '  (core instance $main (instantiate $main (with "libc" (instance $libc)) (with "host" (instance $host))))\n'
            '  (alias core export $main "run" (core func $run))\n'
            "  (func $lifted (result s32) (canon lift (core func $run)))\n"
            '  (export "run" (func $lifted)))\n')
