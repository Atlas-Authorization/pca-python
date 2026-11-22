"""Differential oracle: the durable state store (atlas_pca.durable_state) against the traces generated from the TypeScript reference:
commit and compaction bytes, tamper / rollback / generation-fence loading, the lock protocol and operator recovery. A scenario is
an initial directory plus steps (open + ops, recover, write, dir); the whole trace (results, error codes and messages, the final
directory) must match."""
import gzip
import hashlib
import json
import os
import re
import shutil
import socket
import tempfile

import pytest

from atlas_pca import DurableStateError, open_durable_state, recover_durable_state

HERE = os.path.dirname(os.path.abspath(__file__))
with gzip.open(os.path.join(HERE, "test-data", "ref-durable-state.json.gz"), "rt", encoding="utf-8") as _f:
    CORPUS = json.load(_f)
DEAD = 999999999
# the reference spells option names in camelCase inside messages
NAMES = [
    ("recover_durable_state requires force=True", "recoverDurableState requires force: true"),
    ("expected_holder='unreadable'", "expectedHolder: 'unreadable'"),
    ("legacy_lock=True, but", "legacyLock: true, but"),
    ("pass legacy_lock=True with its expected_holder", "pass legacyLock: true with its expectedHolder"),
    ("call recover_durable_state without legacy_lock", "call recoverDurableState without legacyLock"),
    ("recover_durable_state(dir=, force=True, legacy_lock=True, expected_holder=)", "recoverDurableState({ dir, force: true, legacyLock: true, expectedHolder })"),
    ("recover_durable_state(dir=, force=True, expected_holder=)", "recoverDurableState({ dir, force: true, expectedHolder })"),
    ("recover_durable_state resumed", "recoverDurableState resumed"),
    ("recover_from_corruption", "recoverFromCorruption"),
    ("expected_holder", "expectedHolder"),
    ("hmac_key", "hmacKey"),
]


def _scenario(sc):
    d = tempfile.mkdtemp(prefix="pca-ds-replay-")
    host = socket.gethostname()
    pid = os.getpid()

    def subst(s):
        return s.replace("$HOST", host).replace("$PID", str(pid)).replace("$DEAD", str(DEAD))

    def norm(s):
        s = s.replace(d, "$DIR").replace(host, "$HOST").replace("pid=%d" % pid, "pid=$PID").replace("pid %d" % pid, "pid $PID")
        s = s.replace("$DIR\\", "$DIR/")  # the reference's messages use POSIX separators; Windows joins with a backslash
        for a, b in NAMES:
            s = s.replace(a, b)
        return s

    def norm_name(f):
        f = re.sub(r"^(state\.fence\.\d+)-[0-9a-f]+", r"\1-*", f)
        f = re.sub(r"\.quarantine-.*$", ".quarantine-*", f)
        f = re.sub(r"^state\.lock\.legacy-recovered-.*$", "state.lock.legacy-recovered-*", f)
        return re.sub(r"^state\.lock\.tmp-.*$", "state.lock.tmp-*", f)

    def err(e):
        return {"err": {"code": e.code, "msg": norm(str(e))}}

    def read(f):
        p = os.path.join(d, f)
        return open(p, encoding="utf-8").read() if os.path.exists(p) else None

    def put(f, text):
        p = os.path.join(d, f)
        if text is None:
            if os.path.exists(p):
                os.unlink(p)
        else:
            with open(p, "w", encoding="utf-8", newline="") as fh:
                fh.write(subst(text))

    def snapshot():
        names = sorted(os.listdir(d))
        fences = []

        def try_fence(f, pick):
            try:
                for x in pick(json.loads(read(f))):
                    fences.append({k: v for k, v in x.items() if k != "t"})
            except Exception:  # noqa: BLE001
                fences.append({"unreadable": norm_name(f)})

        if "state.fence" in names:
            try_fence("state.fence", lambda x: x["fences"])
        ents = [f for f in names if re.fullmatch(r"state\.fence\.\d+-[0-9a-f]+", f)]
        for f in sorted(ents, key=lambda x: (int(x.split(".")[2].split("-")[0]), x)):
            try_fence(f, lambda x: [x["fence"]])
        gens = [int(f[11:]) for f in names if re.fullmatch(r"state\.lock\.\d+", f)]
        top = None
        if gens:
            g = max(gens)
            try:
                b = json.loads(read("state.lock.%d" % g))
                if b is None:
                    raise TypeError("null has no members")  # the reference reads b.st: a TypeError, so the record is unreadable
                top = {"g": g}
                if isinstance(b, dict) and b.get("st") is not None:
                    top["st"] = b["st"]
                for k in ("recovering", "recoveredFrom"):
                    if isinstance(b, dict) and k in b:
                        top[k] = b[k]
            except Exception:  # noqa: BLE001
                top = {"g": g, "st": "unreadable"}
        keep = [f for f in names if not f.startswith("state.lock.tmp-") and not f.startswith("state.probe-") and ".tmp-" not in f]
        return {"t": "dir", "files": [norm_name(f) for f in keep], "journal": read("state.journal"), "head": read("state.head"), "fences": fences, "top": top}

    def so(v):
        if v == "$HOST":
            return host
        if v == "$PID":
            return pid
        if isinstance(v, list):
            return [so(x) for x in v]
        if isinstance(v, dict):
            return {k: so(x) for k, x in v.items()}
        return v

    out = []
    try:
        for f, t in (sc.get("files") or {}).items():
            put(f, t)
        for st in sc["steps"]:
            if st["t"] == "write":
                put(st["file"], st["text"])
                out.append(None)
            elif st["t"] == "dir":
                out.append(snapshot())
            elif st["t"] == "recover":
                o = so(st.get("opts") or {})
                kw = {"dir": d, "force": True}
                if "force" in o:
                    kw["force"] = o["force"]
                if "expectedHolder" in o:
                    kw["expected_holder"] = o["expectedHolder"]
                if "legacyLock" in o:
                    kw["legacy_lock"] = o["legacyLock"]
                try:
                    r = recover_durable_state(**kw)
                    ok = {"released": r["released"], "reason": r["reason"]}
                    if "lock_file" in r:
                        ok["lockFile"] = norm(r["lock_file"])
                    out.append({"ok": ok})
                except DurableStateError as e:
                    out.append(err(e))
            elif st["t"] == "open":
                op = st.get("opts") or {}
                clock = [1000]

                def now():
                    clock[0] += 1
                    return clock[0] - 1

                kw = {"dir": op["dir"] if "dir" in op else d, "now": now}
                if "hmacKey" in op:
                    kw["hmac_key"] = hashlib.sha256(op["hmacKey"].encode()).digest()
                if "hmacKeyBytes" in op:
                    kw["hmac_key"] = bytes(op["hmacKeyBytes"])
                for a, b in (("recoverFromCorruption", "recover_from_corruption"), ("lockTimeoutMs", "lock_timeout_ms"), ("compactEvery", "compact_every"), ("maxValueBytes", "max_value_bytes")):
                    if a in op:
                        kw[b] = op[a]
                try:
                    h = open_durable_state(**kw)
                except DurableStateError as e:
                    out.append(err(e))
                    continue
                res = []
                saved = {}
                undef = {"$undef": True}
                for x in st.get("ops") or []:
                    try:
                        o = x["op"]
                        if o == "set":
                            h.set(x["key"], x["value"])
                            v = None
                        elif o == "get":
                            r = h.get(x["key"])
                            v = undef if r is None and x["key"] not in h._load()["state"] else r
                        elif o == "keys":
                            v = h.keys()
                        elif o == "verify":
                            v = h.verify()
                        elif o == "position":
                            v = h.position()
                        elif o == "update":
                            arg = x.get("arg")
                            fn = {
                                "append": lambda p: (p or []) + [arg],
                                "max": lambda p: arg if (p is None or arg > p) else None,
                                "noop": lambda p: None,
                                "same": lambda p: p,
                                "set": lambda p: arg,
                            }[x["kind"]]
                            r = h.update(x["key"], fn)
                            v = undef if r is None and x["key"] not in h._load()["state"] else r
                        elif o == "fs":
                            put(x["file"], x["text"])
                            v = None
                        elif o == "save":
                            saved[x["name"]] = (read("state.journal"), read("state.head"))
                            v = None
                        elif o == "restore":
                            j, hd = saved[x["name"]]
                            put("state.journal", j)
                            put("state.head", hd)
                            v = None
                        else:
                            raise AssertionError("unknown op " + o)
                        res.append({"ok": v})
                    except DurableStateError as e:
                        res.append(err(e))
                out.append({"ok": {"recovered": h.recovered, "ops": res}})
            else:
                raise AssertionError("unknown step " + st["t"])
        out.append(snapshot())
        return out
    finally:
        shutil.rmtree(d, ignore_errors=True)


def test_corpus_is_the_full_oracle():
    assert CORPUS["count"] == len(CORPUS["cases"]) and CORPUS["count"] > 200


@pytest.mark.parametrize("case", CORPUS["cases"], ids=lambda c: c["name"])
def test_scenario_matches_the_reference(case):
    assert _scenario(case["args"][0]) == case["out"]
