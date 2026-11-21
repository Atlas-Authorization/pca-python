"""The proved goal kernel (the TypeScript reference is @atlasauth/pca-goal `compiler` over @atlasauth/pca-verified-core `goalCall`).

typecheck / compile_goal / decide_goal / decide_policy / render_tape run the Dafny-proved goal compiler (formal/dafny/Goal.dfy), compiled
to Python with the pinned Dafny by formal/dafny/build-native.sh into `atlas_pca/goal_kernel_gen/`. No decision logic lives in this file:
it converts token tapes to the extracted code's tokens and back. No Dafny value crosses this boundary.

When the extraction is not present (a source tree before CI committed it) every call raises GoalKernelUnavailable: there is no fallback."""
import importlib
import os
import sys
import threading
from typing import Any, Dict, List, Optional

from .goal_codec import IrError, decode_policy, encode_act, encode_goal, encode_hist, encode_ontology
from .goal_compiler import policy_digest
from .goal_review import ReviewKernel

__all__ = [
    "GoalKernelUnavailable", "GEN_DIR", "available", "kernel_call", "tape_to_text", "tape_from_text", "typecheck", "compile_goal",
    "decide_goal", "decide_policy", "render_tape", "proved_kernel",
]

GEN_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "goal_kernel_gen")
_OPS = ("typecheck", "compile", "decideg", "decidep", "render")
_MAX_SAFE = 9007199254740991


class GoalKernelUnavailable(RuntimeError):
    def __init__(self, cause: Any):
        super().__init__("pca-goal: the extracted goal kernel is missing from atlas_pca/goal_kernel_gen "
                         "(formal/dafny/build-native.sh py produces it): %s" % (cause,))


_lock = threading.Lock()
_mods: Optional[tuple] = None


def _load() -> tuple:
    global _mods
    if _mods is not None:
        return _mods
    with _lock:
        if _mods is None:
            if not os.path.isfile(os.path.join(GEN_DIR, "GoalApi.py")):
                raise GoalKernelUnavailable("no GoalApi.py")
            # the extraction's modules import each other as atlas_pca.goal_kernel_gen.<name> (rewritten by build-native.sh py)
            try:
                _mods = (importlib.import_module(__package__ + ".goal_kernel_gen._dafny"),
                         importlib.import_module(__package__ + ".goal_kernel_gen.GoalApi").default__)
            except Exception as e:  # noqa: BLE001 - any import failure means the kernel is unusable
                raise GoalKernelUnavailable(e)
    return _mods
    with _lock:
        if _mods is None:
            if not os.path.isfile(os.path.join(GEN_DIR, "GoalApi.py")):
                raise GoalKernelUnavailable("no GoalApi.py")
            # shortcut: the generated modules import each other by top-level name (GoalApi, GoalIr, _dafny, ...), so their directory
            # goes on sys.path; move to a vendored package with relative imports if another Dafny extraction is ever loaded alongside.
            if GEN_DIR not in sys.path:
                sys.path.append(GEN_DIR)
            try:
                _mods = (importlib.import_module("_dafny"), importlib.import_module("GoalApi").default__)
            except Exception as e:  # noqa: BLE001 - any import failure means the kernel is unusable
                raise GoalKernelUnavailable(e)
    return _mods


def available() -> bool:
    try:
        _load()
        return True
    except GoalKernelUnavailable:
        return False


def _ival(v: Any) -> int:
    if isinstance(v, float) and v.is_integer():
        v = int(v)
    if isinstance(v, bool) or not isinstance(v, int) or abs(v) > _MAX_SAFE:
        raise IrError("goal tape: %r is not a safe integer" % (v,))
    return v


def _to_dafny(tape: List[Any]) -> Any:
    D, F = _load()
    seq_of = getattr(D, "SeqWithoutIsStrInference", D.Seq)
    toks = []
    for t in tape:
        if not isinstance(t, (list, tuple)) or len(t) != 2:
            raise IrError("goal tape: token expected")
        tag, v = t
        if tag == "k":
            toks.append(F.MkKw(_ival(v)))
        elif tag == "i":
            toks.append(F.MkI(_ival(v)))
        elif tag == "s":
            if not isinstance(v, str):
                raise IrError("goal tape: string token expected")
            toks.append(F.MkS(seq_of([D.CodePoint(c) for c in v])))
        else:
            raise IrError("goal tape: unknown token tag %r" % (tag,))
    return D.Seq(toks)


def _cp(c: Any) -> str:
    return chr(ord(c)) if isinstance(c, str) else chr(int(c))


def _from_dafny(seq: Any) -> List[list]:
    _, F = _load()
    out: List[list] = []
    for i in range(len(seq)):
        t = seq[i]
        kind = F.TokKind(t)
        if kind == 0:
            out.append(["k", int(F.TokKw(t))])
        elif kind == 1:
            out.append(["i", int(F.TokInt(t))])
        else:
            s = F.TokStr(t)
            out.append(["s", "".join(_cp(s[j]) for j in range(len(s)))])
    return out


_STACK_BYTES = 512 * 1024 * 1024
_RECURSION = 1_000_000
_stack_lock = threading.Lock()


_rec_users = 0
_rec_saved = 0


def _set_big_stack() -> int:
    """Raise the new-thread stack size to the largest of 512 MiB down to 16 MiB the platform accepts (Windows refuses 512 MiB); returns the old size."""
    size = _STACK_BYTES
    while True:
        try:
            return threading.stack_size(size)
        except ValueError:
            if size <= 16 * 1024 * 1024:
                raise
            size //= 2


def _on_big_stack(fn: Any) -> Any:
    """Run fn on a thread with a large stack and recursion limit: the generated code recurses (Python's default 1000 frames
    would fail on a long tape or string), the same failure class as the JS runtime's Seq.Concat on a huge sequence."""
    box: List[Any] = [None, None]

    def run() -> None:
        try:
            box[0] = fn()
        except BaseException as e:  # noqa: BLE001 - re-raised on the caller's thread
            box[1] = e

    global _rec_users, _rec_saved
    with _stack_lock:  # threading.stack_size and the recursion limit are process-wide
        old_stack = _set_big_stack()
        if _rec_users == 0:
            _rec_saved = sys.getrecursionlimit()
        _rec_users += 1
        sys.setrecursionlimit(max(_rec_saved, _RECURSION))
        try:
            t = threading.Thread(target=run, name="pca-goal-kernel")
            t.start()
        finally:
            threading.stack_size(old_stack)
    try:
        t.join()
    finally:
        with _stack_lock:  # the raised limit must not outlive the last running kernel call (it leaked into every later test and caller)
            _rec_users -= 1
            if _rec_users == 0:
                sys.setrecursionlimit(_rec_saved)
    if box[1] is not None:
        raise box[1]
    return box[0]


def kernel_call(op: str, goal: List[Any], ont: Optional[List[Any]] = None, act: Optional[List[Any]] = None,
                hist: Optional[List[Any]] = None) -> List[list]:
    """One proved entry point over token tapes (op in typecheck compile decideg decidep render). First output token: i0 ok,
    i1 rejected with reasons, i9 malformed input."""
    if op not in _OPS:
        raise ValueError("goal kernel: unknown op %r" % (op,))
    return _on_big_stack(lambda: _kernel_call(op, goal, ont, act, hist))


def _kernel_call(op: str, goal: List[Any], ont: Optional[List[Any]], act: Optional[List[Any]], hist: Optional[List[Any]]) -> List[list]:
    _, F = _load()
    g, o = _to_dafny(goal), _to_dafny(ont or [])
    if op == "typecheck":
        return _from_dafny(F.TypecheckT(g, o))
    if op == "compile":
        return _from_dafny(F.CompileT(g, o))
    if op == "render":
        return _from_dafny(F.RenderT(g))
    a, h = _to_dafny(act or []), _to_dafny(hist or [])
    return _from_dafny((F.DecideGoalT if op == "decideg" else F.DecidePolicyT)(g, o, a, h))


def tape_to_text(tape: List[Any]) -> str:
    """Tape -> harness text (kN, iN, s<hex>.<hex>...), the case syntax of the differential harness and the kernel corpus."""
    parts = []
    for tag, v in tape:
        parts.append("s" + ".".join("%x" % ord(c) for c in v) if tag == "s" else "%s%d" % (tag, v))
    return " ".join(parts)


def tape_from_text(s: str) -> List[list]:
    out: List[list] = []
    for x in s.split(" "):
        if not x:
            continue
        b = x[1:]
        if x[0] in ("k", "i"):
            out.append([x[0], int(b)])
        elif x[0] == "s":
            out.append(["s", "".join(chr(int(h, 16)) for h in b.split(".")) if b else ""])
        else:
            raise IrError("goal tape text: bad token %r" % (x,))
    return out


# ---- the typed front door (compiler.ts) ------------------------------------------------------------------------------------------

def _first(t: List[list]) -> int:
    if not t or t[0][0] != "i":
        raise IrError("malformed compiler output")
    return t[0][1]


def _reasons(t: List[list]) -> List[str]:
    n = t[1][1] if len(t) > 1 and t[1][0] == "i" else 0
    return [x[1] if x[0] == "s" else "" for x in t[2:2 + n]]


def _decision(n: int) -> str:
    return "allow" if n == 2 else "escalate" if n == 1 else "deny"


def typecheck(goal: Any, ont: Any) -> List[str]:
    """Type reasons of a goal against an ontology; [] = well typed."""
    out = kernel_call("typecheck", encode_goal(goal), encode_ontology(ont))
    s = _first(out)
    if s == 0:
        return []
    if s == 1:
        return _reasons(out)
    raise IrError("compiler rejected the input tape")


def compile_goal(goal: Any, ont: Any) -> Dict[str, Any]:
    """C: Goal -> {ok: True, policy} | {ok: False, reasons}. Ill-typed goals are rejected, never coerced."""
    out = kernel_call("compile", encode_goal(goal), encode_ontology(ont))
    s = _first(out)
    if s == 0:
        return {"ok": True, "policy": decode_policy(out[1:])}
    if s == 1:
        return {"ok": False, "reasons": _reasons(out)}
    raise IrError("compiler rejected the input tape")


def decide_goal(goal: Any, ont: Any, act: Any, hist: Any) -> str:
    """The reference semantics D_G(a, H) (the specification the compiled policy is proved equal to)."""
    out = kernel_call("decideg", encode_goal(goal), encode_ontology(ont), encode_act(act), encode_hist(hist))
    if _first(out) != 0:
        raise IrError("compiler rejected the input tape")
    return _decision(out[1][1])


def decide_policy(goal: Any, ont: Any, act: Any, hist: Any) -> Dict[str, Any]:
    """The compiled policy's decision, the witness of an Allow and the separate checker's verdict on it."""
    out = kernel_call("decidep", encode_goal(goal), encode_ontology(ont), encode_act(act), encode_hist(hist))
    s = _first(out)
    if s == 1:
        return {"ok": False, "reasons": _reasons(out)}
    if s != 0:
        raise IrError("compiler rejected the input tape")
    d = _decision(out[1][1])
    n = out[3][1]
    bids = [x[1] if x[0] == "s" else "" for x in out[4:4 + n]]
    return {"ok": True, "decision": d, "witness": {"gid": out[2][1], "bids": bids} if d == "allow" else None,
            "witnessChecked": out[4 + n][1] == 1}


def render_tape(goal: Any) -> List[list]:
    """The card as a token tape (GoalRender.Render): decode_goal(render_tape(g)) equals g."""
    out = kernel_call("render", encode_goal(goal))
    if _first(out) != 0:
        raise IrError("goal tape rejected")
    return out[1:]


def proved_kernel() -> ReviewKernel:
    """The review kernel of the reference (`provedKernel`): compile, policy digest and the reference decision."""
    return ReviewKernel(compile=compile_goal, policy_digest=policy_digest, decide=decide_goal)

