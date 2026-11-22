import sys
from typing import Callable, Any, TypeVar, NamedTuple
from math import floor
from itertools import count

import atlas_pca.goal_kernel_gen.module_ as module_
import atlas_pca.goal_kernel_gen._dafny as _dafny
import atlas_pca.goal_kernel_gen.System_ as System_
import atlas_pca.goal_kernel_gen.GoalIr as GoalIr
import atlas_pca.goal_kernel_gen.GoalCompile as GoalCompile

# Module: GoalWitness

class default__:
    def  __init__(self):
        pass

    @staticmethod
    def Applicable(cs, gid, verb):
        d_0___accumulator_ = _dafny.SeqWithoutIsStrInference([])
        while True:
            with _dafny.label():
                if (len(cs)) == (0):
                    return (d_0___accumulator_) + (_dafny.SeqWithoutIsStrInference([]))
                elif True:
                    d_0___accumulator_ = (d_0___accumulator_) + ((_dafny.SeqWithoutIsStrInference([((cs)[0]).bid]) if GoalIr.default__.AppliesL(((cs)[0]).sel, gid, verb) else _dafny.SeqWithoutIsStrInference([])))
                    in0_ = _dafny.SeqWithoutIsStrInference((cs)[1::])
                    in1_ = gid
                    in2_ = verb
                    cs = in0_
                    gid = in1_
                    verb = in2_
                    raise _dafny.TailCall()
                break

    @staticmethod
    def FindAllow(ps, ceils, dg, a, h):
        while True:
            with _dafny.label():
                if (len(ps)) == (0):
                    return GoalIr.Option_None()
                elif (GoalCompile.default__.PredDec((ps)[0], ceils, dg, a, h)) == (GoalIr.default__.Allow):
                    return GoalIr.Option_Some((ps)[0])
                elif True:
                    in0_ = _dafny.SeqWithoutIsStrInference((ps)[1::])
                    in1_ = ceils
                    in2_ = dg
                    in3_ = a
                    in4_ = h
                    ps = in0_
                    ceils = in1_
                    dg = in2_
                    a = in3_
                    h = in4_
                    raise _dafny.TailCall()
                break

    @staticmethod
    def DecideW(p, a, h):
        d_0_d_ = GoalCompile.default__.DP(p, a, h)
        if (d_0_d_) == (GoalIr.default__.Allow):
            source0_ = default__.FindAllow((p).preds, (p).ceils, (p).deleg, a, h)
            if True:
                if source0_.is_Some:
                    d_1_pr_ = source0_.v
                    return (GoalIr.default__.Allow, Wit_Wit((d_1_pr_).gid, default__.Applicable((p).ceils, (d_1_pr_).gid, (a).verb)))
            if True:
                return (GoalIr.default__.Deny, Wit_Wit(_dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "")), _dafny.SeqWithoutIsStrInference([])))
        elif True:
            return (d_0_d_, Wit_Wit(_dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "")), _dafny.SeqWithoutIsStrInference([])))

    @staticmethod
    def AnyPredAllows(ps, gid, ceils, dg, a, h):
        return ((len(ps)) > (0)) and ((((((ps)[0]).gid) == (gid)) and ((GoalCompile.default__.PredDec((ps)[0], ceils, dg, a, h)) == (GoalIr.default__.Allow))) or (default__.AnyPredAllows(_dafny.SeqWithoutIsStrInference((ps)[1::]), gid, ceils, dg, a, h)))

    @staticmethod
    def VerifyWitness(p, a, h, w):
        return (((((GoalIr.default__.ValidityDec((p).validity, (p).deleg, a, h)) == (GoalIr.default__.Allow)) and ((GoalCompile.default__.ProhDecP((p).prohs, a, h)) == (GoalIr.default__.Allow))) and ((GoalCompile.default__.EscDecP((p).escs, a, h)) == (GoalIr.default__.Allow))) and (default__.AnyPredAllows((p).preds, (w).gid, (p).ceils, (p).deleg, a, h))) and (((w).bids) == (default__.Applicable((p).ceils, (w).gid, (a).verb)))

    @staticmethod
    def PepAllows(d, ans, pd, ad, hh):
        return ((d) == (GoalIr.default__.Allow)) or (((((((d) == (GoalIr.default__.Escalate)) and ((ans).is_Some)) and (((ans).v).sigOk)) and ((((ans).v).policyDigest) == (pd))) and ((((ans).v).actionDigest) == (ad))) and ((((ans).v).histHead) == (hh)))


class Wit:
    @classmethod
    def default(cls, ):
        return lambda: Wit_Wit(_dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "")), _dafny.Seq({}))
    def __ne__(self, __o: object) -> bool:
        return not self.__eq__(__o)
    @property
    def is_Wit(self) -> bool:
        return isinstance(self, Wit_Wit)

class Wit_Wit(Wit, NamedTuple('Wit', [('gid', Any), ('bids', Any)])):
    def __dafnystr__(self) -> str:
        return f'GoalWitness.Wit.Wit({self.gid.VerbatimString(True)}, {_dafny.string_of(self.bids)})'
    def __eq__(self, __o: object) -> bool:
        return isinstance(__o, Wit_Wit) and self.gid == __o.gid and self.bids == __o.bids
    def __hash__(self) -> int:
        return super().__hash__()


class Answer:
    @classmethod
    def default(cls, ):
        return lambda: Answer_Answer(False, _dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "")), _dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "")), _dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "")))
    def __ne__(self, __o: object) -> bool:
        return not self.__eq__(__o)
    @property
    def is_Answer(self) -> bool:
        return isinstance(self, Answer_Answer)

class Answer_Answer(Answer, NamedTuple('Answer', [('sigOk', Any), ('policyDigest', Any), ('actionDigest', Any), ('histHead', Any)])):
    def __dafnystr__(self) -> str:
        return f'GoalWitness.Answer.Answer({_dafny.string_of(self.sigOk)}, {self.policyDigest.VerbatimString(True)}, {self.actionDigest.VerbatimString(True)}, {self.histHead.VerbatimString(True)})'
    def __eq__(self, __o: object) -> bool:
        return isinstance(__o, Answer_Answer) and self.sigOk == __o.sigOk and self.policyDigest == __o.policyDigest and self.actionDigest == __o.actionDigest and self.histHead == __o.histHead
    def __hash__(self) -> int:
        return super().__hash__()

