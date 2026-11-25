import sys
from typing import Callable, Any, TypeVar, NamedTuple
from math import floor
from itertools import count

import atlas_pca.goal_kernel_gen.module_ as module_
import atlas_pca.goal_kernel_gen._dafny as _dafny
import atlas_pca.goal_kernel_gen.System_ as System_
import atlas_pca.goal_kernel_gen.GoalIr as GoalIr

# Module: GoalCompile

class default__:
    def  __init__(self):
        pass

    @staticmethod
    def EvalN(c, a, h):
        source0_ = c
        if True:
            if source0_.is_NTrue:
                return GoalIr.default__.KT
        if True:
            if source0_.is_NFalse:
                return GoalIr.default__.KF
        if True:
            if source0_.is_NAtom:
                d_0_op_ = source0_.op
                d_1_l_ = source0_.l
                d_2_r_ = source0_.r
                return GoalIr.default__.CmpT(d_0_op_, GoalIr.default__.EvalT(d_1_l_, a, h), GoalIr.default__.EvalT(d_2_r_, a, h))
        if True:
            if source0_.is_NAnd:
                d_3_x_ = source0_.a
                d_4_y_ = source0_.b
                return GoalIr.default__.AndK(default__.EvalN(d_3_x_, a, h), default__.EvalN(d_4_y_, a, h))
        if True:
            d_5_x_ = source0_.a
            d_6_y_ = source0_.b
            return GoalIr.default__.OrK(default__.EvalN(d_5_x_, a, h), default__.EvalN(d_6_y_, a, h))

    @staticmethod
    def Nnf(c, pos):
        source0_ = c
        if True:
            if source0_.is_CTrue:
                if pos:
                    return NC_NTrue()
                elif True:
                    return NC_NFalse()
        if True:
            if source0_.is_Cmp:
                d_0_op_ = source0_.op
                d_1_l_ = source0_.l
                d_2_r_ = source0_.r
                return NC_NAtom((d_0_op_ if pos else GoalIr.default__.NegOp(d_0_op_)), d_1_l_, d_2_r_)
        if True:
            if source0_.is_And:
                d_3_x_ = source0_.a
                d_4_y_ = source0_.b
                if pos:
                    return NC_NAnd(default__.Nnf(d_3_x_, True), default__.Nnf(d_4_y_, True))
                elif True:
                    return NC_NOr(default__.Nnf(d_3_x_, False), default__.Nnf(d_4_y_, False))
        if True:
            if source0_.is_Or:
                d_5_x_ = source0_.a
                d_6_y_ = source0_.b
                if pos:
                    return NC_NOr(default__.Nnf(d_5_x_, True), default__.Nnf(d_6_y_, True))
                elif True:
                    return NC_NAnd(default__.Nnf(d_5_x_, False), default__.Nnf(d_6_y_, False))
        if True:
            d_7_x_ = source0_.c
            return default__.Nnf(d_7_x_, not(pos))

    @staticmethod
    def ProhOneP(p, a, h):
        d_0_m_ = GoalIr.default__.AndK(GoalIr.default__.B2T(((a).verb) in ((p).verbs)), GoalIr.default__.AndK(GoalIr.default__.B2T(GoalIr.default__.ResOk((p).res, (a).res)), default__.EvalN((p).cond, a, h)))
        if (d_0_m_) == (GoalIr.default__.KT):
            return GoalIr.default__.Deny
        elif (d_0_m_) == (GoalIr.default__.KU):
            return GoalIr.default__.Escalate
        elif True:
            return GoalIr.default__.Allow

    @staticmethod
    def ProhDecP(ps, a, h):
        if (len(ps)) == (0):
            return GoalIr.default__.Allow
        elif True:
            return GoalIr.default__.MeetD(default__.ProhOneP((ps)[0], a, h), default__.ProhDecP(_dafny.SeqWithoutIsStrInference((ps)[1::]), a, h))

    @staticmethod
    def EscDecP(cs, a, h):
        if (len(cs)) == (0):
            return GoalIr.default__.Allow
        elif True:
            return GoalIr.default__.MeetD(GoalIr.default__.EscOne(default__.EvalN((cs)[0], a, h)), default__.EscDecP(_dafny.SeqWithoutIsStrInference((cs)[1::]), a, h))

    @staticmethod
    def CeilOne(c, gid, a, h):
        if GoalIr.default__.AppliesL((c).sel, gid, (a).verb):
            return GoalIr.default__.BoundStat((c).core, (c).sel, a, h)
        elif True:
            return GoalIr.default__.Allow

    @staticmethod
    def CeilsDecP(cs, gid, a, h):
        if (len(cs)) == (0):
            return GoalIr.default__.Allow
        elif True:
            return GoalIr.default__.MeetD(default__.CeilOne((cs)[0], gid, a, h), default__.CeilsDecP(_dafny.SeqWithoutIsStrInference((cs)[1::]), gid, a, h))

    @staticmethod
    def PredMatch(p, dg, a, h):
        return GoalIr.default__.AndK(GoalIr.default__.B2T((((a).verb) == ((p).verb)) and (GoalIr.default__.DelegOk(dg, (p).gid, a))), GoalIr.default__.AndK(GoalIr.default__.B2T(GoalIr.default__.ResOk((p).res, (a).res)), default__.EvalN((p).cond, a, h)))

    @staticmethod
    def PredDec(p, ceils, dg, a, h):
        return GoalIr.default__.MeetD(GoalIr.default__.DecOfTri(default__.PredMatch(p, dg, a, h)), default__.CeilsDecP(ceils, (p).gid, a, h))

    @staticmethod
    def PredsDecP(ps, ceils, dg, a, h):
        if (len(ps)) == (0):
            return GoalIr.default__.Deny
        elif True:
            return GoalIr.default__.JoinD(default__.PredDec((ps)[0], ceils, dg, a, h), default__.PredsDecP(_dafny.SeqWithoutIsStrInference((ps)[1::]), ceils, dg, a, h))

    @staticmethod
    def DP(p, a, h):
        return GoalIr.default__.MeetD(GoalIr.default__.ValidityDec((p).validity, (p).deleg, a, h), GoalIr.default__.MeetD(default__.ProhDecP((p).prohs, a, h), GoalIr.default__.MeetD(default__.EscDecP((p).escs, a, h), default__.PredsDecP((p).preds, (p).ceils, (p).deleg, a, h))))

    @staticmethod
    def LowerGrants(ont, gs):
        d_0___accumulator_ = _dafny.SeqWithoutIsStrInference([])
        while True:
            with _dafny.label():
                if (len(gs)) == (0):
                    return (d_0___accumulator_) + (_dafny.SeqWithoutIsStrInference([]))
                elif True:
                    d_0___accumulator_ = (d_0___accumulator_) + (_dafny.SeqWithoutIsStrInference([LPred_LPred(((gs)[0]).gid, ((gs)[0]).verb, GoalIr.default__.ResolveSel(ont, ((gs)[0]).res), default__.Nnf(((gs)[0]).cond, True))]))
                    in0_ = ont
                    in1_ = _dafny.SeqWithoutIsStrInference((gs)[1::])
                    ont = in0_
                    gs = in1_
                    raise _dafny.TailCall()
                break

    @staticmethod
    def LowerProhs(ont, ps):
        d_0___accumulator_ = _dafny.SeqWithoutIsStrInference([])
        while True:
            with _dafny.label():
                if (len(ps)) == (0):
                    return (d_0___accumulator_) + (_dafny.SeqWithoutIsStrInference([]))
                elif True:
                    d_0___accumulator_ = (d_0___accumulator_) + (_dafny.SeqWithoutIsStrInference([LProh_LProh(((ps)[0]).pid, GoalIr.default__.ProhVerbs(ont, ((ps)[0]).target), GoalIr.default__.ResolveSel(ont, ((ps)[0]).res), default__.Nnf(((ps)[0]).cond, True))]))
                    in0_ = ont
                    in1_ = _dafny.SeqWithoutIsStrInference((ps)[1::])
                    ont = in0_
                    ps = in1_
                    raise _dafny.TailCall()
                break

    @staticmethod
    def LowerBounds(ont, bs):
        d_0___accumulator_ = _dafny.SeqWithoutIsStrInference([])
        while True:
            with _dafny.label():
                if (len(bs)) == (0):
                    return (d_0___accumulator_) + (_dafny.SeqWithoutIsStrInference([]))
                elif True:
                    d_0___accumulator_ = (d_0___accumulator_) + (_dafny.SeqWithoutIsStrInference([LCeil_LCeil(((bs)[0]).bid, GoalIr.default__.ResolveBSel(ont, ((bs)[0]).sel), ((bs)[0]).core)]))
                    in0_ = ont
                    in1_ = _dafny.SeqWithoutIsStrInference((bs)[1::])
                    ont = in0_
                    bs = in1_
                    raise _dafny.TailCall()
                break

    @staticmethod
    def LowerEscs(cs):
        d_0___accumulator_ = _dafny.SeqWithoutIsStrInference([])
        while True:
            with _dafny.label():
                if (len(cs)) == (0):
                    return (d_0___accumulator_) + (_dafny.SeqWithoutIsStrInference([]))
                elif True:
                    d_0___accumulator_ = (d_0___accumulator_) + (_dafny.SeqWithoutIsStrInference([default__.Nnf((cs)[0], True)]))
                    in0_ = _dafny.SeqWithoutIsStrInference((cs)[1::])
                    cs = in0_
                    raise _dafny.TailCall()
                break

    @staticmethod
    def Lower(ont, g):
        return Pol_Pol(default__.LowerGrants(ont, (g).grants), default__.LowerProhs(ont, (g).prohibits), default__.LowerBounds(ont, (g).bounds), default__.LowerEscs((g).escalateOn), (g).validity, (g).deleg)

    @staticmethod
    def DependsOn(hs, gid):
        return ((len(hs)) > (0)) and (((((hs)[0]).global_) or ((gid) in (((hs)[0]).affects))) or (default__.DependsOn(_dafny.SeqWithoutIsStrInference((hs)[1::]), gid)))

    @staticmethod
    def StripGrants(hs, gs):
        d_0___accumulator_ = _dafny.SeqWithoutIsStrInference([])
        while True:
            with _dafny.label():
                if (len(gs)) == (0):
                    return (d_0___accumulator_) + (_dafny.SeqWithoutIsStrInference([]))
                elif True:
                    d_0___accumulator_ = (d_0___accumulator_) + ((_dafny.SeqWithoutIsStrInference([]) if default__.DependsOn(hs, ((gs)[0]).gid) else _dafny.SeqWithoutIsStrInference([(gs)[0]])))
                    in0_ = hs
                    in1_ = _dafny.SeqWithoutIsStrInference((gs)[1::])
                    hs = in0_
                    gs = in1_
                    raise _dafny.TailCall()
                break

    @staticmethod
    def Strip(g):
        d_0_dt__update__tmp_h0_ = g
        d_1_dt__update_hholes_h0_ = _dafny.SeqWithoutIsStrInference([])
        d_2_dt__update_hgrants_h0_ = default__.StripGrants((g).holes, (g).grants)
        return GoalIr.Goal_Goal((d_0_dt__update__tmp_h0_).v, (d_0_dt__update__tmp_h0_).principal, (d_0_dt__update__tmp_h0_).ontDigest, (d_0_dt__update__tmp_h0_).nlDigest, (d_0_dt__update__tmp_h0_).sources, d_2_dt__update_hgrants_h0_, (d_0_dt__update__tmp_h0_).prohibits, (d_0_dt__update__tmp_h0_).bounds, (d_0_dt__update__tmp_h0_).validity, (d_0_dt__update__tmp_h0_).deleg, (d_0_dt__update__tmp_h0_).escalateOn, (d_0_dt__update__tmp_h0_).wildcardAck, d_1_dt__update_hholes_h0_)

    @staticmethod
    def BadGrants(ont, g, gs):
        d_0___accumulator_ = _dafny.SeqWithoutIsStrInference([])
        while True:
            with _dafny.label():
                if (len(gs)) == (0):
                    return (d_0___accumulator_) + (_dafny.SeqWithoutIsStrInference([]))
                elif True:
                    d_0___accumulator_ = (d_0___accumulator_) + ((_dafny.SeqWithoutIsStrInference([]) if GoalIr.default__.GrantOk(ont, g, (gs)[0]) else _dafny.SeqWithoutIsStrInference([((gs)[0]).gid])))
                    in0_ = ont
                    in1_ = g
                    in2_ = _dafny.SeqWithoutIsStrInference((gs)[1::])
                    ont = in0_
                    g = in1_
                    gs = in2_
                    raise _dafny.TailCall()
                break

    @staticmethod
    def BadProhibits(ont, ps):
        d_0___accumulator_ = _dafny.SeqWithoutIsStrInference([])
        while True:
            with _dafny.label():
                if (len(ps)) == (0):
                    return (d_0___accumulator_) + (_dafny.SeqWithoutIsStrInference([]))
                elif True:
                    d_0___accumulator_ = (d_0___accumulator_) + ((_dafny.SeqWithoutIsStrInference([]) if GoalIr.default__.ProhibitOk(ont, (ps)[0]) else _dafny.SeqWithoutIsStrInference([((ps)[0]).pid])))
                    in0_ = ont
                    in1_ = _dafny.SeqWithoutIsStrInference((ps)[1::])
                    ont = in0_
                    ps = in1_
                    raise _dafny.TailCall()
                break

    @staticmethod
    def BadBounds(ont, g, bs):
        d_0___accumulator_ = _dafny.SeqWithoutIsStrInference([])
        while True:
            with _dafny.label():
                if (len(bs)) == (0):
                    return (d_0___accumulator_) + (_dafny.SeqWithoutIsStrInference([]))
                elif True:
                    d_0___accumulator_ = (d_0___accumulator_) + ((_dafny.SeqWithoutIsStrInference([]) if GoalIr.default__.BoundOk(ont, g, (bs)[0]) else _dafny.SeqWithoutIsStrInference([((bs)[0]).bid])))
                    in0_ = ont
                    in1_ = g
                    in2_ = _dafny.SeqWithoutIsStrInference((bs)[1::])
                    ont = in0_
                    g = in1_
                    bs = in2_
                    raise _dafny.TailCall()
                break

    @staticmethod
    def BadHoles(g, hs):
        d_0___accumulator_ = _dafny.SeqWithoutIsStrInference([])
        while True:
            with _dafny.label():
                if (len(hs)) == (0):
                    return (d_0___accumulator_) + (_dafny.SeqWithoutIsStrInference([]))
                elif True:
                    d_0___accumulator_ = (d_0___accumulator_) + ((_dafny.SeqWithoutIsStrInference([]) if GoalIr.default__.HoleOk(g, (hs)[0]) else _dafny.SeqWithoutIsStrInference([((hs)[0]).hid])))
                    in0_ = g
                    in1_ = _dafny.SeqWithoutIsStrInference((hs)[1::])
                    g = in0_
                    hs = in1_
                    raise _dafny.TailCall()
                break

    @staticmethod
    def TypeReasons(ont, g):
        return (((((((_dafny.SeqWithoutIsStrInference([]) if GoalIr.default__.Sorted4(g) else _dafny.SeqWithoutIsStrInference([_dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "not_canonical_order"))]))) + ((_dafny.SeqWithoutIsStrInference([]) if (len(default__.BadGrants(ont, g, (g).grants))) == (0) else _dafny.SeqWithoutIsStrInference([_dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "ill_typed_grant"))])))) + ((_dafny.SeqWithoutIsStrInference([]) if (len(default__.BadProhibits(ont, (g).prohibits))) == (0) else _dafny.SeqWithoutIsStrInference([_dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "ill_typed_prohibit"))])))) + ((_dafny.SeqWithoutIsStrInference([]) if (len(default__.BadBounds(ont, g, (g).bounds))) == (0) else _dafny.SeqWithoutIsStrInference([_dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "ill_typed_bound"))])))) + ((_dafny.SeqWithoutIsStrInference([]) if GoalIr.default__.EscsTyped(ont, g) else _dafny.SeqWithoutIsStrInference([_dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "ill_typed_escalation"))])))) + ((_dafny.SeqWithoutIsStrInference([]) if GoalIr.default__.ValidityOk((g).validity, (g).deleg, g) else _dafny.SeqWithoutIsStrInference([_dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "bad_validity_or_delegation"))])))) + ((_dafny.SeqWithoutIsStrInference([]) if (len(default__.BadHoles(g, (g).holes))) == (0) else _dafny.SeqWithoutIsStrInference([_dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "bad_hole"))])))

    @staticmethod
    def Compile(ont, g):
        d_0_rs_ = default__.TypeReasons(ont, g)
        if (len(d_0_rs_)) > (0):
            return CResult_CEscalate(d_0_rs_)
        elif True:
            return CResult_Compiled(default__.Lower(ont, default__.Strip(g)))

    @staticmethod
    def ResNarrows(p2, p1):
        def lambda0_(forall_var_0_):
            d_0_i_: int = forall_var_0_
            return not (((0) <= (d_0_i_)) and ((d_0_i_) < (len((p2).ids)))) or ((((p2).ids)[d_0_i_]) in ((p1).ids))

        return ((p1).is_PStar) or ((((p2).is_PSet) and ((p1).is_PSet)) and (_dafny.quantifier(_dafny.IntegerRange(0, len((p2).ids)), True, lambda0_)))

    @staticmethod
    def CondNarrows(c2, c1):
        return ((c2) == (c1)) or (((c2).is_And) and ((((c2).a) == (c1)) or (((c2).b) == (c1))))

    @staticmethod
    def GrantNarrows(ont, g2, g1):
        return (((((g2).gid) == ((g1).gid)) and (((g2).verb) == ((g1).verb))) and (default__.ResNarrows(GoalIr.default__.ResolveSel(ont, (g2).res), GoalIr.default__.ResolveSel(ont, (g1).res)))) and (default__.CondNarrows((g2).cond, (g1).cond))

    @staticmethod
    def SubsetOf(xs, ys):
        def lambda0_(forall_var_0_):
            d_0_i_: int = forall_var_0_
            return not (((0) <= (d_0_i_)) and ((d_0_i_) < (len(xs)))) or (((xs)[d_0_i_]) in (ys))

        return _dafny.quantifier(_dafny.IntegerRange(0, len(xs)), True, lambda0_)

    @staticmethod
    def Refines(ont, g2, g1):
        def lambda0_(forall_var_0_):
            def lambda1_(exists_var_0_):
                d_1_j_: int = exists_var_0_
                return (((0) <= (d_1_j_)) and ((d_1_j_) < (len((g1).grants)))) and (default__.GrantNarrows(ont, ((g2).grants)[d_0_i_], ((g1).grants)[d_1_j_]))

            d_0_i_: int = forall_var_0_
            return not (((0) <= (d_0_i_)) and ((d_0_i_) < (len((g2).grants)))) or (_dafny.quantifier(_dafny.IntegerRange(0, len((g1).grants)), False, lambda1_))

        return ((((((((_dafny.quantifier(_dafny.IntegerRange(0, len((g2).grants)), True, lambda0_)) and (default__.SubsetOf((g1).prohibits, (g2).prohibits))) and (default__.SubsetOf((g1).bounds, (g2).bounds))) and (default__.SubsetOf((g1).escalateOn, (g2).escalateOn))) and ((((g2).validity).notBefore) >= (((g1).validity).notBefore))) and ((((g2).validity).notAfter) <= (((g1).validity).notAfter))) and (((((g1).validity).maxIdle) <= (0)) or (((0) < (((g2).validity).maxIdle)) and ((((g2).validity).maxIdle) <= (((g1).validity).maxIdle))))) and ((((g2).deleg).maxDepth) <= (((g1).deleg).maxDepth))) and (default__.SubsetOf(((g2).deleg).mayTouch, ((g1).deleg).mayTouch))

    @staticmethod
    def BoundOne(ont, b, gid, a, h):
        d_0_s_ = GoalIr.default__.ResolveBSel(ont, (b).sel)
        if GoalIr.default__.AppliesL(d_0_s_, gid, (a).verb):
            return GoalIr.default__.BoundStat((b).core, d_0_s_, a, h)
        elif True:
            return GoalIr.default__.Allow

    @staticmethod
    def Refines2V(g2, g1):
        return ((((((g2).validity).notBefore) >= (((g1).validity).notBefore)) and ((((g2).validity).notAfter) <= (((g1).validity).notAfter))) and (((((g1).validity).maxIdle) <= (0)) or (((0) < (((g2).validity).maxIdle)) and ((((g2).validity).maxIdle) <= (((g1).validity).maxIdle))))) and ((((g2).deleg).maxDepth) <= (((g1).deleg).maxDepth))


class NC:
    @classmethod
    def default(cls, ):
        return lambda: NC_NTrue()
    def __ne__(self, __o: object) -> bool:
        return not self.__eq__(__o)
    @property
    def is_NTrue(self) -> bool:
        return isinstance(self, NC_NTrue)
    @property
    def is_NFalse(self) -> bool:
        return isinstance(self, NC_NFalse)
    @property
    def is_NAtom(self) -> bool:
        return isinstance(self, NC_NAtom)
    @property
    def is_NAnd(self) -> bool:
        return isinstance(self, NC_NAnd)
    @property
    def is_NOr(self) -> bool:
        return isinstance(self, NC_NOr)

class NC_NTrue(NC, NamedTuple('NTrue', [])):
    def __dafnystr__(self) -> str:
        return f'GoalCompile.NC.NTrue'
    def __eq__(self, __o: object) -> bool:
        return isinstance(__o, NC_NTrue)
    def __hash__(self) -> int:
        return super().__hash__()

class NC_NFalse(NC, NamedTuple('NFalse', [])):
    def __dafnystr__(self) -> str:
        return f'GoalCompile.NC.NFalse'
    def __eq__(self, __o: object) -> bool:
        return isinstance(__o, NC_NFalse)
    def __hash__(self) -> int:
        return super().__hash__()

class NC_NAtom(NC, NamedTuple('NAtom', [('op', Any), ('l', Any), ('r', Any)])):
    def __dafnystr__(self) -> str:
        return f'GoalCompile.NC.NAtom({_dafny.string_of(self.op)}, {_dafny.string_of(self.l)}, {_dafny.string_of(self.r)})'
    def __eq__(self, __o: object) -> bool:
        return isinstance(__o, NC_NAtom) and self.op == __o.op and self.l == __o.l and self.r == __o.r
    def __hash__(self) -> int:
        return super().__hash__()

class NC_NAnd(NC, NamedTuple('NAnd', [('a', Any), ('b', Any)])):
    def __dafnystr__(self) -> str:
        return f'GoalCompile.NC.NAnd({_dafny.string_of(self.a)}, {_dafny.string_of(self.b)})'
    def __eq__(self, __o: object) -> bool:
        return isinstance(__o, NC_NAnd) and self.a == __o.a and self.b == __o.b
    def __hash__(self) -> int:
        return super().__hash__()

class NC_NOr(NC, NamedTuple('NOr', [('a', Any), ('b', Any)])):
    def __dafnystr__(self) -> str:
        return f'GoalCompile.NC.NOr({_dafny.string_of(self.a)}, {_dafny.string_of(self.b)})'
    def __eq__(self, __o: object) -> bool:
        return isinstance(__o, NC_NOr) and self.a == __o.a and self.b == __o.b
    def __hash__(self) -> int:
        return super().__hash__()


class LPred:
    @classmethod
    def default(cls, ):
        return lambda: LPred_LPred(_dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "")), _dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "")), GoalIr.ResPat.default()(), NC.default()())
    def __ne__(self, __o: object) -> bool:
        return not self.__eq__(__o)
    @property
    def is_LPred(self) -> bool:
        return isinstance(self, LPred_LPred)

class LPred_LPred(LPred, NamedTuple('LPred', [('gid', Any), ('verb', Any), ('res', Any), ('cond', Any)])):
    def __dafnystr__(self) -> str:
        return f'GoalCompile.LPred.LPred({self.gid.VerbatimString(True)}, {self.verb.VerbatimString(True)}, {_dafny.string_of(self.res)}, {_dafny.string_of(self.cond)})'
    def __eq__(self, __o: object) -> bool:
        return isinstance(__o, LPred_LPred) and self.gid == __o.gid and self.verb == __o.verb and self.res == __o.res and self.cond == __o.cond
    def __hash__(self) -> int:
        return super().__hash__()


class LProh:
    @classmethod
    def default(cls, ):
        return lambda: LProh_LProh(_dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "")), _dafny.Seq({}), GoalIr.ResPat.default()(), NC.default()())
    def __ne__(self, __o: object) -> bool:
        return not self.__eq__(__o)
    @property
    def is_LProh(self) -> bool:
        return isinstance(self, LProh_LProh)

class LProh_LProh(LProh, NamedTuple('LProh', [('pid', Any), ('verbs', Any), ('res', Any), ('cond', Any)])):
    def __dafnystr__(self) -> str:
        return f'GoalCompile.LProh.LProh({self.pid.VerbatimString(True)}, {_dafny.string_of(self.verbs)}, {_dafny.string_of(self.res)}, {_dafny.string_of(self.cond)})'
    def __eq__(self, __o: object) -> bool:
        return isinstance(__o, LProh_LProh) and self.pid == __o.pid and self.verbs == __o.verbs and self.res == __o.res and self.cond == __o.cond
    def __hash__(self) -> int:
        return super().__hash__()


class LCeil:
    @classmethod
    def default(cls, ):
        return lambda: LCeil_LCeil(_dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "")), GoalIr.LSel.default()(), GoalIr.BCore.default()())
    def __ne__(self, __o: object) -> bool:
        return not self.__eq__(__o)
    @property
    def is_LCeil(self) -> bool:
        return isinstance(self, LCeil_LCeil)

class LCeil_LCeil(LCeil, NamedTuple('LCeil', [('bid', Any), ('sel', Any), ('core', Any)])):
    def __dafnystr__(self) -> str:
        return f'GoalCompile.LCeil.LCeil({self.bid.VerbatimString(True)}, {_dafny.string_of(self.sel)}, {_dafny.string_of(self.core)})'
    def __eq__(self, __o: object) -> bool:
        return isinstance(__o, LCeil_LCeil) and self.bid == __o.bid and self.sel == __o.sel and self.core == __o.core
    def __hash__(self) -> int:
        return super().__hash__()


class Pol:
    @classmethod
    def default(cls, ):
        return lambda: Pol_Pol(_dafny.Seq({}), _dafny.Seq({}), _dafny.Seq({}), _dafny.Seq({}), GoalIr.Validity.default()(), GoalIr.Delegation.default()())
    def __ne__(self, __o: object) -> bool:
        return not self.__eq__(__o)
    @property
    def is_Pol(self) -> bool:
        return isinstance(self, Pol_Pol)

class Pol_Pol(Pol, NamedTuple('Pol', [('preds', Any), ('prohs', Any), ('ceils', Any), ('escs', Any), ('validity', Any), ('deleg', Any)])):
    def __dafnystr__(self) -> str:
        return f'GoalCompile.Pol.Pol({_dafny.string_of(self.preds)}, {_dafny.string_of(self.prohs)}, {_dafny.string_of(self.ceils)}, {_dafny.string_of(self.escs)}, {_dafny.string_of(self.validity)}, {_dafny.string_of(self.deleg)})'
    def __eq__(self, __o: object) -> bool:
        return isinstance(__o, Pol_Pol) and self.preds == __o.preds and self.prohs == __o.prohs and self.ceils == __o.ceils and self.escs == __o.escs and self.validity == __o.validity and self.deleg == __o.deleg
    def __hash__(self) -> int:
        return super().__hash__()


class CResult:
    @classmethod
    def default(cls, ):
        return lambda: CResult_Compiled(Pol.default()())
    def __ne__(self, __o: object) -> bool:
        return not self.__eq__(__o)
    @property
    def is_Compiled(self) -> bool:
        return isinstance(self, CResult_Compiled)
    @property
    def is_CEscalate(self) -> bool:
        return isinstance(self, CResult_CEscalate)

class CResult_Compiled(CResult, NamedTuple('Compiled', [('p', Any)])):
    def __dafnystr__(self) -> str:
        return f'GoalCompile.CResult.Compiled({_dafny.string_of(self.p)})'
    def __eq__(self, __o: object) -> bool:
        return isinstance(__o, CResult_Compiled) and self.p == __o.p
    def __hash__(self) -> int:
        return super().__hash__()

class CResult_CEscalate(CResult, NamedTuple('CEscalate', [('reasons', Any)])):
    def __dafnystr__(self) -> str:
        return f'GoalCompile.CResult.CEscalate({_dafny.string_of(self.reasons)})'
    def __eq__(self, __o: object) -> bool:
        return isinstance(__o, CResult_CEscalate) and self.reasons == __o.reasons
    def __hash__(self) -> int:
        return super().__hash__()

