import sys
from typing import Callable, Any, TypeVar, NamedTuple
from math import floor
from itertools import count

import atlas_pca.goal_kernel_gen.module_ as module_
import atlas_pca.goal_kernel_gen._dafny as _dafny
import atlas_pca.goal_kernel_gen.System_ as System_

# Module: GoalIr

class default__:
    def  __init__(self):
        pass

    @staticmethod
    def MeetD(a, b):
        if (a) <= (b):
            return a
        elif True:
            return b

    @staticmethod
    def JoinD(a, b):
        if (a) >= (b):
            return a
        elif True:
            return b

    @staticmethod
    def AndK(a, b):
        if (a) <= (b):
            return a
        elif True:
            return b

    @staticmethod
    def OrK(a, b):
        if (a) >= (b):
            return a
        elif True:
            return b

    @staticmethod
    def NotK(a):
        return (2) - (a)

    @staticmethod
    def B2T(b):
        if b:
            return default__.KT
        elif True:
            return default__.KF

    @staticmethod
    def DecOfTri(t):
        return t

    @staticmethod
    def AtomV(a):
        source0_ = a
        if True:
            if source0_.is_AQ:
                d_0_q_ = source0_.q
                return V_VQ(d_0_q_)
        if True:
            d_1_s_ = source0_.s
            return V_VS(d_1_s_)

    @staticmethod
    def TypeOfV(v):
        source0_ = v
        if True:
            if source0_.is_VQ:
                d_0_q_ = source0_.q
                return Option_Some(Ty_TyQ((d_0_q_).u))
        if True:
            if source0_.is_VS:
                return Option_Some(Ty_TyS())
        if True:
            return Option_None()

    @staticmethod
    def ResOk(p, r):
        source0_ = p
        if True:
            if source0_.is_PStar:
                return True
        if True:
            d_0_ids_ = source0_.ids
            return (r) in (d_0_ids_)

    @staticmethod
    def RelMembers(rels, rel, anchor):
        while True:
            with _dafny.label():
                if (len(rels)) == (0):
                    return _dafny.SeqWithoutIsStrInference([])
                elif ((((rels)[0]).rel) == (rel)) and ((((rels)[0]).anchor) == (anchor)):
                    return ((rels)[0]).members
                elif True:
                    in0_ = _dafny.SeqWithoutIsStrInference((rels)[1::])
                    in1_ = rel
                    in2_ = anchor
                    rels = in0_
                    rel = in1_
                    anchor = in2_
                    raise _dafny.TailCall()
                break

    @staticmethod
    def ResolveSel(ont, s):
        source0_ = s
        if True:
            if source0_.is_Exact:
                d_0_id_ = source0_.id_
                return ResPat_PSet(_dafny.SeqWithoutIsStrInference([d_0_id_]))
        if True:
            if source0_.is_OneOf:
                d_1_ids_ = source0_.ids
                return ResPat_PSet(d_1_ids_)
        if True:
            if source0_.is_Related:
                d_2_rel_ = source0_.rel
                d_3_anchor_ = source0_.anchor
                return ResPat_PSet(default__.RelMembers((ont).rels, d_2_rel_, d_3_anchor_))
        if True:
            if source0_.is_AnyRes:
                return ResPat_PStar()
        if True:
            d_4_ps_ = source0_.parts
            return default__.ResolveParts(ont, d_4_ps_)

    @staticmethod
    def ResolvePart(ont, p):
        source0_ = p
        if True:
            if source0_.is_PartExact:
                d_0_id_ = source0_.id_
                return ResPat_PSet(_dafny.SeqWithoutIsStrInference([d_0_id_]))
        if True:
            if source0_.is_PartOneOf:
                d_1_ids_ = source0_.ids
                return ResPat_PSet(d_1_ids_)
        if True:
            d_2_rel_ = source0_.rel
            d_3_anchor_ = source0_.anchor
            return ResPat_PSet(default__.RelMembers((ont).rels, d_2_rel_, d_3_anchor_))

    @staticmethod
    def FilterIn(a, b):
        d_0___accumulator_ = _dafny.SeqWithoutIsStrInference([])
        while True:
            with _dafny.label():
                if (len(a)) == (0):
                    return (d_0___accumulator_) + (_dafny.SeqWithoutIsStrInference([]))
                elif True:
                    d_0___accumulator_ = (d_0___accumulator_) + ((_dafny.SeqWithoutIsStrInference([(a)[0]]) if ((a)[0]) in (b) else _dafny.SeqWithoutIsStrInference([])))
                    in0_ = _dafny.SeqWithoutIsStrInference((a)[1::])
                    in1_ = b
                    a = in0_
                    b = in1_
                    raise _dafny.TailCall()
                break

    @staticmethod
    def InterPat(x, y):
        source0_ = x
        if True:
            if source0_.is_PStar:
                return y
        if True:
            d_0_a_ = source0_.ids
            source1_ = y
            if True:
                if source1_.is_PStar:
                    return x
            if True:
                d_1_b_ = source1_.ids
                return ResPat_PSet(default__.FilterIn(d_0_a_, d_1_b_))

    @staticmethod
    def ResolveParts(ont, ps):
        if (len(ps)) == (0):
            return ResPat_PStar()
        elif True:
            return default__.InterPat(default__.ResolvePart(ont, (ps)[0]), default__.ResolveParts(ont, _dafny.SeqWithoutIsStrInference((ps)[1::])))

    @staticmethod
    def VerbsOfClass(vs, cls):
        d_0___accumulator_ = _dafny.SeqWithoutIsStrInference([])
        while True:
            with _dafny.label():
                if (len(vs)) == (0):
                    return (d_0___accumulator_) + (_dafny.SeqWithoutIsStrInference([]))
                elif True:
                    d_0___accumulator_ = (d_0___accumulator_) + ((_dafny.SeqWithoutIsStrInference([((vs)[0]).verb]) if (((vs)[0]).cls) == (cls) else _dafny.SeqWithoutIsStrInference([])))
                    in0_ = _dafny.SeqWithoutIsStrInference((vs)[1::])
                    in1_ = cls
                    vs = in0_
                    cls = in1_
                    raise _dafny.TailCall()
                break

    @staticmethod
    def ResolveBSel(ont, s):
        source0_ = s
        if True:
            if source0_.is_SelGids:
                d_0_g_ = source0_.gids
                return LSel_LSel(d_0_g_, _dafny.SeqWithoutIsStrInference([]))
        if True:
            d_1_c_ = source0_.cls
            return LSel_LSel(_dafny.SeqWithoutIsStrInference([]), default__.VerbsOfClass((ont).verbs, d_1_c_))

    @staticmethod
    def ProhVerbs(ont, t):
        source0_ = t
        if True:
            if source0_.is_PVerb:
                d_0_v_ = source0_.verb
                return _dafny.SeqWithoutIsStrInference([d_0_v_])
        if True:
            d_1_c_ = source0_.cls
            return default__.VerbsOfClass((ont).verbs, d_1_c_)

    @staticmethod
    def EqT(x, y):
        source0_ = x
        if True:
            if source0_.is_VQ:
                d_0_p_ = source0_.q
                source1_ = y
                if True:
                    if source1_.is_VQ:
                        d_1_q_ = source1_.q
                        if ((d_0_p_).u) == ((d_1_q_).u):
                            return default__.B2T(((d_0_p_).n) == ((d_1_q_).n))
                        elif True:
                            return default__.KU
                if True:
                    return default__.KU
        if True:
            if source0_.is_VS:
                d_2_s_ = source0_.s
                source2_ = y
                if True:
                    if source2_.is_VS:
                        d_3_t_ = source2_.s
                        return default__.B2T((d_2_s_) == (d_3_t_))
                if True:
                    return default__.KU
        if True:
            return default__.KU

    @staticmethod
    def LtT(x, y):
        source0_ = x
        if True:
            if source0_.is_VQ:
                d_0_p_ = source0_.q
                source1_ = y
                if True:
                    if source1_.is_VQ:
                        d_1_q_ = source1_.q
                        if ((d_0_p_).u) == ((d_1_q_).u):
                            return default__.B2T(((d_0_p_).n) < ((d_1_q_).n))
                        elif True:
                            return default__.KU
                if True:
                    return default__.KU
        if True:
            return default__.KU

    @staticmethod
    def InT(x, items):
        if (len(items)) == (0):
            return default__.KF
        elif True:
            return default__.OrK(default__.EqT(x, default__.AtomV((items)[0])), default__.InT(x, _dafny.SeqWithoutIsStrInference((items)[1::])))

    @staticmethod
    def CmpT(op, x, y):
        if ((x).is_None) or ((y).is_None):
            return default__.KU
        elif True:
            source0_ = op
            if True:
                if source0_.is_Eq:
                    return default__.EqT((x).v, (y).v)
            if True:
                if source0_.is_Ne:
                    return default__.NotK(default__.EqT((x).v, (y).v))
            if True:
                if source0_.is_Lt:
                    return default__.LtT((x).v, (y).v)
            if True:
                if source0_.is_Gte:
                    return default__.NotK(default__.LtT((x).v, (y).v))
            if True:
                if source0_.is_Gt:
                    return default__.LtT((y).v, (x).v)
            if True:
                if source0_.is_Lte:
                    return default__.NotK(default__.LtT((y).v, (x).v))
            if True:
                if source0_.is_In:
                    source1_ = (y).v
                    if True:
                        if source1_.is_VSet:
                            d_0_items_ = source1_.items
                            return default__.InT((x).v, d_0_items_)
                    if True:
                        return default__.KU
            if True:
                def lambda0_():
                    source2_ = (y).v
                    if True:
                        if source2_.is_VSet:
                            d_1_items_ = source2_.items
                            return default__.InT((x).v, d_1_items_)
                    if True:
                        return default__.KU

                return default__.NotK(lambda0_())

    @staticmethod
    def NegOp(op):
        source0_ = op
        if True:
            if source0_.is_Eq:
                return Op_Ne()
        if True:
            if source0_.is_Ne:
                return Op_Eq()
        if True:
            if source0_.is_Lt:
                return Op_Gte()
        if True:
            if source0_.is_Gte:
                return Op_Lt()
        if True:
            if source0_.is_Gt:
                return Op_Lte()
        if True:
            if source0_.is_Lte:
                return Op_Gt()
        if True:
            if source0_.is_In:
                return Op_Nin()
        if True:
            return Op_In()

    @staticmethod
    def EvalT(t, a, h):
        source0_ = t
        if True:
            if source0_.is_Param:
                d_0_p_ = source0_.path
                if (d_0_p_) in ((a).params):
                    return Option_Some(((a).params)[d_0_p_])
                elif True:
                    return Option_None()
        if True:
            if source0_.is_Lit:
                d_1_v_ = source0_.v
                return Option_Some(d_1_v_)
        if True:
            d_2_b_ = source0_.bid
            if (d_2_b_) in ((h).aggs):
                return Option_Some(V_VQ(((h).aggs)[d_2_b_]))
            elif True:
                return Option_None()

    @staticmethod
    def EvalC(c, a, h):
        source0_ = c
        if True:
            if source0_.is_CTrue:
                return default__.KT
        if True:
            if source0_.is_Cmp:
                d_0_op_ = source0_.op
                d_1_l_ = source0_.l
                d_2_r_ = source0_.r
                return default__.CmpT(d_0_op_, default__.EvalT(d_1_l_, a, h), default__.EvalT(d_2_r_, a, h))
        if True:
            if source0_.is_And:
                d_3_x_ = source0_.a
                d_4_y_ = source0_.b
                return default__.AndK(default__.EvalC(d_3_x_, a, h), default__.EvalC(d_4_y_, a, h))
        if True:
            if source0_.is_Or:
                d_5_x_ = source0_.a
                d_6_y_ = source0_.b
                return default__.OrK(default__.EvalC(d_5_x_, a, h), default__.EvalC(d_6_y_, a, h))
        if True:
            d_7_x_ = source0_.c
            return default__.NotK(default__.EvalC(d_7_x_, a, h))

    @staticmethod
    def StrIn(x, s):
        return (x) in (s)

    @staticmethod
    def AppliesL(s, gid, verb):
        return ((gid) in ((s).gids)) or ((verb) in ((s).verbs))

    @staticmethod
    def InScope(sc, a, x):
        source0_ = sc
        if True:
            if source0_.is_SSession:
                return ((a).sess) == ((x).sess)
        if True:
            if source0_.is_SPrincipal:
                return ((a).prin) == ((x).prin)
        if True:
            if source0_.is_SOrg:
                return ((a).org) == ((x).org)
        if True:
            d_0_ag_ = source0_.agents
            return (((a).agent) in (d_0_ag_)) and (((x).agent) in (d_0_ag_))

    @staticmethod
    def InWindow(w, a, x):
        source0_ = w
        if True:
            if source0_.is_WTask:
                return True
        if True:
            if source0_.is_WLifetime:
                return True
        if True:
            if source0_.is_WSliding:
                d_0_ms_ = source0_.ms
                return (((x).t) > (((a).t) - (d_0_ms_))) and (((x).t) <= ((a).t))
        if True:
            d_1_ms_ = source0_.ms
            d_2_t0_ = source0_.t0
            return ((d_1_ms_) > (0)) and ((_dafny.euclidian_division(((a).t) - (d_2_t0_), d_1_ms_)) == (_dafny.euclidian_division(((x).t) - (d_2_t0_), d_1_ms_)))

    @staticmethod
    def SelItems(core, s, adms, a):
        d_0___accumulator_ = _dafny.SeqWithoutIsStrInference([])
        while True:
            with _dafny.label():
                if (len(adms)) == (0):
                    return (d_0___accumulator_) + (_dafny.SeqWithoutIsStrInference([a]))
                elif True:
                    d_0___accumulator_ = (d_0___accumulator_) + ((_dafny.SeqWithoutIsStrInference([((adms)[0]).act]) if ((default__.AppliesL(s, ((adms)[0]).gid, (((adms)[0]).act).verb)) and (default__.InScope((core).scope, a, ((adms)[0]).act))) and (default__.InWindow((core).window, a, ((adms)[0]).act)) else _dafny.SeqWithoutIsStrInference([])))
                    in0_ = core
                    in1_ = s
                    in2_ = _dafny.SeqWithoutIsStrInference((adms)[1::])
                    in3_ = a
                    core = in0_
                    s = in1_
                    adms = in2_
                    a = in3_
                    raise _dafny.TailCall()
                break

    @staticmethod
    def ItemVals(core, items, h):
        if (len(items)) == (0):
            return Option_Some(_dafny.SeqWithoutIsStrInference([]))
        elif True:
            source0_ = default__.EvalT((core).value, (items)[0], h)
            if True:
                if source0_.is_Some:
                    v0 = source0_.v
                    if v0.is_VQ:
                        d_0_q_ = v0.q
                        if ((d_0_q_).u) != (((core).cap).u):
                            return Option_None()
                        elif True:
                            source1_ = default__.ItemVals(core, _dafny.SeqWithoutIsStrInference((items)[1::]), h)
                            if True:
                                if source1_.is_Some:
                                    d_1_r_ = source1_.v
                                    return Option_Some((_dafny.SeqWithoutIsStrInference([(d_0_q_).n])) + (d_1_r_))
                            if True:
                                return Option_None()
            if True:
                return Option_None()

    @staticmethod
    def SumI(xs):
        d_0___accumulator_ = 0
        while True:
            with _dafny.label():
                if (len(xs)) == (0):
                    return (0) + (d_0___accumulator_)
                elif True:
                    d_0___accumulator_ = (d_0___accumulator_) + ((xs)[0])
                    in0_ = _dafny.SeqWithoutIsStrInference((xs)[1::])
                    xs = in0_
                    raise _dafny.TailCall()
                break

    @staticmethod
    def MaxI(xs):
        if (len(xs)) == (1):
            return (xs)[0]
        elif True:
            d_0_m_ = default__.MaxI(_dafny.SeqWithoutIsStrInference((xs)[1::]))
            if ((xs)[0]) >= (d_0_m_):
                return (xs)[0]
            elif True:
                return d_0_m_

    @staticmethod
    def KeyVals(core, items):
        if (len(items)) == (0):
            return Option_Some(_dafny.SeqWithoutIsStrInference([]))
        elif ((core).key) not in (((items)[0]).params):
            return Option_None()
        elif True:
            source0_ = default__.KeyVals(core, _dafny.SeqWithoutIsStrInference((items)[1::]))
            if True:
                if source0_.is_Some:
                    d_0_r_ = source0_.v
                    return Option_Some((_dafny.SeqWithoutIsStrInference([(((items)[0]).params)[(core).key]])) + (d_0_r_))
            if True:
                return Option_None()

    @staticmethod
    def Dedup(vs):
        d_0___accumulator_ = _dafny.SeqWithoutIsStrInference([])
        while True:
            with _dafny.label():
                if (len(vs)) == (0):
                    return (d_0___accumulator_) + (_dafny.SeqWithoutIsStrInference([]))
                elif ((vs)[0]) in (_dafny.SeqWithoutIsStrInference((vs)[1::])):
                    in0_ = _dafny.SeqWithoutIsStrInference((vs)[1::])
                    vs = in0_
                    raise _dafny.TailCall()
                elif True:
                    d_0___accumulator_ = (d_0___accumulator_) + (_dafny.SeqWithoutIsStrInference([(vs)[0]]))
                    in1_ = _dafny.SeqWithoutIsStrInference((vs)[1::])
                    vs = in1_
                    raise _dafny.TailCall()
                break

    @staticmethod
    def Exceeded(core, items, h):
        source0_ = (core).agg
        if True:
            if source0_.is_ACount:
                return default__.B2T((len(items)) > (((core).cap).n))
        if True:
            if source0_.is_ASum:
                source1_ = default__.ItemVals(core, items, h)
                if True:
                    if source1_.is_Some:
                        d_0_xs_ = source1_.v
                        return default__.B2T((default__.SumI(d_0_xs_)) > (((core).cap).n))
                if True:
                    return default__.KU
        if True:
            if source0_.is_AMax:
                source2_ = default__.ItemVals(core, items, h)
                if True:
                    if source2_.is_Some:
                        d_1_xs_ = source2_.v
                        if (len(d_1_xs_)) == (0):
                            return default__.KU
                        elif True:
                            return default__.B2T((default__.MaxI(d_1_xs_)) > (((core).cap).n))
                if True:
                    return default__.KU
        if True:
            source3_ = default__.KeyVals(core, items)
            if True:
                if source3_.is_Some:
                    d_2_vs_ = source3_.v
                    return default__.B2T((len(default__.Dedup(d_2_vs_))) > (((core).cap).n))
            if True:
                return default__.KU

    @staticmethod
    def BoundStat(core, s, a, h):
        d_0_e_ = default__.Exceeded(core, default__.SelItems(core, s, (h).adms, a), h)
        if (d_0_e_) == (default__.KT):
            source0_ = (core).onExceed
            if True:
                if source0_.is_OnDeny:
                    return default__.Deny
            if True:
                return default__.Escalate
        elif (d_0_e_) == (default__.KU):
            return default__.Escalate
        elif True:
            return default__.Allow

    @staticmethod
    def ValidityDec(v, dg, a, h):
        if (((a).t) < ((v).notBefore)) or (((a).t) > ((v).notAfter)):
            return default__.Deny
        elif ((((v).maxIdle) > (0)) and (((h).last) >= (0))) and ((((a).t) - ((h).last)) > ((v).maxIdle)):
            return default__.Deny
        elif (((a).depth) < (0)) or (((a).depth) > ((dg).maxDepth)):
            return default__.Deny
        elif True:
            return default__.Allow

    @staticmethod
    def DelegOk(dg, gid, a):
        return (((a).depth) == (0)) or ((gid) in ((dg).mayTouch))

    @staticmethod
    def ProhOne(verbs, res, c, a, h):
        d_0_m_ = default__.AndK(default__.B2T(((a).verb) in (verbs)), default__.AndK(default__.B2T(default__.ResOk(res, (a).res)), default__.EvalC(c, a, h)))
        if (d_0_m_) == (default__.KT):
            return default__.Deny
        elif (d_0_m_) == (default__.KU):
            return default__.Escalate
        elif True:
            return default__.Allow

    @staticmethod
    def ProhDecG(ont, ps, a, h):
        if (len(ps)) == (0):
            return default__.Allow
        elif True:
            return default__.MeetD(default__.ProhOne(default__.ProhVerbs(ont, ((ps)[0]).target), default__.ResolveSel(ont, ((ps)[0]).res), ((ps)[0]).cond, a, h), default__.ProhDecG(ont, _dafny.SeqWithoutIsStrInference((ps)[1::]), a, h))

    @staticmethod
    def EscOne(m):
        if (m) == (default__.KF):
            return default__.Allow
        elif True:
            return default__.Escalate

    @staticmethod
    def EscDecG(cs, a, h):
        if (len(cs)) == (0):
            return default__.Allow
        elif True:
            return default__.MeetD(default__.EscOne(default__.EvalC((cs)[0], a, h)), default__.EscDecG(_dafny.SeqWithoutIsStrInference((cs)[1::]), a, h))

    @staticmethod
    def BoundsDecG(ont, bs, gid, a, h):
        if (len(bs)) == (0):
            return default__.Allow
        elif True:
            d_0_s_ = default__.ResolveBSel(ont, ((bs)[0]).sel)
            return default__.MeetD((default__.BoundStat(((bs)[0]).core, d_0_s_, a, h) if default__.AppliesL(d_0_s_, gid, (a).verb) else default__.Allow), default__.BoundsDecG(ont, _dafny.SeqWithoutIsStrInference((bs)[1::]), gid, a, h))

    @staticmethod
    def GrantMatch(ont, g, dg, a, h):
        return default__.AndK(default__.B2T((((a).verb) == ((g).verb)) and (default__.DelegOk(dg, (g).gid, a))), default__.AndK(default__.B2T(default__.ResOk(default__.ResolveSel(ont, (g).res), (a).res)), default__.EvalC((g).cond, a, h)))

    @staticmethod
    def GrantDecG(ont, g, gr, a, h):
        return default__.MeetD(default__.DecOfTri(default__.GrantMatch(ont, gr, (g).deleg, a, h)), default__.BoundsDecG(ont, (g).bounds, (gr).gid, a, h))

    @staticmethod
    def GrantsDecG(ont, g, gs, a, h):
        if (len(gs)) == (0):
            return default__.Deny
        elif True:
            return default__.JoinD(default__.GrantDecG(ont, g, (gs)[0], a, h), default__.GrantsDecG(ont, g, _dafny.SeqWithoutIsStrInference((gs)[1::]), a, h))

    @staticmethod
    def DG(ont, g, a, h):
        return default__.MeetD(default__.ValidityDec((g).validity, (g).deleg, a, h), default__.MeetD(default__.ProhDecG(ont, (g).prohibits, a, h), default__.MeetD(default__.EscDecG((g).escalateOn, a, h), default__.GrantsDecG(ont, g, (g).grants, a, h))))

    @staticmethod
    def StrLt(a, b):
        while True:
            with _dafny.label():
                if (len(b)) == (0):
                    return False
                elif (len(a)) == (0):
                    return True
                elif ((a)[0]) != ((b)[0]):
                    return (ord((a)[0])) < (ord((b)[0]))
                elif True:
                    in0_ = _dafny.SeqWithoutIsStrInference((a)[1::])
                    in1_ = _dafny.SeqWithoutIsStrInference((b)[1::])
                    a = in0_
                    b = in1_
                    raise _dafny.TailCall()
                break

    @staticmethod
    def StrictlySorted(xs):
        return ((len(xs)) <= (1)) or ((default__.StrLt((xs)[0], (xs)[1])) and (default__.StrictlySorted(_dafny.SeqWithoutIsStrInference((xs)[1::]))))

    @staticmethod
    def UnitOk(u):
        source0_ = u
        if True:
            if source0_.is_UMoney:
                d_0_c_ = source0_.ccy
                return (len(d_0_c_)) > (0)
        if True:
            return True

    @staticmethod
    def TyOk(t):
        source0_ = t
        if True:
            if source0_.is_TyQ:
                d_0_u_ = source0_.u
                return default__.UnitOk(d_0_u_)
        if True:
            return True

    @staticmethod
    def VOk(v):
        source0_ = v
        if True:
            if source0_.is_VQ:
                d_0_q_ = source0_.q
                return default__.UnitOk((d_0_q_).u)
        if True:
            if source0_.is_VS:
                return True
        if True:
            d_1_items_ = source0_.items
            def lambda0_(forall_var_0_):
                def lambda1_():
                    source1_ = (d_1_items_)[d_2_i_]
                    if True:
                        if source1_.is_AQ:
                            d_3_q_ = source1_.q
                            return default__.UnitOk((d_3_q_).u)
                    if True:
                        return True

                d_2_i_: int = forall_var_0_
                return not (((0) <= (d_2_i_)) and ((d_2_i_) < (len(d_1_items_)))) or (lambda1_())

            return _dafny.quantifier(_dafny.IntegerRange(0, len(d_1_items_)), True, lambda0_)

    @staticmethod
    def TypeOfTerm(t):
        source0_ = t
        if True:
            if source0_.is_Param:
                d_0_ty_ = source0_.ty
                return Option_Some(d_0_ty_)
        if True:
            if source0_.is_Lit:
                d_1_v_ = source0_.v
                return default__.TypeOfV(d_1_v_)
        if True:
            d_2_u_ = source0_.u
            return Option_Some(Ty_TyQ(d_2_u_))

    @staticmethod
    def TermOk(t):
        source0_ = t
        if True:
            if source0_.is_Param:
                d_0_p_ = source0_.path
                d_1_ty_ = source0_.ty
                return ((len(d_0_p_)) > (0)) and (default__.TyOk(d_1_ty_))
        if True:
            if source0_.is_Lit:
                d_2_v_ = source0_.v
                return default__.VOk(d_2_v_)
        if True:
            d_3_b_ = source0_.bid
            d_4_u_ = source0_.u
            return ((len(d_3_b_)) > (0)) and (default__.UnitOk(d_4_u_))

    @staticmethod
    def AllOfTy(items, ty):
        def lambda0_(forall_var_0_):
            d_0_i_: int = forall_var_0_
            return not (((0) <= (d_0_i_)) and ((d_0_i_) < (len(items)))) or ((default__.TypeOfV(default__.AtomV((items)[d_0_i_]))) == (Option_Some(ty)))

        return _dafny.quantifier(_dafny.IntegerRange(0, len(items)), True, lambda0_)

    @staticmethod
    def CmpTyped(op, l, r):
        def lambda0_():
            source0_ = op
            if True:
                if source0_.is_Eq:
                    return (default__.TypeOfTerm(l)) == (default__.TypeOfTerm(r))
            if True:
                if source0_.is_Ne:
                    return (default__.TypeOfTerm(l)) == (default__.TypeOfTerm(r))
            if True:
                if source0_.is_Lt:
                    return ((default__.TypeOfTerm(l)) == (default__.TypeOfTerm(r))) and (((default__.TypeOfTerm(l)).v).is_TyQ)
            if True:
                if source0_.is_Lte:
                    return ((default__.TypeOfTerm(l)) == (default__.TypeOfTerm(r))) and (((default__.TypeOfTerm(l)).v).is_TyQ)
            if True:
                if source0_.is_Gt:
                    return ((default__.TypeOfTerm(l)) == (default__.TypeOfTerm(r))) and (((default__.TypeOfTerm(l)).v).is_TyQ)
            if True:
                if source0_.is_Gte:
                    return ((default__.TypeOfTerm(l)) == (default__.TypeOfTerm(r))) and (((default__.TypeOfTerm(l)).v).is_TyQ)
            if True:
                if source0_.is_In:
                    return (((r).is_Lit) and (((r).v).is_VSet)) and (default__.AllOfTy(((r).v).items, (default__.TypeOfTerm(l)).v))
            if True:
                return (((r).is_Lit) and (((r).v).is_VSet)) and (default__.AllOfTy(((r).v).items, (default__.TypeOfTerm(l)).v))

        return (((default__.TermOk(l)) and (default__.TermOk(r))) and ((default__.TypeOfTerm(l)).is_Some)) and (lambda0_())

    @staticmethod
    def CondTyped(c, ok):
        source0_ = c
        if True:
            if source0_.is_CTrue:
                return True
        if True:
            if source0_.is_Cmp:
                d_0_op_ = source0_.op
                d_1_l_ = source0_.l
                d_2_r_ = source0_.r
                return ((default__.CmpTyped(d_0_op_, d_1_l_, d_2_r_)) and (default__.ParamsOk(d_1_l_, ok))) and (default__.ParamsOk(d_2_r_, ok))
        if True:
            if source0_.is_And:
                d_3_x_ = source0_.a
                d_4_y_ = source0_.b
                return (default__.CondTyped(d_3_x_, ok)) and (default__.CondTyped(d_4_y_, ok))
        if True:
            if source0_.is_Or:
                d_5_x_ = source0_.a
                d_6_y_ = source0_.b
                return (default__.CondTyped(d_5_x_, ok)) and (default__.CondTyped(d_6_y_, ok))
        if True:
            d_7_x_ = source0_.c
            return default__.CondTyped(d_7_x_, ok)

    @staticmethod
    def ParamsOk(t, ok):
        source0_ = t
        if True:
            if source0_.is_Param:
                d_0_p_ = source0_.path
                d_1_ty_ = source0_.ty
                return ok(d_0_p_, d_1_ty_)
        if True:
            return True

    @staticmethod
    def FindDecl(vs, verb):
        while True:
            with _dafny.label():
                if (len(vs)) == (0):
                    return Option_None()
                elif (((vs)[0]).verb) == (verb):
                    return Option_Some((vs)[0])
                elif True:
                    in0_ = _dafny.SeqWithoutIsStrInference((vs)[1::])
                    in1_ = verb
                    vs = in0_
                    verb = in1_
                    raise _dafny.TailCall()
                break

    @staticmethod
    def HasParam(ps, p, ty):
        return (ParamDecl_ParamDecl(p, ty)) in (ps)

    @staticmethod
    def DeclaredFor(ont, verbs, p, ty):
        def lambda0_(forall_var_0_):
            d_0_i_: int = forall_var_0_
            return not (((0) <= (d_0_i_)) and ((d_0_i_) < (len(verbs)))) or (((default__.FindDecl((ont).verbs, (verbs)[d_0_i_])).is_Some) and (default__.HasParam(((default__.FindDecl((ont).verbs, (verbs)[d_0_i_])).v).params, p, ty)))

        return _dafny.quantifier(_dafny.IntegerRange(0, len(verbs)), True, lambda0_)

    @staticmethod
    def NoConflictP(ps, p, ty):
        return ((len(ps)) == (0)) or ((((((ps)[0]).path) != (p)) or ((((ps)[0]).ty) == (ty))) and (default__.NoConflictP(_dafny.SeqWithoutIsStrInference((ps)[1::]), p, ty)))

    @staticmethod
    def NoConflict(vs, p, ty):
        return ((len(vs)) == (0)) or ((default__.NoConflictP(((vs)[0]).params, p, ty)) and (default__.NoConflict(_dafny.SeqWithoutIsStrInference((vs)[1::]), p, ty)))

    @staticmethod
    def ResSelOk(ont, s):
        source0_ = s
        if True:
            if source0_.is_Exact:
                d_0_id_ = source0_.id_
                return (len(d_0_id_)) > (0)
        if True:
            if source0_.is_OneOf:
                d_1_ids_ = source0_.ids
                return (len(d_1_ids_)) > (0)
        if True:
            if source0_.is_Related:
                d_2_rel_ = source0_.rel
                d_3_anchor_ = source0_.anchor
                def lambda0_(exists_var_0_):
                    d_4_i_: int = exists_var_0_
                    return ((((0) <= (d_4_i_)) and ((d_4_i_) < (len((ont).rels)))) and (((((ont).rels)[d_4_i_]).rel) == (d_2_rel_))) and (((((ont).rels)[d_4_i_]).anchor) == (d_3_anchor_))

                return _dafny.quantifier(_dafny.IntegerRange(0, len((ont).rels)), False, lambda0_)
        if True:
            if source0_.is_AnyRes:
                return True
        if True:
            d_5_ps_ = source0_.parts
            def lambda1_(forall_var_0_):
                d_6_i_: int = forall_var_0_
                return not (((0) <= (d_6_i_)) and ((d_6_i_) < (len(d_5_ps_)))) or (default__.PartOk(ont, (d_5_ps_)[d_6_i_]))

            return ((len(d_5_ps_)) >= (2)) and (_dafny.quantifier(_dafny.IntegerRange(0, len(d_5_ps_)), True, lambda1_))

    @staticmethod
    def PartOk(ont, p):
        source0_ = p
        if True:
            if source0_.is_PartExact:
                d_0_id_ = source0_.id_
                return (len(d_0_id_)) > (0)
        if True:
            if source0_.is_PartOneOf:
                d_1_ids_ = source0_.ids
                return (len(d_1_ids_)) > (0)
        if True:
            d_2_rel_ = source0_.rel
            d_3_anchor_ = source0_.anchor
            def lambda0_(exists_var_0_):
                d_4_i_: int = exists_var_0_
                return ((((0) <= (d_4_i_)) and ((d_4_i_) < (len((ont).rels)))) and (((((ont).rels)[d_4_i_]).rel) == (d_2_rel_))) and (((((ont).rels)[d_4_i_]).anchor) == (d_3_anchor_))

            return _dafny.quantifier(_dafny.IntegerRange(0, len((ont).rels)), False, lambda0_)

    @staticmethod
    def GrantOk(ont, g, gr):
        def lambda0_(d_0_ont_, d_1_gr_):
            def lambda1_(d_2_p_, d_3_ty_):
                return default__.DeclaredFor(d_0_ont_, _dafny.SeqWithoutIsStrInference([(d_1_gr_).verb]), d_2_p_, d_3_ty_)

            return lambda1_

        return (((((len((gr).gid)) > (0)) and ((default__.FindDecl((ont).verbs, (gr).verb)).is_Some)) and (default__.ResSelOk(ont, (gr).res))) and (not (((gr).res).is_AnyRes) or (((gr).gid) in ((g).wildcardAck)))) and (default__.CondTyped((gr).cond, lambda0_(ont, gr)))

    @staticmethod
    def ProhibitOk(ont, p):
        def lambda0_():
            source0_ = (p).target
            if True:
                if source0_.is_PVerb:
                    d_0_v_ = source0_.verb
                    return (default__.FindDecl((ont).verbs, d_0_v_)).is_Some
            if True:
                d_1_c_ = source0_.cls
                return ((len(d_1_c_)) > (0)) and ((len(default__.VerbsOfClass((ont).verbs, d_1_c_))) > (0))

        def lambda1_(d_2_ont_, d_3_p_):
            def lambda2_(d_4_q_, d_5_ty_):
                return default__.DeclaredFor(d_2_ont_, default__.ProhVerbs(d_2_ont_, (d_3_p_).target), d_4_q_, d_5_ty_)

            return lambda2_

        return ((((len((p).pid)) > (0)) and (default__.ResSelOk(ont, (p).res))) and (lambda0_())) and (default__.CondTyped((p).cond, lambda1_(ont, p)))

    @staticmethod
    def WindowOk(w):
        source0_ = w
        if True:
            if source0_.is_WSliding:
                d_0_ms_ = source0_.ms
                return (d_0_ms_) > (0)
        if True:
            if source0_.is_WPeriod:
                d_1_ms_ = source0_.ms
                return (d_1_ms_) > (0)
        if True:
            return True

    @staticmethod
    def ScopeOk(s):
        source0_ = s
        if True:
            if source0_.is_SFleet:
                d_0_ag_ = source0_.agents
                return (len(d_0_ag_)) > (0)
        if True:
            return True

    @staticmethod
    def BoundOk(ont, g, b):
        def lambda0_():
            source0_ = (b).sel
            if True:
                if source0_.is_SelGids:
                    d_0_gids_ = source0_.gids
                    def lambda1_(forall_var_0_):
                        def lambda2_(exists_var_0_):
                            d_2_j_: int = exists_var_0_
                            return (((0) <= (d_2_j_)) and ((d_2_j_) < (len((g).grants)))) and (((((g).grants)[d_2_j_]).gid) == ((d_0_gids_)[d_1_i_]))

                        d_1_i_: int = forall_var_0_
                        return not (((0) <= (d_1_i_)) and ((d_1_i_) < (len(d_0_gids_)))) or (_dafny.quantifier(_dafny.IntegerRange(0, len((g).grants)), False, lambda2_))

                    return ((len(d_0_gids_)) > (0)) and (_dafny.quantifier(_dafny.IntegerRange(0, len(d_0_gids_)), True, lambda1_))
            if True:
                d_3_c_ = source0_.cls
                return (len(d_3_c_)) > (0)

        def lambda3_():
            source1_ = ((b).core).agg
            if True:
                if source1_.is_ACount:
                    return ((((b).core).cap).u) == (Unit_UCount())
            if True:
                if source1_.is_ASum:
                    return (default__.TypeOfTerm(((b).core).value)) == (Option_Some(Ty_TyQ((((b).core).cap).u)))
            if True:
                if source1_.is_AMax:
                    return (default__.TypeOfTerm(((b).core).value)) == (Option_Some(Ty_TyQ((((b).core).cap).u)))
            if True:
                return (((((b).core).cap).u) == (Unit_UCount())) and ((len(((b).core).key)) > (0))

        return ((((((((len((b).bid)) > (0)) and (default__.TermOk(((b).core).value))) and (default__.UnitOk((((b).core).cap).u))) and (((((b).core).cap).n) >= (0))) and (default__.WindowOk(((b).core).window))) and (default__.ScopeOk(((b).core).scope))) and (lambda0_())) and (lambda3_())

    @staticmethod
    def ValidityOk(v, dg, g):
        def lambda0_(forall_var_0_):
            def lambda1_(exists_var_0_):
                d_1_j_: int = exists_var_0_
                return (((0) <= (d_1_j_)) and ((d_1_j_) < (len((g).grants)))) and (((((g).grants)[d_1_j_]).gid) == (((dg).mayTouch)[d_0_i_]))

            d_0_i_: int = forall_var_0_
            return not (((0) <= (d_0_i_)) and ((d_0_i_) < (len((dg).mayTouch)))) or (_dafny.quantifier(_dafny.IntegerRange(0, len((g).grants)), False, lambda1_))

        return ((((((v).notBefore) <= ((v).notAfter)) and (((v).maxIdle) >= (0))) and (((0) <= ((dg).maxDepth)) and (((dg).maxDepth) <= (16)))) and ((dg).narrowOnly)) and (_dafny.quantifier(_dafny.IntegerRange(0, len((dg).mayTouch)), True, lambda0_))

    @staticmethod
    def HoleOk(g, h):
        def lambda0_(forall_var_0_):
            def lambda1_(exists_var_0_):
                d_1_j_: int = exists_var_0_
                return (((0) <= (d_1_j_)) and ((d_1_j_) < (len((g).grants)))) and (((((g).grants)[d_1_j_]).gid) == (((h).affects)[d_0_i_]))

            d_0_i_: int = forall_var_0_
            return not (((0) <= (d_0_i_)) and ((d_0_i_) < (len((h).affects)))) or (_dafny.quantifier(_dafny.IntegerRange(0, len((g).grants)), False, lambda1_))

        return ((len((h).hid)) > (0)) and (_dafny.quantifier(_dafny.IntegerRange(0, len((h).affects)), True, lambda0_))

    @staticmethod
    def Gids(gs):
        return _dafny.SeqWithoutIsStrInference([((gs)[d_0_i_]).gid for d_0_i_ in range(len(gs))])

    @staticmethod
    def Pids(ps):
        return _dafny.SeqWithoutIsStrInference([((ps)[d_0_i_]).pid for d_0_i_ in range(len(ps))])

    @staticmethod
    def Bids(bs):
        return _dafny.SeqWithoutIsStrInference([((bs)[d_0_i_]).bid for d_0_i_ in range(len(bs))])

    @staticmethod
    def Hids(hs):
        return _dafny.SeqWithoutIsStrInference([((hs)[d_0_i_]).hid for d_0_i_ in range(len(hs))])

    @staticmethod
    def EscsTyped(ont, g):
        def lambda0_(forall_var_0_):
            def lambda1_(d_1_ont_):
                def lambda2_(d_2_p_, d_3_ty_):
                    return default__.NoConflict((d_1_ont_).verbs, d_2_p_, d_3_ty_)

                return lambda2_

            d_0_i_: int = forall_var_0_
            return not (((0) <= (d_0_i_)) and ((d_0_i_) < (len((g).escalateOn)))) or (default__.CondTyped(((g).escalateOn)[d_0_i_], lambda1_(ont)))

        return _dafny.quantifier(_dafny.IntegerRange(0, len((g).escalateOn)), True, lambda0_)

    @staticmethod
    def Sorted4(g):
        return (((default__.StrictlySorted(default__.Gids((g).grants))) and (default__.StrictlySorted(default__.Pids((g).prohibits)))) and (default__.StrictlySorted(default__.Bids((g).bounds)))) and (default__.StrictlySorted(default__.Hids((g).holes)))

    @staticmethod
    def IsWellTyped(ont, g):
        def lambda0_(forall_var_0_):
            d_0_i_: int = forall_var_0_
            return not (((0) <= (d_0_i_)) and ((d_0_i_) < (len((g).grants)))) or (default__.GrantOk(ont, g, ((g).grants)[d_0_i_]))

        def lambda1_(forall_var_1_):
            d_1_i_: int = forall_var_1_
            return not (((0) <= (d_1_i_)) and ((d_1_i_) < (len((g).prohibits)))) or (default__.ProhibitOk(ont, ((g).prohibits)[d_1_i_]))

        def lambda2_(forall_var_2_):
            d_2_i_: int = forall_var_2_
            return not (((0) <= (d_2_i_)) and ((d_2_i_) < (len((g).bounds)))) or (default__.BoundOk(ont, g, ((g).bounds)[d_2_i_]))

        def lambda3_(forall_var_3_):
            d_3_i_: int = forall_var_3_
            return not (((0) <= (d_3_i_)) and ((d_3_i_) < (len((g).holes)))) or (default__.HoleOk(g, ((g).holes)[d_3_i_]))

        return ((((((default__.Sorted4(g)) and (_dafny.quantifier(_dafny.IntegerRange(0, len((g).grants)), True, lambda0_))) and (_dafny.quantifier(_dafny.IntegerRange(0, len((g).prohibits)), True, lambda1_))) and (_dafny.quantifier(_dafny.IntegerRange(0, len((g).bounds)), True, lambda2_))) and (default__.EscsTyped(ont, g))) and (default__.ValidityOk((g).validity, (g).deleg, g))) and (_dafny.quantifier(_dafny.IntegerRange(0, len((g).holes)), True, lambda3_))

    @staticmethod
    def Signable(ont, g):
        return (default__.IsWellTyped(ont, g)) and ((len((g).holes)) == (0))

    @_dafny.classproperty
    def Deny(instance):
        return 0
    @_dafny.classproperty
    def Escalate(instance):
        return 1
    @_dafny.classproperty
    def Allow(instance):
        return 2
    @_dafny.classproperty
    def KF(instance):
        return 0
    @_dafny.classproperty
    def KU(instance):
        return 1
    @_dafny.classproperty
    def KT(instance):
        return 2

class Dec:
    def  __init__(self):
        pass

    @staticmethod
    def default():
        return int(0)
    def _Is(source__):
        d_0_d_: int = source__
        return ((0) <= (d_0_d_)) and ((d_0_d_) <= (2))

class Tri:
    def  __init__(self):
        pass

    @staticmethod
    def default():
        return int(0)
    def _Is(source__):
        d_1_t_: int = source__
        return ((0) <= (d_1_t_)) and ((d_1_t_) <= (2))

class Unit:
    @classmethod
    def default(cls, ):
        return lambda: Unit_UMoney(_dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "")))
    def __ne__(self, __o: object) -> bool:
        return not self.__eq__(__o)
    @property
    def is_UMoney(self) -> bool:
        return isinstance(self, Unit_UMoney)
    @property
    def is_UCount(self) -> bool:
        return isinstance(self, Unit_UCount)
    @property
    def is_UDuration(self) -> bool:
        return isinstance(self, Unit_UDuration)
    @property
    def is_UInstant(self) -> bool:
        return isinstance(self, Unit_UInstant)
    @property
    def is_UBytes(self) -> bool:
        return isinstance(self, Unit_UBytes)
    @property
    def is_URatio(self) -> bool:
        return isinstance(self, Unit_URatio)

class Unit_UMoney(Unit, NamedTuple('UMoney', [('ccy', Any)])):
    def __dafnystr__(self) -> str:
        return f'GoalIr.Unit.UMoney({self.ccy.VerbatimString(True)})'
    def __eq__(self, __o: object) -> bool:
        return isinstance(__o, Unit_UMoney) and self.ccy == __o.ccy
    def __hash__(self) -> int:
        return super().__hash__()

class Unit_UCount(Unit, NamedTuple('UCount', [])):
    def __dafnystr__(self) -> str:
        return f'GoalIr.Unit.UCount'
    def __eq__(self, __o: object) -> bool:
        return isinstance(__o, Unit_UCount)
    def __hash__(self) -> int:
        return super().__hash__()

class Unit_UDuration(Unit, NamedTuple('UDuration', [])):
    def __dafnystr__(self) -> str:
        return f'GoalIr.Unit.UDuration'
    def __eq__(self, __o: object) -> bool:
        return isinstance(__o, Unit_UDuration)
    def __hash__(self) -> int:
        return super().__hash__()

class Unit_UInstant(Unit, NamedTuple('UInstant', [])):
    def __dafnystr__(self) -> str:
        return f'GoalIr.Unit.UInstant'
    def __eq__(self, __o: object) -> bool:
        return isinstance(__o, Unit_UInstant)
    def __hash__(self) -> int:
        return super().__hash__()

class Unit_UBytes(Unit, NamedTuple('UBytes', [])):
    def __dafnystr__(self) -> str:
        return f'GoalIr.Unit.UBytes'
    def __eq__(self, __o: object) -> bool:
        return isinstance(__o, Unit_UBytes)
    def __hash__(self) -> int:
        return super().__hash__()

class Unit_URatio(Unit, NamedTuple('URatio', [])):
    def __dafnystr__(self) -> str:
        return f'GoalIr.Unit.URatio'
    def __eq__(self, __o: object) -> bool:
        return isinstance(__o, Unit_URatio)
    def __hash__(self) -> int:
        return super().__hash__()


class Q:
    @classmethod
    def default(cls, ):
        return lambda: Q_Q(Unit.default()(), int(0))
    def __ne__(self, __o: object) -> bool:
        return not self.__eq__(__o)
    @property
    def is_Q(self) -> bool:
        return isinstance(self, Q_Q)

class Q_Q(Q, NamedTuple('Q', [('u', Any), ('n', Any)])):
    def __dafnystr__(self) -> str:
        return f'GoalIr.Q.Q({_dafny.string_of(self.u)}, {_dafny.string_of(self.n)})'
    def __eq__(self, __o: object) -> bool:
        return isinstance(__o, Q_Q) and self.u == __o.u and self.n == __o.n
    def __hash__(self) -> int:
        return super().__hash__()


class Atom:
    @classmethod
    def default(cls, ):
        return lambda: Atom_AQ(Q.default()())
    def __ne__(self, __o: object) -> bool:
        return not self.__eq__(__o)
    @property
    def is_AQ(self) -> bool:
        return isinstance(self, Atom_AQ)
    @property
    def is_AS(self) -> bool:
        return isinstance(self, Atom_AS)

class Atom_AQ(Atom, NamedTuple('AQ', [('q', Any)])):
    def __dafnystr__(self) -> str:
        return f'GoalIr.Atom.AQ({_dafny.string_of(self.q)})'
    def __eq__(self, __o: object) -> bool:
        return isinstance(__o, Atom_AQ) and self.q == __o.q
    def __hash__(self) -> int:
        return super().__hash__()

class Atom_AS(Atom, NamedTuple('AS', [('s', Any)])):
    def __dafnystr__(self) -> str:
        return f'GoalIr.Atom.AS({self.s.VerbatimString(True)})'
    def __eq__(self, __o: object) -> bool:
        return isinstance(__o, Atom_AS) and self.s == __o.s
    def __hash__(self) -> int:
        return super().__hash__()


class V:
    @classmethod
    def default(cls, ):
        return lambda: V_VQ(Q.default()())
    def __ne__(self, __o: object) -> bool:
        return not self.__eq__(__o)
    @property
    def is_VQ(self) -> bool:
        return isinstance(self, V_VQ)
    @property
    def is_VS(self) -> bool:
        return isinstance(self, V_VS)
    @property
    def is_VSet(self) -> bool:
        return isinstance(self, V_VSet)

class V_VQ(V, NamedTuple('VQ', [('q', Any)])):
    def __dafnystr__(self) -> str:
        return f'GoalIr.V.VQ({_dafny.string_of(self.q)})'
    def __eq__(self, __o: object) -> bool:
        return isinstance(__o, V_VQ) and self.q == __o.q
    def __hash__(self) -> int:
        return super().__hash__()

class V_VS(V, NamedTuple('VS', [('s', Any)])):
    def __dafnystr__(self) -> str:
        return f'GoalIr.V.VS({self.s.VerbatimString(True)})'
    def __eq__(self, __o: object) -> bool:
        return isinstance(__o, V_VS) and self.s == __o.s
    def __hash__(self) -> int:
        return super().__hash__()

class V_VSet(V, NamedTuple('VSet', [('items', Any)])):
    def __dafnystr__(self) -> str:
        return f'GoalIr.V.VSet({_dafny.string_of(self.items)})'
    def __eq__(self, __o: object) -> bool:
        return isinstance(__o, V_VSet) and self.items == __o.items
    def __hash__(self) -> int:
        return super().__hash__()


class Ty:
    @classmethod
    def default(cls, ):
        return lambda: Ty_TyQ(Unit.default()())
    def __ne__(self, __o: object) -> bool:
        return not self.__eq__(__o)
    @property
    def is_TyQ(self) -> bool:
        return isinstance(self, Ty_TyQ)
    @property
    def is_TyS(self) -> bool:
        return isinstance(self, Ty_TyS)

class Ty_TyQ(Ty, NamedTuple('TyQ', [('u', Any)])):
    def __dafnystr__(self) -> str:
        return f'GoalIr.Ty.TyQ({_dafny.string_of(self.u)})'
    def __eq__(self, __o: object) -> bool:
        return isinstance(__o, Ty_TyQ) and self.u == __o.u
    def __hash__(self) -> int:
        return super().__hash__()

class Ty_TyS(Ty, NamedTuple('TyS', [])):
    def __dafnystr__(self) -> str:
        return f'GoalIr.Ty.TyS'
    def __eq__(self, __o: object) -> bool:
        return isinstance(__o, Ty_TyS)
    def __hash__(self) -> int:
        return super().__hash__()


class Option:
    @classmethod
    def default(cls, ):
        return lambda: Option_None()
    def __ne__(self, __o: object) -> bool:
        return not self.__eq__(__o)
    @property
    def is_None(self) -> bool:
        return isinstance(self, Option_None)
    @property
    def is_Some(self) -> bool:
        return isinstance(self, Option_Some)

class Option_None(Option, NamedTuple('None_', [])):
    def __dafnystr__(self) -> str:
        return f'GoalIr.Option.None'
    def __eq__(self, __o: object) -> bool:
        return isinstance(__o, Option_None)
    def __hash__(self) -> int:
        return super().__hash__()

class Option_Some(Option, NamedTuple('Some', [('v', Any)])):
    def __dafnystr__(self) -> str:
        return f'GoalIr.Option.Some({_dafny.string_of(self.v)})'
    def __eq__(self, __o: object) -> bool:
        return isinstance(__o, Option_Some) and self.v == __o.v
    def __hash__(self) -> int:
        return super().__hash__()


class Term:
    @classmethod
    def default(cls, ):
        return lambda: Term_Param(_dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "")), Ty.default()())
    def __ne__(self, __o: object) -> bool:
        return not self.__eq__(__o)
    @property
    def is_Param(self) -> bool:
        return isinstance(self, Term_Param)
    @property
    def is_Lit(self) -> bool:
        return isinstance(self, Term_Lit)
    @property
    def is_HistAgg(self) -> bool:
        return isinstance(self, Term_HistAgg)

class Term_Param(Term, NamedTuple('Param', [('path', Any), ('ty', Any)])):
    def __dafnystr__(self) -> str:
        return f'GoalIr.Term.Param({self.path.VerbatimString(True)}, {_dafny.string_of(self.ty)})'
    def __eq__(self, __o: object) -> bool:
        return isinstance(__o, Term_Param) and self.path == __o.path and self.ty == __o.ty
    def __hash__(self) -> int:
        return super().__hash__()

class Term_Lit(Term, NamedTuple('Lit', [('v', Any)])):
    def __dafnystr__(self) -> str:
        return f'GoalIr.Term.Lit({_dafny.string_of(self.v)})'
    def __eq__(self, __o: object) -> bool:
        return isinstance(__o, Term_Lit) and self.v == __o.v
    def __hash__(self) -> int:
        return super().__hash__()

class Term_HistAgg(Term, NamedTuple('HistAgg', [('bid', Any), ('u', Any)])):
    def __dafnystr__(self) -> str:
        return f'GoalIr.Term.HistAgg({self.bid.VerbatimString(True)}, {_dafny.string_of(self.u)})'
    def __eq__(self, __o: object) -> bool:
        return isinstance(__o, Term_HistAgg) and self.bid == __o.bid and self.u == __o.u
    def __hash__(self) -> int:
        return super().__hash__()


class Op:
    @_dafny.classproperty
    def AllSingletonConstructors(cls):
        return [Op_Eq(), Op_Ne(), Op_Lt(), Op_Lte(), Op_Gt(), Op_Gte(), Op_In(), Op_Nin()]
    @classmethod
    def default(cls, ):
        return lambda: Op_Eq()
    def __ne__(self, __o: object) -> bool:
        return not self.__eq__(__o)
    @property
    def is_Eq(self) -> bool:
        return isinstance(self, Op_Eq)
    @property
    def is_Ne(self) -> bool:
        return isinstance(self, Op_Ne)
    @property
    def is_Lt(self) -> bool:
        return isinstance(self, Op_Lt)
    @property
    def is_Lte(self) -> bool:
        return isinstance(self, Op_Lte)
    @property
    def is_Gt(self) -> bool:
        return isinstance(self, Op_Gt)
    @property
    def is_Gte(self) -> bool:
        return isinstance(self, Op_Gte)
    @property
    def is_In(self) -> bool:
        return isinstance(self, Op_In)
    @property
    def is_Nin(self) -> bool:
        return isinstance(self, Op_Nin)

class Op_Eq(Op, NamedTuple('Eq', [])):
    def __dafnystr__(self) -> str:
        return f'GoalIr.Op.Eq'
    def __eq__(self, __o: object) -> bool:
        return isinstance(__o, Op_Eq)
    def __hash__(self) -> int:
        return super().__hash__()

class Op_Ne(Op, NamedTuple('Ne', [])):
    def __dafnystr__(self) -> str:
        return f'GoalIr.Op.Ne'
    def __eq__(self, __o: object) -> bool:
        return isinstance(__o, Op_Ne)
    def __hash__(self) -> int:
        return super().__hash__()

class Op_Lt(Op, NamedTuple('Lt', [])):
    def __dafnystr__(self) -> str:
        return f'GoalIr.Op.Lt'
    def __eq__(self, __o: object) -> bool:
        return isinstance(__o, Op_Lt)
    def __hash__(self) -> int:
        return super().__hash__()

class Op_Lte(Op, NamedTuple('Lte', [])):
    def __dafnystr__(self) -> str:
        return f'GoalIr.Op.Lte'
    def __eq__(self, __o: object) -> bool:
        return isinstance(__o, Op_Lte)
    def __hash__(self) -> int:
        return super().__hash__()

class Op_Gt(Op, NamedTuple('Gt', [])):
    def __dafnystr__(self) -> str:
        return f'GoalIr.Op.Gt'
    def __eq__(self, __o: object) -> bool:
        return isinstance(__o, Op_Gt)
    def __hash__(self) -> int:
        return super().__hash__()

class Op_Gte(Op, NamedTuple('Gte', [])):
    def __dafnystr__(self) -> str:
        return f'GoalIr.Op.Gte'
    def __eq__(self, __o: object) -> bool:
        return isinstance(__o, Op_Gte)
    def __hash__(self) -> int:
        return super().__hash__()

class Op_In(Op, NamedTuple('In', [])):
    def __dafnystr__(self) -> str:
        return f'GoalIr.Op.In'
    def __eq__(self, __o: object) -> bool:
        return isinstance(__o, Op_In)
    def __hash__(self) -> int:
        return super().__hash__()

class Op_Nin(Op, NamedTuple('Nin', [])):
    def __dafnystr__(self) -> str:
        return f'GoalIr.Op.Nin'
    def __eq__(self, __o: object) -> bool:
        return isinstance(__o, Op_Nin)
    def __hash__(self) -> int:
        return super().__hash__()


class Cond:
    @classmethod
    def default(cls, ):
        return lambda: Cond_CTrue()
    def __ne__(self, __o: object) -> bool:
        return not self.__eq__(__o)
    @property
    def is_CTrue(self) -> bool:
        return isinstance(self, Cond_CTrue)
    @property
    def is_Cmp(self) -> bool:
        return isinstance(self, Cond_Cmp)
    @property
    def is_And(self) -> bool:
        return isinstance(self, Cond_And)
    @property
    def is_Or(self) -> bool:
        return isinstance(self, Cond_Or)
    @property
    def is_Not(self) -> bool:
        return isinstance(self, Cond_Not)

class Cond_CTrue(Cond, NamedTuple('CTrue', [])):
    def __dafnystr__(self) -> str:
        return f'GoalIr.Cond.CTrue'
    def __eq__(self, __o: object) -> bool:
        return isinstance(__o, Cond_CTrue)
    def __hash__(self) -> int:
        return super().__hash__()

class Cond_Cmp(Cond, NamedTuple('Cmp', [('op', Any), ('l', Any), ('r', Any)])):
    def __dafnystr__(self) -> str:
        return f'GoalIr.Cond.Cmp({_dafny.string_of(self.op)}, {_dafny.string_of(self.l)}, {_dafny.string_of(self.r)})'
    def __eq__(self, __o: object) -> bool:
        return isinstance(__o, Cond_Cmp) and self.op == __o.op and self.l == __o.l and self.r == __o.r
    def __hash__(self) -> int:
        return super().__hash__()

class Cond_And(Cond, NamedTuple('And', [('a', Any), ('b', Any)])):
    def __dafnystr__(self) -> str:
        return f'GoalIr.Cond.And({_dafny.string_of(self.a)}, {_dafny.string_of(self.b)})'
    def __eq__(self, __o: object) -> bool:
        return isinstance(__o, Cond_And) and self.a == __o.a and self.b == __o.b
    def __hash__(self) -> int:
        return super().__hash__()

class Cond_Or(Cond, NamedTuple('Or', [('a', Any), ('b', Any)])):
    def __dafnystr__(self) -> str:
        return f'GoalIr.Cond.Or({_dafny.string_of(self.a)}, {_dafny.string_of(self.b)})'
    def __eq__(self, __o: object) -> bool:
        return isinstance(__o, Cond_Or) and self.a == __o.a and self.b == __o.b
    def __hash__(self) -> int:
        return super().__hash__()

class Cond_Not(Cond, NamedTuple('Not', [('c', Any)])):
    def __dafnystr__(self) -> str:
        return f'GoalIr.Cond.Not({_dafny.string_of(self.c)})'
    def __eq__(self, __o: object) -> bool:
        return isinstance(__o, Cond_Not) and self.c == __o.c
    def __hash__(self) -> int:
        return super().__hash__()


class ResPart:
    @classmethod
    def default(cls, ):
        return lambda: ResPart_PartExact(_dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "")))
    def __ne__(self, __o: object) -> bool:
        return not self.__eq__(__o)
    @property
    def is_PartExact(self) -> bool:
        return isinstance(self, ResPart_PartExact)
    @property
    def is_PartOneOf(self) -> bool:
        return isinstance(self, ResPart_PartOneOf)
    @property
    def is_PartRelated(self) -> bool:
        return isinstance(self, ResPart_PartRelated)

class ResPart_PartExact(ResPart, NamedTuple('PartExact', [('id_', Any)])):
    def __dafnystr__(self) -> str:
        return f'GoalIr.ResPart.PartExact({self.id_.VerbatimString(True)})'
    def __eq__(self, __o: object) -> bool:
        return isinstance(__o, ResPart_PartExact) and self.id_ == __o.id_
    def __hash__(self) -> int:
        return super().__hash__()

class ResPart_PartOneOf(ResPart, NamedTuple('PartOneOf', [('ids', Any)])):
    def __dafnystr__(self) -> str:
        return f'GoalIr.ResPart.PartOneOf({_dafny.string_of(self.ids)})'
    def __eq__(self, __o: object) -> bool:
        return isinstance(__o, ResPart_PartOneOf) and self.ids == __o.ids
    def __hash__(self) -> int:
        return super().__hash__()

class ResPart_PartRelated(ResPart, NamedTuple('PartRelated', [('rel', Any), ('anchor', Any)])):
    def __dafnystr__(self) -> str:
        return f'GoalIr.ResPart.PartRelated({self.rel.VerbatimString(True)}, {self.anchor.VerbatimString(True)})'
    def __eq__(self, __o: object) -> bool:
        return isinstance(__o, ResPart_PartRelated) and self.rel == __o.rel and self.anchor == __o.anchor
    def __hash__(self) -> int:
        return super().__hash__()


class ResSel:
    @classmethod
    def default(cls, ):
        return lambda: ResSel_Exact(_dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "")))
    def __ne__(self, __o: object) -> bool:
        return not self.__eq__(__o)
    @property
    def is_Exact(self) -> bool:
        return isinstance(self, ResSel_Exact)
    @property
    def is_OneOf(self) -> bool:
        return isinstance(self, ResSel_OneOf)
    @property
    def is_Related(self) -> bool:
        return isinstance(self, ResSel_Related)
    @property
    def is_AnyRes(self) -> bool:
        return isinstance(self, ResSel_AnyRes)
    @property
    def is_AllOf(self) -> bool:
        return isinstance(self, ResSel_AllOf)

class ResSel_Exact(ResSel, NamedTuple('Exact', [('id_', Any)])):
    def __dafnystr__(self) -> str:
        return f'GoalIr.ResSel.Exact({self.id_.VerbatimString(True)})'
    def __eq__(self, __o: object) -> bool:
        return isinstance(__o, ResSel_Exact) and self.id_ == __o.id_
    def __hash__(self) -> int:
        return super().__hash__()

class ResSel_OneOf(ResSel, NamedTuple('OneOf', [('ids', Any)])):
    def __dafnystr__(self) -> str:
        return f'GoalIr.ResSel.OneOf({_dafny.string_of(self.ids)})'
    def __eq__(self, __o: object) -> bool:
        return isinstance(__o, ResSel_OneOf) and self.ids == __o.ids
    def __hash__(self) -> int:
        return super().__hash__()

class ResSel_Related(ResSel, NamedTuple('Related', [('rel', Any), ('anchor', Any)])):
    def __dafnystr__(self) -> str:
        return f'GoalIr.ResSel.Related({self.rel.VerbatimString(True)}, {self.anchor.VerbatimString(True)})'
    def __eq__(self, __o: object) -> bool:
        return isinstance(__o, ResSel_Related) and self.rel == __o.rel and self.anchor == __o.anchor
    def __hash__(self) -> int:
        return super().__hash__()

class ResSel_AnyRes(ResSel, NamedTuple('AnyRes', [('reason', Any)])):
    def __dafnystr__(self) -> str:
        return f'GoalIr.ResSel.AnyRes({self.reason.VerbatimString(True)})'
    def __eq__(self, __o: object) -> bool:
        return isinstance(__o, ResSel_AnyRes) and self.reason == __o.reason
    def __hash__(self) -> int:
        return super().__hash__()

class ResSel_AllOf(ResSel, NamedTuple('AllOf', [('parts', Any)])):
    def __dafnystr__(self) -> str:
        return f'GoalIr.ResSel.AllOf({_dafny.string_of(self.parts)})'
    def __eq__(self, __o: object) -> bool:
        return isinstance(__o, ResSel_AllOf) and self.parts == __o.parts
    def __hash__(self) -> int:
        return super().__hash__()


class Grant:
    @classmethod
    def default(cls, ):
        return lambda: Grant_Grant(_dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "")), _dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "")), ResSel.default()(), Cond.default()())
    def __ne__(self, __o: object) -> bool:
        return not self.__eq__(__o)
    @property
    def is_Grant(self) -> bool:
        return isinstance(self, Grant_Grant)

class Grant_Grant(Grant, NamedTuple('Grant', [('gid', Any), ('verb', Any), ('res', Any), ('cond', Any)])):
    def __dafnystr__(self) -> str:
        return f'GoalIr.Grant.Grant({self.gid.VerbatimString(True)}, {self.verb.VerbatimString(True)}, {_dafny.string_of(self.res)}, {_dafny.string_of(self.cond)})'
    def __eq__(self, __o: object) -> bool:
        return isinstance(__o, Grant_Grant) and self.gid == __o.gid and self.verb == __o.verb and self.res == __o.res and self.cond == __o.cond
    def __hash__(self) -> int:
        return super().__hash__()


class ProhTarget:
    @classmethod
    def default(cls, ):
        return lambda: ProhTarget_PVerb(_dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "")))
    def __ne__(self, __o: object) -> bool:
        return not self.__eq__(__o)
    @property
    def is_PVerb(self) -> bool:
        return isinstance(self, ProhTarget_PVerb)
    @property
    def is_PEffect(self) -> bool:
        return isinstance(self, ProhTarget_PEffect)

class ProhTarget_PVerb(ProhTarget, NamedTuple('PVerb', [('verb', Any)])):
    def __dafnystr__(self) -> str:
        return f'GoalIr.ProhTarget.PVerb({self.verb.VerbatimString(True)})'
    def __eq__(self, __o: object) -> bool:
        return isinstance(__o, ProhTarget_PVerb) and self.verb == __o.verb
    def __hash__(self) -> int:
        return super().__hash__()

class ProhTarget_PEffect(ProhTarget, NamedTuple('PEffect', [('cls', Any)])):
    def __dafnystr__(self) -> str:
        return f'GoalIr.ProhTarget.PEffect({self.cls.VerbatimString(True)})'
    def __eq__(self, __o: object) -> bool:
        return isinstance(__o, ProhTarget_PEffect) and self.cls == __o.cls
    def __hash__(self) -> int:
        return super().__hash__()


class Prohibit:
    @classmethod
    def default(cls, ):
        return lambda: Prohibit_Prohibit(_dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "")), ProhTarget.default()(), ResSel.default()(), Cond.default()())
    def __ne__(self, __o: object) -> bool:
        return not self.__eq__(__o)
    @property
    def is_Prohibit(self) -> bool:
        return isinstance(self, Prohibit_Prohibit)

class Prohibit_Prohibit(Prohibit, NamedTuple('Prohibit', [('pid', Any), ('target', Any), ('res', Any), ('cond', Any)])):
    def __dafnystr__(self) -> str:
        return f'GoalIr.Prohibit.Prohibit({self.pid.VerbatimString(True)}, {_dafny.string_of(self.target)}, {_dafny.string_of(self.res)}, {_dafny.string_of(self.cond)})'
    def __eq__(self, __o: object) -> bool:
        return isinstance(__o, Prohibit_Prohibit) and self.pid == __o.pid and self.target == __o.target and self.res == __o.res and self.cond == __o.cond
    def __hash__(self) -> int:
        return super().__hash__()


class Agg:
    @_dafny.classproperty
    def AllSingletonConstructors(cls):
        return [Agg_ACount(), Agg_ASum(), Agg_AMax(), Agg_ADistinct()]
    @classmethod
    def default(cls, ):
        return lambda: Agg_ACount()
    def __ne__(self, __o: object) -> bool:
        return not self.__eq__(__o)
    @property
    def is_ACount(self) -> bool:
        return isinstance(self, Agg_ACount)
    @property
    def is_ASum(self) -> bool:
        return isinstance(self, Agg_ASum)
    @property
    def is_AMax(self) -> bool:
        return isinstance(self, Agg_AMax)
    @property
    def is_ADistinct(self) -> bool:
        return isinstance(self, Agg_ADistinct)

class Agg_ACount(Agg, NamedTuple('ACount', [])):
    def __dafnystr__(self) -> str:
        return f'GoalIr.Agg.ACount'
    def __eq__(self, __o: object) -> bool:
        return isinstance(__o, Agg_ACount)
    def __hash__(self) -> int:
        return super().__hash__()

class Agg_ASum(Agg, NamedTuple('ASum', [])):
    def __dafnystr__(self) -> str:
        return f'GoalIr.Agg.ASum'
    def __eq__(self, __o: object) -> bool:
        return isinstance(__o, Agg_ASum)
    def __hash__(self) -> int:
        return super().__hash__()

class Agg_AMax(Agg, NamedTuple('AMax', [])):
    def __dafnystr__(self) -> str:
        return f'GoalIr.Agg.AMax'
    def __eq__(self, __o: object) -> bool:
        return isinstance(__o, Agg_AMax)
    def __hash__(self) -> int:
        return super().__hash__()

class Agg_ADistinct(Agg, NamedTuple('ADistinct', [])):
    def __dafnystr__(self) -> str:
        return f'GoalIr.Agg.ADistinct'
    def __eq__(self, __o: object) -> bool:
        return isinstance(__o, Agg_ADistinct)
    def __hash__(self) -> int:
        return super().__hash__()


class Sel:
    @classmethod
    def default(cls, ):
        return lambda: Sel_SelGids(_dafny.Seq({}))
    def __ne__(self, __o: object) -> bool:
        return not self.__eq__(__o)
    @property
    def is_SelGids(self) -> bool:
        return isinstance(self, Sel_SelGids)
    @property
    def is_SelEffect(self) -> bool:
        return isinstance(self, Sel_SelEffect)

class Sel_SelGids(Sel, NamedTuple('SelGids', [('gids', Any)])):
    def __dafnystr__(self) -> str:
        return f'GoalIr.Sel.SelGids({_dafny.string_of(self.gids)})'
    def __eq__(self, __o: object) -> bool:
        return isinstance(__o, Sel_SelGids) and self.gids == __o.gids
    def __hash__(self) -> int:
        return super().__hash__()

class Sel_SelEffect(Sel, NamedTuple('SelEffect', [('cls', Any)])):
    def __dafnystr__(self) -> str:
        return f'GoalIr.Sel.SelEffect({self.cls.VerbatimString(True)})'
    def __eq__(self, __o: object) -> bool:
        return isinstance(__o, Sel_SelEffect) and self.cls == __o.cls
    def __hash__(self) -> int:
        return super().__hash__()


class Window:
    @classmethod
    def default(cls, ):
        return lambda: Window_WTask()
    def __ne__(self, __o: object) -> bool:
        return not self.__eq__(__o)
    @property
    def is_WTask(self) -> bool:
        return isinstance(self, Window_WTask)
    @property
    def is_WSliding(self) -> bool:
        return isinstance(self, Window_WSliding)
    @property
    def is_WPeriod(self) -> bool:
        return isinstance(self, Window_WPeriod)
    @property
    def is_WLifetime(self) -> bool:
        return isinstance(self, Window_WLifetime)

class Window_WTask(Window, NamedTuple('WTask', [])):
    def __dafnystr__(self) -> str:
        return f'GoalIr.Window.WTask'
    def __eq__(self, __o: object) -> bool:
        return isinstance(__o, Window_WTask)
    def __hash__(self) -> int:
        return super().__hash__()

class Window_WSliding(Window, NamedTuple('WSliding', [('ms', Any)])):
    def __dafnystr__(self) -> str:
        return f'GoalIr.Window.WSliding({_dafny.string_of(self.ms)})'
    def __eq__(self, __o: object) -> bool:
        return isinstance(__o, Window_WSliding) and self.ms == __o.ms
    def __hash__(self) -> int:
        return super().__hash__()

class Window_WPeriod(Window, NamedTuple('WPeriod', [('ms', Any), ('t0', Any)])):
    def __dafnystr__(self) -> str:
        return f'GoalIr.Window.WPeriod({_dafny.string_of(self.ms)}, {_dafny.string_of(self.t0)})'
    def __eq__(self, __o: object) -> bool:
        return isinstance(__o, Window_WPeriod) and self.ms == __o.ms and self.t0 == __o.t0
    def __hash__(self) -> int:
        return super().__hash__()

class Window_WLifetime(Window, NamedTuple('WLifetime', [])):
    def __dafnystr__(self) -> str:
        return f'GoalIr.Window.WLifetime'
    def __eq__(self, __o: object) -> bool:
        return isinstance(__o, Window_WLifetime)
    def __hash__(self) -> int:
        return super().__hash__()


class Scope:
    @classmethod
    def default(cls, ):
        return lambda: Scope_SSession()
    def __ne__(self, __o: object) -> bool:
        return not self.__eq__(__o)
    @property
    def is_SSession(self) -> bool:
        return isinstance(self, Scope_SSession)
    @property
    def is_SPrincipal(self) -> bool:
        return isinstance(self, Scope_SPrincipal)
    @property
    def is_SOrg(self) -> bool:
        return isinstance(self, Scope_SOrg)
    @property
    def is_SFleet(self) -> bool:
        return isinstance(self, Scope_SFleet)

class Scope_SSession(Scope, NamedTuple('SSession', [])):
    def __dafnystr__(self) -> str:
        return f'GoalIr.Scope.SSession'
    def __eq__(self, __o: object) -> bool:
        return isinstance(__o, Scope_SSession)
    def __hash__(self) -> int:
        return super().__hash__()

class Scope_SPrincipal(Scope, NamedTuple('SPrincipal', [])):
    def __dafnystr__(self) -> str:
        return f'GoalIr.Scope.SPrincipal'
    def __eq__(self, __o: object) -> bool:
        return isinstance(__o, Scope_SPrincipal)
    def __hash__(self) -> int:
        return super().__hash__()

class Scope_SOrg(Scope, NamedTuple('SOrg', [])):
    def __dafnystr__(self) -> str:
        return f'GoalIr.Scope.SOrg'
    def __eq__(self, __o: object) -> bool:
        return isinstance(__o, Scope_SOrg)
    def __hash__(self) -> int:
        return super().__hash__()

class Scope_SFleet(Scope, NamedTuple('SFleet', [('agents', Any)])):
    def __dafnystr__(self) -> str:
        return f'GoalIr.Scope.SFleet({_dafny.string_of(self.agents)})'
    def __eq__(self, __o: object) -> bool:
        return isinstance(__o, Scope_SFleet) and self.agents == __o.agents
    def __hash__(self) -> int:
        return super().__hash__()


class OnExceed:
    @_dafny.classproperty
    def AllSingletonConstructors(cls):
        return [OnExceed_OnDeny(), OnExceed_OnEscalate()]
    @classmethod
    def default(cls, ):
        return lambda: OnExceed_OnDeny()
    def __ne__(self, __o: object) -> bool:
        return not self.__eq__(__o)
    @property
    def is_OnDeny(self) -> bool:
        return isinstance(self, OnExceed_OnDeny)
    @property
    def is_OnEscalate(self) -> bool:
        return isinstance(self, OnExceed_OnEscalate)

class OnExceed_OnDeny(OnExceed, NamedTuple('OnDeny', [])):
    def __dafnystr__(self) -> str:
        return f'GoalIr.OnExceed.OnDeny'
    def __eq__(self, __o: object) -> bool:
        return isinstance(__o, OnExceed_OnDeny)
    def __hash__(self) -> int:
        return super().__hash__()

class OnExceed_OnEscalate(OnExceed, NamedTuple('OnEscalate', [])):
    def __dafnystr__(self) -> str:
        return f'GoalIr.OnExceed.OnEscalate'
    def __eq__(self, __o: object) -> bool:
        return isinstance(__o, OnExceed_OnEscalate)
    def __hash__(self) -> int:
        return super().__hash__()


class BCore:
    @classmethod
    def default(cls, ):
        return lambda: BCore_BCore(Agg.default()(), Term.default()(), _dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "")), Window.default()(), Scope.default()(), Q.default()(), OnExceed.default()())
    def __ne__(self, __o: object) -> bool:
        return not self.__eq__(__o)
    @property
    def is_BCore(self) -> bool:
        return isinstance(self, BCore_BCore)

class BCore_BCore(BCore, NamedTuple('BCore', [('agg', Any), ('value', Any), ('key', Any), ('window', Any), ('scope', Any), ('cap', Any), ('onExceed', Any)])):
    def __dafnystr__(self) -> str:
        return f'GoalIr.BCore.BCore({_dafny.string_of(self.agg)}, {_dafny.string_of(self.value)}, {self.key.VerbatimString(True)}, {_dafny.string_of(self.window)}, {_dafny.string_of(self.scope)}, {_dafny.string_of(self.cap)}, {_dafny.string_of(self.onExceed)})'
    def __eq__(self, __o: object) -> bool:
        return isinstance(__o, BCore_BCore) and self.agg == __o.agg and self.value == __o.value and self.key == __o.key and self.window == __o.window and self.scope == __o.scope and self.cap == __o.cap and self.onExceed == __o.onExceed
    def __hash__(self) -> int:
        return super().__hash__()


class Bound:
    @classmethod
    def default(cls, ):
        return lambda: Bound_Bound(_dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "")), Sel.default()(), BCore.default()())
    def __ne__(self, __o: object) -> bool:
        return not self.__eq__(__o)
    @property
    def is_Bound(self) -> bool:
        return isinstance(self, Bound_Bound)

class Bound_Bound(Bound, NamedTuple('Bound', [('bid', Any), ('sel', Any), ('core', Any)])):
    def __dafnystr__(self) -> str:
        return f'GoalIr.Bound.Bound({self.bid.VerbatimString(True)}, {_dafny.string_of(self.sel)}, {_dafny.string_of(self.core)})'
    def __eq__(self, __o: object) -> bool:
        return isinstance(__o, Bound_Bound) and self.bid == __o.bid and self.sel == __o.sel and self.core == __o.core
    def __hash__(self) -> int:
        return super().__hash__()


class Validity:
    @classmethod
    def default(cls, ):
        return lambda: Validity_Validity(int(0), int(0), int(0))
    def __ne__(self, __o: object) -> bool:
        return not self.__eq__(__o)
    @property
    def is_Validity(self) -> bool:
        return isinstance(self, Validity_Validity)

class Validity_Validity(Validity, NamedTuple('Validity', [('notBefore', Any), ('notAfter', Any), ('maxIdle', Any)])):
    def __dafnystr__(self) -> str:
        return f'GoalIr.Validity.Validity({_dafny.string_of(self.notBefore)}, {_dafny.string_of(self.notAfter)}, {_dafny.string_of(self.maxIdle)})'
    def __eq__(self, __o: object) -> bool:
        return isinstance(__o, Validity_Validity) and self.notBefore == __o.notBefore and self.notAfter == __o.notAfter and self.maxIdle == __o.maxIdle
    def __hash__(self) -> int:
        return super().__hash__()


class Delegation:
    @classmethod
    def default(cls, ):
        return lambda: Delegation_Delegation(int(0), False, _dafny.Seq({}))
    def __ne__(self, __o: object) -> bool:
        return not self.__eq__(__o)
    @property
    def is_Delegation(self) -> bool:
        return isinstance(self, Delegation_Delegation)

class Delegation_Delegation(Delegation, NamedTuple('Delegation', [('maxDepth', Any), ('narrowOnly', Any), ('mayTouch', Any)])):
    def __dafnystr__(self) -> str:
        return f'GoalIr.Delegation.Delegation({_dafny.string_of(self.maxDepth)}, {_dafny.string_of(self.narrowOnly)}, {_dafny.string_of(self.mayTouch)})'
    def __eq__(self, __o: object) -> bool:
        return isinstance(__o, Delegation_Delegation) and self.maxDepth == __o.maxDepth and self.narrowOnly == __o.narrowOnly and self.mayTouch == __o.mayTouch
    def __hash__(self) -> int:
        return super().__hash__()


class Hole:
    @classmethod
    def default(cls, ):
        return lambda: Hole_Hole(_dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "")), _dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "")), _dafny.Seq({}), _dafny.Seq({}), False)
    def __ne__(self, __o: object) -> bool:
        return not self.__eq__(__o)
    @property
    def is_Hole(self) -> bool:
        return isinstance(self, Hole_Hole)

class Hole_Hole(Hole, NamedTuple('Hole', [('hid', Any), ('q', Any), ('domain', Any), ('affects', Any), ('global_', Any)])):
    def __dafnystr__(self) -> str:
        return f'GoalIr.Hole.Hole({self.hid.VerbatimString(True)}, {self.q.VerbatimString(True)}, {_dafny.string_of(self.domain)}, {_dafny.string_of(self.affects)}, {_dafny.string_of(self.global_)})'
    def __eq__(self, __o: object) -> bool:
        return isinstance(__o, Hole_Hole) and self.hid == __o.hid and self.q == __o.q and self.domain == __o.domain and self.affects == __o.affects and self.global_ == __o.global_
    def __hash__(self) -> int:
        return super().__hash__()


class Goal:
    @classmethod
    def default(cls, ):
        return lambda: Goal_Goal(int(0), _dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "")), _dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "")), _dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "")), _dafny.Seq({}), _dafny.Seq({}), _dafny.Seq({}), _dafny.Seq({}), Validity.default()(), Delegation.default()(), _dafny.Seq({}), _dafny.Seq({}), _dafny.Seq({}))
    def __ne__(self, __o: object) -> bool:
        return not self.__eq__(__o)
    @property
    def is_Goal(self) -> bool:
        return isinstance(self, Goal_Goal)

class Goal_Goal(Goal, NamedTuple('Goal', [('v', Any), ('principal', Any), ('ontDigest', Any), ('nlDigest', Any), ('sources', Any), ('grants', Any), ('prohibits', Any), ('bounds', Any), ('validity', Any), ('deleg', Any), ('escalateOn', Any), ('wildcardAck', Any), ('holes', Any)])):
    def __dafnystr__(self) -> str:
        return f'GoalIr.Goal.Goal({_dafny.string_of(self.v)}, {self.principal.VerbatimString(True)}, {self.ontDigest.VerbatimString(True)}, {self.nlDigest.VerbatimString(True)}, {_dafny.string_of(self.sources)}, {_dafny.string_of(self.grants)}, {_dafny.string_of(self.prohibits)}, {_dafny.string_of(self.bounds)}, {_dafny.string_of(self.validity)}, {_dafny.string_of(self.deleg)}, {_dafny.string_of(self.escalateOn)}, {_dafny.string_of(self.wildcardAck)}, {_dafny.string_of(self.holes)})'
    def __eq__(self, __o: object) -> bool:
        return isinstance(__o, Goal_Goal) and self.v == __o.v and self.principal == __o.principal and self.ontDigest == __o.ontDigest and self.nlDigest == __o.nlDigest and self.sources == __o.sources and self.grants == __o.grants and self.prohibits == __o.prohibits and self.bounds == __o.bounds and self.validity == __o.validity and self.deleg == __o.deleg and self.escalateOn == __o.escalateOn and self.wildcardAck == __o.wildcardAck and self.holes == __o.holes
    def __hash__(self) -> int:
        return super().__hash__()


class ParamDecl:
    @classmethod
    def default(cls, ):
        return lambda: ParamDecl_ParamDecl(_dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "")), Ty.default()())
    def __ne__(self, __o: object) -> bool:
        return not self.__eq__(__o)
    @property
    def is_ParamDecl(self) -> bool:
        return isinstance(self, ParamDecl_ParamDecl)

class ParamDecl_ParamDecl(ParamDecl, NamedTuple('ParamDecl', [('path', Any), ('ty', Any)])):
    def __dafnystr__(self) -> str:
        return f'GoalIr.ParamDecl.ParamDecl({self.path.VerbatimString(True)}, {_dafny.string_of(self.ty)})'
    def __eq__(self, __o: object) -> bool:
        return isinstance(__o, ParamDecl_ParamDecl) and self.path == __o.path and self.ty == __o.ty
    def __hash__(self) -> int:
        return super().__hash__()


class VerbDecl:
    @classmethod
    def default(cls, ):
        return lambda: VerbDecl_VerbDecl(_dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "")), _dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "")), _dafny.Seq({}))
    def __ne__(self, __o: object) -> bool:
        return not self.__eq__(__o)
    @property
    def is_VerbDecl(self) -> bool:
        return isinstance(self, VerbDecl_VerbDecl)

class VerbDecl_VerbDecl(VerbDecl, NamedTuple('VerbDecl', [('verb', Any), ('cls', Any), ('params', Any)])):
    def __dafnystr__(self) -> str:
        return f'GoalIr.VerbDecl.VerbDecl({self.verb.VerbatimString(True)}, {self.cls.VerbatimString(True)}, {_dafny.string_of(self.params)})'
    def __eq__(self, __o: object) -> bool:
        return isinstance(__o, VerbDecl_VerbDecl) and self.verb == __o.verb and self.cls == __o.cls and self.params == __o.params
    def __hash__(self) -> int:
        return super().__hash__()


class RelDecl:
    @classmethod
    def default(cls, ):
        return lambda: RelDecl_RelDecl(_dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "")), _dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "")), _dafny.Seq({}))
    def __ne__(self, __o: object) -> bool:
        return not self.__eq__(__o)
    @property
    def is_RelDecl(self) -> bool:
        return isinstance(self, RelDecl_RelDecl)

class RelDecl_RelDecl(RelDecl, NamedTuple('RelDecl', [('rel', Any), ('anchor', Any), ('members', Any)])):
    def __dafnystr__(self) -> str:
        return f'GoalIr.RelDecl.RelDecl({self.rel.VerbatimString(True)}, {self.anchor.VerbatimString(True)}, {_dafny.string_of(self.members)})'
    def __eq__(self, __o: object) -> bool:
        return isinstance(__o, RelDecl_RelDecl) and self.rel == __o.rel and self.anchor == __o.anchor and self.members == __o.members
    def __hash__(self) -> int:
        return super().__hash__()


class Ontology:
    @classmethod
    def default(cls, ):
        return lambda: Ontology_Ontology(_dafny.Seq({}), _dafny.Seq({}))
    def __ne__(self, __o: object) -> bool:
        return not self.__eq__(__o)
    @property
    def is_Ontology(self) -> bool:
        return isinstance(self, Ontology_Ontology)

class Ontology_Ontology(Ontology, NamedTuple('Ontology', [('verbs', Any), ('rels', Any)])):
    def __dafnystr__(self) -> str:
        return f'GoalIr.Ontology.Ontology({_dafny.string_of(self.verbs)}, {_dafny.string_of(self.rels)})'
    def __eq__(self, __o: object) -> bool:
        return isinstance(__o, Ontology_Ontology) and self.verbs == __o.verbs and self.rels == __o.rels
    def __hash__(self) -> int:
        return super().__hash__()


class Act:
    @classmethod
    def default(cls, ):
        return lambda: Act_Act(_dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "")), _dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "")), _dafny.Map({}), int(0), _dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "")), _dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "")), _dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "")), _dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "")), int(0))
    def __ne__(self, __o: object) -> bool:
        return not self.__eq__(__o)
    @property
    def is_Act(self) -> bool:
        return isinstance(self, Act_Act)

class Act_Act(Act, NamedTuple('Act', [('verb', Any), ('res', Any), ('params', Any), ('t', Any), ('sess', Any), ('prin', Any), ('org', Any), ('agent', Any), ('depth', Any)])):
    def __dafnystr__(self) -> str:
        return f'GoalIr.Act.Act({self.verb.VerbatimString(True)}, {self.res.VerbatimString(True)}, {_dafny.string_of(self.params)}, {_dafny.string_of(self.t)}, {self.sess.VerbatimString(True)}, {self.prin.VerbatimString(True)}, {self.org.VerbatimString(True)}, {self.agent.VerbatimString(True)}, {_dafny.string_of(self.depth)})'
    def __eq__(self, __o: object) -> bool:
        return isinstance(__o, Act_Act) and self.verb == __o.verb and self.res == __o.res and self.params == __o.params and self.t == __o.t and self.sess == __o.sess and self.prin == __o.prin and self.org == __o.org and self.agent == __o.agent and self.depth == __o.depth
    def __hash__(self) -> int:
        return super().__hash__()


class Adm:
    @classmethod
    def default(cls, ):
        return lambda: Adm_Adm(_dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "")), Act.default()())
    def __ne__(self, __o: object) -> bool:
        return not self.__eq__(__o)
    @property
    def is_Adm(self) -> bool:
        return isinstance(self, Adm_Adm)

class Adm_Adm(Adm, NamedTuple('Adm', [('gid', Any), ('act', Any)])):
    def __dafnystr__(self) -> str:
        return f'GoalIr.Adm.Adm({self.gid.VerbatimString(True)}, {_dafny.string_of(self.act)})'
    def __eq__(self, __o: object) -> bool:
        return isinstance(__o, Adm_Adm) and self.gid == __o.gid and self.act == __o.act
    def __hash__(self) -> int:
        return super().__hash__()


class Hist:
    @classmethod
    def default(cls, ):
        return lambda: Hist_Hist(_dafny.Seq({}), int(0), _dafny.Map({}))
    def __ne__(self, __o: object) -> bool:
        return not self.__eq__(__o)
    @property
    def is_Hist(self) -> bool:
        return isinstance(self, Hist_Hist)

class Hist_Hist(Hist, NamedTuple('Hist', [('adms', Any), ('last', Any), ('aggs', Any)])):
    def __dafnystr__(self) -> str:
        return f'GoalIr.Hist.Hist({_dafny.string_of(self.adms)}, {_dafny.string_of(self.last)}, {_dafny.string_of(self.aggs)})'
    def __eq__(self, __o: object) -> bool:
        return isinstance(__o, Hist_Hist) and self.adms == __o.adms and self.last == __o.last and self.aggs == __o.aggs
    def __hash__(self) -> int:
        return super().__hash__()


class ResPat:
    @classmethod
    def default(cls, ):
        return lambda: ResPat_PStar()
    def __ne__(self, __o: object) -> bool:
        return not self.__eq__(__o)
    @property
    def is_PStar(self) -> bool:
        return isinstance(self, ResPat_PStar)
    @property
    def is_PSet(self) -> bool:
        return isinstance(self, ResPat_PSet)

class ResPat_PStar(ResPat, NamedTuple('PStar', [])):
    def __dafnystr__(self) -> str:
        return f'GoalIr.ResPat.PStar'
    def __eq__(self, __o: object) -> bool:
        return isinstance(__o, ResPat_PStar)
    def __hash__(self) -> int:
        return super().__hash__()

class ResPat_PSet(ResPat, NamedTuple('PSet', [('ids', Any)])):
    def __dafnystr__(self) -> str:
        return f'GoalIr.ResPat.PSet({_dafny.string_of(self.ids)})'
    def __eq__(self, __o: object) -> bool:
        return isinstance(__o, ResPat_PSet) and self.ids == __o.ids
    def __hash__(self) -> int:
        return super().__hash__()


class LSel:
    @classmethod
    def default(cls, ):
        return lambda: LSel_LSel(_dafny.Seq({}), _dafny.Seq({}))
    def __ne__(self, __o: object) -> bool:
        return not self.__eq__(__o)
    @property
    def is_LSel(self) -> bool:
        return isinstance(self, LSel_LSel)

class LSel_LSel(LSel, NamedTuple('LSel', [('gids', Any), ('verbs', Any)])):
    def __dafnystr__(self) -> str:
        return f'GoalIr.LSel.LSel({_dafny.string_of(self.gids)}, {_dafny.string_of(self.verbs)})'
    def __eq__(self, __o: object) -> bool:
        return isinstance(__o, LSel_LSel) and self.gids == __o.gids and self.verbs == __o.verbs
    def __hash__(self) -> int:
        return super().__hash__()

