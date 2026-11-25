import sys
from typing import Callable, Any, TypeVar, NamedTuple
from math import floor
from itertools import count

import atlas_pca.goal_kernel_gen.module_ as module_
import atlas_pca.goal_kernel_gen._dafny as _dafny
import atlas_pca.goal_kernel_gen.System_ as System_
import atlas_pca.goal_kernel_gen.GoalIr as GoalIr
import atlas_pca.goal_kernel_gen.GoalCompile as GoalCompile
import atlas_pca.goal_kernel_gen.GoalWitness as GoalWitness

# Module: GoalRender

class default__:
    def  __init__(self):
        pass

    @staticmethod
    def EncStr(s):
        return _dafny.SeqWithoutIsStrInference([Tok_TS(s)])

    @staticmethod
    def DecStr(ts):
        if ((len(ts)) > (0)) and (((ts)[0]).is_TS):
            return PR_Ok(((ts)[0]).s, _dafny.SeqWithoutIsStrInference((ts)[1::]))
        elif True:
            return PR_Fail()

    @staticmethod
    def EncInt(i):
        return _dafny.SeqWithoutIsStrInference([Tok_TI(i)])

    @staticmethod
    def DecInt(ts):
        if ((len(ts)) > (0)) and (((ts)[0]).is_TI):
            return PR_Ok(((ts)[0]).i, _dafny.SeqWithoutIsStrInference((ts)[1::]))
        elif True:
            return PR_Fail()

    @staticmethod
    def EncBool(b):
        return _dafny.SeqWithoutIsStrInference([Tok_TI((1 if b else 0))])

    @staticmethod
    def DecBool(ts):
        if (((len(ts)) > (0)) and (((ts)[0]).is_TI)) and (((((ts)[0]).i) == (0)) or ((((ts)[0]).i) == (1))):
            return PR_Ok((((ts)[0]).i) == (1), _dafny.SeqWithoutIsStrInference((ts)[1::]))
        elif True:
            return PR_Fail()

    @staticmethod
    def EncUnit(u):
        source0_ = u
        if True:
            if source0_.is_UMoney:
                d_0_c_ = source0_.ccy
                return (_dafny.SeqWithoutIsStrInference([Tok_TKw(300)])) + (default__.EncStr(d_0_c_))
        if True:
            if source0_.is_UCount:
                return _dafny.SeqWithoutIsStrInference([Tok_TKw(301)])
        if True:
            if source0_.is_UDuration:
                return _dafny.SeqWithoutIsStrInference([Tok_TKw(302)])
        if True:
            if source0_.is_UInstant:
                return _dafny.SeqWithoutIsStrInference([Tok_TKw(303)])
        if True:
            if source0_.is_UBytes:
                return _dafny.SeqWithoutIsStrInference([Tok_TKw(304)])
        if True:
            return _dafny.SeqWithoutIsStrInference([Tok_TKw(305)])

    @staticmethod
    def DecUnit(ts):
        if ((len(ts)) == (0)) or (not(((ts)[0]).is_TKw)):
            return PR_Fail()
        elif (((ts)[0]).k) == (300):
            source0_ = default__.DecStr(_dafny.SeqWithoutIsStrInference((ts)[1::]))
            if True:
                if source0_.is_Ok:
                    d_0_c_ = source0_.v
                    d_1_r_ = source0_.rest
                    return PR_Ok(GoalIr.Unit_UMoney(d_0_c_), d_1_r_)
            if True:
                return PR_Fail()
        elif (((ts)[0]).k) == (301):
            return PR_Ok(GoalIr.Unit_UCount(), _dafny.SeqWithoutIsStrInference((ts)[1::]))
        elif (((ts)[0]).k) == (302):
            return PR_Ok(GoalIr.Unit_UDuration(), _dafny.SeqWithoutIsStrInference((ts)[1::]))
        elif (((ts)[0]).k) == (303):
            return PR_Ok(GoalIr.Unit_UInstant(), _dafny.SeqWithoutIsStrInference((ts)[1::]))
        elif (((ts)[0]).k) == (304):
            return PR_Ok(GoalIr.Unit_UBytes(), _dafny.SeqWithoutIsStrInference((ts)[1::]))
        elif (((ts)[0]).k) == (305):
            return PR_Ok(GoalIr.Unit_URatio(), _dafny.SeqWithoutIsStrInference((ts)[1::]))
        elif True:
            return PR_Fail()

    @staticmethod
    def EncQ(q):
        return (default__.EncUnit((q).u)) + (default__.EncInt((q).n))

    @staticmethod
    def DecQ(ts):
        source0_ = default__.DecUnit(ts)
        if True:
            if source0_.is_Fail:
                return PR_Fail()
        if True:
            d_0_u_ = source0_.v
            d_1_r_ = source0_.rest
            source1_ = default__.DecInt(d_1_r_)
            if True:
                if source1_.is_Fail:
                    return PR_Fail()
            if True:
                d_2_n_ = source1_.v
                d_3_r2_ = source1_.rest
                return PR_Ok(GoalIr.Q_Q(d_0_u_, d_2_n_), d_3_r2_)

    @staticmethod
    def EncTy(t):
        source0_ = t
        if True:
            if source0_.is_TyQ:
                d_0_u_ = source0_.u
                return (_dafny.SeqWithoutIsStrInference([Tok_TKw(310)])) + (default__.EncUnit(d_0_u_))
        if True:
            return _dafny.SeqWithoutIsStrInference([Tok_TKw(311)])

    @staticmethod
    def DecTy(ts):
        if ((len(ts)) == (0)) or (not(((ts)[0]).is_TKw)):
            return PR_Fail()
        elif (((ts)[0]).k) == (310):
            source0_ = default__.DecUnit(_dafny.SeqWithoutIsStrInference((ts)[1::]))
            if True:
                if source0_.is_Ok:
                    d_0_u_ = source0_.v
                    d_1_r_ = source0_.rest
                    return PR_Ok(GoalIr.Ty_TyQ(d_0_u_), d_1_r_)
            if True:
                return PR_Fail()
        elif (((ts)[0]).k) == (311):
            return PR_Ok(GoalIr.Ty_TyS(), _dafny.SeqWithoutIsStrInference((ts)[1::]))
        elif True:
            return PR_Fail()

    @staticmethod
    def EncAtom(a):
        source0_ = a
        if True:
            if source0_.is_AQ:
                d_0_q_ = source0_.q
                return (_dafny.SeqWithoutIsStrInference([Tok_TKw(320)])) + (default__.EncQ(d_0_q_))
        if True:
            d_1_s_ = source0_.s
            return (_dafny.SeqWithoutIsStrInference([Tok_TKw(321)])) + (default__.EncStr(d_1_s_))

    @staticmethod
    def DecAtom(ts):
        if ((len(ts)) == (0)) or (not(((ts)[0]).is_TKw)):
            return PR_Fail()
        elif (((ts)[0]).k) == (320):
            source0_ = default__.DecQ(_dafny.SeqWithoutIsStrInference((ts)[1::]))
            if True:
                if source0_.is_Ok:
                    d_0_q_ = source0_.v
                    d_1_r_ = source0_.rest
                    return PR_Ok(GoalIr.Atom_AQ(d_0_q_), d_1_r_)
            if True:
                return PR_Fail()
        elif (((ts)[0]).k) == (321):
            source1_ = default__.DecStr(_dafny.SeqWithoutIsStrInference((ts)[1::]))
            if True:
                if source1_.is_Ok:
                    d_2_s_ = source1_.v
                    d_3_r_ = source1_.rest
                    return PR_Ok(GoalIr.Atom_AS(d_2_s_), d_3_r_)
            if True:
                return PR_Fail()
        elif True:
            return PR_Fail()

    @staticmethod
    def EncAtomsElems(xs):
        d_0___accumulator_ = _dafny.SeqWithoutIsStrInference([])
        while True:
            with _dafny.label():
                if (len(xs)) == (0):
                    return (d_0___accumulator_) + (_dafny.SeqWithoutIsStrInference([]))
                elif True:
                    d_0___accumulator_ = (d_0___accumulator_) + (default__.EncAtom((xs)[0]))
                    in0_ = _dafny.SeqWithoutIsStrInference((xs)[1::])
                    xs = in0_
                    raise _dafny.TailCall()
                break

    @staticmethod
    def EncAtoms(xs):
        return (_dafny.SeqWithoutIsStrInference([Tok_TI(len(xs))])) + (default__.EncAtomsElems(xs))

    @staticmethod
    def DecAtomsElems(ts, n):
        if (n) == (0):
            return PR_Ok(_dafny.SeqWithoutIsStrInference([]), ts)
        elif True:
            source0_ = default__.DecAtom(ts)
            if True:
                if source0_.is_Fail:
                    return PR_Fail()
            if True:
                d_0_x_ = source0_.v
                d_1_r_ = source0_.rest
                source1_ = default__.DecAtomsElems(d_1_r_, (n) - (1))
                if True:
                    if source1_.is_Fail:
                        return PR_Fail()
                if True:
                    d_2_xs_ = source1_.v
                    d_3_r2_ = source1_.rest
                    return PR_Ok((_dafny.SeqWithoutIsStrInference([d_0_x_])) + (d_2_xs_), d_3_r2_)

    @staticmethod
    def DecAtoms(ts):
        if (((len(ts)) > (0)) and (((ts)[0]).is_TI)) and ((((ts)[0]).i) >= (0)):
            return default__.DecAtomsElems(_dafny.SeqWithoutIsStrInference((ts)[1::]), ((ts)[0]).i)
        elif True:
            return PR_Fail()

    @staticmethod
    def EncV(v):
        source0_ = v
        if True:
            if source0_.is_VQ:
                d_0_q_ = source0_.q
                return (_dafny.SeqWithoutIsStrInference([Tok_TKw(330)])) + (default__.EncQ(d_0_q_))
        if True:
            if source0_.is_VS:
                d_1_s_ = source0_.s
                return (_dafny.SeqWithoutIsStrInference([Tok_TKw(331)])) + (default__.EncStr(d_1_s_))
        if True:
            d_2_items_ = source0_.items
            return (_dafny.SeqWithoutIsStrInference([Tok_TKw(332)])) + (default__.EncAtoms(d_2_items_))

    @staticmethod
    def DecV(ts):
        if ((len(ts)) == (0)) or (not(((ts)[0]).is_TKw)):
            return PR_Fail()
        elif (((ts)[0]).k) == (330):
            source0_ = default__.DecQ(_dafny.SeqWithoutIsStrInference((ts)[1::]))
            if True:
                if source0_.is_Ok:
                    d_0_q_ = source0_.v
                    d_1_r_ = source0_.rest
                    return PR_Ok(GoalIr.V_VQ(d_0_q_), d_1_r_)
            if True:
                return PR_Fail()
        elif (((ts)[0]).k) == (331):
            source1_ = default__.DecStr(_dafny.SeqWithoutIsStrInference((ts)[1::]))
            if True:
                if source1_.is_Ok:
                    d_2_s_ = source1_.v
                    d_3_r_ = source1_.rest
                    return PR_Ok(GoalIr.V_VS(d_2_s_), d_3_r_)
            if True:
                return PR_Fail()
        elif (((ts)[0]).k) == (332):
            source2_ = default__.DecAtoms(_dafny.SeqWithoutIsStrInference((ts)[1::]))
            if True:
                if source2_.is_Ok:
                    d_4_xs_ = source2_.v
                    d_5_r_ = source2_.rest
                    return PR_Ok(GoalIr.V_VSet(d_4_xs_), d_5_r_)
            if True:
                return PR_Fail()
        elif True:
            return PR_Fail()

    @staticmethod
    def EncTerm(t):
        source0_ = t
        if True:
            if source0_.is_Param:
                d_0_p_ = source0_.path
                d_1_ty_ = source0_.ty
                return (_dafny.SeqWithoutIsStrInference([Tok_TKw(340)])) + ((default__.EncStr(d_0_p_)) + (default__.EncTy(d_1_ty_)))
        if True:
            if source0_.is_Lit:
                d_2_v_ = source0_.v
                return (_dafny.SeqWithoutIsStrInference([Tok_TKw(341)])) + (default__.EncV(d_2_v_))
        if True:
            d_3_b_ = source0_.bid
            d_4_u_ = source0_.u
            return (_dafny.SeqWithoutIsStrInference([Tok_TKw(342)])) + ((default__.EncStr(d_3_b_)) + (default__.EncUnit(d_4_u_)))

    @staticmethod
    def DecTerm(ts):
        if ((len(ts)) == (0)) or (not(((ts)[0]).is_TKw)):
            return PR_Fail()
        elif (((ts)[0]).k) == (340):
            source0_ = default__.DecStr(_dafny.SeqWithoutIsStrInference((ts)[1::]))
            if True:
                if source0_.is_Fail:
                    return PR_Fail()
            if True:
                d_0_p_ = source0_.v
                d_1_r1_ = source0_.rest
                source1_ = default__.DecTy(d_1_r1_)
                if True:
                    if source1_.is_Fail:
                        return PR_Fail()
                if True:
                    d_2_ty_ = source1_.v
                    d_3_r2_ = source1_.rest
                    return PR_Ok(GoalIr.Term_Param(d_0_p_, d_2_ty_), d_3_r2_)
        elif (((ts)[0]).k) == (341):
            source2_ = default__.DecV(_dafny.SeqWithoutIsStrInference((ts)[1::]))
            if True:
                if source2_.is_Ok:
                    d_4_v_ = source2_.v
                    d_5_r_ = source2_.rest
                    return PR_Ok(GoalIr.Term_Lit(d_4_v_), d_5_r_)
            if True:
                return PR_Fail()
        elif (((ts)[0]).k) == (342):
            source3_ = default__.DecStr(_dafny.SeqWithoutIsStrInference((ts)[1::]))
            if True:
                if source3_.is_Fail:
                    return PR_Fail()
            if True:
                d_6_b_ = source3_.v
                d_7_r1_ = source3_.rest
                source4_ = default__.DecUnit(d_7_r1_)
                if True:
                    if source4_.is_Fail:
                        return PR_Fail()
                if True:
                    d_8_u_ = source4_.v
                    d_9_r2_ = source4_.rest
                    return PR_Ok(GoalIr.Term_HistAgg(d_6_b_, d_8_u_), d_9_r2_)
        elif True:
            return PR_Fail()

    @staticmethod
    def OpIdx(op):
        source0_ = op
        if True:
            if source0_.is_Eq:
                return 0
        if True:
            if source0_.is_Ne:
                return 1
        if True:
            if source0_.is_Lt:
                return 2
        if True:
            if source0_.is_Lte:
                return 3
        if True:
            if source0_.is_Gt:
                return 4
        if True:
            if source0_.is_Gte:
                return 5
        if True:
            if source0_.is_In:
                return 6
        if True:
            return 7

    @staticmethod
    def EncOp(op):
        return _dafny.SeqWithoutIsStrInference([Tok_TKw((350) + (default__.OpIdx(op)))])

    @staticmethod
    def DecOp(ts):
        if ((len(ts)) == (0)) or (not(((ts)[0]).is_TKw)):
            return PR_Fail()
        elif (((ts)[0]).k) == (350):
            return PR_Ok(GoalIr.Op_Eq(), _dafny.SeqWithoutIsStrInference((ts)[1::]))
        elif (((ts)[0]).k) == (351):
            return PR_Ok(GoalIr.Op_Ne(), _dafny.SeqWithoutIsStrInference((ts)[1::]))
        elif (((ts)[0]).k) == (352):
            return PR_Ok(GoalIr.Op_Lt(), _dafny.SeqWithoutIsStrInference((ts)[1::]))
        elif (((ts)[0]).k) == (353):
            return PR_Ok(GoalIr.Op_Lte(), _dafny.SeqWithoutIsStrInference((ts)[1::]))
        elif (((ts)[0]).k) == (354):
            return PR_Ok(GoalIr.Op_Gt(), _dafny.SeqWithoutIsStrInference((ts)[1::]))
        elif (((ts)[0]).k) == (355):
            return PR_Ok(GoalIr.Op_Gte(), _dafny.SeqWithoutIsStrInference((ts)[1::]))
        elif (((ts)[0]).k) == (356):
            return PR_Ok(GoalIr.Op_In(), _dafny.SeqWithoutIsStrInference((ts)[1::]))
        elif (((ts)[0]).k) == (357):
            return PR_Ok(GoalIr.Op_Nin(), _dafny.SeqWithoutIsStrInference((ts)[1::]))
        elif True:
            return PR_Fail()

    @staticmethod
    def EncCond(c):
        source0_ = c
        if True:
            if source0_.is_CTrue:
                return _dafny.SeqWithoutIsStrInference([Tok_TKw(360)])
        if True:
            if source0_.is_Cmp:
                d_0_op_ = source0_.op
                d_1_l_ = source0_.l
                d_2_r_ = source0_.r
                return (_dafny.SeqWithoutIsStrInference([Tok_TKw(361)])) + ((default__.EncOp(d_0_op_)) + ((default__.EncTerm(d_1_l_)) + (default__.EncTerm(d_2_r_))))
        if True:
            if source0_.is_And:
                d_3_x_ = source0_.a
                d_4_y_ = source0_.b
                return (_dafny.SeqWithoutIsStrInference([Tok_TKw(362)])) + ((default__.EncCond(d_3_x_)) + (default__.EncCond(d_4_y_)))
        if True:
            if source0_.is_Or:
                d_5_x_ = source0_.a
                d_6_y_ = source0_.b
                return (_dafny.SeqWithoutIsStrInference([Tok_TKw(363)])) + ((default__.EncCond(d_5_x_)) + (default__.EncCond(d_6_y_)))
        if True:
            d_7_x_ = source0_.c
            return (_dafny.SeqWithoutIsStrInference([Tok_TKw(364)])) + (default__.EncCond(d_7_x_))

    @staticmethod
    def DecCond(ts, fuel):
        if (((fuel) == (0)) or ((len(ts)) == (0))) or (not(((ts)[0]).is_TKw)):
            return PR_Fail()
        elif (((ts)[0]).k) == (360):
            return PR_Ok(GoalIr.Cond_CTrue(), _dafny.SeqWithoutIsStrInference((ts)[1::]))
        elif (((ts)[0]).k) == (361):
            source0_ = default__.DecOp(_dafny.SeqWithoutIsStrInference((ts)[1::]))
            if True:
                if source0_.is_Fail:
                    return PR_Fail()
            if True:
                d_0_op_ = source0_.v
                d_1_r1_ = source0_.rest
                source1_ = default__.DecTerm(d_1_r1_)
                if True:
                    if source1_.is_Fail:
                        return PR_Fail()
                if True:
                    d_2_l_ = source1_.v
                    d_3_r2_ = source1_.rest
                    source2_ = default__.DecTerm(d_3_r2_)
                    if True:
                        if source2_.is_Fail:
                            return PR_Fail()
                    if True:
                        d_4_r_ = source2_.v
                        d_5_r3_ = source2_.rest
                        return PR_Ok(GoalIr.Cond_Cmp(d_0_op_, d_2_l_, d_4_r_), d_5_r3_)
        elif (((ts)[0]).k) == (362):
            source3_ = default__.DecCond(_dafny.SeqWithoutIsStrInference((ts)[1::]), (fuel) - (1))
            if True:
                if source3_.is_Fail:
                    return PR_Fail()
            if True:
                d_6_x_ = source3_.v
                d_7_r1_ = source3_.rest
                source4_ = default__.DecCond(d_7_r1_, (fuel) - (1))
                if True:
                    if source4_.is_Fail:
                        return PR_Fail()
                if True:
                    d_8_y_ = source4_.v
                    d_9_r2_ = source4_.rest
                    return PR_Ok(GoalIr.Cond_And(d_6_x_, d_8_y_), d_9_r2_)
        elif (((ts)[0]).k) == (363):
            source5_ = default__.DecCond(_dafny.SeqWithoutIsStrInference((ts)[1::]), (fuel) - (1))
            if True:
                if source5_.is_Fail:
                    return PR_Fail()
            if True:
                d_10_x_ = source5_.v
                d_11_r1_ = source5_.rest
                source6_ = default__.DecCond(d_11_r1_, (fuel) - (1))
                if True:
                    if source6_.is_Fail:
                        return PR_Fail()
                if True:
                    d_12_y_ = source6_.v
                    d_13_r2_ = source6_.rest
                    return PR_Ok(GoalIr.Cond_Or(d_10_x_, d_12_y_), d_13_r2_)
        elif (((ts)[0]).k) == (364):
            source7_ = default__.DecCond(_dafny.SeqWithoutIsStrInference((ts)[1::]), (fuel) - (1))
            if True:
                if source7_.is_Ok:
                    d_14_x_ = source7_.v
                    d_15_r_ = source7_.rest
                    return PR_Ok(GoalIr.Cond_Not(d_14_x_), d_15_r_)
            if True:
                return PR_Fail()
        elif True:
            return PR_Fail()

    @staticmethod
    def DecCondTop(ts):
        return default__.DecCond(ts, len(ts))

    @staticmethod
    def Depth(c):
        source0_ = c
        if True:
            if source0_.is_CTrue:
                return 1
        if True:
            if source0_.is_Cmp:
                return 1
        if True:
            if source0_.is_And:
                d_0_x_ = source0_.a
                d_1_y_ = source0_.b
                return (1) + ((default__.Depth(d_0_x_) if (default__.Depth(d_0_x_)) >= (default__.Depth(d_1_y_)) else default__.Depth(d_1_y_)))
        if True:
            if source0_.is_Or:
                d_2_x_ = source0_.a
                d_3_y_ = source0_.b
                return (1) + ((default__.Depth(d_2_x_) if (default__.Depth(d_2_x_)) >= (default__.Depth(d_3_y_)) else default__.Depth(d_3_y_)))
        if True:
            d_4_x_ = source0_.c
            return (1) + (default__.Depth(d_4_x_))

    @staticmethod
    def EncPart(p):
        source0_ = p
        if True:
            if source0_.is_PartExact:
                d_0_id_ = source0_.id_
                return (_dafny.SeqWithoutIsStrInference([Tok_TKw(375)])) + (default__.EncStr(d_0_id_))
        if True:
            if source0_.is_PartOneOf:
                d_1_ids_ = source0_.ids
                return (_dafny.SeqWithoutIsStrInference([Tok_TKw(376)])) + (default__.EncStrs(d_1_ids_))
        if True:
            d_2_rel_ = source0_.rel
            d_3_anchor_ = source0_.anchor
            return (_dafny.SeqWithoutIsStrInference([Tok_TKw(377)])) + ((default__.EncStr(d_2_rel_)) + (default__.EncStr(d_3_anchor_)))

    @staticmethod
    def DecPart(ts):
        if ((len(ts)) == (0)) or (not(((ts)[0]).is_TKw)):
            return PR_Fail()
        elif (((ts)[0]).k) == (375):
            source0_ = default__.DecStr(_dafny.SeqWithoutIsStrInference((ts)[1::]))
            if True:
                if source0_.is_Ok:
                    d_0_id_ = source0_.v
                    d_1_r_ = source0_.rest
                    return PR_Ok(GoalIr.ResPart_PartExact(d_0_id_), d_1_r_)
            if True:
                return PR_Fail()
        elif (((ts)[0]).k) == (376):
            source1_ = default__.DecStrs(_dafny.SeqWithoutIsStrInference((ts)[1::]))
            if True:
                if source1_.is_Ok:
                    d_2_ids_ = source1_.v
                    d_3_r_ = source1_.rest
                    return PR_Ok(GoalIr.ResPart_PartOneOf(d_2_ids_), d_3_r_)
            if True:
                return PR_Fail()
        elif (((ts)[0]).k) == (377):
            source2_ = default__.DecStr(_dafny.SeqWithoutIsStrInference((ts)[1::]))
            if True:
                if source2_.is_Fail:
                    return PR_Fail()
            if True:
                d_4_rel_ = source2_.v
                d_5_r1_ = source2_.rest
                source3_ = default__.DecStr(d_5_r1_)
                if True:
                    if source3_.is_Fail:
                        return PR_Fail()
                if True:
                    d_6_anchor_ = source3_.v
                    d_7_r2_ = source3_.rest
                    return PR_Ok(GoalIr.ResPart_PartRelated(d_4_rel_, d_6_anchor_), d_7_r2_)
        elif True:
            return PR_Fail()

    @staticmethod
    def EncPartsElems(xs):
        d_0___accumulator_ = _dafny.SeqWithoutIsStrInference([])
        while True:
            with _dafny.label():
                if (len(xs)) == (0):
                    return (d_0___accumulator_) + (_dafny.SeqWithoutIsStrInference([]))
                elif True:
                    d_0___accumulator_ = (d_0___accumulator_) + (default__.EncPart((xs)[0]))
                    in0_ = _dafny.SeqWithoutIsStrInference((xs)[1::])
                    xs = in0_
                    raise _dafny.TailCall()
                break

    @staticmethod
    def EncParts(xs):
        return (_dafny.SeqWithoutIsStrInference([Tok_TI(len(xs))])) + (default__.EncPartsElems(xs))

    @staticmethod
    def DecPartsElems(ts, n):
        if (n) == (0):
            return PR_Ok(_dafny.SeqWithoutIsStrInference([]), ts)
        elif True:
            source0_ = default__.DecPart(ts)
            if True:
                if source0_.is_Fail:
                    return PR_Fail()
            if True:
                d_0_x_ = source0_.v
                d_1_r_ = source0_.rest
                source1_ = default__.DecPartsElems(d_1_r_, (n) - (1))
                if True:
                    if source1_.is_Fail:
                        return PR_Fail()
                if True:
                    d_2_xs_ = source1_.v
                    d_3_r2_ = source1_.rest
                    return PR_Ok((_dafny.SeqWithoutIsStrInference([d_0_x_])) + (d_2_xs_), d_3_r2_)

    @staticmethod
    def DecParts(ts):
        if (((len(ts)) > (0)) and (((ts)[0]).is_TI)) and ((((ts)[0]).i) >= (0)):
            return default__.DecPartsElems(_dafny.SeqWithoutIsStrInference((ts)[1::]), ((ts)[0]).i)
        elif True:
            return PR_Fail()

    @staticmethod
    def EncResSel(s):
        source0_ = s
        if True:
            if source0_.is_Exact:
                d_0_id_ = source0_.id_
                return (_dafny.SeqWithoutIsStrInference([Tok_TKw(370)])) + (default__.EncStr(d_0_id_))
        if True:
            if source0_.is_OneOf:
                d_1_ids_ = source0_.ids
                return (_dafny.SeqWithoutIsStrInference([Tok_TKw(371)])) + (default__.EncStrs(d_1_ids_))
        if True:
            if source0_.is_Related:
                d_2_rel_ = source0_.rel
                d_3_anchor_ = source0_.anchor
                return (_dafny.SeqWithoutIsStrInference([Tok_TKw(372)])) + ((default__.EncStr(d_2_rel_)) + (default__.EncStr(d_3_anchor_)))
        if True:
            if source0_.is_AnyRes:
                d_4_reason_ = source0_.reason
                return (_dafny.SeqWithoutIsStrInference([Tok_TKw(373)])) + (default__.EncStr(d_4_reason_))
        if True:
            d_5_ps_ = source0_.parts
            return (_dafny.SeqWithoutIsStrInference([Tok_TKw(374)])) + (default__.EncParts(d_5_ps_))

    @staticmethod
    def DecResSel(ts):
        if ((len(ts)) == (0)) or (not(((ts)[0]).is_TKw)):
            return PR_Fail()
        elif (((ts)[0]).k) == (370):
            source0_ = default__.DecStr(_dafny.SeqWithoutIsStrInference((ts)[1::]))
            if True:
                if source0_.is_Ok:
                    d_0_id_ = source0_.v
                    d_1_r_ = source0_.rest
                    return PR_Ok(GoalIr.ResSel_Exact(d_0_id_), d_1_r_)
            if True:
                return PR_Fail()
        elif (((ts)[0]).k) == (371):
            source1_ = default__.DecStrs(_dafny.SeqWithoutIsStrInference((ts)[1::]))
            if True:
                if source1_.is_Ok:
                    d_2_ids_ = source1_.v
                    d_3_r_ = source1_.rest
                    return PR_Ok(GoalIr.ResSel_OneOf(d_2_ids_), d_3_r_)
            if True:
                return PR_Fail()
        elif (((ts)[0]).k) == (372):
            source2_ = default__.DecStr(_dafny.SeqWithoutIsStrInference((ts)[1::]))
            if True:
                if source2_.is_Fail:
                    return PR_Fail()
            if True:
                d_4_rel_ = source2_.v
                d_5_r1_ = source2_.rest
                source3_ = default__.DecStr(d_5_r1_)
                if True:
                    if source3_.is_Fail:
                        return PR_Fail()
                if True:
                    d_6_anchor_ = source3_.v
                    d_7_r2_ = source3_.rest
                    return PR_Ok(GoalIr.ResSel_Related(d_4_rel_, d_6_anchor_), d_7_r2_)
        elif (((ts)[0]).k) == (373):
            source4_ = default__.DecStr(_dafny.SeqWithoutIsStrInference((ts)[1::]))
            if True:
                if source4_.is_Ok:
                    d_8_reason_ = source4_.v
                    d_9_r_ = source4_.rest
                    return PR_Ok(GoalIr.ResSel_AnyRes(d_8_reason_), d_9_r_)
            if True:
                return PR_Fail()
        elif (((ts)[0]).k) == (374):
            source5_ = default__.DecParts(_dafny.SeqWithoutIsStrInference((ts)[1::]))
            if True:
                if source5_.is_Ok:
                    d_10_ps_ = source5_.v
                    d_11_r_ = source5_.rest
                    return PR_Ok(GoalIr.ResSel_AllOf(d_10_ps_), d_11_r_)
            if True:
                return PR_Fail()
        elif True:
            return PR_Fail()

    @staticmethod
    def EncGrant(g):
        return (_dafny.SeqWithoutIsStrInference([Tok_TKw(380)])) + ((default__.EncStr((g).gid)) + ((default__.EncStr((g).verb)) + ((default__.EncResSel((g).res)) + (default__.EncCond((g).cond)))))

    @staticmethod
    def DecGrant(ts):
        if ((len(ts)) == (0)) or (((ts)[0]) != (Tok_TKw(380))):
            return PR_Fail()
        elif True:
            source0_ = default__.DecStr(_dafny.SeqWithoutIsStrInference((ts)[1::]))
            if True:
                if source0_.is_Fail:
                    return PR_Fail()
            if True:
                d_0_gid_ = source0_.v
                d_1_r1_ = source0_.rest
                source1_ = default__.DecStr(d_1_r1_)
                if True:
                    if source1_.is_Fail:
                        return PR_Fail()
                if True:
                    d_2_verb_ = source1_.v
                    d_3_r2_ = source1_.rest
                    source2_ = default__.DecResSel(d_3_r2_)
                    if True:
                        if source2_.is_Fail:
                            return PR_Fail()
                    if True:
                        d_4_res_ = source2_.v
                        d_5_r3_ = source2_.rest
                        source3_ = default__.DecCondTop(d_5_r3_)
                        if True:
                            if source3_.is_Fail:
                                return PR_Fail()
                        if True:
                            d_6_c_ = source3_.v
                            d_7_r4_ = source3_.rest
                            return PR_Ok(GoalIr.Grant_Grant(d_0_gid_, d_2_verb_, d_4_res_, d_6_c_), d_7_r4_)

    @staticmethod
    def EncProhTarget(t):
        source0_ = t
        if True:
            if source0_.is_PVerb:
                d_0_v_ = source0_.verb
                return (_dafny.SeqWithoutIsStrInference([Tok_TKw(390)])) + (default__.EncStr(d_0_v_))
        if True:
            d_1_c_ = source0_.cls
            return (_dafny.SeqWithoutIsStrInference([Tok_TKw(391)])) + (default__.EncStr(d_1_c_))

    @staticmethod
    def DecProhTarget(ts):
        if ((len(ts)) == (0)) or (not(((ts)[0]).is_TKw)):
            return PR_Fail()
        elif (((ts)[0]).k) == (390):
            source0_ = default__.DecStr(_dafny.SeqWithoutIsStrInference((ts)[1::]))
            if True:
                if source0_.is_Ok:
                    d_0_v_ = source0_.v
                    d_1_r_ = source0_.rest
                    return PR_Ok(GoalIr.ProhTarget_PVerb(d_0_v_), d_1_r_)
            if True:
                return PR_Fail()
        elif (((ts)[0]).k) == (391):
            source1_ = default__.DecStr(_dafny.SeqWithoutIsStrInference((ts)[1::]))
            if True:
                if source1_.is_Ok:
                    d_2_c_ = source1_.v
                    d_3_r_ = source1_.rest
                    return PR_Ok(GoalIr.ProhTarget_PEffect(d_2_c_), d_3_r_)
            if True:
                return PR_Fail()
        elif True:
            return PR_Fail()

    @staticmethod
    def EncProhibit(p):
        return (_dafny.SeqWithoutIsStrInference([Tok_TKw(392)])) + ((default__.EncStr((p).pid)) + ((default__.EncProhTarget((p).target)) + ((default__.EncResSel((p).res)) + (default__.EncCond((p).cond)))))

    @staticmethod
    def DecProhibit(ts):
        if ((len(ts)) == (0)) or (((ts)[0]) != (Tok_TKw(392))):
            return PR_Fail()
        elif True:
            source0_ = default__.DecStr(_dafny.SeqWithoutIsStrInference((ts)[1::]))
            if True:
                if source0_.is_Fail:
                    return PR_Fail()
            if True:
                d_0_pid_ = source0_.v
                d_1_r1_ = source0_.rest
                source1_ = default__.DecProhTarget(d_1_r1_)
                if True:
                    if source1_.is_Fail:
                        return PR_Fail()
                if True:
                    d_2_tg_ = source1_.v
                    d_3_r2_ = source1_.rest
                    source2_ = default__.DecResSel(d_3_r2_)
                    if True:
                        if source2_.is_Fail:
                            return PR_Fail()
                    if True:
                        d_4_res_ = source2_.v
                        d_5_r3_ = source2_.rest
                        source3_ = default__.DecCondTop(d_5_r3_)
                        if True:
                            if source3_.is_Fail:
                                return PR_Fail()
                        if True:
                            d_6_c_ = source3_.v
                            d_7_r4_ = source3_.rest
                            return PR_Ok(GoalIr.Prohibit_Prohibit(d_0_pid_, d_2_tg_, d_4_res_, d_6_c_), d_7_r4_)

    @staticmethod
    def EncAgg(a):
        source0_ = a
        if True:
            if source0_.is_ACount:
                return _dafny.SeqWithoutIsStrInference([Tok_TKw(400)])
        if True:
            if source0_.is_ASum:
                return _dafny.SeqWithoutIsStrInference([Tok_TKw(401)])
        if True:
            if source0_.is_AMax:
                return _dafny.SeqWithoutIsStrInference([Tok_TKw(402)])
        if True:
            return _dafny.SeqWithoutIsStrInference([Tok_TKw(403)])

    @staticmethod
    def DecAgg(ts):
        if ((len(ts)) == (0)) or (not(((ts)[0]).is_TKw)):
            return PR_Fail()
        elif (((ts)[0]).k) == (400):
            return PR_Ok(GoalIr.Agg_ACount(), _dafny.SeqWithoutIsStrInference((ts)[1::]))
        elif (((ts)[0]).k) == (401):
            return PR_Ok(GoalIr.Agg_ASum(), _dafny.SeqWithoutIsStrInference((ts)[1::]))
        elif (((ts)[0]).k) == (402):
            return PR_Ok(GoalIr.Agg_AMax(), _dafny.SeqWithoutIsStrInference((ts)[1::]))
        elif (((ts)[0]).k) == (403):
            return PR_Ok(GoalIr.Agg_ADistinct(), _dafny.SeqWithoutIsStrInference((ts)[1::]))
        elif True:
            return PR_Fail()

    @staticmethod
    def EncSel(s):
        source0_ = s
        if True:
            if source0_.is_SelGids:
                d_0_g_ = source0_.gids
                return (_dafny.SeqWithoutIsStrInference([Tok_TKw(410)])) + (default__.EncStrs(d_0_g_))
        if True:
            d_1_c_ = source0_.cls
            return (_dafny.SeqWithoutIsStrInference([Tok_TKw(411)])) + (default__.EncStr(d_1_c_))

    @staticmethod
    def DecSel(ts):
        if ((len(ts)) == (0)) or (not(((ts)[0]).is_TKw)):
            return PR_Fail()
        elif (((ts)[0]).k) == (410):
            source0_ = default__.DecStrs(_dafny.SeqWithoutIsStrInference((ts)[1::]))
            if True:
                if source0_.is_Ok:
                    d_0_g_ = source0_.v
                    d_1_r_ = source0_.rest
                    return PR_Ok(GoalIr.Sel_SelGids(d_0_g_), d_1_r_)
            if True:
                return PR_Fail()
        elif (((ts)[0]).k) == (411):
            source1_ = default__.DecStr(_dafny.SeqWithoutIsStrInference((ts)[1::]))
            if True:
                if source1_.is_Ok:
                    d_2_c_ = source1_.v
                    d_3_r_ = source1_.rest
                    return PR_Ok(GoalIr.Sel_SelEffect(d_2_c_), d_3_r_)
            if True:
                return PR_Fail()
        elif True:
            return PR_Fail()

    @staticmethod
    def EncWindow(w):
        source0_ = w
        if True:
            if source0_.is_WTask:
                return _dafny.SeqWithoutIsStrInference([Tok_TKw(420)])
        if True:
            if source0_.is_WSliding:
                d_0_ms_ = source0_.ms
                return (_dafny.SeqWithoutIsStrInference([Tok_TKw(421)])) + (default__.EncInt(d_0_ms_))
        if True:
            if source0_.is_WPeriod:
                d_1_ms_ = source0_.ms
                d_2_t0_ = source0_.t0
                return (_dafny.SeqWithoutIsStrInference([Tok_TKw(422)])) + ((default__.EncInt(d_1_ms_)) + (default__.EncInt(d_2_t0_)))
        if True:
            return _dafny.SeqWithoutIsStrInference([Tok_TKw(423)])

    @staticmethod
    def DecWindow(ts):
        if ((len(ts)) == (0)) or (not(((ts)[0]).is_TKw)):
            return PR_Fail()
        elif (((ts)[0]).k) == (420):
            return PR_Ok(GoalIr.Window_WTask(), _dafny.SeqWithoutIsStrInference((ts)[1::]))
        elif (((ts)[0]).k) == (421):
            source0_ = default__.DecInt(_dafny.SeqWithoutIsStrInference((ts)[1::]))
            if True:
                if source0_.is_Ok:
                    d_0_ms_ = source0_.v
                    d_1_r_ = source0_.rest
                    return PR_Ok(GoalIr.Window_WSliding(d_0_ms_), d_1_r_)
            if True:
                return PR_Fail()
        elif (((ts)[0]).k) == (422):
            source1_ = default__.DecInt(_dafny.SeqWithoutIsStrInference((ts)[1::]))
            if True:
                if source1_.is_Fail:
                    return PR_Fail()
            if True:
                d_2_ms_ = source1_.v
                d_3_r1_ = source1_.rest
                source2_ = default__.DecInt(d_3_r1_)
                if True:
                    if source2_.is_Fail:
                        return PR_Fail()
                if True:
                    d_4_t0_ = source2_.v
                    d_5_r2_ = source2_.rest
                    return PR_Ok(GoalIr.Window_WPeriod(d_2_ms_, d_4_t0_), d_5_r2_)
        elif (((ts)[0]).k) == (423):
            return PR_Ok(GoalIr.Window_WLifetime(), _dafny.SeqWithoutIsStrInference((ts)[1::]))
        elif True:
            return PR_Fail()

    @staticmethod
    def EncScope(s):
        source0_ = s
        if True:
            if source0_.is_SSession:
                return _dafny.SeqWithoutIsStrInference([Tok_TKw(430)])
        if True:
            if source0_.is_SPrincipal:
                return _dafny.SeqWithoutIsStrInference([Tok_TKw(431)])
        if True:
            if source0_.is_SOrg:
                return _dafny.SeqWithoutIsStrInference([Tok_TKw(432)])
        if True:
            d_0_a_ = source0_.agents
            return (_dafny.SeqWithoutIsStrInference([Tok_TKw(433)])) + (default__.EncStrs(d_0_a_))

    @staticmethod
    def DecScope(ts):
        if ((len(ts)) == (0)) or (not(((ts)[0]).is_TKw)):
            return PR_Fail()
        elif (((ts)[0]).k) == (430):
            return PR_Ok(GoalIr.Scope_SSession(), _dafny.SeqWithoutIsStrInference((ts)[1::]))
        elif (((ts)[0]).k) == (431):
            return PR_Ok(GoalIr.Scope_SPrincipal(), _dafny.SeqWithoutIsStrInference((ts)[1::]))
        elif (((ts)[0]).k) == (432):
            return PR_Ok(GoalIr.Scope_SOrg(), _dafny.SeqWithoutIsStrInference((ts)[1::]))
        elif (((ts)[0]).k) == (433):
            source0_ = default__.DecStrs(_dafny.SeqWithoutIsStrInference((ts)[1::]))
            if True:
                if source0_.is_Ok:
                    d_0_a_ = source0_.v
                    d_1_r_ = source0_.rest
                    return PR_Ok(GoalIr.Scope_SFleet(d_0_a_), d_1_r_)
            if True:
                return PR_Fail()
        elif True:
            return PR_Fail()

    @staticmethod
    def EncOnExceed(o):
        source0_ = o
        if True:
            if source0_.is_OnDeny:
                return _dafny.SeqWithoutIsStrInference([Tok_TKw(440)])
        if True:
            return _dafny.SeqWithoutIsStrInference([Tok_TKw(441)])

    @staticmethod
    def DecOnExceed(ts):
        if ((len(ts)) == (0)) or (not(((ts)[0]).is_TKw)):
            return PR_Fail()
        elif (((ts)[0]).k) == (440):
            return PR_Ok(GoalIr.OnExceed_OnDeny(), _dafny.SeqWithoutIsStrInference((ts)[1::]))
        elif (((ts)[0]).k) == (441):
            return PR_Ok(GoalIr.OnExceed_OnEscalate(), _dafny.SeqWithoutIsStrInference((ts)[1::]))
        elif True:
            return PR_Fail()

    @staticmethod
    def EncBCore(b):
        return (_dafny.SeqWithoutIsStrInference([Tok_TKw(450)])) + ((default__.EncAgg((b).agg)) + ((default__.EncTerm((b).value)) + ((default__.EncStr((b).key)) + ((default__.EncWindow((b).window)) + ((default__.EncScope((b).scope)) + ((default__.EncQ((b).cap)) + (default__.EncOnExceed((b).onExceed))))))))

    @staticmethod
    def DecBCore(ts):
        if ((len(ts)) == (0)) or (((ts)[0]) != (Tok_TKw(450))):
            return PR_Fail()
        elif True:
            source0_ = default__.DecAgg(_dafny.SeqWithoutIsStrInference((ts)[1::]))
            if True:
                if source0_.is_Fail:
                    return PR_Fail()
            if True:
                d_0_agg_ = source0_.v
                d_1_r1_ = source0_.rest
                source1_ = default__.DecTerm(d_1_r1_)
                if True:
                    if source1_.is_Fail:
                        return PR_Fail()
                if True:
                    d_2_value_ = source1_.v
                    d_3_r2_ = source1_.rest
                    source2_ = default__.DecStr(d_3_r2_)
                    if True:
                        if source2_.is_Fail:
                            return PR_Fail()
                    if True:
                        d_4_key_ = source2_.v
                        d_5_r3_ = source2_.rest
                        source3_ = default__.DecWindow(d_5_r3_)
                        if True:
                            if source3_.is_Fail:
                                return PR_Fail()
                        if True:
                            d_6_window_ = source3_.v
                            d_7_r4_ = source3_.rest
                            source4_ = default__.DecScope(d_7_r4_)
                            if True:
                                if source4_.is_Fail:
                                    return PR_Fail()
                            if True:
                                d_8_scope_ = source4_.v
                                d_9_r5_ = source4_.rest
                                source5_ = default__.DecQ(d_9_r5_)
                                if True:
                                    if source5_.is_Fail:
                                        return PR_Fail()
                                if True:
                                    d_10_cap_ = source5_.v
                                    d_11_r6_ = source5_.rest
                                    source6_ = default__.DecOnExceed(d_11_r6_)
                                    if True:
                                        if source6_.is_Fail:
                                            return PR_Fail()
                                    if True:
                                        d_12_oe_ = source6_.v
                                        d_13_r7_ = source6_.rest
                                        return PR_Ok(GoalIr.BCore_BCore(d_0_agg_, d_2_value_, d_4_key_, d_6_window_, d_8_scope_, d_10_cap_, d_12_oe_), d_13_r7_)

    @staticmethod
    def EncBound(b):
        return (_dafny.SeqWithoutIsStrInference([Tok_TKw(451)])) + ((default__.EncStr((b).bid)) + ((default__.EncSel((b).sel)) + (default__.EncBCore((b).core))))

    @staticmethod
    def DecBound(ts):
        if ((len(ts)) == (0)) or (((ts)[0]) != (Tok_TKw(451))):
            return PR_Fail()
        elif True:
            source0_ = default__.DecStr(_dafny.SeqWithoutIsStrInference((ts)[1::]))
            if True:
                if source0_.is_Fail:
                    return PR_Fail()
            if True:
                d_0_bid_ = source0_.v
                d_1_r1_ = source0_.rest
                source1_ = default__.DecSel(d_1_r1_)
                if True:
                    if source1_.is_Fail:
                        return PR_Fail()
                if True:
                    d_2_sel_ = source1_.v
                    d_3_r2_ = source1_.rest
                    source2_ = default__.DecBCore(d_3_r2_)
                    if True:
                        if source2_.is_Fail:
                            return PR_Fail()
                    if True:
                        d_4_core_ = source2_.v
                        d_5_r3_ = source2_.rest
                        return PR_Ok(GoalIr.Bound_Bound(d_0_bid_, d_2_sel_, d_4_core_), d_5_r3_)

    @staticmethod
    def EncValidity(v):
        return (_dafny.SeqWithoutIsStrInference([Tok_TKw(460)])) + ((default__.EncInt((v).notBefore)) + ((default__.EncInt((v).notAfter)) + (default__.EncInt((v).maxIdle))))

    @staticmethod
    def DecValidity(ts):
        if ((len(ts)) == (0)) or (((ts)[0]) != (Tok_TKw(460))):
            return PR_Fail()
        elif True:
            source0_ = default__.DecInt(_dafny.SeqWithoutIsStrInference((ts)[1::]))
            if True:
                if source0_.is_Fail:
                    return PR_Fail()
            if True:
                d_0_nb_ = source0_.v
                d_1_r1_ = source0_.rest
                source1_ = default__.DecInt(d_1_r1_)
                if True:
                    if source1_.is_Fail:
                        return PR_Fail()
                if True:
                    d_2_na_ = source1_.v
                    d_3_r2_ = source1_.rest
                    source2_ = default__.DecInt(d_3_r2_)
                    if True:
                        if source2_.is_Fail:
                            return PR_Fail()
                    if True:
                        d_4_mi_ = source2_.v
                        d_5_r3_ = source2_.rest
                        return PR_Ok(GoalIr.Validity_Validity(d_0_nb_, d_2_na_, d_4_mi_), d_5_r3_)

    @staticmethod
    def EncDeleg(d):
        return (_dafny.SeqWithoutIsStrInference([Tok_TKw(461)])) + ((default__.EncInt((d).maxDepth)) + ((default__.EncBool((d).narrowOnly)) + (default__.EncStrs((d).mayTouch))))

    @staticmethod
    def DecDeleg(ts):
        if ((len(ts)) == (0)) or (((ts)[0]) != (Tok_TKw(461))):
            return PR_Fail()
        elif True:
            source0_ = default__.DecInt(_dafny.SeqWithoutIsStrInference((ts)[1::]))
            if True:
                if source0_.is_Fail:
                    return PR_Fail()
            if True:
                d_0_md_ = source0_.v
                d_1_r1_ = source0_.rest
                source1_ = default__.DecBool(d_1_r1_)
                if True:
                    if source1_.is_Fail:
                        return PR_Fail()
                if True:
                    d_2_no_ = source1_.v
                    d_3_r2_ = source1_.rest
                    source2_ = default__.DecStrs(d_3_r2_)
                    if True:
                        if source2_.is_Fail:
                            return PR_Fail()
                    if True:
                        d_4_mt_ = source2_.v
                        d_5_r3_ = source2_.rest
                        return PR_Ok(GoalIr.Delegation_Delegation(d_0_md_, d_2_no_, d_4_mt_), d_5_r3_)

    @staticmethod
    def EncHole(h):
        return (_dafny.SeqWithoutIsStrInference([Tok_TKw(470)])) + ((default__.EncStr((h).hid)) + ((default__.EncStr((h).q)) + ((default__.EncStrs((h).domain)) + ((default__.EncStrs((h).affects)) + (default__.EncBool((h).global_))))))

    @staticmethod
    def DecHole(ts):
        if ((len(ts)) == (0)) or (((ts)[0]) != (Tok_TKw(470))):
            return PR_Fail()
        elif True:
            source0_ = default__.DecStr(_dafny.SeqWithoutIsStrInference((ts)[1::]))
            if True:
                if source0_.is_Fail:
                    return PR_Fail()
            if True:
                d_0_hid_ = source0_.v
                d_1_r1_ = source0_.rest
                source1_ = default__.DecStr(d_1_r1_)
                if True:
                    if source1_.is_Fail:
                        return PR_Fail()
                if True:
                    d_2_q_ = source1_.v
                    d_3_r2_ = source1_.rest
                    source2_ = default__.DecStrs(d_3_r2_)
                    if True:
                        if source2_.is_Fail:
                            return PR_Fail()
                    if True:
                        d_4_dom_ = source2_.v
                        d_5_r3_ = source2_.rest
                        source3_ = default__.DecStrs(d_5_r3_)
                        if True:
                            if source3_.is_Fail:
                                return PR_Fail()
                        if True:
                            d_6_aff_ = source3_.v
                            d_7_r4_ = source3_.rest
                            source4_ = default__.DecBool(d_7_r4_)
                            if True:
                                if source4_.is_Fail:
                                    return PR_Fail()
                            if True:
                                d_8_gl_ = source4_.v
                                d_9_r5_ = source4_.rest
                                return PR_Ok(GoalIr.Hole_Hole(d_0_hid_, d_2_q_, d_4_dom_, d_6_aff_, d_8_gl_), d_9_r5_)

    @staticmethod
    def EncStrsElems(xs):
        d_0___accumulator_ = _dafny.SeqWithoutIsStrInference([])
        while True:
            with _dafny.label():
                if (len(xs)) == (0):
                    return (d_0___accumulator_) + (_dafny.SeqWithoutIsStrInference([]))
                elif True:
                    d_0___accumulator_ = (d_0___accumulator_) + (default__.EncStr((xs)[0]))
                    in0_ = _dafny.SeqWithoutIsStrInference((xs)[1::])
                    xs = in0_
                    raise _dafny.TailCall()
                break

    @staticmethod
    def EncStrs(xs):
        return (_dafny.SeqWithoutIsStrInference([Tok_TI(len(xs))])) + (default__.EncStrsElems(xs))

    @staticmethod
    def DecStrsElems(ts, n):
        if (n) == (0):
            return PR_Ok(_dafny.SeqWithoutIsStrInference([]), ts)
        elif True:
            source0_ = default__.DecStr(ts)
            if True:
                if source0_.is_Fail:
                    return PR_Fail()
            if True:
                d_0_x_ = source0_.v
                d_1_r_ = source0_.rest
                source1_ = default__.DecStrsElems(d_1_r_, (n) - (1))
                if True:
                    if source1_.is_Fail:
                        return PR_Fail()
                if True:
                    d_2_xs_ = source1_.v
                    d_3_r2_ = source1_.rest
                    return PR_Ok((_dafny.SeqWithoutIsStrInference([d_0_x_])) + (d_2_xs_), d_3_r2_)

    @staticmethod
    def DecStrs(ts):
        if (((len(ts)) > (0)) and (((ts)[0]).is_TI)) and ((((ts)[0]).i) >= (0)):
            return default__.DecStrsElems(_dafny.SeqWithoutIsStrInference((ts)[1::]), ((ts)[0]).i)
        elif True:
            return PR_Fail()

    @staticmethod
    def EncGrantsElems(xs):
        d_0___accumulator_ = _dafny.SeqWithoutIsStrInference([])
        while True:
            with _dafny.label():
                if (len(xs)) == (0):
                    return (d_0___accumulator_) + (_dafny.SeqWithoutIsStrInference([]))
                elif True:
                    d_0___accumulator_ = (d_0___accumulator_) + (default__.EncGrant((xs)[0]))
                    in0_ = _dafny.SeqWithoutIsStrInference((xs)[1::])
                    xs = in0_
                    raise _dafny.TailCall()
                break

    @staticmethod
    def EncGrants(xs):
        return (_dafny.SeqWithoutIsStrInference([Tok_TI(len(xs))])) + (default__.EncGrantsElems(xs))

    @staticmethod
    def DecGrantsElems(ts, n):
        if (n) == (0):
            return PR_Ok(_dafny.SeqWithoutIsStrInference([]), ts)
        elif True:
            source0_ = default__.DecGrant(ts)
            if True:
                if source0_.is_Fail:
                    return PR_Fail()
            if True:
                d_0_x_ = source0_.v
                d_1_r_ = source0_.rest
                source1_ = default__.DecGrantsElems(d_1_r_, (n) - (1))
                if True:
                    if source1_.is_Fail:
                        return PR_Fail()
                if True:
                    d_2_xs_ = source1_.v
                    d_3_r2_ = source1_.rest
                    return PR_Ok((_dafny.SeqWithoutIsStrInference([d_0_x_])) + (d_2_xs_), d_3_r2_)

    @staticmethod
    def DecGrants(ts):
        if (((len(ts)) > (0)) and (((ts)[0]).is_TI)) and ((((ts)[0]).i) >= (0)):
            return default__.DecGrantsElems(_dafny.SeqWithoutIsStrInference((ts)[1::]), ((ts)[0]).i)
        elif True:
            return PR_Fail()

    @staticmethod
    def EncProhibitsElems(xs):
        d_0___accumulator_ = _dafny.SeqWithoutIsStrInference([])
        while True:
            with _dafny.label():
                if (len(xs)) == (0):
                    return (d_0___accumulator_) + (_dafny.SeqWithoutIsStrInference([]))
                elif True:
                    d_0___accumulator_ = (d_0___accumulator_) + (default__.EncProhibit((xs)[0]))
                    in0_ = _dafny.SeqWithoutIsStrInference((xs)[1::])
                    xs = in0_
                    raise _dafny.TailCall()
                break

    @staticmethod
    def EncProhibits(xs):
        return (_dafny.SeqWithoutIsStrInference([Tok_TI(len(xs))])) + (default__.EncProhibitsElems(xs))

    @staticmethod
    def DecProhibitsElems(ts, n):
        if (n) == (0):
            return PR_Ok(_dafny.SeqWithoutIsStrInference([]), ts)
        elif True:
            source0_ = default__.DecProhibit(ts)
            if True:
                if source0_.is_Fail:
                    return PR_Fail()
            if True:
                d_0_x_ = source0_.v
                d_1_r_ = source0_.rest
                source1_ = default__.DecProhibitsElems(d_1_r_, (n) - (1))
                if True:
                    if source1_.is_Fail:
                        return PR_Fail()
                if True:
                    d_2_xs_ = source1_.v
                    d_3_r2_ = source1_.rest
                    return PR_Ok((_dafny.SeqWithoutIsStrInference([d_0_x_])) + (d_2_xs_), d_3_r2_)

    @staticmethod
    def DecProhibits(ts):
        if (((len(ts)) > (0)) and (((ts)[0]).is_TI)) and ((((ts)[0]).i) >= (0)):
            return default__.DecProhibitsElems(_dafny.SeqWithoutIsStrInference((ts)[1::]), ((ts)[0]).i)
        elif True:
            return PR_Fail()

    @staticmethod
    def EncBoundsElems(xs):
        d_0___accumulator_ = _dafny.SeqWithoutIsStrInference([])
        while True:
            with _dafny.label():
                if (len(xs)) == (0):
                    return (d_0___accumulator_) + (_dafny.SeqWithoutIsStrInference([]))
                elif True:
                    d_0___accumulator_ = (d_0___accumulator_) + (default__.EncBound((xs)[0]))
                    in0_ = _dafny.SeqWithoutIsStrInference((xs)[1::])
                    xs = in0_
                    raise _dafny.TailCall()
                break

    @staticmethod
    def EncBounds(xs):
        return (_dafny.SeqWithoutIsStrInference([Tok_TI(len(xs))])) + (default__.EncBoundsElems(xs))

    @staticmethod
    def DecBoundsElems(ts, n):
        if (n) == (0):
            return PR_Ok(_dafny.SeqWithoutIsStrInference([]), ts)
        elif True:
            source0_ = default__.DecBound(ts)
            if True:
                if source0_.is_Fail:
                    return PR_Fail()
            if True:
                d_0_x_ = source0_.v
                d_1_r_ = source0_.rest
                source1_ = default__.DecBoundsElems(d_1_r_, (n) - (1))
                if True:
                    if source1_.is_Fail:
                        return PR_Fail()
                if True:
                    d_2_xs_ = source1_.v
                    d_3_r2_ = source1_.rest
                    return PR_Ok((_dafny.SeqWithoutIsStrInference([d_0_x_])) + (d_2_xs_), d_3_r2_)

    @staticmethod
    def DecBounds(ts):
        if (((len(ts)) > (0)) and (((ts)[0]).is_TI)) and ((((ts)[0]).i) >= (0)):
            return default__.DecBoundsElems(_dafny.SeqWithoutIsStrInference((ts)[1::]), ((ts)[0]).i)
        elif True:
            return PR_Fail()

    @staticmethod
    def EncCondsElems(xs):
        d_0___accumulator_ = _dafny.SeqWithoutIsStrInference([])
        while True:
            with _dafny.label():
                if (len(xs)) == (0):
                    return (d_0___accumulator_) + (_dafny.SeqWithoutIsStrInference([]))
                elif True:
                    d_0___accumulator_ = (d_0___accumulator_) + (default__.EncCond((xs)[0]))
                    in0_ = _dafny.SeqWithoutIsStrInference((xs)[1::])
                    xs = in0_
                    raise _dafny.TailCall()
                break

    @staticmethod
    def EncConds(xs):
        return (_dafny.SeqWithoutIsStrInference([Tok_TI(len(xs))])) + (default__.EncCondsElems(xs))

    @staticmethod
    def DecCondsElems(ts, n):
        if (n) == (0):
            return PR_Ok(_dafny.SeqWithoutIsStrInference([]), ts)
        elif True:
            source0_ = default__.DecCondTop(ts)
            if True:
                if source0_.is_Fail:
                    return PR_Fail()
            if True:
                d_0_x_ = source0_.v
                d_1_r_ = source0_.rest
                source1_ = default__.DecCondsElems(d_1_r_, (n) - (1))
                if True:
                    if source1_.is_Fail:
                        return PR_Fail()
                if True:
                    d_2_xs_ = source1_.v
                    d_3_r2_ = source1_.rest
                    return PR_Ok((_dafny.SeqWithoutIsStrInference([d_0_x_])) + (d_2_xs_), d_3_r2_)

    @staticmethod
    def DecConds(ts):
        if (((len(ts)) > (0)) and (((ts)[0]).is_TI)) and ((((ts)[0]).i) >= (0)):
            return default__.DecCondsElems(_dafny.SeqWithoutIsStrInference((ts)[1::]), ((ts)[0]).i)
        elif True:
            return PR_Fail()

    @staticmethod
    def EncHolesElems(xs):
        d_0___accumulator_ = _dafny.SeqWithoutIsStrInference([])
        while True:
            with _dafny.label():
                if (len(xs)) == (0):
                    return (d_0___accumulator_) + (_dafny.SeqWithoutIsStrInference([]))
                elif True:
                    d_0___accumulator_ = (d_0___accumulator_) + (default__.EncHole((xs)[0]))
                    in0_ = _dafny.SeqWithoutIsStrInference((xs)[1::])
                    xs = in0_
                    raise _dafny.TailCall()
                break

    @staticmethod
    def EncHoles(xs):
        return (_dafny.SeqWithoutIsStrInference([Tok_TI(len(xs))])) + (default__.EncHolesElems(xs))

    @staticmethod
    def DecHolesElems(ts, n):
        if (n) == (0):
            return PR_Ok(_dafny.SeqWithoutIsStrInference([]), ts)
        elif True:
            source0_ = default__.DecHole(ts)
            if True:
                if source0_.is_Fail:
                    return PR_Fail()
            if True:
                d_0_x_ = source0_.v
                d_1_r_ = source0_.rest
                source1_ = default__.DecHolesElems(d_1_r_, (n) - (1))
                if True:
                    if source1_.is_Fail:
                        return PR_Fail()
                if True:
                    d_2_xs_ = source1_.v
                    d_3_r2_ = source1_.rest
                    return PR_Ok((_dafny.SeqWithoutIsStrInference([d_0_x_])) + (d_2_xs_), d_3_r2_)

    @staticmethod
    def DecHoles(ts):
        if (((len(ts)) > (0)) and (((ts)[0]).is_TI)) and ((((ts)[0]).i) >= (0)):
            return default__.DecHolesElems(_dafny.SeqWithoutIsStrInference((ts)[1::]), ((ts)[0]).i)
        elif True:
            return PR_Fail()

    @staticmethod
    def EncGoal(g):
        return (_dafny.SeqWithoutIsStrInference([Tok_TKw(480), Tok_TI((g).v), Tok_TS((g).principal), Tok_TS((g).ontDigest), Tok_TS((g).nlDigest)])) + ((default__.EncStrs((g).sources)) + ((default__.EncGrants((g).grants)) + ((default__.EncProhibits((g).prohibits)) + ((default__.EncBounds((g).bounds)) + ((default__.EncValidity((g).validity)) + ((default__.EncDeleg((g).deleg)) + ((default__.EncConds((g).escalateOn)) + ((default__.EncStrs((g).wildcardAck)) + (default__.EncHoles((g).holes))))))))))

    @staticmethod
    def DecGoal(ts):
        if ((((((len(ts)) < (5)) or (((ts)[0]) != (Tok_TKw(480)))) or (not(((ts)[1]).is_TI))) or (not(((ts)[2]).is_TS))) or (not(((ts)[3]).is_TS))) or (not(((ts)[4]).is_TS)):
            return PR_Fail()
        elif True:
            source0_ = default__.DecStrs(_dafny.SeqWithoutIsStrInference((ts)[5::]))
            if True:
                if source0_.is_Fail:
                    return PR_Fail()
            if True:
                d_0_sources_ = source0_.v
                d_1_r1_ = source0_.rest
                source1_ = default__.DecGrants(d_1_r1_)
                if True:
                    if source1_.is_Fail:
                        return PR_Fail()
                if True:
                    d_2_grants_ = source1_.v
                    d_3_r2_ = source1_.rest
                    source2_ = default__.DecProhibits(d_3_r2_)
                    if True:
                        if source2_.is_Fail:
                            return PR_Fail()
                    if True:
                        d_4_prohibits_ = source2_.v
                        d_5_r3_ = source2_.rest
                        source3_ = default__.DecBounds(d_5_r3_)
                        if True:
                            if source3_.is_Fail:
                                return PR_Fail()
                        if True:
                            d_6_bounds_ = source3_.v
                            d_7_r4_ = source3_.rest
                            source4_ = default__.DecValidity(d_7_r4_)
                            if True:
                                if source4_.is_Fail:
                                    return PR_Fail()
                            if True:
                                d_8_validity_ = source4_.v
                                d_9_r5_ = source4_.rest
                                source5_ = default__.DecDeleg(d_9_r5_)
                                if True:
                                    if source5_.is_Fail:
                                        return PR_Fail()
                                if True:
                                    d_10_deleg_ = source5_.v
                                    d_11_r6_ = source5_.rest
                                    source6_ = default__.DecConds(d_11_r6_)
                                    if True:
                                        if source6_.is_Fail:
                                            return PR_Fail()
                                    if True:
                                        d_12_esc_ = source6_.v
                                        d_13_r7_ = source6_.rest
                                        source7_ = default__.DecStrs(d_13_r7_)
                                        if True:
                                            if source7_.is_Fail:
                                                return PR_Fail()
                                        if True:
                                            d_14_ack_ = source7_.v
                                            d_15_r8_ = source7_.rest
                                            source8_ = default__.DecHoles(d_15_r8_)
                                            if True:
                                                if source8_.is_Fail:
                                                    return PR_Fail()
                                            if True:
                                                d_16_holes_ = source8_.v
                                                d_17_r9_ = source8_.rest
                                                return PR_Ok(GoalIr.Goal_Goal(((ts)[1]).i, ((ts)[2]).s, ((ts)[3]).s, ((ts)[4]).s, d_0_sources_, d_2_grants_, d_4_prohibits_, d_6_bounds_, d_8_validity_, d_10_deleg_, d_12_esc_, d_14_ack_, d_16_holes_), d_17_r9_)

    @staticmethod
    def Render(g):
        return default__.EncGoal(g)

    @staticmethod
    def Parse(ts):
        source0_ = default__.DecGoal(ts)
        if True:
            if source0_.is_Ok:
                d_0_g_ = source0_.v
                d_1_rest_ = source0_.rest
                if (len(d_1_rest_)) == (0):
                    return GoalIr.Option_Some(d_0_g_)
                elif True:
                    return GoalIr.Option_None()
        if True:
            return GoalIr.Option_None()


class Tok:
    @classmethod
    def default(cls, ):
        return lambda: Tok_TKw(int(0))
    def __ne__(self, __o: object) -> bool:
        return not self.__eq__(__o)
    @property
    def is_TKw(self) -> bool:
        return isinstance(self, Tok_TKw)
    @property
    def is_TI(self) -> bool:
        return isinstance(self, Tok_TI)
    @property
    def is_TS(self) -> bool:
        return isinstance(self, Tok_TS)

class Tok_TKw(Tok, NamedTuple('TKw', [('k', Any)])):
    def __dafnystr__(self) -> str:
        return f'GoalRender.Tok.TKw({_dafny.string_of(self.k)})'
    def __eq__(self, __o: object) -> bool:
        return isinstance(__o, Tok_TKw) and self.k == __o.k
    def __hash__(self) -> int:
        return super().__hash__()

class Tok_TI(Tok, NamedTuple('TI', [('i', Any)])):
    def __dafnystr__(self) -> str:
        return f'GoalRender.Tok.TI({_dafny.string_of(self.i)})'
    def __eq__(self, __o: object) -> bool:
        return isinstance(__o, Tok_TI) and self.i == __o.i
    def __hash__(self) -> int:
        return super().__hash__()

class Tok_TS(Tok, NamedTuple('TS', [('s', Any)])):
    def __dafnystr__(self) -> str:
        return f'GoalRender.Tok.TS({self.s.VerbatimString(True)})'
    def __eq__(self, __o: object) -> bool:
        return isinstance(__o, Tok_TS) and self.s == __o.s
    def __hash__(self) -> int:
        return super().__hash__()


class PR:
    @classmethod
    def default(cls, ):
        return lambda: PR_Fail()
    def __ne__(self, __o: object) -> bool:
        return not self.__eq__(__o)
    @property
    def is_Fail(self) -> bool:
        return isinstance(self, PR_Fail)
    @property
    def is_Ok(self) -> bool:
        return isinstance(self, PR_Ok)

class PR_Fail(PR, NamedTuple('Fail', [])):
    def __dafnystr__(self) -> str:
        return f'GoalRender.PR.Fail'
    def __eq__(self, __o: object) -> bool:
        return isinstance(__o, PR_Fail)
    def __hash__(self) -> int:
        return super().__hash__()

class PR_Ok(PR, NamedTuple('Ok', [('v', Any), ('rest', Any)])):
    def __dafnystr__(self) -> str:
        return f'GoalRender.PR.Ok({_dafny.string_of(self.v)}, {_dafny.string_of(self.rest)})'
    def __eq__(self, __o: object) -> bool:
        return isinstance(__o, PR_Ok) and self.v == __o.v and self.rest == __o.rest
    def __hash__(self) -> int:
        return super().__hash__()

