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
import atlas_pca.goal_kernel_gen.GoalRender as GoalRender

# Module: GoalApi

class default__:
    def  __init__(self):
        pass

    @staticmethod
    def DecParamDecl(ts):
        if ((len(ts)) == (0)) or (((ts)[0]) != (GoalRender.Tok_TKw(500))):
            return GoalRender.PR_Fail()
        elif True:
            source0_ = GoalRender.default__.DecStr(_dafny.SeqWithoutIsStrInference((ts)[1::]))
            if True:
                if source0_.is_Fail:
                    return GoalRender.PR_Fail()
            if True:
                d_0_p_ = source0_.v
                d_1_r1_ = source0_.rest
                source1_ = GoalRender.default__.DecTy(d_1_r1_)
                if True:
                    if source1_.is_Fail:
                        return GoalRender.PR_Fail()
                if True:
                    d_2_ty_ = source1_.v
                    d_3_r2_ = source1_.rest
                    return GoalRender.PR_Ok(GoalIr.ParamDecl_ParamDecl(d_0_p_, d_2_ty_), d_3_r2_)

    @staticmethod
    def DecParamDeclsElems(ts, n):
        if (n) == (0):
            return GoalRender.PR_Ok(_dafny.SeqWithoutIsStrInference([]), ts)
        elif True:
            source0_ = default__.DecParamDecl(ts)
            if True:
                if source0_.is_Fail:
                    return GoalRender.PR_Fail()
            if True:
                d_0_x_ = source0_.v
                d_1_r_ = source0_.rest
                source1_ = default__.DecParamDeclsElems(d_1_r_, (n) - (1))
                if True:
                    if source1_.is_Fail:
                        return GoalRender.PR_Fail()
                if True:
                    d_2_xs_ = source1_.v
                    d_3_r2_ = source1_.rest
                    return GoalRender.PR_Ok((_dafny.SeqWithoutIsStrInference([d_0_x_])) + (d_2_xs_), d_3_r2_)

    @staticmethod
    def DecParamDecls(ts):
        if (((len(ts)) > (0)) and (((ts)[0]).is_TI)) and ((((ts)[0]).i) >= (0)):
            return default__.DecParamDeclsElems(_dafny.SeqWithoutIsStrInference((ts)[1::]), ((ts)[0]).i)
        elif True:
            return GoalRender.PR_Fail()

    @staticmethod
    def DecVerbDecl(ts):
        if ((len(ts)) == (0)) or (((ts)[0]) != (GoalRender.Tok_TKw(501))):
            return GoalRender.PR_Fail()
        elif True:
            source0_ = GoalRender.default__.DecStr(_dafny.SeqWithoutIsStrInference((ts)[1::]))
            if True:
                if source0_.is_Fail:
                    return GoalRender.PR_Fail()
            if True:
                d_0_v_ = source0_.v
                d_1_r1_ = source0_.rest
                source1_ = GoalRender.default__.DecStr(d_1_r1_)
                if True:
                    if source1_.is_Fail:
                        return GoalRender.PR_Fail()
                if True:
                    d_2_c_ = source1_.v
                    d_3_r2_ = source1_.rest
                    source2_ = default__.DecParamDecls(d_3_r2_)
                    if True:
                        if source2_.is_Fail:
                            return GoalRender.PR_Fail()
                    if True:
                        d_4_ps_ = source2_.v
                        d_5_r3_ = source2_.rest
                        return GoalRender.PR_Ok(GoalIr.VerbDecl_VerbDecl(d_0_v_, d_2_c_, d_4_ps_), d_5_r3_)

    @staticmethod
    def DecRelDecl(ts):
        if ((len(ts)) == (0)) or (((ts)[0]) != (GoalRender.Tok_TKw(502))):
            return GoalRender.PR_Fail()
        elif True:
            source0_ = GoalRender.default__.DecStr(_dafny.SeqWithoutIsStrInference((ts)[1::]))
            if True:
                if source0_.is_Fail:
                    return GoalRender.PR_Fail()
            if True:
                d_0_rel_ = source0_.v
                d_1_r1_ = source0_.rest
                source1_ = GoalRender.default__.DecStr(d_1_r1_)
                if True:
                    if source1_.is_Fail:
                        return GoalRender.PR_Fail()
                if True:
                    d_2_an_ = source1_.v
                    d_3_r2_ = source1_.rest
                    source2_ = GoalRender.default__.DecStrs(d_3_r2_)
                    if True:
                        if source2_.is_Fail:
                            return GoalRender.PR_Fail()
                    if True:
                        d_4_ms_ = source2_.v
                        d_5_r3_ = source2_.rest
                        return GoalRender.PR_Ok(GoalIr.RelDecl_RelDecl(d_0_rel_, d_2_an_, d_4_ms_), d_5_r3_)

    @staticmethod
    def DecVerbDeclsElems(ts, n):
        if (n) == (0):
            return GoalRender.PR_Ok(_dafny.SeqWithoutIsStrInference([]), ts)
        elif True:
            source0_ = default__.DecVerbDecl(ts)
            if True:
                if source0_.is_Fail:
                    return GoalRender.PR_Fail()
            if True:
                d_0_x_ = source0_.v
                d_1_r_ = source0_.rest
                source1_ = default__.DecVerbDeclsElems(d_1_r_, (n) - (1))
                if True:
                    if source1_.is_Fail:
                        return GoalRender.PR_Fail()
                if True:
                    d_2_xs_ = source1_.v
                    d_3_r2_ = source1_.rest
                    return GoalRender.PR_Ok((_dafny.SeqWithoutIsStrInference([d_0_x_])) + (d_2_xs_), d_3_r2_)

    @staticmethod
    def DecVerbDecls(ts):
        if (((len(ts)) > (0)) and (((ts)[0]).is_TI)) and ((((ts)[0]).i) >= (0)):
            return default__.DecVerbDeclsElems(_dafny.SeqWithoutIsStrInference((ts)[1::]), ((ts)[0]).i)
        elif True:
            return GoalRender.PR_Fail()

    @staticmethod
    def DecRelDeclsElems(ts, n):
        if (n) == (0):
            return GoalRender.PR_Ok(_dafny.SeqWithoutIsStrInference([]), ts)
        elif True:
            source0_ = default__.DecRelDecl(ts)
            if True:
                if source0_.is_Fail:
                    return GoalRender.PR_Fail()
            if True:
                d_0_x_ = source0_.v
                d_1_r_ = source0_.rest
                source1_ = default__.DecRelDeclsElems(d_1_r_, (n) - (1))
                if True:
                    if source1_.is_Fail:
                        return GoalRender.PR_Fail()
                if True:
                    d_2_xs_ = source1_.v
                    d_3_r2_ = source1_.rest
                    return GoalRender.PR_Ok((_dafny.SeqWithoutIsStrInference([d_0_x_])) + (d_2_xs_), d_3_r2_)

    @staticmethod
    def DecRelDecls(ts):
        if (((len(ts)) > (0)) and (((ts)[0]).is_TI)) and ((((ts)[0]).i) >= (0)):
            return default__.DecRelDeclsElems(_dafny.SeqWithoutIsStrInference((ts)[1::]), ((ts)[0]).i)
        elif True:
            return GoalRender.PR_Fail()

    @staticmethod
    def DecOntology(ts):
        if ((len(ts)) == (0)) or (((ts)[0]) != (GoalRender.Tok_TKw(510))):
            return GoalRender.PR_Fail()
        elif True:
            source0_ = default__.DecVerbDecls(_dafny.SeqWithoutIsStrInference((ts)[1::]))
            if True:
                if source0_.is_Fail:
                    return GoalRender.PR_Fail()
            if True:
                d_0_vs_ = source0_.v
                d_1_r1_ = source0_.rest
                source1_ = default__.DecRelDecls(d_1_r1_)
                if True:
                    if source1_.is_Fail:
                        return GoalRender.PR_Fail()
                if True:
                    d_2_rs_ = source1_.v
                    d_3_r2_ = source1_.rest
                    return GoalRender.PR_Ok(GoalIr.Ontology_Ontology(d_0_vs_, d_2_rs_), d_3_r2_)

    @staticmethod
    def DecParamEntries(ts, n):
        if (n) == (0):
            return GoalRender.PR_Ok(_dafny.Map({}), ts)
        elif ((len(ts)) == (0)) or (((ts)[0]) != (GoalRender.Tok_TKw(520))):
            return GoalRender.PR_Fail()
        elif True:
            source0_ = GoalRender.default__.DecStr(_dafny.SeqWithoutIsStrInference((ts)[1::]))
            if True:
                if source0_.is_Fail:
                    return GoalRender.PR_Fail()
            if True:
                d_0_k_ = source0_.v
                d_1_r1_ = source0_.rest
                source1_ = GoalRender.default__.DecV(d_1_r1_)
                if True:
                    if source1_.is_Fail:
                        return GoalRender.PR_Fail()
                if True:
                    d_2_v_ = source1_.v
                    d_3_r2_ = source1_.rest
                    source2_ = default__.DecParamEntries(d_3_r2_, (n) - (1))
                    if True:
                        if source2_.is_Fail:
                            return GoalRender.PR_Fail()
                    if True:
                        d_4_m_ = source2_.v
                        d_5_r3_ = source2_.rest
                        return GoalRender.PR_Ok((d_4_m_).set(d_0_k_, d_2_v_), d_5_r3_)

    @staticmethod
    def DecParams(ts):
        if (((len(ts)) > (0)) and (((ts)[0]).is_TI)) and ((((ts)[0]).i) >= (0)):
            return default__.DecParamEntries(_dafny.SeqWithoutIsStrInference((ts)[1::]), ((ts)[0]).i)
        elif True:
            return GoalRender.PR_Fail()

    @staticmethod
    def DecAct(ts):
        if ((len(ts)) == (0)) or (((ts)[0]) != (GoalRender.Tok_TKw(530))):
            return GoalRender.PR_Fail()
        elif True:
            source0_ = GoalRender.default__.DecStr(_dafny.SeqWithoutIsStrInference((ts)[1::]))
            if True:
                if source0_.is_Fail:
                    return GoalRender.PR_Fail()
            if True:
                d_0_verb_ = source0_.v
                d_1_r1_ = source0_.rest
                source1_ = GoalRender.default__.DecStr(d_1_r1_)
                if True:
                    if source1_.is_Fail:
                        return GoalRender.PR_Fail()
                if True:
                    d_2_res_ = source1_.v
                    d_3_r2_ = source1_.rest
                    source2_ = default__.DecParams(d_3_r2_)
                    if True:
                        if source2_.is_Fail:
                            return GoalRender.PR_Fail()
                    if True:
                        d_4_ps_ = source2_.v
                        d_5_r3_ = source2_.rest
                        source3_ = GoalRender.default__.DecInt(d_5_r3_)
                        if True:
                            if source3_.is_Fail:
                                return GoalRender.PR_Fail()
                        if True:
                            d_6_t_ = source3_.v
                            d_7_r4_ = source3_.rest
                            source4_ = GoalRender.default__.DecStr(d_7_r4_)
                            if True:
                                if source4_.is_Fail:
                                    return GoalRender.PR_Fail()
                            if True:
                                d_8_sess_ = source4_.v
                                d_9_r5_ = source4_.rest
                                source5_ = GoalRender.default__.DecStr(d_9_r5_)
                                if True:
                                    if source5_.is_Fail:
                                        return GoalRender.PR_Fail()
                                if True:
                                    d_10_prin_ = source5_.v
                                    d_11_r6_ = source5_.rest
                                    source6_ = GoalRender.default__.DecStr(d_11_r6_)
                                    if True:
                                        if source6_.is_Fail:
                                            return GoalRender.PR_Fail()
                                    if True:
                                        d_12_org_ = source6_.v
                                        d_13_r7_ = source6_.rest
                                        source7_ = GoalRender.default__.DecStr(d_13_r7_)
                                        if True:
                                            if source7_.is_Fail:
                                                return GoalRender.PR_Fail()
                                        if True:
                                            d_14_agent_ = source7_.v
                                            d_15_r8_ = source7_.rest
                                            source8_ = GoalRender.default__.DecInt(d_15_r8_)
                                            if True:
                                                if source8_.is_Fail:
                                                    return GoalRender.PR_Fail()
                                            if True:
                                                d_16_depth_ = source8_.v
                                                d_17_r9_ = source8_.rest
                                                return GoalRender.PR_Ok(GoalIr.Act_Act(d_0_verb_, d_2_res_, d_4_ps_, d_6_t_, d_8_sess_, d_10_prin_, d_12_org_, d_14_agent_, d_16_depth_), d_17_r9_)

    @staticmethod
    def DecAdm(ts):
        if ((len(ts)) == (0)) or (((ts)[0]) != (GoalRender.Tok_TKw(531))):
            return GoalRender.PR_Fail()
        elif True:
            source0_ = GoalRender.default__.DecStr(_dafny.SeqWithoutIsStrInference((ts)[1::]))
            if True:
                if source0_.is_Fail:
                    return GoalRender.PR_Fail()
            if True:
                d_0_gid_ = source0_.v
                d_1_r1_ = source0_.rest
                source1_ = default__.DecAct(d_1_r1_)
                if True:
                    if source1_.is_Fail:
                        return GoalRender.PR_Fail()
                if True:
                    d_2_a_ = source1_.v
                    d_3_r2_ = source1_.rest
                    return GoalRender.PR_Ok(GoalIr.Adm_Adm(d_0_gid_, d_2_a_), d_3_r2_)

    @staticmethod
    def DecAdmsElems(ts, n):
        if (n) == (0):
            return GoalRender.PR_Ok(_dafny.SeqWithoutIsStrInference([]), ts)
        elif True:
            source0_ = default__.DecAdm(ts)
            if True:
                if source0_.is_Fail:
                    return GoalRender.PR_Fail()
            if True:
                d_0_x_ = source0_.v
                d_1_r_ = source0_.rest
                source1_ = default__.DecAdmsElems(d_1_r_, (n) - (1))
                if True:
                    if source1_.is_Fail:
                        return GoalRender.PR_Fail()
                if True:
                    d_2_xs_ = source1_.v
                    d_3_r2_ = source1_.rest
                    return GoalRender.PR_Ok((_dafny.SeqWithoutIsStrInference([d_0_x_])) + (d_2_xs_), d_3_r2_)

    @staticmethod
    def DecAdms(ts):
        if (((len(ts)) > (0)) and (((ts)[0]).is_TI)) and ((((ts)[0]).i) >= (0)):
            return default__.DecAdmsElems(_dafny.SeqWithoutIsStrInference((ts)[1::]), ((ts)[0]).i)
        elif True:
            return GoalRender.PR_Fail()

    @staticmethod
    def DecAggEntries(ts, n):
        if (n) == (0):
            return GoalRender.PR_Ok(_dafny.Map({}), ts)
        elif ((len(ts)) == (0)) or (((ts)[0]) != (GoalRender.Tok_TKw(540))):
            return GoalRender.PR_Fail()
        elif True:
            source0_ = GoalRender.default__.DecStr(_dafny.SeqWithoutIsStrInference((ts)[1::]))
            if True:
                if source0_.is_Fail:
                    return GoalRender.PR_Fail()
            if True:
                d_0_k_ = source0_.v
                d_1_r1_ = source0_.rest
                source1_ = GoalRender.default__.DecQ(d_1_r1_)
                if True:
                    if source1_.is_Fail:
                        return GoalRender.PR_Fail()
                if True:
                    d_2_q_ = source1_.v
                    d_3_r2_ = source1_.rest
                    source2_ = default__.DecAggEntries(d_3_r2_, (n) - (1))
                    if True:
                        if source2_.is_Fail:
                            return GoalRender.PR_Fail()
                    if True:
                        d_4_m_ = source2_.v
                        d_5_r3_ = source2_.rest
                        return GoalRender.PR_Ok((d_4_m_).set(d_0_k_, d_2_q_), d_5_r3_)

    @staticmethod
    def DecAggs(ts):
        if (((len(ts)) > (0)) and (((ts)[0]).is_TI)) and ((((ts)[0]).i) >= (0)):
            return default__.DecAggEntries(_dafny.SeqWithoutIsStrInference((ts)[1::]), ((ts)[0]).i)
        elif True:
            return GoalRender.PR_Fail()

    @staticmethod
    def DecHist(ts):
        if ((len(ts)) == (0)) or (((ts)[0]) != (GoalRender.Tok_TKw(541))):
            return GoalRender.PR_Fail()
        elif True:
            source0_ = default__.DecAdms(_dafny.SeqWithoutIsStrInference((ts)[1::]))
            if True:
                if source0_.is_Fail:
                    return GoalRender.PR_Fail()
            if True:
                d_0_adms_ = source0_.v
                d_1_r1_ = source0_.rest
                source1_ = GoalRender.default__.DecInt(d_1_r1_)
                if True:
                    if source1_.is_Fail:
                        return GoalRender.PR_Fail()
                if True:
                    d_2_last_ = source1_.v
                    d_3_r2_ = source1_.rest
                    source2_ = default__.DecAggs(d_3_r2_)
                    if True:
                        if source2_.is_Fail:
                            return GoalRender.PR_Fail()
                    if True:
                        d_4_aggs_ = source2_.v
                        d_5_r3_ = source2_.rest
                        return GoalRender.PR_Ok(GoalIr.Hist_Hist(d_0_adms_, d_2_last_, d_4_aggs_), d_5_r3_)

    @staticmethod
    def Whole(r):
        source0_ = r
        if True:
            if source0_.is_Ok:
                d_0_v_ = source0_.v
                d_1_rest_ = source0_.rest
                if (len(d_1_rest_)) == (0):
                    return GoalIr.Option_Some(d_0_v_)
                elif True:
                    return GoalIr.Option_None()
        if True:
            return GoalIr.Option_None()

    @staticmethod
    def EncResPat(p):
        source0_ = p
        if True:
            if source0_.is_PStar:
                return _dafny.SeqWithoutIsStrInference([GoalRender.Tok_TKw(630)])
        if True:
            d_0_ids_ = source0_.ids
            return (_dafny.SeqWithoutIsStrInference([GoalRender.Tok_TKw(631)])) + (GoalRender.default__.EncStrs(d_0_ids_))

    @staticmethod
    def EncNC(c):
        source0_ = c
        if True:
            if source0_.is_NTrue:
                return _dafny.SeqWithoutIsStrInference([GoalRender.Tok_TKw(600)])
        if True:
            if source0_.is_NFalse:
                return _dafny.SeqWithoutIsStrInference([GoalRender.Tok_TKw(601)])
        if True:
            if source0_.is_NAtom:
                d_0_op_ = source0_.op
                d_1_l_ = source0_.l
                d_2_r_ = source0_.r
                return (_dafny.SeqWithoutIsStrInference([GoalRender.Tok_TKw(602)])) + ((GoalRender.default__.EncOp(d_0_op_)) + ((GoalRender.default__.EncTerm(d_1_l_)) + (GoalRender.default__.EncTerm(d_2_r_))))
        if True:
            if source0_.is_NAnd:
                d_3_x_ = source0_.a
                d_4_y_ = source0_.b
                return (_dafny.SeqWithoutIsStrInference([GoalRender.Tok_TKw(603)])) + ((default__.EncNC(d_3_x_)) + (default__.EncNC(d_4_y_)))
        if True:
            d_5_x_ = source0_.a
            d_6_y_ = source0_.b
            return (_dafny.SeqWithoutIsStrInference([GoalRender.Tok_TKw(604)])) + ((default__.EncNC(d_5_x_)) + (default__.EncNC(d_6_y_)))

    @staticmethod
    def EncLPred(p):
        return (_dafny.SeqWithoutIsStrInference([GoalRender.Tok_TKw(620)])) + ((GoalRender.default__.EncStr((p).gid)) + ((GoalRender.default__.EncStr((p).verb)) + ((default__.EncResPat((p).res)) + (default__.EncNC((p).cond)))))

    @staticmethod
    def EncLProh(p):
        return (_dafny.SeqWithoutIsStrInference([GoalRender.Tok_TKw(640)])) + ((GoalRender.default__.EncStr((p).pid)) + ((GoalRender.default__.EncStrs((p).verbs)) + ((default__.EncResPat((p).res)) + (default__.EncNC((p).cond)))))

    @staticmethod
    def EncLCeil(c):
        return (_dafny.SeqWithoutIsStrInference([GoalRender.Tok_TKw(610)])) + ((GoalRender.default__.EncStr((c).bid)) + ((GoalRender.default__.EncStrs(((c).sel).gids)) + ((GoalRender.default__.EncStrs(((c).sel).verbs)) + (GoalRender.default__.EncBCore((c).core)))))

    @staticmethod
    def EncLPredsElems(xs):
        d_0___accumulator_ = _dafny.SeqWithoutIsStrInference([])
        while True:
            with _dafny.label():
                if (len(xs)) == (0):
                    return (d_0___accumulator_) + (_dafny.SeqWithoutIsStrInference([]))
                elif True:
                    d_0___accumulator_ = (d_0___accumulator_) + (default__.EncLPred((xs)[0]))
                    in0_ = _dafny.SeqWithoutIsStrInference((xs)[1::])
                    xs = in0_
                    raise _dafny.TailCall()
                break

    @staticmethod
    def EncLPreds(xs):
        return (_dafny.SeqWithoutIsStrInference([GoalRender.Tok_TI(len(xs))])) + (default__.EncLPredsElems(xs))

    @staticmethod
    def EncLProhsElems(xs):
        d_0___accumulator_ = _dafny.SeqWithoutIsStrInference([])
        while True:
            with _dafny.label():
                if (len(xs)) == (0):
                    return (d_0___accumulator_) + (_dafny.SeqWithoutIsStrInference([]))
                elif True:
                    d_0___accumulator_ = (d_0___accumulator_) + (default__.EncLProh((xs)[0]))
                    in0_ = _dafny.SeqWithoutIsStrInference((xs)[1::])
                    xs = in0_
                    raise _dafny.TailCall()
                break

    @staticmethod
    def EncLProhs(xs):
        return (_dafny.SeqWithoutIsStrInference([GoalRender.Tok_TI(len(xs))])) + (default__.EncLProhsElems(xs))

    @staticmethod
    def EncLCeilsElems(xs):
        d_0___accumulator_ = _dafny.SeqWithoutIsStrInference([])
        while True:
            with _dafny.label():
                if (len(xs)) == (0):
                    return (d_0___accumulator_) + (_dafny.SeqWithoutIsStrInference([]))
                elif True:
                    d_0___accumulator_ = (d_0___accumulator_) + (default__.EncLCeil((xs)[0]))
                    in0_ = _dafny.SeqWithoutIsStrInference((xs)[1::])
                    xs = in0_
                    raise _dafny.TailCall()
                break

    @staticmethod
    def EncLCeils(xs):
        return (_dafny.SeqWithoutIsStrInference([GoalRender.Tok_TI(len(xs))])) + (default__.EncLCeilsElems(xs))

    @staticmethod
    def EncNCsElems(xs):
        d_0___accumulator_ = _dafny.SeqWithoutIsStrInference([])
        while True:
            with _dafny.label():
                if (len(xs)) == (0):
                    return (d_0___accumulator_) + (_dafny.SeqWithoutIsStrInference([]))
                elif True:
                    d_0___accumulator_ = (d_0___accumulator_) + (default__.EncNC((xs)[0]))
                    in0_ = _dafny.SeqWithoutIsStrInference((xs)[1::])
                    xs = in0_
                    raise _dafny.TailCall()
                break

    @staticmethod
    def EncNCs(xs):
        return (_dafny.SeqWithoutIsStrInference([GoalRender.Tok_TI(len(xs))])) + (default__.EncNCsElems(xs))

    @staticmethod
    def EncPol(p):
        return (_dafny.SeqWithoutIsStrInference([GoalRender.Tok_TKw(650)])) + ((default__.EncLPreds((p).preds)) + ((default__.EncLProhs((p).prohs)) + ((default__.EncLCeils((p).ceils)) + ((default__.EncNCs((p).escs)) + ((GoalRender.default__.EncValidity((p).validity)) + (GoalRender.default__.EncDeleg((p).deleg)))))))

    @staticmethod
    def MkKw(k):
        return GoalRender.Tok_TKw(k)

    @staticmethod
    def MkI(i):
        return GoalRender.Tok_TI(i)

    @staticmethod
    def MkS(s):
        return GoalRender.Tok_TS(s)

    @staticmethod
    def TokKind(t):
        source0_ = t
        if True:
            if source0_.is_TKw:
                return 0
        if True:
            if source0_.is_TI:
                return 1
        if True:
            return 2

    @staticmethod
    def TokKw(t):
        source0_ = t
        if True:
            if source0_.is_TKw:
                d_0_k_ = source0_.k
                return d_0_k_
        if True:
            return 0

    @staticmethod
    def TokInt(t):
        source0_ = t
        if True:
            if source0_.is_TI:
                d_0_i_ = source0_.i
                return d_0_i_
        if True:
            return 0

    @staticmethod
    def TokStr(t):
        source0_ = t
        if True:
            if source0_.is_TS:
                d_0_s_ = source0_.s
                return d_0_s_
        if True:
            return _dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, ""))

    @staticmethod
    def Bad():
        return _dafny.SeqWithoutIsStrInference([GoalRender.Tok_TI(9)])

    @staticmethod
    def ParseG(ts):
        return GoalRender.default__.Parse(ts)

    @staticmethod
    def TypecheckT(gt, ot):
        source0_ = (default__.ParseG(gt), default__.Whole(default__.DecOntology(ot)))
        if True:
            d_00_ = source0_[0]
            if d_00_.is_Some:
                d_0_g_ = d_00_.v
                d_10_ = source0_[1]
                if d_10_.is_Some:
                    d_1_o_ = d_10_.v
                    d_2_rs_ = GoalCompile.default__.TypeReasons(d_1_o_, d_0_g_)
                    if (len(d_2_rs_)) == (0):
                        return _dafny.SeqWithoutIsStrInference([GoalRender.Tok_TI(0)])
                    elif True:
                        return (_dafny.SeqWithoutIsStrInference([GoalRender.Tok_TI(1)])) + (GoalRender.default__.EncStrs(d_2_rs_))
        if True:
            return default__.Bad()

    @staticmethod
    def CompileT(gt, ot):
        source0_ = (default__.ParseG(gt), default__.Whole(default__.DecOntology(ot)))
        if True:
            d_00_ = source0_[0]
            if d_00_.is_Some:
                d_0_g_ = d_00_.v
                d_10_ = source0_[1]
                if d_10_.is_Some:
                    d_1_o_ = d_10_.v
                    source1_ = GoalCompile.default__.Compile(d_1_o_, d_0_g_)
                    if True:
                        if source1_.is_Compiled:
                            d_2_p_ = source1_.p
                            return (_dafny.SeqWithoutIsStrInference([GoalRender.Tok_TI(0)])) + (default__.EncPol(d_2_p_))
                    if True:
                        d_3_rs_ = source1_.reasons
                        return (_dafny.SeqWithoutIsStrInference([GoalRender.Tok_TI(1)])) + (GoalRender.default__.EncStrs(d_3_rs_))
        if True:
            return default__.Bad()

    @staticmethod
    def DecideGoalT(gt, ot, at, ht):
        source0_ = (default__.ParseG(gt), default__.Whole(default__.DecOntology(ot)), default__.Whole(default__.DecAct(at)), default__.Whole(default__.DecHist(ht)))
        if True:
            d_00_ = source0_[0]
            if d_00_.is_Some:
                d_0_g_ = d_00_.v
                d_10_ = source0_[1]
                if d_10_.is_Some:
                    d_1_o_ = d_10_.v
                    d_20_ = source0_[2]
                    if d_20_.is_Some:
                        d_2_a_ = d_20_.v
                        d_30_ = source0_[3]
                        if d_30_.is_Some:
                            d_3_h_ = d_30_.v
                            return _dafny.SeqWithoutIsStrInference([GoalRender.Tok_TI(0), GoalRender.Tok_TI(GoalIr.default__.DG(d_1_o_, d_0_g_, d_2_a_, d_3_h_))])
        if True:
            return default__.Bad()

    @staticmethod
    def DecidePolicyT(gt, ot, at, ht):
        source0_ = (default__.ParseG(gt), default__.Whole(default__.DecOntology(ot)), default__.Whole(default__.DecAct(at)), default__.Whole(default__.DecHist(ht)))
        if True:
            d_00_ = source0_[0]
            if d_00_.is_Some:
                d_0_g_ = d_00_.v
                d_10_ = source0_[1]
                if d_10_.is_Some:
                    d_1_o_ = d_10_.v
                    d_20_ = source0_[2]
                    if d_20_.is_Some:
                        d_2_a_ = d_20_.v
                        d_30_ = source0_[3]
                        if d_30_.is_Some:
                            d_3_h_ = d_30_.v
                            source1_ = GoalCompile.default__.Compile(d_1_o_, d_0_g_)
                            if True:
                                if source1_.is_CEscalate:
                                    d_4_rs_ = source1_.reasons
                                    return (_dafny.SeqWithoutIsStrInference([GoalRender.Tok_TI(1)])) + (GoalRender.default__.EncStrs(d_4_rs_))
                            if True:
                                d_5_p_ = source1_.p
                                d_6_r_ = GoalWitness.default__.DecideW(d_5_p_, d_2_a_, d_3_h_)
                                return ((_dafny.SeqWithoutIsStrInference([GoalRender.Tok_TI(0), GoalRender.Tok_TI((d_6_r_)[0]), GoalRender.Tok_TS(((d_6_r_)[1]).gid)])) + (GoalRender.default__.EncStrs(((d_6_r_)[1]).bids))) + (_dafny.SeqWithoutIsStrInference([GoalRender.Tok_TI((1 if (((d_6_r_)[0]) == (GoalIr.default__.Allow)) and (GoalWitness.default__.VerifyWitness(d_5_p_, d_2_a_, d_3_h_, (d_6_r_)[1])) else 0))]))
        if True:
            return default__.Bad()

    @staticmethod
    def RenderT(gt):
        source0_ = default__.ParseG(gt)
        if True:
            if source0_.is_Some:
                d_0_g_ = source0_.v
                return (_dafny.SeqWithoutIsStrInference([GoalRender.Tok_TI(0)])) + (GoalRender.default__.Render(d_0_g_))
        if True:
            return default__.Bad()

