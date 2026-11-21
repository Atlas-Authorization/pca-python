"""``pow`` as the reference runtime computes it: fdlibm's __ieee754_pow (e_pow.c), statement for statement with the same constants, plus the
rule that (+-1) ** +-Infinity is NaN. The platform libm may round the last bit differently; values that feed a verdict use this routine.

Method: log2(x) to extra precision as t1 + t2, y * log2(x) = n + y' with |y'| <= 0.5, x ** y = 2 ** n * exp(y' * ln2). Plain IEEE-754
double arithmetic (Python floats), no fused multiply-add; the 32-bit word arithmetic of the original is done on wrapped integers."""
import math
import struct

_F = float.fromhex
_INF = math.inf
_SIGNIF = 0x7FFFFFFF


def _i32(v: int) -> int:
    v &= 0xFFFFFFFF
    return v - 0x100000000 if v & 0x80000000 else v


def _bits(x: float) -> int:
    return struct.unpack(">Q", struct.pack(">d", x))[0]


def _hi(x: float) -> int:
    return _i32(_bits(x) >> 32)


def _lo(x: float) -> int:
    return _i32(_bits(x))


def _set_hi(x: float, h: int) -> float:
    return struct.unpack(">d", struct.pack(">Q", ((h & 0xFFFFFFFF) << 32) | (_bits(x) & 0xFFFFFFFF)))[0]


def _lo0(x: float) -> float:
    return struct.unpack(">d", struct.pack(">Q", _bits(x) & 0xFFFFFFFF00000000))[0]


def _recip(z: float) -> float:
    return math.copysign(_INF, z) if z == 0.0 else 1.0 / z


def pow(x: float, y: float) -> float:  # noqa: A001 - the name of the function it reproduces
    x, y = float(x), float(y)
    if y == 0.0:
        return 1.0
    if x != x or y != y:
        return math.nan
    y_abs = abs(y)
    x_abs = abs(x)
    if y == 2.0:
        return x * x
    if y == 0.5:
        if x >= -1.7976931348623157e308:  # x == -infinity is handled below
            return math.sqrt(x + 0.0) if x >= 0.0 else math.nan
    elif y_abs == 1.0:
        return x if y == 1.0 else _recip(x)
    elif y_abs == _INF:
        if x_abs == 1.0:
            return math.nan
        if x_abs > 1.0:
            return y if y >= 0 else 0.0
        return -y if y < 0 else 0.0

    hx = _hi(x)
    ix = hx & _SIGNIF

    # y_is_int = 0: y is not an integer, 1: an odd integer, 2: an even integer (only needed for x < 0)
    y_is_int = 0
    if hx < 0:
        if y_abs >= 9007199254740992.0:
            y_is_int = 2
        elif y_abs >= 1.0:
            as_long = int(y_abs)
            if float(as_long) == y_abs:
                y_is_int = 2 - (as_long & 1)

    if x_abs == 0.0 or x_abs == _INF or x_abs == 1.0:
        z = x_abs
        if y < 0.0:
            z = _recip(z)
        if hx < 0:
            if (_i32(ix - 0x3FF00000) | y_is_int) == 0:
                z = math.nan  # (-1) ** non-integer
            elif y_is_int == 1:
                z = -1.0 * z
        return z

    n = _i32((hx >> 31) + 1)
    if (n | y_is_int) == 0:
        return math.nan  # (x < 0) ** non-integer

    s = 1.0  # sign of the result: -1 for (negative) ** (odd integer)
    if (n | _i32(y_is_int - 1)) == 0:
        s = -1.0

    if y_abs > _F("0x1.00000ffffffffp31"):  # |y| is huge
        inv_ln2 = _F("0x1.71547652b82fep0")
        inv_ln2_h = _F("0x1.71547p+0")
        inv_ln2_l = _F("0x1.94ae0bf85ddf4p-22")
        if x_abs < _F("0x1.fffff00000000p-1"):
            return s * _INF if y < 0.0 else s * 0.0
        if x_abs > _F("0x1.00000ffffffffp0"):
            return s * _INF if y > 0.0 else s * 0.0
        t = x_abs - 1.0
        w = (t * t) * (0.5 - t * (0.3333333333333333333333 - t * 0.25))
        u = inv_ln2_h * t
        v = t * inv_ln2_l - w * inv_ln2
        t1 = _lo0(u + v)
        t2 = v - (t1 - u)
    else:
        cp = _F("0x1.ec709dc3a03fdp-1")
        cp_h = _F("0x1.ec709ep-1")
        cp_l = -_F("0x1.e2fe0145b01f5p-28")
        n = 0
        if ix < 0x00100000:  # subnormal x
            x_abs *= 9007199254740992.0
            n = _i32(n - 53)
            ix = _hi(x_abs)
        n = _i32(n + ((ix >> 20) - 0x3FF))
        j = ix & 0x000FFFFF
        ix = j | 0x3FF00000
        if j <= 0x3988E:
            k = 0
        elif j < 0xBB67A:
            k = 1
        else:
            k = 0
            n = _i32(n + 1)
            ix = _i32(ix - 0x00100000)
        x_abs = _set_hi(x_abs, ix)

        dp_h = _F("0x1.2b8034p-1")
        dp_l = _F("0x1.cfdeb43cfd006p-27")
        l1 = _F("0x1.3333333333303p-1")
        l2 = _F("0x1.b6db6db6fabffp-2")
        l3 = _F("0x1.55555518f264dp-2")
        l4 = _F("0x1.17460a91d4101p-2")
        l5 = _F("0x1.d864a93c9db65p-3")
        l6 = _F("0x1.a7e284a454eefp-3")
        kd = float(k)
        bp_k = 1.0 + 0.5 * kd
        u = x_abs - bp_k
        v = 1.0 / (x_abs + bp_k)
        ss = u * v
        s_h = _lo0(ss)
        t_h = _set_hi(0.0, _i32(_i32(((ix >> 1) | 0x20000000) + 0x00080000) + _i32(k << 18)))
        t_l = x_abs - (t_h - bp_k)
        s_l = v * ((u - s_h * t_h) - s_h * t_l)
        s2 = ss * ss
        r = s2 * s2 * (l1 + s2 * (l2 + s2 * (l3 + s2 * (l4 + s2 * (l5 + s2 * l6)))))
        r += s_l * (s_h + ss)
        s2 = s_h * s_h
        t_h = _lo0(3.0 + s2 + r)
        t_l = r - ((t_h - 3.0) - s2)
        u = s_h * t_h
        v = s_l * t_h + t_l * ss
        p_h = _lo0(u + v)
        p_l = v - (p_h - u)
        z_h = cp_h * p_h
        z_l = cp_l * p_h + p_l * cp + dp_l * kd
        t = float(n)
        t1 = _lo0(((z_h + z_l) + dp_h * kd) + t)
        t2 = z_l - (((t1 - t) - dp_h * kd) - z_h)

    # split y into y1 + y2 and compute (y1 + y2) * (t1 + t2)
    y1 = _lo0(y)
    p_l = (y - y1) * t1 + y * t2
    p_h = y1 * t1
    z = p_l + p_h
    j = _hi(z)
    i = _lo(z)
    if j >= 0x40900000:  # z >= 1024
        if (_i32(j - 0x40900000) | i) != 0:
            return s * _INF
        if p_l + 8.0085662595372944372e-0017 > z - p_h:
            return s * _INF
    elif (j & _SIGNIF) >= 0x4090CC00:  # z <= -1075
        if (_i32(j - _i32(0xC090CC00)) | i) != 0:
            return s * 0.0
        if p_l <= z - p_h:
            return s * 0.0

    # 2 ** (p_h + p_l)
    p1 = _F("0x1.555555555553ep-3")
    p2 = -_F("0x1.6c16c16bebd93p-9")
    p3 = _F("0x1.1566aaf25de2cp-14")
    p4 = -_F("0x1.bbd41c5d26bf1p-20")
    p5 = _F("0x1.6376972bea4d0p-25")
    lg2 = _F("0x1.62e42fefa39efp-1")
    lg2_h = _F("0x1.62e43p-1")
    lg2_l = -_F("0x1.05c610ca86c39p-29")
    i = j & _SIGNIF
    k = (i >> 20) - 0x3FF
    n = 0
    if i > 0x3FE00000:  # |z| > 0.5: n = [z + 0.5]
        n = _i32(j + (0x00100000 >> (k + 1)))
        k = ((n & _SIGNIF) >> 20) - 0x3FF
        t = _set_hi(0.0, n & ~(0x000FFFFF >> k))
        n = ((n & 0x000FFFFF) | 0x00100000) >> (20 - k)
        if j < 0:
            n = -n
        p_h -= t
    t = _lo0(p_l + p_h)
    u = t * lg2_h
    v = (p_l - (t - p_h)) * lg2 + t * lg2_l
    z = u + v
    w = v - (z - u)
    t = z * z
    t1 = z - t * (p1 + t * (p2 + t * (p3 + t * (p4 + t * p5))))
    r = (z * t1) / (t1 - 2.0) - (w + z * w)
    z = 1.0 - (r - z)
    j = _i32(_hi(z) + _i32(n << 20))
    if (j >> 20) <= 0:
        z = math.ldexp(z, n)  # subnormal output
    else:
        z = _set_hi(z, _i32(_hi(z) + _i32(n << 20)))
    return s * z
