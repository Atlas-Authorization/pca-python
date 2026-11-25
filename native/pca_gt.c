/*
 * GT (the BLS12-381 pairing target group, a subgroup of Fp12) operations over supranational blst's public API, for the
 * pairing packages whose bindings expose no GT parsing or exponentiation (attribute-based encryption needs both).
 *
 * Nothing here implements field or curve arithmetic: every multiplication, squaring, Miller loop, final exponentiation,
 * point decoding and subgroup check is a blst call. This file only moves bytes in and out of blst's types and sequences
 * blst calls (a Montgomery ladder for exponentiation, with a branch-free byte-masked swap, so the exponent does not
 * steer control flow or memory access: constant-time to the extent blst's Fp12 multiply and square are).
 *
 * GT encoding (576 bytes): the 12 Fp coordinates in tower order c0.c0.c0, c0.c0.c1, c0.c1.c0, ..., c1.c2.c1
 * (Fp12 = Fp6[w], Fp6 = Fp2[v], Fp2 = Fp[u]), each 48-byte big-endian, i.e. the blst_fp12 struct walked in memory
 * order. This is the encoding of the TypeScript reference (Fp12.toBytes); it is NOT blst_bendian_from_fp12's order.
 *
 * Every function returns 1 on success and 0 on any malformed input (non-canonical coordinate, bad point, identity).
 */
#include <stddef.h>
#include <string.h>
#include "blst.h"

#define GT_BYTES 576

/* The subgroup order r, big-endian. */
static const byte R_BE[32] = {
    0x73, 0xed, 0xa7, 0x53, 0x29, 0x9d, 0x7d, 0x48, 0x33, 0x39, 0xd8, 0x08, 0x09, 0xa1, 0xd8, 0x05,
    0x53, 0xbd, 0xa4, 0x02, 0xff, 0xfe, 0x5b, 0xfe, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x01};

static blst_fp *coord(blst_fp12 *x, int i) { return &x->fp6[i / 6].fp2[(i % 6) / 2].fp[i % 2]; }

static void gt_to_bytes(byte out[GT_BYTES], const blst_fp12 *x) {
    for (int i = 0; i < 12; i++) blst_bendian_from_fp(out + 48 * i, coord((blst_fp12 *)x, i));
}

/* Strict decoding: every coordinate must be canonical (< p), checked by re-encoding through blst. */
static int gt_from_bytes(blst_fp12 *x, const byte in[GT_BYTES]) {
    byte back[48];
    int ok = 1;
    for (int i = 0; i < 12; i++) {
        blst_fp_from_bendian(coord(x, i), in + 48 * i);
        blst_bendian_from_fp(back, coord(x, i));
        ok &= memcmp(back, in + 48 * i, 48) == 0;
    }
    return ok;
}

static void cswap(blst_fp12 *a, blst_fp12 *b, byte bit) {
    volatile byte mask = (byte)(0 - bit);
    byte *pa = (byte *)a, *pb = (byte *)b;
    for (size_t i = 0; i < sizeof(blst_fp12); i++) {
        byte t = (byte)((pa[i] ^ pb[i]) & mask);
        pa[i] ^= t;
        pb[i] ^= t;
    }
}

/* x^k for a 32-byte big-endian k (all 256 bits processed, so the running time does not depend on k). */
static void gt_pow(blst_fp12 *out, const blst_fp12 *x, const byte k[32]) {
    blst_fp12 r0 = *blst_fp12_one(), r1 = *x, t;
    for (int i = 0; i < 256; i++) {
        byte bit = (byte)((k[i / 8] >> (7 - i % 8)) & 1);
        cswap(&r0, &r1, bit);
        blst_fp12_mul(&t, &r0, &r1);
        r1 = t;
        blst_fp12_sqr(&t, &r0);
        r0 = t;
        cswap(&r0, &r1, bit);
    }
    *out = r0;
}

int pca_gt_mul(byte out[GT_BYTES], const byte a[GT_BYTES], const byte b[GT_BYTES]) {
    blst_fp12 x, y, z;
    if (!gt_from_bytes(&x, a) || !gt_from_bytes(&y, b)) return 0;
    blst_fp12_mul(&z, &x, &y);
    gt_to_bytes(out, &z);
    return 1;
}

int pca_gt_pow(byte out[GT_BYTES], const byte a[GT_BYTES], const byte k[32]) {
    blst_fp12 x, z;
    if (!gt_from_bytes(&x, a)) return 0;
    gt_pow(&z, &x, k);
    gt_to_bytes(out, &z);
    return 1;
}

/* 1 iff the bytes are the canonical encoding of an element of the order-r subgroup GT other than the identity. */
int pca_gt_is_element(const byte a[GT_BYTES]) {
    blst_fp12 x, z;
    if (!gt_from_bytes(&x, a) || blst_fp12_is_one(&x)) return 0;
    gt_pow(&z, &x, R_BE);
    return blst_fp12_is_one(&z) ? 1 : 0;
}

/*
 * prod_i e(P_i, Q_i) with one shared final exponentiation. g1s: n compressed G1 points (48 bytes each), g2s: n compressed
 * G2 points (96 bytes each). Each point must be the canonical compressed encoding of a non-identity point of the
 * prime-order subgroup.
 */
int pca_gt_pairing(byte out[GT_BYTES], const byte *g1s, const byte *g2s, size_t n) {
    blst_fp12 acc = *blst_fp12_one(), ml, t;
    byte back[96];
    if (n == 0) return 0;
    for (size_t i = 0; i < n; i++) {
        blst_p1_affine p;
        blst_p2_affine q;
        /* compression flag required: blst would otherwise read an uncompressed (96/192-byte) point past this buffer */
        if (!(g1s[48 * i] & 0x80) || !(g2s[96 * i] & 0x80)) return 0;
        if (blst_p1_uncompress(&p, g1s + 48 * i) != BLST_SUCCESS) return 0;
        if (blst_p2_uncompress(&q, g2s + 96 * i) != BLST_SUCCESS) return 0;
        if (blst_p1_affine_is_inf(&p) || blst_p2_affine_is_inf(&q)) return 0;
        if (!blst_p1_affine_in_g1(&p) || !blst_p2_affine_in_g2(&q)) return 0;
        blst_p1_affine_compress(back, &p);
        if (memcmp(back, g1s + 48 * i, 48) != 0) return 0;
        blst_p2_affine_compress(back, &q);
        if (memcmp(back, g2s + 96 * i, 96) != 0) return 0;
        blst_miller_loop(&ml, &q, &p);
        blst_fp12_mul(&t, &acc, &ml);
        acc = t;
    }
    blst_final_exp(&t, &acc);
    gt_to_bytes(out, &t);
    return 1;
}
