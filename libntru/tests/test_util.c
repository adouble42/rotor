#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "test_util.h"
#include "poly.h"

/** For equals_hash_func() */
#define HASH_INPUT_LEN 100

uint8_t equals_int(NtruIntPoly *a, NtruIntPoly *b) {
    if (a->N != b->N)
        return 0;

    uint16_t i;
    for (i=0; i<a->N; i++)
        if (a->coeffs[i] != b->coeffs[i])
            return 0;

    return 1;
}

uint8_t equals_int_mod(NtruIntPoly *a, NtruIntPoly *b, uint16_t modulus) {
    if (a->N != b->N)
        return 0;

    uint16_t i;
    for (i=0; i<a->N; i++)
        if ((a->coeffs[i]-b->coeffs[i]) % modulus)
            return 0;

    return 1;
}

uint8_t equals_tern(NtruTernPoly *a, NtruTernPoly *b) {
    if (a->N != b->N)
        return 0;
    if (a->num_ones != b->num_ones)
        return 0;
    if (a->num_neg_ones != b->num_neg_ones)
        return 0;

    uint16_t i;
    for (i=0; i<a->num_ones; i++)
        if (a->ones[i] != b->ones[i])
            return 0;
    for (i=0; i<a->num_neg_ones; i++)
        if (a->neg_ones[i] != b->neg_ones[i])
            return 0;

    return 1;
}

#ifndef NTRU_AVOID_HAMMING_WT_PATENT
uint8_t equals_prod(NtruProdPoly *a, NtruProdPoly *b) {
    return a->N==b->N && equals_tern(&a->f1, &b->f1) && equals_tern(&a->f2, &b->f2) && equals_tern(&a->f3, &b->f3);
}
#endif   /* NTRU_AVOID_HAMMING_WT_PATENT */

uint8_t equals_key_pair(NtruEncKeyPair *kp1, NtruEncKeyPair *kp2) {
    if (kp1->priv.q != kp2->priv.q)
        return 0;
#ifndef NTRU_AVOID_HAMMING_WT_PATENT
    if (kp1->priv.t.prod_flag && !equals_prod(&kp1->priv.t.poly.prod, &kp2->priv.t.poly.prod))
        return 0;
#endif   /* NTRU_AVOID_HAMMING_WT_PATENT */
    if (!kp1->priv.t.prod_flag && !equals_tern(&kp1->priv.t.poly.tern, &kp2->priv.t.poly.tern))
        return 0;
    if (kp1->pub.q != kp2->pub.q)
        return 0;
    if (!equals_int(&kp1->pub.h, &kp2->pub.h))
        return 0;
    return 1;
}

uint8_t equals_arr(uint8_t *arr1, uint8_t *arr2, uint16_t len) {
    uint16_t i;
    for (i=0; i<len; i++)
        if (arr1[i] != arr2[i])
            return 0;

    return 1;
}

/**
 * A probabilistic test for equality of two hash functions.
 * Calls the two hash functions with a random input value
 * and considers the functions equal if the outputs match.
 */
int equals_hash_func(void (*func1)(uint8_t[], uint16_t, uint8_t[]), void (*func2)(uint8_t[], uint16_t, uint8_t[]), uint8_t hash_len) {
    srand(0);
    uint8_t input[HASH_INPUT_LEN];
    uint8_t i;
    for (i=0; i<HASH_INPUT_LEN; i++)
        input[i] = rand();
    uint8_t hash1[256];
    uint8_t hash2[256];
    func1(input, HASH_INPUT_LEN, hash1);
    func2(input, HASH_INPUT_LEN, hash2);
    return memcmp(hash1, hash2, hash_len) == 0;
}

uint8_t equals_params(NtruEncParams *params1, NtruEncParams *params2) {
    uint8_t equal = 1;
    equal &= strcmp(params1->name, params2->name) == 0;
    equal &= params1->N == params2->N;
    equal &= params1->q == params2->q;
    equal &= params1->prod_flag == params2->prod_flag;
    equal &= params1->df1 == params2->df1;
    if (params1->prod_flag) {
        equal &= params1->df2 == params2->df2;
        equal &= params1->df3 == params2->df3;
    }
    equal &= params1->dm0 == params2->dm0;
    equal &= params1->db == params2->db;
    equal &= params1->c == params2->c;
    equal &= params1->min_calls_r == params2->min_calls_r;
    equal &= params1->min_calls_mask == params2->min_calls_mask;
    equal &= params1->hash_seed == params2->hash_seed;
    equal &= memcmp(params1->oid, params2->oid, sizeof(params1->oid)) == 0;
    equal &= equals_hash_func(params1->hash, params2->hash, params1->hlen);
    equal &= params1->hlen == params2->hlen;
    equal &= params1->pklen == params2->pklen;
    return equal;
}

uint8_t rand_int(uint16_t N, uint16_t pow2q, NtruIntPoly *poly, NtruRandContext *rand_ctx) {
    uint16_t rand_data[N];
    if (!rand_ctx->rand_gen->generate((uint8_t*)rand_data, N*2, rand_ctx))
        return 0;

    poly->N = N;
    uint16_t shift = 16 - pow2q;
    while ((int16_t)--N >= 0)
        poly->coeffs[N] = rand_data[N] >> shift;

    return 1;
}

void ntru_tern_to_int(NtruTernPoly *a, NtruIntPoly *b) {
    memset(&b->coeffs, 0, a->N * sizeof b->coeffs[0]);
    uint16_t i;
    for (i=0; i<a->num_ones; i++)
        b->coeffs[a->ones[i]] = 1;
    for (i=0; i<a->num_neg_ones; i++)
        b->coeffs[a->neg_ones[i]] = -1;

    b->N = a->N;
}

void ntru_add_tern(NtruIntPoly *a, NtruTernPoly *b) {
    uint16_t i;
    for (i=0; i<b->num_ones; i++)
        a->coeffs[b->ones[i]]++;
    for (i=0; i<b->num_neg_ones; i++)
        a->coeffs[b->neg_ones[i]]--;
}

#ifndef NTRU_AVOID_HAMMING_WT_PATENT
void ntru_prod_to_int(NtruProdPoly *a, NtruIntPoly *b, uint16_t modulus) {
    memset(&b->coeffs, 0, a->N * sizeof b->coeffs[0]);
    b->N = a->N;
    uint16_t mod_mask = modulus - 1;
    NtruIntPoly c;
    ntru_tern_to_int(&a->f1, &c);
    ntru_mult_tern(&c, &a->f2, b, mod_mask);
    ntru_add_tern(b, &a->f3);
}
#endif   /* NTRU_AVOID_HAMMING_WT_PATENT */

void ntru_priv_to_int(NtruPrivPoly *a, NtruIntPoly *b, uint16_t modulus) {
#ifndef NTRU_AVOID_HAMMING_WT_PATENT
    if (a->prod_flag)
        ntru_prod_to_int(&a->poly.prod, b, modulus);
    else
#endif   /* NTRU_AVOID_HAMMING_WT_PATENT */
        ntru_tern_to_int(&a->poly.tern, b);
}

void str_to_uint8(char *in, uint8_t *out) {
    size_t len = strlen(in);
    size_t i;
    for (i=0; i<len; i++)
        out[i] = (uint8_t)in[i];
}

void print_result(char *test_name, uint8_t valid) {
#ifdef WIN32
    printf("  %-17s%s\n", test_name, valid?"OK":"FAIL");
#else
    printf("  %-17s%s\n", test_name, valid?"✓":"FAIL");
#endif
}
