#include <string.h>
#include <stdint.h>
#ifdef WIN32
#include <Winsock2.h>
#else
#include <netinet/in.h>
#endif
#include "key.h"
#include "poly.h"
#include "encparams.h"
#include "types.h"
#include "arith.h"
#include "err.h"

void ntru_export_pub(NtruEncPubKey *key, uint8_t *arr) {
    /* write N */
    uint16_t N_endian = htons(key->h.N);
    memcpy(arr, &N_endian, sizeof N_endian);
    arr += sizeof N_endian;

    /* write q */
    uint16_t q_endian = htons(key->q);
    memcpy(arr, &q_endian, sizeof q_endian);
    arr += sizeof q_endian;

    /* write h */
    ntru_to_arr_32(&key->h, key->q, arr);
}

uint16_t ntru_import_pub(uint8_t *arr, NtruEncPubKey *key) {
    uint8_t *arr_head = arr;

    /* read N */
    uint16_t N_endian;
    memcpy(&N_endian, arr_head, sizeof N_endian);
    uint16_t N = ntohs(N_endian);
    key->h.N = N;

    /* read q */
    arr_head += sizeof N_endian;
    uint16_t q_endian;
    memcpy(&q_endian, arr_head, sizeof q_endian);
    uint16_t q = ntohs(q_endian);
    key->q = q;
    arr_head += sizeof q_endian;

    /* read h */
    ntru_from_arr(arr_head, N, q, &key->h);
    arr_head += ntru_enc_len_Nq(N, q);

    return arr_head - arr;
}

uint16_t ntru_pub_len(const NtruEncParams *params) {
    return 4 + ntru_enc_len(params);
}

uint16_t ntru_tern_to_arr(NtruTernPoly *poly, uint8_t *arr) {
    uint8_t *arr_head = arr;

    /* write #ones and #neg_ones */
    uint16_t num_ones = htons(poly->num_ones);
    memcpy(arr_head, &num_ones, sizeof num_ones);
    arr_head += sizeof num_ones;
    uint16_t num_neg_ones = htons(poly->num_neg_ones);
    memcpy(arr_head, &num_neg_ones, sizeof num_neg_ones);
    arr_head += sizeof num_neg_ones;

    /* write indices of ones and negative ones */
    uint8_t bits_per_idx = ntru_log2(poly->N-1) + 1;
    uint32_t buf = 0;
    uint8_t buf_size = 0;   /* #bits in buf */
    uint16_t i;
    for (i=0; i<poly->num_ones; i++) {
        uint16_t idx = poly->ones[i];
        buf |= idx << buf_size;
        buf_size += bits_per_idx;
        while (buf_size > 8) {
            *arr_head = buf & 0xFF;
            arr_head++;
            buf >>= 8;
            buf_size -= 8;
        }
    }
    for (i=0; i<poly->num_neg_ones; i++) {
        uint16_t idx = poly->neg_ones[i];
        buf |= idx << buf_size;
        buf_size += bits_per_idx;
        while (buf_size > 8) {
            *arr_head = buf & 0xFF;
            arr_head++;
            buf >>= 8;
            buf_size -= 8;
        }
    }
    if (buf_size > 0) {
        *arr_head = buf & 0xFF;
        arr_head++;
    }

    return arr_head - arr;
}

uint16_t ntru_export_priv(NtruEncPrivKey *key, uint8_t *arr) {
    uint8_t *arr_head = arr;

    uint8_t prod_flag = key->t.prod_flag;

    /* write N */
#ifndef NTRU_AVOID_HAMMING_WT_PATENT
    uint16_t N_endian = prod_flag ? htons(key->t.poly.prod.N) : htons(key->t.poly.tern.N);
#else
    uint16_t N_endian = htons(key->t.poly.tern.N);
#endif   /* NTRU_AVOID_HAMMING_WT_PATENT */
    memcpy(arr_head, &N_endian, sizeof N_endian);
    arr_head += sizeof N_endian;

    /* write q */
    uint16_t q_endian = htons(key->q);
    memcpy(arr_head, &q_endian, sizeof q_endian);
    arr_head += sizeof q_endian;

    /* write flags */
    *arr_head = 3 | (prod_flag?4:0);
    arr_head++;

    /* write f1, f2, f3 */
#ifndef NTRU_AVOID_HAMMING_WT_PATENT
    if (prod_flag) {
        arr_head += ntru_tern_to_arr(&key->t.poly.prod.f1, arr_head);
        arr_head += ntru_tern_to_arr(&key->t.poly.prod.f2, arr_head);
        arr_head += ntru_tern_to_arr(&key->t.poly.prod.f3, arr_head);
    }
    else
#endif   /* NTRU_AVOID_HAMMING_WT_PATENT */
        arr_head += ntru_tern_to_arr(&key->t.poly.tern, arr_head);

    return arr_head - arr;
}

uint16_t ntru_tern_from_arr(uint8_t *arr, uint16_t N, NtruTernPoly *poly) {
    poly->N = N;
    uint8_t *arr_head = arr;

    /* read #ones and #ones */
    uint16_t num_ones;
    memcpy(&num_ones, arr_head, sizeof num_ones);
    poly->num_ones = ntohs(num_ones);
    arr_head += sizeof num_ones;
    uint16_t num_neg_ones;
    memcpy(&num_neg_ones, arr_head, sizeof num_neg_ones);
    poly->num_neg_ones = ntohs(num_neg_ones);
    arr_head += sizeof num_neg_ones;

    /* read indices of ones and negative ones */
    uint8_t bits_per_idx = ntru_log2(N-1) + 1;
    uint16_t mask = (1<<bits_per_idx) - 1;
    uint32_t buf = 0;
    uint8_t buf_size = 0;   /* #bits in buf */
    uint16_t i;
    for (i=0; i<poly->num_ones; i++) {
        while (buf_size < bits_per_idx) {
            buf |= *arr_head << buf_size;
            arr_head++;
            buf_size += 8;
        }
        poly->ones[i] = buf & mask;
        buf >>= bits_per_idx;
        buf_size -= bits_per_idx;
    }
    for (i=0; i<poly->num_neg_ones; i++) {
        while (buf_size < bits_per_idx) {
            buf |= *arr_head << buf_size;
            arr_head++;
            buf_size += 8;
        }
        poly->neg_ones[i] = buf & mask;
        buf >>= bits_per_idx;
        buf_size -= bits_per_idx;
    }

    return arr_head - arr;
}

void ntru_import_priv(uint8_t *arr, NtruEncPrivKey *key) {
    /* read N */
    uint16_t N;
    memcpy(&N, arr, sizeof N);
    N = ntohs(N);
    arr += sizeof N;

    /* read q */
    uint16_t q;
    memcpy(&q, arr, sizeof q);
    key->q = ntohs(q);
    arr += sizeof q;

    /* read flags and check bit 2 */
    uint8_t flags = *arr;
    key->t.prod_flag = (flags&4) != 0;
    arr++;

#ifndef NTRU_AVOID_HAMMING_WT_PATENT
    if (key->t.prod_flag) {
        key->t.poly.prod.N = N;
        arr += ntru_tern_from_arr(arr, N, &key->t.poly.prod.f1);
        arr += ntru_tern_from_arr(arr, N, &key->t.poly.prod.f2);
        arr += ntru_tern_from_arr(arr, N, &key->t.poly.prod.f3);
    }
    else
#endif   /* NTRU_AVOID_HAMMING_WT_PATENT */
    {
        key->t.poly.tern.N = N;
        arr += ntru_tern_from_arr(arr, key->t.poly.tern.N, &key->t.poly.tern);
    }
}

uint16_t ntru_priv_len(const NtruEncParams *params) {
    uint8_t bits_per_idx = ntru_log2(params->N-1) + 1;
    if (params->prod_flag) {
        uint16_t poly1_len = 4 + (bits_per_idx*2*params->df1+7) / 8;
        uint16_t poly2_len = 4 + (bits_per_idx*2*params->df2+7) / 8;
        uint16_t poly3_len = 4 + (bits_per_idx*2*params->df3+7) / 8;
        return 5 + poly1_len + poly2_len + poly3_len;
    }
    else
        return 5 + 4 + (bits_per_idx*2*params->df1+7) / 8;
}

uint8_t ntru_params_from_key_pair(NtruEncKeyPair *kp, NtruEncParams *params) {
    return ntru_params_from_priv_key(&kp->priv, params);
}

uint8_t ntru_params_from_priv_key(NtruEncPrivKey *key, NtruEncParams *params) {
    if (!key || !params)
        return NTRU_ERR_NULL_ARG;

    size_t i = 0;
    struct NtruEncParams all[] = ALL_PARAM_SETS;
    for (i=0; i<sizeof(all)/sizeof(struct NtruEncParams); i++) {
        uint16_t df, N;
#ifndef NTRU_AVOID_HAMMING_WT_PATENT
        if (key->t.prod_flag) {
            df = key->t.poly.prod.f1.num_ones;
            N = key->t.poly.prod.N;
        }
        else {
#endif
            df = key->t.poly.tern.num_ones;
            N = key->t.poly.tern.N;
#ifndef NTRU_AVOID_HAMMING_WT_PATENT
        }
#endif
        if (N==all[i].N && df==all[i].df1) {
            strcpy(params->name, all[i].name);
            params->N = all[i].N;
            params->q = all[i].q;
            params->prod_flag = all[i].prod_flag;
            params->df1 = all[i].df1;
            params->df2 = all[i].df2;
            params->df3 = all[i].df3;
            params->dm0 = all[i].dm0;
            params->db = all[i].db;
            params->c = all[i].c;
            params->min_calls_r = all[i].min_calls_r;
            params->min_calls_mask = all[i].min_calls_mask;
            params->hash_seed = all[i].hash_seed;
            memcpy(params->oid, all[i].oid, sizeof(all[i].oid));
            params->hash = all[i].hash;
            params->hlen = all[i].hlen;
            params->pklen = all[i].pklen;
            return NTRU_SUCCESS;
        }
    }

    return NTRU_ERR_UNKNOWN_PARAM_SET;
}
