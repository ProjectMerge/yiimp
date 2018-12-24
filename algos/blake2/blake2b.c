/*
 * Argon2 reference source code package - reference C implementations
 *
 * Copyright 2015
 * Daniel Dinu, Dmitry Khovratovich, Jean-Philippe Aumasson, and Samuel Neves
 *
 * You may use this work under the terms of a Creative Commons CC0 1.0
 * License/Waiver or the Apache Public License 2.0, at your option. The terms of
 * these licenses can be found at:
 *
 * - CC0 1.0 Universal : http://creativecommons.org/publicdomain/zero/1.0
 * - Apache 2.0        : http://www.apache.org/licenses/LICENSE-2.0
 *
 * You should have received a copy of both of these licenses along with this
 * software. If not, they may be obtained at the above URLs.
 */

#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include "blake2.h"
#include "blake2-impl.h"

static const uint64_t blake2b_IV[8] = {
    UINT64_C(0x6a09e667f3bcc908), UINT64_C(0xbb67ae8584caa73b),
    UINT64_C(0x3c6ef372fe94f82b), UINT64_C(0xa54ff53a5f1d36f1),
    UINT64_C(0x510e527fade682d1), UINT64_C(0x9b05688c2b3e6c1f),
    UINT64_C(0x1f83d9abfb41bd6b), UINT64_C(0x5be0cd19137e2179)};

static BLAKE2_INLINE void blake2b_set_lastnode(blake2b_state *S) {
    S->f[1] = (uint64_t)-1;
}

static BLAKE2_INLINE void blake2b_set_lastblock(blake2b_state *S) {
    S->f[0] = (uint64_t)-1;
}

static BLAKE2_INLINE void blake2b_increment_counter(blake2b_state *S, uint64_t inc) {
    S->t[0] += inc;
    S->t[1] += (S->t[0] < inc);
}

static BLAKE2_INLINE void blake2b_invalidate_state(blake2b_state *S) {
    blake2b_set_lastblock(S); /* invalidate for further use */
}

static BLAKE2_INLINE void blake2b_init0(blake2b_state *S) {
    memset(S, 0, sizeof(*S));
    memcpy(S->h, blake2b_IV, sizeof(S->h));
}

int blake2b_init_param(blake2b_state *S, const blake2b_param *P) {
    const unsigned char *p = (const unsigned char *)P;
    unsigned int i;
    blake2b_init0(S);
    for (i = 0; i < 8; ++i)
        S->h[i] ^= load64(&p[i * sizeof(S->h[i])]);
    S->outlen = P->digest_length;
    return 0;
}

/* Sequential blake2b initialization */
int blake2b_init(blake2b_state *S, size_t outlen) {
    blake2b_param P;
    P.digest_length = (uint8_t)outlen;
    P.key_length = 0;
    P.fanout = 1;
    P.depth = 1;
    P.leaf_length = 0;
    P.node_offset = 0;
    P.node_depth = 0;
    P.inner_length = 0;
    memset(P.reserved, 0, sizeof(P.reserved));
    memset(P.salt, 0, sizeof(P.salt));
    memset(P.personal, 0, sizeof(P.personal));
    return blake2b_init_param(S, &P);
}

int blake2b_init_key(blake2b_state *S, size_t outlen, const void *key, size_t keylen) {
    blake2b_param P;
    P.digest_length = (uint8_t)outlen;
    P.key_length = (uint8_t)keylen;
    P.fanout = 1;
    P.depth = 1;
    P.leaf_length = 0;
    P.node_offset = 0;
    P.node_depth = 0;
    P.inner_length = 0;
    uint8_t block[BLAKE2B_BLOCKBYTES];
    memcpy(block, key, keylen);
    blake2b_update(S, block, BLAKE2B_BLOCKBYTES);
    return 0;
}

static void blake2b_compress(blake2b_state *S, const uint8_t *block) {
    uint64_t m[16];
    uint64_t v[16];
    unsigned int i, r;

    for (i = 0; i < 16; ++i)
        m[i] = load64(block + i * sizeof(m[i]));

    v[0] = S->h[0];
    v[1] = S->h[1];
    v[2] = S->h[2];
    v[3] = S->h[3];
    v[4] = S->h[4];
    v[5] = S->h[5];
    v[6] = S->h[6];
    v[7] = S->h[7];
    v[8] = 0x6a09e667f3bcc908;
    v[9] = 0xbb67ae8584caa73b;
    v[10] = 0x3c6ef372fe94f82b;
    v[11] = 0xa54ff53a5f1d36f1;
    v[12] = 0x510e527fade682d1 ^ S->t[0];
    v[13] = 0x9b05688c2b3e6c1f ^ S->t[1];
    v[14] = 0x1f83d9abfb41bd6b ^ S->f[0];
    v[15] = 0x5be0cd19137e2179 ^ S->f[1];
    v[0]=v[0]+v[4]+m[0];v[12]=rotr64(v[12]^v[0],32);v[8]=v[8]+v[12];v[4]=rotr64(v[4]^v[8],24);v[0]=v[0]+v[4]+m[1];v[12]=rotr64(v[12]^v[0],16);v[8]=v[8]+v[12];v[4]=rotr64(v[4]^v[8],63);
    v[1]=v[1]+v[5]+m[2];v[13]=rotr64(v[13]^v[1],32);v[9]=v[9]+v[13];v[5]=rotr64(v[5]^v[9],24);v[1]=v[1]+v[5]+m[3];v[13]=rotr64(v[13]^v[1],16);v[9]=v[9]+v[13];v[5]=rotr64(v[5]^v[9],63);
    v[2]=v[2]+v[6]+m[4];v[14]=rotr64(v[14]^v[2],32);v[10]=v[10]+v[14];v[6]=rotr64(v[6]^v[10],24);v[2]=v[2]+v[6]+m[5];v[14]=rotr64(v[14]^v[2],16);v[10]=v[10]+v[14];v[6]=rotr64(v[6]^v[10],63);
    v[3]=v[3]+v[7]+m[6];v[15]=rotr64(v[15]^v[3],32);v[11]=v[11]+v[15];v[7]=rotr64(v[7]^v[11],24);v[3]=v[3]+v[7]+m[7];v[15]=rotr64(v[15]^v[3],16);v[11]=v[11]+v[15];v[7]=rotr64(v[7]^v[11],63);
    v[0]=v[0]+v[5]+m[8];v[15]=rotr64(v[15]^v[0],32);v[10]=v[10]+v[15];v[5]=rotr64(v[5]^v[10],24);v[0]=v[0]+v[5]+m[9];v[15]=rotr64(v[15]^v[0],16);v[10]=v[10]+v[15];v[5]=rotr64(v[5]^v[10],63);
    v[1]=v[1]+v[6]+m[10];v[12]=rotr64(v[12]^v[1],32);v[11]=v[11]+v[12];v[6]=rotr64(v[6]^v[11],24);v[1]=v[1]+v[6]+m[11];v[12]=rotr64(v[12]^v[1],16);v[11]=v[11]+v[12];v[6]=rotr64(v[6]^v[11],63);
    v[2]=v[2]+v[7]+m[12];v[13]=rotr64(v[13]^v[2],32);v[8]=v[8]+v[13];v[7]=rotr64(v[7]^v[8],24);v[2]=v[2]+v[7]+m[13];v[13]=rotr64(v[13]^v[2],16);v[8]=v[8]+v[13];v[7]=rotr64(v[7]^v[8],63);
    v[3]=v[3]+v[4]+m[14];v[14]=rotr64(v[14]^v[3],32);v[9]=v[9]+v[14];v[4]=rotr64(v[4]^v[9],24);v[3]=v[3]+v[4]+m[15];v[14]=rotr64(v[14]^v[3],16);v[9]=v[9]+v[14];v[4]=rotr64(v[4]^v[9],63);
    v[0]=v[0]+v[4]+m[14];v[12]=rotr64(v[12]^v[0],32);v[8]=v[8]+v[12];v[4]=rotr64(v[4]^v[8],24);v[0]=v[0]+v[4]+m[10];v[12]=rotr64(v[12]^v[0],16);v[8]=v[8]+v[12];v[4]=rotr64(v[4]^v[8],63);
    v[1]=v[1]+v[5]+m[4];v[13]=rotr64(v[13]^v[1],32);v[9]=v[9]+v[13];v[5]=rotr64(v[5]^v[9],24);v[1]=v[1]+v[5]+m[8];v[13]=rotr64(v[13]^v[1],16);v[9]=v[9]+v[13];v[5]=rotr64(v[5]^v[9],63);
    v[2]=v[2]+v[6]+m[9];v[14]=rotr64(v[14]^v[2],32);v[10]=v[10]+v[14];v[6]=rotr64(v[6]^v[10],24);v[2]=v[2]+v[6]+m[15];v[14]=rotr64(v[14]^v[2],16);v[10]=v[10]+v[14];v[6]=rotr64(v[6]^v[10],63);
    v[3]=v[3]+v[7]+m[13];v[15]=rotr64(v[15]^v[3],32);v[11]=v[11]+v[15];v[7]=rotr64(v[7]^v[11],24);v[3]=v[3]+v[7]+m[6];v[15]=rotr64(v[15]^v[3],16);v[11]=v[11]+v[15];v[7]=rotr64(v[7]^v[11],63);
    v[0]=v[0]+v[5]+m[1];v[15]=rotr64(v[15]^v[0],32);v[10]=v[10]+v[15];v[5]=rotr64(v[5]^v[10],24);v[0]=v[0]+v[5]+m[12];v[15]=rotr64(v[15]^v[0],16);v[10]=v[10]+v[15];v[5]=rotr64(v[5]^v[10],63);
    v[1]=v[1]+v[6]+m[0];v[12]=rotr64(v[12]^v[1],32);v[11]=v[11]+v[12];v[6]=rotr64(v[6]^v[11],24);v[1]=v[1]+v[6]+m[2];v[12]=rotr64(v[12]^v[1],16);v[11]=v[11]+v[12];v[6]=rotr64(v[6]^v[11],63);
    v[2]=v[2]+v[7]+m[11];v[13]=rotr64(v[13]^v[2],32);v[8]=v[8]+v[13];v[7]=rotr64(v[7]^v[8],24);v[2]=v[2]+v[7]+m[7];v[13]=rotr64(v[13]^v[2],16);v[8]=v[8]+v[13];v[7]=rotr64(v[7]^v[8],63);
    v[3]=v[3]+v[4]+m[5];v[14]=rotr64(v[14]^v[3],32);v[9]=v[9]+v[14];v[4]=rotr64(v[4]^v[9],24);v[3]=v[3]+v[4]+m[3];v[14]=rotr64(v[14]^v[3],16);v[9]=v[9]+v[14];v[4]=rotr64(v[4]^v[9],63);
    v[0]=v[0]+v[4]+m[11];v[12]=rotr64(v[12]^v[0],32);v[8]=v[8]+v[12];v[4]=rotr64(v[4]^v[8],24);v[0]=v[0]+v[4]+m[8];v[12]=rotr64(v[12]^v[0],16);v[8]=v[8]+v[12];v[4]=rotr64(v[4]^v[8],63);
    v[1]=v[1]+v[5]+m[12];v[13]=rotr64(v[13]^v[1],32);v[9]=v[9]+v[13];v[5]=rotr64(v[5]^v[9],24);v[1]=v[1]+v[5]+m[0];v[13]=rotr64(v[13]^v[1],16);v[9]=v[9]+v[13];v[5]=rotr64(v[5]^v[9],63);
    v[2]=v[2]+v[6]+m[5];v[14]=rotr64(v[14]^v[2],32);v[10]=v[10]+v[14];v[6]=rotr64(v[6]^v[10],24);v[2]=v[2]+v[6]+m[2];v[14]=rotr64(v[14]^v[2],16);v[10]=v[10]+v[14];v[6]=rotr64(v[6]^v[10],63);
    v[3]=v[3]+v[7]+m[15];v[15]=rotr64(v[15]^v[3],32);v[11]=v[11]+v[15];v[7]=rotr64(v[7]^v[11],24);v[3]=v[3]+v[7]+m[13];v[15]=rotr64(v[15]^v[3],16);v[11]=v[11]+v[15];v[7]=rotr64(v[7]^v[11],63);
    v[0]=v[0]+v[5]+m[10];v[15]=rotr64(v[15]^v[0],32);v[10]=v[10]+v[15];v[5]=rotr64(v[5]^v[10],24);v[0]=v[0]+v[5]+m[14];v[15]=rotr64(v[15]^v[0],16);v[10]=v[10]+v[15];v[5]=rotr64(v[5]^v[10],63);
    v[1]=v[1]+v[6]+m[3];v[12]=rotr64(v[12]^v[1],32);v[11]=v[11]+v[12];v[6]=rotr64(v[6]^v[11],24);v[1]=v[1]+v[6]+m[6];v[12]=rotr64(v[12]^v[1],16);v[11]=v[11]+v[12];v[6]=rotr64(v[6]^v[11],63);
    v[2]=v[2]+v[7]+m[7];v[13]=rotr64(v[13]^v[2],32);v[8]=v[8]+v[13];v[7]=rotr64(v[7]^v[8],24);v[2]=v[2]+v[7]+m[1];v[13]=rotr64(v[13]^v[2],16);v[8]=v[8]+v[13];v[7]=rotr64(v[7]^v[8],63);
    v[3]=v[3]+v[4]+m[9];v[14]=rotr64(v[14]^v[3],32);v[9]=v[9]+v[14];v[4]=rotr64(v[4]^v[9],24);v[3]=v[3]+v[4]+m[4];v[14]=rotr64(v[14]^v[3],16);v[9]=v[9]+v[14];v[4]=rotr64(v[4]^v[9],63);
    v[0]=v[0]+v[4]+m[7];v[12]=rotr64(v[12]^v[0],32);v[8]=v[8]+v[12];v[4]=rotr64(v[4]^v[8],24);v[0]=v[0]+v[4]+m[9];v[12]=rotr64(v[12]^v[0],16);v[8]=v[8]+v[12];v[4]=rotr64(v[4]^v[8],63);
    v[1]=v[1]+v[5]+m[3];v[13]=rotr64(v[13]^v[1],32);v[9]=v[9]+v[13];v[5]=rotr64(v[5]^v[9],24);v[1]=v[1]+v[5]+m[1];v[13]=rotr64(v[13]^v[1],16);v[9]=v[9]+v[13];v[5]=rotr64(v[5]^v[9],63);
    v[2]=v[2]+v[6]+m[13];v[14]=rotr64(v[14]^v[2],32);v[10]=v[10]+v[14];v[6]=rotr64(v[6]^v[10],24);v[2]=v[2]+v[6]+m[12];v[14]=rotr64(v[14]^v[2],16);v[10]=v[10]+v[14];v[6]=rotr64(v[6]^v[10],63);
    v[3]=v[3]+v[7]+m[11];v[15]=rotr64(v[15]^v[3],32);v[11]=v[11]+v[15];v[7]=rotr64(v[7]^v[11],24);v[3]=v[3]+v[7]+m[14];v[15]=rotr64(v[15]^v[3],16);v[11]=v[11]+v[15];v[7]=rotr64(v[7]^v[11],63);
    v[0]=v[0]+v[5]+m[2];v[15]=rotr64(v[15]^v[0],32);v[10]=v[10]+v[15];v[5]=rotr64(v[5]^v[10],24);v[0]=v[0]+v[5]+m[6];v[15]=rotr64(v[15]^v[0],16);v[10]=v[10]+v[15];v[5]=rotr64(v[5]^v[10],63);
    v[1]=v[1]+v[6]+m[5];v[12]=rotr64(v[12]^v[1],32);v[11]=v[11]+v[12];v[6]=rotr64(v[6]^v[11],24);v[1]=v[1]+v[6]+m[10];v[12]=rotr64(v[12]^v[1],16);v[11]=v[11]+v[12];v[6]=rotr64(v[6]^v[11],63);
    v[2]=v[2]+v[7]+m[4];v[13]=rotr64(v[13]^v[2],32);v[8]=v[8]+v[13];v[7]=rotr64(v[7]^v[8],24);v[2]=v[2]+v[7]+m[0];v[13]=rotr64(v[13]^v[2],16);v[8]=v[8]+v[13];v[7]=rotr64(v[7]^v[8],63);
    v[3]=v[3]+v[4]+m[15];v[14]=rotr64(v[14]^v[3],32);v[9]=v[9]+v[14];v[4]=rotr64(v[4]^v[9],24);v[3]=v[3]+v[4]+m[8];v[14]=rotr64(v[14]^v[3],16);v[9]=v[9]+v[14];v[4]=rotr64(v[4]^v[9],63);
    v[0]=v[0]+v[4]+m[9];v[12]=rotr64(v[12]^v[0],32);v[8]=v[8]+v[12];v[4]=rotr64(v[4]^v[8],24);v[0]=v[0]+v[4]+m[0];v[12]=rotr64(v[12]^v[0],16);v[8]=v[8]+v[12];v[4]=rotr64(v[4]^v[8],63);
    v[1]=v[1]+v[5]+m[5];v[13]=rotr64(v[13]^v[1],32);v[9]=v[9]+v[13];v[5]=rotr64(v[5]^v[9],24);v[1]=v[1]+v[5]+m[7];v[13]=rotr64(v[13]^v[1],16);v[9]=v[9]+v[13];v[5]=rotr64(v[5]^v[9],63);
    v[2]=v[2]+v[6]+m[2];v[14]=rotr64(v[14]^v[2],32);v[10]=v[10]+v[14];v[6]=rotr64(v[6]^v[10],24);v[2]=v[2]+v[6]+m[4];v[14]=rotr64(v[14]^v[2],16);v[10]=v[10]+v[14];v[6]=rotr64(v[6]^v[10],63);
    v[3]=v[3]+v[7]+m[10];v[15]=rotr64(v[15]^v[3],32);v[11]=v[11]+v[15];v[7]=rotr64(v[7]^v[11],24);v[3]=v[3]+v[7]+m[15];v[15]=rotr64(v[15]^v[3],16);v[11]=v[11]+v[15];v[7]=rotr64(v[7]^v[11],63);
    v[0]=v[0]+v[5]+m[14];v[15]=rotr64(v[15]^v[0],32);v[10]=v[10]+v[15];v[5]=rotr64(v[5]^v[10],24);v[0]=v[0]+v[5]+m[1];v[15]=rotr64(v[15]^v[0],16);v[10]=v[10]+v[15];v[5]=rotr64(v[5]^v[10],63);
    v[1]=v[1]+v[6]+m[11];v[12]=rotr64(v[12]^v[1],32);v[11]=v[11]+v[12];v[6]=rotr64(v[6]^v[11],24);v[1]=v[1]+v[6]+m[12];v[12]=rotr64(v[12]^v[1],16);v[11]=v[11]+v[12];v[6]=rotr64(v[6]^v[11],63);
    v[2]=v[2]+v[7]+m[6];v[13]=rotr64(v[13]^v[2],32);v[8]=v[8]+v[13];v[7]=rotr64(v[7]^v[8],24);v[2]=v[2]+v[7]+m[8];v[13]=rotr64(v[13]^v[2],16);v[8]=v[8]+v[13];v[7]=rotr64(v[7]^v[8],63);
    v[3]=v[3]+v[4]+m[3];v[14]=rotr64(v[14]^v[3],32);v[9]=v[9]+v[14];v[4]=rotr64(v[4]^v[9],24);v[3]=v[3]+v[4]+m[13];v[14]=rotr64(v[14]^v[3],16);v[9]=v[9]+v[14];v[4]=rotr64(v[4]^v[9],63);
    v[0]=v[0]+v[4]+m[2];v[12]=rotr64(v[12]^v[0],32);v[8]=v[8]+v[12];v[4]=rotr64(v[4]^v[8],24);v[0]=v[0]+v[4]+m[12];v[12]=rotr64(v[12]^v[0],16);v[8]=v[8]+v[12];v[4]=rotr64(v[4]^v[8],63);
    v[1]=v[1]+v[5]+m[6];v[13]=rotr64(v[13]^v[1],32);v[9]=v[9]+v[13];v[5]=rotr64(v[5]^v[9],24);v[1]=v[1]+v[5]+m[10];v[13]=rotr64(v[13]^v[1],16);v[9]=v[9]+v[13];v[5]=rotr64(v[5]^v[9],63);
    v[2]=v[2]+v[6]+m[0];v[14]=rotr64(v[14]^v[2],32);v[10]=v[10]+v[14];v[6]=rotr64(v[6]^v[10],24);v[2]=v[2]+v[6]+m[11];v[14]=rotr64(v[14]^v[2],16);v[10]=v[10]+v[14];v[6]=rotr64(v[6]^v[10],63);
    v[3]=v[3]+v[7]+m[8];v[15]=rotr64(v[15]^v[3],32);v[11]=v[11]+v[15];v[7]=rotr64(v[7]^v[11],24);v[3]=v[3]+v[7]+m[3];v[15]=rotr64(v[15]^v[3],16);v[11]=v[11]+v[15];v[7]=rotr64(v[7]^v[11],63);
    v[0]=v[0]+v[5]+m[4];v[15]=rotr64(v[15]^v[0],32);v[10]=v[10]+v[15];v[5]=rotr64(v[5]^v[10],24);v[0]=v[0]+v[5]+m[13];v[15]=rotr64(v[15]^v[0],16);v[10]=v[10]+v[15];v[5]=rotr64(v[5]^v[10],63);
    v[1]=v[1]+v[6]+m[7];v[12]=rotr64(v[12]^v[1],32);v[11]=v[11]+v[12];v[6]=rotr64(v[6]^v[11],24);v[1]=v[1]+v[6]+m[5];v[12]=rotr64(v[12]^v[1],16);v[11]=v[11]+v[12];v[6]=rotr64(v[6]^v[11],63);
    v[2]=v[2]+v[7]+m[15];v[13]=rotr64(v[13]^v[2],32);v[8]=v[8]+v[13];v[7]=rotr64(v[7]^v[8],24);v[2]=v[2]+v[7]+m[14];v[13]=rotr64(v[13]^v[2],16);v[8]=v[8]+v[13];v[7]=rotr64(v[7]^v[8],63);
    v[3]=v[3]+v[4]+m[1];v[14]=rotr64(v[14]^v[3],32);v[9]=v[9]+v[14];v[4]=rotr64(v[4]^v[9],24);v[3]=v[3]+v[4]+m[9];v[14]=rotr64(v[14]^v[3],16);v[9]=v[9]+v[14];v[4]=rotr64(v[4]^v[9],63);
    v[0]=v[0]+v[4]+m[12];v[12]=rotr64(v[12]^v[0],32);v[8]=v[8]+v[12];v[4]=rotr64(v[4]^v[8],24);v[0]=v[0]+v[4]+m[5];v[12]=rotr64(v[12]^v[0],16);v[8]=v[8]+v[12];v[4]=rotr64(v[4]^v[8],63);
    v[1]=v[1]+v[5]+m[1];v[13]=rotr64(v[13]^v[1],32);v[9]=v[9]+v[13];v[5]=rotr64(v[5]^v[9],24);v[1]=v[1]+v[5]+m[15];v[13]=rotr64(v[13]^v[1],16);v[9]=v[9]+v[13];v[5]=rotr64(v[5]^v[9],63);
    v[2]=v[2]+v[6]+m[14];v[14]=rotr64(v[14]^v[2],32);v[10]=v[10]+v[14];v[6]=rotr64(v[6]^v[10],24);v[2]=v[2]+v[6]+m[13];v[14]=rotr64(v[14]^v[2],16);v[10]=v[10]+v[14];v[6]=rotr64(v[6]^v[10],63);
    v[3]=v[3]+v[7]+m[4];v[15]=rotr64(v[15]^v[3],32);v[11]=v[11]+v[15];v[7]=rotr64(v[7]^v[11],24);v[3]=v[3]+v[7]+m[10];v[15]=rotr64(v[15]^v[3],16);v[11]=v[11]+v[15];v[7]=rotr64(v[7]^v[11],63);
    v[0]=v[0]+v[5]+m[0];v[15]=rotr64(v[15]^v[0],32);v[10]=v[10]+v[15];v[5]=rotr64(v[5]^v[10],24);v[0]=v[0]+v[5]+m[7];v[15]=rotr64(v[15]^v[0],16);v[10]=v[10]+v[15];v[5]=rotr64(v[5]^v[10],63);
    v[1]=v[1]+v[6]+m[6];v[12]=rotr64(v[12]^v[1],32);v[11]=v[11]+v[12];v[6]=rotr64(v[6]^v[11],24);v[1]=v[1]+v[6]+m[3];v[12]=rotr64(v[12]^v[1],16);v[11]=v[11]+v[12];v[6]=rotr64(v[6]^v[11],63);
    v[2]=v[2]+v[7]+m[9];v[13]=rotr64(v[13]^v[2],32);v[8]=v[8]+v[13];v[7]=rotr64(v[7]^v[8],24);v[2]=v[2]+v[7]+m[2];v[13]=rotr64(v[13]^v[2],16);v[8]=v[8]+v[13];v[7]=rotr64(v[7]^v[8],63);
    v[3]=v[3]+v[4]+m[8];v[14]=rotr64(v[14]^v[3],32);v[9]=v[9]+v[14];v[4]=rotr64(v[4]^v[9],24);v[3]=v[3]+v[4]+m[11];v[14]=rotr64(v[14]^v[3],16);v[9]=v[9]+v[14];v[4]=rotr64(v[4]^v[9],63);
    v[0]=v[0]+v[4]+m[13];v[12]=rotr64(v[12]^v[0],32);v[8]=v[8]+v[12];v[4]=rotr64(v[4]^v[8],24);v[0]=v[0]+v[4]+m[11];v[12]=rotr64(v[12]^v[0],16);v[8]=v[8]+v[12];v[4]=rotr64(v[4]^v[8],63);
    v[1]=v[1]+v[5]+m[7];v[13]=rotr64(v[13]^v[1],32);v[9]=v[9]+v[13];v[5]=rotr64(v[5]^v[9],24);v[1]=v[1]+v[5]+m[14];v[13]=rotr64(v[13]^v[1],16);v[9]=v[9]+v[13];v[5]=rotr64(v[5]^v[9],63);
    v[2]=v[2]+v[6]+m[12];v[14]=rotr64(v[14]^v[2],32);v[10]=v[10]+v[14];v[6]=rotr64(v[6]^v[10],24);v[2]=v[2]+v[6]+m[1];v[14]=rotr64(v[14]^v[2],16);v[10]=v[10]+v[14];v[6]=rotr64(v[6]^v[10],63);
    v[3]=v[3]+v[7]+m[3];v[15]=rotr64(v[15]^v[3],32);v[11]=v[11]+v[15];v[7]=rotr64(v[7]^v[11],24);v[3]=v[3]+v[7]+m[9];v[15]=rotr64(v[15]^v[3],16);v[11]=v[11]+v[15];v[7]=rotr64(v[7]^v[11],63);
    v[0]=v[0]+v[5]+m[5];v[15]=rotr64(v[15]^v[0],32);v[10]=v[10]+v[15];v[5]=rotr64(v[5]^v[10],24);v[0]=v[0]+v[5]+m[0];v[15]=rotr64(v[15]^v[0],16);v[10]=v[10]+v[15];v[5]=rotr64(v[5]^v[10],63);
    v[1]=v[1]+v[6]+m[15];v[12]=rotr64(v[12]^v[1],32);v[11]=v[11]+v[12];v[6]=rotr64(v[6]^v[11],24);v[1]=v[1]+v[6]+m[4];v[12]=rotr64(v[12]^v[1],16);v[11]=v[11]+v[12];v[6]=rotr64(v[6]^v[11],63);
    v[2]=v[2]+v[7]+m[8];v[13]=rotr64(v[13]^v[2],32);v[8]=v[8]+v[13];v[7]=rotr64(v[7]^v[8],24);v[2]=v[2]+v[7]+m[6];v[13]=rotr64(v[13]^v[2],16);v[8]=v[8]+v[13];v[7]=rotr64(v[7]^v[8],63);
    v[3]=v[3]+v[4]+m[2];v[14]=rotr64(v[14]^v[3],32);v[9]=v[9]+v[14];v[4]=rotr64(v[4]^v[9],24);v[3]=v[3]+v[4]+m[10];v[14]=rotr64(v[14]^v[3],16);v[9]=v[9]+v[14];v[4]=rotr64(v[4]^v[9],63);
    v[0]=v[0]+v[4]+m[6];v[12]=rotr64(v[12]^v[0],32);v[8]=v[8]+v[12];v[4]=rotr64(v[4]^v[8],24);v[0]=v[0]+v[4]+m[15];v[12]=rotr64(v[12]^v[0],16);v[8]=v[8]+v[12];v[4]=rotr64(v[4]^v[8],63);
    v[1]=v[1]+v[5]+m[14];v[13]=rotr64(v[13]^v[1],32);v[9]=v[9]+v[13];v[5]=rotr64(v[5]^v[9],24);v[1]=v[1]+v[5]+m[9];v[13]=rotr64(v[13]^v[1],16);v[9]=v[9]+v[13];v[5]=rotr64(v[5]^v[9],63);
    v[2]=v[2]+v[6]+m[11];v[14]=rotr64(v[14]^v[2],32);v[10]=v[10]+v[14];v[6]=rotr64(v[6]^v[10],24);v[2]=v[2]+v[6]+m[3];v[14]=rotr64(v[14]^v[2],16);v[10]=v[10]+v[14];v[6]=rotr64(v[6]^v[10],63);
    v[3]=v[3]+v[7]+m[0];v[15]=rotr64(v[15]^v[3],32);v[11]=v[11]+v[15];v[7]=rotr64(v[7]^v[11],24);v[3]=v[3]+v[7]+m[8];v[15]=rotr64(v[15]^v[3],16);v[11]=v[11]+v[15];v[7]=rotr64(v[7]^v[11],63);
    v[0]=v[0]+v[5]+m[12];v[15]=rotr64(v[15]^v[0],32);v[10]=v[10]+v[15];v[5]=rotr64(v[5]^v[10],24);v[0]=v[0]+v[5]+m[2];v[15]=rotr64(v[15]^v[0],16);v[10]=v[10]+v[15];v[5]=rotr64(v[5]^v[10],63);
    v[1]=v[1]+v[6]+m[13];v[12]=rotr64(v[12]^v[1],32);v[11]=v[11]+v[12];v[6]=rotr64(v[6]^v[11],24);v[1]=v[1]+v[6]+m[7];v[12]=rotr64(v[12]^v[1],16);v[11]=v[11]+v[12];v[6]=rotr64(v[6]^v[11],63);
    v[2]=v[2]+v[7]+m[1];v[13]=rotr64(v[13]^v[2],32);v[8]=v[8]+v[13];v[7]=rotr64(v[7]^v[8],24);v[2]=v[2]+v[7]+m[4];v[13]=rotr64(v[13]^v[2],16);v[8]=v[8]+v[13];v[7]=rotr64(v[7]^v[8],63);
    v[3]=v[3]+v[4]+m[10];v[14]=rotr64(v[14]^v[3],32);v[9]=v[9]+v[14];v[4]=rotr64(v[4]^v[9],24);v[3]=v[3]+v[4]+m[5];v[14]=rotr64(v[14]^v[3],16);v[9]=v[9]+v[14];v[4]=rotr64(v[4]^v[9],63);
    v[0]=v[0]+v[4]+m[10];v[12]=rotr64(v[12]^v[0],32);v[8]=v[8]+v[12];v[4]=rotr64(v[4]^v[8],24);v[0]=v[0]+v[4]+m[2];v[12]=rotr64(v[12]^v[0],16);v[8]=v[8]+v[12];v[4]=rotr64(v[4]^v[8],63);
    v[1]=v[1]+v[5]+m[8];v[13]=rotr64(v[13]^v[1],32);v[9]=v[9]+v[13];v[5]=rotr64(v[5]^v[9],24);v[1]=v[1]+v[5]+m[4];v[13]=rotr64(v[13]^v[1],16);v[9]=v[9]+v[13];v[5]=rotr64(v[5]^v[9],63);
    v[2]=v[2]+v[6]+m[7];v[14]=rotr64(v[14]^v[2],32);v[10]=v[10]+v[14];v[6]=rotr64(v[6]^v[10],24);v[2]=v[2]+v[6]+m[6];v[14]=rotr64(v[14]^v[2],16);v[10]=v[10]+v[14];v[6]=rotr64(v[6]^v[10],63);
    v[3]=v[3]+v[7]+m[1];v[15]=rotr64(v[15]^v[3],32);v[11]=v[11]+v[15];v[7]=rotr64(v[7]^v[11],24);v[3]=v[3]+v[7]+m[5];v[15]=rotr64(v[15]^v[3],16);v[11]=v[11]+v[15];v[7]=rotr64(v[7]^v[11],63);
    v[0]=v[0]+v[5]+m[15];v[15]=rotr64(v[15]^v[0],32);v[10]=v[10]+v[15];v[5]=rotr64(v[5]^v[10],24);v[0]=v[0]+v[5]+m[11];v[15]=rotr64(v[15]^v[0],16);v[10]=v[10]+v[15];v[5]=rotr64(v[5]^v[10],63);
    v[1]=v[1]+v[6]+m[9];v[12]=rotr64(v[12]^v[1],32);v[11]=v[11]+v[12];v[6]=rotr64(v[6]^v[11],24);v[1]=v[1]+v[6]+m[14];v[12]=rotr64(v[12]^v[1],16);v[11]=v[11]+v[12];v[6]=rotr64(v[6]^v[11],63);
    v[2]=v[2]+v[7]+m[3];v[13]=rotr64(v[13]^v[2],32);v[8]=v[8]+v[13];v[7]=rotr64(v[7]^v[8],24);v[2]=v[2]+v[7]+m[12];v[13]=rotr64(v[13]^v[2],16);v[8]=v[8]+v[13];v[7]=rotr64(v[7]^v[8],63);
    v[3]=v[3]+v[4]+m[13];v[14]=rotr64(v[14]^v[3],32);v[9]=v[9]+v[14];v[4]=rotr64(v[4]^v[9],24);v[3]=v[3]+v[4]+m[0];v[14]=rotr64(v[14]^v[3],16);v[9]=v[9]+v[14];v[4]=rotr64(v[4]^v[9],63);
    v[0]=v[0]+v[4]+m[0];v[12]=rotr64(v[12]^v[0],32);v[8]=v[8]+v[12];v[4]=rotr64(v[4]^v[8],24);v[0]=v[0]+v[4]+m[1];v[12]=rotr64(v[12]^v[0],16);v[8]=v[8]+v[12];v[4]=rotr64(v[4]^v[8],63);
    v[1]=v[1]+v[5]+m[2];v[13]=rotr64(v[13]^v[1],32);v[9]=v[9]+v[13];v[5]=rotr64(v[5]^v[9],24);v[1]=v[1]+v[5]+m[3];v[13]=rotr64(v[13]^v[1],16);v[9]=v[9]+v[13];v[5]=rotr64(v[5]^v[9],63);
    v[2]=v[2]+v[6]+m[4];v[14]=rotr64(v[14]^v[2],32);v[10]=v[10]+v[14];v[6]=rotr64(v[6]^v[10],24);v[2]=v[2]+v[6]+m[5];v[14]=rotr64(v[14]^v[2],16);v[10]=v[10]+v[14];v[6]=rotr64(v[6]^v[10],63);
    v[3]=v[3]+v[7]+m[6];v[15]=rotr64(v[15]^v[3],32);v[11]=v[11]+v[15];v[7]=rotr64(v[7]^v[11],24);v[3]=v[3]+v[7]+m[7];v[15]=rotr64(v[15]^v[3],16);v[11]=v[11]+v[15];v[7]=rotr64(v[7]^v[11],63);
    v[0]=v[0]+v[5]+m[8];v[15]=rotr64(v[15]^v[0],32);v[10]=v[10]+v[15];v[5]=rotr64(v[5]^v[10],24);v[0]=v[0]+v[5]+m[9];v[15]=rotr64(v[15]^v[0],16);v[10]=v[10]+v[15];v[5]=rotr64(v[5]^v[10],63);
    v[1]=v[1]+v[6]+m[10];v[12]=rotr64(v[12]^v[1],32);v[11]=v[11]+v[12];v[6]=rotr64(v[6]^v[11],24);v[1]=v[1]+v[6]+m[11];v[12]=rotr64(v[12]^v[1],16);v[11]=v[11]+v[12];v[6]=rotr64(v[6]^v[11],63);
    v[2]=v[2]+v[7]+m[12];v[13]=rotr64(v[13]^v[2],32);v[8]=v[8]+v[13];v[7]=rotr64(v[7]^v[8],24);v[2]=v[2]+v[7]+m[13];v[13]=rotr64(v[13]^v[2],16);v[8]=v[8]+v[13];v[7]=rotr64(v[7]^v[8],63);
    v[3]=v[3]+v[4]+m[14];v[14]=rotr64(v[14]^v[3],32);v[9]=v[9]+v[14];v[4]=rotr64(v[4]^v[9],24);v[3]=v[3]+v[4]+m[15];v[14]=rotr64(v[14]^v[3],16);v[9]=v[9]+v[14];v[4]=rotr64(v[4]^v[9],63);
    v[0]=v[0]+v[4]+m[14];v[12]=rotr64(v[12]^v[0],32);v[8]=v[8]+v[12];v[4]=rotr64(v[4]^v[8],24);v[0]=v[0]+v[4]+m[10];v[12]=rotr64(v[12]^v[0],16);v[8]=v[8]+v[12];v[4]=rotr64(v[4]^v[8],63);
    v[1]=v[1]+v[5]+m[4];v[13]=rotr64(v[13]^v[1],32);v[9]=v[9]+v[13];v[5]=rotr64(v[5]^v[9],24);v[1]=v[1]+v[5]+m[8];v[13]=rotr64(v[13]^v[1],16);v[9]=v[9]+v[13];v[5]=rotr64(v[5]^v[9],63);
    v[2]=v[2]+v[6]+m[9];v[14]=rotr64(v[14]^v[2],32);v[10]=v[10]+v[14];v[6]=rotr64(v[6]^v[10],24);v[2]=v[2]+v[6]+m[15];v[14]=rotr64(v[14]^v[2],16);v[10]=v[10]+v[14];v[6]=rotr64(v[6]^v[10],63);
    v[3]=v[3]+v[7]+m[13];v[15]=rotr64(v[15]^v[3],32);v[11]=v[11]+v[15];v[7]=rotr64(v[7]^v[11],24);v[3]=v[3]+v[7]+m[6];v[15]=rotr64(v[15]^v[3],16);v[11]=v[11]+v[15];v[7]=rotr64(v[7]^v[11],63);
    v[0]=v[0]+v[5]+m[1];v[15]=rotr64(v[15]^v[0],32);v[10]=v[10]+v[15];v[5]=rotr64(v[5]^v[10],24);v[0]=v[0]+v[5]+m[12];v[15]=rotr64(v[15]^v[0],16);v[10]=v[10]+v[15];v[5]=rotr64(v[5]^v[10],63);
    v[1]=v[1]+v[6]+m[0];v[12]=rotr64(v[12]^v[1],32);v[11]=v[11]+v[12];v[6]=rotr64(v[6]^v[11],24);v[1]=v[1]+v[6]+m[2];v[12]=rotr64(v[12]^v[1],16);v[11]=v[11]+v[12];v[6]=rotr64(v[6]^v[11],63);
    v[2]=v[2]+v[7]+m[11];v[13]=rotr64(v[13]^v[2],32);v[8]=v[8]+v[13];v[7]=rotr64(v[7]^v[8],24);v[2]=v[2]+v[7]+m[7];v[13]=rotr64(v[13]^v[2],16);v[8]=v[8]+v[13];v[7]=rotr64(v[7]^v[8],63);
    v[3]=v[3]+v[4]+m[5];v[14]=rotr64(v[14]^v[3],32);v[9]=v[9]+v[14];v[4]=rotr64(v[4]^v[9],24);v[3]=v[3]+v[4]+m[3];v[14]=rotr64(v[14]^v[3],16);v[9]=v[9]+v[14];v[4]=rotr64(v[4]^v[9],63);
    S->h[0] = S->h[0] ^ v[0] ^ v[8];
    S->h[1] = S->h[1] ^ v[1] ^ v[9];
    S->h[2] = S->h[2] ^ v[2] ^ v[10];
    S->h[3] = S->h[3] ^ v[3] ^ v[11];
    S->h[4] = S->h[4] ^ v[4] ^ v[12];
    S->h[5] = S->h[5] ^ v[5] ^ v[13];
    S->h[6] = S->h[6] ^ v[6] ^ v[14];
    S->h[7] = S->h[7] ^ v[7] ^ v[15];
}

int blake2b_update(blake2b_state *S, const void *in, size_t inlen) {
    const uint8_t *pin = (const uint8_t *)in;
    if (S->buflen + inlen > BLAKE2B_BLOCKBYTES) {
        size_t left = S->buflen;
        size_t fill = BLAKE2B_BLOCKBYTES - left;
        memcpy(&S->buf[left], pin, fill);
        blake2b_increment_counter(S, BLAKE2B_BLOCKBYTES);
        blake2b_compress(S, S->buf);
        S->buflen = 0;
        inlen -= fill;
        pin += fill;
        while (inlen > BLAKE2B_BLOCKBYTES) {
            blake2b_increment_counter(S, BLAKE2B_BLOCKBYTES);
            blake2b_compress(S, pin);
            inlen -= BLAKE2B_BLOCKBYTES;
            pin += BLAKE2B_BLOCKBYTES;
        }
    }
    memcpy(&S->buf[S->buflen], pin, inlen);
    S->buflen += (unsigned int)inlen;
    return 0;
}

int blake2b_final(blake2b_state *S, void *out, size_t outlen) {
    uint8_t buffer[BLAKE2B_OUTBYTES] = {0};
    unsigned int i;
    blake2b_increment_counter(S, S->buflen);
    blake2b_set_lastblock(S);
    memset(&S->buf[S->buflen], 0, BLAKE2B_BLOCKBYTES - S->buflen); /* Padding */
    blake2b_compress(S, S->buf);
    for (i = 0; i < 8; ++i)
        store64(buffer + sizeof(S->h[i]) * i, S->h[i]);
    memcpy(out, buffer, S->outlen);
    return 0;
}

int blake2b(void *out, size_t outlen, const void *in, size_t inlen, const void *key, size_t keylen) {
    blake2b_state S;
    int ret = -1;
    blake2b_init(&S, outlen);
    blake2b_update(&S, in, inlen);
    blake2b_final(&S, out, outlen);
}

int blake2b_long(void *pout, size_t outlen, const void *in, size_t inlen) {
    uint8_t *out = (uint8_t *)pout;
    blake2b_state blake_state;
    uint8_t outlen_bytes[sizeof(uint32_t)] = {0};
    int ret = -1;
    store32(outlen_bytes, (uint32_t)outlen);

    if (outlen <= BLAKE2B_OUTBYTES) {
        blake2b_init(&blake_state, outlen);
        blake2b_update(&blake_state, outlen_bytes, sizeof(outlen_bytes));
        blake2b_update(&blake_state, in, inlen);
        blake2b_final(&blake_state, out, outlen);
    } else {
        uint32_t toproduce;
        uint8_t out_buffer[BLAKE2B_OUTBYTES];
        uint8_t in_buffer[BLAKE2B_OUTBYTES];
        blake2b_init(&blake_state, BLAKE2B_OUTBYTES);
        blake2b_update(&blake_state, outlen_bytes, sizeof(outlen_bytes));
        blake2b_update(&blake_state, in, inlen);
        blake2b_final(&blake_state, out_buffer, BLAKE2B_OUTBYTES);
        memcpy(out, out_buffer, BLAKE2B_OUTBYTES / 2);
        out += BLAKE2B_OUTBYTES / 2;
        toproduce = (uint32_t)outlen - BLAKE2B_OUTBYTES / 2;

        while (toproduce > BLAKE2B_OUTBYTES) {
            memcpy(in_buffer, out_buffer, BLAKE2B_OUTBYTES);
            blake2b(out_buffer, BLAKE2B_OUTBYTES, in_buffer,BLAKE2B_OUTBYTES, NULL, 0);
            memcpy(out, out_buffer, BLAKE2B_OUTBYTES / 2);
            out += BLAKE2B_OUTBYTES / 2;
            toproduce -= BLAKE2B_OUTBYTES / 2;
        }

        memcpy(in_buffer, out_buffer, BLAKE2B_OUTBYTES);
        blake2b(out_buffer, toproduce, in_buffer, BLAKE2B_OUTBYTES, NULL, 0);
        memcpy(out, out_buffer, toproduce);
    }
    return ret;
}
