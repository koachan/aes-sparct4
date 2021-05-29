/* An ESTREAM-compatible AES-CTR wrapper for SPARC T4 AES instructions.
 *
 * Copyright (c) 2021 Koakuma <koachan@protonmail.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <string.h>

#include "aes-round.h"
#include "ecrypt-sync.h"

/* Encrypt a single block */
static inline void
aes_encrypt(ECRYPT_ctx *c, u64 output[2], u64 const input[2]) {
    u64 tmp[2] = {
        fxor(input[0], c->rk[0]),
        fxor(input[1], c->rk[1]),
    };

    aes_enc     (tmp, tmp, c->rk+2);
    aes_enc     (tmp, tmp, c->rk+4);
    aes_enc     (tmp, tmp, c->rk+6);
    aes_enc     (tmp, tmp, c->rk+8);
    aes_enc     (tmp, tmp, c->rk+10);
    aes_enc     (tmp, tmp, c->rk+12);
    aes_enc     (tmp, tmp, c->rk+14);
    aes_enc     (tmp, tmp, c->rk+16);
    aes_enc     (tmp, tmp, c->rk+18);
    aes_enc_last(tmp, tmp, c->rk+20);

    output[0] = tmp[0]; output[1] = tmp[1];
}

static inline void
increment_iv(u64 iv[2]) {
    u64 l0, l1, l2, l3, l4, l5;
    u64 l6 = iv[0], l7 = iv[1];
    u64 *l8 = &iv[0], *l9 = &iv[1];

    /* Do the addition in little-endian */
    asm volatile ("stxa %6, [%5] #ASI_P_L \n\t"
                  "stxa %7, [%4] #ASI_P_L \n\t"
                  "ldx [%4], %0 \n\t"
                  "ldx [%5], %1 \n\t"
                  "addcc %1, 1, %3 \n\t"
                  "addxc %0, %%g0, %2 \n\t"
                  "stxa %2, [%9] #ASI_P_L \n\t"
                  "stxa %3, [%8] #ASI_P_L"
                 :"=&r" (l0), "=&r" (l1),
                  "=&r" (l2), "=&r" (l3)
                 :"r" (&l4), "r" (&l5),
                  "r" (l6), "r" (l7),
                  "r" (l8), "r" (l9)
                 :"cc");
}

void
ECRYPT_init(void) {
    return;
}

void
ECRYPT_keysetup(ECRYPT_ctx *c, const u8 *k, u32 keysize, u32 ivsize) {
    memcpy(c->rk, __builtin_assume_aligned(k, 16), 16);
    aes_kexpand(c->rk+2,  0, c->rk);
    aes_kexpand(c->rk+4,  1, c->rk+2);
    aes_kexpand(c->rk+6,  2, c->rk+4);
    aes_kexpand(c->rk+8,  3, c->rk+6);
    aes_kexpand(c->rk+10, 4, c->rk+8);
    aes_kexpand(c->rk+12, 5, c->rk+10);
    aes_kexpand(c->rk+14, 6, c->rk+12);
    aes_kexpand(c->rk+16, 7, c->rk+14);
    aes_kexpand(c->rk+18, 8, c->rk+16);
    aes_kexpand(c->rk+20, 9, c->rk+18);
}

void
ECRYPT_ivsetup(ECRYPT_ctx *c, const u8 *iv) {
    memcpy(c->iv, __builtin_assume_aligned(iv, 16), 16);
}

void
ECRYPT_process_bytes(int action, ECRYPT_ctx *c, const u8 *input, u8 *output, u32 len) {
    u32 blocks   = len >> 4;
    u32 residual = len & 0xF;

    input  = __builtin_assume_aligned(input, 16);
    output = __builtin_assume_aligned(output, 16);

    union {
        u8  b[16];
        u64 x[2];
    } iv_alias, pt_alias;

    u32 i = 0;
    for (i = 0; i < blocks; i++) {
        memcpy(iv_alias.b, c->iv, 16);
        memcpy(pt_alias.b, input + i*16, 16);

        aes_encrypt(c, iv_alias.x, iv_alias.x);
        pt_alias.x[0] = fxor(pt_alias.x[0], iv_alias.x[0]);
        pt_alias.x[1] = fxor(pt_alias.x[1], iv_alias.x[1]);
        increment_iv(c->iv);

        memcpy(output + i*16, pt_alias.b, 16);
    }

    /* Now encrypt the last block. */
    if (!residual) return;

    memcpy(iv_alias.b, c->iv, 16);
    aes_encrypt(c, iv_alias.x, iv_alias.x);
    increment_iv(c->iv);

    u32 cont = i*16;
    for (i = 0; i < residual; i++, cont++) {
        output[cont] = input[cont] ^ iv_alias.b[i];
    }
}
