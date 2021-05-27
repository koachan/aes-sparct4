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
static void
aes_encrypt(ECRYPT_ctx *c, u64 output[2], u64 const input[2]) {
    u64 tmp[2] = {
        fxor(input[0], c->rk[0]),
        fxor(input[1], c->rk[1]),
    };

    aesenc    (tmp, tmp, c->rk+2);
    aesenc    (tmp, tmp, c->rk+4);
    aesenc    (tmp, tmp, c->rk+6);
    aesenc    (tmp, tmp, c->rk+8);
    aesenc    (tmp, tmp, c->rk+10);
    aesenc    (tmp, tmp, c->rk+12);
    aesenc    (tmp, tmp, c->rk+14);
    aesenc    (tmp, tmp, c->rk+16);
    aesenc    (tmp, tmp, c->rk+18);
    aesenclast(tmp, tmp, c->rk+20);

    output[0] = tmp[0]; output[1] = tmp[1];
}

static void
increment_iv(u64 iv[2]) {
    asm ("addcc %3, 1, %1 \n\t"
         "addxc %2, %%g0, %0"
        : "=&r" (iv[0]), "=&r" (iv[1])
        : "r" (iv[0]), "r" (iv[1])
        : "cc");
}

void
ECRYPT_init(void) {
    return;
}

void
ECRYPT_keysetup(ECRYPT_ctx *c, const u8 *k, u32 keysize, u32 ivsize) {
}

void
ECRYPT_ivsetup(ECRYPT_ctx *c, const u8 *iv) {
    memcpy(c->iv, iv, 16);
}

void
ECRYPT_process_bytes(int action, ECRYPT_ctx *c, const u8 *input, u8 *output, u32 len) {
}
