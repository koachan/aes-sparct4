#ifndef AES_ROUND_H
#define AES_ROUND_H

#include "ecrypt-sync.h"

static inline u64
fxor(u64 a, u64 b) {
    u64 res;
    asm volatile ("fxor %1, %2, %0"
                 :"=e" (res)
                 :"e" (a), "e" (b));
    return res;
}

static inline void
aes_enc(u64 c[2], u64 const p[2], u64 const k[2]) {
    asm volatile ("aes_eround01 %4, %2, %3, %0\n\t"
                  "aes_eround23 %5, %2, %3, %1"
                 :"=&e" (c[0]), "=&e" (c[1])
                 :"e" (p[0]), "e" (p[1]),
                  "e" (k[0]), "e" (k[1]));
}

static inline void
aes_enc_last(u64 c[2], u64 const p[2], u64 const k[2]) {
    asm volatile ("aes_eround01_l %4, %2, %3, %0\n\t"
                  "aes_eround23_l %5, %2, %3, %1"
                 :"=&e" (c[0]), "=&e" (c[1])
                 :"e" (p[0]), "e" (p[1]),
                  "e" (k[0]), "e" (k[1]));
}

static inline void
aes_kexpand(u64 k[2], u8 imm5, u64 const prev[2]) {
    /* The value of imm5 is mapped into rcon as follows:
     *   imm5 | RC (rcon is 0xRC000000)
     *      0 | 01
     *      1 | 02
     *      2 | 04
     *      3 | 08
     *      4 | 10
     *      5 | 20
     *      6 | 40
     *      7 | 80
     *      8 | 1B
     *      9 | 36
     * others | 00
     *
     * See Oracle SPARC Architecture 2011, section 7.3:
     * AES Cryptographic Operations (4 operand)
     */

    asm volatile ("aes_kexpand1 %3, %4, %2, %0\n\t"
                  "aes_kexpand2 %4, %0, %1"
                 :"=&e" (k[0]), "=&e" (k[1])
                 :"I" (imm5),
                  "e" (prev[0]), "e" (prev[1]));
}

#endif /* AES_ROUND_H */
