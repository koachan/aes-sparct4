#ifndef AES_ROUND_H
#define AES_ROUND_H

#include "ecrypt-sync.h"

static inline u64
fxor(u64 a, u64 b) {
    u64 res;
    asm ("fxor %1, %2, %0"
        : "=e" (res)
        : "e" (a), "e" (b));
    return res;
}

static inline void
aes_enc(u64 c[2], u64 const p[2], u64 const k[2]) {
    asm ("aes_eround01 %4, %2, %3, %0\n\t"
         "aes_eround23 %5, %2, %3, %1"
        : "=&e" (c[0]), "=&e" (c[1])
        : "e" (p[0]), "e" (p[1]),
          "e" (k[0]), "e" (k[1]));
}

static inline void
aes_enc_last(u64 c[2], u64 const p[2], u64 const k[2]) {
    asm ("aes_eround01_l %4, %2, %3, %0\n\t"
         "aes_eround23_l %5, %2, %3, %1"
        : "=&e" (c[0]), "=&e" (c[1])
        : "e" (p[0]), "e" (p[1]),
          "e" (k[0]), "e" (k[1]));
}

#endif /* AES_ROUND_H */
