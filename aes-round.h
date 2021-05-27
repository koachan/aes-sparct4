#ifndef AES_ROUND_H
#define AES_ROUND_H

#include "ecrypt-sync.h"

static inline u64
fxor(u64 a, u64 b) {
    uint64_t res;
    asm ("fxor %1, %2, %0"
        : "=e" (res)
        : "e" (a), "e" (b));
    return res;
}

static inline void
aes_enc(u64 const c[2], u64 const p[2], u64 const k[2]) {
    asm ("aes_eround01 %4, %2, %3, %0\n\t"
         "aes_eround23 %5, %2, %3, %1"
        : "=&e" (out[0]), "=&e" (out[1])
        : "e" (in[0]), "e" (in[1]),
          "e" (rk[0]), "e" (rk[1]));
}

static inline void
aes_enc_last(u64 const c[2], u64 const p[2], u64 const k[2]) {
    asm ("aes_eround01_l %4, %2, %3, %0\n\t"
         "aes_eround23_l %5, %2, %3, %1"
        : "=&e" (out[0]), "=&e" (out[1])
        : "e" (in[0]), "e" (in[1]),
          "e" (rk[0]), "e" (rk[1]));
}

#endif /* AES_ROUND_H */
