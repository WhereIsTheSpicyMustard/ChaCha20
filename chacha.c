#include "chacha.h"

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define WORD_SIZE 32

#define ROTL(x, n) (((x) << (n)) | ((x) >> (WORD_SIZE - n)))
#define QR(a, b, c, d) do {                      \
    (a) += (b); (d) ^= (a); (d) = ROTL((d), 16); \
    (c) += (d); (b) ^= (c); (b) = ROTL((b), 12); \
    (a) += (b); (d) ^= (a); (d) = ROTL((d), 8);  \
    (c) += (d); (b) ^= (c); (b) = ROTL((b), 7);  \
} while(0)

static void chacha_block(uint32_t* restrict x, const uint32_t* restrict const state)
{
    for (int i = 0; i < 16; ++i)
        x[i] = state[i];
    for (int i = 0; i < 10; ++i) {
        QR(x[0], x[4], x[8],  x[12]); QR(x[1], x[5], x[9],  x[13]);
        QR(x[2], x[6], x[10], x[14]); QR(x[3], x[7], x[11], x[15]);
        QR(x[0], x[5], x[10], x[15]); QR(x[1], x[6], x[11], x[12]);
        QR(x[2], x[7], x[8],  x[13]); QR(x[3], x[4], x[9],  x[14]);
    }
    for (int i = 0; i < 16; ++i)
        x[i] += state[i];
}

void chacha20(const uint32_t* restrict key, uint32_t counter, const uint32_t* restrict nonce, void* restrict out, const size_t out_len)
{
    uint32_t x[16];
    uint32_t state[16] = {
        [0] =  0x61707865, [1] =  0x3320646e, [2] = 0x79622d32, [3] = 0x6b206574,
        [4] =  key[0],     [5] =  key[1],     [6] = key[2],     [7] = key[3],
        [8] =  key[4],     [9] =  key[5],    [10] = key[6],    [11] = key[7],
                          [13] = nonce[0],   [14] = nonce[1],  [15] = nonce[2],
    };

    for (size_t i = 0; i < out_len; i += 64) {
        const size_t min = (out_len - i) < 64 ? (out_len - i) : 64;
        state[12] = counter++;
        chacha_block(x, state);
        memcpy((uint8_t*)out + i, x, min);
    }
}

