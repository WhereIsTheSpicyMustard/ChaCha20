#include "chacha20.h"

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>

#define WORD_SIZE 32
#define STATE_SIZE 16
#define ROUNDS 10
#define BLOCK_SIZE 64

#define ROTL(x, n) (((x) << (n)) | ((x) >> (WORD_SIZE - n)))
#define QR(a, b, c, d) do {                      \
    (a) += (b); (d) ^= (a); (d) = ROTL((d), 16); \
    (c) += (d); (b) ^= (c); (b) = ROTL((b), 12); \
    (a) += (b); (d) ^= (a); (d) = ROTL((d), 8);  \
    (c) += (d); (b) ^= (c); (b) = ROTL((b), 7);  \
} while(0)

static void chacha20_block(uint32_t* restrict x, const uint32_t* restrict const state)
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

void chacha20(Chacha20_ctx* restrict ctx, void* restrict out, const size_t out_size)
{
    assert(ctx != NULL);

    uint32_t state[STATE_SIZE] = {
        [0]  = 0x61707865,   [1]  = 0x3320646e,    [2]  = 0x79622d32,    [3]  = 0x6b206574,
        [4]  = ctx->key[0],  [5]  = ctx->key[1],   [6]  = ctx->key[2],   [7]  = ctx->key[3],
        [8]  = ctx->key[4],  [9]  = ctx->key[5],   [10] = ctx->key[6],   [11] = ctx->key[7],
        [12] = ctx->counter, [13] = ctx->nonce[0], [14] = ctx->nonce[1], [15] = ctx->nonce[2]
    };

    size_t i = 0;
    for (; (i + BLOCK_SIZE - 1) < out_size; i += BLOCK_SIZE) {
        chacha20_block((uint32_t*)((uint8_t*)out + i), state);
        state[12] = ++(ctx->counter);
    }
    if (i == out_size) return;
    uint32_t x[STATE_SIZE];
    chacha20_block(x, state);
    assert(i < out_size);
    assert(out_size - i <= BLOCK_SIZE);
    memcpy((uint8_t*)out + i, x, out_size - i);
}
