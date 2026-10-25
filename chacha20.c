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

#define ROTL(x, n) (((x) << (n)) | ((x) >> (WORD_SIZE - (n))))
#define QR(a, b, c, d) do {                      \
    (a) += (b); (d) ^= (a); (d) = ROTL((d), 16); \
    (c) += (d); (b) ^= (c); (b) = ROTL((b), 12); \
    (a) += (b); (d) ^= (a); (d) = ROTL((d), 8);  \
    (c) += (d); (b) ^= (c); (b) = ROTL((b), 7);  \
} while(0)

static void chacha20_block(uint32_t* restrict x, const uint32_t* restrict const state)
{
    for (int i = 0; i < STATE_SIZE; ++i)
        x[i] = state[i];
    for (int i = 0; i < ROUNDS; ++i) {
        QR(x[0], x[4], x[8],  x[12]); QR(x[1], x[5], x[9],  x[13]);
        QR(x[2], x[6], x[10], x[14]); QR(x[3], x[7], x[11], x[15]);
        QR(x[0], x[5], x[10], x[15]); QR(x[1], x[6], x[11], x[12]);
        QR(x[2], x[7], x[8],  x[13]); QR(x[3], x[4], x[9],  x[14]);
    }
    for (int i = 0; i < STATE_SIZE; ++i)
        x[i] += state[i];
}

void chacha20(Chacha20_ctx* restrict ctx, void* restrict out, const size_t out_size)
{
    assert(ctx != NULL);
    assert(out != NULL);

    if (ctx == NULL || out == NULL || out_size == 0) return;

    uint32_t state[STATE_SIZE] = {
        [0]  = 0x61707865,   [1]  = 0x3320646e,    [2]  = 0x79622d32,    [3]  = 0x6b206574,
        [4]  = ctx->key[0],  [5]  = ctx->key[1],   [6]  = ctx->key[2],   [7]  = ctx->key[3],
        [8]  = ctx->key[4],  [9]  = ctx->key[5],   [10] = ctx->key[6],   [11] = ctx->key[7],
        [12] = (uint32_t)(ctx->counter & UINT32_MAX), [13] = (uint32_t)(ctx->counter >> 32),
        [14] = (uint32_t)(ctx->nonce & UINT32_MAX),   [15] = (uint32_t)(ctx->nonce >> 32)
    };

    uint32_t x[STATE_SIZE];
    for (size_t i = 0; i < out_size; i += BLOCK_SIZE) {
        chacha20_block(x, state);
        ++(ctx->counter);
        state[12] = (uint32_t)(ctx->counter & UINT32_MAX);
        state[13] = (uint32_t)(ctx->counter >> 32);
        memcpy((uint8_t*)out + i, x, BLOCK_SIZE <= (out_size - i) ? BLOCK_SIZE : (out_size - i));
    }
}





