#ifndef CHACHA20_H
#define CHACHA20_H

#include <stddef.h>
#include <stdint.h>

typedef struct Chacha20_ctx {
    uint32_t key[8];
    uint32_t counter;
    uint32_t nonce[3];
} Chacha20_ctx;

/**
    - The key must have 8 elements.
    - The nonce must have 3 elements.
    - You can use the same key but the nonce
    must be different each time the function
    is called.
    - Pointers must not alias.
*/
void chacha20(Chacha20_ctx* ctx, void* out, const size_t out_len);

#endif
