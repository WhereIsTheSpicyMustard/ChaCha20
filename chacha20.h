#ifndef CHACHA20_H
#define CHACHA20_H

#include <stddef.h>
#include <stdint.h>

typedef struct Chacha20_ctx {
    uint32_t key[8];
    uint64_t counter;
    uint64_t nonce;
} Chacha20_ctx;

/**
  - You can use the same key but the nonce
  must be different each time the function
  is called.
  - Pointers must not alias.
  - Key stream has a period of 64 * UINT64_MAX
*/
void chacha20(Chacha20_ctx* ctx, void* out, const size_t out_size);

#endif
