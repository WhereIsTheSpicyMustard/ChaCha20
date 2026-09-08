#ifndef CHACHA_H
#define CHACHA_H

#include <stddef.h>
#include <stdint.h>

/**
    - The key must have 8 elements.
    - The nonce must have 3 elements.
    - You can use the same key but the nonce
    must be different each time the function
    is called.
    - Pointers must not alias.
*/
void chacha20(const uint32_t* key, uint32_t counter, const uint32_t* nonce, void* out, const size_t out_len);

#endif
