#pragma once

#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

struct chacha20_context
{
    uint32_t keystream32[16];
    size_t position;

    uint8_t key[32];
    uint8_t nonce[12];
    uint64_t counter;

    uint32_t state[16];
};

void chacha20_init_context(struct chacha20_context *ctx, const uint8_t key[],
    const uint8_t nounc[], const uint64_t counter);
void chacha20_xor(struct chacha20_context *ctx, uint8_t *bytes, size_t n_bytes);
void chacha20_block_next(struct chacha20_context *ctx);

#ifdef __cplusplus
}
#endif
