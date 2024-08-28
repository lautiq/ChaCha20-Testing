#include "chacha20.h"

#define ROTL(a, b) (((a) << (b)) | ((a) >> (32 - (b))))
#define CHACHA20_QUARTERROUND(x, a, b, c, d)                                                       \
    x[a] += x[b];                                                                                  \
    x[d] = ROTL(x[d] ^ x[a], 16);                                                                  \
    x[c] += x[d];                                                                                  \
    x[b] = ROTL(x[b] ^ x[c], 12);                                                                  \
    x[a] += x[b];                                                                                  \
    x[d] = ROTL(x[d] ^ x[a], 8);                                                                   \
    x[c] += x[d];                                                                                  \
    x[b] = ROTL(x[b] ^ x[c], 7);

static uint32_t pack4(const uint8_t * a) {
    uint32_t res = 0;
    res |= (uint32_t)a[0];
    res |= (uint32_t)a[1] << 8;
    res |= (uint32_t)a[2] << 16;
    res |= (uint32_t)a[3] << 24;
    return res;
}

static void chacha20_init_block(struct chacha20_context * ctx, const uint8_t key[],
                                const uint8_t nonce[]) {
    memcpy(ctx->key, key, sizeof(ctx->key));
    memcpy(ctx->nonce, nonce, 8); // sizeof(ctx->nonce)

    const uint8_t * magic_constant = (uint8_t *)"expand 32-byte k";
    ctx->state[0] = pack4(magic_constant + 0 * 4);
    ctx->state[1] = pack4(magic_constant + 1 * 4);
    ctx->state[2] = pack4(magic_constant + 2 * 4);
    ctx->state[3] = pack4(magic_constant + 3 * 4);
    ctx->state[4] = pack4(key + 0 * 4);
    ctx->state[5] = pack4(key + 1 * 4);
    ctx->state[6] = pack4(key + 2 * 4);
    ctx->state[7] = pack4(key + 3 * 4);
    ctx->state[8] = pack4(key + 4 * 4);
    ctx->state[9] = pack4(key + 5 * 4);
    ctx->state[10] = pack4(key + 6 * 4);
    ctx->state[11] = pack4(key + 7 * 4);
    ctx->state[12] = 0; // 64 bit counter initialized to zero by default.
    ctx->state[13] = pack4(ctx->nonce);
    ctx->state[14] = pack4(ctx->nonce + 4);
    ctx->state[15] = pack4(ctx->nonce + 8);

    memcpy(ctx->nonce, nonce, sizeof(ctx->nonce));
}

static void chacha20_block_set_counter(struct chacha20_context * ctx, uint64_t counter) {
    ctx->state[12] = (uint32_t)counter;
    ctx->state[13] = pack4(ctx->nonce + 0 * 4) + (uint32_t)(counter >> 32);
}

void chacha20_block_next(struct chacha20_context * ctx) {
    // This is where the crazy voodoo magic happens.
    // Mix the bytes a lot and hope that nobody finds out how to undo it.
    for (int i = 0; i < 16; i++) {
        ctx->keystream32[i] = ctx->state[i];
    }

    for (int i = 0; i < 10; i++) {
        CHACHA20_QUARTERROUND(ctx->keystream32, 0, 4, 8, 12)
        CHACHA20_QUARTERROUND(ctx->keystream32, 1, 5, 9, 13)
        CHACHA20_QUARTERROUND(ctx->keystream32, 2, 6, 10, 14)
        CHACHA20_QUARTERROUND(ctx->keystream32, 3, 7, 11, 15)
        CHACHA20_QUARTERROUND(ctx->keystream32, 0, 5, 10, 15)
        CHACHA20_QUARTERROUND(ctx->keystream32, 1, 6, 11, 12)
        CHACHA20_QUARTERROUND(ctx->keystream32, 2, 7, 8, 13)
        CHACHA20_QUARTERROUND(ctx->keystream32, 3, 4, 9, 14)
    }

    for (int i = 0; i < 16; i++) {
        ctx->keystream32[i] += ctx->state[i];
    }

    uint32_t * counter = ctx->state + 12;
    counter[0]++;
    if (0 == counter[0]) {
        // wrap around occured, increment higher 32 bits of counter
        counter[1]++;
        // Limited to 2^64 blocks of 64 bytes each.
        // If you want to process more than 1180591620717411303424 bytes
        // you have other problems.
        // We could keep counting with counter[2] and counter[3] (nonce),
        // but then we risk reusing the nonce which is very bad.
        assert(0 != counter[1]);
    }
}

void chacha20_init_context(struct chacha20_context * ctx, const uint8_t key[],
                           const uint8_t nonce[], const uint64_t counter) {
    memset(ctx, 0, sizeof(struct chacha20_context));

    chacha20_init_block(ctx, key, nonce);
    chacha20_block_set_counter(ctx, counter);

    ctx->counter = counter;
    ctx->position = 64;
}

void chacha20_xor(struct chacha20_context * ctx, uint8_t * bytes, size_t n_bytes) {
    uint8_t * keystream8 = (uint8_t *)ctx->keystream32;
    for (size_t i = 0; i < n_bytes; i++) {
        if (ctx->position >= 64) {
            chacha20_block_next(ctx);
            ctx->position = 0;
        }
        bytes[i] ^= keystream8[ctx->position];
        ctx->position++;
    }
}
