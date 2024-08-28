#include "/var/lib/gems/3.0.0/gems/ceedling-0.31.1/vendor/unity/src/unity.h"
#include "src/chacha20.h"

static struct chacha20_context ctx;

static const uint8_t test_key[32] = {

    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,

    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,

    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

static const uint8_t test_nonce[12] = {

    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,

    0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

static const uint64_t test_counter = 0;

static uint8_t plaintext[] = {

    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,

    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,

    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

static const uint8_t expected_ciphertext[] = {

    0x76, 0xb8, 0xe0, 0xad, 0xa0, 0xf1, 0x3d, 0x90, 0x40, 0x5d, 0x6a,

    0xe5, 0x53, 0x86, 0xbd, 0x28, 0xbd, 0xd2, 0x19, 0xb8, 0xa0, 0x8d,

    0xed, 0x1a, 0xa8, 0x36, 0xef, 0xcc, 0x8b, 0x77, 0x0d, 0xc7};

static const uint32_t expected_keystream32[16] = {

    0xade0b876, 0x903df1a0, 0xe56a5d40, 0x28bd8653, 0xb819d2bd, 0x1aed8da0, 0xccef36a8, 0xc70d778b,

    0x7c5941da, 0x8d485751, 0x3fe02477, 0x374ad8b8, 0xf4b8436a, 0x1ca11815, 0x69b687c3, 0x8665eeb2};

void setUp(void) {

    chacha20_init_context(&ctx, test_key, test_nonce, test_counter);
}

void test_chacha20_init_context(void) {

    UnityAssertEqualNumber((UNITY_INT)(UNITY_UINT32)((0x61707865)),
                           (UNITY_INT)(UNITY_UINT32)((ctx.state[0])),
                           (

                               ((void *)0)

                                   ),
                           (UNITY_UINT)(56), UNITY_DISPLAY_STYLE_UINT32);

    UnityAssertEqualNumber((UNITY_INT)(UNITY_UINT32)((0x3320646e)),
                           (UNITY_INT)(UNITY_UINT32)((ctx.state[1])),
                           (

                               ((void *)0)

                                   ),
                           (UNITY_UINT)(57), UNITY_DISPLAY_STYLE_UINT32);

    UnityAssertEqualNumber((UNITY_INT)(UNITY_UINT32)((0x79622d32)),
                           (UNITY_INT)(UNITY_UINT32)((ctx.state[2])),
                           (

                               ((void *)0)

                                   ),
                           (UNITY_UINT)(58), UNITY_DISPLAY_STYLE_UINT32);

    UnityAssertEqualNumber((UNITY_INT)(UNITY_UINT32)((0x6b206574)),
                           (UNITY_INT)(UNITY_UINT32)((ctx.state[3])),
                           (

                               ((void *)0)

                                   ),
                           (UNITY_UINT)(59), UNITY_DISPLAY_STYLE_UINT32);

    UnityAssertEqualIntArray((const void *)((test_key)), (const void *)((ctx.key)),
                             (UNITY_UINT32)((32)),
                             (

                                 ((void *)0)

                                     ),
                             (UNITY_UINT)(62), UNITY_DISPLAY_STYLE_UINT8, UNITY_ARRAY_TO_ARRAY);

    UnityAssertEqualIntArray((const void *)((test_nonce)), (const void *)((ctx.nonce)),
                             (UNITY_UINT32)((12)),
                             (

                                 ((void *)0)

                                     ),
                             (UNITY_UINT)(65), UNITY_DISPLAY_STYLE_UINT8, UNITY_ARRAY_TO_ARRAY);

    UnityAssertEqualNumber((UNITY_INT)(UNITY_UINT32)((0)),
                           (UNITY_INT)(UNITY_UINT32)((ctx.state[12])),
                           (

                               ((void *)0)

                                   ),
                           (UNITY_UINT)(68), UNITY_DISPLAY_STYLE_UINT32);

    UnityAssertEqualNumber((UNITY_INT)(UNITY_UINT32)((0)),
                           (UNITY_INT)(UNITY_UINT32)((ctx.state[13])),
                           (

                               ((void *)0)

                                   ),
                           (UNITY_UINT)(69), UNITY_DISPLAY_STYLE_UINT32);

    UnityAssertEqualNumber((UNITY_INT)(UNITY_UINT32)((64)),
                           (UNITY_INT)(UNITY_UINT32)((ctx.position)),
                           (

                               ((void *)0)

                                   ),
                           (UNITY_UINT)(72), UNITY_DISPLAY_STYLE_UINT32);
}

void test_chacha20_encrypt_known_vector(void) {

    chacha20_xor(&ctx, plaintext, sizeof(plaintext));

    UnityAssertEqualIntArray((const void *)((expected_ciphertext)), (const void *)((plaintext)),
                             (UNITY_UINT32)((sizeof(plaintext))),
                             (

                                 ((void *)0)

                                     ),
                             (UNITY_UINT)(81), UNITY_DISPLAY_STYLE_UINT8, UNITY_ARRAY_TO_ARRAY);
}

void test_chacha20_generate_keystream(void) {

    chacha20_block_next(&ctx);

    UnityAssertEqualIntArray((const void *)((expected_keystream32)),
                             (const void *)((ctx.keystream32)), (UNITY_UINT32)((16)),
                             (

                                 ((void *)0)

                                     ),
                             (UNITY_UINT)(88), UNITY_DISPLAY_STYLE_UINT32, UNITY_ARRAY_TO_ARRAY);
}

void test_chacha20_encrypt_with_different_counters(void) {

    uint8_t ciphertext_counter_0[sizeof(plaintext)];

    uint8_t ciphertext_counter_1[sizeof(plaintext)];

    chacha20_xor(&ctx, plaintext, sizeof(plaintext));

    memcpy(ciphertext_counter_0, plaintext, sizeof(plaintext));

    uint64_t new_counter = 1;

    chacha20_init_context(&ctx, test_key, test_nonce, new_counter);

    chacha20_xor(&ctx, plaintext, sizeof(plaintext));

    memcpy(ciphertext_counter_1, plaintext, sizeof(plaintext));

    do {
        if (((0) != (memcmp(ciphertext_counter_0, ciphertext_counter_1, sizeof(plaintext))))) {
        } else {
            UnityFail(((" Expected Not-Equal")), (UNITY_UINT)((UNITY_UINT)(109)));
        }
    } while (0);
}

void test_chacha20_encrypt_with_different_nonces(void) {

    uint8_t ciphertext_nonce_0[sizeof(plaintext)];

    uint8_t ciphertext_nonce_1[sizeof(plaintext)];

    chacha20_init_context(&ctx, test_key, test_nonce, test_counter);

    chacha20_xor(&ctx, plaintext, sizeof(plaintext));

    memcpy(ciphertext_nonce_0, plaintext, sizeof(plaintext));

    uint8_t new_nonce[12] = {0x01, 0x01, 0x01, 0x01, 0x01, 0x01,

                             0x01, 0x01, 0x01, 0x01, 0x01, 0x01};

    chacha20_init_context(&ctx, test_key, new_nonce, test_counter);

    chacha20_xor(&ctx, plaintext, sizeof(plaintext));

    memcpy(ciphertext_nonce_1, plaintext, sizeof(plaintext));

    do {
        if (((0) != (memcmp(ciphertext_nonce_0, ciphertext_nonce_1, sizeof(plaintext))))) {
        } else {
            UnityFail(((" Expected Not-Equal")), (UNITY_UINT)((UNITY_UINT)(133)));
        }
    } while (0);
}
