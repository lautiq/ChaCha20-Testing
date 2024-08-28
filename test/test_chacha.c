/*      Lista de tests a realizar:
 * Verifica rque la inicialización del contexto sea correcta.
 * Probar el cifrado ChaCha20 con un vector conocido de entrada y salida.
 * Verificar la generación del keystream para un bloque.
 * Probar el cifrado con diferentes valores del contador para verificar la salida.
 * Verificar la variación en la salida del cifrado al cambiar el nonce.
 */

/* === Inclusiones para archivos Cabeceras=============================================================== */
#include "chacha20.h"
#include "unity.h"
#include <string.h>

/* === Variables estáticas para pruebas ======================================================= */
static struct chacha20_context ctx; ///< Contexto para las funciones de cifrado ChaCha20.

static const uint8_t test_key[32] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
}; ///< Ejemplo de clave para pruebas.

static const uint8_t test_nonce[12] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
    0x00, 0x00, 0x00, 0x00
}; ///< Ejemplo de nonce para pruebas.

static const uint64_t test_counter = 0; ///< Ejemplo de contador inicial.

/* Vector de entrada conocido */
static uint8_t plaintext[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
}; ///< Ejemplo de texto plano para pruebas.

/* Vector de salida esperado */
static const uint8_t expected_ciphertext[] = {
    0x76, 0xb8, 0xe0, 0xad, 0xa0, 0xf1, 0x3d, 0x90,
    0x40, 0x5d, 0x6a, 0xe5, 0x53, 0x86, 0xbd, 0x28,
    0xbd, 0xd2, 0x19, 0xb8, 0xa0, 0x8d, 0xed, 0x1a,
    0xa8, 0x36, 0xef, 0xcc, 0x8b, 0x77, 0x0d, 0xc7
}; ///< Salida cifrada esperada para pruebas.

static const uint32_t expected_keystream32[16] = {
        0xade0b876, 0x903df1a0, 0xe56a5d40, 0x28bd8653,
        0xb819d2bd, 0x1aed8da0, 0xccef36a8, 0xc70d778b,
        0x7c5941da, 0x8d485751, 0x3fe02477, 0x374ad8b8,
        0xf4b8436a, 0x1ca11815, 0x69b687c3, 0x8665eeb2
};

/* === Función de configuración inicial ======================================================= */
void setUp(void) {
    // Inicializa el contexto antes de cada prueba
    chacha20_init_context(&ctx, test_key, test_nonce, test_counter);
}

/* === Test Case: Verificar la inicialización del contexto ===================================== */
void test_chacha20_init_context(void) {
    // Verificar que el estado inicial sea correcto
    TEST_ASSERT_EQUAL_UINT32(0x61707865, ctx.state[0]);
    TEST_ASSERT_EQUAL_UINT32(0x3320646e, ctx.state[1]);
    TEST_ASSERT_EQUAL_UINT32(0x79622d32, ctx.state[2]);
    TEST_ASSERT_EQUAL_UINT32(0x6b206574, ctx.state[3]);

    // Verificar que la clave se haya copiado correctamente
    TEST_ASSERT_EQUAL_UINT8_ARRAY(test_key, ctx.key, 32);

    // Verificar que el nonce se haya copiado correctamente
    TEST_ASSERT_EQUAL_UINT8_ARRAY(test_nonce, ctx.nonce, 12);

    // Verificar que el contador se haya inicializado correctamente
    TEST_ASSERT_EQUAL_UINT32(0, ctx.state[12]);
    TEST_ASSERT_EQUAL_UINT32(0, ctx.state[13]);

    // Verificar que la posición esté en el valor esperado
    TEST_ASSERT_EQUAL_UINT32(64, ctx.position);
}

/* === Test Case: Probar el cifrado ChaCha20 con un vector conocido ============================ */
void test_chacha20_encrypt_known_vector(void) {
    // Aplicar ChaCha20 XOR en el texto plano
    chacha20_xor(&ctx, plaintext, sizeof(plaintext));

    // Verificar que el texto cifrado coincida con el resultado esperado
    TEST_ASSERT_EQUAL_UINT8_ARRAY(expected_ciphertext, plaintext, sizeof(plaintext));
}

/* === Test Case: Verificar la generación del keystream para un bloque ======================== */
void test_chacha20_generate_keystream(void) {
    chacha20_block_next(&ctx);

    TEST_ASSERT_EQUAL_UINT32_ARRAY(expected_keystream32, ctx.keystream32, 16);
}

/* === Test Case: Probar el cifrado con diferentes valores del contador ======================== */
void test_chacha20_encrypt_with_different_counters(void) {
    uint8_t ciphertext_counter_0[sizeof(plaintext)];
    uint8_t ciphertext_counter_1[sizeof(plaintext)];

    // Cifrar el texto plano con el contador 0
    chacha20_xor(&ctx, plaintext, sizeof(plaintext));
    memcpy(ciphertext_counter_0, plaintext, sizeof(plaintext));

    // Cambiar el contador y reiniciar el contexto
    uint64_t new_counter = 1;
    chacha20_init_context(&ctx, test_key, test_nonce, new_counter);

    // Cifrar el texto plano nuevamente con el nuevo contador
    chacha20_xor(&ctx, plaintext, sizeof(plaintext));
    memcpy(ciphertext_counter_1, plaintext, sizeof(plaintext));

    // Verificar que los resultados de los cifrados sean diferentes
    TEST_ASSERT_NOT_EQUAL(0, memcmp(ciphertext_counter_0, ciphertext_counter_1, sizeof(plaintext)));
}

/* === Test Case: Verificar la variación en la salida del cifrado al cambiar el nonce ========== */
void test_chacha20_encrypt_with_different_nonces(void) {
    uint8_t ciphertext_nonce_0[sizeof(plaintext)];
    uint8_t ciphertext_nonce_1[sizeof(plaintext)];

    // Cifrar el texto plano con el nonce 0
    chacha20_init_context(&ctx, test_key, test_nonce, test_counter);
    chacha20_xor(&ctx, plaintext, sizeof(plaintext));
    memcpy(ciphertext_nonce_0, plaintext, sizeof(plaintext));

    // Cambiar el nonce y reiniciar el contexto
    uint8_t new_nonce[12] = {
        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 
        0x01, 0x01, 0x01, 0x01
    }; // Nuevo nonce para pruebas

    chacha20_init_context(&ctx, test_key, new_nonce, test_counter);
    
    // Cifrar el texto plano nuevamente con el nuevo nonce
    chacha20_xor(&ctx, plaintext, sizeof(plaintext));
    memcpy(ciphertext_nonce_1, plaintext, sizeof(plaintext));

    // Verificar que los resultados de los cifrados sean diferentes
    TEST_ASSERT_NOT_EQUAL(0, memcmp(ciphertext_nonce_0, ciphertext_nonce_1, sizeof(plaintext)));
}