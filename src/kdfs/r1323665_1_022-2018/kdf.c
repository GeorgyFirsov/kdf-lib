/**
 * @file kdf.c
 * @brief R1323665.1.022-2018 KDF implementation
 */

#include "kdfs/r1323665_1_022-2018/kdf.h"
#include "common/utils.h"

#include <immintrin.h>


/**
 * @brief Maximum size in bytes for initialized master key.
 */
#define KDFP_MAX_INTERMEDIATE_KEY (256 / 8)


/**
 * @brief Set of functions that correspond to one of three possible 
 *        internal algorithms for kdf(1) mentioned in R1323665.1.022-2018.
 */
typedef struct tagKDF1P_DIPATCH_TABLE_ENTRY
{
    /**
     * @brief Key initialization function. 
     * 
     * Parameter `out` of this function is passed to `derive_intermediate_key`
     * as `key`.
     */
    void (*initialize_key)(const unsigned char* key, unsigned char* out);


    /**
     * @brief Derives an intermediate key.
     */
    void (*derive_intermediate_key)(const unsigned char* key, const unsigned char* salt, unsigned char* out);
} KDF1P_DIPATCH_TABLE_ENTRY;


/**
 * @brief Initializes master key for 3rd algorithm from R1323665.1.022-2018.
 */
void r1323665_1_022_2018p_xor_initialize_key(const unsigned char* key, unsigned char* out)
{
    const __m128i* internal_key = (const __m128i*)key;
    __m128i* internal_out       = (__m128i*)out;

    internal_out[0] = internal_key[0];
    internal_out[1] = internal_key[1];
}


/**
 * @brief Derives intermediate key by XOR-ing master key and salt.
 * 
 * 3rd algorithm from R1323665.1.022-2018.
 */
void r1323665_1_022_2018p_xor_derive_intermediate_key(const unsigned char* key, const unsigned char* salt,
                                                      unsigned char* out)
{
    const __m128i* internal_key  = (const __m128i*)key;
    const __m128i* internal_salt = (const __m128i*)salt;
    __m128i* internal_out        = (__m128i*)out;

    internal_out[0] = _mm_xor_si128(internal_key[0], internal_salt[0]);
    internal_out[1] = _mm_xor_si128(internal_key[1], internal_salt[1]);
}


/**
 * @brief Returns an appropriate set of functions for kdf(1) context.
 */
const KDF1P_DIPATCH_TABLE_ENTRY* r1323665_1_022_2018p_dispatch(R1323665_1_022_2018_KDF1_CONTEXT* context)
{
    static KDF1P_DIPATCH_TABLE_ENTRY dispatch_table[] = {
        {0,                                       0                                               },
        {0,                                       0                                               },
        {r1323665_1_022_2018p_xor_initialize_key, r1323665_1_022_2018p_xor_derive_intermediate_key}
    };

    //
    // Won't check array bounds here. This code was written for
    // experimental purpose, not for production!
    //

    return &dispatch_table[context->function - 1];
}


/**
 * @brief Initializes master key for appropriate function.
 */
void r1323665_1_022_2018p_initialize_key(const unsigned char* key, R1323665_1_022_2018_KDF1_CONTEXT* context,
                                         unsigned char* out)
{
    const KDF1P_DIPATCH_TABLE_ENTRY* functions = r1323665_1_022_2018p_dispatch(context);
    functions->initialize_key(key, out);
}


/**
 * @brief Derives an intermediate key using appropriate function.
 */
void r1323665_1_022_2018p_derive_intermediate_key(const unsigned char* key, const unsigned char* salt,
                                                  R1323665_1_022_2018_KDF1_CONTEXT* context, unsigned char* out)
{
    const KDF1P_DIPATCH_TABLE_ENTRY* functions = r1323665_1_022_2018p_dispatch(context);
    functions->derive_intermediate_key(key, salt, out);
}


void r1323665_1_022_2018_kdf1(const unsigned char* key, const unsigned char* t,
                              R1323665_1_022_2018_KDF1_CONTEXT* context, unsigned char* out)
{
    unsigned char intermediate_key[KDFP_MAX_INTERMEDIATE_KEY];
    r1323665_1_022_2018p_initialize_key(key, context, intermediate_key);

    r1323665_1_022_2018_kdf1_perform(intermediate_key, t, context, out);
}


void r1323665_1_022_2018_kdf1_perform(const unsigned char* key, const unsigned char* t,
                                      R1323665_1_022_2018_KDF1_CONTEXT* context, unsigned char* out)
{
    r1323665_1_022_2018p_derive_intermediate_key(key, t, context, out);
}


void r1323665_1_022_2018_kdf2(const unsigned char* key, const unsigned char* iv, unsigned long long l,
                              const unsigned char* p, const unsigned char* u, const unsigned char* a,
                              R1323665_1_022_2018_KDF2_CONTEXT* context, unsigned char* out)
{
    context->initialize_key(key, context->user_context, context->key_buffer);
    r1323665_1_022_2018_kdf2_perform(iv, l, p, u, a, context, out);
}


void r1323665_1_022_2018_kdf2_perform(const unsigned char* iv, unsigned long long l, const unsigned char* p,
                                      const unsigned char* u, const unsigned char* a,
                                      R1323665_1_022_2018_KDF2_CONTEXT* context, unsigned char* out)
{
    //
    // Calculate required number of iterations.
    // L represents key length in bits, hence, I need to
    // convert it into bytes before further processing.
    //

    const unsigned long long iterations = (l >> 3) / context->mac_size;

    //
    // Now perform iterations!
    // Well... KDF itself is not quite complicated
    //

    unsigned long long counter = 0;
    const unsigned char* z     = iv;

    for (; counter < iterations; ++counter)
    {
        context->format(z, counter, p, u, a, l, context->user_context, context->format_buffer);
        context->mac(context->key_buffer, context->format_buffer, context->user_context, out);

        z = out;
        out += context->mac_size;
    }
}
