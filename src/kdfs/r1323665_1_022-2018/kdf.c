/**
 * @file kdf.c
 * @brief R1323665.1.022-2018 KDF implementation
 */

#include "kdfs/r1323665_1_022-2018/kdf.h"


void r1323665_1_022_2018_kdf1(const unsigned char* key, const unsigned char* t,
                              R1323665_1_022_2018_KDF1_CONTEXT* context, unsigned char* out)
{
    context->initialize_key(key, context->user_context, context->key_buffer);
    r1323665_1_022_2018_kdf1_perform(t, context, out);
}


void r1323665_1_022_2018_kdf1_perform(const unsigned char* t, R1323665_1_022_2018_KDF1_CONTEXT* context,
                                      unsigned char* out)
{
    context->derive_key(context->key_buffer, t, context->user_context, out);
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
