/**
 * @file kdf.c
 * @brief R1323665.1.022-2018 KDF implementation
 */

#include "kdfs/r1323665_1_022-2018/kdf.h"
#include "common/utils.h"


void kdf2(const unsigned char* key, const unsigned char* iv, const unsigned char* l, const unsigned char* p,
          const unsigned char* u, const unsigned char* a, unsigned long derived_key_size,
          R1323665_1_022_2018_KDF2_CONTEXT* context, unsigned char* out)
{
    context->initialize_key(key, context->user_context, context->key_buffer);
    kdf2_perform(iv, l, p, u, a, derived_key_size, context, out);
}


void kdf2_perform(const unsigned char* iv, const unsigned char* l, const unsigned char* p, const unsigned char* u,
                  const unsigned char* a, unsigned long derived_key_size, R1323665_1_022_2018_KDF2_CONTEXT* context,
                  unsigned char* out)
{
    //
    // Calculate required number of iterations
    //

    const unsigned long iterations = derived_key_size / context->mac_size;

    //
    // Now perform iterations
    // Well... KDF itself is not quite complicated
    //

    unsigned long counter  = 0;
    const unsigned char* z = iv;

    for (; counter < iterations; ++counter)
    {
        context->format(z, counter, p, u, a, l, context->user_context, context->format_buffer);
        context->mac(context->key_buffer, context->format_buffer, context->user_context, out);

        z = out;
        out += context->mac_size;
    }
}
