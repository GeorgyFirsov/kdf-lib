/**
 * @file kdf.h
 * @brief R1323665.1.022-2018 KDF header
 */

#ifndef KDFLIB_R1323665_1_022_2018_INCLUDED
#define KDFLIB_R1323665_1_022_2018_INCLUDED

#ifdef __cplusplus
extern "C" {
#endif  // __cplusplus


/**
 * @brief 
 */
typedef struct tagR1323665_1_022_2018_KDF2_CONTEXT
{
    unsigned char* key_buffer;    /**< */
    unsigned char* format_buffer; /**< */

    unsigned long mac_size; /**< */

    /**
     * @brief 
     * 
     * @param kdf
     * @param out
     */
    void (*initialize_key)(const unsigned char* key, unsigned char* out);

    /**
     * @brief 
     * 
     * @param z
     * @param c
     * @param p
     * @param u
     * @param a
     * @param l 
     * @param out 
     */
    void (*format)(const unsigned char* z, unsigned long c, const unsigned char* p,
                   const unsigned char* u, const unsigned char* a, const unsigned char* l,
                   unsigned char* out);

    /**
     * @brief
     * 
     * @param key 
     * @param in 
     * @param out 
     */
    void (*mac)(const unsigned char* key, const unsigned char* in, unsigned char* out);
} R1323665_1_022_2018_KDF2_CONTEXT;


/**
 * @brief 
 */
void kdf2(const unsigned char* key, const unsigned char* iv, const unsigned char* l, const unsigned char* p,
          const unsigned char* u, const unsigned char* a, unsigned long derived_key_size,
          R1323665_1_022_2018_KDF2_CONTEXT* context, unsigned char* out);


/**
 * @brief 
 */
void kdf2_perform(const unsigned char* iv, const unsigned char* l, const unsigned char* p, const unsigned char* u,
                  const unsigned char* a, unsigned long derived_key_size, R1323665_1_022_2018_KDF2_CONTEXT* context,
                  unsigned char* out);


#ifdef __cplusplus
}
#endif  // __cplusplus

#endif  // !KDFLIB_R1323665_1_022_2018_INCLUDED
