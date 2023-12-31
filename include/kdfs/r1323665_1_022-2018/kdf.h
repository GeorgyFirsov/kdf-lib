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
 * @brief Context for kdf(1) part of R1323665.1.022-2018 KDF.
 */
typedef struct tagR1323665_1_022_2018_KDF1_CONTEXT
{
    unsigned char* key_buffer; /**< Buffer for `initialize_key` function output */

    void* user_context; /**< User-defined context, that is passed to all following functions */

    /**
     * @brief Initializes key for `derive_key`.
     * 
     * Note, that this function's `out` parameter points to
     * `key_buffer` member of this structure, hence, the
     * buffer MUST be able to hold an output of the function.
     * 
     * @param key binary key
     * @param user_context pointer to `user_context`
     * @param out pointer to `key_buffer`
     */
    void (*initialize_key)(const unsigned char* key, void* user_context, unsigned char* out);

    /**
     * @brief Initializes key for `mac`.
     * 
     * Note, that this function's `out` parameter points to
     * `key_buffer` member of this structure, hence, the
     * buffer MUST be able to hold an output of the function.
     * 
     * @param key binary key
     * @param t T parameter
     * @param user_context pointer to `user_context`
     * @param out pointer to `out` parameter of `kdf1` function
     */
    void (*derive_key)(const unsigned char* key, const unsigned char* t,
                       void* user_context, unsigned char* out);
} R1323665_1_022_2018_KDF1_CONTEXT;


/**
 * @brief Context for kdf(2) part of R1323665.1.022-2018 KDF.
 */
typedef struct tagR1323665_1_022_2018_KDF2_CONTEXT
{
    unsigned char* key_buffer;    /**< Buffer for `initialize_key` function output */
    unsigned char* format_buffer; /**< Buffer for `format` function output */

    unsigned long long mac_size; /**< Size of `mac` output in bytes */

    void* user_context; /**< User-defined context, that is passed to all following functions */

    /**
     * @brief Initializes key for `mac`.
     * 
     * Note, that this function's `out` parameter points to
     * `key_buffer` member of this structure, hence, the
     * buffer MUST be able to hold an output of the function.
     * 
     * @param key binary key
     * @param user_context pointer to `user_context`
     * @param out pointer to `key_buffer`
     */
    void (*initialize_key)(const unsigned char* key, void* user_context, unsigned char* out);

    /**
     * @brief Performs formattion of KDF parameters.
     * 
     * Note, that this function's `out` parameter points to
     * `format_buffer` member of this structure, hence, the
     * buffer MUST be able to hold an output of the function.
     * 
     * @param z Z_{i - 1} parameter
     * @param c C_{i} parameter
     * @param p P parameter
     * @param u U parameter
     * @param a A parameter
     * @param l L parameter
     * @param user_context pointer to `user_context`
     * @param out pointer to `format_buffer`
     */
    void (*format)(const unsigned char* z, unsigned long long c, const unsigned char* p,
                   const unsigned char* u, const unsigned char* a, unsigned long long l,
                   void* user_context, unsigned char* out);

    /**
     * @brief Calculates MAC of formatted parameters.
     * 
     * @param key pointer to `key_buffer`
     * @param in pointer to `format_buffer`
     * @param user_context pointer to `user_context`
     * @param out pointer to a shifted `out` parameter of `kdf2` function
     */
    void (*mac)(const unsigned char* key, const unsigned char* in,
                void* user_context, unsigned char* out);
} R1323665_1_022_2018_KDF2_CONTEXT;


/**
 * @brief Performs kdf(1) part of R1323665.1.022-2018 KDF.
 * 
 * @param key master key
 * @param t T parameter (salt)
 * @param context initialized kdf(1) context
 * @param out pointer to intermediate key
 */
void r1323665_1_022_2018_kdf1(const unsigned char* key, const unsigned char* t,
                              R1323665_1_022_2018_KDF1_CONTEXT* context, unsigned char* out);


/**
 * @brief Performs actual action of kdf(1) part of R1323665.1.022-2018 KDF. 
 *        This function exists for testing purposes. 
 */
void r1323665_1_022_2018_kdf1_perform(const unsigned char* t, R1323665_1_022_2018_KDF1_CONTEXT* context,
                                      unsigned char* out);


/**
 * @brief Performs kdf(2) part of R1323665.1.022-2018 KDF.
 * 
 * Size of `out` parameter MUST be enough for writing N
 * `R1323665_1_022_2018_KDF2_CONTEXT::mac` results each shifted 
 * by M bytes from each other, where:
 *  - N = `derived_key_size / R1323665_1_022_2018_KDF2_CONTEXT:mac_size`
 *  - M = `R1323665_1_022_2018_KDF2_CONTEXT::mac_size` 
 * 
 * @param key intermediate key
 * @param iv initialization vector (its size matches the size of `z` 
 *           parameter of `R1323665_1_022_2018_KDF2_CONTEXT::format`)
 * @param l L parameter (length in bits of a key to derive)
 * @param p P parameter
 * @param u U parameter
 * @param a A parameter
 * @param context initialized kdf(2) context
 * @param out pointer to derived key
 */
void r1323665_1_022_2018_kdf2(const unsigned char* key, const unsigned char* iv, unsigned long long l,
                              const unsigned char* p, const unsigned char* u, const unsigned char* a,
                              R1323665_1_022_2018_KDF2_CONTEXT* context, unsigned char* out);


/**
 * @brief Performs actual action of kdf(2) part of R1323665.1.022-2018 KDF. 
 *        This function exists for testing purposes. 
 */
void r1323665_1_022_2018_kdf2_perform(const unsigned char* iv, unsigned long long l, const unsigned char* p,
                                      const unsigned char* u, const unsigned char* a,
                                      R1323665_1_022_2018_KDF2_CONTEXT* context, unsigned char* out);


#ifdef __cplusplus
}
#endif  // __cplusplus

#endif  // !KDFLIB_R1323665_1_022_2018_INCLUDED
