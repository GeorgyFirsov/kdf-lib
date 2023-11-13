/**
 * @file utils.h
 * @brief Some useful helper things.
 */

#ifndef KDFLIB_UTILS_INCLUDED
#define KDFLIB_UTILS_INCLUDED


/**
 * @brief Alignment specifier (alignas is supported since C11).
 */
#if defined(_MSC_VER)
#   define KDFLIB_ALIGN16 __declspec(align(16))
#elif defined(__GNUC__)
#   define KDFLIB_ALIGN16 __attribute__((aligned(16)))
#else
#   error Unsupported target for now
#endif


/**
 * @brief Force inlining specifier.
 */
#if defined(_MSC_VER)
#   define KDFLIB_FORCEINLINE __forceinline
#elif defined(__GNUC__)
#   define KDFLIB_FORCEINLINE __attribute__((always_inline))
#else
#   error Unsupported target for now
#endif


/**
 * @brief Static assertion for C language (prior to C11).
 */
#define KDFLIB_STATIC_ASSERT(cond, msg) \
   typedef char static_assertion_failed_##msg[(cond) ? 1 : -1]

#endif  // !KDFLIB_UTILS_INCLUDED