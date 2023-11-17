/**
 * @file test_utils.hpp
 * @brief Some helpers for tests.
 */

#pragma once

#include <cstdint>


//
// Necessary helper macro
//

#if defined(_MSC_VER)
#   define KDFLIB_TESTS_ALIGN16 __declspec(align(16))
#elif defined(__GNUC__)
#   define KDFLIB_TESTS_ALIGN16 __attribute__((aligned(16)))
#else
#   error Unsupported target for now
#endif


namespace test::details {

/**
 * @brief Test BLOBs for equality.
 */
inline bool EqualBlobs(const unsigned char* lhs, const unsigned char* rhs, std::size_t size)
{
    for (std::size_t idx = 0; idx < size; ++idx)
    {
        if (lhs[idx] != rhs[idx])
        {
            return false;
        }
    }

    return true;
}

}  // namespace test::details
