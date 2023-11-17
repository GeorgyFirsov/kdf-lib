/**
 * @file r1323665_1_022-2018.cpp
 * @brief Test cases for R1323665.1.022-2018 KDF.
 */

#include <test_common.hpp>

#include <algorithm>
#include <cstring>
#include <cstdint>
#include <limits>


namespace test::r1323665_1_022_2018 {
namespace details {

/**
 * @brief Parameters for kdf(2) in raw form.
 */
const auto internal_iv = (std::numeric_limits<unsigned long long>::max)();
const auto internal_p  = (std::numeric_limits<unsigned long long>::max)();
const auto internal_u  = (std::numeric_limits<unsigned long long>::max)();
const auto internal_a  = (std::numeric_limits<unsigned long long>::max)();

}  // namespace details


/**
 * @brief User context for KDF test.
 */
struct UserContext
{
    std::size_t key_size;
    std::size_t format_size;
};


/**
 * @brief Key initialization function.
 */
void initialize_key(const unsigned char* key, void* user_context, unsigned char* out)
{
    const auto internal_user_context = static_cast<const UserContext*>(user_context);
    std::memcpy(out, key, internal_user_context->key_size);
}


/**
 * @brief Intermediate key derivation function for kdf(1).
 */
void derive_key(const unsigned char* key, const unsigned char* t,
                void* user_context, unsigned char* out)
{
    const auto internal_user_context = static_cast<const UserContext*>(user_context);

    for (std::size_t idx = 0; idx < internal_user_context->key_size; ++idx)
    {
        out[idx] = key[idx] ^ t[idx];
    }
}


/**
 * @brief Formatting function for kdf(2).
 */
void format(const unsigned char* z, unsigned long long c, const unsigned char* p,
            const unsigned char* u, const unsigned char* a, unsigned long long l,
            void* /* user_context */, unsigned char* out)
{
    const auto internal_z   = reinterpret_cast<const unsigned long long*>(z);
    const auto internal_p   = reinterpret_cast<const unsigned long long*>(p);
    const auto internal_u   = reinterpret_cast<const unsigned long long*>(u);
    const auto internal_a   = reinterpret_cast<const unsigned long long*>(a);
    const auto internal_out = reinterpret_cast<unsigned long long*>(out);

    internal_out[0] = *internal_z;
    internal_out[1] = c;
    internal_out[2] = *internal_p;
    internal_out[3] = *internal_u;
    internal_out[4] = *internal_a;
    internal_out[5] = l;
}


/**
 * @brief Keyed hash function for kdf(2).
 * 
 * Not very secure one, but it is enough for testing purposes.
 */
void mac(const unsigned char* key, const unsigned char* in,
         void* user_context, unsigned char* out)
{
    const auto internal_user_context = static_cast<const UserContext*>(user_context);
    const auto max_size              = (std::max)(internal_user_context->format_size, internal_user_context->key_size);

    //
    // Copy key to the output buffer
    //

    std::memcpy(out, key, internal_user_context->key_size);

    //
    // And then xor them
    //

    for (std::size_t idx = 0; idx < max_size; ++idx)
    {
        out[idx % internal_user_context->key_size] ^= in[idx % internal_user_context->format_size];
    }
}


/**
 * @brief Parameters for kdf(1) and kdf(2).
 */
const auto t  = data::salt;
const auto l  = 256ull;
const auto iv = reinterpret_cast<const unsigned char*>(&details::internal_iv);
const auto p  = reinterpret_cast<const unsigned char*>(&details::internal_p);
const auto u  = reinterpret_cast<const unsigned char*>(&details::internal_u);
const auto a  = reinterpret_cast<const unsigned char*>(&details::internal_a);


/**
 * @brief Expected intermediate key for kdf(1).
 */
KDFLIB_TESTS_ALIGN16 constexpr unsigned char kdf1_expected_key[] = {
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xef, 0xef, 0xef, 0xef, 0xef, 0xef, 0xef, 0xef,
    0xef, 0xef, 0xef, 0xef, 0xef, 0xef, 0xef, 0xef};


/**
 * @brief Expected derived key for kdf(2).
 */
KDFLIB_TESTS_ALIGN16 constexpr unsigned char kdf2_expected_key[] = {
    0xff, 0xfe, 0xfd, 0xfc, 0xfb, 0xfa, 0xf9, 0xf8,
    0xf7, 0xf7, 0xf5, 0xf4, 0xf3, 0xf2, 0xf1, 0xf0,
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};

}  // namespace test::r1323665_1_022_2018



TEST(R1323665_1_022_2018, Kdf1)
{
    KDFLIB_TESTS_ALIGN16 unsigned char key_buffer[sizeof(test::data::master_key)] = {0};

    test::r1323665_1_022_2018::UserContext user_context = {
        .key_size = sizeof(key_buffer)};

    R1323665_1_022_2018_KDF1_CONTEXT kdf_context = {
        .key_buffer     = key_buffer,
        .user_context   = &user_context,
        .initialize_key = test::r1323665_1_022_2018::initialize_key,
        .derive_key     = test::r1323665_1_022_2018::derive_key};

    KDFLIB_TESTS_ALIGN16 unsigned char key[sizeof(test::data::master_key)] = {0};
    r1323665_1_022_2018_kdf1(test::data::master_key, test::r1323665_1_022_2018::t,
                             &kdf_context, key);

    EXPECT_PRED3(test::details::EqualBlobs, test::r1323665_1_022_2018::kdf1_expected_key,
                 key, sizeof(key));
}


TEST(R1323665_1_022_2018, Kdf2)
{
    KDFLIB_TESTS_ALIGN16 unsigned char key_buffer[sizeof(test::data::master_key)]    = {0};
    KDFLIB_TESTS_ALIGN16 unsigned char format_buffer[sizeof(unsigned long long) * 6] = {0};

    test::r1323665_1_022_2018::UserContext user_context = {
        .key_size    = sizeof(key_buffer),
        .format_size = sizeof(format_buffer)};

    R1323665_1_022_2018_KDF2_CONTEXT kdf_context = {
        .key_buffer     = key_buffer,
        .format_buffer  = format_buffer,
        .mac_size       = sizeof(key_buffer),
        .user_context   = &user_context,
        .initialize_key = test::r1323665_1_022_2018::initialize_key,
        .format         = test::r1323665_1_022_2018::format,
        .mac            = test::r1323665_1_022_2018::mac};

    KDFLIB_TESTS_ALIGN16 unsigned char key[sizeof(test::data::master_key)] = {0};
    r1323665_1_022_2018_kdf2(test::data::master_key,
                             test::r1323665_1_022_2018::iv,
                             test::r1323665_1_022_2018::l,
                             test::r1323665_1_022_2018::p,
                             test::r1323665_1_022_2018::u,
                             test::r1323665_1_022_2018::a,
                             &kdf_context, key);

    EXPECT_PRED3(test::details::EqualBlobs, test::r1323665_1_022_2018::kdf2_expected_key,
                 key, sizeof(key));
}
