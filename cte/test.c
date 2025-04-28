#include <math.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "cte_command.h"
#include "cte_core.h"
#include "cte_ixdata.h"
#include "cte_pklist.h"
#include "cte_siglist.h"

static int g_total_errors = 0;

int approx_equal_double(double d1, double d2)
{
    double epsilon = 1e-9;
    return fabs(d1 - d2) < epsilon;
}
int approx_equal_float(float f1, float f2)
{
    float epsilon = 1e-6f;
    return fabsf(f1 - f2) < epsilon;
}

void print_hex(const char *prefix, const uint8_t *buffer, size_t len)
{
    if (!buffer)
    {
        printf("%s[NULL buffer]\n", prefix);
        return;
    }
    printf("%s[%zu bytes]: ", prefix, len);
    for (size_t i = 0; i < len; ++i)
    {
        printf("%02X ", buffer[i]);
    }
    printf("\n");
}

#define TEST_ASSERT_TRUE(cond, desc, test_name)                                                                        \
    if (!(cond))                                                                                                       \
    {                                                                                                                  \
        fprintf(stderr, "FAIL [%s]: %s\n", test_name, desc);                                                           \
        g_total_errors++;                                                                                              \
    }                                                                                                                  \
    else                                                                                                               \
    {                                                                                                                  \
    }

#define TEST_ASSERT_EQUAL_INT(actual, expected, desc, test_name)                                                       \
    if ((actual) != (expected))                                                                                        \
    {                                                                                                                  \
        fprintf(stderr, "FAIL [%s]: %s - Expected %lld, Got %lld\n", test_name, desc, (long long)(expected),           \
                (long long)(actual));                                                                                  \
        g_total_errors++;                                                                                              \
    }                                                                                                                  \
    else                                                                                                               \
    {                                                                                                                  \
    }

#define TEST_ASSERT_EQUAL_UINT(actual, expected, desc, test_name)                                                      \
    if ((actual) != (expected))                                                                                        \
    {                                                                                                                  \
        fprintf(stderr, "FAIL [%s]: %s - Expected %llu, Got %llu\n", test_name, desc, (unsigned long long)(expected),  \
                (unsigned long long)(actual));                                                                         \
        g_total_errors++;                                                                                              \
    }                                                                                                                  \
    else                                                                                                               \
    {                                                                                                                  \
    }

#define TEST_ASSERT_EQUAL_FLOAT(actual, expected, desc, test_name)                                                     \
    if (!approx_equal_float(actual, expected))                                                                         \
    {                                                                                                                  \
        fprintf(stderr, "FAIL [%s]: %s - Expected %f, Got %f\n", test_name, desc, (expected), (actual));               \
        g_total_errors++;                                                                                              \
    }                                                                                                                  \
    else                                                                                                               \
    {                                                                                                                  \
    }

#define TEST_ASSERT_EQUAL_DOUBLE(actual, expected, desc, test_name)                                                    \
    if (!approx_equal_double(actual, expected))                                                                        \
    {                                                                                                                  \
        fprintf(stderr, "FAIL [%s]: %s - Expected %lf, Got %lf\n", test_name, desc, (expected), (actual));             \
        g_total_errors++;                                                                                              \
    }                                                                                                                  \
    else                                                                                                               \
    {                                                                                                                  \
    }

#define TEST_ASSERT_EQUAL_MEM(actual_ptr, expected_ptr, len, desc, test_name)                                          \
    if (memcmp((void *)(actual_ptr), (void *)(expected_ptr), (size_t)(len)) != 0)                                      \
    {                                                                                                                  \
        fprintf(stderr, "FAIL [%s]: %s - Memory mismatch (%zu bytes)\n", test_name, desc, (size_t)(len));              \
        print_hex("  Actual  ", (const uint8_t *)(actual_ptr), (size_t)(len));                                         \
        print_hex("  Expected", (const uint8_t *)(expected_ptr), (size_t)(len));                                       \
        g_total_errors++;                                                                                              \
    }                                                                                                                  \
    else                                                                                                               \
    {                                                                                                                  \
    }

#define TEST_ASSERT_NOT_NULL(ptr, desc, test_name) TEST_ASSERT_TRUE((ptr) != NULL, desc, test_name)

void generate_random_bytes(uint8_t *buffer, size_t len)
{
    for (size_t i = 0; i < len; ++i)
    {
        buffer[i] = (uint8_t)(rand() % 256);
    }
}

uint8_t test_pk1[PQC_PUBKEY_SLH256F_SIZE];
uint8_t test_pk2[PQC_PUBKEY_SLH256F_SIZE];
uint8_t test_sig1[ED25519_SIGNATURE_SIZE];
uint8_t test_hash1[PQC_SIG_HASH_SIZE];
uint8_t test_hash2[PQC_SIG_HASH_SIZE];
char test_cmd_short[] = "ShortCmd";
char test_cmd_long[400];

void setup_test_data()
{

    for (size_t i = 0; i < sizeof(test_pk1); ++i)
        test_pk1[i] = (uint8_t)(0x10 + i);
    for (size_t i = 0; i < sizeof(test_pk2); ++i)
        test_pk2[i] = (uint8_t)(0xA0 + i);
    for (size_t i = 0; i < sizeof(test_sig1); ++i)
        test_sig1[i] = (uint8_t)(0xCC);
    for (size_t i = 0; i < sizeof(test_hash1); ++i)
        test_hash1[i] = (uint8_t)(0xEE);
    for (size_t i = 0; i < sizeof(test_hash2); ++i)
        test_hash2[i] = (uint8_t)(0xF0 + i);
    for (size_t i = 0; i < sizeof(test_cmd_long); ++i)
        test_cmd_long[i] = (char)('A' + (i % 26));
    test_cmd_long[sizeof(test_cmd_long) - 1] = '\0';
}

void test_pk_list()
{
    const char *test_name = "PK List";
    printf("--- Test: %s ---\n", test_name);
    void *enc, *dec;
    uintptr_t w_ptr_offset, r_ptr_offset;
    uint8_t *w_ptr;
    const uint8_t *r_ptr;
    size_t size;
    int res;

    enc = cte_encoder_new();
    TEST_ASSERT_NOT_NULL(enc, "Encoder creation", test_name);
    w_ptr_offset = cte_encoder_prepare_public_key_list(enc, 2, CTE_CRYPTO_TYPE_ED25519);
    TEST_ASSERT_TRUE(w_ptr_offset != 0, "Prepare Ed25519 PK List (count=2)", test_name);
    w_ptr = (uint8_t *)w_ptr_offset;
    memcpy(w_ptr, test_pk1, ED25519_PUBLIC_KEY_SIZE);
    memcpy(w_ptr + ED25519_PUBLIC_KEY_SIZE, test_pk2, ED25519_PUBLIC_KEY_SIZE);
    r_ptr_offset = cte_encoder_get_buffer_ptr(enc);
    size = cte_encoder_get_buffer_size(enc);
    TEST_ASSERT_EQUAL_UINT(size, 1 + 1 + 2 * ED25519_PUBLIC_KEY_SIZE, "Encoded size (Ed25519, N=2)", test_name);
    r_ptr = (const uint8_t *)r_ptr_offset;
    TEST_ASSERT_EQUAL_UINT(r_ptr[1], TAG_PUBLIC_KEY_LIST | (2 << 2) | CTE_CRYPTO_TYPE_ED25519,
                           "Header byte (Ed25519, N=2)", test_name);

    dec = cte_decoder_new();
    TEST_ASSERT_NOT_NULL(dec, "Decoder creation", test_name);
    res = cte_decoder_set_input_buffer(dec, r_ptr, size);
    TEST_ASSERT_EQUAL_INT(res, CTE_SUCCESS, "Set Input Buffer", test_name);
    res = cte_decoder_advance(dec);
    TEST_ASSERT_EQUAL_INT(res, CTE_FIELD_TYPE_PUBKEY_LIST, "Advance to PK List", test_name);
    TEST_ASSERT_EQUAL_INT(cte_decoder_get_list_count(dec), 2, "Decoded count", test_name);
    TEST_ASSERT_EQUAL_INT(cte_decoder_get_pklist_type_code(dec), CTE_CRYPTO_TYPE_ED25519, "Decoded type code",
                          test_name);
    uintptr_t d_ptr_offset = cte_decoder_get_data_ptr(dec);
    TEST_ASSERT_NOT_NULL((void *)d_ptr_offset, "Get data pointer", test_name);

    TEST_ASSERT_EQUAL_MEM(d_ptr_offset, test_pk1, ED25519_PUBLIC_KEY_SIZE, "Key 1 data", test_name);
    TEST_ASSERT_EQUAL_MEM(d_ptr_offset + ED25519_PUBLIC_KEY_SIZE, test_pk2, ED25519_PUBLIC_KEY_SIZE, "Key 2 data",
                          test_name);
    res = cte_decoder_advance(dec);
    TEST_ASSERT_EQUAL_INT(res, CTE_ERROR_END_OF_BUFFER, "Advance past last field", test_name);

    enc = cte_encoder_new();
    w_ptr_offset = cte_encoder_prepare_public_key_list(enc, 1, CTE_CRYPTO_TYPE_SLH_SHA2_192F);
    TEST_ASSERT_TRUE(w_ptr_offset != 0, "Prepare SLH192f PK List (count=1)", test_name);
    w_ptr = (uint8_t *)w_ptr_offset;
    memcpy(w_ptr, test_pk1, PQC_PUBKEY_SLH192F_SIZE);
    r_ptr_offset = cte_encoder_get_buffer_ptr(enc);
    size = cte_encoder_get_buffer_size(enc);
    TEST_ASSERT_EQUAL_UINT(size, 1 + 1 + 1 * PQC_PUBKEY_SLH192F_SIZE, "Encoded size (SLH192f, N=1)", test_name);
    r_ptr = (const uint8_t *)r_ptr_offset;
    TEST_ASSERT_EQUAL_UINT(r_ptr[1], TAG_PUBLIC_KEY_LIST | (1 << 2) | CTE_CRYPTO_TYPE_SLH_SHA2_192F,
                           "Header byte (SLH192f, N=1)", test_name);
    dec = cte_decoder_new();
    cte_decoder_set_input_buffer(dec, r_ptr, size);
    cte_decoder_advance(dec);
    TEST_ASSERT_EQUAL_INT(cte_decoder_get_list_count(dec), 1, "Decoded count (SLH192f)", test_name);
    TEST_ASSERT_EQUAL_INT(cte_decoder_get_pklist_type_code(dec), CTE_CRYPTO_TYPE_SLH_SHA2_192F,
                          "Decoded type code (SLH192f)", test_name);
    d_ptr_offset = cte_decoder_get_data_ptr(dec);
    TEST_ASSERT_EQUAL_MEM(d_ptr_offset, test_pk1, PQC_PUBKEY_SLH192F_SIZE, "Key 1 data (SLH192f)", test_name);

    enc = cte_encoder_new();
    w_ptr_offset = cte_encoder_prepare_public_key_list(enc, 1, 0xFE);
    TEST_ASSERT_EQUAL_UINT(w_ptr_offset, 0, "Prepare PK List (Invalid type)", test_name);

    enc = cte_encoder_new();
    w_ptr_offset = cte_encoder_prepare_public_key_list(enc, 0, CTE_CRYPTO_TYPE_ED25519);
    TEST_ASSERT_EQUAL_UINT(w_ptr_offset, 0, "Prepare PK List (Count=0)", test_name);

    enc = cte_encoder_new();
    w_ptr_offset = cte_encoder_prepare_public_key_list(enc, MAX_LIST_LEN + 1, CTE_CRYPTO_TYPE_ED25519);
    TEST_ASSERT_EQUAL_UINT(w_ptr_offset, 0, "Prepare PK List (Count>Max)", test_name);
}

void test_sig_list()
{
    const char *test_name = "Sig List";
    printf("--- Test: %s ---\n", test_name);
    void *enc, *dec;
    uintptr_t w_ptr_offset, r_ptr_offset;
    uint8_t *w_ptr;
    const uint8_t *r_ptr;
    size_t size;
    int res;

    enc = cte_encoder_new();
    w_ptr_offset = cte_encoder_prepare_signature_list(enc, 1, CTE_SIG_TYPE_ED25519);
    TEST_ASSERT_TRUE(w_ptr_offset != 0, "Prepare Ed25519 Sig List (count=1)", test_name);
    w_ptr = (uint8_t *)w_ptr_offset;
    memcpy(w_ptr, test_sig1, ED25519_SIGNATURE_SIZE);
    r_ptr_offset = cte_encoder_get_buffer_ptr(enc);
    size = cte_encoder_get_buffer_size(enc);
    TEST_ASSERT_EQUAL_UINT(size, 1 + 1 + 1 * ED25519_SIGNATURE_SIZE, "Encoded size (Ed25519, N=1)", test_name);
    r_ptr = (const uint8_t *)r_ptr_offset;
    TEST_ASSERT_EQUAL_UINT(r_ptr[1], TAG_SIGNATURE_LIST | (1 << 2) | CTE_SIG_TYPE_ED25519, "Header byte (Ed25519, N=1)",
                           test_name);
    dec = cte_decoder_new();
    cte_decoder_set_input_buffer(dec, r_ptr, size);
    res = cte_decoder_advance(dec);
    TEST_ASSERT_EQUAL_INT(res, CTE_FIELD_TYPE_SIGNATURE_LIST, "Advance to Sig List", test_name);
    TEST_ASSERT_EQUAL_INT(cte_decoder_get_list_count(dec), 1, "Decoded count", test_name);
    TEST_ASSERT_EQUAL_INT(cte_decoder_get_siglist_type_code(dec), CTE_SIG_TYPE_ED25519, "Decoded type code", test_name);
    uintptr_t d_ptr_offset = cte_decoder_get_data_ptr(dec);
    TEST_ASSERT_NOT_NULL((void *)d_ptr_offset, "Get data pointer", test_name);
    TEST_ASSERT_EQUAL_MEM(d_ptr_offset, test_sig1, ED25519_SIGNATURE_SIZE, "Sig 1 data", test_name);
    res = cte_decoder_advance(dec);
    TEST_ASSERT_EQUAL_INT(res, CTE_ERROR_END_OF_BUFFER, "Advance past last field", test_name);

    enc = cte_encoder_new();
    w_ptr_offset = cte_encoder_prepare_signature_list(enc, 2, CTE_SIG_TYPE_SLH_SHA2_256F_HASH32);
    TEST_ASSERT_TRUE(w_ptr_offset != 0, "Prepare PQC Hash List (count=2)", test_name);
    w_ptr = (uint8_t *)w_ptr_offset;
    memcpy(w_ptr, test_hash1, PQC_SIG_HASH_SIZE);
    memcpy(w_ptr + PQC_SIG_HASH_SIZE, test_hash2, PQC_SIG_HASH_SIZE);
    r_ptr_offset = cte_encoder_get_buffer_ptr(enc);
    size = cte_encoder_get_buffer_size(enc);
    TEST_ASSERT_EQUAL_UINT(size, 1 + 1 + 2 * PQC_SIG_HASH_SIZE, "Encoded size (PQC Hash, N=2)", test_name);
    r_ptr = (const uint8_t *)r_ptr_offset;
    TEST_ASSERT_EQUAL_UINT(r_ptr[1], TAG_SIGNATURE_LIST | (2 << 2) | CTE_SIG_TYPE_SLH_SHA2_256F_HASH32,
                           "Header byte (PQC Hash, N=2)", test_name);
    dec = cte_decoder_new();
    cte_decoder_set_input_buffer(dec, r_ptr, size);
    res = cte_decoder_advance(dec);
    TEST_ASSERT_EQUAL_INT(res, CTE_FIELD_TYPE_SIGNATURE_LIST, "Advance to PQC Hash List", test_name);
    TEST_ASSERT_EQUAL_INT(cte_decoder_get_list_count(dec), 2, "Decoded count (PQC Hash)", test_name);
    TEST_ASSERT_EQUAL_INT(cte_decoder_get_siglist_type_code(dec), CTE_SIG_TYPE_SLH_SHA2_256F_HASH32,
                          "Decoded type code (PQC Hash)", test_name);
    d_ptr_offset = cte_decoder_get_data_ptr(dec);
    TEST_ASSERT_NOT_NULL((void *)d_ptr_offset, "Get data pointer (PQC Hash)", test_name);
    TEST_ASSERT_EQUAL_MEM(d_ptr_offset, test_hash1, PQC_SIG_HASH_SIZE, "Hash 1 data", test_name);
    TEST_ASSERT_EQUAL_MEM(d_ptr_offset + PQC_SIG_HASH_SIZE, test_hash2, PQC_SIG_HASH_SIZE, "Hash 2 data", test_name);
    res = cte_decoder_advance(dec);
    TEST_ASSERT_EQUAL_INT(res, CTE_ERROR_END_OF_BUFFER, "Advance past last field (PQC Hash)", test_name);
}

void test_ixdata()
{
    const char *test_name = "IxData";
    printf("--- Test: %s ---\n", test_name);
    void *enc, *dec;
    uintptr_t r_ptr_offset;
    const uint8_t *r_ptr;
    size_t size;
    int res;

    uint8_t leg_idx = 5;
    uint64_t uleb_vals[] = {0, 1, 127, 128, 16383, 16384, 0xFFFFFFFFFFFFFFFFULL};
    int64_t sleb_vals[] = {0, 1, -1, 63, -64, 8191, -8192, 0x7FFFFFFFFFFFFFFFLL, -0x8000000000000000LL};
    int8_t fix_i8 = -128;
    uint8_t fix_u8 = 255;
    int16_t fix_i16 = -32768;
    uint16_t fix_u16 = 65535;
    int32_t fix_i32 = -2147483648;
    uint32_t fix_u32 = 0xFFFFFFFF;
    int64_t fix_i64 = -0x8000000000000000LL;
    uint64_t fix_u64 = 0xFFFFFFFFFFFFFFFFULL;
    float fix_f32 = -1.2345e+30f;
    double fix_f64 = 1.23456789e-100;

    enc = cte_encoder_new();
    TEST_ASSERT_NOT_NULL(enc, "Encoder creation", test_name);

    cte_encoder_write_index_reference(enc, leg_idx);
    cte_encoder_write_ixdata_zero(enc);
    for (size_t i = 0; i < sizeof(uleb_vals) / sizeof(uleb_vals[0]); ++i)
        cte_encoder_write_ixdata_uleb128(enc, uleb_vals[i]);
    for (size_t i = 0; i < sizeof(sleb_vals) / sizeof(sleb_vals[0]); ++i)
        cte_encoder_write_ixdata_sleb128(enc, sleb_vals[i]);
    cte_encoder_write_ixdata_fixed_int8(enc, fix_i8);
    cte_encoder_write_ixdata_fixed_uint8(enc, fix_u8);
    cte_encoder_write_ixdata_fixed_int16(enc, fix_i16);
    cte_encoder_write_ixdata_fixed_uint16(enc, fix_u16);
    cte_encoder_write_ixdata_fixed_int32(enc, fix_i32);
    cte_encoder_write_ixdata_fixed_uint32(enc, fix_u32);
    cte_encoder_write_ixdata_fixed_int64(enc, fix_i64);
    cte_encoder_write_ixdata_fixed_uint64(enc, fix_u64);
    cte_encoder_write_ixdata_fixed_float32(enc, fix_f32);
    cte_encoder_write_ixdata_fixed_float64(enc, fix_f64);
    cte_encoder_write_ixdata_boolean(enc, 0);
    cte_encoder_write_ixdata_boolean(enc, 1);

    r_ptr_offset = cte_encoder_get_buffer_ptr(enc);
    size = cte_encoder_get_buffer_size(enc);
    r_ptr = (const uint8_t *)r_ptr_offset;
    print_hex("Encoded IxData Mix", r_ptr, size);

    dec = cte_decoder_new();
    TEST_ASSERT_NOT_NULL(dec, "Decoder creation", test_name);
    res = cte_decoder_set_input_buffer(dec, r_ptr, size);
    TEST_ASSERT_EQUAL_INT(res, CTE_SUCCESS, "Set Input Buffer", test_name);

    int field_idx = 0;

    res = cte_decoder_advance(dec);
    TEST_ASSERT_EQUAL_INT(res, CTE_FIELD_TYPE_IXDATA, "Advance IxData[0]", test_name);
    TEST_ASSERT_EQUAL_INT(cte_decoder_get_ixdata_subtype(dec), IXDATA_SUBTYPE_LEGACY_INDEX, "SubType[0]", test_name);
    TEST_ASSERT_EQUAL_INT(cte_decoder_get_ixdata_legacy_index(dec), leg_idx, "Value[0]", test_name);
    field_idx++;

    res = cte_decoder_advance(dec);
    TEST_ASSERT_EQUAL_INT(res, CTE_FIELD_TYPE_IXDATA, "Advance IxData[1]", test_name);
    TEST_ASSERT_EQUAL_INT(cte_decoder_get_ixdata_subtype(dec), IXDATA_SUBTYPE_VARINT, "SubType[1]", test_name);
    TEST_ASSERT_EQUAL_INT(cte_decoder_get_ixdata_varint_scheme(dec), IXDATA_VARINT_SCHEME_ZERO, "Scheme[1]", test_name);
    uint64_t uval;
    int64_t sval;
    cte_decoder_get_ixdata_varint_value_u64(dec, &uval);
    TEST_ASSERT_EQUAL_UINT(uval, 0, "Value[1].u64", test_name);
    cte_decoder_get_ixdata_varint_value_i64(dec, &sval);
    TEST_ASSERT_EQUAL_INT(sval, 0, "Value[1].i64", test_name);
    field_idx++;

    for (size_t i = 0; i < sizeof(uleb_vals) / sizeof(uleb_vals[0]); ++i, ++field_idx)
    {
        char desc[50];
        snprintf(desc, 50, "Advance IxData[%d]", field_idx);
        res = cte_decoder_advance(dec);
        TEST_ASSERT_EQUAL_INT(res, CTE_FIELD_TYPE_IXDATA, desc, test_name);
        snprintf(desc, 50, "SubType[%d]", field_idx);
        TEST_ASSERT_EQUAL_INT(cte_decoder_get_ixdata_subtype(dec), IXDATA_SUBTYPE_VARINT, desc, test_name);
        snprintf(desc, 50, "Scheme[%d]", field_idx);
        TEST_ASSERT_EQUAL_INT(cte_decoder_get_ixdata_varint_scheme(dec), IXDATA_VARINT_SCHEME_ULEB128, desc, test_name);
        snprintf(desc, 50, "Value[%d]", field_idx);
        cte_decoder_get_ixdata_varint_value_u64(dec, &uval);
        TEST_ASSERT_EQUAL_UINT(uval, uleb_vals[i], desc, test_name);
    }

    for (size_t i = 0; i < sizeof(sleb_vals) / sizeof(sleb_vals[0]); ++i, ++field_idx)
    {
        char desc[50];
        snprintf(desc, 50, "Advance IxData[%d]", field_idx);
        res = cte_decoder_advance(dec);
        TEST_ASSERT_EQUAL_INT(res, CTE_FIELD_TYPE_IXDATA, desc, test_name);
        snprintf(desc, 50, "SubType[%d]", field_idx);
        TEST_ASSERT_EQUAL_INT(cte_decoder_get_ixdata_subtype(dec), IXDATA_SUBTYPE_VARINT, desc, test_name);
        snprintf(desc, 50, "Scheme[%d]", field_idx);
        TEST_ASSERT_EQUAL_INT(cte_decoder_get_ixdata_varint_scheme(dec), IXDATA_VARINT_SCHEME_SLEB128, desc, test_name);
        snprintf(desc, 50, "Value[%d]", field_idx);
        cte_decoder_get_ixdata_varint_value_i64(dec, &sval);
        TEST_ASSERT_EQUAL_INT(sval, sleb_vals[i], desc, test_name);
    }

    res = cte_decoder_advance(dec);
    TEST_ASSERT_EQUAL_INT(res, CTE_FIELD_TYPE_IXDATA, "Advance IxData[18]", test_name);
    TEST_ASSERT_EQUAL_INT(cte_decoder_get_ixdata_subtype(dec), IXDATA_SUBTYPE_FIXED, "SubType[18]", test_name);
    TEST_ASSERT_EQUAL_INT(cte_decoder_get_ixdata_fixed_type_code(dec), IXDATA_FIXED_TYPE_INT8, "TypeCode[18]",
                          test_name);
    int8_t i8v;
    cte_decoder_get_ixdata_fixed_value_int8(dec, &i8v);
    TEST_ASSERT_EQUAL_INT(i8v, fix_i8, "Value[18]", test_name);
    field_idx++;

    res = cte_decoder_advance(dec);
    TEST_ASSERT_EQUAL_INT(res, CTE_FIELD_TYPE_IXDATA, "Advance IxData[19]", test_name);
    TEST_ASSERT_EQUAL_INT(cte_decoder_get_ixdata_subtype(dec), IXDATA_SUBTYPE_FIXED, "SubType[19]", test_name);
    TEST_ASSERT_EQUAL_INT(cte_decoder_get_ixdata_fixed_type_code(dec), IXDATA_FIXED_TYPE_UINT8, "TypeCode[19]",
                          test_name);
    uint8_t u8v;
    cte_decoder_get_ixdata_fixed_value_uint8(dec, &u8v);
    TEST_ASSERT_EQUAL_UINT(u8v, fix_u8, "Value[19]", test_name);
    field_idx++;

    res = cte_decoder_advance(dec);
    TEST_ASSERT_EQUAL_INT(res, CTE_FIELD_TYPE_IXDATA, "Advance IxData[20]", test_name);
    TEST_ASSERT_EQUAL_INT(cte_decoder_get_ixdata_subtype(dec), IXDATA_SUBTYPE_FIXED, "SubType[20]", test_name);
    TEST_ASSERT_EQUAL_INT(cte_decoder_get_ixdata_fixed_type_code(dec), IXDATA_FIXED_TYPE_INT16, "TypeCode[20]",
                          test_name);
    int16_t i16v;
    cte_decoder_get_ixdata_fixed_value_int16(dec, &i16v);
    TEST_ASSERT_EQUAL_INT(i16v, fix_i16, "Value[20]", test_name);
    field_idx++;

    res = cte_decoder_advance(dec);
    TEST_ASSERT_EQUAL_INT(res, CTE_FIELD_TYPE_IXDATA, "Advance IxData[21]", test_name);
    TEST_ASSERT_EQUAL_INT(cte_decoder_get_ixdata_subtype(dec), IXDATA_SUBTYPE_FIXED, "SubType[21]", test_name);
    TEST_ASSERT_EQUAL_INT(cte_decoder_get_ixdata_fixed_type_code(dec), IXDATA_FIXED_TYPE_UINT16, "TypeCode[21]",
                          test_name);
    uint16_t u16v;
    cte_decoder_get_ixdata_fixed_value_uint16(dec, &u16v);
    TEST_ASSERT_EQUAL_UINT(u16v, fix_u16, "Value[21]", test_name);
    field_idx++;

    res = cte_decoder_advance(dec);
    TEST_ASSERT_EQUAL_INT(res, CTE_FIELD_TYPE_IXDATA, "Advance IxData[22]", test_name);
    TEST_ASSERT_EQUAL_INT(cte_decoder_get_ixdata_subtype(dec), IXDATA_SUBTYPE_FIXED, "SubType[22]", test_name);
    TEST_ASSERT_EQUAL_INT(cte_decoder_get_ixdata_fixed_type_code(dec), IXDATA_FIXED_TYPE_INT32, "TypeCode[22]",
                          test_name);
    int32_t i32v;
    cte_decoder_get_ixdata_fixed_value_int32(dec, &i32v);
    TEST_ASSERT_EQUAL_INT(i32v, fix_i32, "Value[22]", test_name);
    field_idx++;

    res = cte_decoder_advance(dec);
    TEST_ASSERT_EQUAL_INT(res, CTE_FIELD_TYPE_IXDATA, "Advance IxData[23]", test_name);
    TEST_ASSERT_EQUAL_INT(cte_decoder_get_ixdata_subtype(dec), IXDATA_SUBTYPE_FIXED, "SubType[23]", test_name);
    TEST_ASSERT_EQUAL_INT(cte_decoder_get_ixdata_fixed_type_code(dec), IXDATA_FIXED_TYPE_UINT32, "TypeCode[23]",
                          test_name);
    uint32_t u32v;
    cte_decoder_get_ixdata_fixed_value_uint32(dec, &u32v);
    TEST_ASSERT_EQUAL_UINT(u32v, fix_u32, "Value[23]", test_name);
    field_idx++;

    res = cte_decoder_advance(dec);
    TEST_ASSERT_EQUAL_INT(res, CTE_FIELD_TYPE_IXDATA, "Advance IxData[24]", test_name);
    TEST_ASSERT_EQUAL_INT(cte_decoder_get_ixdata_subtype(dec), IXDATA_SUBTYPE_FIXED, "SubType[24]", test_name);
    TEST_ASSERT_EQUAL_INT(cte_decoder_get_ixdata_fixed_type_code(dec), IXDATA_FIXED_TYPE_INT64, "TypeCode[24]",
                          test_name);
    int64_t i64v;
    cte_decoder_get_ixdata_fixed_value_int64(dec, &i64v);
    TEST_ASSERT_EQUAL_INT(i64v, fix_i64, "Value[24]", test_name);
    field_idx++;

    res = cte_decoder_advance(dec);
    TEST_ASSERT_EQUAL_INT(res, CTE_FIELD_TYPE_IXDATA, "Advance IxData[25]", test_name);
    TEST_ASSERT_EQUAL_INT(cte_decoder_get_ixdata_subtype(dec), IXDATA_SUBTYPE_FIXED, "SubType[25]", test_name);
    TEST_ASSERT_EQUAL_INT(cte_decoder_get_ixdata_fixed_type_code(dec), IXDATA_FIXED_TYPE_UINT64, "TypeCode[25]",
                          test_name);
    uint64_t u64v;
    cte_decoder_get_ixdata_fixed_value_uint64(dec, &u64v);
    TEST_ASSERT_EQUAL_UINT(u64v, fix_u64, "Value[25]", test_name);
    field_idx++;

    res = cte_decoder_advance(dec);
    TEST_ASSERT_EQUAL_INT(res, CTE_FIELD_TYPE_IXDATA, "Advance IxData[26]", test_name);
    TEST_ASSERT_EQUAL_INT(cte_decoder_get_ixdata_subtype(dec), IXDATA_SUBTYPE_FIXED, "SubType[26]", test_name);
    TEST_ASSERT_EQUAL_INT(cte_decoder_get_ixdata_fixed_type_code(dec), IXDATA_FIXED_TYPE_FLOAT32, "TypeCode[26]",
                          test_name);
    float f32v;
    cte_decoder_get_ixdata_fixed_value_float32(dec, &f32v);
    TEST_ASSERT_EQUAL_FLOAT(f32v, fix_f32, "Value[26]", test_name);
    field_idx++;

    res = cte_decoder_advance(dec);
    TEST_ASSERT_EQUAL_INT(res, CTE_FIELD_TYPE_IXDATA, "Advance IxData[27]", test_name);
    TEST_ASSERT_EQUAL_INT(cte_decoder_get_ixdata_subtype(dec), IXDATA_SUBTYPE_FIXED, "SubType[27]", test_name);
    TEST_ASSERT_EQUAL_INT(cte_decoder_get_ixdata_fixed_type_code(dec), IXDATA_FIXED_TYPE_FLOAT64, "TypeCode[27]",
                          test_name);
    double f64v;
    cte_decoder_get_ixdata_fixed_value_float64(dec, &f64v);
    TEST_ASSERT_EQUAL_DOUBLE(f64v, fix_f64, "Value[27]", test_name);
    field_idx++;

    res = cte_decoder_advance(dec);
    TEST_ASSERT_EQUAL_INT(res, CTE_FIELD_TYPE_IXDATA, "Advance IxData[28]", test_name);
    TEST_ASSERT_EQUAL_INT(cte_decoder_get_ixdata_subtype(dec), IXDATA_SUBTYPE_CONSTANT, "SubType[28]", test_name);
    TEST_ASSERT_EQUAL_INT(cte_decoder_get_ixdata_constant_code(dec), IXDATA_CONSTANT_CODE_FALSE, "ConstCode[28]",
                          test_name);
    uint8_t bval;
    cte_decoder_get_ixdata_boolean_value(dec, &bval);
    TEST_ASSERT_EQUAL_UINT(bval, 0, "Value[28]", test_name);
    field_idx++;

    res = cte_decoder_advance(dec);
    TEST_ASSERT_EQUAL_INT(res, CTE_FIELD_TYPE_IXDATA, "Advance IxData[29]", test_name);
    TEST_ASSERT_EQUAL_INT(cte_decoder_get_ixdata_subtype(dec), IXDATA_SUBTYPE_CONSTANT, "SubType[29]", test_name);
    TEST_ASSERT_EQUAL_INT(cte_decoder_get_ixdata_constant_code(dec), IXDATA_CONSTANT_CODE_TRUE, "ConstCode[29]",
                          test_name);
    cte_decoder_get_ixdata_boolean_value(dec, &bval);
    TEST_ASSERT_EQUAL_UINT(bval, 1, "Value[29]", test_name);
    field_idx++;

    res = cte_decoder_advance(dec);
    TEST_ASSERT_EQUAL_INT(res, CTE_ERROR_END_OF_BUFFER, "Advance past last field", test_name);
}

void test_command_data()
{
    const char *test_name = "Command Data";
    printf("--- Test: %s ---\n", test_name);
    void *enc, *dec;
    uintptr_t w_ptr_offset, r_ptr_offset;
    uint8_t *w_ptr;
    const uint8_t *r_ptr;
    size_t size;
    int res;

    enc = cte_encoder_new();
    w_ptr_offset = cte_encoder_prepare_command_data(enc, 0);

    TEST_ASSERT_TRUE(w_ptr_offset == (uintptr_t)cte_encoder_get_buffer_ptr(enc) + 1 + 1,
                     "Prepare Cmd Short (len=0) offset check", test_name);
    r_ptr_offset = cte_encoder_get_buffer_ptr(enc);
    size = cte_encoder_get_buffer_size(enc);
    TEST_ASSERT_EQUAL_UINT(size, 1 + 1, "Encoded size (Cmd Short, len=0)", test_name);
    r_ptr = (const uint8_t *)r_ptr_offset;
    TEST_ASSERT_EQUAL_UINT(r_ptr[1], TAG_COMMAND_DATA | 0, "Header (Cmd Short, len=0)", test_name);
    dec = cte_decoder_new();
    cte_decoder_set_input_buffer(dec, r_ptr, size);
    res = cte_decoder_advance(dec);
    TEST_ASSERT_EQUAL_INT(res, CTE_FIELD_TYPE_COMMAND_DATA, "Advance Cmd Short (len=0)", test_name);
    TEST_ASSERT_EQUAL_UINT(cte_decoder_get_command_len(dec), 0, "Decoded len (Cmd Short, len=0)", test_name);
    TEST_ASSERT_EQUAL_UINT(cte_decoder_get_data_ptr(dec), 0, "Decoded ptr (Cmd Short, len=0)", test_name);
    res = cte_decoder_advance(dec);
    TEST_ASSERT_EQUAL_INT(res, CTE_ERROR_END_OF_BUFFER, "Advance EOB", test_name);

    size_t cmd_short_len = strlen(test_cmd_short);
    enc = cte_encoder_new();
    w_ptr_offset = cte_encoder_prepare_command_data(enc, cmd_short_len);
    TEST_ASSERT_TRUE(w_ptr_offset != 0, "Prepare Cmd Short (len=10)", test_name);
    w_ptr = (uint8_t *)w_ptr_offset;
    memcpy(w_ptr, test_cmd_short, cmd_short_len);
    r_ptr_offset = cte_encoder_get_buffer_ptr(enc);
    size = cte_encoder_get_buffer_size(enc);
    TEST_ASSERT_EQUAL_UINT(size, 1 + 1 + cmd_short_len, "Encoded size (Cmd Short, len=10)", test_name);
    r_ptr = (const uint8_t *)r_ptr_offset;
    TEST_ASSERT_EQUAL_UINT(r_ptr[1], TAG_COMMAND_DATA | (uint8_t)cmd_short_len, "Header (Cmd Short, len=10)",
                           test_name);
    dec = cte_decoder_new();
    cte_decoder_set_input_buffer(dec, r_ptr, size);
    res = cte_decoder_advance(dec);
    TEST_ASSERT_EQUAL_INT(res, CTE_FIELD_TYPE_COMMAND_DATA, "Advance Cmd Short (len=10)", test_name);
    TEST_ASSERT_EQUAL_UINT(cte_decoder_get_command_len(dec), cmd_short_len, "Decoded len (Cmd Short, len=10)",
                           test_name);
    uintptr_t d_ptr_offset = cte_decoder_get_data_ptr(dec);
    TEST_ASSERT_NOT_NULL((void *)d_ptr_offset, "Data ptr (Cmd Short, len=10)", test_name);
    TEST_ASSERT_EQUAL_MEM(d_ptr_offset, test_cmd_short, cmd_short_len, "Data (Cmd Short, len=10)", test_name);
    res = cte_decoder_advance(dec);
    TEST_ASSERT_EQUAL_INT(res, CTE_ERROR_END_OF_BUFFER, "Advance EOB", test_name);

    char cmd_31[31];
    memset(cmd_31, 'S', 31);
    enc = cte_encoder_new();
    w_ptr_offset = cte_encoder_prepare_command_data(enc, 31);
    TEST_ASSERT_TRUE(w_ptr_offset != 0, "Prepare Cmd Short (len=31)", test_name);
    w_ptr = (uint8_t *)w_ptr_offset;
    memcpy(w_ptr, cmd_31, 31);
    r_ptr_offset = cte_encoder_get_buffer_ptr(enc);
    size = cte_encoder_get_buffer_size(enc);
    TEST_ASSERT_EQUAL_UINT(size, 1 + 1 + 31, "Encoded size (Cmd Short, len=31)", test_name);
    r_ptr = (const uint8_t *)r_ptr_offset;
    TEST_ASSERT_EQUAL_UINT(r_ptr[1], TAG_COMMAND_DATA | 31, "Header (Cmd Short, len=31)", test_name);
    dec = cte_decoder_new();
    cte_decoder_set_input_buffer(dec, r_ptr, size);
    res = cte_decoder_advance(dec);
    TEST_ASSERT_EQUAL_INT(res, CTE_FIELD_TYPE_COMMAND_DATA, "Advance Cmd Short (len=31)", test_name);
    TEST_ASSERT_EQUAL_UINT(cte_decoder_get_command_len(dec), 31, "Decoded len (Cmd Short, len=31)", test_name);
    d_ptr_offset = cte_decoder_get_data_ptr(dec);
    TEST_ASSERT_NOT_NULL((void *)d_ptr_offset, "Data ptr (Cmd Short, len=31)", test_name);
    TEST_ASSERT_EQUAL_MEM(d_ptr_offset, cmd_31, 31, "Data (Cmd Short, len=31)", test_name);
    res = cte_decoder_advance(dec);
    TEST_ASSERT_EQUAL_INT(res, CTE_ERROR_END_OF_BUFFER, "Advance EOB", test_name);

    char cmd_32[32];
    memset(cmd_32, 'E', 32);
    enc = cte_encoder_new();
    w_ptr_offset = cte_encoder_prepare_command_data(enc, 32);
    TEST_ASSERT_TRUE(w_ptr_offset != 0, "Prepare Cmd Ext (len=32)", test_name);
    w_ptr = (uint8_t *)w_ptr_offset;
    memcpy(w_ptr, cmd_32, 32);
    r_ptr_offset = cte_encoder_get_buffer_ptr(enc);
    size = cte_encoder_get_buffer_size(enc);
    TEST_ASSERT_EQUAL_UINT(size, 1 + 2 + 32, "Encoded size (Cmd Ext, len=32)", test_name);
    r_ptr = (const uint8_t *)r_ptr_offset;
    TEST_ASSERT_EQUAL_UINT(r_ptr[1], TAG_COMMAND_DATA | (1 << 5) | (0 << 2), "Header1 (Cmd Ext, len=32)", test_name);
    TEST_ASSERT_EQUAL_UINT(r_ptr[2], 32, "Header2 (Cmd Ext, len=32)", test_name);
    dec = cte_decoder_new();
    cte_decoder_set_input_buffer(dec, r_ptr, size);
    res = cte_decoder_advance(dec);
    TEST_ASSERT_EQUAL_INT(res, CTE_FIELD_TYPE_COMMAND_DATA, "Advance Cmd Ext (len=32)", test_name);
    TEST_ASSERT_EQUAL_UINT(cte_decoder_get_command_len(dec), 32, "Decoded len (Cmd Ext, len=32)", test_name);
    d_ptr_offset = cte_decoder_get_data_ptr(dec);
    TEST_ASSERT_NOT_NULL((void *)d_ptr_offset, "Data ptr (Cmd Ext, len=32)", test_name);
    TEST_ASSERT_EQUAL_MEM(d_ptr_offset, cmd_32, 32, "Data (Cmd Ext, len=32)", test_name);
    res = cte_decoder_advance(dec);
    TEST_ASSERT_EQUAL_INT(res, CTE_ERROR_END_OF_BUFFER, "Advance EOB", test_name);

    enc = cte_encoder_new();
    w_ptr_offset = cte_encoder_prepare_command_data(enc, 400);
    TEST_ASSERT_TRUE(w_ptr_offset != 0, "Prepare Cmd Ext (len=400)", test_name);
    w_ptr = (uint8_t *)w_ptr_offset;
    memcpy(w_ptr, test_cmd_long, 400);
    r_ptr_offset = cte_encoder_get_buffer_ptr(enc);
    size = cte_encoder_get_buffer_size(enc);
    TEST_ASSERT_EQUAL_UINT(size, 1 + 2 + 400, "Encoded size (Cmd Ext, len=400)", test_name);
    r_ptr = (const uint8_t *)r_ptr_offset;

    TEST_ASSERT_EQUAL_UINT(r_ptr[1], TAG_COMMAND_DATA | (1 << 5) | (1 << 2), "Header1 (Cmd Ext, len=400)", test_name);
    TEST_ASSERT_EQUAL_UINT(r_ptr[2], 0x90, "Header2 (Cmd Ext, len=400)", test_name);
    dec = cte_decoder_new();
    cte_decoder_set_input_buffer(dec, r_ptr, size);
    res = cte_decoder_advance(dec);
    TEST_ASSERT_EQUAL_INT(res, CTE_FIELD_TYPE_COMMAND_DATA, "Advance Cmd Ext (len=400)", test_name);
    TEST_ASSERT_EQUAL_UINT(cte_decoder_get_command_len(dec), 400, "Decoded len (Cmd Ext, len=400)", test_name);
    d_ptr_offset = cte_decoder_get_data_ptr(dec);
    TEST_ASSERT_NOT_NULL((void *)d_ptr_offset, "Data ptr (Cmd Ext, len=400)", test_name);
    TEST_ASSERT_EQUAL_MEM(d_ptr_offset, test_cmd_long, 400, "Data (Cmd Ext, len=400)", test_name);
    res = cte_decoder_advance(dec);
    TEST_ASSERT_EQUAL_INT(res, CTE_ERROR_END_OF_BUFFER, "Advance EOB", test_name);

    char cmd_1197[1197];
    memset(cmd_1197, 'M', 1197);
    enc = cte_encoder_new();
    w_ptr_offset = cte_encoder_prepare_command_data(enc, 1197);
    TEST_ASSERT_TRUE(w_ptr_offset != 0, "Prepare Cmd Ext (len=1197)", test_name);
    w_ptr = (uint8_t *)w_ptr_offset;
    memcpy(w_ptr, cmd_1197, 1197);
    r_ptr_offset = cte_encoder_get_buffer_ptr(enc);
    size = cte_encoder_get_buffer_size(enc);
    TEST_ASSERT_EQUAL_UINT(size, 1 + 2 + 1197, "Encoded size (Cmd Ext, len=1197)", test_name);
    r_ptr = (const uint8_t *)r_ptr_offset;

    TEST_ASSERT_EQUAL_UINT(r_ptr[1], TAG_COMMAND_DATA | (1 << 5) | (4 << 2), "Header1 (Cmd Ext, len=1197)", test_name);
    TEST_ASSERT_EQUAL_UINT(r_ptr[2], 0xAD, "Header2 (Cmd Ext, len=1197)", test_name);
    dec = cte_decoder_new();
    cte_decoder_set_input_buffer(dec, r_ptr, size);
    res = cte_decoder_advance(dec);
    TEST_ASSERT_EQUAL_INT(res, CTE_FIELD_TYPE_COMMAND_DATA, "Advance Cmd Ext (len=1197)", test_name);
    TEST_ASSERT_EQUAL_UINT(cte_decoder_get_command_len(dec), 1197, "Decoded len (Cmd Ext, len=1197)", test_name);
    d_ptr_offset = cte_decoder_get_data_ptr(dec);
    TEST_ASSERT_NOT_NULL((void *)d_ptr_offset, "Data ptr (Cmd Ext, len=1197)", test_name);
    TEST_ASSERT_EQUAL_MEM(d_ptr_offset, cmd_1197, 1197, "Data (Cmd Ext, len=1197)", test_name);
    res = cte_decoder_advance(dec);
    TEST_ASSERT_EQUAL_INT(res, CTE_ERROR_END_OF_BUFFER, "Advance EOB", test_name);

    enc = cte_encoder_new();
    w_ptr_offset = cte_encoder_prepare_command_data(enc, COMMAND_DATA_EXTENDED_MAX_LEN + 1);
    TEST_ASSERT_EQUAL_UINT(w_ptr_offset, 0, "Prepare Cmd Ext (len > max)", test_name);

    uint8_t invalid_cmd_hdr1[] = {CTE_VERSION_V1, TAG_COMMAND_DATA | (1 << 5) | (1 << 2) | 0x01, 0x90};
    dec = cte_decoder_new();
    cte_decoder_set_input_buffer(dec, invalid_cmd_hdr1, sizeof(invalid_cmd_hdr1));
    res = cte_decoder_advance(dec);
    TEST_ASSERT_EQUAL_INT(res, CTE_ERROR_INVALID_FORMAT, "Advance Cmd Ext (invalid padding)", test_name);
}

void test_round_trip()
{
    const char *test_name = "Round Trip";
    printf("--- Test: %s ---\n", test_name);
    void *enc, *dec;
    uintptr_t w_ptr_offset, r_ptr_offset;
    uint8_t *w_ptr;
    const uint8_t *r_ptr;
    size_t size;
    int res;

    uint8_t pk_tc = CTE_CRYPTO_TYPE_SLH_SHA2_256F;
    uint8_t pk_n = 1;
    size_t pk_s = _get_pk_size_from_type(pk_tc);

    uint8_t sig_tc = CTE_SIG_TYPE_SLH_SHA2_128F_HASH32;
    uint8_t sig_n = 2;
    size_t sig_s = _get_sig_item_size_from_type(sig_tc);

    uint8_t leg_idx_val = 0;

    uint64_t uleb_val = 1234567890ULL;
    int64_t sleb_val = -987654321LL;
    uint32_t fixed_u32 = 0xABCD1234;
    uint8_t bool_val = 1;

    size_t cmd_len = strlen(test_cmd_short);

    enc = cte_encoder_new();
    TEST_ASSERT_NOT_NULL(enc, "Encoder creation", test_name);

    w_ptr_offset = cte_encoder_prepare_public_key_list(enc, pk_n, pk_tc);
    TEST_ASSERT_TRUE(w_ptr_offset != 0, "Encode: Prepare PK", test_name);
    w_ptr = (uint8_t *)w_ptr_offset;
    memcpy(w_ptr, test_pk1, pk_s);

    w_ptr_offset = cte_encoder_prepare_signature_list(enc, sig_n, sig_tc);
    TEST_ASSERT_TRUE(w_ptr_offset != 0, "Encode: Prepare Sig", test_name);
    w_ptr = (uint8_t *)w_ptr_offset;
    memcpy(w_ptr, test_hash1, sig_s);
    memcpy(w_ptr + sig_s, test_hash2, sig_s);

    res = cte_encoder_write_index_reference(enc, leg_idx_val);
    TEST_ASSERT_EQUAL_INT(res, CTE_SUCCESS, "Encode: Legacy Index", test_name);

    res = cte_encoder_write_ixdata_uleb128(enc, uleb_val);
    TEST_ASSERT_EQUAL_INT(res, CTE_SUCCESS, "Encode: ULEB", test_name);

    res = cte_encoder_write_ixdata_sleb128(enc, sleb_val);
    TEST_ASSERT_EQUAL_INT(res, CTE_SUCCESS, "Encode: SLEB", test_name);

    res = cte_encoder_write_ixdata_fixed_uint32(enc, fixed_u32);
    TEST_ASSERT_EQUAL_INT(res, CTE_SUCCESS, "Encode: Fixed U32", test_name);

    res = cte_encoder_write_ixdata_boolean(enc, bool_val);
    TEST_ASSERT_EQUAL_INT(res, CTE_SUCCESS, "Encode: Boolean", test_name);

    w_ptr_offset = cte_encoder_prepare_command_data(enc, cmd_len);
    TEST_ASSERT_TRUE(w_ptr_offset != 0, "Encode: Prepare Cmd", test_name);
    w_ptr = (uint8_t *)w_ptr_offset;
    memcpy(w_ptr, test_cmd_short, cmd_len);

    r_ptr_offset = cte_encoder_get_buffer_ptr(enc);
    size = cte_encoder_get_buffer_size(enc);
    r_ptr = (const uint8_t *)r_ptr_offset;
    print_hex("Round Trip Encoded", r_ptr, size);

    dec = cte_decoder_new();
    TEST_ASSERT_NOT_NULL(dec, "Decoder creation", test_name);
    res = cte_decoder_set_input_buffer(dec, r_ptr, size);
    TEST_ASSERT_EQUAL_INT(res, CTE_SUCCESS, "Set Input Buffer", test_name);

    res = cte_decoder_advance(dec);
    TEST_ASSERT_EQUAL_INT(res, CTE_FIELD_TYPE_PUBKEY_LIST, "Decode[0]: Type PK", test_name);
    TEST_ASSERT_EQUAL_INT(cte_decoder_get_list_count(dec), pk_n, "Decode[0]: Count", test_name);
    TEST_ASSERT_EQUAL_INT(cte_decoder_get_pklist_type_code(dec), pk_tc, "Decode[0]: TypeCode", test_name);
    uintptr_t d_ptr_offset = cte_decoder_get_data_ptr(dec);
    TEST_ASSERT_EQUAL_MEM(d_ptr_offset, test_pk1, pk_s, "Decode[0]: Data", test_name);

    res = cte_decoder_advance(dec);
    TEST_ASSERT_EQUAL_INT(res, CTE_FIELD_TYPE_SIGNATURE_LIST, "Decode[1]: Type Sig", test_name);
    TEST_ASSERT_EQUAL_INT(cte_decoder_get_list_count(dec), sig_n, "Decode[1]: Count", test_name);
    TEST_ASSERT_EQUAL_INT(cte_decoder_get_siglist_type_code(dec), sig_tc, "Decode[1]: TypeCode", test_name);
    d_ptr_offset = cte_decoder_get_data_ptr(dec);
    TEST_ASSERT_EQUAL_MEM(d_ptr_offset, test_hash1, sig_s, "Decode[1]: Data 1", test_name);
    TEST_ASSERT_EQUAL_MEM(d_ptr_offset + sig_s, test_hash2, sig_s, "Decode[1]: Data 2", test_name);

    res = cte_decoder_advance(dec);
    TEST_ASSERT_EQUAL_INT(res, CTE_FIELD_TYPE_IXDATA, "Decode[2]: Type IxD", test_name);
    TEST_ASSERT_EQUAL_INT(cte_decoder_get_ixdata_subtype(dec), IXDATA_SUBTYPE_LEGACY_INDEX, "Decode[2]: SubType LegIdx",
                          test_name);
    TEST_ASSERT_EQUAL_INT(cte_decoder_get_ixdata_legacy_index(dec), leg_idx_val, "Decode[2]: Value", test_name);

    res = cte_decoder_advance(dec);
    TEST_ASSERT_EQUAL_INT(res, CTE_FIELD_TYPE_IXDATA, "Decode[3]: Type IxD", test_name);
    TEST_ASSERT_EQUAL_INT(cte_decoder_get_ixdata_subtype(dec), IXDATA_SUBTYPE_VARINT, "Decode[3]: SubType VarInt",
                          test_name);
    TEST_ASSERT_EQUAL_INT(cte_decoder_get_ixdata_varint_scheme(dec), IXDATA_VARINT_SCHEME_ULEB128,
                          "Decode[3]: Scheme ULEB", test_name);
    uint64_t uval;
    cte_decoder_get_ixdata_varint_value_u64(dec, &uval);
    TEST_ASSERT_EQUAL_UINT(uval, uleb_val, "Decode[3]: Value", test_name);

    res = cte_decoder_advance(dec);
    TEST_ASSERT_EQUAL_INT(res, CTE_FIELD_TYPE_IXDATA, "Decode[4]: Type IxD", test_name);
    TEST_ASSERT_EQUAL_INT(cte_decoder_get_ixdata_subtype(dec), IXDATA_SUBTYPE_VARINT, "Decode[4]: SubType VarInt",
                          test_name);
    TEST_ASSERT_EQUAL_INT(cte_decoder_get_ixdata_varint_scheme(dec), IXDATA_VARINT_SCHEME_SLEB128,
                          "Decode[4]: Scheme SLEB", test_name);
    int64_t sval;
    cte_decoder_get_ixdata_varint_value_i64(dec, &sval);
    TEST_ASSERT_EQUAL_INT(sval, sleb_val, "Decode[4]: Value", test_name);

    res = cte_decoder_advance(dec);
    TEST_ASSERT_EQUAL_INT(res, CTE_FIELD_TYPE_IXDATA, "Decode[5]: Type IxD", test_name);
    TEST_ASSERT_EQUAL_INT(cte_decoder_get_ixdata_subtype(dec), IXDATA_SUBTYPE_FIXED, "Decode[5]: SubType Fixed",
                          test_name);
    TEST_ASSERT_EQUAL_INT(cte_decoder_get_ixdata_fixed_type_code(dec), IXDATA_FIXED_TYPE_UINT32,
                          "Decode[5]: TypeCode U32", test_name);
    uint32_t u32v;
    cte_decoder_get_ixdata_fixed_value_uint32(dec, &u32v);
    TEST_ASSERT_EQUAL_UINT(u32v, fixed_u32, "Decode[5]: Value", test_name);

    res = cte_decoder_advance(dec);
    TEST_ASSERT_EQUAL_INT(res, CTE_FIELD_TYPE_IXDATA, "Decode[6]: Type IxD", test_name);
    TEST_ASSERT_EQUAL_INT(cte_decoder_get_ixdata_subtype(dec), IXDATA_SUBTYPE_CONSTANT, "Decode[6]: SubType Const",
                          test_name);
    TEST_ASSERT_EQUAL_INT(cte_decoder_get_ixdata_constant_code(dec), IXDATA_CONSTANT_CODE_TRUE,
                          "Decode[6]: ConstCode True", test_name);
    uint8_t bval;
    cte_decoder_get_ixdata_boolean_value(dec, &bval);
    TEST_ASSERT_EQUAL_UINT(bval, bool_val, "Decode[6]: Value", test_name);

    res = cte_decoder_advance(dec);
    TEST_ASSERT_EQUAL_INT(res, CTE_FIELD_TYPE_COMMAND_DATA, "Decode[7]: Type Cmd", test_name);
    TEST_ASSERT_EQUAL_UINT(cte_decoder_get_command_len(dec), cmd_len, "Decode[7]: Length", test_name);
    d_ptr_offset = cte_decoder_get_data_ptr(dec);
    TEST_ASSERT_EQUAL_MEM(d_ptr_offset, test_cmd_short, cmd_len, "Decode[7]: Data", test_name);

    res = cte_decoder_advance(dec);
    TEST_ASSERT_EQUAL_INT(res, CTE_ERROR_END_OF_BUFFER, "Final Advance EOB", test_name);
}

void test_errors()
{
    const char *test_name = "Errors";
    printf("--- Test: %s ---\n", test_name);
    void *enc, *dec;
    int res;

    uint8_t buf_v1[] = {CTE_VERSION_V1};
    dec = cte_decoder_new();
    cte_decoder_set_input_buffer(dec, buf_v1, sizeof(buf_v1));
    res = cte_decoder_advance(dec);
    TEST_ASSERT_EQUAL_INT(res, CTE_ERROR_END_OF_BUFFER, "Decode: Truncated (no header)", test_name);

    uint8_t buf_pk_trunc[] = {CTE_VERSION_V1, TAG_PUBLIC_KEY_LIST | (1 << 2) | CTE_CRYPTO_TYPE_ED25519};
    dec = cte_decoder_new();
    cte_decoder_set_input_buffer(dec, buf_pk_trunc, sizeof(buf_pk_trunc));
    res = cte_decoder_advance(dec);
    TEST_ASSERT_EQUAL_INT(res, CTE_ERROR_INSUFFICIENT_DATA, "Decode: Truncated PK Payload", test_name);

    uint8_t buf_cmd_trunc[] = {CTE_VERSION_V1, TAG_COMMAND_DATA | (1 << 5) | (1 << 2), 0x90};
    dec = cte_decoder_new();
    cte_decoder_set_input_buffer(dec, buf_cmd_trunc, sizeof(buf_cmd_trunc));
    res = cte_decoder_advance(dec);
    TEST_ASSERT_EQUAL_INT(res, CTE_ERROR_INSUFFICIENT_DATA, "Decode: Truncated Cmd Payload", test_name);

    uint8_t buf_inv_tag[] = {CTE_VERSION_V1, 0x20};
    dec = cte_decoder_new();
    cte_decoder_set_input_buffer(dec, buf_inv_tag, sizeof(buf_inv_tag));
    res = cte_decoder_advance(dec);

    TEST_ASSERT_EQUAL_INT(res, CTE_ERROR_INSUFFICIENT_DATA, "Decode: Invalid Tag (leads to insufficient data)",
                          test_name);

    uint8_t buf_inv_pk_cnt[] = {CTE_VERSION_V1, TAG_PUBLIC_KEY_LIST | (0 << 2) | CTE_CRYPTO_TYPE_ED25519};
    dec = cte_decoder_new();
    cte_decoder_set_input_buffer(dec, buf_inv_pk_cnt, sizeof(buf_inv_pk_cnt));
    res = cte_decoder_advance(dec);
    TEST_ASSERT_EQUAL_INT(res, CTE_ERROR_INVALID_FORMAT, "Decode: Invalid PK Count (0)", test_name);

    uint8_t buf_valid_idx_15[] = {CTE_VERSION_V1, 0xBC};
    dec = cte_decoder_new();
    cte_decoder_set_input_buffer(dec, buf_valid_idx_15, sizeof(buf_valid_idx_15));
    res = cte_decoder_advance(dec);

    TEST_ASSERT_EQUAL_INT(res, CTE_FIELD_TYPE_IXDATA, "Decode: Valid Legacy Index (15)", test_name);

    if (res == CTE_FIELD_TYPE_IXDATA)
    {
        TEST_ASSERT_EQUAL_INT(cte_decoder_get_ixdata_legacy_index(dec), 15, "Decode: Value Legacy Index (15)",
                              test_name);
    }

    dec = cte_decoder_new();
    res = cte_decoder_advance(dec);
    TEST_ASSERT_EQUAL_INT(res, CTE_ERROR_INVALID_STATE, "Decode: Advance before SetInput", test_name);

    dec = cte_decoder_new();
    cte_decoder_set_input_buffer(dec, buf_v1, sizeof(buf_v1));
    TEST_ASSERT_EQUAL_INT(cte_decoder_get_list_count(dec), -1, "Decode: Get Count before Advance", test_name);
}

int run_fuzzer(int iterations)
{
    const char *test_name = "Fuzzer";
    printf("\n--- Test: %s (%d iterations) ---\n", test_name, iterations);
    srand((unsigned int)time(NULL));
    int fuzz_failures = 0;

    for (int i = 0; i < iterations; ++i)
    {
        if (i > 0 && i % 20000 == 0)
            printf("  Fuzz iteration %d...\n", i);

        void *enc = cte_encoder_new();
        if (!enc)
        {
            fprintf(stderr, "[Fuzz %d] FAIL: cte_encoder_new failed\n", i);
            fuzz_failures++;
            continue;
        }

        int fields_added = 0;
        int max_fields = 20;
        bool stop_adding = false;

        while (fields_added < max_fields && !stop_adding)
        {
            size_t current_size = cte_encoder_get_buffer_size(enc);
            int field_choice = rand() % 7;

            size_t needed = 1;
            if (field_choice == 0)
                needed = 1 + MAX_LIST_LEN * PQC_PUBKEY_SLH256F_SIZE;
            else if (field_choice == 1)
                needed = 1 + MAX_LIST_LEN * ED25519_SIGNATURE_SIZE;
            else if (field_choice == 2)
                needed = 1;
            else if (field_choice == 3)
                needed = 1 + MAX_LEB128_BYTES;
            else if (field_choice == 4)
                needed = 1 + 8;
            else if (field_choice == 5)
                needed = 1;
            else if (field_choice == 6)
                needed = 2 + COMMAND_DATA_EXTENDED_MAX_LEN;

            if (current_size + needed > MAX_CTE_SIZE + 50)
            {
                stop_adding = true;
                continue;
            }

            int enc_res = CTE_SUCCESS;
            uintptr_t write_loc = 0;
            uint8_t *write_ptr = NULL;

            switch (field_choice)
            {
            case 0:
            {
                uint8_t ct = (rand() % 4);
                uint8_t cn = (rand() % MAX_LIST_LEN) + 1;
                size_t ks = _get_pk_size_from_type(ct);
                if (ks == 0)
                    continue;
                write_loc = cte_encoder_prepare_public_key_list(enc, cn, ct);
                if (write_loc)
                {
                    generate_random_bytes((uint8_t *)write_loc, cn * ks);
                    fields_added++;
                }
                else
                {
                    enc_res = CTE_ERROR_BUFFER_OVERFLOW;
                }
                break;
            }
            case 1:
            {
                uint8_t ct = (rand() % 4);
                uint8_t cn = (rand() % MAX_LIST_LEN) + 1;
                size_t ss = _get_sig_item_size_from_type(ct);
                if (ss == 0)
                    continue;
                write_loc = cte_encoder_prepare_signature_list(enc, cn, ct);
                if (write_loc)
                {
                    generate_random_bytes((uint8_t *)write_loc, cn * ss);
                    fields_added++;
                }
                else
                {
                    enc_res = CTE_ERROR_BUFFER_OVERFLOW;
                }
                break;
            }
            case 2:
            {
                enc_res = cte_encoder_write_index_reference(enc, rand() % (IXDATA_LEGACY_INDEX_MAX + 5));
                if (enc_res == CTE_SUCCESS)
                    fields_added++;
                break;
            }
            case 3:
            {
                int v_choice = rand() % 3;
                if (v_choice == 0)
                    enc_res = cte_encoder_write_ixdata_zero(enc);
                else if (v_choice == 1)
                    enc_res = cte_encoder_write_ixdata_uleb128(enc, ((uint64_t)rand() << 32) | rand());
                else
                    enc_res = cte_encoder_write_ixdata_sleb128(enc, ((int64_t)rand() << 32) | rand());
                if (enc_res == CTE_SUCCESS)
                    fields_added++;
                break;
            }
            case 4:
            {
                int t_choice = rand() % 10;

                if (t_choice == 0)
                    enc_res = cte_encoder_write_ixdata_fixed_int8(enc, 0);
                else if (t_choice == 1)
                    enc_res = cte_encoder_write_ixdata_fixed_int16(enc, 0);

                else if (t_choice == 7)
                    enc_res = cte_encoder_write_ixdata_fixed_uint64(enc, 0);
                else if (t_choice == 9)
                    enc_res = cte_encoder_write_ixdata_fixed_float64(enc, 0.0);
                else
                    enc_res = cte_encoder_write_ixdata_fixed_uint8(enc, 0);
                if (enc_res == CTE_SUCCESS)
                    fields_added++;
                break;
            }
            case 5:
            {
                enc_res = cte_encoder_write_ixdata_boolean(enc, rand() % 2);
                if (enc_res == CTE_SUCCESS)
                    fields_added++;
                break;
            }
            case 6:
            {
                size_t cl = rand() % (MAX_CTE_SIZE / 2);
                write_loc = cte_encoder_prepare_command_data(enc, cl);
                if (write_loc)
                {
                    generate_random_bytes((uint8_t *)write_loc, cl);
                    fields_added++;
                }
                else
                {
                    enc_res = CTE_ERROR_BUFFER_OVERFLOW;
                }
                break;
            }
            }

            if (enc_res == CTE_ERROR_BUFFER_OVERFLOW)
            {
                stop_adding = true;
            }
            else if (enc_res != CTE_SUCCESS && enc_res != CTE_ERROR_INVALID_ARGUMENT)
            {

                fprintf(stderr, "[Fuzz %d] WARNING: Encoder returned %d for choice %d\n", i, enc_res, field_choice);
            }
        }

        uintptr_t encoded_ptr_offset = cte_encoder_get_buffer_ptr(enc);
        size_t encoded_size = cte_encoder_get_buffer_size(enc);
        uint8_t *encoded_ptr = (uint8_t *)encoded_ptr_offset;

        if (!encoded_ptr || encoded_size == 0 || encoded_size > MAX_CTE_SIZE || encoded_ptr[0] != CTE_VERSION_V1)
        {

            continue;
        }

        void *dec = cte_decoder_new();
        if (!dec)
        {
            fprintf(stderr, "[Fuzz %d] FAIL: cte_decoder_new failed\n", i);
            fuzz_failures++;
            continue;
        }
        int decode_res = cte_decoder_set_input_buffer(dec, encoded_ptr, encoded_size);
        if (decode_res != CTE_SUCCESS)
        {
            fprintf(stderr, "[Fuzz %d] FAIL: cte_decoder_set_input_buffer failed (%d) for size %zu\n", i, decode_res,
                    encoded_size);
            print_hex("Fuzz Buffer", encoded_ptr, encoded_size);
            fuzz_failures++;
            continue;
        }

        int decoded_fields = 0;
        int final_decode_res = CTE_SUCCESS;
        while (true)
        {
            decode_res = cte_decoder_advance(dec);
            if (decode_res < 0)
            {
                final_decode_res = decode_res;
                break;
            }
            if (decode_res == CTE_FIELD_TYPE_UNKNOWN || decode_res > CTE_FIELD_TYPE_COMMAND_DATA)
            {
                fprintf(stderr, "[Fuzz %d] FAIL: Decoder advanced with invalid type %d after %d fields\n", i,
                        decode_res, decoded_fields);
                print_hex("Fuzz Buffer", encoded_ptr, encoded_size);
                fuzz_failures++;
                final_decode_res = CTE_ERROR_INVALID_FORMAT;
                break;
            }
            decoded_fields++;
            if (decoded_fields > max_fields * 2)
            {
                fprintf(stderr, "[Fuzz %d] FAIL: Potential infinite loop decoding (> %d fields)\n", i, max_fields * 2);
                print_hex("Fuzz Buffer", encoded_ptr, encoded_size);
                fuzz_failures++;
                final_decode_res = CTE_ERROR_INVALID_STATE;
                break;
            }
        }

        if (final_decode_res != CTE_ERROR_END_OF_BUFFER)
        {
            fprintf(stderr, "[Fuzz %d] FAIL: Decoder finished with %d (expected EOB %d) after %d fields.\n", i,
                    final_decode_res, CTE_ERROR_END_OF_BUFFER, decoded_fields);
            print_hex("Fuzz Buffer", encoded_ptr, encoded_size);
            fuzz_failures++;
        }

        if (fuzz_failures > 0)
        {
            printf("Fuzzing stopped early due to failure at iteration %d.\n", i);
            return 1;
        }
    }

    printf("Fuzzer finished %d iterations.\n", iterations);
    return fuzz_failures > 0 ? 1 : 0;
}

int main()
{
    printf("Starting CTE Tests...\n");
    setup_test_data();
    g_total_errors = 0;

    test_pk_list();
    test_sig_list();
    test_ixdata();
    test_command_data();
    test_round_trip();
    test_errors();

    if (g_total_errors == 0)
    {
        printf("\n--- All Deterministic Tests PASSED ---\n");

        int fuzz_res = run_fuzzer(100000);
        if (fuzz_res == 0)
        {
            printf("\n--- Fuzzer PASSED ---\n");
            printf("\nOverall Result: ALL TESTS PASSED\n");
            return 0;
        }
        else
        {
            printf("\n--- Fuzzer FAILED ---\n");
            printf("\nOverall Result: FUZZER FAILED\n");
            return 1;
        }
    }
    else
    {
        printf("\n--- Deterministic Tests FAILED (%d errors) ---\n", g_total_errors);
        printf("\nOverall Result: TESTS FAILED\n");
        return 1;
    }
}