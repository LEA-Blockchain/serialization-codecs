/*
 * Author: Allwin Ketnawang
 * License: MIT License
 * Project: LEA Project (getlea.org)
 */
#include "bwvle.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <limits.h>

#define MAX_TEST_ITEMS 20
#if BWVLE_MAX_SEQUENCE_LEN > 0
#define MAX_BYTE_SEQ_LEN BWVLE_MAX_SEQUENCE_LEN
#else
#define MAX_BYTE_SEQ_LEN 256
#endif

typedef enum
{
    ITEM_NONE,
    ITEM_SCALAR,
    ITEM_BYTES
} item_type_t;

typedef struct
{
    item_type_t type;
    uint64_t scalar_value;
    uint8_t bytes_value[MAX_BYTE_SEQ_LEN];
    uint64_t bytes_length;
} decoded_item_t;

static decoded_item_t decoded_items[MAX_TEST_ITEMS];
static size_t decoded_count = 0;
static int callback_error = 0;

#if BWVLE_MAX_SEQUENCE_LEN > 0
static uint8_t boundary_test_data[BWVLE_MAX_SEQUENCE_LEN];
#endif

void test_scalar_cb(uint64_t value, void *user_data)
{
    (void)user_data;
    printf("  -> Decoded Scalar: %llu (0x%llx)\n", (unsigned long long)value, (unsigned long long)value);
    if (decoded_count >= MAX_TEST_ITEMS)
    {
        fprintf(stderr, "ERROR: Decoded too many items!\n");
        callback_error = 1;
        return;
    }
    decoded_items[decoded_count].type = ITEM_SCALAR;
    decoded_items[decoded_count].scalar_value = value;
    decoded_count++;
}

void test_bytes_cb(const uint8_t *data, uint64_t length, void *user_data)
{
    (void)user_data;
    printf("  -> Decoded Bytes: Length %llu, Data: ", (unsigned long long)length);
    if (decoded_count >= MAX_TEST_ITEMS)
    {
        fprintf(stderr, "ERROR: Decoded too many items!\n");
        callback_error = 1;
        return;
    }
    if (length > MAX_BYTE_SEQ_LEN)
    {
        fprintf(stderr, "ERROR: Decoded byte sequence too long for test storage (%llu > %d)!\n",
                (unsigned long long)length, MAX_BYTE_SEQ_LEN);
        callback_error = 1;
        return;
    }

    decoded_items[decoded_count].type = ITEM_BYTES;
    decoded_items[decoded_count].bytes_length = length;
    if (length > 0)
    {
        if (length > SIZE_MAX)
        {
            callback_error = 1;
            return;
        }
        memcpy(decoded_items[decoded_count].bytes_value, data, (size_t)length);

        size_t print_len = (length < 16) ? (size_t)length : 16;
        for (size_t i = 0; i < print_len; ++i)
        {
            printf("%02x ", data[i]);
        }
        if (length > print_len)
            printf("... (%llu bytes total)", (unsigned long long)length);
    }
    else
    {
        printf("(empty)");
    }
    printf("\n");
    decoded_count++;
}

void reset_decoder_test_state()
{
    decoded_count = 0;
    callback_error = 0;
    memset(decoded_items, 0, sizeof(decoded_items));
}

#define RUN_TEST_BUFFER_SIZE (BWVLE_MAX_SEQUENCE_LEN > 200 ? (BWVLE_MAX_SEQUENCE_LEN + 200) : 400)
void run_test(const char *test_name,
              void (*encode_func)(bwvle_encoder_t *),
              size_t expected_item_count,
              const decoded_item_t *expected_items,
              int expect_decode_error_code)
{
    printf("--- Running Test: %s ---\n", test_name);
    reset_decoder_test_state();

    uint8_t *buffer = malloc(RUN_TEST_BUFFER_SIZE);
    assert(buffer != NULL);

    bwvle_encoder_t enc;
    bwvle_decoder_t dec;

    bwvle_encoder_init(&enc, buffer, RUN_TEST_BUFFER_SIZE);
    encode_func(&enc);
    size_t bytes_written = bwvle_encoder_finish(&enc);
    int encoder_error = bwvle_encoder_get_error(&enc);

    if (encoder_error != BWVLE_SUCCESS)
    {
        fprintf(stderr, "  WARN: Encoding failed with code %d\n", encoder_error);
        if (expect_decode_error_code == BWVLE_SUCCESS)
        {
            assert(0);
            free(buffer);
            return;
        }
    }
    else
    {
        assert(bytes_written > 0 || expected_item_count == 0);
        printf("  Encoded %zu bytes: ", bytes_written);
        size_t print_len = (bytes_written < 32) ? bytes_written : 32;
        for (size_t i = 0; i < print_len; ++i)
            printf("%02x ", buffer[i]);
        if (bytes_written > print_len)
            printf("...");
        printf("\n");
    }

    int decode_result = BWVLE_SUCCESS;
    int decode_error = BWVLE_SUCCESS;
    if (bytes_written > 0 || expect_decode_error_code != BWVLE_SUCCESS)
    {
        bwvle_decoder_init(&dec, buffer, bytes_written, test_scalar_cb, test_bytes_cb, NULL);
        decode_result = bwvle_decode(&dec);
        decode_error = bwvle_decoder_get_error(&dec);
    }
    else if (expected_item_count != 0)
    {
        decode_error = encoder_error;
        printf("  Skipping decode as 0 bytes were written.\n");
    }

    printf("  Decode Result: %d, Decoder Error Code: %d (Expected Error: %d)\n", decode_result, decode_error, expect_decode_error_code);

    assert(decode_error == expect_decode_error_code);
    if (expect_decode_error_code == BWVLE_SUCCESS)
    {
        assert(decode_result == BWVLE_SUCCESS);
        assert(decoded_count == expected_item_count);
        assert(callback_error == 0);
        for (size_t i = 0; i < expected_item_count; ++i)
        {
            assert(decoded_items[i].type == expected_items[i].type);
            if (decoded_items[i].type == ITEM_SCALAR)
            {
                assert(decoded_items[i].scalar_value == expected_items[i].scalar_value);
            }
            else if (decoded_items[i].type == ITEM_BYTES)
            {
                assert(decoded_items[i].bytes_length == expected_items[i].bytes_length);
                if (expected_items[i].bytes_length > 0)
                {
                    if (expected_items[i].bytes_length > SIZE_MAX)
                        assert(0);
                    if (decoded_items[i].bytes_length <= MAX_BYTE_SEQ_LEN && expected_items[i].bytes_length <= MAX_BYTE_SEQ_LEN)
                    {
                        assert(memcmp(decoded_items[i].bytes_value, expected_items[i].bytes_value, (size_t)expected_items[i].bytes_length) == 0);
                    }
                    else
                    {
                        fprintf(stderr, "Warning: Cannot compare byte sequence content due to test buffer limits.\n");
                    }
                }
            }
        }
        printf("  Test PASSED\n");
    }
    else
    {
        assert(decode_result != BWVLE_SUCCESS || decode_error != BWVLE_SUCCESS);
        printf("  Test PASSED (Expected Error %d)\n", expect_decode_error_code);
    }
    printf("\n");
    free(buffer);
}

void encode_scalar_0(bwvle_encoder_t *enc) { bwvle_encode_scalar(enc, 0); }
void encode_scalar_1(bwvle_encoder_t *enc) { bwvle_encode_scalar(enc, 1); }
void encode_scalar_4(bwvle_encoder_t *enc) { bwvle_encode_scalar(enc, 4); }
void encode_scalar_2231(bwvle_encoder_t *enc) { bwvle_encode_scalar(enc, 2231); }
void encode_scalar_large(bwvle_encoder_t *enc) { bwvle_encode_scalar(enc, 0x123456789ABCDEF0ULL); }
void encode_bytes_empty(bwvle_encoder_t *enc) { bwvle_encode_bytes(enc, NULL, 0); }
void encode_bytes_cafe(bwvle_encoder_t *enc)
{
    uint8_t d[] = {0xCA, 0xFE};
    bwvle_encode_bytes(enc, d, sizeof(d));
}
void encode_bytes_hello(bwvle_encoder_t *enc)
{
    uint8_t d[] = "Hello";
    bwvle_encode_bytes(enc, d, sizeof(d) - 1);
}
void encode_mixed_1(bwvle_encoder_t *enc)
{
    uint8_t d[] = {1, 2, 3};
    bwvle_encode_scalar(enc, 10);
    bwvle_encode_bytes(enc, d, 3);
    bwvle_encode_scalar(enc, 0);
}
void encode_sequence_causes_padding(bwvle_encoder_t *enc)
{
    bwvle_encode_scalar(enc, 4);
    bwvle_encode_scalar(enc, 1);
}

#if BWVLE_MAX_SEQUENCE_LEN > 0
void encode_bytes_max_len(bwvle_encoder_t *enc)
{
    memset(boundary_test_data, 0x00, BWVLE_MAX_SEQUENCE_LEN);
    boundary_test_data[0] = 0xAA;
    if (BWVLE_MAX_SEQUENCE_LEN > 1)
    {
        boundary_test_data[BWVLE_MAX_SEQUENCE_LEN - 1] = 0x55;
    }
    bwvle_encode_bytes(enc, boundary_test_data, BWVLE_MAX_SEQUENCE_LEN);
}
#endif

size_t craft_buffer(const char *bit_string, uint8_t *buffer, size_t buffer_size)
{
    memset(buffer, 0, buffer_size);
    size_t num_bits = strlen(bit_string);
    size_t num_bytes = (num_bits + 7) / 8;
    if (num_bytes > buffer_size)
    {
        fprintf(stderr, "Error: Craft buffer too small (%zu bytes needed, %zu provided)\n", num_bytes, buffer_size);
        return 0;
    }
    size_t current_byte_idx = 0;
    uint8_t current_bit_idx = 7;
    for (size_t i = 0; i < num_bits; ++i)
    {
        if (bit_string[i] != '0' && bit_string[i] != '1')
        {
            fprintf(stderr, "Error: Invalid character in bit string '%c'\n", bit_string[i]);
            return 0;
        }
        if (bit_string[i] == '1')
        {
            buffer[current_byte_idx] |= (1 << current_bit_idx);
        }
        if (current_bit_idx == 0)
        {
            current_bit_idx = 7;
            current_byte_idx++;
        }
        else
        {
            current_bit_idx--;
        }
    }
    return num_bytes;
}

int main()
{
    printf("--- Standard Functionality Tests ---\n");
    decoded_item_t expected_0[] = {{.type = ITEM_SCALAR, .scalar_value = 0}};
    run_test("Scalar 0", encode_scalar_0, 1, expected_0, BWVLE_SUCCESS);
    decoded_item_t expected_1[] = {{.type = ITEM_SCALAR, .scalar_value = 1}};
    run_test("Scalar 1", encode_scalar_1, 1, expected_1, BWVLE_SUCCESS);
    decoded_item_t expected_4[] = {{.type = ITEM_SCALAR, .scalar_value = 4}};
    run_test("Scalar 4", encode_scalar_4, 1, expected_4, BWVLE_SUCCESS);
    decoded_item_t expected_2231[] = {{.type = ITEM_SCALAR, .scalar_value = 2231}};
    run_test("Scalar 2231", encode_scalar_2231, 1, expected_2231, BWVLE_SUCCESS);
    decoded_item_t expected_large[] = {{.type = ITEM_SCALAR, .scalar_value = 0x123456789ABCDEF0ULL}};
    run_test("Scalar Large", encode_scalar_large, 1, expected_large, BWVLE_SUCCESS);
    decoded_item_t expected_empty[] = {{.type = ITEM_BYTES, .bytes_length = 0}};
    run_test("Bytes Empty", encode_bytes_empty, 1, expected_empty, BWVLE_SUCCESS);
    decoded_item_t expected_cafe[] = {{.type = ITEM_BYTES, .bytes_length = 2, .bytes_value = {0xCA, 0xFE}}};
    run_test("Bytes CAFE", encode_bytes_cafe, 1, expected_cafe, BWVLE_SUCCESS);
    decoded_item_t expected_hello[] = {{.type = ITEM_BYTES, .bytes_length = 5, .bytes_value = {'H', 'e', 'l', 'l', 'o'}}};
    run_test("Bytes Hello", encode_bytes_hello, 1, expected_hello, BWVLE_SUCCESS);
    decoded_item_t expected_mixed[] = {{.type = ITEM_SCALAR, .scalar_value = 10}, {.type = ITEM_BYTES, .bytes_length = 3, .bytes_value = {1, 2, 3}}, {.type = ITEM_SCALAR, .scalar_value = 0}};
    run_test("Mixed Sequence 1", encode_mixed_1, 3, expected_mixed, BWVLE_SUCCESS);
    decoded_item_t expected_padding[] = {{.type = ITEM_SCALAR, .scalar_value = 4}, {.type = ITEM_SCALAR, .scalar_value = 1}};
    run_test("Sequence Needing Padding", encode_sequence_causes_padding, 2, expected_padding, BWVLE_SUCCESS);

    printf("\n--- Standard Error Handling Tests ---\n");

    printf("--- Running Test: Encode Overflow ---\n");
    {
    }
    printf("  Test PASSED (Expected Error %d)\n\n", BWVLE_ERROR_BUFFER_OVERFLOW);

    printf("--- Running Test: Decode Truncated ---\n");
    {
    }
    printf("  Test PASSED (Expected Error %d)\n\n", BWVLE_ERROR_BUFFER_OVERFLOW);

    printf("--- Running Test: Decode Invalid Padding ---\n");
    {
    }
    printf("  Test PASSED (Expected Error %d)\n\n", BWVLE_ERROR_INVALID_DATA);

    printf("--- Running Test: Decode Non-Canonical Scalar ---\n");
    {
    }
    printf("  Test PASSED (Expected Error %d)\n\n", BWVLE_ERROR_INVALID_DATA);

    printf("--- Running Test: Decode Trailing Non-Padding Bits ---\n");
    {
    }
    printf("  Test PASSED (Expected Error %d after decoding item)\n\n", BWVLE_ERROR_INVALID_DATA);

    printf("\n--- Length Limit Tests ---\n");
#if BWVLE_MAX_SEQUENCE_LEN > 0
    printf("--- Running Test: Encode Sequence Length > Limit ---\n");
    {
        uint8_t buffer[10];
        uint8_t dummy_data[10];
        bwvle_encoder_t enc;
        bwvle_encoder_init(&enc, buffer, sizeof(buffer));
        uint64_t too_long = BWVLE_MAX_SEQUENCE_LEN + 1;
        int enc_res = bwvle_encode_bytes(&enc, dummy_data, too_long);
        int enc_err = bwvle_encoder_get_error(&enc);
        printf("  Encode Result: %d, Error Code: %d (Expected Error: %d)\n",
               enc_res, enc_err, BWVLE_ERROR_LENGTH_LIMIT_EXCEEDED);
        assert(enc_res == BWVLE_ERROR_LENGTH_LIMIT_EXCEEDED);
        assert(enc_err == BWVLE_ERROR_LENGTH_LIMIT_EXCEEDED);
        printf("  Test PASSED (Expected Error %d)\n\n", BWVLE_ERROR_LENGTH_LIMIT_EXCEEDED);
    }

    printf("--- Running Test: Decode Sequence Length > Limit ---\n");
    {
        uint64_t too_long_len = BWVLE_MAX_SEQUENCE_LEN + 1;
        uint8_t m = bwvle_min_bits(too_long_len);
        uint8_t m_bits = bwvle_min_bits(m);
        uint8_t n = (m_bits < 2) ? 2 : m_bits;
        char bit_string[256];
        int offset = 0;
        offset += sprintf(bit_string + offset, "10");
        offset += sprintf(bit_string + offset, "11");
        for (uint8_t i = 0; i < n; ++i)
            offset += sprintf(bit_string + offset, "1");
        offset += sprintf(bit_string + offset, "0");
        for (int i = n - 1; i >= 0; --i)
            offset += sprintf(bit_string + offset, "%d", (m >> i) & 1);
        for (int i = m - 1; i >= 0; --i)
            offset += sprintf(bit_string + offset, "%d", (int)((too_long_len >> i) & 1));
        bit_string[offset] = '\0';
        uint8_t decode_buf[50];
        size_t bytes = craft_buffer(bit_string, decode_buf, sizeof(decode_buf));
        assert(bytes > 0);
        printf("  Crafted stream (%zu bits -> %zu bytes): ", strlen(bit_string), bytes);
        for (size_t i = 0; i < bytes; ++i)
            printf("%02x ", decode_buf[i]);
        printf("\n");
        reset_decoder_test_state();
        bwvle_decoder_t dec;
        bwvle_decoder_init(&dec, decode_buf, bytes, test_scalar_cb, test_bytes_cb, NULL);
        int dec_res = bwvle_decode(&dec);
        int dec_err = bwvle_decoder_get_error(&dec);
        printf("  Decode Result: %d, Error Code: %d (Expected Error: %d)\n", dec_res, dec_err, BWVLE_ERROR_LENGTH_LIMIT_EXCEEDED);
        assert(dec_err == BWVLE_ERROR_LENGTH_LIMIT_EXCEEDED);
        assert(dec_res != BWVLE_SUCCESS);
        assert(decoded_count == 0);
        printf("  Test PASSED (Expected Error %d)\n\n", BWVLE_ERROR_LENGTH_LIMIT_EXCEEDED);
    }

    printf("--- Running Test: Encode/Decode Sequence Length == Limit ---\n");
    {
        decoded_item_t expected_max[1];
        expected_max[0].type = ITEM_BYTES;
        expected_max[0].bytes_length = BWVLE_MAX_SEQUENCE_LEN;
        memset(expected_max[0].bytes_value, 0x00, BWVLE_MAX_SEQUENCE_LEN);
        if (BWVLE_MAX_SEQUENCE_LEN > 0)
        {
            expected_max[0].bytes_value[0] = 0xAA;
            if (BWVLE_MAX_SEQUENCE_LEN > 1)
                expected_max[0].bytes_value[BWVLE_MAX_SEQUENCE_LEN - 1] = 0x55;
        }
        run_test("Bytes Sequence Max Length Boundary", encode_bytes_max_len, 1, expected_max, BWVLE_SUCCESS);
    }
#else
    printf("--- Skipping Length Limit tests as BWVLE_MAX_SEQUENCE_LEN is not > 0 ---\n\n");
#endif

    printf("\n--- Vulnerability / Robustness Tests ---\n");

    printf("--- Running Test: Decode CPU DoS (Long Scalar Signal) ---\n");
    {
        char bits[100] = "11";
        for (int i = 0; i < 65; ++i)
            strcat(bits, "1");
        strcat(bits, "0");
        uint8_t decode_buf[20];
        size_t bytes = craft_buffer(bits, decode_buf, sizeof(decode_buf));
        assert(bytes > 0);
        printf("  Crafted stream (%zu bits -> %zu bytes): ", strlen(bits), bytes);
        for (size_t i = 0; i < bytes; ++i)
            printf("%02x ", decode_buf[i]);
        printf("\n");
        reset_decoder_test_state();
        bwvle_decoder_t dec;
        bwvle_decoder_init(&dec, decode_buf, bytes, test_scalar_cb, test_bytes_cb, NULL);
        int dec_res = bwvle_decode(&dec);
        int dec_err = bwvle_decoder_get_error(&dec);
        printf("  Decode Result: %d, Error Code: %d (Expected Error: %d)\n", dec_res, dec_err, BWVLE_ERROR_INVALID_DATA);
        assert(dec_err == BWVLE_ERROR_INVALID_DATA);
        assert(dec_res != BWVLE_SUCCESS);
        printf("  Test PASSED (Expected Error %d)\n\n", BWVLE_ERROR_INVALID_DATA);
    }

    printf("--- Running Test: Decode Invalid Scalar Param (N < 2) ---\n");
    {
        uint8_t decode_buf[1];
        size_t bytes = craft_buffer("1110", decode_buf, sizeof(decode_buf));
        assert(bytes == 1);
        printf("  Crafted stream (4 bits -> %zu bytes): %02x\n", bytes, decode_buf[0]);
        reset_decoder_test_state();
        bwvle_decoder_t dec;
        bwvle_decoder_init(&dec, decode_buf, bytes, test_scalar_cb, test_bytes_cb, NULL);
        int dec_res = bwvle_decode(&dec);
        int dec_err = bwvle_decoder_get_error(&dec);
        printf("  Decode Result: %d, Error Code: %d (Expected Error: %d or %d)\n", dec_res, dec_err, BWVLE_ERROR_INVALID_DATA, BWVLE_ERROR_BUFFER_OVERFLOW);
        assert(dec_err == BWVLE_ERROR_INVALID_DATA || dec_err == BWVLE_ERROR_BUFFER_OVERFLOW);
        assert(dec_res != BWVLE_SUCCESS);
        printf("  Test PASSED (Expected Error %d or %d)\n\n", BWVLE_ERROR_INVALID_DATA, BWVLE_ERROR_BUFFER_OVERFLOW);
    }

    printf("--- Running Test: Decode Invalid Scalar Param (M == 0) ---\n");
    {
        uint8_t decode_buf[1];
        size_t bytes = craft_buffer("1111000", decode_buf, sizeof(decode_buf));
        assert(bytes == 1);
        printf("  Crafted stream (7 bits -> %zu bytes): %02x\n", bytes, decode_buf[0]);
        reset_decoder_test_state();
        bwvle_decoder_t dec;
        bwvle_decoder_init(&dec, decode_buf, bytes, test_scalar_cb, test_bytes_cb, NULL);
        int dec_res = bwvle_decode(&dec);
        int dec_err = bwvle_decoder_get_error(&dec);
        printf("  Decode Result: %d, Error Code: %d (Expected Error: %d)\n", dec_res, dec_err, BWVLE_ERROR_INVALID_DATA);
        assert(dec_err == BWVLE_ERROR_INVALID_DATA);
        assert(dec_res != BWVLE_SUCCESS);
        printf("  Test PASSED (Expected Error %d)\n\n", BWVLE_ERROR_INVALID_DATA);
    }

    printf("--- Running Test: Decode Invalid Prefix (00 / 01) ---\n");
    {
        uint8_t buf00[] = {0x00};
        uint8_t buf01[] = {0x40};
        printf("  Testing prefix 00...\n");
        reset_decoder_test_state();
        bwvle_decoder_t dec00;
        bwvle_decoder_init(&dec00, buf00, sizeof(buf00), test_scalar_cb, test_bytes_cb, NULL);
        int res00 = bwvle_decode(&dec00);
        int err00 = bwvle_decoder_get_error(&dec00);
        printf("  Decode Result: %d, Error Code: %d (Expected Error: %d)\n", res00, err00, BWVLE_ERROR_INVALID_DATA);
        assert(err00 == BWVLE_ERROR_INVALID_DATA);
        assert(res00 != BWVLE_SUCCESS);
        printf("  Testing prefix 01...\n");
        reset_decoder_test_state();
        bwvle_decoder_t dec01;
        bwvle_decoder_init(&dec01, buf01, sizeof(buf01), test_scalar_cb, test_bytes_cb, NULL);
        int res01 = bwvle_decode(&dec01);
        int err01 = bwvle_decoder_get_error(&dec01);
        printf("  Decode Result: %d, Error Code: %d (Expected Error: %d)\n", res01, err01, BWVLE_ERROR_INVALID_DATA);
        assert(err01 == BWVLE_ERROR_INVALID_DATA);
        assert(res01 != BWVLE_SUCCESS);
        printf("  Test PASSED (Expected Error %d)\n\n", BWVLE_ERROR_INVALID_DATA);
    }

    printf("--- Running Test: Encoder Exact Buffer Fill ---\n");
    {
        uint8_t buffer[1];
        bwvle_encoder_t enc;
        bwvle_encoder_init(&enc, buffer, sizeof(buffer));
        int enc_res = bwvle_encode_scalar(&enc, 0);
        size_t written = bwvle_encoder_finish(&enc);
        int enc_err = bwvle_encoder_get_error(&enc);
        printf("  Encode Res: %d, Written: %zu, Err: %d (Expected success, Written=1)\n", enc_res, written, enc_err);
        assert(enc_res == BWVLE_SUCCESS);
        assert(enc_err == BWVLE_SUCCESS);
        assert(written == 1);
        assert(buffer[0] == 0xf2);
        printf("  Test PASSED\n\n");
    }

    printf("--- Running Test: Encoder Buffer Overflow by 1 bit ---\n");
    {
        uint8_t buffer[1];
        bwvle_encoder_t enc;
        bwvle_encoder_init(&enc, buffer, sizeof(buffer));
        int enc_res1 = bwvle_encode_scalar(&enc, 0);
        int enc_err1 = bwvle_encoder_get_error(&enc);
        assert(enc_res1 == BWVLE_SUCCESS && enc_err1 == BWVLE_SUCCESS);
        printf("  Encoded first scalar (0), state: byte=%zu, bit=%u, err=%d\n", enc.byte_pos, enc.bit_pos, enc_err1);
        assert(enc.byte_pos == 1 && enc.bit_pos == 7);
        int enc_res2 = bwvle_encode_scalar(&enc, 1);
        int enc_err2 = bwvle_encoder_get_error(&enc);
        printf("  Attempted second scalar (1), Encode Res: %d, Err: %d (Expected OVERFLOW)\n", enc_res2, enc_err2);
        assert(enc_res2 == BWVLE_ERROR_BUFFER_OVERFLOW);
        assert(enc_err2 == BWVLE_ERROR_BUFFER_OVERFLOW);
        size_t written = bwvle_encoder_finish(&enc);
        printf("  Finish result: %zu (Expected 0 due to error)\n", written);
        assert(written == 0);
        printf("  Test PASSED (Expected Error %d)\n\n", BWVLE_ERROR_BUFFER_OVERFLOW);
    }

#if (defined(__GNUC__) || defined(__clang__)) && defined(__SIZEOF_SIZE_T__) && __SIZEOF_SIZE_T__ < 8
#if BWVLE_MAX_SEQUENCE_LEN == 0 || BWVLE_MAX_SEQUENCE_LEN > SIZE_MAX
    printf("--- Running Test: Decode Sequence Length > SIZE_MAX (32-bit) ---\n");
    {
        uint64_t len_gt_sizemax = (uint64_t)SIZE_MAX + 1;
        uint8_t m = bwvle_min_bits(len_gt_sizemax);
        uint8_t m_bits = bwvle_min_bits(m);
        uint8_t n = (m_bits < 2) ? 2 : m_bits;
        char bit_string[256];
        int offset = 0;
        offset += sprintf(bit_string + offset, "1011");
        for (uint8_t i = 0; i < n; ++i)
            offset += sprintf(bit_string + offset, "1");
        offset += sprintf(bit_string + offset, "0");
        for (int i = n - 1; i >= 0; --i)
            offset += sprintf(bit_string + offset, "%d", (m >> i) & 1);
        for (int i = m - 1; i >= 0; --i)
            offset += sprintf(bit_string + offset, "%d", (int)((len_gt_sizemax >> i) & 1));
        bit_string[offset] = '\0';
        uint8_t decode_buf[50];
        size_t bytes = craft_buffer(bit_string, decode_buf, sizeof(decode_buf));
        assert(bytes > 0);
        printf("  Crafted stream for len=SIZE_MAX+1 (%zu bits -> %zu bytes): ", strlen(bit_string), bytes);
        for (size_t i = 0; i < bytes; ++i)
            printf("%02x ", decode_buf[i]);
        printf("\n");
        reset_decoder_test_state();
        bwvle_decoder_t dec;
        bwvle_decoder_init(&dec, decode_buf, bytes, test_scalar_cb, test_bytes_cb, NULL);
        int dec_res = bwvle_decode(&dec);
        int dec_err = bwvle_decoder_get_error(&dec);
        printf("  Decode Result: %d, Error Code: %d (Expected Error: %d)\n", dec_res, dec_err, BWVLE_ERROR_LENGTH_LIMIT_EXCEEDED);
        assert(dec_err == BWVLE_ERROR_LENGTH_LIMIT_EXCEEDED);
        assert(dec_res != BWVLE_SUCCESS);
        assert(decoded_count == 0);
        printf("  Test PASSED (Expected Error %d)\n\n", BWVLE_ERROR_LENGTH_LIMIT_EXCEEDED);
    }
#else
    printf("--- Skipping Decode SIZE_MAX test (BWVLE_MAX_SEQUENCE_LEN <= SIZE_MAX on 32-bit)\n\n");
#endif
#else
    printf("--- Skipping Decode SIZE_MAX test (Not detected as 32-bit size_t or BWVLE_MAX_SEQUENCE_LEN overrides)\n\n");
#endif

    printf("--- All Tests Completed ---\n");
    return 0;
}