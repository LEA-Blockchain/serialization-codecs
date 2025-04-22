/*
 * Author: Allwin Ketnawang
 * License: MIT License
 * Project: LEA Project (getlea.org)
 */
#ifndef BWVLE_H
#define BWVLE_H

#include <stddef.h>
#include <stdint.h>

/**
 * Define BWVLE_NO_BUILTIN_CLZ to disable GCC/Clang CLZ intrinsics.
 *
 * Sets max byte sequence length and callback buffer size.
 * Use a reasonable non-zero value to limit impact of malformed or malicious input.
 */
#define BWVLE_MAX_SEQUENCE_LEN 1232

#define BWVLE_SUCCESS 0
#define BWVLE_ERROR_BUFFER_OVERFLOW -1
#define BWVLE_ERROR_INVALID_DATA -2
#define BWVLE_ERROR_CALLBACK_FAILED -3
#define BWVLE_ERROR_ALLOCATION_FAILED -4
#define BWVLE_ERROR_LENGTH_LIMIT_EXCEEDED -5 // if sequence length > BWVLE_MAX_SEQUENCE_LEN

typedef struct
{
    uint8_t *buffer;
    size_t buffer_size;
    size_t byte_pos;
    uint8_t bit_pos;
    int error_code;
} bwvle_encoder_t;

typedef void (*bwvle_scalar_callback_t)(uint64_t value, void *user_data);
typedef void (*bwvle_bytes_callback_t)(const uint8_t *data, uint64_t length, void *user_data);

typedef struct
{
    const uint8_t *buffer;
    size_t buffer_size;
    size_t byte_pos;
    uint8_t bit_pos;
    int error_code;
    bwvle_scalar_callback_t scalar_cb;
    bwvle_bytes_callback_t bytes_cb;
    void *user_data;
    uint64_t total_bits_consumed;
} bwvle_decoder_t;

uint8_t bwvle_min_bits(uint64_t v);
void bwvle_encoder_init(bwvle_encoder_t *enc, uint8_t *buffer, size_t buffer_size);
int bwvle_encode_scalar(bwvle_encoder_t *enc, uint64_t value);
int bwvle_encode_bytes(bwvle_encoder_t *enc, const uint8_t *data, uint64_t length);
size_t bwvle_encoder_finish(bwvle_encoder_t *enc);
int bwvle_encoder_get_error(const bwvle_encoder_t *enc);
void bwvle_decoder_init(bwvle_decoder_t *dec, const uint8_t *buffer, size_t buffer_size,
                        bwvle_scalar_callback_t scalar_cb, bwvle_bytes_callback_t bytes_cb, void *user_data);
int bwvle_decode(bwvle_decoder_t *dec);
int bwvle_decoder_get_error(const bwvle_decoder_t *dec);

#endif // BWVLE_H