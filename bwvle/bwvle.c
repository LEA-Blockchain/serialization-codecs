/*
 * Author: Allwin Ketnawang
 * License: MIT License
 * Project: LEA Project (getlea.org)
 */
#include "bwvle.h"
#include <limits.h>
#include <stdlib.h>
#include <string.h>

static int set_encoder_error(bwvle_encoder_t *enc, int error_code)
{
    if (enc && enc->error_code == BWVLE_SUCCESS)
    {
        enc->error_code = error_code;
    }
    return error_code;
}

static int set_decoder_error(bwvle_decoder_t *dec, int error_code)
{
    if (dec && dec->error_code == BWVLE_SUCCESS)
    {
        dec->error_code = error_code;
    }
    return error_code;
}

static int bwvle_write_bit(bwvle_encoder_t *enc, uint8_t bit)
{
    if (enc->error_code != BWVLE_SUCCESS)
        return enc->error_code;
    if (enc->byte_pos >= enc->buffer_size)
    {
        return set_encoder_error(enc, BWVLE_ERROR_BUFFER_OVERFLOW);
    }
    if (enc->bit_pos == 7)
    {
        enc->buffer[enc->byte_pos] = 0;
    }
    if (bit)
    {
        enc->buffer[enc->byte_pos] |= (1 << enc->bit_pos);
    }
    if (enc->bit_pos == 0)
    {
        enc->bit_pos = 7;
        enc->byte_pos++;
    }
    else
    {
        enc->bit_pos--;
    }
    return BWVLE_SUCCESS;
}

static int bwvle_write_bits(bwvle_encoder_t *enc, uint64_t value, uint8_t num_bits)
{
    if (enc->error_code != BWVLE_SUCCESS)
        return enc->error_code;
    if (num_bits > 64)
        return set_encoder_error(enc, BWVLE_ERROR_INVALID_DATA);
    for (int i = num_bits - 1; i >= 0; --i)
    {
        if (bwvle_write_bit(enc, (value >> i) & 1) != BWVLE_SUCCESS)
        {
            return enc->error_code;
        }
    }
    return BWVLE_SUCCESS;
}

static int bwvle_read_bit(bwvle_decoder_t *dec)
{
    if (dec->error_code != BWVLE_SUCCESS)
        return dec->error_code;
    size_t current_absolute_bit = dec->byte_pos * 8 + (7 - dec->bit_pos);
    if (current_absolute_bit >= dec->buffer_size * 8)
    {
        return set_decoder_error(dec, BWVLE_ERROR_BUFFER_OVERFLOW);
    }
    if (dec->byte_pos >= dec->buffer_size)
    {
        return set_decoder_error(dec, BWVLE_ERROR_BUFFER_OVERFLOW);
    }
    uint8_t bit = (dec->buffer[dec->byte_pos] >> dec->bit_pos) & 1;
    if (dec->bit_pos == 0)
    {
        dec->bit_pos = 7;
        dec->byte_pos++;
    }
    else
    {
        dec->bit_pos--;
    }
    dec->total_bits_consumed++;
    return bit;
}

static int bwvle_read_bits(bwvle_decoder_t *dec, uint8_t num_bits, uint64_t *value)
{
    if (dec->error_code != BWVLE_SUCCESS)
        return dec->error_code;
    if (num_bits > 64)
        return set_decoder_error(dec, BWVLE_ERROR_INVALID_DATA);
    *value = 0;
    for (uint8_t i = 0; i < num_bits; ++i)
    {
        int bit = bwvle_read_bit(dec);
        if (bit < 0)
        {
            return dec->error_code;
        }
        *value = (*value << 1) | bit;
    }
    return BWVLE_SUCCESS;
}

uint8_t bwvle_min_bits(uint64_t v)
{
    if (v == 0)
    {
        return 1;
    }
#if defined(__GNUC__) && !defined(BWVLE_NO_BUILTIN_CLZ)
    return (uint8_t)(64 - __builtin_clzll(v));
#else
    uint8_t bits = 0;
    uint64_t temp = v;
    while (temp > 0)
    {
        temp >>= 1;
        bits++;
    }
    return bits;
#endif
}

static int bwvle_encode_scalar_internal(bwvle_encoder_t *enc, uint64_t v)
{
    if (enc->error_code != BWVLE_SUCCESS)
        return enc->error_code;
    uint8_t m = bwvle_min_bits(v);
    uint8_t m_bits = bwvle_min_bits(m);
    uint8_t n = (m_bits < 2) ? 2 : m_bits;
    for (uint8_t i = 0; i < n; ++i)
    {
        if (bwvle_write_bit(enc, 1) != BWVLE_SUCCESS)
            return enc->error_code;
    }
    if (bwvle_write_bit(enc, 0) != BWVLE_SUCCESS)
        return enc->error_code;
    if (bwvle_write_bits(enc, m, n) != BWVLE_SUCCESS)
        return enc->error_code;
    if (bwvle_write_bits(enc, v, m) != BWVLE_SUCCESS)
        return enc->error_code;
    return BWVLE_SUCCESS;
}

static int bwvle_decode_scalar_internal(bwvle_decoder_t *dec, uint64_t *value)
{
    if (dec->error_code != BWVLE_SUCCESS)
        return dec->error_code;
    uint8_t n = 0;
    int bit;
    while ((bit = bwvle_read_bit(dec)) == 1)
    {
        n++;
        if (n > 64)
            return set_decoder_error(dec, BWVLE_ERROR_INVALID_DATA);
    }
    if (bit < 0)
        return dec->error_code;
    if (n < 2)
        return set_decoder_error(dec, BWVLE_ERROR_INVALID_DATA);
    uint64_t m_u64;
    if (bwvle_read_bits(dec, n, &m_u64) != BWVLE_SUCCESS)
        return dec->error_code;
    if (m_u64 > 64 || m_u64 == 0)
        return set_decoder_error(dec, BWVLE_ERROR_INVALID_DATA);
    uint8_t m = (uint8_t)m_u64;
    uint64_t v;
    if (bwvle_read_bits(dec, m, &v) != BWVLE_SUCCESS)
        return dec->error_code;
    uint8_t m_check = bwvle_min_bits(v);
    if (m_check != m)
        return set_decoder_error(dec, BWVLE_ERROR_INVALID_DATA);
    *value = v;
    return BWVLE_SUCCESS;
}

void bwvle_encoder_init(bwvle_encoder_t *enc, uint8_t *buffer, size_t buffer_size)
{
    if (!enc || !buffer)
        return;
    enc->buffer = buffer;
    enc->buffer_size = buffer_size;
    enc->byte_pos = 0;
    enc->bit_pos = 7;
    enc->error_code = BWVLE_SUCCESS;
    if (buffer_size > 0)
        memset(buffer, 0, buffer_size);
}

int bwvle_encode_scalar(bwvle_encoder_t *enc, uint64_t value)
{
    if (enc->error_code != BWVLE_SUCCESS)
        return enc->error_code;
    if (bwvle_write_bit(enc, 1) != BWVLE_SUCCESS)
        return enc->error_code;
    if (bwvle_write_bit(enc, 1) != BWVLE_SUCCESS)
        return enc->error_code;
    return bwvle_encode_scalar_internal(enc, value);
}

int bwvle_encode_bytes(bwvle_encoder_t *enc, const uint8_t *data, uint64_t length)
{
    if (!enc)
        return BWVLE_ERROR_INVALID_DATA;
    if (enc->error_code != BWVLE_SUCCESS)
        return enc->error_code;

#if BWVLE_MAX_SEQUENCE_LEN > 0
    if (length > BWVLE_MAX_SEQUENCE_LEN)
    {

        return set_encoder_error(enc, BWVLE_ERROR_LENGTH_LIMIT_EXCEEDED);
    }
#endif

    if (bwvle_write_bit(enc, 1) != BWVLE_SUCCESS)
        return enc->error_code;
    if (bwvle_write_bit(enc, 0) != BWVLE_SUCCESS)
        return enc->error_code;

    if (bwvle_write_bit(enc, 1) != BWVLE_SUCCESS)
        return enc->error_code;
    if (bwvle_write_bit(enc, 1) != BWVLE_SUCCESS)
        return enc->error_code;
    if (bwvle_encode_scalar_internal(enc, length) != BWVLE_SUCCESS)
        return enc->error_code;

    for (uint64_t i = 0; i < length; ++i)
    {

        if (!data)
            return set_encoder_error(enc, BWVLE_ERROR_INVALID_DATA);
        if (bwvle_write_bits(enc, data[i], 8) != BWVLE_SUCCESS)
            return enc->error_code;
    }
    return BWVLE_SUCCESS;
}

size_t bwvle_encoder_finish(bwvle_encoder_t *enc)
{
    if (!enc)
        return 0;
    if (enc->error_code != BWVLE_SUCCESS)
        return 0;
    if (enc->bit_pos != 7)
    {
        size_t bits_to_pad = enc->bit_pos + 1;
        for (size_t i = 0; i < bits_to_pad; ++i)
        {
            if (bwvle_write_bit(enc, 0) != BWVLE_SUCCESS)
            {
                if (enc->error_code == BWVLE_ERROR_BUFFER_OVERFLOW && enc->byte_pos == enc->buffer_size &&
                    enc->bit_pos == 7)
                {
                    enc->error_code = BWVLE_SUCCESS;
                }
                if (enc->error_code != BWVLE_SUCCESS)
                    return 0;
            }
        }
    }
    if (enc->error_code != BWVLE_SUCCESS)
        return 0;
    return enc->byte_pos;
}

int bwvle_encoder_get_error(const bwvle_encoder_t *enc)
{
    return enc ? enc->error_code : BWVLE_ERROR_INVALID_DATA;
}

void bwvle_decoder_init(bwvle_decoder_t *dec, const uint8_t *buffer, size_t buffer_size,
                        bwvle_scalar_callback_t scalar_cb, bwvle_bytes_callback_t bytes_cb, void *user_data)
{
    if (!dec || !buffer || !scalar_cb || !bytes_cb)
        return;
    dec->buffer = buffer;
    dec->buffer_size = buffer_size;
    dec->byte_pos = 0;
    dec->bit_pos = 7;
    dec->error_code = BWVLE_SUCCESS;
    dec->scalar_cb = scalar_cb;
    dec->bytes_cb = bytes_cb;
    dec->user_data = user_data;
    dec->total_bits_consumed = 0;
}

int bwvle_decode(bwvle_decoder_t *dec)
{
    if (!dec || dec->error_code != BWVLE_SUCCESS)
    {
        return dec->error_code != BWVLE_SUCCESS ? dec->error_code : BWVLE_ERROR_INVALID_DATA;
    }

    size_t buffer_total_bits = dec->buffer_size * 8;

    while (dec->total_bits_consumed < buffer_total_bits)
    {
        int bit1 = bwvle_read_bit(dec);
        if (bit1 < 0)
        {
            if (dec->error_code == BWVLE_ERROR_BUFFER_OVERFLOW && dec->total_bits_consumed == buffer_total_bits)
            {
                dec->error_code = BWVLE_SUCCESS;
            }
            break;
        }
        if (bit1 == 0)
        {
            dec->total_bits_consumed--;
            if (dec->bit_pos == 7)
            {
                dec->byte_pos--;
                dec->bit_pos = 0;
            }
            else
            {
                dec->bit_pos++;
            }
            break;
        }
        if (dec->total_bits_consumed >= buffer_total_bits)
        {
            set_decoder_error(dec, BWVLE_ERROR_INVALID_DATA);
            break;
        }
        int bit2 = bwvle_read_bit(dec);
        if (bit2 < 0)
        {
            if (dec->error_code == BWVLE_SUCCESS)
                set_decoder_error(dec, BWVLE_ERROR_INVALID_DATA);
            break;
        }

        if (bit2 == 0)
        {
            uint64_t length;
            int len_bit1 = bwvle_read_bit(dec);
            int len_bit2 = bwvle_read_bit(dec);
            if (len_bit1 < 0 || len_bit2 < 0)
            {
                if (dec->error_code == BWVLE_SUCCESS)
                    set_decoder_error(dec, BWVLE_ERROR_INVALID_DATA);
                break;
            }
            if (len_bit1 != 1 || len_bit2 != 1)
            {
                set_decoder_error(dec, BWVLE_ERROR_INVALID_DATA);
                break;
            }
            if (bwvle_decode_scalar_internal(dec, &length) != BWVLE_SUCCESS)
                break;

#if BWVLE_MAX_SEQUENCE_LEN > 0
            if (length > BWVLE_MAX_SEQUENCE_LEN)
            {
                set_decoder_error(dec, BWVLE_ERROR_LENGTH_LIMIT_EXCEEDED);
                break;
            }
#endif

            if (length > 0 && (UINT64_MAX / 8) < length)
            {
                set_decoder_error(dec, BWVLE_ERROR_LENGTH_LIMIT_EXCEEDED);
                break;
            }
            uint64_t data_bits_needed = length * 8;

            if (data_bits_needed > buffer_total_bits - dec->total_bits_consumed)
            {
                set_decoder_error(dec, BWVLE_ERROR_BUFFER_OVERFLOW);
                break;
            }

            uint8_t *data_buf = NULL;
            if (length > 0)
            {
                if (length > SIZE_MAX)
                {
                    set_decoder_error(dec, BWVLE_ERROR_LENGTH_LIMIT_EXCEEDED);
                    break;
                }
                data_buf = (uint8_t *)malloc((size_t)length);
                if (!data_buf)
                {
                    set_decoder_error(dec, BWVLE_ERROR_ALLOCATION_FAILED);
                    break;
                }
            }

            int read_byte_error = 0;
            for (uint64_t i = 0; i < length; ++i)
            {
                uint64_t byte_val;
                if (bwvle_read_bits(dec, 8, &byte_val) != BWVLE_SUCCESS)
                {
                    read_byte_error = 1;
                    break;
                }
                if (data_buf)
                    data_buf[i] = (uint8_t)byte_val;
            }
            if (read_byte_error)
            {
                free(data_buf);
                break;
            }

            dec->bytes_cb(data_buf, length, dec->user_data);
            free(data_buf);
        }
        else
        {
            uint64_t value;
            if (bwvle_decode_scalar_internal(dec, &value) != BWVLE_SUCCESS)
                break;
            dec->scalar_cb(value, dec->user_data);
        }
    }

    if (dec->error_code == BWVLE_SUCCESS)
    {
        size_t bits_remaining = buffer_total_bits - dec->total_bits_consumed;
        size_t remainder_bits_in_byte = dec->total_bits_consumed % 8;
        size_t expected_padding_bits = (remainder_bits_in_byte == 0) ? 0 : (8 - remainder_bits_in_byte);
        if (bits_remaining != expected_padding_bits)
        {
            set_decoder_error(dec, BWVLE_ERROR_INVALID_DATA);
        }
        else if (expected_padding_bits > 0)
        {
            for (size_t i = 0; i < expected_padding_bits; ++i)
            {
                int pad_bit = bwvle_read_bit(dec);
                if (pad_bit < 0)
                {
                    if (dec->error_code == BWVLE_SUCCESS)
                        set_decoder_error(dec, BWVLE_ERROR_INVALID_DATA);
                    break;
                }
                if (pad_bit != 0)
                {
                    set_decoder_error(dec, BWVLE_ERROR_INVALID_DATA);
                    break;
                }
            }
        }
    }
    if (dec->error_code == BWVLE_SUCCESS && dec->total_bits_consumed != buffer_total_bits)
    {
        set_decoder_error(dec, BWVLE_ERROR_INVALID_DATA);
    }

    return dec->error_code;
}

int bwvle_decoder_get_error(const bwvle_decoder_t *dec)
{
    return dec ? dec->error_code : BWVLE_ERROR_INVALID_DATA;
}