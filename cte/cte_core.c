#include "cte_core.h"
#include "cte_command.h"
#include "cte_ixdata.h"
#include "cte_pklist.h"
#include "cte_siglist.h"

#ifdef LEA_ENV
#include <stdlea.h>
#define IF_LEA_EXPORT(FUNC_NAME) LEA_EXPORT(FUNC_NAME)
#else
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#define IF_LEA_EXPORT(FUNC_NAME)
#endif

void _write_le16(uint8_t *buf, uint16_t val)
{
    buf[0] = (uint8_t)(val & 0xFF);
    buf[1] = (uint8_t)((val >> 8) & 0xFF);
}
void _write_le32(uint8_t *buf, uint32_t val)
{
    buf[0] = (uint8_t)(val & 0xFF);
    buf[1] = (uint8_t)((val >> 8) & 0xFF);
    buf[2] = (uint8_t)((val >> 16) & 0xFF);
    buf[3] = (uint8_t)((val >> 24) & 0xFF);
}
void _write_le64(uint8_t *buf, uint64_t val)
{
    _write_le32(buf, (uint32_t)(val & 0xFFFFFFFFULL));
    _write_le32(buf + 4, (uint32_t)(val >> 32));
}
uint16_t _read_le16(const uint8_t *buf)
{
    return ((uint16_t)buf[0]) | ((uint16_t)buf[1] << 8);
}
uint32_t _read_le32(const uint8_t *buf)
{
    return ((uint32_t)buf[0]) | ((uint32_t)buf[1] << 8) | ((uint32_t)buf[2] << 16) | ((uint32_t)buf[3] << 24);
}
uint64_t _read_le64(const uint8_t *buf)
{
    uint32_t low = _read_le32(buf);
    uint32_t high = _read_le32(buf + 4);
    return ((uint64_t)high << 32) | low;
}

int _encode_uleb128(uint8_t *buf, size_t buf_size, uint64_t value, size_t *bytes_written)
{
    size_t count = 0;
    do
    {
        if (count >= buf_size)
            return CTE_ERROR_BUFFER_OVERFLOW;
        uint8_t byte = value & 0x7F;
        value >>= 7;
        if (value != 0)
        {
            byte |= 0x80;
        }
        buf[count++] = byte;
    } while (value != 0);
    *bytes_written = count;
    return CTE_SUCCESS;
}

int _decode_uleb128(const uint8_t *buf, size_t buf_len, uint64_t *value, size_t *bytes_read)
{
    uint64_t result = 0;
    uint32_t shift = 0;
    size_t count = 0;
    uint8_t byte;
    do
    {
        if (count >= buf_len)
            return CTE_ERROR_INSUFFICIENT_DATA;
        if (count >= MAX_LEB128_BYTES)
            return CTE_ERROR_LEB_OVERFLOW;
        byte = buf[count++];
        uint64_t slice = byte & 0x7F;
        if (shift >= 64 || (slice << shift >> shift) != slice)
        {
            if (shift == 63 && slice > 1)
                return CTE_ERROR_LEB_OVERFLOW;
            if (shift > 63)
                return CTE_ERROR_LEB_OVERFLOW;
        }
        result |= (slice << shift);
        shift += 7;
    } while (byte & 0x80);
    *value = result;
    *bytes_read = count;
    return CTE_SUCCESS;
}

int _encode_sleb128(uint8_t *buf, size_t buf_size, int64_t value, size_t *bytes_written)
{
    size_t count = 0;
    int more = 1;
    while (more)
    {
        if (count >= buf_size)
            return CTE_ERROR_BUFFER_OVERFLOW;
        uint8_t byte = value & 0x7F;
        value >>= 7;
        if ((value == 0 && !(byte & 0x40)) || (value == -1 && (byte & 0x40)))
        {
            more = 0;
        }
        else
        {
            byte |= 0x80;
        }
        buf[count++] = byte;
    }
    *bytes_written = count;
    return CTE_SUCCESS;
}

int _decode_sleb128(const uint8_t *buf, size_t buf_len, int64_t *value, size_t *bytes_read)
{
    int64_t result = 0;
    uint32_t shift = 0;
    size_t count = 0;
    uint8_t byte;

    do
    {
        if (count >= buf_len)
            return CTE_ERROR_INSUFFICIENT_DATA;
        if (count >= MAX_LEB128_BYTES)
            return CTE_ERROR_LEB_OVERFLOW;

        byte = buf[count++];
        result |= ((int64_t)(byte & 0x7F)) << shift;
        shift += 7;

        if (shift >= 64 && (byte & 0x80))
        {

            if (shift > 64)
                return CTE_ERROR_LEB_OVERFLOW;
        }

    } while (byte & 0x80);

    if (shift < 64 && (byte & 0x40))
    {
        result |= (~((int64_t)0) << shift);
    }

    result = 0;
    shift = 0;
    count = 0;
    do
    {
        if (count >= buf_len)
            return CTE_ERROR_INSUFFICIENT_DATA;
        if (count >= MAX_LEB128_BYTES)
            return CTE_ERROR_LEB_OVERFLOW;

        byte = buf[count++];
        result |= ((int64_t)(byte & 0x7F)) << shift;
        shift += 7;
    } while (byte & 0x80);

    if ((byte & 0x40) && (shift < 64))
    {
        result |= (~((int64_t)0) << shift);
    }

    *value = result;
    *bytes_read = count;
    return CTE_SUCCESS;
}

size_t _get_pk_size_from_type(uint8_t type_code)
{
    switch (type_code)
    {
    case CTE_CRYPTO_TYPE_ED25519:
        return ED25519_PUBLIC_KEY_SIZE;
    case CTE_CRYPTO_TYPE_SLH_SHA2_128F:
        return PQC_PUBKEY_SLH128F_SIZE;
    case CTE_CRYPTO_TYPE_SLH_SHA2_192F:
        return PQC_PUBKEY_SLH192F_SIZE;
    case CTE_CRYPTO_TYPE_SLH_SHA2_256F:
        return PQC_PUBKEY_SLH256F_SIZE;
    default:
        return 0;
    }
}

size_t _get_sig_item_size_from_type(uint8_t type_code)
{
    switch (type_code)
    {
    case CTE_SIG_TYPE_ED25519:
        return ED25519_SIGNATURE_SIZE;
    case CTE_SIG_TYPE_SLH_SHA2_128F_HASH32:
    case CTE_SIG_TYPE_SLH_SHA2_192F_HASH32:
    case CTE_SIG_TYPE_SLH_SHA2_256F_HASH32:
        return PQC_SIG_HASH_SIZE;
    default:
        return 0;
    }
}

IF_LEA_EXPORT(cte_encoder_new)
void *cte_encoder_new()
{
    cte_encoder_state_t *state = (cte_encoder_state_t *)malloc(sizeof(cte_encoder_state_t));
    if (!state)
        return NULL;
    memset(state, 0, sizeof(cte_encoder_state_t));

#ifndef LEA_ENV
    state->buffer = (uint8_t *)malloc(MAX_CTE_SIZE);
#else
    state->buffer = (uint8_t *)malloc(MAX_CTE_SIZE);
#endif

    if (!state->buffer)
    {
#ifndef LEA_ENV
        free(state);
#endif
        return NULL;
    }
    state->buffer_capacity = MAX_CTE_SIZE;
    state->current_offset = 0;

    if (state->current_offset < state->buffer_capacity)
    {
        state->buffer[state->current_offset++] = CTE_VERSION_V1;
        state->active = 1;
        return (void *)state;
    }
    else
    {
#ifndef LEA_ENV
        free(state->buffer);
        free(state);
#endif
        return NULL;
    }
}

IF_LEA_EXPORT(cte_decoder_new)
void *cte_decoder_new()
{
    cte_decoder_state_t *state = (cte_decoder_state_t *)malloc(sizeof(cte_decoder_state_t));
    if (!state)
        return NULL;
    memset(state, 0, sizeof(cte_decoder_state_t));
    state->active = 0;
    return (void *)state;
}

IF_LEA_EXPORT(cte_decoder_set_input_buffer)
int cte_decoder_set_input_buffer(void *handle, const uint8_t *buffer_ptr, size_t buffer_len)
{
    if (!handle)
        return CTE_ERROR_INVALID_ARGUMENT;
    cte_decoder_state_t *state = (cte_decoder_state_t *)handle;

    if (state->active != 0)
        return CTE_ERROR_INVALID_STATE;
    if (!buffer_ptr || buffer_len == 0 || buffer_len > MAX_CTE_SIZE)
        return CTE_ERROR_INVALID_ARGUMENT;

    if (buffer_ptr[0] != CTE_VERSION_V1)
        return CTE_ERROR_INVALID_FORMAT;

    state->decode_buffer_ptr = buffer_ptr;
    state->decode_buffer_len = buffer_len;
    state->decode_current_offset = 1;
    memset(&state->last_decoded_field, 0, sizeof(cte_decoded_field_t));
    state->active = 2;

    return CTE_SUCCESS;
}

static int _cte_decode_next_field_internal(cte_decoder_state_t *state)
{
    if (!state || state->active != 2)
        return CTE_ERROR_INVALID_STATE;

    const uint8_t *buffer = state->decode_buffer_ptr;
    size_t buffer_len = state->decode_buffer_len;
    size_t current_offset = state->decode_current_offset;

    if (current_offset >= buffer_len)
        return CTE_ERROR_END_OF_BUFFER;

    memset(&state->last_decoded_field, 0, sizeof(cte_decoded_field_t));
    uint8_t header1 = buffer[current_offset];
    uint8_t tag = header1 & TAG_MASK;
    int result = CTE_ERROR_INVALID_FORMAT;

    switch (tag)
    {
    case TAG_PUBLIC_KEY_LIST:
        result = _cte_decode_pklist_field(state, buffer, buffer_len, current_offset);
        break;
    case TAG_SIGNATURE_LIST:
        result = _cte_decode_siglist_field(state, buffer, buffer_len, current_offset);
        break;
    case TAG_IXDATA:
        result = _cte_decode_ixdata_field(state, buffer, buffer_len, current_offset);
        break;
    case TAG_COMMAND_DATA:
        result = _cte_decode_command_field(state, buffer, buffer_len, current_offset);
        break;
    default:
        result = CTE_ERROR_INVALID_FORMAT;
        break;
    }

    if (result == CTE_SUCCESS)
    {
        state->decode_current_offset = current_offset + state->last_decoded_field.field_total_size;
    }
    else
    {
        memset(&state->last_decoded_field, 0, sizeof(cte_decoded_field_t));
        state->last_decoded_field.type = CTE_FIELD_TYPE_UNKNOWN;
    }
    return result;
}

IF_LEA_EXPORT(cte_decoder_advance)
int cte_decoder_advance(void *handle)
{
    if (!handle)
        return CTE_ERROR_INVALID_ARGUMENT;
    cte_decoder_state_t *state = (cte_decoder_state_t *)handle;
    if (state->active != 2)
        return CTE_ERROR_INVALID_STATE;

    int result = _cte_decode_next_field_internal(state);

    if (result < CTE_SUCCESS)
    {
        return result;
    }
    return (int)state->last_decoded_field.type;
}

IF_LEA_EXPORT(cte_encoder_get_buffer_ptr)
uintptr_t cte_encoder_get_buffer_ptr(void *handle)
{
    if (!handle)
        return 0;
    cte_encoder_state_t *state = (cte_encoder_state_t *)handle;
    if (state->active != 1)
        return 0;
    return (uintptr_t)state->buffer;
}

IF_LEA_EXPORT(cte_encoder_get_buffer_size)
size_t cte_encoder_get_buffer_size(void *handle)
{
    if (!handle)
        return 0;
    cte_encoder_state_t *state = (cte_encoder_state_t *)handle;
    if (state->active != 1)
        return 0;
    return state->current_offset;
}

IF_LEA_EXPORT(cte_decoder_get_data_ptr)
uintptr_t cte_decoder_get_data_ptr(void *handle)
{
    if (!handle)
        return 0;
    cte_decoder_state_t *state = (cte_decoder_state_t *)handle;
    if (state->active != 2)
        return 0;

    switch (state->last_decoded_field.type)
    {
    case CTE_FIELD_TYPE_PUBKEY_LIST:
        return (uintptr_t)state->last_decoded_field.data.pk_list.first_key;
    case CTE_FIELD_TYPE_SIGNATURE_LIST:
        return (uintptr_t)state->last_decoded_field.data.sig_list.first_item;
    case CTE_FIELD_TYPE_IXDATA:
        if (state->last_decoded_field.data.ixdata.subtype == IXDATA_SUBTYPE_FIXED)
        {
            return (uintptr_t)state->last_decoded_field.data.ixdata.fixed_data_ptr;
        }
        return 0;
    case CTE_FIELD_TYPE_COMMAND_DATA:
        return (uintptr_t)state->last_decoded_field.data.command.data;
    default:
        return 0;
    }
}

IF_LEA_EXPORT(cte_decoder_get_list_count)
int8_t cte_decoder_get_list_count(void *handle)
{
    if (!handle)
        return -1;
    cte_decoder_state_t *state = (cte_decoder_state_t *)handle;
    if (state->active != 2)
        return -1;

    switch (state->last_decoded_field.type)
    {
    case CTE_FIELD_TYPE_PUBKEY_LIST:
        return (int8_t)state->last_decoded_field.data.pk_list.count;
    case CTE_FIELD_TYPE_SIGNATURE_LIST:
        return (int8_t)state->last_decoded_field.data.sig_list.count;
    default:
        return -1;
    }
}