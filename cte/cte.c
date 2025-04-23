#include "cte.h"
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

typedef struct
{
    uint8_t active;
    uint8_t *buffer;
    size_t buffer_capacity;
    size_t current_offset;
} cte_encoder_state_t;

typedef struct
{
    uint8_t active;
    const uint8_t *decode_buffer_ptr;
    size_t decode_buffer_len;
    size_t decode_current_offset;
    cte_decoded_field_t last_decoded_field;
} cte_decoder_state_t;

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
    size_t field_size = 0;
    size_t required_data_size = 0;
    const uint8_t *payload_ptr = NULL;
    size_t header_size = 0;
    int result = CTE_SUCCESS;

    switch (tag)
    {
    case TAG_PUBLIC_KEY_LIST:
    {
        header_size = 1;
        uint8_t c = (header1 >> 2) & 0x0F;
        uint8_t p = header1 & 3;
        if (p != 0 || c == 0 || c > MAX_LIST_LEN)
        {
            result = CTE_ERROR_INVALID_FORMAT;
            break;
        }
        required_data_size = (size_t)c * PUBLIC_KEY_SIZE;
        field_size = header_size + required_data_size;
        if (current_offset + field_size > buffer_len)
        {
            result = CTE_ERROR_INSUFFICIENT_DATA;
            break;
        }
        payload_ptr = &buffer[current_offset + header_size];
        state->last_decoded_field.type = CTE_FIELD_TYPE_PUBKEY_LIST;
        state->last_decoded_field.data.pk_list.count = c;
        state->last_decoded_field.data.pk_list.first_key = payload_ptr;
        break;
    }
    case TAG_SIGNATURE_LIST:
    {
        header_size = 1;
        uint8_t c = (header1 >> 2) & 0x0F;
        uint8_t p = header1 & 3;
        if (p != 0 || c == 0 || c > MAX_LIST_LEN)
        {
            result = CTE_ERROR_INVALID_FORMAT;
            break;
        }
        required_data_size = (size_t)c * SIGNATURE_SIZE;
        field_size = header_size + required_data_size;
        if (current_offset + field_size > buffer_len)
        {
            result = CTE_ERROR_INSUFFICIENT_DATA;
            break;
        }
        payload_ptr = &buffer[current_offset + header_size];
        state->last_decoded_field.type = CTE_FIELD_TYPE_SIGNATURE_LIST;
        state->last_decoded_field.data.sig_list.count = c;
        state->last_decoded_field.data.sig_list.first_signature = payload_ptr;
        break;
    }
    case TAG_INDEX_REFERENCE:
    {
        header_size = 1;
        uint8_t i = (header1 >> 2) & 0x0F;
        uint8_t p = header1 & 3;
        if (p != 0)
        {
            result = CTE_ERROR_INVALID_FORMAT;
            break;
        }
        field_size = header_size;
        state->last_decoded_field.type = CTE_FIELD_TYPE_INDEX_REF;
        state->last_decoded_field.data.index = i;
        break;
    }
    case TAG_COMMAND_DATA:
    {
        uint8_t f = (header1 >> 5) & 1;
        size_t l = 0;
        if (f == 0)
        {
            header_size = 1;
            l = header1 & 0x1F;
            field_size = header_size + l;
            if (current_offset + field_size > buffer_len)
            {
                result = CTE_ERROR_INSUFFICIENT_DATA;
                break;
            }
            payload_ptr = (l > 0) ? &buffer[current_offset + header_size] : NULL;
        }
        else
        {
            header_size = 2;
            uint8_t p = header1 & 3;
            if (p != 0)
            {
                result = CTE_ERROR_INVALID_FORMAT;
                break;
            }
            if (current_offset + header_size > buffer_len)
            {
                result = CTE_ERROR_INSUFFICIENT_DATA;
                break;
            }
            uint8_t h2 = buffer[current_offset + 1];
            uint8_t lh = (header1 >> 2) & 7;
            uint8_t ll = h2;
            l = ((size_t)lh << 8) | ll;
            if (l < COMMAND_DATA_EXTENDED_MIN_LEN || l > COMMAND_DATA_EXTENDED_MAX_LEN)
            {
                result = CTE_ERROR_INVALID_FORMAT;
                break;
            }
            field_size = header_size + l;
            if (current_offset + field_size > buffer_len)
            {
                result = CTE_ERROR_INSUFFICIENT_DATA;
                break;
            }
            payload_ptr = &buffer[current_offset + header_size];
        }
        state->last_decoded_field.type = CTE_FIELD_TYPE_COMMAND_DATA;
        state->last_decoded_field.data.command.length = l;
        state->last_decoded_field.data.command.data = payload_ptr;
        break;
    }
    default:
        state->last_decoded_field.type = CTE_FIELD_TYPE_UNKNOWN;
        result = CTE_ERROR_INVALID_FORMAT;
        break;
    }

    if (result == CTE_SUCCESS)
    {
        state->last_decoded_field.field_total_size = field_size;
        state->decode_current_offset = current_offset + field_size;
    }
    return result;
}

void *cte_encoder_new()
{
    cte_encoder_state_t *state = (cte_encoder_state_t *)malloc(sizeof(cte_encoder_state_t));
    if (!state)
        return NULL;
    memset(state, 0, sizeof(cte_encoder_state_t));

    state->buffer = (uint8_t *)malloc(MAX_CTE_SIZE);
    if (!state->buffer)
    {

        return NULL;
    }
    state->buffer_capacity = MAX_CTE_SIZE;
    state->current_offset = 0;

    state->buffer[state->current_offset++] = CTE_VERSION_V1;
    state->active = 1;
    return (void *)state;
}

uintptr_t cte_encoder_prepare_public_key_list(void *handle, uint8_t key_count)
{
    if (!handle)
        return 0;
    cte_encoder_state_t *state = (cte_encoder_state_t *)handle;
    if (state->active != 1 || key_count == 0 || key_count > MAX_LIST_LEN)
        return 0;
    size_t header_size = 1;
    size_t data_size = (size_t)key_count * PUBLIC_KEY_SIZE;
    if (state->current_offset + header_size + data_size > state->buffer_capacity)
        return 0;
    uint8_t header = TAG_PUBLIC_KEY_LIST | (key_count << 2);
    state->buffer[state->current_offset++] = header;
    uintptr_t write_start_offset = (uintptr_t)&state->buffer[state->current_offset];
    state->current_offset += data_size;
    return write_start_offset;
}

uintptr_t cte_encoder_prepare_signature_list(void *handle, uint8_t sig_count)
{
    if (!handle)
        return 0;
    cte_encoder_state_t *state = (cte_encoder_state_t *)handle;
    if (state->active != 1 || sig_count == 0 || sig_count > MAX_LIST_LEN)
        return 0;
    size_t header_size = 1;
    size_t data_size = (size_t)sig_count * SIGNATURE_SIZE;
    if (state->current_offset + header_size + data_size > state->buffer_capacity)
        return 0;
    uint8_t header = TAG_SIGNATURE_LIST | (sig_count << 2);
    state->buffer[state->current_offset++] = header;
    uintptr_t write_start_offset = (uintptr_t)&state->buffer[state->current_offset];
    state->current_offset += data_size;
    return write_start_offset;
}

int cte_encoder_write_index_reference(void *handle, uint8_t index)
{
    if (!handle)
        return CTE_ERROR_INVALID_ARGUMENT;
    cte_encoder_state_t *state = (cte_encoder_state_t *)handle;
    if (state->active != 1 || index > MAX_INDEX)
        return CTE_ERROR_INVALID_ARGUMENT;
    if (state->current_offset + 1 > state->buffer_capacity)
        return CTE_ERROR_BUFFER_OVERFLOW;
    uint8_t header = TAG_INDEX_REFERENCE | (index << 2);
    state->buffer[state->current_offset++] = header;
    return CTE_SUCCESS;
}

uintptr_t cte_encoder_prepare_command_data(void *handle, size_t payload_len)
{
    if (!handle)
        return 0;
    cte_encoder_state_t *state = (cte_encoder_state_t *)handle;
    if (state->active != 1)
        return 0;
    if (payload_len > COMMAND_DATA_EXTENDED_MAX_LEN ||
        (payload_len > COMMAND_DATA_SHORT_MAX_LEN && payload_len < COMMAND_DATA_EXTENDED_MIN_LEN))
        return 0;
    size_t required_size;
    uint8_t header1;
    size_t header_bytes;
    uintptr_t write_start_offset = 0;
    if (payload_len <= COMMAND_DATA_SHORT_MAX_LEN)
    {
        header_bytes = 1;
        required_size = header_bytes + payload_len;
    }
    else
    {
        header_bytes = 2;
        required_size = header_bytes + payload_len;
    }
    if (state->current_offset + required_size > state->buffer_capacity)
        return 0;
    if (header_bytes == 1)
    {
        header1 = TAG_COMMAND_DATA | (0 << 5) | (uint8_t)payload_len;
        state->buffer[state->current_offset++] = header1;
    }
    else
    {
        uint8_t len_high = (uint8_t)((payload_len >> 8) & 0x07);
        uint8_t len_low = (uint8_t)(payload_len & 0xFF);
        header1 = TAG_COMMAND_DATA | (1 << 5) | (len_high << 2);
        uint8_t header2 = len_low;
        if ((header1 & 0x03) != 0)
        {
            state->active = 0;
            return 0;
        }
        state->buffer[state->current_offset++] = header1;
        state->buffer[state->current_offset++] = header2;
    }
    write_start_offset = (uintptr_t)&state->buffer[state->current_offset];
    state->current_offset += payload_len;
    return write_start_offset;
}

uintptr_t cte_encoder_get_buffer_ptr(void *handle)
{
    if (!handle)
        return 0;
    cte_encoder_state_t *state = (cte_encoder_state_t *)handle;
    if (state->active != 1)
        return 0;
    return (uintptr_t)state->buffer;
}

size_t cte_encoder_get_buffer_size(void *handle)
{
    if (!handle)
        return 0;
    cte_encoder_state_t *state = (cte_encoder_state_t *)handle;
    if (state->active != 1)
        return 0;
    return state->current_offset;
}

void *cte_decoder_new()
{
    cte_decoder_state_t *state = (cte_decoder_state_t *)malloc(sizeof(cte_decoder_state_t));
    if (!state)
        return NULL;
    memset(state, 0, sizeof(cte_decoder_state_t));

    return (void *)state;
}

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
    state->active = 2;

    return CTE_SUCCESS;
}

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
        state->active = 0;
        return result;
    }

    return (int)state->last_decoded_field.type;
}

int64_t cte_decoder_get_index_value(void *handle)
{
    if (!handle)
        return -1;
    cte_decoder_state_t *state = (cte_decoder_state_t *)handle;

    if (state->last_decoded_field.type == CTE_FIELD_TYPE_INDEX_REF)
    {
        return (int64_t)state->last_decoded_field.data.index;
    }
    return -1;
}

uintptr_t cte_decoder_get_data_ptr(void *handle)
{
    if (!handle)
        return 0;
    cte_decoder_state_t *state = (cte_decoder_state_t *)handle;

    switch (state->last_decoded_field.type)
    {
    case CTE_FIELD_TYPE_PUBKEY_LIST:
        return (uintptr_t)state->last_decoded_field.data.pk_list.first_key;
    case CTE_FIELD_TYPE_SIGNATURE_LIST:
        return (uintptr_t)state->last_decoded_field.data.sig_list.first_signature;
    case CTE_FIELD_TYPE_COMMAND_DATA:
        return (uintptr_t)state->last_decoded_field.data.command.data;
    default:
        return 0;
    }
}

int8_t cte_decoder_get_list_count(void *handle)
{
    if (!handle)
        return -1;
    cte_decoder_state_t *state = (cte_decoder_state_t *)handle;

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

size_t cte_decoder_get_command_len(void *handle)
{
    if (!handle)
        return (size_t)-1;
    cte_decoder_state_t *state = (cte_decoder_state_t *)handle;

    if (state->last_decoded_field.type == CTE_FIELD_TYPE_COMMAND_DATA)
    {
        return state->last_decoded_field.data.command.length;
    }
    return (size_t)-1;
}