#include "cte_command.h"
#include "cte_core.h"

#ifdef LEA_ENV
#include <stdlea.h>
#else
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#endif

IF_LEA_EXPORT(cte_encoder_prepare_command_data)
uintptr_t cte_encoder_prepare_command_data(void *handle, size_t payload_len)
{
    if (!handle)
        return 0;
    cte_encoder_state_t *state = (cte_encoder_state_t *)handle;
    if (state->active != 1)
        return 0;

    if (payload_len > COMMAND_DATA_EXTENDED_MAX_LEN ||
        (payload_len > COMMAND_DATA_SHORT_MAX_LEN && payload_len < COMMAND_DATA_EXTENDED_MIN_LEN))
    {
        return 0;
    }

    size_t required_size;
    uint8_t header1;
    size_t header_bytes;
    uintptr_t write_start_ptr = 0;

    if (payload_len <= COMMAND_DATA_SHORT_MAX_LEN)
    {
        header_bytes = 1;
        required_size = header_bytes + payload_len;
        if (state->current_offset + required_size > state->buffer_capacity)
            return 0;

        header1 = TAG_COMMAND_DATA | (0 << 5) | (uint8_t)payload_len;
        state->buffer[state->current_offset++] = header1;
    }
    else
    {
        header_bytes = 2;
        required_size = header_bytes + payload_len;
        if (state->current_offset + required_size > state->buffer_capacity)
            return 0;

        uint8_t len_high = (uint8_t)((payload_len >> 8) & 0x07);
        uint8_t len_low = (uint8_t)(payload_len & 0xFF);

        header1 = TAG_COMMAND_DATA | (1 << 5) | (len_high << 2);
        uint8_t header2 = len_low;

        state->buffer[state->current_offset++] = header1;
        state->buffer[state->current_offset++] = header2;
    }

    write_start_ptr = (uintptr_t)&state->buffer[state->current_offset];

    state->current_offset += payload_len;
    return write_start_ptr;
}

int _cte_decode_command_field(cte_decoder_state_t *state, const uint8_t *buffer, size_t buffer_len,
                              size_t current_offset)
{

    uint8_t header1 = buffer[current_offset];
    uint8_t format_flag = (header1 >> 5) & 1;
    size_t payload_len = 0;
    size_t field_header_size = 0;
    size_t field_total_size = 0;
    const uint8_t *payload_ptr = NULL;
    int result = CTE_SUCCESS;

    if (format_flag == 0)
    {
        field_header_size = 1;
        payload_len = header1 & 0x1F;
        field_total_size = field_header_size + payload_len;

        if (current_offset + field_total_size > buffer_len)
        {
            result = CTE_ERROR_INSUFFICIENT_DATA;
        }
        else
        {
            payload_ptr = (payload_len > 0) ? &buffer[current_offset + field_header_size] : NULL;
        }
    }
    else
    {
        field_header_size = 2;

        uint8_t p = header1 & 0x03;
        if (p != 0)
        {
            result = CTE_ERROR_INVALID_FORMAT;
        }
        else
        {

            if (current_offset + field_header_size > buffer_len)
            {
                result = CTE_ERROR_INSUFFICIENT_DATA;
            }
            else
            {
                uint8_t header2 = buffer[current_offset + 1];
                uint8_t len_high = (header1 >> 2) & 0x07;
                uint8_t len_low = header2;
                payload_len = ((size_t)len_high << 8) | len_low;

                if (payload_len < COMMAND_DATA_EXTENDED_MIN_LEN || payload_len > COMMAND_DATA_EXTENDED_MAX_LEN)
                {
                    result = CTE_ERROR_INVALID_FORMAT;
                }
                else
                {
                    field_total_size = field_header_size + payload_len;

                    if (current_offset + field_total_size > buffer_len)
                    {
                        result = CTE_ERROR_INSUFFICIENT_DATA;
                    }
                    else
                    {
                        payload_ptr = &buffer[current_offset + field_header_size];
                    }
                }
            }
        }
    }

    if (result == CTE_SUCCESS)
    {
        state->last_decoded_field.type = CTE_FIELD_TYPE_COMMAND_DATA;
        state->last_decoded_field.data.command.length = payload_len;
        state->last_decoded_field.data.command.data = payload_ptr;
        state->last_decoded_field.field_total_size = field_total_size;
    }

    return result;
}

IF_LEA_EXPORT(cte_decoder_get_command_len)
size_t cte_decoder_get_command_len(void *handle)
{
#ifdef SIZE_MAX
    const size_t error_val = SIZE_MAX;
#else

    const size_t error_val = (size_t)-1;
#endif

    if (!handle)
        return error_val;
    cte_decoder_state_t *state = (cte_decoder_state_t *)handle;
    if (state->active != 2)
        return error_val;

    if (state->last_decoded_field.type == CTE_FIELD_TYPE_COMMAND_DATA)
    {
        return state->last_decoded_field.data.command.length;
    }

    return error_val;
}