#include "cte_siglist.h"
#include "cte_core.h"

#ifdef LEA_ENV
#include <stdlea.h>
#else
#include <stddef.h>
#include <stdint.h>
#endif

IF_LEA_EXPORT(cte_encoder_prepare_signature_list)
uintptr_t cte_encoder_prepare_signature_list(void *handle, uint8_t sig_count, uint8_t type_code)
{
    if (!handle)
        return 0;
    cte_encoder_state_t *state = (cte_encoder_state_t *)handle;

    if (state->active != 1 || sig_count == 0 || sig_count > MAX_LIST_LEN)
        return 0;

    size_t item_size = _get_sig_item_size_from_type(type_code);
    if (item_size == 0)
    {
        return 0;
    }

    size_t header_size = 1;
    size_t data_size = (size_t)sig_count * item_size;

    if (state->current_offset + header_size + data_size > state->buffer_capacity)
        return 0;

    uint8_t header = TAG_SIGNATURE_LIST | (sig_count << 2) | (type_code & CRYPTO_TYPE_CODE_MASK);
    state->buffer[state->current_offset++] = header;

    uintptr_t write_start_ptr = (uintptr_t)&state->buffer[state->current_offset];

    state->current_offset += data_size;

    return write_start_ptr;
}

int _cte_decode_siglist_field(cte_decoder_state_t *state, const uint8_t *buffer, size_t buffer_len,
                              size_t current_offset)
{
    const size_t field_header_size = 1;

    if (current_offset + field_header_size > buffer_len)
    {
        return CTE_ERROR_INSUFFICIENT_DATA;
    }

    uint8_t header1 = buffer[current_offset];
    uint8_t c = (header1 >> 2) & 0x0F;
    uint8_t type_code = header1 & CRYPTO_TYPE_CODE_MASK;

    if (c == 0 || c > MAX_LIST_LEN)
    {
        return CTE_ERROR_INVALID_FORMAT;
    }

    size_t item_size = _get_sig_item_size_from_type(type_code);
    if (item_size == 0)
    {
        return CTE_ERROR_INVALID_CRYPTO_TYPE;
    }

    size_t data_size = (size_t)c * item_size;
    size_t field_total_size = field_header_size + data_size;

    if (current_offset + field_total_size > buffer_len)
    {
        return CTE_ERROR_INSUFFICIENT_DATA;
    }

    const uint8_t *payload_ptr = &buffer[current_offset + field_header_size];

    state->last_decoded_field.type = CTE_FIELD_TYPE_SIGNATURE_LIST;
    state->last_decoded_field.data.sig_list.count = c;
    state->last_decoded_field.data.sig_list.type_code = type_code;
    state->last_decoded_field.data.sig_list.first_item = payload_ptr;
    state->last_decoded_field.field_total_size = field_total_size;

    return CTE_SUCCESS;
}

IF_LEA_EXPORT(cte_decoder_get_siglist_type_code)
int cte_decoder_get_siglist_type_code(void *handle)
{
    if (!handle)
        return CTE_ERROR_INVALID_ARGUMENT;
    cte_decoder_state_t *state = (cte_decoder_state_t *)handle;
    if (state->active != 2)
        return CTE_ERROR_INVALID_STATE;

    if (state->last_decoded_field.type == CTE_FIELD_TYPE_SIGNATURE_LIST)
    {
        return (int)state->last_decoded_field.data.sig_list.type_code;
    }

    return CTE_ERROR_UNSUPPORTED_TYPE;
}