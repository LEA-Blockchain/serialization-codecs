#include "cte_ixdata.h"
#include "cte_core.h"

#ifdef LEA_ENV
#include <stdlea.h>
#else
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#endif

IF_LEA_EXPORT(cte_encoder_write_index_reference)
int cte_encoder_write_index_reference(void *handle, uint8_t index)
{
    if (!handle)
        return CTE_ERROR_INVALID_ARGUMENT;
    cte_encoder_state_t *state = (cte_encoder_state_t *)handle;
    if (state->active != 1 || index > IXDATA_LEGACY_INDEX_MAX)
        return CTE_ERROR_INVALID_ARGUMENT;
    if (state->current_offset + 1 > state->buffer_capacity)
        return CTE_ERROR_BUFFER_OVERFLOW;
    uint8_t header = TAG_IXDATA | (index << 2) | IXDATA_SUBTYPE_LEGACY_INDEX;
    state->buffer[state->current_offset++] = header;
    return CTE_SUCCESS;
}

IF_LEA_EXPORT(cte_encoder_write_ixdata_zero)
int cte_encoder_write_ixdata_zero(void *handle)
{
    if (!handle)
        return CTE_ERROR_INVALID_ARGUMENT;
    cte_encoder_state_t *state = (cte_encoder_state_t *)handle;
    if (state->active != 1)
        return CTE_ERROR_INVALID_STATE;
    if (state->current_offset + 1 > state->buffer_capacity)
        return CTE_ERROR_BUFFER_OVERFLOW;
    uint8_t header = TAG_IXDATA | (IXDATA_VARINT_SCHEME_ZERO << 2) | IXDATA_SUBTYPE_VARINT;
    state->buffer[state->current_offset++] = header;
    return CTE_SUCCESS;
}

IF_LEA_EXPORT(cte_encoder_write_ixdata_uleb128)
int cte_encoder_write_ixdata_uleb128(void *handle, uint64_t value)
{
    if (!handle)
        return CTE_ERROR_INVALID_ARGUMENT;
    cte_encoder_state_t *state = (cte_encoder_state_t *)handle;
    if (state->active != 1)
        return CTE_ERROR_INVALID_STATE;

    if (state->current_offset + 1 >= state->buffer_capacity)
        return CTE_ERROR_BUFFER_OVERFLOW;

    uint8_t header = TAG_IXDATA | (IXDATA_VARINT_SCHEME_ULEB128 << 2) | IXDATA_SUBTYPE_VARINT;
    size_t leb_bytes_written = 0;
    uint8_t *leb_buf_start = &state->buffer[state->current_offset + 1];
    size_t leb_buf_avail = state->buffer_capacity - (state->current_offset + 1);

    int leb_res = _encode_uleb128(leb_buf_start, leb_buf_avail, value, &leb_bytes_written);
    if (leb_res != CTE_SUCCESS)
        return leb_res;

    state->buffer[state->current_offset++] = header;
    state->current_offset += leb_bytes_written;
    return CTE_SUCCESS;
}

IF_LEA_EXPORT(cte_encoder_write_ixdata_sleb128)
int cte_encoder_write_ixdata_sleb128(void *handle, int64_t value)
{
    if (!handle)
        return CTE_ERROR_INVALID_ARGUMENT;
    cte_encoder_state_t *state = (cte_encoder_state_t *)handle;
    if (state->active != 1)
        return CTE_ERROR_INVALID_STATE;

    if (state->current_offset + 1 >= state->buffer_capacity)
        return CTE_ERROR_BUFFER_OVERFLOW;

    uint8_t header = TAG_IXDATA | (IXDATA_VARINT_SCHEME_SLEB128 << 2) | IXDATA_SUBTYPE_VARINT;
    size_t leb_bytes_written = 0;
    uint8_t *leb_buf_start = &state->buffer[state->current_offset + 1];
    size_t leb_buf_avail = state->buffer_capacity - (state->current_offset + 1);

    int leb_res = _encode_sleb128(leb_buf_start, leb_buf_avail, value, &leb_bytes_written);
    if (leb_res != CTE_SUCCESS)
        return leb_res;

    state->buffer[state->current_offset++] = header;
    state->current_offset += leb_bytes_written;
    return CTE_SUCCESS;
}

static int _cte_encoder_write_ixdata_fixed(void *handle, uint8_t type_code, size_t data_len, const void *data_ptr)
{
    if (!handle)
        return CTE_ERROR_INVALID_ARGUMENT;
    cte_encoder_state_t *state = (cte_encoder_state_t *)handle;
    if (state->active != 1)
        return CTE_ERROR_INVALID_STATE;

    if (state->current_offset + 1 + data_len > state->buffer_capacity)
        return CTE_ERROR_BUFFER_OVERFLOW;

    uint8_t header = TAG_IXDATA | (type_code << 2) | IXDATA_SUBTYPE_FIXED;
    state->buffer[state->current_offset++] = header;

    switch (data_len)
    {
    case 1:
        state->buffer[state->current_offset] = *(uint8_t *)data_ptr;
        break;
    case 2:
        _write_le16(&state->buffer[state->current_offset], *(uint16_t *)data_ptr);
        break;
    case 4:
        _write_le32(&state->buffer[state->current_offset], *(uint32_t *)data_ptr);
        break;
    case 8:
        _write_le64(&state->buffer[state->current_offset], *(uint64_t *)data_ptr);
        break;
    default:
        return CTE_ERROR_INVALID_ARGUMENT;
    }
    state->current_offset += data_len;
    return CTE_SUCCESS;
}

IF_LEA_EXPORT(cte_encoder_write_ixdata_fixed_int8)
int cte_encoder_write_ixdata_fixed_int8(void *handle, int8_t value)
{
    return _cte_encoder_write_ixdata_fixed(handle, IXDATA_FIXED_TYPE_INT8, 1, &value);
}
IF_LEA_EXPORT(cte_encoder_write_ixdata_fixed_int16)
int cte_encoder_write_ixdata_fixed_int16(void *handle, int16_t value)
{
    uint16_t uval = (uint16_t)value;
    return _cte_encoder_write_ixdata_fixed(handle, IXDATA_FIXED_TYPE_INT16, 2, &uval);
}
IF_LEA_EXPORT(cte_encoder_write_ixdata_fixed_int32)
int cte_encoder_write_ixdata_fixed_int32(void *handle, int32_t value)
{
    uint32_t uval = (uint32_t)value;
    return _cte_encoder_write_ixdata_fixed(handle, IXDATA_FIXED_TYPE_INT32, 4, &uval);
}
IF_LEA_EXPORT(cte_encoder_write_ixdata_fixed_int64)
int cte_encoder_write_ixdata_fixed_int64(void *handle, int64_t value)
{
    uint64_t uval = (uint64_t)value;
    return _cte_encoder_write_ixdata_fixed(handle, IXDATA_FIXED_TYPE_INT64, 8, &uval);
}
IF_LEA_EXPORT(cte_encoder_write_ixdata_fixed_uint8)
int cte_encoder_write_ixdata_fixed_uint8(void *handle, uint8_t value)
{
    return _cte_encoder_write_ixdata_fixed(handle, IXDATA_FIXED_TYPE_UINT8, 1, &value);
}
IF_LEA_EXPORT(cte_encoder_write_ixdata_fixed_uint16)
int cte_encoder_write_ixdata_fixed_uint16(void *handle, uint16_t value)
{
    return _cte_encoder_write_ixdata_fixed(handle, IXDATA_FIXED_TYPE_UINT16, 2, &value);
}
IF_LEA_EXPORT(cte_encoder_write_ixdata_fixed_uint32)
int cte_encoder_write_ixdata_fixed_uint32(void *handle, uint32_t value)
{
    return _cte_encoder_write_ixdata_fixed(handle, IXDATA_FIXED_TYPE_UINT32, 4, &value);
}
IF_LEA_EXPORT(cte_encoder_write_ixdata_fixed_uint64)
int cte_encoder_write_ixdata_fixed_uint64(void *handle, uint64_t value)
{
    return _cte_encoder_write_ixdata_fixed(handle, IXDATA_FIXED_TYPE_UINT64, 8, &value);
}
IF_LEA_EXPORT(cte_encoder_write_ixdata_fixed_float32)
int cte_encoder_write_ixdata_fixed_float32(void *handle, float value)
{
    uint32_t uval;
    memcpy(&uval, &value, sizeof(float));
    return _cte_encoder_write_ixdata_fixed(handle, IXDATA_FIXED_TYPE_FLOAT32, 4, &uval);
}
IF_LEA_EXPORT(cte_encoder_write_ixdata_fixed_float64)
int cte_encoder_write_ixdata_fixed_float64(void *handle, double value)
{
    uint64_t uval;
    memcpy(&uval, &value, sizeof(double));
    return _cte_encoder_write_ixdata_fixed(handle, IXDATA_FIXED_TYPE_FLOAT64, 8, &uval);
}

IF_LEA_EXPORT(cte_encoder_write_ixdata_boolean)
int cte_encoder_write_ixdata_boolean(void *handle, uint8_t value)
{
    if (!handle)
        return CTE_ERROR_INVALID_ARGUMENT;
    cte_encoder_state_t *state = (cte_encoder_state_t *)handle;
    if (state->active != 1)
        return CTE_ERROR_INVALID_STATE;
    if (state->current_offset + 1 > state->buffer_capacity)
        return CTE_ERROR_BUFFER_OVERFLOW;
    uint8_t constant_code = value ? IXDATA_CONSTANT_CODE_TRUE : IXDATA_CONSTANT_CODE_FALSE;
    uint8_t header = TAG_IXDATA | (constant_code << 2) | IXDATA_SUBTYPE_CONSTANT;
    state->buffer[state->current_offset++] = header;
    return CTE_SUCCESS;
}

int _cte_decode_ixdata_field(cte_decoder_state_t *state, const uint8_t *buffer, size_t buffer_len,
                             size_t current_offset)
{
    const size_t field_header_size = 1;
    int result = CTE_SUCCESS;
    size_t field_total_size = 0;
    const uint8_t *payload_ptr = NULL;

    if (current_offset + field_header_size > buffer_len)
    {
        return CTE_ERROR_INSUFFICIENT_DATA;
    }

    uint8_t header1 = buffer[current_offset];
    uint8_t subtype = header1 & IXDATA_SUBTYPE_MASK;
    uint8_t subdata = (header1 >> 2) & 0x0F;

    state->last_decoded_field.type = CTE_FIELD_TYPE_IXDATA;
    state->last_decoded_field.data.ixdata.subtype = subtype;
    state->last_decoded_field.data.ixdata.subdata_code = subdata;
    state->last_decoded_field.data.ixdata.leb_byte_count = 0;
    state->last_decoded_field.data.ixdata.fixed_data_ptr = NULL;

    switch (subtype)
    {
    case IXDATA_SUBTYPE_LEGACY_INDEX:
    {
        if (subdata > IXDATA_LEGACY_INDEX_MAX)
        {
            result = CTE_ERROR_INVALID_FORMAT;
            break;
        }
        field_total_size = 1;
        break;
    }
    case IXDATA_SUBTYPE_VARINT:
    {
        uint8_t scheme = subdata;
        if (scheme == IXDATA_VARINT_SCHEME_ZERO)
        {
            state->last_decoded_field.data.ixdata.value.u64 = 0;
            state->last_decoded_field.data.ixdata.value.i64 = 0;
            field_total_size = 1;
        }
        else if (scheme == IXDATA_VARINT_SCHEME_ULEB128)
        {
            size_t leb_bytes = 0;
            if (current_offset + field_header_size >= buffer_len)
            {
                result = CTE_ERROR_INSUFFICIENT_DATA;
                break;
            }
            payload_ptr = &buffer[current_offset + field_header_size];
            size_t remaining_len = buffer_len - (current_offset + field_header_size);

            result = _decode_uleb128(payload_ptr, remaining_len, &state->last_decoded_field.data.ixdata.value.u64,
                                     &leb_bytes);

            if (result == CTE_SUCCESS)
            {
                state->last_decoded_field.data.ixdata.leb_byte_count = (uint8_t)leb_bytes;
                field_total_size = field_header_size + leb_bytes;
            }
        }
        else if (scheme == IXDATA_VARINT_SCHEME_SLEB128)
        {
            size_t leb_bytes = 0;
            if (current_offset + field_header_size >= buffer_len)
            {
                result = CTE_ERROR_INSUFFICIENT_DATA;
                break;
            }
            payload_ptr = &buffer[current_offset + field_header_size];
            size_t remaining_len = buffer_len - (current_offset + field_header_size);

            result = _decode_sleb128(payload_ptr, remaining_len, &state->last_decoded_field.data.ixdata.value.i64,
                                     &leb_bytes);

            if (result == CTE_SUCCESS)
            {
                state->last_decoded_field.data.ixdata.leb_byte_count = (uint8_t)leb_bytes;
                field_total_size = field_header_size + leb_bytes;
            }
        }
        else
        {
            result = CTE_ERROR_INVALID_FORMAT;
        }
        break;
    }
    case IXDATA_SUBTYPE_FIXED:
    {
        uint8_t type_code = subdata;
        size_t data_len = 0;
        switch (type_code)
        {
        case IXDATA_FIXED_TYPE_INT8:
        case IXDATA_FIXED_TYPE_UINT8:
            data_len = 1;
            break;
        case IXDATA_FIXED_TYPE_INT16:
        case IXDATA_FIXED_TYPE_UINT16:
            data_len = 2;
            break;
        case IXDATA_FIXED_TYPE_INT32:
        case IXDATA_FIXED_TYPE_UINT32:
        case IXDATA_FIXED_TYPE_FLOAT32:
            data_len = 4;
            break;
        case IXDATA_FIXED_TYPE_INT64:
        case IXDATA_FIXED_TYPE_UINT64:
        case IXDATA_FIXED_TYPE_FLOAT64:
            data_len = 8;
            break;
        default:
            result = CTE_ERROR_INVALID_FORMAT;
            break;
        }
        if (result != CTE_SUCCESS)
            break;

        field_total_size = field_header_size + data_len;
        if (current_offset + field_total_size > buffer_len)
        {
            result = CTE_ERROR_INSUFFICIENT_DATA;
            break;
        }
        payload_ptr = &buffer[current_offset + field_header_size];
        state->last_decoded_field.data.ixdata.fixed_data_ptr = payload_ptr;

        switch (type_code)
        {
        case IXDATA_FIXED_TYPE_INT8:
            state->last_decoded_field.data.ixdata.value.fixed_val.val_i8 = (int8_t)payload_ptr[0];
            break;
        case IXDATA_FIXED_TYPE_UINT8:
            state->last_decoded_field.data.ixdata.value.fixed_val.val_u8 = payload_ptr[0];
            break;
        case IXDATA_FIXED_TYPE_INT16:
            state->last_decoded_field.data.ixdata.value.fixed_val.val_i16 = (int16_t)_read_le16(payload_ptr);
            break;
        case IXDATA_FIXED_TYPE_UINT16:
            state->last_decoded_field.data.ixdata.value.fixed_val.val_u16 = _read_le16(payload_ptr);
            break;
        case IXDATA_FIXED_TYPE_INT32:
            state->last_decoded_field.data.ixdata.value.fixed_val.val_i32 = (int32_t)_read_le32(payload_ptr);
            break;
        case IXDATA_FIXED_TYPE_UINT32:
            state->last_decoded_field.data.ixdata.value.fixed_val.val_u32 = _read_le32(payload_ptr);
            break;
        case IXDATA_FIXED_TYPE_INT64:
            state->last_decoded_field.data.ixdata.value.fixed_val.val_i64 = (int64_t)_read_le64(payload_ptr);
            break;
        case IXDATA_FIXED_TYPE_UINT64:
            state->last_decoded_field.data.ixdata.value.fixed_val.val_u64 = _read_le64(payload_ptr);
            break;
        case IXDATA_FIXED_TYPE_FLOAT32:
        {
            uint32_t temp = _read_le32(payload_ptr);
            memcpy(&state->last_decoded_field.data.ixdata.value.fixed_val.val_f32, &temp, sizeof(float));
            break;
        }
        case IXDATA_FIXED_TYPE_FLOAT64:
        {
            uint64_t temp = _read_le64(payload_ptr);
            memcpy(&state->last_decoded_field.data.ixdata.value.fixed_val.val_f64, &temp, sizeof(double));
            break;
        }
        }
        break;
    }
    case IXDATA_SUBTYPE_CONSTANT:
    {
        uint8_t const_code = subdata;
        if (const_code == IXDATA_CONSTANT_CODE_FALSE)
        {
            state->last_decoded_field.data.ixdata.value.boolean = 0;
        }
        else if (const_code == IXDATA_CONSTANT_CODE_TRUE)
        {
            state->last_decoded_field.data.ixdata.value.boolean = 1;
        }
        else
        {
            result = CTE_ERROR_INVALID_FORMAT;
            break;
        }
        field_total_size = 1;
        break;
    }
    default:
        result = CTE_ERROR_INVALID_FORMAT;
        break;
    }

    if (result == CTE_SUCCESS)
    {
        state->last_decoded_field.field_total_size = field_total_size;
    }
    return result;
}

IF_LEA_EXPORT(cte_decoder_get_ixdata_legacy_index)
int64_t cte_decoder_get_ixdata_legacy_index(void *handle)
{
    if (!handle)
        return -1;
    cte_decoder_state_t *state = (cte_decoder_state_t *)handle;
    if (state->active != 2)
        return -1;
    if (state->last_decoded_field.type == CTE_FIELD_TYPE_IXDATA &&
        state->last_decoded_field.data.ixdata.subtype == IXDATA_SUBTYPE_LEGACY_INDEX)
    {
        return (int64_t)state->last_decoded_field.data.ixdata.subdata_code;
    }
    return -1;
}

IF_LEA_EXPORT(cte_decoder_get_ixdata_subtype)
int cte_decoder_get_ixdata_subtype(void *handle)
{
    if (!handle)
        return CTE_ERROR_INVALID_ARGUMENT;
    cte_decoder_state_t *state = (cte_decoder_state_t *)handle;
    if (state->active != 2)
        return CTE_ERROR_INVALID_STATE;
    if (state->last_decoded_field.type != CTE_FIELD_TYPE_IXDATA)
        return CTE_ERROR_UNSUPPORTED_TYPE;
    return (int)state->last_decoded_field.data.ixdata.subtype;
}

IF_LEA_EXPORT(cte_decoder_get_ixdata_subdata_code)
int cte_decoder_get_ixdata_subdata_code(void *handle)
{
    if (!handle)
        return CTE_ERROR_INVALID_ARGUMENT;
    cte_decoder_state_t *state = (cte_decoder_state_t *)handle;
    if (state->active != 2)
        return CTE_ERROR_INVALID_STATE;
    if (state->last_decoded_field.type != CTE_FIELD_TYPE_IXDATA)
        return CTE_ERROR_UNSUPPORTED_TYPE;
    return (int)state->last_decoded_field.data.ixdata.subdata_code;
}

IF_LEA_EXPORT(cte_decoder_get_ixdata_varint_scheme)
int cte_decoder_get_ixdata_varint_scheme(void *handle)
{
    if (!handle)
        return CTE_ERROR_INVALID_ARGUMENT;
    cte_decoder_state_t *state = (cte_decoder_state_t *)handle;
    if (state->active != 2)
        return CTE_ERROR_INVALID_STATE;
    if (state->last_decoded_field.type == CTE_FIELD_TYPE_IXDATA &&
        state->last_decoded_field.data.ixdata.subtype == IXDATA_SUBTYPE_VARINT)
    {
        return (int)state->last_decoded_field.data.ixdata.subdata_code;
    }
    return CTE_ERROR_UNSUPPORTED_TYPE;
}

IF_LEA_EXPORT(cte_decoder_get_ixdata_varint_value_u64)
int cte_decoder_get_ixdata_varint_value_u64(void *handle, uint64_t *value)
{
    if (!handle || !value)
        return CTE_ERROR_INVALID_ARGUMENT;
    cte_decoder_state_t *state = (cte_decoder_state_t *)handle;
    if (state->active != 2)
        return CTE_ERROR_INVALID_STATE;

    if (state->last_decoded_field.type == CTE_FIELD_TYPE_IXDATA &&
        state->last_decoded_field.data.ixdata.subtype == IXDATA_SUBTYPE_VARINT)
    {
        uint8_t scheme = state->last_decoded_field.data.ixdata.subdata_code;
        if (scheme == IXDATA_VARINT_SCHEME_ZERO || scheme == IXDATA_VARINT_SCHEME_ULEB128)
        {
            *value = state->last_decoded_field.data.ixdata.value.u64;
            return CTE_SUCCESS;
        }
        else if (scheme == IXDATA_VARINT_SCHEME_SLEB128 && state->last_decoded_field.data.ixdata.value.i64 >= 0)
        {
            *value = (uint64_t)state->last_decoded_field.data.ixdata.value.i64;
            return CTE_SUCCESS;
        }
        else
        {
            return CTE_ERROR_UNSUPPORTED_TYPE;
        }
    }
    return CTE_ERROR_INVALID_STATE;
}

IF_LEA_EXPORT(cte_decoder_get_ixdata_varint_value_i64)
int cte_decoder_get_ixdata_varint_value_i64(void *handle, int64_t *value)
{
    if (!handle || !value)
        return CTE_ERROR_INVALID_ARGUMENT;
    cte_decoder_state_t *state = (cte_decoder_state_t *)handle;
    if (state->active != 2)
        return CTE_ERROR_INVALID_STATE;

    if (state->last_decoded_field.type == CTE_FIELD_TYPE_IXDATA &&
        state->last_decoded_field.data.ixdata.subtype == IXDATA_SUBTYPE_VARINT)
    {
        uint8_t scheme = state->last_decoded_field.data.ixdata.subdata_code;
        if (scheme == IXDATA_VARINT_SCHEME_ZERO || scheme == IXDATA_VARINT_SCHEME_SLEB128)
        {
            *value = state->last_decoded_field.data.ixdata.value.i64;
            return CTE_SUCCESS;
        }
        else if (scheme == IXDATA_VARINT_SCHEME_ULEB128 && (state->last_decoded_field.data.ixdata.value.u64 >> 63) == 0)
        {
            *value = (int64_t)state->last_decoded_field.data.ixdata.value.u64;
            return CTE_SUCCESS;
        }
        else
        {
            return CTE_ERROR_UNSUPPORTED_TYPE;
        }
    }
    return CTE_ERROR_INVALID_STATE;
}

IF_LEA_EXPORT(cte_decoder_get_ixdata_fixed_type_code)
int cte_decoder_get_ixdata_fixed_type_code(void *handle)
{
    if (!handle)
        return CTE_ERROR_INVALID_ARGUMENT;
    cte_decoder_state_t *state = (cte_decoder_state_t *)handle;
    if (state->active != 2)
        return CTE_ERROR_INVALID_STATE;
    if (state->last_decoded_field.type == CTE_FIELD_TYPE_IXDATA &&
        state->last_decoded_field.data.ixdata.subtype == IXDATA_SUBTYPE_FIXED)
    {
        return (int)state->last_decoded_field.data.ixdata.subdata_code;
    }
    return CTE_ERROR_UNSUPPORTED_TYPE;
}

#define GET_IXDATA_FIXED_VALUE(FUNC_NAME, TYPE, TYPE_CODE, FIELD)                                                      \
    IF_LEA_EXPORT(FUNC_NAME) int FUNC_NAME(void *handle, TYPE *value)                                                  \
    {                                                                                                                  \
        if (!handle || !value)                                                                                         \
            return CTE_ERROR_INVALID_ARGUMENT;                                                                         \
        cte_decoder_state_t *state = (cte_decoder_state_t *)handle;                                                    \
        if (state->active != 2)                                                                                        \
            return CTE_ERROR_INVALID_STATE;                                                                            \
        if (state->last_decoded_field.type == CTE_FIELD_TYPE_IXDATA &&                                                 \
            state->last_decoded_field.data.ixdata.subtype == IXDATA_SUBTYPE_FIXED &&                                   \
            state->last_decoded_field.data.ixdata.subdata_code == TYPE_CODE)                                           \
        {                                                                                                              \
            *value = state->last_decoded_field.data.ixdata.value.fixed_val.FIELD;                                      \
            return CTE_SUCCESS;                                                                                        \
        }                                                                                                              \
        return CTE_ERROR_UNSUPPORTED_TYPE;                                                                             \
    }

GET_IXDATA_FIXED_VALUE(cte_decoder_get_ixdata_fixed_value_int8, int8_t, IXDATA_FIXED_TYPE_INT8, val_i8)
GET_IXDATA_FIXED_VALUE(cte_decoder_get_ixdata_fixed_value_int16, int16_t, IXDATA_FIXED_TYPE_INT16, val_i16)
GET_IXDATA_FIXED_VALUE(cte_decoder_get_ixdata_fixed_value_int32, int32_t, IXDATA_FIXED_TYPE_INT32, val_i32)
GET_IXDATA_FIXED_VALUE(cte_decoder_get_ixdata_fixed_value_int64, int64_t, IXDATA_FIXED_TYPE_INT64, val_i64)
GET_IXDATA_FIXED_VALUE(cte_decoder_get_ixdata_fixed_value_uint8, uint8_t, IXDATA_FIXED_TYPE_UINT8, val_u8)
GET_IXDATA_FIXED_VALUE(cte_decoder_get_ixdata_fixed_value_uint16, uint16_t, IXDATA_FIXED_TYPE_UINT16, val_u16)
GET_IXDATA_FIXED_VALUE(cte_decoder_get_ixdata_fixed_value_uint32, uint32_t, IXDATA_FIXED_TYPE_UINT32, val_u32)
GET_IXDATA_FIXED_VALUE(cte_decoder_get_ixdata_fixed_value_uint64, uint64_t, IXDATA_FIXED_TYPE_UINT64, val_u64)
GET_IXDATA_FIXED_VALUE(cte_decoder_get_ixdata_fixed_value_float32, float, IXDATA_FIXED_TYPE_FLOAT32, val_f32)
GET_IXDATA_FIXED_VALUE(cte_decoder_get_ixdata_fixed_value_float64, double, IXDATA_FIXED_TYPE_FLOAT64, val_f64)

IF_LEA_EXPORT(cte_decoder_get_ixdata_constant_code)
int cte_decoder_get_ixdata_constant_code(void *handle)
{
    if (!handle)
        return CTE_ERROR_INVALID_ARGUMENT;
    cte_decoder_state_t *state = (cte_decoder_state_t *)handle;
    if (state->active != 2)
        return CTE_ERROR_INVALID_STATE;
    if (state->last_decoded_field.type == CTE_FIELD_TYPE_IXDATA &&
        state->last_decoded_field.data.ixdata.subtype == IXDATA_SUBTYPE_CONSTANT)
    {
        return (int)state->last_decoded_field.data.ixdata.subdata_code;
    }
    return CTE_ERROR_UNSUPPORTED_TYPE;
}

IF_LEA_EXPORT(cte_decoder_get_ixdata_boolean_value)
int cte_decoder_get_ixdata_boolean_value(void *handle, uint8_t *value)
{
    if (!handle || !value)
        return CTE_ERROR_INVALID_ARGUMENT;
    cte_decoder_state_t *state = (cte_decoder_state_t *)handle;
    if (state->active != 2)
        return CTE_ERROR_INVALID_STATE;

    if (state->last_decoded_field.type == CTE_FIELD_TYPE_IXDATA &&
        state->last_decoded_field.data.ixdata.subtype == IXDATA_SUBTYPE_CONSTANT)
    {
        uint8_t code = state->last_decoded_field.data.ixdata.subdata_code;
        if (code == IXDATA_CONSTANT_CODE_TRUE || code == IXDATA_CONSTANT_CODE_FALSE)
        {
            *value = state->last_decoded_field.data.ixdata.value.boolean;
            return CTE_SUCCESS;
        }
    }
    return CTE_ERROR_UNSUPPORTED_TYPE;
}