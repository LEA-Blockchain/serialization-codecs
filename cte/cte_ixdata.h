#ifndef CTE_IXDATA_H
#define CTE_IXDATA_H

#include "cte_core.h"

#ifdef LEA_ENV
#define IF_LEA_EXPORT(FUNC_NAME) LEA_EXPORT(FUNC_NAME)
#else
#define IF_LEA_EXPORT(FUNC_NAME)
#endif

IF_LEA_EXPORT(cte_encoder_write_index_reference)
int cte_encoder_write_index_reference(void *handle, uint8_t index);

IF_LEA_EXPORT(cte_encoder_write_ixdata_zero)
int cte_encoder_write_ixdata_zero(void *handle);

IF_LEA_EXPORT(cte_encoder_write_ixdata_uleb128)
int cte_encoder_write_ixdata_uleb128(void *handle, uint64_t value);

IF_LEA_EXPORT(cte_encoder_write_ixdata_sleb128)
int cte_encoder_write_ixdata_sleb128(void *handle, int64_t value);

IF_LEA_EXPORT(cte_encoder_write_ixdata_fixed_int8)
int cte_encoder_write_ixdata_fixed_int8(void *handle, int8_t value);

IF_LEA_EXPORT(cte_encoder_write_ixdata_fixed_int16)
int cte_encoder_write_ixdata_fixed_int16(void *handle, int16_t value);

IF_LEA_EXPORT(cte_encoder_write_ixdata_fixed_int32)
int cte_encoder_write_ixdata_fixed_int32(void *handle, int32_t value);

IF_LEA_EXPORT(cte_encoder_write_ixdata_fixed_int64)
int cte_encoder_write_ixdata_fixed_int64(void *handle, int64_t value);

IF_LEA_EXPORT(cte_encoder_write_ixdata_fixed_uint8)
int cte_encoder_write_ixdata_fixed_uint8(void *handle, uint8_t value);

IF_LEA_EXPORT(cte_encoder_write_ixdata_fixed_uint16)
int cte_encoder_write_ixdata_fixed_uint16(void *handle, uint16_t value);

IF_LEA_EXPORT(cte_encoder_write_ixdata_fixed_uint32)
int cte_encoder_write_ixdata_fixed_uint32(void *handle, uint32_t value);

IF_LEA_EXPORT(cte_encoder_write_ixdata_fixed_uint64)
int cte_encoder_write_ixdata_fixed_uint64(void *handle, uint64_t value);

IF_LEA_EXPORT(cte_encoder_write_ixdata_fixed_float32)
int cte_encoder_write_ixdata_fixed_float32(void *handle, float value);

IF_LEA_EXPORT(cte_encoder_write_ixdata_fixed_float64)
int cte_encoder_write_ixdata_fixed_float64(void *handle, double value);

IF_LEA_EXPORT(cte_encoder_write_ixdata_boolean)
int cte_encoder_write_ixdata_boolean(void *handle, uint8_t value);

IF_LEA_EXPORT(cte_decoder_get_ixdata_legacy_index)
int64_t cte_decoder_get_ixdata_legacy_index(void *handle);

IF_LEA_EXPORT(cte_decoder_get_ixdata_subtype)
int cte_decoder_get_ixdata_subtype(void *handle);

IF_LEA_EXPORT(cte_decoder_get_ixdata_subdata_code)
int cte_decoder_get_ixdata_subdata_code(void *handle);

IF_LEA_EXPORT(cte_decoder_get_ixdata_varint_scheme)
int cte_decoder_get_ixdata_varint_scheme(void *handle);

IF_LEA_EXPORT(cte_decoder_get_ixdata_varint_value_u64)
int cte_decoder_get_ixdata_varint_value_u64(void *handle, uint64_t *value);

IF_LEA_EXPORT(cte_decoder_get_ixdata_varint_value_i64)
int cte_decoder_get_ixdata_varint_value_i64(void *handle, int64_t *value);

IF_LEA_EXPORT(cte_decoder_get_ixdata_fixed_type_code)
int cte_decoder_get_ixdata_fixed_type_code(void *handle);

IF_LEA_EXPORT(cte_decoder_get_ixdata_fixed_value_int8)
int cte_decoder_get_ixdata_fixed_value_int8(void *handle, int8_t *value);

IF_LEA_EXPORT(cte_decoder_get_ixdata_fixed_value_int16)
int cte_decoder_get_ixdata_fixed_value_int16(void *handle, int16_t *value);

IF_LEA_EXPORT(cte_decoder_get_ixdata_fixed_value_int32)
int cte_decoder_get_ixdata_fixed_value_int32(void *handle, int32_t *value);

IF_LEA_EXPORT(cte_decoder_get_ixdata_fixed_value_int64)
int cte_decoder_get_ixdata_fixed_value_int64(void *handle, int64_t *value);

IF_LEA_EXPORT(cte_decoder_get_ixdata_fixed_value_uint8)
int cte_decoder_get_ixdata_fixed_value_uint8(void *handle, uint8_t *value);

IF_LEA_EXPORT(cte_decoder_get_ixdata_fixed_value_uint16)
int cte_decoder_get_ixdata_fixed_value_uint16(void *handle, uint16_t *value);

IF_LEA_EXPORT(cte_decoder_get_ixdata_fixed_value_uint32)
int cte_decoder_get_ixdata_fixed_value_uint32(void *handle, uint32_t *value);

IF_LEA_EXPORT(cte_decoder_get_ixdata_fixed_value_uint64)
int cte_decoder_get_ixdata_fixed_value_uint64(void *handle, uint64_t *value);

IF_LEA_EXPORT(cte_decoder_get_ixdata_fixed_value_float32)
int cte_decoder_get_ixdata_fixed_value_float32(void *handle, float *value);

IF_LEA_EXPORT(cte_decoder_get_ixdata_fixed_value_float64)
int cte_decoder_get_ixdata_fixed_value_float64(void *handle, double *value);

IF_LEA_EXPORT(cte_decoder_get_ixdata_constant_code)
int cte_decoder_get_ixdata_constant_code(void *handle);

IF_LEA_EXPORT(cte_decoder_get_ixdata_boolean_value)
int cte_decoder_get_ixdata_boolean_value(void *handle, uint8_t *value);

int _cte_decode_ixdata_field(cte_decoder_state_t *state, const uint8_t *buffer, size_t buffer_len,
                             size_t current_offset);

#endif // CTE_IXDATA_H