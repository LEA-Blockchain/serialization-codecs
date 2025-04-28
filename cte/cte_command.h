#ifndef CTE_COMMAND_H
#define CTE_COMMAND_H

#include "cte_core.h"

#ifdef LEA_ENV
#define IF_LEA_EXPORT(FUNC_NAME) LEA_EXPORT(FUNC_NAME)
#else
#define IF_LEA_EXPORT(FUNC_NAME)
#endif

IF_LEA_EXPORT(cte_encoder_prepare_command_data)
uintptr_t cte_encoder_prepare_command_data(void *handle, size_t payload_len);

IF_LEA_EXPORT(cte_decoder_get_command_len)
size_t cte_decoder_get_command_len(void *handle);

int _cte_decode_command_field(cte_decoder_state_t *state, const uint8_t *buffer, size_t buffer_len,
                              size_t current_offset);

#endif