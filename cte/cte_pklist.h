#ifndef CTE_PKLIST_H
#define CTE_PKLIST_H

#include "cte_core.h"

#ifdef LEA_ENV
#define IF_LEA_EXPORT(FUNC_NAME) LEA_EXPORT(FUNC_NAME)
#else
#define IF_LEA_EXPORT(FUNC_NAME)
#endif

IF_LEA_EXPORT(cte_encoder_prepare_public_key_list)
uintptr_t cte_encoder_prepare_public_key_list(void *handle, uint8_t key_count, uint8_t type_code);

IF_LEA_EXPORT(cte_decoder_get_pklist_type_code)
int cte_decoder_get_pklist_type_code(void *handle);

int _cte_decode_pklist_field(cte_decoder_state_t *state, const uint8_t *buffer, size_t buffer_len,
                             size_t current_offset);

#endif // CTE_PKLIST_H
