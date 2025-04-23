#ifndef CTE_H
#define CTE_H

#include <stddef.h>
#include <stdint.h>

#define CTE_VERSION_V1 0x01
#define MAX_CTE_SIZE 1232
#define TAG_MASK 0xC0
#define TAG_PUBLIC_KEY_LIST 0x00
#define TAG_SIGNATURE_LIST 0x40
#define TAG_INDEX_REFERENCE 0x80
#define TAG_COMMAND_DATA 0xC0
#define PUBLIC_KEY_SIZE 32
#define SIGNATURE_SIZE 64
#define MAX_LIST_LEN 15
#define MAX_INDEX 15
#define COMMAND_DATA_SHORT_MAX_LEN 31
#define COMMAND_DATA_EXTENDED_MIN_LEN 32
#define COMMAND_DATA_EXTENDED_MAX_LEN 1197

#define CTE_SUCCESS 0
#define CTE_ERROR_BUFFER_OVERFLOW -1
#define CTE_ERROR_INVALID_ARGUMENT -2
#define CTE_ERROR_INVALID_FORMAT -3
#define CTE_ERROR_INSUFFICIENT_DATA -4
#define CTE_ERROR_INVALID_STATE -5
#define CTE_ERROR_ALLOCATION_FAILED -6
#define CTE_ERROR_END_OF_BUFFER -7

typedef enum
{
    CTE_FIELD_TYPE_UNKNOWN = 0,
    CTE_FIELD_TYPE_VERSION = 1,
    CTE_FIELD_TYPE_PUBKEY_LIST = 2,
    CTE_FIELD_TYPE_SIGNATURE_LIST = 3,
    CTE_FIELD_TYPE_INDEX_REF = 4,
    CTE_FIELD_TYPE_COMMAND_DATA = 5
} cte_field_type_t;

typedef struct
{
    cte_field_type_t type;
    union
    {
        struct
        {
            uint8_t count;
            const uint8_t *first_key;
        } pk_list;
        struct
        {
            uint8_t count;
            const uint8_t *first_signature;
        } sig_list;
        uint8_t index;
        struct
        {
            size_t length;
            const uint8_t *data;
        } command;
    } data;
    size_t field_total_size;
} cte_decoded_field_t;

// Encoder
void *cte_encoder_new();
uintptr_t cte_encoder_prepare_public_key_list(void *handle, uint8_t key_count);
uintptr_t cte_encoder_prepare_signature_list(void *handle, uint8_t sig_count);
int cte_encoder_write_index_reference(void *handle, uint8_t index);
uintptr_t cte_encoder_prepare_command_data(void *handle, size_t payload_len);
uintptr_t cte_encoder_get_buffer_ptr(void *handle);
size_t cte_encoder_get_buffer_size(void *handle);

// Decoder
void *cte_decoder_new();
int cte_decoder_set_input_buffer(void *handle, const uint8_t *buffer_ptr, size_t buffer_len);
int cte_decoder_advance(void *handle);             // Returns type (>=0) or error (<0)
int64_t cte_decoder_get_index_value(void *handle); // Returns index (0-15) or -1 on error/wrong type
uintptr_t cte_decoder_get_data_ptr(void *handle);  // Returns pointer or 0 on error/wrong type
int8_t cte_decoder_get_list_count(void *handle);   // Returns count (1-15) or -1 on error/wrong type
size_t cte_decoder_get_command_len(void *handle);  // Returns length or (size_t)-1 on error/wrong type

#endif // CTE_H