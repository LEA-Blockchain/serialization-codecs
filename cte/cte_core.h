#ifndef CTE_CORE_H
#define CTE_CORE_H

#ifdef LEA_ENV
#include <stdlea.h>
#else
#include <stddef.h>
#include <stdint.h>
#endif

// CTE Definitions
#define CTE_VERSION_V1 0x02
#define MAX_CTE_SIZE 1232
#define TAG_MASK 0xC0
#define TAG_PUBLIC_KEY_LIST 0x00
#define TAG_SIGNATURE_LIST 0x40
#define TAG_IXDATA 0x80
#define TAG_COMMAND_DATA 0xC0
#define MAX_LIST_LEN 15

// LIP-0002: Crypto Type Codes (Bits 1-0 of Tag 00/01 Header)
#define CRYPTO_TYPE_CODE_MASK 0x03
// Public Key List (Tag 00) Type Codes
#define CTE_CRYPTO_TYPE_ED25519 0x00
#define CTE_CRYPTO_TYPE_SLH_SHA2_128F 0x01
#define CTE_CRYPTO_TYPE_SLH_SHA2_192F 0x02
#define CTE_CRYPTO_TYPE_SLH_SHA2_256F 0x03
// Signature List (Tag 01) Type Codes
#define CTE_SIG_TYPE_ED25519 0x00              // Full Signature
#define CTE_SIG_TYPE_SLH_SHA2_128F_HASH32 0x01 // BLAKE3 Hash not Full Signature 
#define CTE_SIG_TYPE_SLH_SHA2_192F_HASH32 0x02 // ...
#define CTE_SIG_TYPE_SLH_SHA2_256F_HASH32 0x03 // ...

// LIP-0002: Crypto Item Sizes
#define ED25519_PUBLIC_KEY_SIZE 32
#define ED25519_SIGNATURE_SIZE 64
#define PQC_PUBKEY_SLH128F_SIZE 32
#define PQC_PUBKEY_SLH192F_SIZE 48
#define PQC_PUBKEY_SLH256F_SIZE 64
#define PQC_SIG_HASH_SIZE 32

// LIP-0001: IxData Definitions
#define MAX_LEB128_BYTES 10

#define IXDATA_SUBTYPE_MASK 0x03
#define IXDATA_SUBTYPE_LEGACY_INDEX 0x00
#define IXDATA_SUBTYPE_VARINT 0x01
#define IXDATA_SUBTYPE_FIXED 0x02
#define IXDATA_SUBTYPE_CONSTANT 0x03

#define IXDATA_LEGACY_INDEX_MAX 15

#define IXDATA_VARINT_SCHEME_MASK 0x0F
#define IXDATA_VARINT_SCHEME_ZERO 0x00
#define IXDATA_VARINT_SCHEME_ULEB128 0x01
#define IXDATA_VARINT_SCHEME_SLEB128 0x02

#define IXDATA_FIXED_TYPE_MASK 0x0F
#define IXDATA_FIXED_TYPE_INT8 0x00
#define IXDATA_FIXED_TYPE_INT16 0x01
#define IXDATA_FIXED_TYPE_INT32 0x02
#define IXDATA_FIXED_TYPE_INT64 0x03
#define IXDATA_FIXED_TYPE_UINT8 0x04
#define IXDATA_FIXED_TYPE_UINT16 0x05
#define IXDATA_FIXED_TYPE_UINT32 0x06
#define IXDATA_FIXED_TYPE_UINT64 0x07
#define IXDATA_FIXED_TYPE_FLOAT32 0x08
#define IXDATA_FIXED_TYPE_FLOAT64 0x09

#define IXDATA_CONSTANT_CODE_MASK 0x0F
#define IXDATA_CONSTANT_CODE_FALSE 0x00
#define IXDATA_CONSTANT_CODE_TRUE 0x01

#define COMMAND_DATA_SHORT_MAX_LEN 31
#define COMMAND_DATA_EXTENDED_MIN_LEN 32
#define COMMAND_DATA_EXTENDED_MAX_LEN 1197 // Max payload

// Error Codes
#define CTE_SUCCESS 0
#define CTE_ERROR_BUFFER_OVERFLOW -1
#define CTE_ERROR_INVALID_ARGUMENT -2
#define CTE_ERROR_INVALID_FORMAT -3
#define CTE_ERROR_INSUFFICIENT_DATA -4
#define CTE_ERROR_INVALID_STATE -5
#define CTE_ERROR_ALLOCATION_FAILED -6
#define CTE_ERROR_END_OF_BUFFER -7
#define CTE_ERROR_LEB_OVERFLOW -8
#define CTE_ERROR_UNSUPPORTED_TYPE -9
#define CTE_ERROR_INVALID_CRYPTO_TYPE -10

typedef enum
{
    CTE_FIELD_TYPE_UNKNOWN = 0,
    CTE_FIELD_TYPE_VERSION = 1,
    CTE_FIELD_TYPE_PUBKEY_LIST = 2,
    CTE_FIELD_TYPE_SIGNATURE_LIST = 3,
    CTE_FIELD_TYPE_IXDATA = 4,
    CTE_FIELD_TYPE_COMMAND_DATA = 5
} cte_field_type_t;

// Decoded Field Structure
typedef struct
{
    cte_field_type_t type;
    union
    {
        struct
        {
            uint8_t count;
            uint8_t type_code;
            const uint8_t *first_key;
        } pk_list;
        struct
        {
            uint8_t count;
            uint8_t type_code;
            const uint8_t *first_item;
        } sig_list;
        struct
        {
            uint8_t subtype;
            uint8_t subdata_code;
            union
            {
                int64_t i64;
                uint64_t u64;
                union
                {
                    int8_t val_i8;
                    int16_t val_i16;
                    int32_t val_i32;
                    int64_t val_i64;
                    uint8_t val_u8;
                    uint16_t val_u16;
                    uint32_t val_u32;
                    uint64_t val_u64;
                    float val_f32;
                    double val_f64;
                    uint8_t raw_bytes[8];
                } fixed_val;
                uint8_t boolean; // Changed from bool to uint8_t
            } value;
            uint8_t leb_byte_count;
            const uint8_t *fixed_data_ptr;
        } ixdata;
        struct
        {
            size_t length;
            const uint8_t *data;
        } command;
    } data;
    size_t field_total_size;
} cte_decoded_field_t;

typedef struct
{
    uint8_t active; // 0 = inactive, 1 = encoding active
    uint8_t *buffer;
    size_t buffer_capacity;
    size_t current_offset;
} cte_encoder_state_t;

typedef struct
{
    uint8_t active; // 0 = inactive, 2 = decoding active
    const uint8_t *decode_buffer_ptr;
    size_t decode_buffer_len;
    size_t decode_current_offset;
    cte_decoded_field_t last_decoded_field;
} cte_decoder_state_t;

void *cte_encoder_new();
void *cte_decoder_new();
int cte_decoder_set_input_buffer(void *handle, const uint8_t *buffer_ptr, size_t buffer_len);
int cte_decoder_advance(void *handle);
uintptr_t cte_encoder_get_buffer_ptr(void *handle);
size_t cte_encoder_get_buffer_size(void *handle);

int8_t cte_decoder_get_list_count(void *handle);
uintptr_t cte_decoder_get_data_ptr(void *handle);

int _encode_uleb128(uint8_t *buf, size_t buf_size, uint64_t value, size_t *bytes_written);
int _decode_uleb128(const uint8_t *buf, size_t buf_len, uint64_t *value, size_t *bytes_read);
int _encode_sleb128(uint8_t *buf, size_t buf_size, int64_t value, size_t *bytes_written);
int _decode_sleb128(const uint8_t *buf, size_t buf_len, int64_t *value, size_t *bytes_read);

void _write_le16(uint8_t *buf, uint16_t val);
void _write_le32(uint8_t *buf, uint32_t val);
void _write_le64(uint8_t *buf, uint64_t val);
uint16_t _read_le16(const uint8_t *buf);
uint32_t _read_le32(const uint8_t *buf);
uint64_t _read_le64(const uint8_t *buf);

size_t _get_pk_size_from_type(uint8_t type_code);
size_t _get_sig_item_size_from_type(uint8_t type_code);

#endif // CTE_CORE_H