#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cte.h"

void print_hex(const char *prefix, const uint8_t *buffer, size_t len)
{
    if (!buffer)
    {
        printf("%s[NULL buffer]\n", prefix);
        return;
    }
    printf("%s[%zu bytes]: ", prefix, len);
    for (size_t i = 0; i < len; ++i)
    {
        printf("%02X ", buffer[i]);
    }
    printf("\n");
}

int main()
{
    int result_or_type;
    void *encoder_handle = NULL;
    void *decoder_handle = NULL;
    uintptr_t encoder_buffer_offset = 0;
    size_t final_size = 0;
    uintptr_t write_location_offset = 0;
    uint8_t *write_ptr = NULL;
    uint8_t *final_encoded_data_ptr = NULL;

    uint8_t pk_count = 2;
    uint8_t sig_count = 1;
    uint8_t index_value = 1;
    const char *cmd_payload_str = "Test Payload!";
    size_t command_len = strlen(cmd_payload_str);
    uint8_t pub_key1[PUBLIC_KEY_SIZE];
    memset(pub_key1, 0x11, sizeof(pub_key1));
    uint8_t pub_key2[PUBLIC_KEY_SIZE];
    memset(pub_key2, 0x22, sizeof(pub_key2));
    uint8_t signature1[SIGNATURE_SIZE];
    memset(signature1, 0xAA, sizeof(signature1));

    encoder_handle = cte_encoder_new();
    printf("cte_encoder_new() -> Handle: %p\n", encoder_handle);
    if (!encoder_handle)
    {
        fprintf(stderr, "Encoder New failed!\n");
        return 1;
    }

    write_location_offset = cte_encoder_prepare_public_key_list(encoder_handle, pk_count);
    printf("cte_encoder_prepare_public_key_list(handle, %u) -> Write Start Offset: %p\n", pk_count,
           (void *)write_location_offset);
    if (!write_location_offset)
    {
        fprintf(stderr, "Prepare PK List failed!\n");
        return 1;
    }
    write_ptr = (uint8_t *)write_location_offset;
    memcpy(write_ptr, pub_key1, PUBLIC_KEY_SIZE);
    write_ptr += PUBLIC_KEY_SIZE;
    memcpy(write_ptr, pub_key2, PUBLIC_KEY_SIZE);

    write_location_offset = cte_encoder_prepare_signature_list(encoder_handle, sig_count);
    printf("cte_encoder_prepare_signature_list(handle, %u) -> Write Start Offset: %p\n", sig_count,
           (void *)write_location_offset);
    if (!write_location_offset)
    {
        fprintf(stderr, "Prepare Sig List failed!\n");
        return 1;
    }
    write_ptr = (uint8_t *)write_location_offset;
    memcpy(write_ptr, signature1, SIGNATURE_SIZE);

    result_or_type = cte_encoder_write_index_reference(encoder_handle, index_value);
    printf("cte_encoder_write_index_reference(handle, %u) -> %d\n", index_value, result_or_type);
    if (result_or_type != CTE_SUCCESS)
    {
        fprintf(stderr, "Write Index Ref failed: %d\n", result_or_type);
        return 1;
    }

    write_location_offset = cte_encoder_prepare_command_data(encoder_handle, command_len);
    printf("cte_encoder_prepare_command_data(handle, len=%zu) -> Write Start Offset: %p\n", command_len,
           (void *)write_location_offset);
    if (!write_location_offset)
    {
        fprintf(stderr, "Prepare Command Data failed!\n");
        return 1;
    }
    write_ptr = (uint8_t *)write_location_offset;
    memcpy(write_ptr, cmd_payload_str, command_len);

    encoder_buffer_offset = cte_encoder_get_buffer_ptr(encoder_handle);
    final_size = cte_encoder_get_buffer_size(encoder_handle);
    printf("cte_encoder_get_buffer_ptr(handle) -> %p\n", (void *)encoder_buffer_offset);
    printf("cte_encoder_get_buffer_size(handle) -> %zu\n", final_size);

    if (!encoder_buffer_offset)
    {
        fprintf(stderr, "Get Buffer failed!\n");
        return 1;
    }
    if (final_size != 146)
    {
        fprintf(stderr, "ERROR: Final size mismatch! Expected 146, Got %zu\n", final_size);
    }

    final_encoded_data_ptr = (uint8_t *)encoder_buffer_offset;
    print_hex("Encoded Data", final_encoded_data_ptr, final_size);

    decoder_handle = cte_decoder_new();
    printf("cte_decoder_new() -> Handle: %p\n", decoder_handle);
    if (!decoder_handle)
    {
        fprintf(stderr, "Decoder New failed!\n");
        return 1;
    }

    result_or_type = cte_decoder_set_input_buffer(decoder_handle, final_encoded_data_ptr, final_size);
    printf("cte_decoder_set_input_buffer(handle, ptr=%p, size=%zu) -> %d\n", (void *)final_encoded_data_ptr, final_size,
           result_or_type);
    if (result_or_type != CTE_SUCCESS)
    {
        fprintf(stderr, "Decoder Set Input Buffer failed!\n");
        return 1;
    }

    while (1)
    {
        result_or_type = cte_decoder_advance(decoder_handle);
        printf("cte_decoder_advance(handle) -> %d\n", result_or_type);

        if (result_or_type == CTE_ERROR_END_OF_BUFFER)
        {
            printf("End of buffer reached cleanly.\n");
            break;
        }
        if (result_or_type < CTE_SUCCESS)
        {
            fprintf(stderr, "Decoding failed with error %d\n", result_or_type);
            return 1;
        }

        cte_field_type_t field_type = (cte_field_type_t)result_or_type;
        printf("Decoded Field Type: %d\n", field_type);

        switch (field_type)
        {
        case CTE_FIELD_TYPE_PUBKEY_LIST:
        {
            uintptr_t ptr = cte_decoder_get_data_ptr(decoder_handle);
            int8_t count = cte_decoder_get_list_count(decoder_handle);
            printf("PK List: Count=%d, FirstKeyPtr=%p %s\n", count, (void *)ptr, ptr ? "" : "(NULL!)");
            if (ptr && count > 0)
                printf("(Data[0]=0x%02X)\n", ((uint8_t *)ptr)[0]);
            break;
        }
        case CTE_FIELD_TYPE_SIGNATURE_LIST:
        {
            uintptr_t ptr = cte_decoder_get_data_ptr(decoder_handle);
            int8_t count = cte_decoder_get_list_count(decoder_handle);
            printf("Sig List: Count=%d, FirstSigPtr=%p %s\n", count, (void *)ptr, ptr ? "" : "(NULL!)");
            if (ptr && count > 0)
                printf("(Data[0]=0x%02X)\n", ((uint8_t *)ptr)[0]);
            break;
        }
        case CTE_FIELD_TYPE_INDEX_REF:
        {
            int64_t value = cte_decoder_get_index_value(decoder_handle);
            printf("Index Ref: Value=%lld\n", (long long)value);
            break;
        }
        case CTE_FIELD_TYPE_COMMAND_DATA:
        {
            uintptr_t ptr = cte_decoder_get_data_ptr(decoder_handle);
            size_t len = cte_decoder_get_command_len(decoder_handle);
            printf("Command Data: Length=%zu, DataPtr=%p %s\n", len, (void *)ptr, (len > 0 && !ptr) ? "(NULL!)" : "");
            if (len > 0 && ptr)
            {
                printf("Payload Preview: \"%.*s\"\n", (int)len, (const char *)ptr);
            }
            break;
        }
        default:
            printf("Unknown type encountered: %d\n", field_type);
            break;
        }
    }

    printf("\nTest Complete\n");
    return 0;
}