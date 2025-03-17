#ifndef KEYVISOR_HANDLE_PBPRFX_H 
#define KEYVISOR_HANDLE_PBPRFX_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>

typedef struct prefix_result {
    bool success;
    uint32_t prefix;
} prefix_res_t;

typedef struct write_result {
    bool success;
    uint8_t bytes_written;
} write_res_t;

prefix_res_t read_pb_prefix(uint8_t bytes[], size_t bytes_len, uint8_t *rest_bytes[]);

uint8_t calc_prefix_len(uint64_t msg_len);

write_res_t write_varint(uint8_t *bytes, size_t bytes_len, uint64_t msg_len);

#ifdef __cplusplus
}
#endif

#endif /* KEYVISOR_HANDLE_PBPRFX_H */
