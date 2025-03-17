#ifndef __KEYVISOR_KEYVALUE_KV_STORAGE_H__
#define __KEYVISOR_KEYVALUE_KV_STORAGE_H__

#include <stdlib.h>
#include <stdint.h>

typedef struct storage_key {
    size_t key_len;
    uint8_t *key;
} s_key_t;

int kv_init_stub_storage(void);
int kv_read_from_stub_storage(s_key_t storage_key, void *out_buf, size_t *out_len);
int kv_write_to_stub_storage(s_key_t storage_key, void *in_buf, size_t in_len);
int kv_destroy_stub_storage(void);

#endif /* __KEYVISOR_KEYVALUE_KV_STORAGE_H__ */
