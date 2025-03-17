#include "include/kv-storage.h"

#include <stdio.h>
#include <string.h> // memcmp
#include <assert.h>

#include "shared/utils.h"

struct kv_list_entry {
    struct kv_list_entry *next;
};

struct key_value_pair {
    struct kv_list_entry entry;
    s_key_t key;
    uint8_t *value;
    size_t value_len;
};

struct kv_list_entry *kv_list_head;

int kv_init_stub_storage(void) {
    printf("Init stub storage\n");
    kv_list_head = NULL;
    return 0;
}

struct key_value_pair *kv_find_entry_stub_storage(s_key_t query_key) {
    printf("Trying to find entry for key\n");
    if (!kv_list_head) return NULL;

    struct kv_list_entry *curr_entry;

    for(curr_entry = kv_list_head; curr_entry; curr_entry = curr_entry->next) {
        struct key_value_pair *curr_pair = (struct key_value_pair *)curr_entry;
        printf("Current entry:\nkey: ");
        print_byte_array(curr_pair->key.key, curr_pair->key.key_len);
        printf("value: ");
        print_byte_array(curr_pair->value, curr_pair->value_len);

        if (curr_pair->key.key_len != query_key.key_len) continue;
        if (memcmp(curr_pair->key.key, query_key.key, query_key.key_len) != 0) 
            continue;
        // found key
        return curr_pair;
    }
}

int kv_read_from_stub_storage(s_key_t query_key, void *out_buf, size_t *out_len) {
    printf("Reading from storage key: ");
    print_byte_array(query_key.key, query_key.key_len);

    struct key_value_pair *kv_pair = kv_find_entry_stub_storage(query_key);
    if (!kv_pair) return -1;

    // found key
    if (*out_len < kv_pair->value_len) {
        printf("Stored value does not fit into intermediate buffer!");
        return -1;
    }
    *out_len = kv_pair->value_len;
    memcpy(out_buf, kv_pair->value, *out_len);

    printf("read value: ");
    print_byte_array((uint8_t *)out_buf, *out_len);

    return 0;
}

int kv_write_to_stub_storage(s_key_t query_key, void *in_buf, size_t in_len) {
    printf("Writing to storage key: ");
    print_byte_array(query_key.key, query_key.key_len);
    printf("value: ");
    print_byte_array((uint8_t *)in_buf, in_len);

    // already in list?
    struct key_value_pair *kv_pair = kv_find_entry_stub_storage(query_key);
    if (kv_pair) {
        // yes: overwrite value
        free(kv_pair->value);
        kv_pair->value_len = in_len;
        kv_pair->value = malloc(in_len);
        assert(kv_pair->value);
        memcpy(kv_pair->value, in_buf, in_len);
        printf("Overwrote existing entry\n");
        return 0;
    }

    // no: require new entry to list

    struct key_value_pair *new_pair = malloc(sizeof(struct key_value_pair));
    assert(new_pair);

    new_pair->key.key = malloc(query_key.key_len);
    assert(new_pair->key.key);
    memcpy(new_pair->key.key, query_key.key, query_key.key_len);
    new_pair->key.key_len = query_key.key_len;

    new_pair->value = malloc(in_len);
    assert(new_pair->value);
    memcpy(new_pair->value, in_buf, in_len);
    new_pair->value_len = in_len;

    // keep it simple: append to head of list
    new_pair->entry.next = kv_list_head;
    kv_list_head = &new_pair->entry;

    return 0;
}

int kv_destroy_stub_storage(void) {
    printf("Destroy stub storage\n");
    return 0;
}
