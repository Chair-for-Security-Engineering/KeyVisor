#ifndef __KEYVISOR_KEY_HANDLE_HELPERS_H__
#define __KEYVISOR_KEY_HANDLE_HELPERS_H__

#include "./instructions.h"
#include "./handle.h"

#include <stdlib.h>
#include <string.h> // memcpy
#include <assert.h>

/// @brief assumes cpu key already loaded (TODO: process binding?)
/// @param aes_128_key key to be wrapped
/// @param crypto_attributes of handle (enc/dec)
/// @param usage_ctr usage counter (or 0 if disable)
/// @param ext_attr_flags additional flags, e.g., for self-binding
/// @return key handle (NULL on failure)
kv_handle_t *kv_create_key_handle_ext(const void *aes_128_key, uint8_t crypto_attributes, uint8_t usage_ctr, uint8_t ext_attr_flags) {
    assert(aes_128_key);
    kv_handle_t *whandle = (kv_handle_t *) calloc(1, sizeof(kv_handle_t));
    assert(whandle);

    kv_wrap_t wrapper_attributes = {
        .privileges = KV_PERMIT_PRIV_USER | KV_PERMIT_PRIV_SUPERVISOR | KV_PERMIT_PRIV_MACHINE, // allow usage by anyone for the moment
        .aes_mode = KV_ALGORITHM_GCM,

        .crypto_attributes = crypto_attributes,
        .ext_attr_flags = ext_attr_flags,

        // set below
        .exattr_map = 0,
        .usage_ctr = 0,

        // not used
        .lifetime_ticks = 0,
        .pID = 0,
    };

    // enable usage counter if requested
    if (usage_ctr > 0) {
        wrapper_attributes.usage_ctr = usage_ctr;
        wrapper_attributes.exattr_map = KV_ENABLE_USAGE_COUNTER;
    }

    // enable binding is self-bind requested
    if (ext_attr_flags & KV_SELF_BIND) {
        wrapper_attributes.exattr_map |= KV_ENABLE_PE_BINDING;
    }

    memcpy(wrapper_attributes.AES_key, aes_128_key, sizeof(wrapper_attributes.AES_key));

    if (kv_ins_wrap_key(&wrapper_attributes, whandle) != KV_SUCCESS) {
        //printf("Failed wrapping key in write-only handle\n");
        free(whandle);
        return NULL;
    }

    return whandle;
}

/// @brief assumes cpu key already loaded (TODO: process binding?)
/// @param crypto_attributes of handle (enc/dec)
/// @return key handle (NULL on failure)
kv_handle_t *kv_create_key_handle(const void *aes_128_key, uint8_t crypto_attributes) {
    return kv_create_key_handle_ext(aes_128_key, crypto_attributes, 0, 0);
}

/// @brief assumes cpu key already loaded (TODO: process binding?)
/// @return write-only key handle (NULL on failure)
kv_handle_t *kv_create_write_only_handle(const void *aes_128_key) {
    return kv_create_key_handle(aes_128_key, KV_PERMIT_ENCRYPT);
}

/// @brief assumes cpu key already loaded (TODO: process binding?)
/// @return key handle (NULL on failure)
kv_handle_t *kv_create_selfbound(const void *aes_128_key) {
    return kv_create_key_handle_ext(aes_128_key, KV_PERMIT_ENCRYPT|KV_PERMIT_DECRYPT, 0, KV_SELF_BIND);
}

#endif /* __KEYVISOR_KEY_HANDLE_HELPERS_H__ */
