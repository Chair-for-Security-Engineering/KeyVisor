#ifndef __KEYVISOR_DEBUG_HANDLE_H__
#define __KEYVISOR_DEBUG_HANDLE_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <stdio.h>
#include "handle.h"

static inline void print_handle(const struct handle* myhandle){
    printf("##### Handle [%lx%lx]  #####\n", myhandle->iv_high, myhandle->iv_low);
    printf("Handle Flags: %u\n", myhandle->attr_flags);
    printf("Privilege: %u\n", myhandle->privileges);
    printf("Algorithm: %u\n", myhandle->crypto_algo);
    printf("Crypto Attributes: %x\n", myhandle->crypto_attr);
    printf("Feature Map: %x\n", myhandle->exattr_map);
    printf("Timestamp: %lx\n", myhandle->timestamp);
    printf("Reserved Bits (should be 0): %x\n", myhandle->reserved);
    printf("IV: %lx%lx\n", myhandle->iv_high, myhandle->iv_low);
    printf("AES GCM TAG: %lx %lx\n", myhandle->AES_GCM_TAG[0], myhandle->AES_GCM_TAG[1]);
    printf("AES GCM CT: %lx %lx\n", myhandle->AES_GCM_CT[0], myhandle->AES_GCM_CT[1]);
    printf("##############################################\n");
}

static inline void print_io(const struct io_struct* io){
    printf("##### Enc/ Dec Data ####\n");
    printf("LenAAD: %d, LenDATA: %d\n", io->len_aad, io->len_data);
    printf("IV:  %#lx, %#lx\n", io->iv_high, io->iv_low);
    printf("Tag: %#lx %#lx\n", io->tag[1], io->tag[0]);
    printf("AAD:\n");
    for(int i = 0; i < io->len_aad; i++){
        printf("%#x ", io->aad[i]);
    }
    printf("\nData:\n");
    for(int i = 0; i < io->len_data; i++){
        printf("%#x ", io->data[i]);
    }
    printf("\n########################\n");
}

#ifdef __cplusplus
}
#endif

#endif /* __KEYVISOR_DEBUG_HANDLE_H__ */
