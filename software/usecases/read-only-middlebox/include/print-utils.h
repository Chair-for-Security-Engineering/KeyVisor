#ifndef __KEYVISOR_KEYVALUE_UTILS_H__
#define __KEYVISOR_KEYVALUE_UTILS_H__

#include <stdio.h>
#include <stdint.h>

static inline void print_byte_array(const uint8_t *buf, size_t buf_len) {
    for (size_t i=0; i<buf_len; i++)
        printf("%#x,", buf[i]);
    printf("\n");
}

#endif /* __KEYVISOR_KEYVALUE_UTILS_H__ */
