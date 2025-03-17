#include <stdio.h>

#include "handle_pb_prefix.h"

/* read protobuf prefix from bytes array
 * bytes: byte array containing prefix|msg
 * bytes_len: length of byte array
 * rest_bytes: address of array pointer; on success, will be set to pointer that points in at the position inside bytes[] where the <msg> starts, i.e., at the first byte position after the read prefix */
prefix_res_t read_pb_prefix(uint8_t bytes[], size_t bytes_len, uint8_t *rest_bytes[]) {
    if (bytes == NULL || rest_bytes == NULL || bytes_len == 0) {
        return (prefix_res_t){false, 0};
    }
    size_t idx = 0;
    uint8_t b = bytes[idx++]; // byte0
    if ((b & 0x80) == 0) {
        *rest_bytes = &bytes[idx];
        return (prefix_res_t){true, (uint32_t)b};
    }
    uint32_t ret = (uint32_t)(b & 0x7f);
    
    if (bytes_len < 2) return (prefix_res_t){false, 0};

    b = bytes[idx++]; // byte1
    ret |= ((uint32_t)(b & 0x7f)) << 7;
    if ((b & 0x80) == 0) {
        *rest_bytes = &bytes[idx];
        return (prefix_res_t){true, ret};
    }

    if (bytes_len < 3) return (prefix_res_t){false, 0};

    b = bytes[idx++]; // byte2
    ret |= ((uint32_t)(b & 0x7f)) << 14;
    if ((b & 0x80) == 0) {
        *rest_bytes = &bytes[idx];
        return (prefix_res_t){true, ret};
    }

    if (bytes_len < 4) return (prefix_res_t){false, 0};

    b = bytes[idx++]; // byte3
    ret |= ((uint32_t)(b & 0x7f)) << 21;
    if ((b & 0x80) == 0) {
        *rest_bytes = &bytes[idx];
        return (prefix_res_t){true, ret};
    }

    if (bytes_len < 5) return (prefix_res_t){false, 0};

    b = bytes[idx++]; // byte4
    ret |= ((uint32_t)(b & 0xf)) << 28; // silently prevent overflow; only mask 0xF
    if ((b & 0x80) == 0) {
        // WARNING ABOUT TRUNCATION
        //
        // In this case, byte4 takes the form 0ZZZ_YYYY where:
        //     Y: part of the resulting 32-bit number
        //     Z: beyond 32 bits (excess bits,not used)
        //
        // If the Z bits were set, it might indicate that the number being
        // decoded was intended to be bigger than 32 bits, suggesting an
        // error somewhere else.
        //
        // THIS FUNCTION SIMPLY IGNORES THE EXTRA BITS, WHICH IS
        // ESSENTIALLY A SILENT TRUNCATION!
        *rest_bytes = &bytes[idx];
        return (prefix_res_t){true, ret};
    }

    // ANOTHER WARNING ABOUT TRUNCATION
    //
    // Again, we do not check whether the byte representation fits within 32
    // bits, and simply ignore extra bytes, CONSTITUTING A SILENT
    // TRUNCATION!
    //
    // Therefore, if the user wants this function to avoid ignoring any
    // bits/bytes, they need to ensure that the input is a varint
    // representing a value within EITHER u32 OR i32 range. Since at this
    // point we are beyond 5 bits, the only possible case is a negative i32
    // (since negative numbers are always 10 bytes in protobuf). We must
    // have exactly 5 bytes more to go.
    //
    // Since we know it must be a negative number, and this function is
    // meant to read 32-bit ints (there is a different function for reading
    // 64-bit ints), the user might want to take care to ensure that this
    // negative number is within valid i32 range, i.e. at least
    // -2,147,483,648. Otherwise, this function simply ignores the extra
    // bits, essentially constituting a silent truncation!
    //
    // What this means in the end is that the user should ensure that the
    // resulting number, once decoded from the varint format, takes such a
    // form:
    //
    // 11111111_11111111_11111111_11111111_1XXXXXXX_XXXXXXXX_XXXXXXXX_XXXXXXXX
    // ^(MSB bit 63)                       ^(bit 31 is set)                  ^(LSB bit 0)

    // discards up to 5 extra bytes
    for (size_t j=0; j<5; j++) {
        if (bytes_len < (6+j)) {
            return (prefix_res_t){false, 0};
        }
        if ((bytes[idx++] & 0x80) == 0) {
            *rest_bytes = &bytes[idx];
            return (prefix_res_t){true, ret};
        }
    }

    // cannot read more than 10 bytes
    return (prefix_res_t){false, 0};
}
/* calculate the number of bytes needed to save msg_len*/
uint8_t calc_prefix_len(uint64_t msg_len) {
    int idx = 0;
    while(msg_len > 0x7F) {
        msg_len >>= 7;
        idx++;
    }
    return idx+1;
}

/* write protobuf prefix to bytes array
 * bytes: byte array that will contain prefix|msg
 * bytes_len: length of byte array
 * msg_len: length of msg to write as a prefix */
write_res_t write_varint(uint8_t *bytes, size_t bytes_len, uint64_t msg_len) {
    int idx = 0;
    while(msg_len > 0x7F) {
        if(bytes_len - idx < 1) return (write_res_t){false, 0};
        bytes[idx] = (((uint8_t) msg_len) & 0x7F) | 0x80;
        msg_len >>= 7;
        idx++;
    }
    bytes[idx] = (uint8_t) msg_len;
    return (write_res_t){true, idx};
}
