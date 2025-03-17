#ifndef _SIMPLE_TLS12_HEADERS_HPP_
#define _SIMPLE_TLS12_HEADERS_HPP_

#include <stdint.h>

enum TLS_ContentType : uint8_t {
    CHANGE_CIPHER_SPEC = 20,
    ALERT = 21,
    HANDSHAKE = 22,
    
    APPLICATION_DATA = 23,
};

struct __attribute__ ((__packed__)) ProtocolVersion {
    uint8_t major;
    uint8_t minor;
};

struct __attribute__ ((__packed__)) simple_tls12_app_data {
    enum TLS_ContentType type; // APPLICATION_DATA
    struct ProtocolVersion version; // TLS 1.2: {0x03, 0x03}
    uint16_t net_length; // (!) network endianess
    uint8_t encrypted_app_data[]; // |.| = .length
};

#endif /* _SIMPLE_TLS12_HEADERS_HPP_ */