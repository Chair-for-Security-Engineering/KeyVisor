#ifndef _CAR_SHARED_KEY_H_
#define _CAR_SHARED_KEY_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

static uint8_t shared_car_vendor_key_128aes[16] = {
  0xFA, 0xFA, 0xFA, 0xFA, 0xFA, 0xFA, 0xFA, 0xFA,
  0xFA, 0xFA, 0xFA, 0xFA, 0xFA, 0xFA, 0xFA, 0xFA,
};

#ifdef __cplusplus
}
#endif

#endif /* _CAR_SHARED_KEY_H_ */