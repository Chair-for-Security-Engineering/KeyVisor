#ifndef _CLI_LICENSE_HOST_H_
#define _CLI_LICENSE_HOST_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stddef.h>

int license_client_request_license(int32_t feature_uid, void *out_khandle, size_t *inout_outlen, int32_t *out_counter);

void set_current_feature_uid(int32_t feature_uid);

#ifdef __cplusplus
}
#endif

#endif /* _CLI_LICENSE_HOST_H_ */