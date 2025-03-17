#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <assert.h>
#include <sys/socket.h>

#include "../car-bus-msg.pb-c.h"

#include "car_shared_key.h"

#include "shared/usock-connection.h"

#include "external/handle_pb_prefix.h"

#include "print-utils.h"

#include "mbedtls/config.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/error.h"
#include "mbedtls/debug.h"
#include "mbedtls/gcm.h"


static volatile int keepListening = 1;

static mbedtls_entropy_context entropy;
static mbedtls_ctr_drbg_context ctr_drbg;
static char *personalization = "motor_unit_drbg_seed";


/// @brief tell server loop to stop on sigint
/// @param unused 
void intSigHandler(int unused) {
    (void)unused;
    keepListening = 0;
}

// TODO: check return values of function calls
int derive_feature_key(uint32_t feature_uid, uint8_t *out_ftr_key, size_t *inout_keylen) {
    assert(out_ftr_key && inout_keylen && *inout_keylen >= 16);

    const mbedtls_md_type_t alg = MBEDTLS_MD_SHA256;
    unsigned char out[MBEDTLS_MD_MAX_SIZE]; // safe but not optimal

    mbedtls_md_context_t ctx;
    mbedtls_md_init(&ctx);

     /* prepare context and load key */
    // the last argument to setup is 1 to enable HMAC (not just hashing)
    const mbedtls_md_info_t *info = mbedtls_md_info_from_type(alg);
    mbedtls_md_setup(&ctx, info, 1);
    mbedtls_md_hmac_starts(&ctx, shared_car_vendor_key_128aes, sizeof(shared_car_vendor_key_128aes));

    /* compute HMAC(key, feature_uid) */
    mbedtls_md_hmac_update(&ctx, (uint8_t *)&feature_uid, sizeof(feature_uid));
    mbedtls_md_hmac_finish(&ctx, out);
    
    size_t out_len = mbedtls_md_get_size(info);
    printf("hmac: "); print_byte_array(out, out_len);

    // discard 128 of 256 bits (TOOD: read in internet to be done, but unsure if secure)
    assert(out_len >= *inout_keylen);
    memcpy(out_ftr_key, out, 16);
    *inout_keylen = 16;
    printf("resulting ftr key: "); print_byte_array(out_ftr_key, 16);

    mbedtls_md_free(&ctx);
    mbedtls_platform_zeroize(out, sizeof(out));

    return 0;
}

// generate nonce, send nonce back
int process_feature_request(int cli_fd, uint32_t *out_feature_uid, uint8_t *out_nonce, size_t *inout_nonce_size) {
    assert(out_nonce && inout_nonce_size && *inout_nonce_size>0);
    uint8_t io_buf[4096];
    ssize_t n_io;
    n_io = recv(cli_fd, io_buf, sizeof(io_buf), 0);
    if (n_io < 0) {
        perror("Receive error");
        return -1;
    }

    uint8_t *msg_start;
    prefix_res_t result;
    result = read_pb_prefix(io_buf, n_io, &msg_start);
    if(!result.success) {
        printf("Failed to read protobuf prefix\n");
        return -1;
    }

    // Unpack new message into malloc() region (NULL->system alloactor)
    CarBusMsgProto__InitFeatureRequest *msg = car_bus_msg_proto__init_feature_request__unpack(NULL, result.prefix, msg_start);
    if (!msg) {
        printf("Failed unpacking incoming feature initialization request\n");
        return -1;
    }
    printf("Client requested feature: %d\n", msg->feature_uid);
    *out_feature_uid = msg->feature_uid;

    car_bus_msg_proto__init_feature_request__free_unpacked(msg, NULL);

    // Generate nonce
    if (mbedtls_ctr_drbg_random( &ctr_drbg, out_nonce, *inout_nonce_size ) != 0) {
        printf("Failed nonce generation\n");
        return -1;
    }


    // Send nonce back
    CarBusMsgProto__InitFeatureResponse resp = CAR_BUS_MSG_PROTO__INIT_FEATURE_RESPONSE__INIT;
    resp.status = CAR_BUS_MSG_PROTO__REQUEST_STATUS__REQUEST_SUCCESS;
    resp.req_nonce.len = *inout_nonce_size;
    resp.req_nonce.data = out_nonce; // TODO: will it get free'd by protobuf?!?!

    size_t resp_len = car_bus_msg_proto__init_feature_response__get_packed_size(&resp);
    uint8_t resp_prfx_len = calc_prefix_len(resp_len);

    write_varint(io_buf, sizeof(io_buf), resp_len);
    car_bus_msg_proto__init_feature_response__pack(&resp, &io_buf[resp_prfx_len]);

    n_io = send(cli_fd, io_buf, resp_prfx_len + resp_len, 0);
    if (n_io < (resp_prfx_len + resp_len)) {
        printf("Sending nonce response back failed (sent: %ld)\n", n_io);
        return -1;
    }

    return 0;
}


int decrypt_verify_feature_request(const uint8_t *ftr_key, size_t keylen, const uint8_t *nonce, size_t nonce_size, const uint8_t *iv, size_t iv_len, const uint8_t *tag, size_t tag_len, const uint8_t *auth_token, size_t token_len) {
    assert(ftr_key && keylen == 16 && nonce && nonce_size > 0 && iv && iv_len == 12 && tag && tag_len == 16 && auth_token && token_len > 0);

    // debug prints
    printf("ftr-key: "); print_byte_array(ftr_key, keylen);
    printf("nonce: "); print_byte_array(nonce, nonce_size);
    printf("iv: "); print_byte_array(iv, iv_len);
    printf("tag: "); print_byte_array(tag, tag_len);
    printf("auth_token (cipher): "); print_byte_array(auth_token, token_len);

    mbedtls_gcm_context ctx;

    uint8_t *output = malloc(token_len);
    if(!output) {
        printf("OOM while allocating decrypt buffer\n");
        return -1;
    }
    
    mbedtls_gcm_init(&ctx);

    // key (key size is specified in bits, not bytes!)
    mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, ftr_key, keylen * 8);

    int ret = mbedtls_gcm_auth_decrypt ( &ctx,
        token_len,
        iv, iv_len,
        // using nonce as AAD for implicit checking
        nonce, nonce_size,
        tag, tag_len,
        auth_token,
        output
    );

    mbedtls_gcm_free(&ctx);

    switch (ret) {
        case 0: {
            break;
        }

        case MBEDTLS_ERR_GCM_AUTH_FAILED: {
            printf("Decrypt-verify of token failed: TAG does not match\n");
            free(output);
            return -1;
        }

        case MBEDTLS_ERR_GCM_BAD_INPUT: {
            printf("Decrypt-verify of token failed: lenghts or pointers are not valid\n");
            free(output);
            return -1;
        }

        default: {
            printf("Decrypt-verify failed, error code: %d\n", ret);
            free(output);
            return -1;
        }
    }

    // TODO: could parse command plaintext in `output`

    printf("Token and nonce are valid\n");

    free(output);
    return 0;
}



int process_feature_activate_request(int cli_fd, uint32_t feature_uid, const uint8_t *nonce, size_t nonce_size) {
    assert(nonce && nonce_size>0);
    uint8_t io_buf[4096];
    ssize_t n_io;
    n_io = recv(cli_fd, io_buf, sizeof(io_buf), 0);
    if (n_io < 0) {
        perror("Receive error");
        return -1;
    }

    uint8_t *msg_start;
    prefix_res_t result;
    result = read_pb_prefix(io_buf, n_io, &msg_start);
    if(!result.success) {
        printf("Failed to read protobuf prefix\n");
        return -1;
    }

    // Unpack new message into malloc() region (NULL->system alloactor)
    CarBusMsgProto__ActivateFeatureRequest *msg = car_bus_msg_proto__activate_feature_request__unpack(NULL, result.prefix, msg_start);
    if (!msg) {
        printf("Failed unpacking incoming feature activation request\n");
        return -1;
    }


    // KDF feature key
    printf("feature uid: %d\n", feature_uid);
    uint8_t ftr_key[16];
    size_t keylen = sizeof(ftr_key);
    if (derive_feature_key(feature_uid, ftr_key, &keylen) != 0) {
        printf("Failed deriving feature-specific key\n");
        return -1;
    }
 
    bool request_granted = false;

    if (decrypt_verify_feature_request(ftr_key, keylen, nonce, nonce_size,
        msg->token_iv.data, msg->token_iv.len,
        msg->token_tag.data, msg->token_tag.len,
        msg->auth_token.data, msg->auth_token.len) != 0) {

        printf("Authentication token is invalid, rejecting request\n");
        request_granted = false;
    } else {
        printf("Authentication token is valid, activating feature\n");
        request_granted = true;
    }

    car_bus_msg_proto__activate_feature_request__free_unpacked(msg, NULL);


    // Send outcome back
    CarBusMsgProto__ActivateFeatureResponse resp = CAR_BUS_MSG_PROTO__ACTIVATE_FEATURE_RESPONSE__INIT;
    if (request_granted) {
        resp.status = CAR_BUS_MSG_PROTO__REQUEST_STATUS__REQUEST_SUCCESS;
    } else {
        resp.status = CAR_BUS_MSG_PROTO__REQUEST_STATUS__REQUEST_FAILED;
    }

    size_t resp_len = car_bus_msg_proto__activate_feature_response__get_packed_size(&resp);
    uint8_t resp_prfx_len = calc_prefix_len(resp_len);

    write_varint(io_buf, sizeof(io_buf), resp_len);
    car_bus_msg_proto__activate_feature_response__pack(&resp, &io_buf[resp_prfx_len]);

    n_io = send(cli_fd, io_buf, resp_prfx_len + resp_len, 0);
    if (n_io < (resp_prfx_len + resp_len)) {
        printf("Sending activation response back failed (sent: %ld)\n", n_io);
        return -1;
    }

    return 0;
}


int main() {
    printf("Starting motor unit:\n");

    mbedtls_entropy_init( &entropy );
    mbedtls_ctr_drbg_init( &ctr_drbg );

    if (0 != mbedtls_ctr_drbg_seed( &ctr_drbg , mbedtls_entropy_func, &entropy,
        (const unsigned char *) personalization, strlen( personalization ) )) {
        printf("Failed initialization of mbedTLS randomness\n");
        return EXIT_FAILURE;
    }

    struct sigaction int_stopper;
    memset(&int_stopper, 0, sizeof(int_stopper));
    int_stopper.sa_handler = intSigHandler;
    if (sigaction(SIGINT, &int_stopper, NULL) < 0) {
        printf("Failed setting up sigint handler\n");
        return EXIT_FAILURE;
    }

    // server based on UNIX domain socket
    int srv_sock = kv_create_server_socket();
    if (srv_sock < 0) {
        printf("Failed creating server socket\n");
        return EXIT_FAILURE;
    }

    while (keepListening) {
        printf("Listening for client ...\n");
        int cli_fd = accept(srv_sock, NULL, NULL);
        if (cli_fd < 0) {
            perror("Failed accepting client");
            continue;
        }
        printf("Accepted client\n");

        // Wait for feature enable request, generate + send nonce
        int32_t feature_uid;
        uint8_t ftr_nonce[12];
        size_t nonce_len = sizeof(ftr_nonce);
        if (process_feature_request(cli_fd, &feature_uid, ftr_nonce, &nonce_len) < 0) {
            printf("Failed receiving feature request and nonce response.\n");
            close(cli_fd);
            continue;
        }
        printf("generated nonce for feature %d: ", feature_uid);
        print_byte_array(ftr_nonce, nonce_len);

        // Wait for cipher(feature, nonce)
        // Try to decrypt-verify and check nonce
        // Reply with result status (enabled/disabled or failure/sucess)
        if (process_feature_activate_request(cli_fd, feature_uid, ftr_nonce, nonce_len) != 0) {
            printf("Failed receiving activation request or authentication checks\n");
            close(cli_fd);
        }

        printf("Finished feature activation. Closing client connection\n");
        close(cli_fd);
    } 

    close(srv_sock);
    unlink(KV_SRV_SOCK_PATH);
    return EXIT_SUCCESS;
}
