#include <iostream>
#include <unistd.h>
#include <sys/socket.h>
#include <string.h>

#include <arpa/inet.h>

#include <assert.h>

#include "driving_module.h"

#include <keyvisor/handle.h>

#include "../cli_license_host.h"

#include "usock-connection.h"

#include <keyvisor/debug_handle.h>
#include <keyvisor/instructions.h>

#include "print-utils.h"

#include "edge_defines.h"

#include "bus_communication.h"

#ifdef USE_OPENSSL_STUB_INSTEAD
#include <openssl/bio.h>
#include <openssl/evp.h>


// option to use OpenSSL as stub alternative to KeyVisor HW extension
int openssl_gcm_encrypt(const uint8_t *aes_128_key, const uint8_t *in_plaintext, uint8_t *in_iv, uint8_t *out_tag, uint8_t *in_aad, size_t aad_len, uint8_t *out_cipher, size_t in_data_len) {
    // debug prints
    printf("AES key: "); print_byte_array(aes_128_key, 16);
    printf("AAD: "); print_byte_array(in_aad, aad_len);
    printf("IV: "); print_byte_array(in_iv, 12);
    printf("plaintext: "); print_byte_array(in_plaintext, in_data_len);

    EVP_CIPHER_CTX *ctx;
    int cipher_outlen = in_data_len, dummy_len = 16, ret;
    unsigned char dummy_buf[16];

    ctx = EVP_CIPHER_CTX_new();
    assert(ctx);
    ret = EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL);
    assert(ret);
    // default IV length is 96 bits
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL);
    /* Initialise key and IV */
    ret = EVP_EncryptInit_ex(ctx, NULL, NULL, aes_128_key, in_iv);
    assert(ret);

    /* Zero or more calls to specify any AAD */
    EVP_EncryptUpdate(ctx, NULL, &cipher_outlen, in_aad, aad_len);
    /* Encrypt plaintext */
    ret = EVP_EncryptUpdate(ctx, out_cipher, &cipher_outlen, in_plaintext, in_data_len);
    if(!ret) {
        printf("failed gcm encrypt\n");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    assert(cipher_outlen == in_data_len);
    printf("Cipher output len: %d\n", cipher_outlen);
    printf("Cipher:\n");
    print_byte_array(out_cipher, cipher_outlen);

    /* Finalize */
    ret = EVP_EncryptFinal_ex(ctx, dummy_buf, &dummy_len);
    if (ret <= 0) {
        printf("failed GCM tag creation!\n");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    /* Get tag */
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, out_tag);
    printf("tag: "); print_byte_array(out_tag, 16);

    EVP_CIPHER_CTX_free(ctx);
    return 0;
}

#else

// warning: in-place encryption
int keyvisor_gcm_encrypt(const kv_handle_t *key_handle, uint8_t *inout_data, size_t in_data_len, uint8_t *out_iv, uint8_t *out_tag, uint8_t *in_aad, size_t aad_len) {
    // debug prints
    print_handle(key_handle);
    printf("AAD: "); print_byte_array(in_aad, aad_len);
    printf("cipher: "); print_byte_array(inout_data, in_data_len);

    uint8_t *tmp_buffer = (uint8_t *) malloc(in_data_len);
    assert(tmp_buffer);
    memcpy(tmp_buffer, inout_data, in_data_len);


    kv_io_t encrypt_info = {
        .aad = in_aad,
        .data = tmp_buffer, //inout_data,
        .len_aad = aad_len,
        .len_data = in_data_len,
    };

    if (kv_ins_encrypt_data(&encrypt_info, key_handle) != KV_SUCCESS) {
        printf("Failed encrypt-auth via handle (warning: plaintext might still be overwritten\n");
        free(tmp_buffer);
        return -1;
    }
    printf("Plaintext:\n");
    memcpy(inout_data, tmp_buffer, in_data_len);
    print_byte_array(inout_data, in_data_len);

    memcpy(out_tag, encrypt_info.tag, 16);
    kv_iv_to_bytes(&encrypt_info, out_iv, 12);
    printf("IV: "); print_byte_array(out_iv, 12);
    printf("tag: "); print_byte_array(out_tag, 16);

    free(tmp_buffer);
    return 0;
}

#endif /* USE_OPENSSL_STUB_INSTEAD */

const int32_t DEMO_FEATURE_UID = 4711;

void run_driving_module(void) {
    // call into enclave-host module to request feature license via enclave
    set_current_feature_uid(DEMO_FEATURE_UID); // expose to enclave
    int32_t usage_counter;
#ifdef USE_OPENSSL_STUB_INSTEAD
    uint8_t feature_key[16];
    size_t outbuf_len = sizeof(feature_key);
    if (0 != license_client_request_license(DEMO_FEATURE_UID, feature_key, &outbuf_len, &usage_counter)) {
        printf("Failed receiving feature license via license client enclave\n");
        return;
    }
#else
    kv_handle_t feature_khandle;
    size_t outbuf_len = sizeof(kv_handle_t);
    if (0 != license_client_request_license(DEMO_FEATURE_UID, (uint8_t *)&feature_khandle, &outbuf_len, &usage_counter)) {
        printf("Failed receiving feature license via license client enclave\n");
        return;
    }
#endif

    // connect to motor unit (UNIX domain socket)
    int cli_sock = kv_create_client_socket();
    if (cli_sock < 0) {
        printf("Failed connecting to motor unit\n");
        return;
    }

    // send feature request to receive the nonce
    uint8_t challenge_nonce[12];
    size_t nonce_size = sizeof(challenge_nonce);
    if (request_feature_nonce(cli_sock, DEMO_FEATURE_UID, challenge_nonce, &nonce_size) != 0) {
        printf("Failed receiving challenge nonce from motor unit\n");
        close(cli_sock);
        return;
    }

    // use the feature key/handle ++ nonce to auth-encrypt the feature uid
    int32_t data_buffer = DEMO_FEATURE_UID;
    uint8_t iv[12];
    uint8_t tag[16];
    int ret;
#ifdef USE_OPENSSL_STUB_INSTEAD
    // TODO: generate random IV
    iv[0] = iv[1] = iv[2] = iv[3] = iv[4] = iv[5] = 0xFA;
    iv[6] = iv[7] = iv[8] = iv[9] = iv[10] = iv[11] = 0xAF;
    ret = openssl_gcm_encrypt(feature_key, (const uint8_t *)&DEMO_FEATURE_UID, iv, tag, challenge_nonce, nonce_size, (uint8_t *)&data_buffer, sizeof(data_buffer));
#else
    ret = keyvisor_gcm_encrypt(&feature_khandle, (uint8_t *)&data_buffer, sizeof(data_buffer), iv, tag, challenge_nonce, nonce_size);
#endif
    if (ret != 0) {
        printf("Failed encrypting feature activation request\n");
        close(cli_sock);
        return;
    }

    // send (cipher, iv, tag) to the motor unit
    // wait for final response
    if (send_feature_enable_request(cli_sock, (uint8_t *)&data_buffer, sizeof(data_buffer), iv, sizeof(iv), tag, sizeof(tag)) != 0) {
        printf("Failed sending feature-activation request to motor unit\n");
    } else {
        printf("Successfully sent feature-activation request. See above print message for result\n");
    }

    close(cli_sock);
}
