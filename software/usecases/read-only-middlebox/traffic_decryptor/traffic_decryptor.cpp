#include <iostream>
#include <unistd.h>
#include <sys/socket.h>

#include <arpa/inet.h>

#include <assert.h>

#include "traffic_decryptor.h"
#include "traffic_monitor.h"

#include <keyvisor/handle.h>
#include "tcp-connection.h"

#include "sess_info_db.h"

#include <keyvisor/debug_handle.h>
#include <keyvisor/instructions.h>

#include "print-utils.h"

#include "edge_defines.h"


#ifdef USE_OPENSSL_STUB_INSTEAD
#include <openssl/bio.h>
#include <openssl/evp.h>


// use OpenSSL as demo replacement for KeyVisor's HW handles
int openssl_gcm_decrypt(session_handle_t *sess_handle, uint8_t *iv, uint8_t *tag, uint8_t *aad, size_t aad_len, uint8_t *cipher, size_t cipher_len) {
    // debug prints
    printf("AES key: "); print_byte_array(sess_handle->aes_128_key, 16);
    printf("IV: "); print_byte_array(iv, 12);
    printf("tag: "); print_byte_array(tag, 16);
    printf("AAD: "); print_byte_array(aad, aad_len);
    printf("cipher: "); print_byte_array(cipher, cipher_len);

    EVP_CIPHER_CTX *ctx;
    int plaintext_outlen = 2048, dummy_len = 16, ret;
    unsigned char plaintext_outbuf[2048], dummy_buf[16];

    ctx = EVP_CIPHER_CTX_new();
    assert(ctx);
    ret = EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL);
    assert(ret);
    // default IV length is 96 bits
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL);
    /* Initialise key and IV */
    ret = EVP_DecryptInit_ex(ctx, NULL, NULL, sess_handle->aes_128_key, (unsigned char *)iv);
    assert(ret);

    /* Zero or more calls to specify any AAD */
    EVP_DecryptUpdate(ctx, NULL, &plaintext_outlen, aad, aad_len);
    /* Decrypt cipher */
    ret = EVP_DecryptUpdate(ctx, plaintext_outbuf, &plaintext_outlen, (unsigned char *)cipher, cipher_len);
    if(!ret) {
        printf("failed gcm decrypt\n");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    printf("Plaintxt output len: %d\n", plaintext_outlen);
    printf("Plaintext:\n");
    print_byte_array(plaintext_outbuf, plaintext_outlen);

    /* Set tag */
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag);

    /* Finalize */
    ret = EVP_DecryptFinal_ex(ctx, dummy_buf, &dummy_len);
    if (ret <= 0) {
        printf("failed GCM tag verification!\n");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    EVP_CIPHER_CTX_free(ctx);
    return 0;
}

#else

// warning: in-place decryption
int keyvisor_gcm_decrypt(session_handle_t *sess_handle, uint8_t *iv, uint8_t *tag, uint8_t *aad, size_t aad_len, uint8_t *cipher, size_t cipher_len) {
    // debug prints
    printf("IV (%p): ", iv); print_byte_array(iv, 12);
    printf("tag (%p): ", tag); print_byte_array(tag, 16);
    printf("AAD (%p): ", aad); print_byte_array(aad, aad_len);
    printf("cipher (%p): ", cipher); print_byte_array(cipher, cipher_len);

    //printf("handle (%p): ", &sess_handle->handle); print_handle(&sess_handle->handle);

    uint8_t *tmp_buffer = (uint8_t *) malloc(cipher_len);
    assert(tmp_buffer);
    memcpy(tmp_buffer, cipher, cipher_len);

    kv_io_t decrypt_info = {
        .aad = aad,
        .data = tmp_buffer, //cipher,
        .len_aad = aad_len,
        .len_data = cipher_len,
    };
    memcpy(decrypt_info.tag, tag, 16);
    kv_bytes_to_iv(&decrypt_info, iv, 12);

    if (kv_ins_decrypt_data(&decrypt_info, &sess_handle->handle) != KV_SUCCESS) {
        printf("Failed decrypt-verify via handle (warning: cipher might still be overwritten)\n");
        free(tmp_buffer);
        return -1;
    } else {
        printf("Plaintxt output len: %d\n", cipher_len);
        printf("Plaintext:\n");
        print_byte_array(tmp_buffer /*cipher*/, cipher_len);
    }
    free(tmp_buffer);
    return 0;
}

#endif /* USE_OPENSSL_STUB_INSTEAD */


void perform_traffic_decryption(void) {
    std::cout << "Starting interception and decryption of forwarding traffic" << std::endl;

    monitor_tls_traffic();
}
