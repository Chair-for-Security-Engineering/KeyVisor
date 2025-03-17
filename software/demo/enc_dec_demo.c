#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../include/keyvisor/rocc.h"
#include "../include/keyvisor/instructions.h"
#include "../include/keyvisor/handle.h"
#include "../include/keyvisor/debug_handle.h"

#define RUNS 16

// Demo User Key
uint8_t key[16] = {0xac, 0xb0, 0x82, 0x1d, 0x71, 0x4f, 0xa2, 0xa6, 0xd2, 0xed, 0xa6, 0x8e, 0x1e, 0x6f, 0x27, 0x53};

// This function returns a random bytestream of length num_bytes
unsigned char *gen_rdm_bytestream (size_t num_bytes)
{
  unsigned char *stream = calloc (num_bytes+16, 1);
  size_t i;
  for (i = 0; i < num_bytes; i++)
  {
    stream[i] = 0xFF-i;//rand();
  }
  return stream;
}

int main(void)
{
    printf("+ Started KeyVisor Demo\n");
    uint64_t result;
    int fails = 0;

    // We need to set the visor key since firesim does not have randomness available. This is only for demonstration purposes 
    // and this instruciton MUST NOT be enabled in real-world scenarios
    result = LOADCPUKEY(0x0C0FFE000C0FFE00, 0x0C0FFE000C0FFE00);

    
    // Allocate memory for handlegen and the handle itself
    struct wrap_data *handlegen_struct = (struct wrap_data*) malloc(sizeof(struct wrap_data));
    struct handle *handle = (struct handle*) malloc(sizeof(struct handle));

    // Set the handlegen option s
    memcpy((uint8_t*) handlegen_struct->AES_key, key, 16); // Set AES User Key
    handlegen_struct->privileges = 8; // Machine Mode for Bare Metal simulator 
    handlegen_struct->aes_mode = 0; // Don't care, we only support AES GCM currently
    handlegen_struct->usage_ctr = 0; // Usage CTR Value (disabled)
    handlegen_struct->crypto_attributes = 3; // Allow enc and dec
    handlegen_struct->exattr_map = 0; // No Special restrictions for this handle
    handlegen_struct->ext_attr_flags = 0; // No Special restrictions for this handle
    handlegen_struct->lifetime_ticks = 0; // Don't care for now
    handlegen_struct->pID = 0; // Process binding is disabled by the flags above
    handlegen_struct->pmp_id = 0; // PMP binding is disabled by the flags above

    
    printf("+ Creating Key Handle\n");
    result = WRAPKEY(handlegen_struct, handle);

    switch(result){
        case 5: 
            printf("No CPU Key set. Aborting.\n"); return 0;
        case 4: 
            printf("This error should not occur.\n"); return 0;
        case 3:
            printf("SRAM is full.\n"); return 0;
        case 2:
            printf("Not enough entrpy\n"); return 0;
        case 1: 
            printf("IO Failure\n"); return 0;
        case 0:
            break;
        default:
            printf("Unknown retrun value: %d.\n", result); return 0;
    }
    
    // We can now start encrypting stuff.
    struct io_struct *aes_io = (struct io_struct*) malloc(sizeof(struct io_struct));

    for(int i=1; i<=RUNS;i++){
        // Generate random testvectors
        int aad_len = i<<2;
        aes_io->len_aad = aad_len;
        aes_io->aad = gen_rdm_bytestream(aes_io->len_aad);
        
        int ct_len = i<<2;
        aes_io->len_data = ct_len;
        aes_io->data = gen_rdm_bytestream(aes_io->len_data);
        
        char* plaintext = malloc(aes_io->len_data);
        memcpy(plaintext, aes_io->data, aes_io->len_data);
        uint64_t tag[2] = {0xFF, 0xFF};

        printf("+ Testing Encryption %4d / %d.\b Data Len: %d, AAD Len: %d\n", i, RUNS, aes_io->len_aad, aes_io->len_data);
        fflush(stdout);

        // Do the encryption using the handle
        result = ENCRYPT(aes_io, handle);
        
        switch(result){
            case 3:
                printf("The handle was revoked.\n"); 
                fails ++;
                break;
            case 2: 
                printf("The permission check failed during encryption.\n");
                fails++;
                break;
            case 1:
                printf("IO Failure during encryption\n");
                fails++;
                break;
            case 0: break;
            default:
                printf("Unknown return value from encryption.\n");
                fails ++;
                break;
        }

        // Print the results
        printf("\t+ Encryption done; IV: %lx %lx; \n\t\tCT: ", aes_io->iv_high, aes_io->iv_low);
        for (int i =0; i<aes_io->len_data; i++)
        {
            printf("%x ", aes_io->data[i]);
        }
        printf("\n");
        printf("\t\tGCM Auth Tag: ");
        for (int i =0; i<aes_io->len_data; i++)
        {
            printf("%x ", ((uint8_t*)(aes_io->tag))[i]);
        }
        printf("\n");

        // Store the tag and check if the ciphertext is different from the plaintext
        tag[1] = aes_io->tag[1];
        tag[0] = aes_io->tag[0];
        if(memcmp(plaintext, aes_io->data, aes_io->len_data) == 0){
            printf("! FAIL: Plaintext unchanged after encryption.\n");
            fails++;
        }

        // Do the decryption
        result = DECRYPT(aes_io, handle);
        switch(result){
            case 4:
                printf("! FAIL: The tag was invalid.\n"); 
                fails++;
                break;
            case 3:
                printf("! FAIL: The handle was revoked.\n"); 
                fails ++;
                break;
            case 2: 
                printf("! FAIL: The permission check failed during decryption.\n");
                fails++;
                break;
            case 1:
                printf("! FAIL: IO Failure during decryption\n");
                fails++;
                break;
            case 0: break;
            default:
                printf("! FAIL: Unknown return value from decryption: %d.\n", result);
                fails ++;
                break;
        }
        printf("\t+ Decryption done.\n\t\tPT: ");
        for (int i =0; i<aes_io->len_data; i++)
        {
            printf("%x ", aes_io->data[i]);
        }
        printf("\n");

        // Check if the tag matches
        if(aes_io->tag[0] != tag[0] || aes_io->tag[1] != tag[1]){
            printf("! FAIL: Encryption test failed.\nTag does not match %lx %lx != %lx %lx\n", aes_io->tag[0],  aes_io->tag[1], tag[0], tag[1]);
            fails++;
        }

        // Check if the plaintext matches
        if(memcmp(plaintext, aes_io->data, aes_io->len_data)){
            printf("Decrypted plaintext is incorrect. Data Len %d, AAD Len %d\n", aes_io->len_data, aes_io->len_aad);
            fails++;
            for (int i =0; i<aes_io->len_data; i++)
            {
                printf("%x %x \n", plaintext[i], aes_io->data[i]);
            }
        }
        if(!fails){
            printf("\t+ Test Successful, decrypted plaintext is correct and tags match.\n");
        }
        
        free(aes_io->aad);
        free(aes_io->data);
        free(plaintext);

        if(fails > 0){
            break;
        }
    }
    if(!fails){
        printf("+++ All tests finished successfully! +++\n");
    }

    return 0;
}
