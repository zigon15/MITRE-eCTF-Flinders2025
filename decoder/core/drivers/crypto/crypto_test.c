#include "crypto.h"
#include <string.h>

//---------- Public Function Definitions ----------//

/** @brief Tests CMAC implementation
 *
 * @return 0 if all test pass, 1 if any test fails
 */
int crypto_test_CMAC(void){   
    printf("@TEST CRYPTO->CMAC:\n");

    uint8_t fail = 0;

    // AES-256 key from RFC4493 Appendix D.3:
    // 603deb1015ca71be2b73aef0857d7781 1f352c073b6108d72d9810a30914dff4
    uint8_t key_256[32] = {
        0x60, 0x3d, 0xeb, 0x10,
        0x15, 0xca, 0x71, 0xbe,
        0x2b, 0x73, 0xae, 0xf0,
        0x85, 0x7d, 0x77, 0x81,
        0x1f, 0x35, 0x2c, 0x07,
        0x3b, 0x61, 0x08, 0xd7,
        0x2d, 0x98, 0x10, 0xa3,
        0x09, 0x14, 0xdf, 0xf4
    };

    uint8_t cmac[16];
    int ret;

    // --- Test Vector 1: Zero-length message ---
    // Expected: 028962f61b7bf89efc6b551f4667d983
    uint8_t expected1[16] = {
        0x02, 0x89, 0x62, 0xf6,
        0x1b, 0x7b, 0xf8, 0x9e,
        0xfc, 0x6b, 0x55, 0x1f,
        0x46, 0x67, 0xd9, 0x83
    };

    printf("\n");
    ret = crypto_AES_CMAC(key_256, MXC_AES_256BITS, NULL, 0, cmac);
    if (ret != 0) {
        printf("-{E} Test 1 error: %d\n", ret);
        fail = 1;
    } else {
        printf("-{I} Test 1 CMAC: ");
        crypto_print_hex(cmac, 16);
        if (memcmp(cmac, expected1, 16) == 0)
            printf("-{I} Test 1 PASSED\n");
        else {
            printf("-{E} Test 1 FAILED. Expected: ");
            crypto_print_hex(expected1, 16);
            fail = 1;
        }
    }

    // --- Test Vector 2: 16-byte message ---
    // Message: 6bc1bee22e409f96e93d7e117393172a
    // Expected: 28a7023f452e8f82bd4bf28d8c37c35c
    uint8_t test2[16] = {
        0x6b, 0xc1, 0xbe, 0xe2,
        0x2e, 0x40, 0x9f, 0x96,
        0xe9, 0x3d, 0x7e, 0x11,
        0x73, 0x93, 0x17, 0x2a
    };
    uint8_t expected2[16] = {
        0x28, 0xa7, 0x02, 0x3f,
        0x45, 0x2e, 0x8f, 0x82,
        0xbd, 0x4b, 0xf2, 0x8d,
        0x8c, 0x37, 0xc3, 0x5c
    };

    printf("\n");
    ret = crypto_AES_CMAC(key_256, MXC_AES_256BITS, test2, sizeof(test2), cmac);
    if (ret != 0) {
        printf("-{E} Test 2 error: %d\n", ret);
        fail = 1;
    } else {
        printf("-{I} Test 2 CMAC: ");
        crypto_print_hex(cmac, 16);
        if (memcmp(cmac, expected2, 16) == 0)
            printf("-{I} Test 2 PASSED\n");
        else {
            printf("-{E} Test 2 FAILED. Expected: ");
            crypto_print_hex(expected2, 16);
            fail = 1;
        }
    }

    // --- Test Vector 3: 40-byte message ---
    // Message: Concatenation of:
    //   6bc1bee22e409f96e93d7e117393172a
    //   ae2d8a571e03ac9c9eb76fac45af8e51
    //   30c81c46a35ce411
    // Expected: aaf3d8f1de5640c232f5b169b9c911e6
    uint8_t test3[40] = {
        0x6b,0xc1,0xbe,0xe2, 0x2e,0x40,0x9f,0x96,
        0xe9,0x3d,0x7e,0x11, 0x73,0x93,0x17,0x2a,
        0xae,0x2d,0x8a,0x57, 0x1e,0x03,0xac,0x9c,
        0x9e,0xb7,0x6f,0xac, 0x45,0xaf,0x8e,0x51,
        0x30,0xc8,0x1c,0x46, 0xa3,0x5c,0xe4,0x11
    };
    uint8_t expected3[16] = {
        0xaa, 0xf3, 0xd8, 0xf1,
        0xde, 0x56, 0x40, 0xc2,
        0x32, 0xf5, 0xb1, 0x69,
        0xb9, 0xc9, 0x11, 0xe6
    };

    printf("\n");
    ret = crypto_AES_CMAC(key_256, MXC_AES_256BITS, test3, sizeof(test3), cmac);
    if (ret != 0) {
        printf("-{E} Test 3 error: %d\n", ret);
        fail = 1;
    } else {
        printf("-{I} Test 3 CMAC: ");
        crypto_print_hex(cmac, 16);
        if (memcmp(cmac, expected3, 16) == 0)
            printf("-{I} Test 3 PASSED\n");
        else {
            printf("-{E} Test 3 FAILED. Expected: ");
            crypto_print_hex(expected3, 16);
            fail = 1;
        }
    }

    // --- Test Vector 4: 64-byte message ---
    // Message: Concatenation of:
    //   6bc1bee22e409f96e93d7e117393172a
    //   ae2d8a571e03ac9c9eb76fac45af8e51
    //   30c81c46a35ce411
    //   e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710
    // Expected: e1992190549f6ed5696a2c056c315410
    uint8_t test4[64] = {
        0x6b,0xc1,0xbe,0xe2, 0x2e,0x40,0x9f,0x96,
        0xe9,0x3d,0x7e,0x11, 0x73,0x93,0x17,0x2a,
        0xae,0x2d,0x8a,0x57, 0x1e,0x03,0xac,0x9c,
        0x9e,0xb7,0x6f,0xac, 0x45,0xaf,0x8e,0x51,
        0x30,0xc8,0x1c,0x46, 0xa3,0x5c,0xe4,0x11,
        0xe5,0xfb,0xc1,0x19, 0x1a,0x0a,0x52,0xef,
        0xf6,0x9f,0x24,0x45, 0xdf,0x4f,0x9b,0x17,
        0xad,0x2b,0x41,0x7b, 0xe6,0x6c,0x37,0x10
    };
    uint8_t expected4[16] = {
        0xe1, 0x99, 0x21, 0x90,
        0x54, 0x9f, 0x6e, 0xd5,
        0x69, 0x6a, 0x2c, 0x05,
        0x6c, 0x31, 0x54, 0x10
    };

    printf("\n");
    ret = crypto_AES_CMAC(key_256, MXC_AES_256BITS, test4, sizeof(test4), cmac);
    if (ret != 0) {
        printf("-{E} Test 4 error: %d\n", ret);
        fail = 1;
    } else {
        printf("-{I} Test 4 CMAC: ");
        crypto_print_hex(cmac, 16);
        if (memcmp(cmac, expected4, 16) == 0)
            printf("-{I} Test 4 PASSED\n");
        else {
            printf("-{E} Test 4 FAILED. Expected: ");
            crypto_print_hex(expected4, 16);
            fail = 1;
        }
    }

    if(fail){
        printf("-FAIL\n\n");
    }else{
        printf("-PASS\n\n");
    }

    return fail;
}

int crypto_test_AES_ECB(void) {
    printf("@TEST CRYPTO->AES_ECB:\n");

    // AES-128 Test Vectors
    // key=2b7e151628aed2a6abf7158809cf4f3c
    uint8_t key_128[] = {
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
    };

    // Set 1 vector 1
    // mode=aes-128
    // plain=6bc1bee22e409f96e93d7e117393172a
    // cipher=3ad77bb40d7a3660a89ecaf32466ef97
    uint8_t plaintext_128_1[] = {
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
        0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a
    };
    uint8_t expected_ciphertext_128_1[] = {
        0x3a, 0xd7, 0x7b, 0xb4, 0x0d, 0x7a, 0x36, 0x60,
        0xa8, 0x9e, 0xca, 0xf3, 0x24, 0x66, 0xef, 0x97
    };

    // Set 1 vector 2
    // mode=aes-128
    // plain=ae2d8a571e03ac9c9eb76fac45af8e51
    // cipher=f5d3d58503b9699de785895a96fdbaaf
    uint8_t plaintext_128_2[] = {
        0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
        0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51
    };
    uint8_t expected_ciphertext_128_2[] = {
        0xf5, 0xd3, 0xd5, 0x85, 0x03, 0xb9, 0x69, 0x9d,
        0xe7, 0x85, 0x89, 0x5a, 0x96, 0xfd, 0xba, 0xaf
    };

    // Set 1 vector 3
    // mode=aes-128
    // plain=30c81c46a35ce411e5fbc1191a0a52ef
    // cipher=43b1cd7f598ece23881b00e3ed030688
    uint8_t plaintext_128_3[] = {
        0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11,
        0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef
    };
    uint8_t expected_ciphertext_128_3[] = {
        0x43, 0xb1, 0xcd, 0x7f, 0x59, 0x8e, 0xce, 0x23,
        0x88, 0x1b, 0x00, 0xe3, 0xed, 0x03, 0x06, 0x88
    };

    // Set 1 vector 4
    // mode=aes-128
    // plain=f69f2445df4f9b17ad2b417be66c3710
    // cipher=7b0c785e27e8ad3f8223207104725dd4
    uint8_t plaintext_128_4[] = {
        0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17,
        0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10
    };
    uint8_t expected_ciphertext_128_4[] = {
        0x7b, 0x0c, 0x78, 0x5e, 0x27, 0xe8, 0xad, 0x3f,
        0x82, 0x23, 0x20, 0x71, 0x04, 0x72, 0x5d, 0xd4
    };

    // AES-192 Test Vectors
    // key=8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b
    uint8_t key_192[] = {
        0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52,
        0xc8, 0x10, 0xf3, 0x2b, 0x80, 0x90, 0x79, 0xe5,
        0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b
    };

    // Set 2 vector 1
    // mode=aes-192
    // plain=6bc1bee22e409f96e93d7e117393172a
    // cipher=bd334f1d6e45f25ff712a214571fa5cc
    uint8_t plaintext_192_1[] = {
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
        0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a
    };
    uint8_t expected_ciphertext_192_1[] = {
        0xbd, 0x33, 0x4f, 0x1d, 0x6e, 0x45, 0xf2, 0x5f,
        0xf7, 0x12, 0xa2, 0x14, 0x57, 0x1f, 0xa5, 0xcc
    };

    // Set 2 vector 2
    // mode=aes-192
    // plain=ae2d8a571e03ac9c9eb76fac45af8e51
    // cipher=974104846d0ad3ad7734ecb3ecee4eef
    uint8_t plaintext_192_2[] = {
        0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
        0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51
    };
    uint8_t expected_ciphertext_192_2[] = {
        0x97, 0x41, 0x04, 0x84, 0x6d, 0x0a, 0xd3, 0xad,
        0x77, 0x34, 0xec, 0xb3, 0xec, 0xee, 0x4e, 0xef
    };


    // Set 2 vector 3
    // mode=aes-192
    // plain=30c81c46a35ce411e5fbc1191a0a52ef
    // cipher=ef7afd2270e2e60adce0ba2face6444e
    uint8_t plaintext_192_3[] = {
        0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11,
        0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef
    };
    uint8_t expected_ciphertext_192_3[] = {
        0xef, 0x7a, 0xfd, 0x22, 0x70, 0xe2, 0xe6, 0x0a,
        0xdc, 0xe0, 0xba, 0x2f, 0xac, 0xe6, 0x44, 0x4e
    };

    // Set 2 vector 4
    // mode=aes-192
    // plain=f69f2445df4f9b17ad2b417be66c3710
    // cipher=9a4b41ba738d6c72fb16691603c18e0e
    uint8_t plaintext_192_4[] = {
        0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17,
        0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10
    };
    uint8_t expected_ciphertext_192_4[] = {
        0x9a, 0x4b, 0x41, 0xba, 0x73, 0x8d, 0x6c, 0x72,
        0xfb, 0x16, 0x69, 0x16, 0x03, 0xc1, 0x8e, 0x0e
    };

    // AES-256 Test Vectors
    // key=603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4
    uint8_t key_256[] = {
        0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe,
        0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
        0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7,
        0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4
    };

    // Set 3 vector 1
    // mode=aes-256
    // plain=6bc1bee22e409f96e93d7e117393172a
    // cipher=f3eed1bdb5d2a03c064b5a7e3db181f8
    uint8_t plaintext_256_1[] = {
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
        0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a
    };
    uint8_t expected_ciphertext_256_1[] = {
        0xf3, 0xee, 0xd1, 0xbd, 0xb5, 0xd2, 0xa0, 0x3c,
        0x06, 0x4b, 0x5a, 0x7e, 0x3d, 0xb1, 0x81, 0xf8
    };

    // Set 3 vector 2
    // mode=aes-256
    // plain=ae2d8a571e03ac9c9eb76fac45af8e51
    // cipher=591ccb10d410ed26dc5ba74a31362870
    uint8_t plaintext_256_2[] = {
        0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
        0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51
    };
    uint8_t expected_ciphertext_256_2[] = {
        0x59, 0x1c, 0xcb, 0x10, 0xd4, 0x10, 0xed, 0x26,
        0xdc, 0x5b, 0xa7, 0x4a, 0x31, 0x36, 0x28, 0x70
    };

    // Set 3 vector 3
    // mode=aes-256
    // plain=30c81c46a35ce411e5fbc1191a0a52ef
    // cipher=b6ed21b99ca6f4f9f153e7b1beafed1d
    uint8_t plaintext_256_3[] = {
        0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11,
        0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef
    };
    uint8_t expected_ciphertext_256_3[] = {
        0xb6, 0xed, 0x21, 0xb9, 0x9c, 0xa6, 0xf4, 0xf9,
        0xf1, 0x53, 0xe7, 0xb1, 0xbe, 0xaf, 0xed, 0x1d
    };

    // Set 3 vector 4
    // mode=aes-256
    // plain=f69f2445df4f9b17ad2b417be66c3710
    // cipher=23304b7a39f9f3ff067d8d8f9e24ecc7
    uint8_t plaintext_256_4[] = {
        0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17,
        0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10
    };
    uint8_t expected_ciphertext_256_4[] = {
        0x23, 0x30, 0x4b, 0x7a, 0x39, 0xf9, 0xf3, 0xff,
        0x06, 0x7d, 0x8d, 0x8f, 0x9e, 0x24, 0xec, 0xc7
    };


    typedef struct {
        uint8_t *key;
        uint8_t idx;
        mxc_aes_keys_t keyType;
        uint8_t *plaintext;
        uint8_t *expectedCiphertext;
    } aes_test_vector_t;

    // Define test vectors
    aes_test_vector_t test_vectors[] = {
        // Set 1: AES-128 vectors
        {key_128, 1, MXC_AES_128BITS, plaintext_128_1, expected_ciphertext_128_1},  // vector 1
        {key_128, 2, MXC_AES_128BITS, plaintext_128_2, expected_ciphertext_128_2},  // vector 2
        {key_128, 3, MXC_AES_128BITS, plaintext_128_3, expected_ciphertext_128_3},  // vector 3
        {key_128, 4, MXC_AES_128BITS, plaintext_128_4, expected_ciphertext_128_4},  // vector 4

        // Set 2: AES-192 vectors
        {key_192, 1, MXC_AES_192BITS, plaintext_192_1, expected_ciphertext_192_1},  // vector 1
        {key_192, 2, MXC_AES_192BITS, plaintext_192_2, expected_ciphertext_192_2},  // vector 2
        {key_192, 3, MXC_AES_192BITS, plaintext_192_3, expected_ciphertext_192_3},  // vector 3
        {key_192, 4, MXC_AES_192BITS, plaintext_192_4, expected_ciphertext_192_4},  // vector 4

        // Set 3: AES-256 vectors
        {key_256, 1, MXC_AES_256BITS, plaintext_256_1, expected_ciphertext_256_1},  // vector 1
        {key_256, 2, MXC_AES_256BITS, plaintext_256_2, expected_ciphertext_256_2},  // vector 2
        {key_256, 3, MXC_AES_256BITS, plaintext_256_3, expected_ciphertext_256_3},  // vector 3
        {key_256, 4, MXC_AES_256BITS, plaintext_256_4, expected_ciphertext_256_4}   // vector 4
    };

    uint8_t fail = 0;

    uint8_t ciphertext[CRYPTO_AES_BLOCK_SIZE_BYTE];
    uint8_t decryptedtext[CRYPTO_AES_BLOCK_SIZE_BYTE];

    for (int i = 0; i < sizeof(test_vectors) / sizeof(test_vectors[0]); i++) {
        aes_test_vector_t *tv = &test_vectors[i];
        uint8_t subFail = 0;

        printf(
            "\n-{I} Testing AES-%d ECB Test Vector %u\n", 
            crypto_get_key_len(tv->keyType) * 8, tv->idx
        );

        // Encrypt the plaintext
        if (crypto_AES_ECB_encrypt(tv->key, tv->keyType, tv->plaintext, ciphertext, CRYPTO_AES_BLOCK_SIZE_BYTE) != 0) {
            printf("-{E} Encryption failed!!\n");
            subFail = 1;
        }

        // Check if the ciphertext matches the expected ciphertext
        if (memcmp(ciphertext, tv->expectedCiphertext, CRYPTO_AES_BLOCK_SIZE_BYTE) != 0) {
            printf("-{E} Ciphertext does not match expected value!!\n");
            subFail = 1;
        }else{
            printf("-{I} Ciphertext matches expected value :)\n");
        }

        // Decrypt the ciphertext
        if (crypto_AES_ECB_decrypt(tv->key, tv->keyType, ciphertext, decryptedtext, CRYPTO_AES_BLOCK_SIZE_BYTE) != 0) {
            printf("-{E} Decryption failed!!\n");
            fail = 1;
        }

        // Check if the decrypted text matches the original plaintext
        if (memcmp(decryptedtext, tv->plaintext, CRYPTO_AES_BLOCK_SIZE_BYTE) != 0) {
            printf("-{E} Decrypted text does not match original plaintext!!\n");
            subFail = 1;
        }else{
            printf("-{I} Decrypted text matches original plaintext :)\n");
        }

        if(subFail){
            printf("-{I} Plain Text: ");
            crypto_print_hex(tv->plaintext, CRYPTO_AES_BLOCK_SIZE_BYTE);
            printf("-{I} Expected Cipher Text: ");
            crypto_print_hex(tv->expectedCiphertext, CRYPTO_AES_BLOCK_SIZE_BYTE);
            printf("-{I} Cipher Text: ");
            crypto_print_hex(ciphertext, CRYPTO_AES_BLOCK_SIZE_BYTE);
            printf("-{I} Decrypted Data: ");
            crypto_print_hex(decryptedtext, CRYPTO_AES_BLOCK_SIZE_BYTE);

            printf(
                "-{E} AES-%d ECB Test Vector %u Failed!!\n", 
                crypto_get_key_len(tv->keyType) * 8, tv->idx
            );
            fail = 1;
        }else{
            printf(
                "-{I} AES-%d ECB Test Vector %u Passed :)\n", 
                crypto_get_key_len(tv->keyType) * 8, tv->idx
            );
        }
    }

    if(fail){
        printf("-FAIL\n\n");
    }else{
        printf("-PASS\n\n");
    }

    return fail;
}

int crypto_test_AES_CTR(void) {
    printf("@TEST CRYPTO->AES_CTR:\n");

    // CTR mode uses a full 16-byte counter (nonce).
    // Nonce: f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff
    uint8_t nonce[16] = {
        0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
        0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff
    };

    // AES-128 CTR test vectors from NIST SP 800-38A:
    // Key (AES-128): 2b7e151628aed2a6abf7158809cf4f3c
    uint8_t key_128[] = {
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
    };

   uint8_t plaintext_128[64] = {
        // Block 1:
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
        0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
        // Block 2:
        0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
        0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
        // Block 3:
        0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11,
        0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
        // Block 4:
        0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17,
        0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10
    };

    // Expected ciphertext (64 bytes, each block as defined in SP 800-38A CTR example)
    uint8_t expected_ciphertext_128[64] = {
        // Block 1:
        0x87, 0x4d, 0x61, 0x91, 0xb6, 0x20, 0xe3, 0x26,
        0x1b, 0xef, 0x68, 0x64, 0x99, 0x0d, 0xb6, 0xce,
        // Block 2:
        0x98, 0x06, 0xf6, 0x6b, 0x79, 0x70, 0xfd, 0xff,
        0x86, 0x17, 0x18, 0x7b, 0xb9, 0xff, 0xfd, 0xff,
        // Block 3:
        0x5a, 0xe4, 0xdf, 0x3e, 0xdb, 0xd5, 0xd3, 0x5e,
        0x5b, 0x4f, 0x09, 0x02, 0x0d, 0xb0, 0x3e, 0xab,
        // Block 4:
        0x1e, 0x03, 0x1d, 0xda, 0x2f, 0xbe, 0x03, 0xd1,
        0x79, 0x21, 0x70, 0xa0, 0xf3, 0x00, 0x9c, 0xee
    };

    // AES-192 key (from NIST SP 800-38A)
    uint8_t key_192[24] = {
        0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52,
        0xc8, 0x10, 0xf3, 0x2b, 0x80, 0x90, 0x79, 0xe5,
        0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b
    };

    // Combined 64-byte plaintext (4 blocks, same as for AES-128)
    uint8_t plaintext_192[64] = {
        // Block 1:
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
        0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
        // Block 2:
        0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
        0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
        // Block 3:
        0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11,
        0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
        // Block 4:
        0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17,
        0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10
    };

    // Expected ciphertext for AES-192 (concatenated 4 blocks):
    uint8_t expected_ciphertext_192[64] = {
        // Block 1:
        0x1a, 0xbc, 0x93, 0x24, 0x17, 0x52, 0x1c, 0xa2,
        0x4f, 0x2b, 0x04, 0x59, 0xfe, 0x7e, 0x6e, 0x0b,
        // Block 2:
        0x09, 0x03, 0x39, 0xec, 0x0a, 0xa6, 0xfa, 0xef,
        0xd5, 0xcc, 0xc2, 0xc6, 0xf4, 0xce, 0x8e, 0x94,
        // Block 3:
        0x1e, 0x36, 0xb2, 0x6b, 0xd1, 0xeb, 0xc6, 0x70,
        0xd1, 0xbd, 0x1d, 0x66, 0x56, 0x20, 0xab, 0xf7,
        // Block 4:
        0x4f, 0x78, 0xa7, 0xf6, 0xd2, 0x98, 0x09, 0x58,
        0x5a, 0x97, 0xda, 0xec, 0x58, 0xc6, 0xb0, 0x50
    };

    // AES-256 key (from NIST SP 800-38A)
    uint8_t key_256[32] = {
        0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe,
        0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
        0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7,
        0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4
    };

    // Combined 64-byte plaintext (4 blocks, same as before)
    uint8_t plaintext_256[64] = {
        // Block 1:
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
        0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
        // Block 2:
        0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
        0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
        // Block 3:
        0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11,
        0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
        // Block 4:
        0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17,
        0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10
    };

    // Expected ciphertext for AES-256 (concatenated 4 blocks):
    uint8_t expected_ciphertext_256[64] = {
        // Block 1:
        0x60, 0x1e, 0xc3, 0x13, 0x77, 0x57, 0x89, 0xa5,
        0xb7, 0xa7, 0xf5, 0x04, 0xbb, 0xf3, 0xd2, 0x28,
        // Block 2:
        0xf4, 0x43, 0xe3, 0xca, 0x4d, 0x62, 0xb5, 0x9a,
        0xca, 0x84, 0xe9, 0x90, 0xca, 0xaf, 0x5c, 0xc5,
        // Block 3:
        0x2b, 0x09, 0x30, 0xda, 0xa2, 0x3d, 0xe9, 0x4c,
        0xe8, 0x70, 0x17, 0xba, 0x2d, 0x84, 0x98, 0x8d,
        // Block 4:
        0xdf, 0xc9, 0xc5, 0x8d, 0xb6, 0x7a, 0xad, 0xa6,
        0x13, 0xc2, 0xdd, 0x08, 0x45, 0x79, 0x41, 0xa6
    };


    // Define a structure for test vectors (note the extra nonce pointer).
    typedef struct {
        uint8_t *key;
        uint8_t keyType; // e.g., MXC_AES_128BITS, MXC_AES_192BITS, MXC_AES_256BITS
        uint8_t idx;
        uint8_t *nonce;
        uint8_t *plaintext;
        uint8_t *expectedCiphertext;
    } aes_ctr_test_vector_t;

    aes_ctr_test_vector_t test_vectors[] = {
        // AES-128 CTR vectors
        {key_128, MXC_AES_128BITS, 1, nonce, plaintext_128, expected_ciphertext_128},
        // AES-192 CTR vectors
        {key_192, MXC_AES_192BITS, 1, nonce, plaintext_192, expected_ciphertext_192},
        // AES-256 CTR vectors
        {key_256, MXC_AES_256BITS, 1, nonce, plaintext_256, expected_ciphertext_256},
    };

    uint8_t fail = 0;
    uint8_t ciphertext[CRYPTO_AES_BLOCK_SIZE_BYTE];
    uint8_t decryptedtext[CRYPTO_AES_BLOCK_SIZE_BYTE];

    for (int i = 0; i < sizeof(test_vectors)/sizeof(test_vectors[0]); i++) {
        aes_ctr_test_vector_t *tv = &test_vectors[i];
        uint8_t subFail = 0;

        printf(
            "\n-{I} Testing AES-%d CTR Test Vector %u\n",
            crypto_get_key_len(tv->keyType) * 8, tv->idx
        );

        // Encrypt using AES CTR mode:
        if (
            crypto_AES_CTR_encrypt(
                tv->key, tv->keyType, tv->nonce,
                tv->plaintext, ciphertext, CRYPTO_AES_BLOCK_SIZE_BYTE
            ) != 0
        ) {
            printf("-{E} Encryption failed!!\n");
            subFail = 1;
        }

        if (memcmp(ciphertext, tv->expectedCiphertext, CRYPTO_AES_BLOCK_SIZE_BYTE) != 0) {
            printf("-{E} Ciphertext does not match expected value!!\n");
            subFail = 1;
        } else {
            printf("-{I} Ciphertext matches expected value :)\n");
        }

        // Decrypt the ciphertext:
        if (
            crypto_AES_CTR_decrypt(
                tv->key, tv->keyType, tv->nonce,
                ciphertext, decryptedtext, CRYPTO_AES_BLOCK_SIZE_BYTE
            ) != 0
        ) {
            printf("-{E} Decryption failed!!\n");
            fail = 1;
        }

        if (memcmp(decryptedtext, tv->plaintext, CRYPTO_AES_BLOCK_SIZE_BYTE) != 0) {
            printf("-{E} Decrypted text does not match original plaintext!!\n");
            subFail = 1;
        } else {
            printf("-{I} Decrypted text matches original plaintext :)\n");
        }

        if (subFail) {
            printf("-{I} Plain Text: ");
            crypto_print_hex(tv->plaintext, CRYPTO_AES_BLOCK_SIZE_BYTE);
            printf("-{I} Expected Cipher Text: ");
            crypto_print_hex(tv->expectedCiphertext, CRYPTO_AES_BLOCK_SIZE_BYTE);
            printf("-{I} Cipher Text: ");
            crypto_print_hex(ciphertext, CRYPTO_AES_BLOCK_SIZE_BYTE);
            printf("-{I} Decrypted Data: ");
            crypto_print_hex(decryptedtext, CRYPTO_AES_BLOCK_SIZE_BYTE);

            printf(
                "-{E} AES-%d CTR Test Vector %u Failed!!\n",
                crypto_get_key_len(tv->keyType) * 8, tv->idx
            );
            fail = 1;
        } else {
            printf(
                "-{I} AES-%d CTR Test Vector %u Passed :)\n",
                crypto_get_key_len(tv->keyType) * 8, tv->idx
            );
        }
    }

    if (fail) {
        printf("-FAIL\n\n");
    } else {
        printf("-PASS\n\n");
    }

    return fail;
}