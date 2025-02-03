/**
 * @file "max_crypto.c"
 * @author Simon Rosenzweig
 * @brief Crypto API Implementation using MAX AES accelerator
 * @date 2025
 *
 *
 * @copyright Copyright (c) 2025 The MITRE Corporation
 */

#include "max_crypto.h"
#include <stdint.h>
#include <string.h>
#include "aes.h"
#include "mxc_errors.h"


/******************************** PUBLIC FUNCTION DECLARATIONS ********************************/
/** @brief Initializes pherpherials required for crypto operations
 *
 * @return 0 on success, MXC type errors
 */
int crypto_init(void){
    // Initialize AES peripheral
    int res = MXC_AES_Init();
    if(res != E_SUCCESS){
        return res; 
    }

    return E_SUCCESS;
}

/** @brief Encrypts plaintext using AES256 ECB symmetric cipher using MAX AES peripheral
 *
 * @param plaintext A pointer to a buffer of length len containing the
 *          plaintext to encrypt
 * @param len The length of the plaintext to encrypt. Must be a multiple of
 *          BLOCK_SIZE (32 bytes)
 * @param key A pointer to a buffer of length KEY_SIZE (32 bytes) containing
 *          the key to use for encryption
 * @param ciphertext A pointer to a buffer of length len where the resulting
 *          ciphertext will be written to
 *
 * @return 0 on success, 1 on bad length, negative for MXC AES peripheral errors
 */
int crypto_AES_ECB_encrypt(
    uint8_t *pKey, uint8_t *pPlaintext, uint8_t *pCiphertext, size_t len
) {
    int res = 0;

    // Ensure data is multiple of key length
    if(len % CRYPTO_AES_KEY_SIZE_BYTE != 0){
        return 1;
    }

    // MAX AES request
    mxc_aes_req_t req;

    // Convert to word (32b) length
    req.length = len / 4; 
    req.inputData = (uint32_t*)pPlaintext;
    req.resultData = (uint32_t*)pCiphertext;
    req.keySize = MXC_AES_256BITS;
    req.encryption = MXC_AES_ENCRYPT_EXT_KEY;

    MXC_AES_SetExtKey(pKey, MXC_AES_256BITS);

    res = MXC_AES_Encrypt(&req);
    if(res != E_SUCCESS){
        return res; 
    }

    return 0;
}

/** @brief Decrypts ciphertext with AES256 ECB symmetric cipher using MAX AES peripheral
 *
 * @param pKey A pointer to a buffer of length KEY_SIZE (32 bytes) containing
 *          the key to use for encryption
 * @param pCiphertext A pointer to a buffer of length len which will be decrypted
 * @param pDecryptedText A pointer to a buffer of length len where the
 *          decrypted data will be stored in
 * @param len The length of the plaintext to encrypt. Must be a multiple of
 *          BLOCK_SIZE (32 bytes)
 *
 * @return 0 on success, 1 on bad length, negative for MXC AES peripheral errors
 */
int crypto_AES_ECB_decrypt(
    uint8_t *pKey, uint8_t *pCiphertext, uint8_t *pDecryptedText, size_t len
) {
    int res = 0;

    // Ensure data is multiple of key length
    if(len % CRYPTO_AES_KEY_SIZE_BYTE != 0){
        return 1;
    }

    // MAX AES request
    mxc_aes_req_t req;

    // Convert to word (32b) length
    req.length = len / 4; 
    req.inputData = (uint32_t*)pCiphertext;
    req.resultData = (uint32_t*)pDecryptedText;
    req.keySize = MXC_AES_256BITS;
    req.encryption = MXC_AES_DECRYPT_INT_KEY;

    MXC_AES_SetExtKey(pKey, MXC_AES_256BITS);
    res = MXC_AES_Decrypt(&req);
    if(res != E_SUCCESS){
        return res; 
    }

    return 0;
}