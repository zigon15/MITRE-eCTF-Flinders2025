/**
 * @file crypto.c
 * @author Simon Rosenzweig
 * @brief Crypto API Implementation using MAX AES accelerator
 * @date 2025
 *
 *
 * @copyright Copyright (c) 2025 The MITRE Corporation
 */

#include "crypto.h"
#include <stdint.h>
#include <string.h>
#include "mxc_errors.h"
#include "max78000.h"

//---------- Private Functions ----------//

/** @brief Bit XORs a block of data 
 *
 * @param pDataIn1 Data buff 1 to XOR with data buff 2
 * @param pDataIn2 Data buff 2 to XOR with data buff 1
 * @param pResult Used to store the result of the XOR
 * @param len Length of pDataIn1, pDataIn2 and pResult
 */
void _block_XOR(
    const uint8_t *pDataIn1, const uint8_t *pDataIn2, 
    uint8_t *pResult, const size_t len
){
  for(size_t i = 0; i < len; i++){
    pResult[i] = pDataIn1[i] ^ pDataIn2[i];
  }
}

/** @brief Bit shifts left a block of data
 *
 * @param pData Data to bit shift left
 * @param len Length of pData
 */
void _block_shift_left(uint8_t *pData, const size_t len){
  uint8_t nextOverFlow = 0;
  uint8_t overFlow = 0;

  for(size_t i = len; i > 0; i--){
    uint32_t idx = i - 1;

    //Check if byte will overflow
    if(pData[idx] & 0b10000000){
      nextOverFlow = 1;
    }else{
      nextOverFlow = 0;
    }

    // Shift left once
    pData[idx] = (pData[idx] << 1) | overFlow;
    overFlow = nextOverFlow;
  }
}

//---------- Public Function Defintions ----------//

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

/** @brief Encrypts plaintext with AES256 ECB symmetric cipher using MAX AES peripheral
 *         Byte big endian!!
 * 
 * @param pKey        Pointer to the AES key
 * @param keyType     Key type (MXC_AES_128BITS, MXC_AES_192BITS, MXC_AES_256BITS)
 * @param pPlaintext  Pointer to the plaintext buffer of length len
 * @param pCiphertext Pointer to the ciphertext buffer of length len
 * @param len         Length of the plaintext and ciphertext in bytes. Must be a multiple of
 *                    BLOCK_SIZE (16 bytes)
 *
 * @return 0 on success, 1 on bad length, negative for MXC AES peripheral errors
 */
int crypto_AES_ECB_encrypt(
    const uint8_t *pKey, const mxc_aes_keys_t keyType, 
    const uint8_t *pPlaintext, uint8_t *pCiphertext, const size_t len
) {
    int res = 0;

    // Ensure data is multiple of key length
    if(len % CRYPTO_AES_BLOCK_SIZE_BYTE != 0){
        return 1;
    }

    // MAX AES request
    mxc_aes_req_t req;

    // Convert to word (32b) length
    req.length = len / 4; 
    req.inputData = (uint32_t*)pPlaintext;
    req.resultData = (uint32_t*)pCiphertext;
    req.keySize = keyType;
    req.encryption = MXC_AES_ENCRYPT_EXT_KEY;

    // Need to disable peripheral when setting key
    MXC_AES->ctrl = 0x00;
    MXC_AES_SetKeySize(keyType);
    MXC_AES_SetExtKey(pKey, keyType);
    MXC_AES->ctrl |= 0x01;

    res = MXC_AES_Encrypt(&req);
    if(res != E_SUCCESS){
        return res; 
    }

    return 0;
}

/** @brief Decrypts ciphertext with AES256 ECB symmetric cipher using MAX AES peripheral
 *         Byte big endian!!
 * 
 * @param pKey        Pointer to the AES key
 * @param keyType     Key type (MXC_AES_128BITS, MXC_AES_192BITS, MXC_AES_256BITS)
 * @param pCiphertext Pointer to the ciphertext buffer of length len
 * @param pDecryptedText Pointer to buffer of length len to store decrypted data
 * @param len         Length of the plaintext and ciphertext in bytes. Must be a multiple of
 *                    BLOCK_SIZE (16 bytes)
 *
 * @return 0 on success, 1 on bad length, negative for MXC AES peripheral errors
 */
int crypto_AES_ECB_decrypt(
    const uint8_t *pKey, const mxc_aes_keys_t keyType, 
    const uint8_t *pCiphertext, uint8_t *pDecryptedText, const size_t len
) {
    int res = 0;

    // Ensure data is multiple of key length
    if(len % CRYPTO_AES_BLOCK_SIZE_BYTE != 0){
        return 1;
    }

    // MAX AES request
    mxc_aes_req_t req;

    // Convert to word (32b) length
    req.length = len / 4; 
    req.inputData = (uint32_t*)pCiphertext;
    req.resultData = (uint32_t*)pDecryptedText;
    req.keySize = keyType;
    req.encryption = MXC_AES_DECRYPT_INT_KEY;

    // Need to disable peripheral when setting key
    MXC_AES->ctrl = 0x00;
    MXC_AES_SetKeySize(keyType);
    MXC_AES_SetExtKey(pKey, keyType);
    MXC_AES->ctrl |= 0x01;
    
    res = MXC_AES_Decrypt(&req);
    if(res != E_SUCCESS){
        return res; 
    }

    return 0;
}

/** @brief Encrypts plaintext with AES CTR mode
 *         Byte big endian!!
 *
 * @param pKey        Pointer to the AES key
 * @param keyType     Key type (MXC_AES_128BITS, MXC_AES_192BITS, MXC_AES_256BITS)
 * @param pNonce      Pointer to the initial counter block (nonce), 16 bytes
 * @param pPlaintext  Pointer to the plaintext buffer of length len
 * @param pCiphertext Pointer to the ciphertext buffer of length len
 * @param len         Length of the plaintext and ciphertext in bytes
 *
 * @return 0 on success, 1 on bad length, negative for MXC AES peripheral errors
 */
int crypto_AES_CTR_encrypt(
    const uint8_t *pKey, const mxc_aes_keys_t keyType, const uint8_t *pNonce, 
    const uint8_t *pPlaintext, uint8_t *pCiphertext, const size_t len
){    
    size_t numBlocks = (len + CRYPTO_AES_BLOCK_SIZE_BYTE - 1) / CRYPTO_AES_BLOCK_SIZE_BYTE;
    CRYPTO_CREATE_CLEANUP_BUFFER(counter, CRYPTO_AES_BLOCK_SIZE_BYTE);
    CRYPTO_CREATE_CLEANUP_BUFFER(keystream, CRYPTO_AES_BLOCK_SIZE_BYTE);

    // Initialize counter from nonce.
    memcpy(counter, pNonce, CRYPTO_AES_BLOCK_SIZE_BYTE);

    for (size_t i = 0; i < numBlocks; i++) {
        // Generate keystream block by encrypting the counter
        int ret = crypto_AES_ECB_encrypt(pKey, keyType, counter, keystream, CRYPTO_AES_BLOCK_SIZE_BYTE);
        if (ret != 0){
            return ret;
        }

        size_t blockLen = CRYPTO_AES_BLOCK_SIZE_BYTE;
        
        // Determine how many bytes to process in this block
        // - Check if partial block
        if(i == numBlocks - 1 && (len % CRYPTO_AES_BLOCK_SIZE_BYTE) != 0){
            blockLen = len % CRYPTO_AES_BLOCK_SIZE_BYTE;
        }

        // XOR the keystream with the plaintext block
        for (size_t j = 0; j < blockLen; j++) {
            pCiphertext[i * CRYPTO_AES_BLOCK_SIZE_BYTE + j] = pPlaintext[i * CRYPTO_AES_BLOCK_SIZE_BYTE + j] ^ keystream[j];
        }

        // Increment the entire 16-byte counter (big-endian).
        for (int k = CRYPTO_AES_BLOCK_SIZE_BYTE - 1; k >= 0; k--) {
            counter[k]++;

            // Check for overflow, if so increment next byte
            if (counter[k] != 0){
                break;
            }
        }
    }

    return 0;
}

/** @brief Decrypts plaintext with AES CTR mode
 *         Byte big endian!!
 * 
 * @param pKey        Pointer to the AES key
 * @param keyType     Key type (e.g., MXC_AES_128BITS, MXC_AES_192BITS, MXC_AES_256BITS)
 * @param pNonce      Pointer to the initial counter block (nonce), 16 bytes.
 * @param pCiphertext Pointer to the ciphertext buffer of length len
 * @param pDecryptedText Pointer to buffer of length len to store decrypted data
 * @param len         Length of the plaintext and ciphertext in bytes
 *
 * @return 0 on success, 1 on bad length, negative for MXC AES peripheral errors
 */
int crypto_AES_CTR_decrypt(
  const uint8_t *pKey, const mxc_aes_keys_t keyType, const uint8_t *pNonce, 
  const uint8_t *pCiphertext, uint8_t *pDecryptedText, const size_t len
){
    // AES CTR encrypt is the same as decrypt
    return crypto_AES_CTR_encrypt(
        pKey, keyType, pNonce,
        pCiphertext, pDecryptedText, len
    );
}

/** @brief Perform AES CMAC using MAX AES peripheral
 *         https://datatracker.ietf.org/doc/rfc4493/
 * 
 * @param pKey A pointer to a buffer of keyType byte length containing
 *             the key to use for encryption
 * @param keyType key type (MXC_AES_128BITS, MXC_AES_192BITS, MXC_AES_256BITS)
 * @param pData A pointer to a buffer of length len containing the
 *              data to calculate CMAC on
 * @param len The length of the pData
 * @param pCMAC A pointer to a buffer of length 16 to store CMAC in
 *
 * @return 0 on success, 1 on bad length, negative for MXC AES peripheral errors
 */
int crypto_AES_CMAC(
  const uint8_t *pKey, const mxc_aes_keys_t keyType,
  const uint8_t *pData, const size_t len, uint8_t *pCMAC
){  
    //---- Calculate Sub Keys ----//
    CRYPTO_CREATE_CLEANUP_BUFFER(key1, CRYPTO_AES_BLOCK_SIZE_BYTE);
    CRYPTO_CREATE_CLEANUP_BUFFER(key2, CRYPTO_AES_BLOCK_SIZE_BYTE);
    memset(key1, 0, CRYPTO_AES_BLOCK_SIZE_BYTE);
    memset(key2, 0, CRYPTO_AES_BLOCK_SIZE_BYTE);

    // Encrypt zeros in key1
    crypto_AES_ECB_encrypt(
        pKey, keyType, 
        key1, key1, CRYPTO_AES_BLOCK_SIZE_BYTE
    );

    uint8_t msbSet = 0;

    // Key1 Calculation
    msbSet = key1[0] >> 7;
    _block_shift_left(key1, CRYPTO_AES_BLOCK_SIZE_BYTE);
    if(msbSet){
        key1[CRYPTO_AES_BLOCK_SIZE_BYTE-1] ^= 0x87;
    }

    // Key2 Calculation
    memcpy(key2, key1, CRYPTO_AES_BLOCK_SIZE_BYTE);
    msbSet = key2[0] >> 7;
    _block_shift_left(key2, CRYPTO_AES_BLOCK_SIZE_BYTE);
    if(msbSet){
        key2[CRYPTO_AES_BLOCK_SIZE_BYTE-1] ^= 0x87;
    }

    // Temp buffers
    CRYPTO_CREATE_CLEANUP_BUFFER(oldBlock, CRYPTO_AES_BLOCK_SIZE_BYTE);
    CRYPTO_CREATE_CLEANUP_BUFFER(newBlock, CRYPTO_AES_BLOCK_SIZE_BYTE);
    memset(oldBlock, 0, CRYPTO_AES_BLOCK_SIZE_BYTE);
    memset(newBlock, 0, CRYPTO_AES_BLOCK_SIZE_BYTE);

    size_t numBlocks = len / CRYPTO_AES_BLOCK_SIZE_BYTE;
    size_t incompleteBlockSize = len % CRYPTO_AES_BLOCK_SIZE_BYTE;

    if(incompleteBlockSize != 0){
        numBlocks++;
    }

    // Figure out how many full block there are to calculate
    // need to stop before the last block though
    size_t numFullBlocks = 0;
    if(numBlocks > 1){
        numFullBlocks = numBlocks-1;
    }

    // Perform full block calculations stopping before the last block
    for(size_t i = 0; i < numFullBlocks; i++){
        // Copy in next block
        memcpy(
            newBlock, (pData + i*CRYPTO_AES_BLOCK_SIZE_BYTE), 
            CRYPTO_AES_BLOCK_SIZE_BYTE
        );

        _block_XOR(newBlock, oldBlock, newBlock, CRYPTO_AES_BLOCK_SIZE_BYTE);

        // Run AES encryption on the newBlock
        crypto_AES_ECB_encrypt(
            pKey, keyType,
            newBlock, newBlock, CRYPTO_AES_BLOCK_SIZE_BYTE
        );

        memcpy(oldBlock, newBlock, CRYPTO_AES_BLOCK_SIZE_BYTE);
    }


    // Perform calculations on the last block
    if(incompleteBlockSize == 0 && len > 0){
        // Data length is multiple of 16 so one complete block left

        // Copy in last block
        memcpy(
            newBlock, (pData + (numBlocks-1)*CRYPTO_AES_BLOCK_SIZE_BYTE), 
            CRYPTO_AES_BLOCK_SIZE_BYTE
        );

        _block_XOR(newBlock, key1, newBlock, CRYPTO_AES_BLOCK_SIZE_BYTE);
        _block_XOR(newBlock, oldBlock, newBlock, CRYPTO_AES_BLOCK_SIZE_BYTE);
    }else{
        //Copy in remaining partial block
        memcpy(
            newBlock, (pData + (numBlocks-1)*CRYPTO_AES_BLOCK_SIZE_BYTE), 
            incompleteBlockSize
        );
        newBlock[incompleteBlockSize] = 0x80;
        memset((newBlock+incompleteBlockSize+1), 0x00, (CRYPTO_AES_BLOCK_SIZE_BYTE-incompleteBlockSize-1));

        _block_XOR(newBlock, key2, newBlock, CRYPTO_AES_BLOCK_SIZE_BYTE);
        _block_XOR(newBlock, oldBlock, newBlock, CRYPTO_AES_BLOCK_SIZE_BYTE);
    } 

    // Calculate and final CMAC
    crypto_AES_ECB_encrypt(
        pKey, keyType,
        newBlock, pCMAC, CRYPTO_AES_BLOCK_SIZE_BYTE
    );

    // Zero all the used memory
    return 0;
}

/** @brief Returns the length of the give key type in bytes
 *
 * @param keyType key type (MXC_AES_128BITS, MXC_AES_192BITS, MXC_AES_256BITS)
 *
 * @return Length of key in bytes
 */
size_t crypto_get_key_len(const mxc_aes_keys_t keyType){
    switch (keyType){
    case MXC_AES_128BITS:
        return 16;
        break;
    case MXC_AES_192BITS:
        return 24;
        break;
    case MXC_AES_256BITS:
        return 32;
        break;
    default:
        return 0;
        break;
    }
}

/** @brief Returns the length of the give key type in bytes
 *
 * @param pData Pointer to data buffer to print in hex
 * @param len Length of pData in bytes
 */
void crypto_print_hex(const uint8_t *pData, const size_t len){
    printf("0x");
    for (size_t i = 0; i < len; i++) {
        printf("%02x", pData[i]);
    }
    printf("\n");
}

/** @brief Securely zeros the given data buffer
 *
 * @param pData Pointer to data buffer to zero
 * @param len Length of pData in bytes
 */
void crypto_secure_zero(void *pData, size_t len) {
    volatile unsigned char *p = pData;
    while (len--) {
        *p++ = 0;
    }
}

/** @brief Zeros the given buffer object
 *
 * @param pCryptBuf Pointer to crypto buffer
 */
void crypto_buffer_cleanup(crypto_buffer_t *pCryptBuf) {
    if (pCryptBuf->data) {
        memset(pCryptBuf->data, 0, pCryptBuf->length);
        pCryptBuf->data = NULL;
        pCryptBuf->length = 0;
    }
}