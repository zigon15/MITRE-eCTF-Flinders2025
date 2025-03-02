/**
 * @file crypto.h
 * @author Simon Rosenzweig
 * @brief Crypto API Implementation using MAX AES accelerator
 * @date 2025
 *
 * @copyright Copyright (c) 2025 The MITRE Corporation
 */

#ifndef MAX_CRYPTO_H
#define MAX_CRYPTO_H

#include <stddef.h>
#include <stdio.h>
#include "aes.h"

//---------- Public Constants ----------//

#define CRYPTO_AES_BLOCK_SIZE_BIT 128
#define CRYPTO_AES_BLOCK_SIZE_BYTE 16

#define CRYPTO_CMAC_OUTPUT_SIZE 16

//---------- Public Types ----------//

typedef struct {
    size_t length;
    uint8_t *data;
} crypto_buffer_t;

//---------- Public Function Prototypes ----------//

/** @brief Initializes pherpherials required for crypto operations
 *
 * @return 0 on success, MXC type errors
 */
int crypto_init(void);

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
);

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
);

/** @brief Encrypts plaintext with AES CTR mode
 *         Byte big endian!!
 * 
 * @param pKey        Pointer to the AES key
 * @param keyType     Key type (MXC_AES_128BITS, MXC_AES_192BITS, MXC_AES_256BITS)
 * @param pNonce      Pointer to the initial counter block (nonce), 16 bytes
 * @param pPlaintext  Pointer to the plaintext buffer of length len
 * @param pCiphertext Pointer to the ciphertext buffer of length len
 * @param len         Length of the plaintext and ciphertext in bytes. Must be a multiple of
 *                    BLOCK_SIZE (16 bytes)
 *
 * @return 0 on success, 1 on bad length, negative for MXC AES peripheral errors
 */
int crypto_AES_CTR_encrypt(
  const uint8_t *pKey, const mxc_aes_keys_t keyType, const uint8_t *pNonce, 
  const uint8_t *pPlaintext, uint8_t *pCiphertext, const size_t len
);

/** @brief Decrypts plaintext with AES CTR mode
 *         Byte big endian!!
 * 
 * @param pKey        Pointer to the AES key
 * @param keyType     Key type (e.g., MXC_AES_128BITS, MXC_AES_192BITS, MXC_AES_256BITS)
 * @param pNonce      Pointer to the initial counter block (nonce), 16 bytes
 * @param pCiphertext Pointer to the ciphertext buffer of length len
 * @param pDecryptedText Pointer to buffer of length len to store decrypted data
 * @param len         Length of the plaintext and ciphertext in bytes
 *
 * @return 0 on success, 1 on bad length, negative for MXC AES peripheral errors
 */
int crypto_AES_CTR_decrypt(
  const uint8_t *pKey, const mxc_aes_keys_t keyType, const uint8_t *pNonce, 
  const uint8_t *pCiphertext, uint8_t *pDecryptedText, const size_t len
);

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
);

/** @brief Returns the length of the give key type in bytes
 *
 * @param keyType key type (MXC_AES_128BITS, MXC_AES_192BITS, MXC_AES_256BITS)
 *
 * @return Length of key in bytes
 */
size_t crypto_get_key_len(const mxc_aes_keys_t keyType);

/** @brief Returns the length of the give key type in bytes
 *
 * @param pData Pointer to data buffer to print in hex
 * @param len Length of pData in bytes
 */
void crypto_print_hex(const uint8_t *pData, const size_t len);

/** @brief Zeros the given data buffer
 *
 * @param pData Pointer to data buffer to zero
 * @param len Length of pData in bytes
 */
void crypto_secure_zero(void *pData, size_t len);

/** @brief Zeros the given buffer object
 *
 * @param pCryptBuf Pointer to crypto buffer
 */
void crypto_buffer_cleanup(crypto_buffer_t *pCryptBuf);

//---------- Public Macros ----------//

/** @brief Creates a buffer which will auto zero when variables 
 *         goes out of scope to prevent secret leakage
 *
 * @param name Name of the buffer
 * @param len Length of the buffer
 */
#define CRYPTO_CREATE_CLEANUP_BUFFER(name, len) \
  uint8_t name[len]; \
  memset(name, 0, len); \
  crypto_buffer_t name##_internal_obj __attribute__((cleanup(crypto_buffer_cleanup))) = { \
    .length = len, \
    .data = name \
  }

#endif

