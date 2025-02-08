/**
 * @file "crypto.h"
 * @author Simon Rosenzweig
 * @brief Crypto API Implementation using MAX AES accelerator
 * @date 2025
 *
 *
 * @copyright Copyright (c) 2025 The MITRE Corporation
 */

#ifndef MAX_CRYPTO_H
#define MAX_CRYPTO_H

#include <stddef.h>
#include <stdio.h>
#include "aes.h"

/******************************** PUBLIC CONSTANTS ********************************/
#define CRYPTO_AES_BLOCK_SIZE_BIT 128
#define CRYPTO_AES_BLOCK_SIZE_BYTE 16

/******************************** PUBLIC FUNCTION PROTOTYPES ********************************/
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
  uint8_t *pKey, mxc_aes_keys_t keyType, 
  uint8_t *pPlaintext, uint8_t *pCiphertext, size_t len
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
  uint8_t *pKey, mxc_aes_keys_t keyType, 
  uint8_t *pCiphertext, uint8_t *pDecryptedText, size_t len
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
  uint8_t *pKey, mxc_aes_keys_t keyType, uint8_t *pNonce, 
  uint8_t *pPlaintext, uint8_t *pCiphertext, size_t len
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
  uint8_t *pKey, mxc_aes_keys_t keyType, uint8_t *pNonce, 
  uint8_t *pCiphertext, uint8_t *pDecryptedText, size_t len
);

/** @brief Perform AES256 CMAC using MAX AES peripheral
 *         https://datatracker.ietf.org/doc/rfc4493/
 *
 * @param pKey    A pointer to a buffer of keyType byte length containing
 *                the key to use for encryption
 * @param keyType key type (MXC_AES_128BITS, MXC_AES_192BITS, MXC_AES_256BITS)
 * @param pData   A pointer to a buffer of length len containing the
 *                data to calculate CMAC on
 * @param len     The length of the pData
 * @param pCMAC    A pointer to a buffer of length 16 to store CMAC in
 *
 * @return 0 on success, 1 on bad length, negative for MXC AES peripheral errors
 */
int crypto_AES_CMAC(
  uint8_t *pKey, mxc_aes_keys_t keyType,
  uint8_t *pData, size_t len, uint8_t *pCMAC
);

uint8_t crypto_get_key_len(mxc_aes_keys_t keyType);

void crypto_print_hex(const uint8_t *data, size_t len);

#endif

