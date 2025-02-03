/**
 * @file "max_crypto.h"
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

/******************************** PUBLIC CONSTANTS ********************************/
#define CRYPTO_AES_KEY_SIZE_IT 256
#define CRYPTO_AES_KEY_SIZE_BYTE 32

/******************************** PUBLIC FUNCTION PROTOTYPES ********************************/
/** @brief Initializes pherpherials required for crypto operations
 *
 * @return 0 on success, MXC type errors
 */
int crypto_init(void);

/** @brief Encrypts plaintext with AES256 ECB symmetric cipher using MAX AES peripheral
 *
 * @param pKey A pointer to a buffer of length KEY_SIZE (32 bytes) containing
 *          the key to use for encryption
 * @param pPlaintext A pointer to a buffer of length len containing the
 *          plaintext to encrypt
 * @param pCiphertext A pointer to a buffer of length len where the resulting
 *          ciphertext will be written to
 * @param len The length of the plaintext to encrypt. Must be a multiple of
 *          BLOCK_SIZE (32 bytes)
 *
 * @return 0 on success, 1 on bad length, negative for MXC AES peripheral errors
 */
int crypto_AES_ECB_encrypt(
  uint8_t *pKey, uint8_t *pPlaintext, uint8_t *pCiphertext, size_t len
);

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
);

#endif

