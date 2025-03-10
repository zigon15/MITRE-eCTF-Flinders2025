/**
 * @file crypto_manager.h
 * @author Simon Rosenzweig
 * @brief The Crypto Manager handles all the various cryptographic operations such as
 *        MIC checks, MIC signing, decryption and auth token checking. Global secrets 
 *        exposure to other tasks is minimized as much as possible.
 * @date 2025
 *
 * @copyright Copyright (c) 2025 The MITRE Corporation
 */

#ifndef CRYPTO_MANAGER_H
#define CRYPTO_MANAGER_H

#include "FreeRTOS.h"
#include "task.h"
#include "queue.h"
#include "aes.h"

#include "decoder.h"
#include "crypto.h"

//----- Public Constants -----//

// FreeRTOS stack size for Crypto Manager
#define CRYPTO_MANAGER_STACK_SIZE 2048

#define CRYPTO_MANAGER_MIC_LEN  CRYPTO_CMAC_OUTPUT_SIZE
#define CRYPTO_MANAGER_NONCE_LEN  (CRYPTO_AES_BLOCK_SIZE_BYTE)

//----- Public Types -----//

// Which global secrets key to use in the KDF
enum CryptoManager_KeySource {
  KEY_SOURCE_SUBSCRIPTION_KDF,
  KEY_SOURCE_FRAME_KDF,
  KEY_SOURCE_FLASH_KDF,
};

// Various requests that can be made to Crypto Manager
enum CryptoManager_RequestType {
  CRYPTO_MANAGER_REQ_SIG_CHECK,
  CRYPTO_MANAGER_REQ_SIG_SIGN,
  CRYPTO_MANAGER_REQ_CHECK_SUB_DECRYPTED_AUTH_TOKEN,
  CRYPTO_MANAGER_REQ_DECRYPT,
};

// Key derivation structure
typedef struct {
  // Data to derive key from
  uint8_t *pData; 
  size_t length;

  // Nonce for AES CTR
  uint8_t *pNonce;

  // Key source for KDF
  uint8_t keySource;
} CryptoManager_KeyDerivationData;

// Signature check structure
typedef struct {
  // KDF data for AES KEY
  CryptoManager_KeyDerivationData kdfData;

  // Data to check
  const uint8_t *pData; 
  size_t length;

  // Signature to check
  const uint8_t *pExpectedSignature; 
} CryptoManager_SignatureCheck;

// Signature sign structure
typedef struct {
  // KDF data for AES KEY
  CryptoManager_KeyDerivationData kdfData;

  // Data to sign
  const uint8_t *pData; 
  size_t length;

  // Where to store signature
  uint8_t *pSignature; 
} CryptoManager_SignatureSign;

// Encrypt data structure
typedef struct {
  // KDF data for AES KEY
  CryptoManager_KeyDerivationData kdfData;

  // Nonce for AES CTR
  const uint8_t *pNonce;

  // Data to decrypt
  const uint8_t *pCipherText; 
  uint8_t *pPlainText; 
  size_t length;
} CryptoManager_DecryptData;

// Subscription decrypted auth token check structure
typedef struct {
  // Subscription auth token to check
  const uint8_t *pPacketAuthToken; 
  uint16_t length;
} CryptoManager_SubDecryptedAuthTokenCheck;

//----- Task Queue Types -----//

// Signature check structure
typedef struct {
  // Calling task to notify when request is complete
  TaskHandle_t xRequestingTask;

  // Must be of CryptoManager_RequestType
  uint8_t requestType;

  // Pointer to structure of "requestType"
  void *pRequest;

  // Size of the pRequest buffer
  size_t requestLen;
} CryptoManager_Request;

//----- Public Functions -----//

/** @brief Initializes the Crypto Manager ready for the main task to be run
 * 
 * @note Must be called before RTOS scheduler starts!!
 */
void cryptoManager_Init(void);

/** @brief Crypto Manager main RTOS task
 * 
 * @param pvParameters FreeRTOS task parameters
 */
void cryptoManager_vMainTask(void *pvParameters);

/** @brief Returns Crypto Manager request queue 
 * 
 * @param QueueHandle_t Request queue to send requests to Crypto Manager
 */
QueueHandle_t cryptoManager_RequestQueue(void);

/** @brief Updated the given pointer to point to the channel KDF key for 
 *         the specified channel.
 * 
 * @param channel Channel to get the KDF key for.
 * @param ppKey Set to point to the specified channel KDF key.
 * 
 *  @return 0 upon success, 1 if channel not found or failed.
*/
int cryptoManager_GetChannelKdfInputKey(const channel_id_t channel, const uint8_t **ppKey);

/** @brief Updates the given pointer to point to the flash KDF input key.
 * 
 * @param ppKey Set to point to the flash KDF input key.
 * 
 *  @return 0 upon success, 1 if error.
*/
int cryptoManager_GetFlashKdfInputKey(const uint8_t **ppKey);

/** @brief Returns the decoder ID.
 * 
 *  @return The current decoder ID.
*/
decoder_id_t cryptoManager_DecoderId(void);

#endif
