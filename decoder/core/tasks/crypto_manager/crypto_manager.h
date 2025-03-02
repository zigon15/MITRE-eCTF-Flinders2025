/**
 * @file decoder.h
 * @author Simon Rosenzweig
 * @brief Flinders eCTF Decoder Implementation
 * @date 2025
 *
 * This source file is part of an example system for MITRE's 2025 Embedded System CTF (eCTF).
 * This code is being provided only for educational purposes for the 2025 MITRE eCTF competition,
 * and may not meet MITRE standards for quality. Use this code at your own risk!
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
#define CRYPTO_MANAGER_STACK_SIZE 4096

#define CRYPTO_MANAGER_MIC_LEN  CRYPTO_CMAC_OUTPUT_SIZE
#define CRYPTO_MANAGER_NONCE_LEN  (CRYPTO_AES_BLOCK_SIZE_BYTE)

//----- Public Types -----//
enum CryptoManager_KeySource {
  KEY_SOURCE_SUBSCRIPTION_KDF,
  KEY_SOURCE_FRAME_KDF,
  KEY_SOURCE_FLASH_KDF,
};

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
  // Data to decrypt
  const uint8_t *pPacketAuthToken; 
  uint16_t length;
} CryptoManager_SubDecryptedAuthTokenCheck;

//----- Task Queue Types -----//
// Signature check structure
typedef struct {
  TaskHandle_t xRequestingTask;
  uint8_t requestType;
  void *pRequest;
  size_t requestLen;
} CryptoManager_Request;

//----- Public Functions -----//
void cryptoManager_Init(void);
void cryptoManager_vMainTask(void *pvParameters);

int cryptoManager_GetChannelKdfInputKey(const channel_id_t channel, const uint8_t **ppKey);
int cryptoManager_GetFlashKdfInputKey(const uint8_t **ppKey);

QueueHandle_t cryptoManager_RequestQueue(void);

decoder_id_t cryptoManager_DecoderId(void);

#endif
