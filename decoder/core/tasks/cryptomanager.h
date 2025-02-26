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

#ifndef CRYPTO_MANAGE_H
#define CRYPTO_MANAGE_H

#include "FreeRTOS.h"
#include "task.h"
#include "queue.h"
#include "aes.h"

//----- Public Types -----//
enum CryptoManager_KeySource {
  FRAME_KDF_KEY,
  SUBSCRIPTION_KDF_KEY,
};

// Key structure
typedef struct {
  uint8_t *pKey;
  mxc_aes_keys_t keyType;
} CryptoManager_Key;

// Key derivation structure
typedef struct {
  // Data to derive key from
  uint8_t *pData; 
  size_t length;

  // Nonce for AES CTR
  uint8_t *pNonce;

  // Key source for KDF
  CryptoManager_KeySource keySource;
} CryptoManager_KeyDerivationData;

// Encrypt data structure
typedef struct {
  // Key for AES CTR
  CryptoManager_Key key;

  // Nonce for AES CTR
  uint8_t *pNonce;

  // Data to encrypt
  uint8_t *pPlainText; 
  uint8_t *pCipherText; 
  size_t length;
} CryptoManager_EncryptData;

// Signature check structure
typedef struct {
  // How to derive the key
  CryptoManager_KeyDerivationData kdfRequest;

  // Nonce for AES CTR
  uint8_t *pNonce;

  // Data to check
  uint8_t *pData; 
  size_t length;

  // Signature to check
  uint8_t *pSignature; 
} CryptoManager_SignatureCheck;

//----- Task Queue Types -----//
// Signature check structure
typedef struct {
  TaskHandle_t xRequestingTask;
  CryptoManager_SignatureCheck sigCheck;
} CryptoManager_SignatureCheckRequest;

// Encryption request structure
typedef struct {
  TaskHandle_t xRequestingTask;
  CryptoManager_EncryptData encData;
} CryptoManager_EncryptionRequest;

//----- Public Functions -----//
void cryptoManager_vEncryptionTask(void *pvParameters);

QueueHandle_t cryptoManager_EncryptionQueue();
QueueHandle_t cryptoManager_SignatureCheckQueue();


#endif
