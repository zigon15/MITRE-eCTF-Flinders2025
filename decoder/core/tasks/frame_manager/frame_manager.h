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

#ifndef FRAME_MANAGER_H
#define FRAME_MANAGER_H

#include "FreeRTOS.h"
#include "task.h"
#include "queue.h"
#include "aes.h"

#include "decoder.h"

//----- Public Constants -----//
#define FRAME_MANAGER_STACK_SIZE 2048

//----- Public Types -----//
enum FrameManager_RequestType {
  FRAME_MANAGER_DECODE,
};

typedef struct {
  const uint8_t *pBuff;
  pkt_len_t pktLen;
} FrameManager_Decode;

//----- Task Queue Types -----//
// Subscription task request structure
typedef struct {
  TaskHandle_t xRequestingTask;
  uint8_t requestType;
  void *pRequest;
  size_t requestLen;
} FrameManager_Request;

//----- Public Functions -----//
void frameManager_Init(void);
void frameManager_vMainTask(void *pvParameters);

QueueHandle_t frameManager_RequestQueue(void);

// QueueHandle_t cryptoManager_EncryptionQueue(void);
// QueueHandle_t cryptoManager_SignatureCheckQueue(void);


#endif
