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

#ifndef SUBSCRIPTION_MANAGER_H
#define SUBSCRIPTION_MANAGER_H

#include "FreeRTOS.h"
#include "task.h"
#include "queue.h"
#include "aes.h"

//----- Public Constants -----//
#define SUBSCRIPTION_MANAGER_STACK_SIZE 2048

//----- Public Types -----//


//----- Public Functions -----//
void subscriptionManager_vEncryptionTask(void *pvParameters);

// QueueHandle_t cryptoManager_EncryptionQueue(void);
// QueueHandle_t cryptoManager_SignatureCheckQueue(void);


#endif
