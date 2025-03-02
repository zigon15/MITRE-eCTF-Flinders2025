/**
 * @file subscription_manager.h
 * @author Simon Rosenzweig
 * @brief The Subscription Manager handles subscription update messages.
 *        Subscription updates messages are protected with a MIC and a known 
 *        cipher auth token.
 * @date 2025
 *
 * @copyright Copyright (c) 2025 The MITRE Corporation
 */

#ifndef SUBSCRIPTION_MANAGER_H
#define SUBSCRIPTION_MANAGER_H

#include "FreeRTOS.h"
#include "task.h"
#include "queue.h"
#include "aes.h"

#include "decoder.h"

//----- Public Constants -----//

// FreeRTOS stack size for Subscription Manager
#define SUBSCRIPTION_MANAGER_STACK_SIZE 2048

//----- Public Types -----//

// Various requests that can be made to Subscription Manager
enum SubscriptionManager_RequestType {
  SUBSCRIPTION_MANAGER_SUB_UPDATE,
};

// Subscription update raw packet structure
typedef struct {
  const uint8_t *pBuff;
  pkt_len_t pktLen;
} SubscriptionManager_SubscriptionUpdate;

//----- Task Queue Types -----//

// Subscription task request structure
typedef struct {
  // Calling task to notify when request is complete
  TaskHandle_t xRequestingTask;

  // Must be of SubscriptionManager_RequestType
  uint8_t requestType;

  // Pointer to structure of "requestType"
  void *pRequest;

  // Size of the pRequest buffer
  size_t requestLen;
} SubscriptionManager_Request;

//----- Public Functions -----//

/** @brief Initializes the Subscription Manager ready for the main task to be run
 * 
 * @note Must be called before RTOS scheduler starts!!
 */
void subscriptionManager_Init(void);

/** @brief Subscription Interface Manager main RTOS task
 * 
 * @param pvParameters FreeRTOS task parameters
 */
void subscriptionManager_vMainTask(void *pvParameters);

/** @brief Returns Subscription Manager request queue 
 * 
 * @param QueueHandle_t Request queue to send requests to Subscription Manager
 */
QueueHandle_t subscriptionManager_RequestQueue(void);

#endif
