/**
 * @file channel_manager.h
 * @author Simon Rosenzweig
 * @brief The Channel Manager handles flash read and writes to update, add and list subscriptions. 
 *        Flash data modification is protected against with a MIC.
 * @date 2025
 *
 * @copyright Copyright (c) 2025 The MITRE Corporation
 */

#ifndef CHANNEL_MANAGER_H
#define CHANNEL_MANAGER_H

#include "decoder.h"

#include "FreeRTOS.h"
#include "task.h"
#include "queue.h"

//----- Public Constants -----//

// FreeRTOS stack size for Channel Manager
#define CHANNEL_MANAGER_STACK_SIZE 2048

//----- Public Types -----//

// Various requests that can be made to Channel Manager
enum ChannelManager_RequestType {
  CHANNEL_MANAGER_CHECK_ACTIVE_SUB,
  CHANNEL_MANAGER_GET_SUBS,
  CHANNEL_MANAGER_UPDATE_SUB,
};

// Check if subscription is active for given "channel" at "time" structure
typedef struct {
  channel_id_t channel;
  timestamp_t time;
} ChannelManager_CheckActiveSub;

// Get all subscriptions structure
typedef struct {
  uint16_t numChannels;
  channel_id_t channels[MAX_CHANNEL_COUNT];
  timestamp_t timeStart[MAX_CHANNEL_COUNT];
  timestamp_t timeEnd[MAX_CHANNEL_COUNT];
} ChannelManager_GetSubscriptions;

// Update channel subscription information
typedef struct {
  channel_id_t channel;
  timestamp_t timeStart;
  timestamp_t timeEnd;
} ChannelManager_UpdateSubscription;

//----- Task Queue Types -----//

// Channel manager request structure
typedef struct {
  // Calling task to notify when request is complete
  TaskHandle_t xRequestingTask;

  // Must be of ChannelManager_RequestType
  uint8_t requestType;

  // Pointer to structure of "requestType"
  void *pRequest;

  // Size of the pRequest buffer
  size_t requestLen;
} ChannelManager_Request;

//----- Public Functions -----//

/** @brief Initializes the Channel Manager ready for the main task to be run
 * 
 * @note Must be called before RTOS scheduler starts!!
 */
void channelManager_Init(void);

/** @brief Channel Manager main RTOS task
 * 
 * @param pvParameters FreeRTOS task parameters
 */
void channelManager_vMainTask(void *pvParameters);


/** @brief Returns Channel Manager request queue 
 * 
 * @param QueueHandle_t Request queue to send requests to Channel Manager
 */
QueueHandle_t channelManager_RequestQueue(void);

#endif
