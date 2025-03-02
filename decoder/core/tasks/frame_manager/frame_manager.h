/**
 * @file frame_manager.h
 * @author Simon Rosenzweig
 * @brief The Frame Manager handles decoding of frame packets and 
 *        if valid, sends the frame data back to the host. Frames are 
 *        protected with a MIC and monotonically increasing timestamp check.
 * @date 2025
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

// FreeRTOS stack size for Channel Manager
#define FRAME_MANAGER_STACK_SIZE 2048

//----- Public Types -----//

// Various requests that can be made to Frame Manager
enum FrameManager_RequestType {
  FRAME_MANAGER_DECODE,
};

// Frame data to decode
typedef struct {
  const uint8_t *pBuff;
  pkt_len_t pktLen;
} FrameManager_Decode;

//----- Task Queue Types -----//

// Frame task request structure
typedef struct {
  // Calling task to notify when request is complete
  TaskHandle_t xRequestingTask;

  // Must be of FrameManager_RequestType
  uint8_t requestType;

  // Pointer to structure of "requestType"
  void *pRequest;

  // Size of the pRequest buffer
  size_t requestLen;
} FrameManager_Request;

//----- Public Functions -----//

/** @brief Initializes the Frame Manager ready for the main task to be run
 * 
 * @note Must be called before RTOS scheduler starts!!
 */
void frameManager_Init(void);

/** @brief Frame Manager main RTOS task
 * 
 * @param pvParameters FreeRTOS task parameters
 */
void frameManager_vMainTask(void *pvParameters);

/** @brief Returns Frame Manager request queue 
 * 
 * @param QueueHandle_t Request queue to send requests to Frame Manager
 */
QueueHandle_t frameManager_RequestQueue(void);

#endif
