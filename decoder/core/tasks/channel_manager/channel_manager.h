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

#ifndef CHANNEL_MANAGER_H
#define CHANNEL_MANAGER_H

#include "decoder.h"

#include "FreeRTOS.h"
#include "task.h"
#include "queue.h"

//----- Public Constants -----//
#define CHANNEL_MANAGER_STACK_SIZE 2048

//----- Public Types -----//
enum ChannelManager_RequestType {
  CHANNEL_MANAGER_CHECK_ACTIVE_SUB,
  CHANNEL_MANAGER_GET_SUBS,
  CHANNEL_MANAGER_UPDATE_SUB,
};

// Check if active subscription structure
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

// Update channel information
typedef struct {
  channel_id_t channel;
  timestamp_t timeStart;
  timestamp_t timeEnd;
} ChannelManager_UpdateSubscription;

//----- Task Queue Types -----//
// Signature check structure
typedef struct {
  TaskHandle_t xRequestingTask;
  uint8_t requestType;
  void *pRequest;
  size_t requestLen;
} ChannelManager_Request;


//----- Public Functions -----//
void channelManager_Init(void);
void channelManager_vMainTask(void *pvParameters);
QueueHandle_t channelManager_RequestQueue(void);

#endif
