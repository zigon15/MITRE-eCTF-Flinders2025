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

 #ifndef DECODER_H
 #define DECODER_H
 
 #include <stdint.h> 
 #include <stdbool.h>
 
 /******************************** PUBLIC CONSTANTS ********************************/
 #define MAX_CHANNEL_COUNT 8
 #define EMERGENCY_CHANNEL 0
 #define FRAME_SIZE 64
 #define DEFAULT_CHANNEL_TIMESTAMP 0xFFFFFFFFFFFFFFFF
 
 // Calculate the flash address where we will store channel info as the 2nd to last page available
 #define FLASH_STATUS_ADDR ((MXC_FLASH_MEM_BASE + MXC_FLASH_MEM_SIZE) - (2 * MXC_FLASH_PAGE_SIZE))
 
 /******************************** PUBLIC TYPES ********************************/
 #define timestamp_t uint64_t
 #define channel_id_t uint32_t
 #define decoder_id_t uint32_t
 #define pkt_len_t uint16_t
 
 typedef struct __attribute__((packed)) {
    channel_id_t channel;
    timestamp_t start;
    timestamp_t end;
} channel_info_t;

 typedef struct __attribute__((packed)) {
    uint32_t n_channels;
    channel_info_t channel_info[MAX_CHANNEL_COUNT];
} list_response_t;
 
 #endif
 