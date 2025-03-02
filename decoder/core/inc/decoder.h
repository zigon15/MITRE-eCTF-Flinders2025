/**
 * @file decoder.h
 * @author Simon Rosenzweig
 * @brief Flinders eCTF Decoder Implementation
 * @date 2025
 *
 *
 * @copyright Copyright (c) 2025 The MITRE Corporation
 */

 #ifndef DECODER_H
 #define DECODER_H
 
 #include <stdint.h> 
 #include <stdbool.h>
 
//---------- Public Constants ----------//

 #define MAX_CHANNEL_COUNT 8
 #define EMERGENCY_CHANNEL 0
 #define FRAME_SIZE 64
 #define DEFAULT_CHANNEL_TIMESTAMP 0xFFFFFFFFFFFFFFFF
 
 // Calculate the flash address where we will store channel info as the 2nd to last page available
 #define FLASH_STATUS_ADDR ((MXC_FLASH_MEM_BASE + MXC_FLASH_MEM_SIZE) - (2 * MXC_FLASH_PAGE_SIZE))
 
 
//---------- Public Types ----------//

#define timestamp_t uint64_t
#define channel_id_t uint32_t
#define decoder_id_t uint32_t
#define pkt_len_t uint16_t
 
 #endif
 