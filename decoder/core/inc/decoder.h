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

/******************************** PRIMITIVE TYPES ********************************/
#define timestamp_t uint64_t
#define channel_id_t uint32_t
#define decoder_id_t uint32_t
#define pkt_len_t uint16_t


/******************************** PUBLIC CONSTANTS ********************************/
#define MAX_CHANNEL_COUNT 8
#define EMERGENCY_CHANNEL 0
#define FRAME_SIZE 64
#define DEFAULT_CHANNEL_TIMESTAMP 0xFFFFFFFFFFFFFFFF

#endif
