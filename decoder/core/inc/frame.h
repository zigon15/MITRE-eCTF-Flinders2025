/**
 * @file frame.h
 * @author Simon Rosenzweig
 * @brief eCTF Frame Decode Implementation
 * @date 2025
 *
 * This source file is part of an example system for MITRE's 2025 Embedded System CTF (eCTF).
 * This code is being provided only for educational purposes for the 2025 MITRE eCTF competition,
 * and may not meet MITRE standards for quality. Use this code at your own risk!
 *
 * @copyright Copyright (c) 2025 The MITRE Corporation
 */

#ifndef FRAME_H
#define FRAME_H

#include "decoder.h"
#include "global_secrets.h"

/******************************** PRIMITIVE TYPES ********************************/

/******************************** PUBLIC CONSTANTS ********************************/

/******************************** PUBLIC FUNCTION PROTOTYPES ********************************/
/** @brief Decoded the given encrypted frame packet
 *
 *  @param pktLen The length of the incoming packet
 *  @param pUpdate A pointer to a encrypted frame message
 *
 *  @note Take care to note that this system is little endian.
 *
 *  @return 0 upon success, 1 if error
*/
int frame_decode(const pkt_len_t pktLen, const uint8_t *pData);

#endif
