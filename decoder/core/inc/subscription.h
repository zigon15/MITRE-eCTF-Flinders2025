/**
 * @file subscription.h
 * @author Simon Rosenzweig
 * @brief eCTF Subscription Implementation
 * @date 2025
 *
 * This source file is part of an example system for MITRE's 2025 Embedded System CTF (eCTF).
 * This code is being provided only for educational purposes for the 2025 MITRE eCTF competition,
 * and may not meet MITRE standards for quality. Use this code at your own risk!
 *
 * @copyright Copyright (c) 2025 The MITRE Corporation
 */

#ifndef SUBSCRIPTION_H
#define SUBSCRIPTION_H

#include "decoder.h"
#include "global_secrets.h"

/******************************** PRIMITIVE TYPES ********************************/

/******************************** PUBLIC CONSTANTS ********************************/

/******************************** PUBLIC FUNCTION PROTOTYPES ********************************/
/** @brief Updates the channel subscription for a subset of channels.
 *
 *  @param pkt_len The length of the incoming packet
 *  @param pUpdate A pointer to a subscription_update_packet struct,
 *                 which contains the channel number, start, and end timestamps
 *                 for each channel being updated.
 *
 *  @note Take care to note that this system is little endian.
 *
 *  @return 0 upon success, 1 if error
*/
int subscription_update(const pkt_len_t pkt_len, const uint8_t *pData);

#endif
