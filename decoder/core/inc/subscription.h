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
 *  @param pUpdate A pointer to a subscription update packet
 * 
 *  @note Take care to note that this system is little endian.
 *
 *  @return 0 upon success, 1 if error
*/
int subscription_update(const pkt_len_t pkt_len, const uint8_t *pData);

/** @brief Checks whether the decoder is subscribed to a given channel
 *
 *  @param channel The channel number to be checked.
 *  @return 1 if the the decoder is subscribed to the channel.  0 if not.
*/
int subscription_is_subscribed(const channel_id_t channel, const timestamp_t timestamp);

/** @brief Prints all the channels the decoder has a subscription for.
 *
*/
void subscription_print_active_channels(void);

#endif
