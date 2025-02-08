/**
 * @file global_secrets.h
 * @author Simon Rosenzweig
 * @brief eCTF Global Secrets Implementation
 * @date 2025
 *
 * This source file is part of an example system for MITRE's 2025 Embedded System CTF (eCTF).
 * This code is being provided only for educational purposes for the 2025 MITRE eCTF competition,
 * and may not meet MITRE standards for quality. Use this code at your own risk!
 *
 * @copyright Copyright (c) 2025 The MITRE Corporation
 */

#ifndef GLOBAL_SECRETS_H
#define GLOBAL_SECRETS_H

#include "decoder.h"
#include <stdint.h>

/******************************** PRIMITIVE TYPES ********************************/

/******************************** PUBLIC CONSTANTS ********************************/
#define SUBSCRIPTION_KDF_KEY_LEN 32
#define FRAME_KDF_KEY_LEN 32
#define CHANNEL_KDF_KEY_LEN 32

/******************************** PUBLIC FUNCTION PROTOTYPES ********************************/
int secrets_init(void);

int secrets_get_subscription_kdf_key(uint8_t *pKey);
int secrets_get_frame_kdf_key(uint8_t *pKey);

int secrets_is_valid_channel(channel_id_t channel);
int secrets_get_channel_kdf_key(channel_id_t channel, uint8_t *pKey);

#endif
