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
#include <stddef.h>

/******************************** PRIMITIVE TYPES ********************************/

/******************************** PUBLIC CONSTANTS ********************************/
#define SUBSCRIPTION_KDF_KEY_LEN 32
#define SUBSCRIPTION_CIPHER_AUTH_TAG_LEN 16
#define FRAME_KDF_KEY_LEN 32
#define CHANNEL_NUM_LEN 2
#define CHANNEL_LEN 2
#define CHANNEL_KDF_KEY_LEN 32

/******************************** PUBLIC FUNCTION PROTOTYPES ********************************/
int secrets_init(void);

int secrets_get_subscription_kdf_key(const uint8_t **ppKey);
int secrets_get_subscription_cipher_auth_tag(const uint8_t **ppCipherAuthTag);
int secrets_get_frame_kdf_key(const uint8_t **ppKey);

int secrets_is_valid_channel(const channel_id_t channel);
int secrets_get_channel_kdf_key(const channel_id_t channel, const uint8_t **ppKey);
int secrets_get_channel_info(
    const size_t idx, 
    const uint16_t **ppChannel, const uint8_t **ppKey
);

#endif
