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
#define CHANNEL_LEN 4
#define CHANNEL_KDF_KEY_LEN 32

/******************************** PUBLIC FUNCTION PROTOTYPES ********************************/

/** @brief Initializes the global secrets module.
 *         Checks the format of the global secrets in flash makes senses.
 * 
 *  @return 0 upon success, 1 if error.
*/
int secrets_init(void);

/** @brief Updates the given pointer to point to the subscription KDF key.
 * 
 * @param ppKey Set to point to the subscription KDF key.
 * 
 *  @return 0 upon success, 1 if error
*/
int secrets_get_subscription_kdf_key(const uint8_t **ppKey);

/** @brief Updates the given pointer to point to the subscription cipher auth tag.
 * 
 * @param ppCipherAuthTag Set to point to the subscription cipher auth tag.
 * 
 *  @return 0 upon success, 1 if error.
*/
int secrets_get_subscription_cipher_auth_tag(const uint8_t **ppCipherAuthTag);

/** @brief Updates the given pointer to point to the frame KDF key.
 * 
 * @param ppKey Set to point to the frame KDF key.
 * 
 *  @return 0 upon success, 1 if error.
*/
int secrets_get_frame_kdf_key(const uint8_t **ppKey);

/** @brief Checks if the given channel is valid in the current deployment.
 * 
 * @param channel Channel to check if is valid.
 * 
 *  @return 0 if valid, 1 if failed to find channel in current deployment.
*/
int secrets_is_valid_channel(const channel_id_t channel);

/** @brief Updated the given pointer to point to the channel KDF key for 
 *         the specified channel.
 * 
 * @param channel Channel to get the KDF key for.
 * @param ppKey Set to point to the specified channel KDF key.
 * 
 *  @return 0 upon success, 1 if channel not found or failed.
*/
int secrets_get_channel_kdf_key(const channel_id_t channel, const uint8_t **ppKey);

/** @brief Get the channel info for the "idx" channel in the current deployment.
 * 
 * @param idx The nth channel to get info for in the current deployment.
 * @param ppChannel Set to point to "idx" channel number,
 * @param ppKey Set to point to the "idx" channel KDF key.
 * 
 *  @return 0 upon success, 1 if failed.
*/
int secrets_get_channel_info(
    const size_t idx, 
    channel_id_t const **ppChannel, const uint8_t **ppKey
);

#endif
