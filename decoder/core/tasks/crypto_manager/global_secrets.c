/**
 * @file global_secrets.h
 * @author Simon Rosenzweig
 * @brief Global Secrets Implementation
 * @date 2025
 *
 * @copyright Copyright (c) 2025 The MITRE Corporation
 */
#include "global_secrets.h"
#include <stdio.h>
#include <string.h>

#include "crypto.h"

//---------- Private Constants ----------//

// Minimum size for global secrets
// [0]: Subscription KDF Key (32 bytes)
// [32]: Subscription Cipher Auth Tag Key (16 bytes)
// [48]: Frame KDF Keys (32 Bytes)
// [80]: Num channels (2 bytes) -> 1 channel in deployment
// [82]: First channel in deployment (2 bytes)
// [84]: Channel KDF key (32 bytes)
// 32 + 16 + 32 + 2 + 2 + 32 -> 116 bytes
#define GLOBAL_SECRETS_MIN_SIZE (SUBSCRIPTION_KDF_KEY_LEN + SUBSCRIPTION_CIPHER_AUTH_TAG_LEN + FRAME_KDF_KEY_LEN + FLASH_KDF_KEY_LEN + FLASH_KDF_INPUT_KEY_LEN + CHANNEL_NUM_LEN + (CHANNEL_LEN + CHANNEL_KDF_INPUT_KEY_LEN))

// Definitions for byte offset of the global secrets variables stored in flash
#define SUBSCRIPTION_KDF_KEY_OFFSET         (0)
#define SUBSCRIPTION_CIPHER_AUTH_TAG_OFFSET (SUBSCRIPTION_KDF_KEY_OFFSET + SUBSCRIPTION_KDF_KEY_LEN)
#define FRAME_KDF_KEY_OFFSET                (SUBSCRIPTION_CIPHER_AUTH_TAG_OFFSET + SUBSCRIPTION_CIPHER_AUTH_TAG_LEN)
#define FLASH_KDF_KEY_OFFSET                (FRAME_KDF_KEY_OFFSET + FRAME_KDF_KEY_LEN)
#define FLASH_KDF_INPUT_KEY_OFFSET          (FLASH_KDF_KEY_OFFSET + FLASH_KDF_KEY_LEN)
#define NUM_CHANNELS_OFFSET                 (FLASH_KDF_INPUT_KEY_OFFSET + FRAME_KDF_KEY_LEN)
#define CHANNEL_INFO_OFFSET                 (NUM_CHANNELS_OFFSET + CHANNEL_NUM_LEN)

//---------- Private Types ----------//
typedef struct __attribute__((packed)) {
    channel_id_t channel;
    uint8_t pKey[CHANNEL_KDF_INPUT_KEY_LEN];
} channel_key_pair_t;

//---------- Extern Variables ----------//

// Start and end bytes of the global secrets
// - Automatically set in the linker script
extern const uint8_t secrets_bin_start[];
extern const uint8_t secrets_bin_end[];

//---------- Private Variables ----------//

static uint8_t _globalSecretsValid = 0;
static size_t _numChannels = 0;

//---------- Private Functions ----------//

/** @brief Calculated how long the global secrets should be 
 *         based on the specified number of channels.
 *  
 * @param numChannels Number of channels in the deployment
 * 
 * @return Expected length of the global secrets given that it contains "numChannels" channels
*/
static uint32_t _num_channels_to_length(const size_t numChannels){
    return (
        SUBSCRIPTION_KDF_KEY_LEN + SUBSCRIPTION_CIPHER_AUTH_TAG_LEN + FRAME_KDF_KEY_LEN + 
        FLASH_KDF_KEY_LEN + FLASH_KDF_INPUT_KEY_LEN + 
        CHANNEL_NUM_LEN + numChannels*(CHANNEL_LEN + CHANNEL_KDF_INPUT_KEY_LEN)
    );
}

/** @brief Finds the specified channel in the current deployment 
 *         and sets the given pointer to the channel KDF key.
 *  
 * @param channel Channel number to find
 * @param ppKey Set to point to the channel KDF key, if channel exists
 * 
 * @return 0 upon success, 1 if failed to find channel or error
*/
static int _find_channel_info(
    const channel_id_t channel, const uint8_t **ppKey
){  
    // Ensure secrets are valid
    if(_globalSecretsValid == 0){
        return 1;
    }

    // Loop through all the channel key pairs to see if the channel exists
    for(size_t i = 0; i < _numChannels; i++){
        channel_id_t foundChannel = *(channel_id_t*)(secrets_bin_start + CHANNEL_INFO_OFFSET + i*CHANNEL_LEN);
        if(channel == foundChannel){
            *ppKey = secrets_bin_start + CHANNEL_INFO_OFFSET + _numChannels*CHANNEL_LEN + i*CHANNEL_KDF_INPUT_KEY_LEN;
            return 0;
        }
    }

    return 1;
}

/** @brief Prints all the global secrets over serial
 *  
 * @note Never call in production!!
*/
// static void _print_global_secrets(void){
//     // Ensure secrets are valid
//     if(_globalSecretsValid == 0){
//         return;
//     }

//     const uint8_t *pSubscriptionKdfKey;
//     const uint8_t *pSubscriptionCipherAuthTag;
//     const uint8_t *pFrameKdfKey;
//     secrets_get_subscription_kdf_key(&pSubscriptionKdfKey);
//     secrets_get_subscription_cipher_auth_tag(&pSubscriptionCipherAuthTag);
//     secrets_get_frame_kdf_key(&pFrameKdfKey);

//     printf("-{I} Subscription KDF Key: ");
//     crypto_print_hex(pSubscriptionKdfKey, SUBSCRIPTION_KDF_KEY_LEN);
//     printf("-{I} Subscription Cypher Auth Tag: ");
//     crypto_print_hex(pSubscriptionCipherAuthTag, SUBSCRIPTION_CIPHER_AUTH_TAG_LEN);
//     printf("-{I} Frame KDF Key: ");
//     crypto_print_hex(pFrameKdfKey, FRAME_KDF_KEY_LEN);
//     printf("-{I} %u Channels:\n", _numChannels);

//     for(size_t i = 0; i < _numChannels; i++){
//         const uint16_t *pChannel;
//         const uint8_t *pChannelKey;
//         secrets_get_channel_info(i, &pChannel, &pChannelKey);

//         printf(
//             "-[%u] Channel: %u, Key: ", 
//             i, *pChannel
//         );
//         crypto_print_hex(pChannelKey, CHANNEL_KDF_INPUT_KEY_LEN);
//     }
// }

//---------- Public Functions ----------//

/** @brief Initializes the global secrets module. 
 *         Checks the format of the global secrets in flash makes senses.
 * 
 *  @return 0 upon success, 1 if error
*/
int secrets_init(void){
    const uint8_t *pSecretsBin = (uint8_t*)secrets_bin_start;
    const uint8_t *pSecretsBinEnd = (uint8_t*)secrets_bin_end;
    const size_t secretsLen = pSecretsBinEnd-pSecretsBin;

    // printf("@TASK Check Global Secrets:\n");
    // printf("-{I} Secrets Start 0x%X\n", pSecretsBin);
    // printf("-{I} Secrets End 0x%X\n", pSecretsBinEnd);
    // printf("-{I} Secrets Length %u Bytes\n", secretsLen);
    
    // for(size_t i = 0; i < secretsLen; i++){
    //     if((i % 16 == 0) && (i != 0)){
    //         printf("\n");
    //     }
    //     printf("0x%02X, ", pSecretsBin[i]);
    // }
    // printf("\n");

    //----- Validate format -----//
    // Check length is good based on number of channels in deployment
    _numChannels = *(uint16_t*)(pSecretsBin + NUM_CHANNELS_OFFSET);
    // printf("-{I} Detected %u Channels in Deployment\n", _numChannels);

    const uint32_t expectedLen = _num_channels_to_length(_numChannels);
    if(expectedLen != secretsLen){
        // printf("-{E} Bad Length -> Expected %u != Actual %u\n", expectedLen, secretsLen);
        // printf("-ERROR\n\n");
        return 1;
    }
    // printf("-{I} Length %u Bytes Good for %u Channels :)\n", secretsLen, _numChannels);

    _globalSecretsValid = 1;

    // Print global secrets for debug
    // TODO: Make sure removed in production!!
    // _print_global_secrets();

    // printf("-COMPLETE\n\n");
    return 0;
}

/** @brief Updates the given pointer to point to the subscription KDF key.
 * 
 * @param ppKey Set to point to the subscription KDF key
 * 
 *  @return 0 upon success, 1 if error
*/
int secrets_get_subscription_kdf_key(const uint8_t **ppKey){
    // Ensure secrets are valid
    if(_globalSecretsValid == 0){
        return 1;
    }

    *ppKey = secrets_bin_start + SUBSCRIPTION_KDF_KEY_OFFSET;
    return 0;
}

/** @brief Updates the given pointer to point to the subscription cipher auth tag.
 * 
 * @param ppKey Set to point to the subscription cipher auth tag.
 * 
 *  @return 0 upon success, 1 if error.
*/
int secrets_get_subscription_cipher_auth_tag(const uint8_t **ppCipherAuthTag){
    // Ensure secrets are valid
    if(_globalSecretsValid == 0){
        return 1;
    }

    *ppCipherAuthTag = secrets_bin_start + SUBSCRIPTION_CIPHER_AUTH_TAG_OFFSET;
    return 0;
}

/** @brief Updates the given pointer to point to the frame KDF key.
 * 
 * @param ppKey Set to point to the frame KDF key.
 * 
 *  @return 0 upon success, 1 if error.
*/
int secrets_get_frame_kdf_key(const uint8_t **ppKey){
    // Ensure secrets are valid
    if(_globalSecretsValid == 0){
        return 1;
    }

    *ppKey = secrets_bin_start + FRAME_KDF_KEY_OFFSET;
    return 0;
}

/** @brief Updates the given pointer to point to the flash KDF key.
 * 
 * @param ppKey Set to point to the flash KDF key.
 * 
 *  @return 0 upon success, 1 if error.
*/
int secrets_get_flash_kdf_key(const uint8_t **ppKey){
    // Ensure secrets are valid
    if(_globalSecretsValid == 0){
        return 1;
    }

    *ppKey = secrets_bin_start + FLASH_KDF_KEY_OFFSET;
    return 0;
}

/** @brief Updates the given pointer to point to the flash KDF input key.
 * 
 * @param ppKey Set to point to the flash KDF input key.
 * 
 *  @return 0 upon success, 1 if error.
*/
int secrets_get_flash_kdf_input_key(const uint8_t **ppKey){
    // Ensure secrets are valid
    if(_globalSecretsValid == 0){
        return 1;
    }

    *ppKey = secrets_bin_start + FLASH_KDF_INPUT_KEY_OFFSET;
    return 0;
}

/** @brief Checks if the given channel is valid in the current deployment.
 * 
 * @param channel Channel to check if is valid.
 * 
 *  @return 0 if valid, 1 if failed to find channel in current deployment.
*/
int secrets_is_valid_channel(const channel_id_t channel){
    // Ensure secrets are valid
    if(_globalSecretsValid == 0){
        return 1;
    }

    const uint8_t *ppKey;
    return _find_channel_info(channel, &ppKey);
}

/** @brief Updated the given pointer to point to the channel KDF key for 
 *         the specified channel.
 * 
 * @param channel Channel to get the KDF key for.
 * @param ppKey Set to point to the specified channel KDF key.
 * 
 *  @return 0 upon success, 1 if channel not found or failed.
*/
int secrets_get_channel_kdf_key(const channel_id_t channel, const uint8_t **ppKey){
    // Ensure secrets are valid
    if(_globalSecretsValid == 0){
        return 1;
    }

    int res = _find_channel_info(
        channel, ppKey
    );
    return res;
}

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
){
    // Ensure secrets are valid
    if(_globalSecretsValid == 0){
        return 1;
    }

    // Ensure idx is valid
    if(idx > _numChannels){
        return 1;
    }

    *ppChannel = (channel_id_t*)(secrets_bin_start + CHANNEL_INFO_OFFSET + idx*CHANNEL_LEN);
    *ppKey = secrets_bin_start + CHANNEL_INFO_OFFSET + _numChannels*CHANNEL_LEN + idx*CHANNEL_KDF_INPUT_KEY_LEN;
    return 0;
}
