#include "global_secrets.h"
#include <stdio.h>
#include <string.h>

#include "crypto.h"

/******************************** PRIVATE CONSTANTS ********************************/
// Minimum size for global secrets
// [0]: Subscription KDF Key (32 bytes)
// [32]: Subscription Cipher Auth Tag Key (16 bytes)
// [48]: Frame KDF Keys (32 Bytes)
// [80]: Num channels (2 bytes) -> 1 channel in deployment
// [82]: First channel in deployment (2 bytes)
// [84]: Channel KDF key (32 bytes)
// 32 + 16 + 32 + 2 + 2 + 32 -> 116 bytes
#define GLOBAL_SECRETS_MIN_SIZE (SUBSCRIPTION_KDF_KEY_LEN + SUBSCRIPTION_CIPHER_AUTH_TAG_LEN + FRAME_KDF_KEY_LEN + 2 + (2 + CHANNEL_KDF_KEY_LEN))

// Defines for byte offset of the variables stored in flash
#define SUBSCRIPTION_KDF_KEY_OFFSET         (0)
#define SUBSCRIPTION_CIPHER_AUTH_TAG_OFFSET (SUBSCRIPTION_KDF_KEY_OFFSET + SUBSCRIPTION_KDF_KEY_LEN)
#define FRAME_KDF_KEY_OFFSET                (SUBSCRIPTION_CIPHER_AUTH_TAG_OFFSET + SUBSCRIPTION_CIPHER_AUTH_TAG_LEN)
#define NUM_CHANNELS_OFFSET                 (FRAME_KDF_KEY_OFFSET + FRAME_KDF_KEY_LEN)
#define CHANNEL_INFO_OFFSET                 (NUM_CHANNELS_OFFSET + 2)

/******************************** PRIVATE TYPES ********************************/
typedef struct __attribute__((packed)) {
    uint16_t channel;
    uint8_t pKey[CHANNEL_KDF_KEY_LEN];
} channel_key_pair_t;

/******************************** EXTERN VARIABLES ********************************/
// Start and end bytes of the global secrets
extern const uint8_t secrets_bin_start[];
extern const uint8_t secrets_bin_end[];

/******************************** PRIVATE VARIABLES ********************************/
static uint8_t globalSecretsValid = 0;
static uint16_t numChannels = 0;

/******************************** PRIVATE FUNCTION DECLARATIONS ********************************/
static uint32_t _num_channels_to_length(const uint16_t numChannels){
    return SUBSCRIPTION_KDF_KEY_LEN + SUBSCRIPTION_CIPHER_AUTH_TAG_LEN + FRAME_KDF_KEY_LEN + CHANNEL_NUM_LEN + numChannels*(CHANNEL_LEN + CHANNEL_KDF_KEY_LEN);
}

static int _find_channel_info(
    const channel_id_t channel, const uint8_t **ppKey
){  
    // Ensure secrets are valid
    if(globalSecretsValid == 0){
        return 1;
    }

    // Loop through all the channel key pairs to see if the channel exists
    for(size_t i = 0; i < numChannels; i++){
        uint16_t foundChannel = *(uint16_t*)(secrets_bin_start + CHANNEL_INFO_OFFSET + i*CHANNEL_LEN);
        if(channel == foundChannel){
            *ppKey = secrets_bin_start + CHANNEL_INFO_OFFSET + numChannels*CHANNEL_LEN + i*CHANNEL_KDF_KEY_LEN;
            return 0;
        }
    }

    return 1;
}

static void _print_global_secrets(void){
    // Ensure secrets are valid
    if(globalSecretsValid == 0){
        return;
    }

    const uint8_t *pSubscriptionKdfKey;
    const uint8_t *pSubscriptionCipherAuthTag;
    const uint8_t *pFrameKdfKey;
    secrets_get_subscription_kdf_key(&pSubscriptionKdfKey);
    secrets_get_subscription_cipher_auth_tag(&pSubscriptionCipherAuthTag);
    secrets_get_frame_kdf_key(&pFrameKdfKey);

    printf("-{I} Subscription KDF Key: ");
    crypto_print_hex(pSubscriptionKdfKey, SUBSCRIPTION_KDF_KEY_LEN);
    printf("-{I} Subscription Cypher Auth Tag: ");
    crypto_print_hex(pSubscriptionCipherAuthTag, SUBSCRIPTION_CIPHER_AUTH_TAG_LEN);
    printf("-{I} Frame KDF Key: ");
    crypto_print_hex(pFrameKdfKey, FRAME_KDF_KEY_LEN);
    printf("-{I} %u Channels:\n", numChannels);

    for(size_t i = 0; i < numChannels; i++){
        const uint16_t *pChannel;
        const uint8_t *pChannelKey;
        secrets_get_channel_info(i, &pChannel, &pChannelKey);

        printf(
            "-[%u] Channel: %u, Key: ", 
            i, *pChannel
        );
        crypto_print_hex(pChannelKey, CHANNEL_KDF_KEY_LEN);
    }
}

/******************************** PUBLIC FUNCTION DECLARATIONS ********************************/
int secrets_init(void){
    const uint8_t *pSecretsBin = (uint8_t*)secrets_bin_start;
    const uint8_t *pSecretsBinEnd = (uint8_t*)secrets_bin_end;
    const size_t secretsLen = pSecretsBinEnd-pSecretsBin;

    printf("@TASK Check Global Secrets:\n");
    printf("-{I} Secrets Start 0x%X\n", pSecretsBin);
    printf("-{I} Secrets End 0x%X\n", pSecretsBinEnd);
    printf("-{I} Secrets Length %u Bytes\n", secretsLen);
    
    for(size_t i = 0; i < secretsLen; i++){
        if((i % 16 == 0) && (i != 0)){
            printf("\n");
        }
        printf("0x%02X, ", pSecretsBin[i]);
    }
    printf("\n");

    //----- Validate format -=---//
    // Check length is good based on number of channels in deployment
    numChannels = *(uint16_t*)(pSecretsBin + NUM_CHANNELS_OFFSET);
    printf("-{I} Detected %u Channels in Deployment\n", numChannels);

    if(numChannels > MAX_CHANNEL_COUNT){
        printf("-{E} Too Many Channels in Deployment, Max %u but Found %u!!\n", MAX_CHANNEL_COUNT, numChannels);
        printf("-ERROR\n\n");
        return 1;
    }
    printf("-{I} Found %u Channels in Deployment, Less Than the Max of %u :)\n", numChannels, MAX_CHANNEL_COUNT);

    const uint32_t expectedLen = _num_channels_to_length(numChannels);
    if(expectedLen != secretsLen){
        printf("-{E} Bad Length -> Expected %u != Actual %u\n", expectedLen, secretsLen);
        printf("-ERROR\n\n");
        return 1;
    }
    printf("-{I} Length %u Bytes Good for %u Channels :)\n", secretsLen, numChannels);

    globalSecretsValid = 1;

    // Print global secrets for debug
    // TODO: Make sure removed in production!!
    _print_global_secrets();

    printf("-COMPLETE\n\n");
    return 0;
}

int secrets_get_subscription_kdf_key(const uint8_t **ppKey){
    // Ensure secrets are valid
    if(globalSecretsValid == 0){
        return 1;
    }

    *ppKey = secrets_bin_start + SUBSCRIPTION_KDF_KEY_OFFSET;
    return 0;
}

int secrets_get_subscription_cipher_auth_tag(const uint8_t **ppCipherAuthTag){
    // Ensure secrets are valid
    if(globalSecretsValid == 0){
        return 1;
    }

    *ppCipherAuthTag = secrets_bin_start + SUBSCRIPTION_CIPHER_AUTH_TAG_OFFSET;
    return 0;
}

int secrets_get_frame_kdf_key(const uint8_t **ppKey){
    // Ensure secrets are valid
    if(globalSecretsValid == 0){
        return 1;
    }

    *ppKey = secrets_bin_start + FRAME_KDF_KEY_OFFSET;
    return 0;
}

int secrets_is_valid_channel(const channel_id_t channel){
    // Ensure secrets are valid
    if(globalSecretsValid == 0){
        return 1;
    }

    const uint8_t *ppKey;
    return _find_channel_info(channel, &ppKey);
}

int secrets_get_channel_kdf_key(const channel_id_t channel, const uint8_t **ppKey){
    // Ensure secrets are valid
    if(globalSecretsValid == 0){
        return 1;
    }

    int res = _find_channel_info(
        channel, ppKey
    );
    return res;
}

int secrets_get_channel_info(
    const size_t idx, 
    uint16_t const **ppChannel, const uint8_t **ppKey
){
    // Ensure secrets are valid
    if(globalSecretsValid == 0){
        return 1;
    }

    // Ensure idx is valid
    if(idx > numChannels){
        return 1;
    }

    *ppChannel = (uint16_t*)(secrets_bin_start + CHANNEL_INFO_OFFSET + idx*CHANNEL_LEN);
    *ppKey = secrets_bin_start + CHANNEL_INFO_OFFSET + numChannels*CHANNEL_LEN + idx*CHANNEL_KDF_KEY_LEN;
    return 0;
}
