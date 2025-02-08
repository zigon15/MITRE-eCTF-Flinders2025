#include "global_secrets.h"
#include <stdio.h>
#include <string.h>

#include "crypto.h"

/******************************** PRIVATE CONSTANTS ********************************/
// Minimum size for global secrets
// [0]: Subscription KDF Key (32 bytes)
// [32]: Frame KDF Keys (32 Bytes)
// [64]: Num channels (2 bytes) -> 1 channel in deployment
// [66]: First channel in deployment (2 bytes)
// [68]: Channel KDF key (32 bytes)
// 32 +32 + 2 + 2 + 32 -> 100 bytes
#define GLOBAL_SECRETS_MIN_SIZE (SUBSCRIPTION_KDF_KEY_LEN + FRAME_KDF_KEY_LEN + 2 + (2 + CHANNEL_KDF_KEY_LEN))

#define MAX_CHANNELS 16

// Defines for byte offset of the variables stored in flash
#define SUBSCRIPTION_KDF_KEY_OFFSET (0)
#define FRAME_KDF_KEY_OFFSET        (SUBSCRIPTION_KDF_KEY_LEN)
#define NUM_CHANNELS_OFFSET         (FRAME_KDF_KEY_OFFSET + FRAME_KDF_KEY_LEN)
#define CHANNEL_INFO_OFFSET         (NUM_CHANNELS_OFFSET + 2)
#define CHANNEL_INFO_SIZE           (2 + CHANNEL_KDF_KEY_LEN)

/******************************** PRIVATE TYPES ********************************/
typedef struct __attribute__((packed)) {
    uint16_t channel;
    uint8_t pKey[CHANNEL_KDF_KEY_LEN];
} channel_key_pair_t;

/******************************** EXTERN VARIABLES ********************************/
// Start and end bytes of the global secrets
extern uint8_t secrets_bin_start[];
extern uint8_t secrets_bin_end[];

/******************************** PRIVATE VARIABLES ********************************/
// TODO: Get rid of this struct and reference flash memory directly
// - Want as little crypto material in ram as possible
static struct {
    uint8_t valid;
    uint8_t subscription_kdf_key[SUBSCRIPTION_KDF_KEY_LEN];
    uint8_t frame_kdf_key[FRAME_KDF_KEY_LEN];

    // Can store 16 channels max!!
    uint8_t num_channels;
    channel_key_pair_t channel_key_pairs[16];
} global_secrets = {
    .valid = 0
};

/******************************** PRIVATE FUNCTION DECLARATIONS ********************************/
static uint32_t _num_channels_to_length(uint16_t numChannels){
    return SUBSCRIPTION_KDF_KEY_LEN + FRAME_KDF_KEY_LEN + 2 + numChannels*(2 + CHANNEL_KDF_KEY_LEN);
}

static int16_t _channel_to_idx(uint16_t channel){
    // Loop through all the channel key pairs to see if the channel exists
    for(uint16_t i = 0; i < global_secrets.num_channels; i++){
        if(global_secrets.channel_key_pairs[i].channel == channel){
            return i;
        }
    }

    return -1;
}

static void _print_global_secrets(){
    printf("-{I} Subscription KDF Key: ");
    crypto_print_hex(global_secrets.subscription_kdf_key, SUBSCRIPTION_KDF_KEY_LEN);
    printf("-{I} Frame KDF Key: ");
    crypto_print_hex(global_secrets.frame_kdf_key, FRAME_KDF_KEY_LEN);
    printf("-{I} %u Channels:\n", global_secrets.num_channels);
    for(uint16_t i = 0; i < global_secrets.num_channels; i++){
        printf(
            "-[%u] Channel: %u, Key: ", 
            i, global_secrets.channel_key_pairs[i].channel
        );

        crypto_print_hex(global_secrets.channel_key_pairs[i].pKey, CHANNEL_KDF_KEY_LEN);
    }
}

/******************************** PUBLIC FUNCTION DECLARATIONS ********************************/
int secrets_init(void){
    memset(&global_secrets, 0, sizeof(global_secrets));

    uint8_t *pSecretsBin = (uint8_t*)secrets_bin_start;
    uint8_t *pSecretsBinEnd = (uint8_t*)secrets_bin_end;
    uint16_t secretsLen = pSecretsBinEnd-pSecretsBin;

    printf("@TASK Parse Secrets:\n");
    printf("-{I} Secrets Start 0x%X\n", pSecretsBin);
    printf("-{I} Secrets End 0x%X\n", pSecretsBinEnd);
    printf("-{I} Secrets Length %u Bytes\n", secretsLen);
    
    for(uint16_t i = 0; i < secretsLen; i++){
        if((i % 16 == 0) && (i != 0)){
            printf("\n");
        }
        printf("0x%02X, ", pSecretsBin[i]);
    }
    printf("\n");

    //----- Validate format -=---//
    // Check length is good based on number of channels in deployment
    uint16_t numChannels = *(uint16_t*)(pSecretsBin + NUM_CHANNELS_OFFSET);
    printf("-{I} Detected %u Channels in Deployment\n", numChannels);

    if(numChannels > MAX_CHANNEL_COUNT){
        printf("-{E} Too Many Channels in Deployment, Max %u but Found %u!!\n", MAX_CHANNEL_COUNT, numChannels);
        printf("-ERROR\n\n");
        return 1;
    }
    printf("-{I} Found %u Channels in Deployment, Less Than the Max of %u :)\n", numChannels, MAX_CHANNEL_COUNT);

    uint32_t expectedLen = _num_channels_to_length(numChannels);
    if(expectedLen != secretsLen){
        printf("-{E} Bad Length -> Expected %u != Actual %u\n", expectedLen, secretsLen);
        printf("-ERROR\n\n");
        return 1;
    }
    printf("-{I} Length %u Bytes Good for %u Channels :)\n", secretsLen, numChannels);

    // Copy subscription and frame KDF keys
    memcpy(
        global_secrets.subscription_kdf_key, 
        (pSecretsBin + SUBSCRIPTION_KDF_KEY_OFFSET), 
        SUBSCRIPTION_KDF_KEY_LEN
    );

    memcpy(
        global_secrets.frame_kdf_key, 
        (pSecretsBin + FRAME_KDF_KEY_OFFSET), 
        FRAME_KDF_KEY_LEN
    );


    // Copy over channel data
    global_secrets.num_channels = *(pSecretsBin + NUM_CHANNELS_OFFSET);

    uint16_t *pChannelNumbers = (uint16_t*)(pSecretsBin + CHANNEL_INFO_OFFSET);
    uint8_t *pChannelKeys =  (pSecretsBin + CHANNEL_INFO_OFFSET + (2 * numChannels));

    for(uint16_t i = 0; i < numChannels; i++){
        global_secrets.channel_key_pairs[i].channel = pChannelNumbers[i];
        memcpy(
            global_secrets.channel_key_pairs[i].pKey,
            pChannelKeys,
            CHANNEL_KDF_KEY_LEN
        );

        pChannelKeys += CHANNEL_KDF_KEY_LEN;
    }

    global_secrets.valid = 1;

    // Print global secrets for debug
    // TODO: Make sure removed in production!!
    _print_global_secrets();

    printf("-COMPLETE\n\n");
    return 0;
}

int secrets_get_subscription_kdf_key(uint8_t *pKey){
    // Ensure data has been parsed
    if(global_secrets.valid != 1){
        return 1;
    }

    memcpy(pKey, global_secrets.subscription_kdf_key, SUBSCRIPTION_KDF_KEY_LEN);
    return 0;
}

int secrets_get_frame_kdf_key(uint8_t *pKey){
    // Ensure data has been parsed
    if(global_secrets.valid != 1){
        return 1;
    }

    memcpy(pKey, global_secrets.frame_kdf_key, FRAME_KDF_KEY_LEN);
    return 0;
}

int secrets_is_valid_channel(channel_id_t channel){
    if(_channel_to_idx(channel) == -1){
        return 1;
    }
    return 0;
}

int secrets_get_channel_kdf_key(channel_id_t channel, uint8_t *pKey){
    int16_t idx = _channel_to_idx(channel);

    // Channel not found so return
    if(idx == -1){
        return 1;
    }

    memcpy(pKey, global_secrets.channel_key_pairs[idx].pKey, CHANNEL_KDF_KEY_LEN);
    return 0;
}

