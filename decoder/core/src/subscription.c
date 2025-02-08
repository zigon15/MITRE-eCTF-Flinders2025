#include "subscription.h"

#include <string.h>

#include "crypto.h"
#include "status_led.h"
#include "global_secrets.h"


/******************************** PRIVATE CONSTANTS ********************************/
#define SUBSCRIPTION_UPDATE_MSG_LEN 48
#define SUBSCRIPTION_KDF_DATA_LENGTH 32

#define CTR_NONCE_RAND_LEN 12

#define SUBSCRIPTION_MIC_KEY_LEN 16
#define SUBSCRIPTION_ENCRYPTION_KEY_LEN 16

/******************************** PRIVATE TYPES ********************************/
typedef struct __attribute__((packed)) {
    uint8_t type;
    uint8_t channelKey[25];
    uint32_t deviceId;
    uint16_t channel;
} subscription_kdf_data_t;

typedef struct __attribute__((packed)) {
    channel_id_t channel;
    uint8_t ctr_nonce_rand[CTR_NONCE_RAND_LEN];
    uint8_t cipher_text[16];
    uint8_t mic[16];
} subscription_update_packet_t;

/******************************** PRIVATE VARIABLES ********************************/
const uint32_t _decoder_id = DECODER_ID;

#define SUBSCRIPTION_MIC_KEY_TYPE 0xC7
#define SUBSCRIPTION_ENCRYPTION_KEY_TYPE 0x98

/******************************** PRIVATE FUNCTION DECLARATIONS ********************************/
static int _derive_subscription_keys(
    channel_id_t channel, uint8_t *pCtrNonceRand,
    uint8_t *pMicKey, uint8_t *pEncryptionKey
){  
    printf("[Subscription] @TASK Derive Keys:\n");
    
    uint8_t pTmpMicKey[SUBSCRIPTION_MIC_KEY_LEN];
    uint8_t pTmpEncryptionKey[SUBSCRIPTION_ENCRYPTION_KEY_LEN];

    // Validate struct size is as expected 
    if(sizeof(subscription_kdf_data_t) != SUBSCRIPTION_KDF_DATA_LENGTH){
        printf("-{E} Bad Subscription KDF Data Struct Length!!");
        return 1;
    }

    int res;

    subscription_kdf_data_t subscriptionKdfData;
    subscriptionKdfData.deviceId = _decoder_id;
    subscriptionKdfData.channel = channel;

    uint8_t tempKey[CHANNEL_KDF_KEY_LEN];


    // Set channel key 
    // Byte offset: 1
    res = secrets_get_channel_kdf_key(channel, tempKey);
    if(res != 0){
        return res;
    }
    memcpy(&subscriptionKdfData.channelKey, tempKey, 25);

    // Get KDF key
    uint8_t kdfKey[SUBSCRIPTION_KDF_KEY_LEN];
    res = secrets_get_subscription_kdf_key(kdfKey);
    if(res != 0){
        return res;
    }

    // Assemble CTR nonce
    uint8_t ctrNonce[CRYPTO_AES_BLOCK_SIZE_BYTE];
    memcpy(ctrNonce+4, pCtrNonceRand, CTR_NONCE_RAND_LEN);
    for(uint8_t i = 0; i < 4; i++){
        ctrNonce[i] = ((uint8_t*)&_decoder_id)[3-i];
    }

    uint8_t pCipherText[SUBSCRIPTION_KDF_DATA_LENGTH];

    printf("-{I} AES CTR Key: ");
    crypto_print_hex(kdfKey, SUBSCRIPTION_KDF_KEY_LEN);

    // Perform encryption to calculate MIC key
    subscriptionKdfData.type = SUBSCRIPTION_MIC_KEY_TYPE;
    res = crypto_AES_CTR_encrypt(
        kdfKey, MXC_AES_256BITS, ctrNonce,
        (uint8_t*)&subscriptionKdfData, pCipherText, SUBSCRIPTION_KDF_DATA_LENGTH
    );
    if(res != 0){
        return res;
    }
    memcpy(pTmpMicKey, pCipherText, SUBSCRIPTION_MIC_KEY_LEN);

    printf("-{I} MIC AES CTR Nonce: ");
    crypto_print_hex(ctrNonce, CRYPTO_AES_BLOCK_SIZE_BYTE);
    printf("-{I} MIC KDF Input Data: ");
    crypto_print_hex((uint8_t*)&subscriptionKdfData, SUBSCRIPTION_KDF_DATA_LENGTH);
    printf("-{I} MIC Key: ");
    crypto_print_hex(pTmpMicKey, SUBSCRIPTION_MIC_KEY_LEN);

    // Increment nonce by one for subscription KDF
    for (int i = CTR_NONCE_RAND_LEN - 1; i >= 0; i--) {
        ctrNonce[4 + i]++;
        if (ctrNonce[4 + i] != 0){
            break; 
        }
    }

    // Perform encryption to calculate Encryption key
    subscriptionKdfData.type = SUBSCRIPTION_ENCRYPTION_KEY_TYPE;
    res = crypto_AES_CTR_encrypt(
        kdfKey, MXC_AES_256BITS, ctrNonce,
        (uint8_t*)&subscriptionKdfData, pCipherText, SUBSCRIPTION_KDF_DATA_LENGTH
    );
    if(res != 0){
        return res;
    }
    memcpy(pTmpEncryptionKey, pCipherText, SUBSCRIPTION_ENCRYPTION_KEY_LEN);


    printf("-{I} Encryption AES CTR Nonce: ");
    crypto_print_hex(ctrNonce, CRYPTO_AES_BLOCK_SIZE_BYTE);
    printf("-{I} Encryption KDF Input Data: ");
    crypto_print_hex((uint8_t*)&subscriptionKdfData, SUBSCRIPTION_KDF_DATA_LENGTH);
    printf("-{I} Encryption Key: ");
    crypto_print_hex(pTmpEncryptionKey, SUBSCRIPTION_ENCRYPTION_KEY_LEN);

    printf("-COMPLETE\n");
    return 0;
}

/******************************** PUBLIC FUNCTION DECLARATIONS ********************************/

/** @brief Updates the channel subscription for a subset of channels.
 *
 *  @param pkt_len The length of the incoming packet
 *  @param pData   A pointer to the subscription update packet
 *
 *  @note Take care to note that this system is little endian.
 *
 *  @return 0 upon success, 1 if error
*/
// TODO: Must be able to take in multiple subscription update packets!!
int subscription_update(pkt_len_t pkt_len, uint8_t *pData){
    int res;

    printf("[Subscription] @TASK Subscription Update:\n");

    // Check length is good
    if((pkt_len != SUBSCRIPTION_UPDATE_MSG_LEN) || (sizeof(subscription_update_packet_t) != SUBSCRIPTION_UPDATE_MSG_LEN)){
        STATUS_LED_RED();
        printf(
            "-{E} Bad Subscription Update Msg Length, Expected %u Bytes != Actual %u Bytes\n",
            SUBSCRIPTION_UPDATE_MSG_LEN, pkt_len
        );
        printf("-FAIL\n\n");
        // host_print_error("Subscription Update: Bad subscription update size!!\n");
        return 1;
    }

    subscription_update_packet_t *pUpdate = (subscription_update_packet_t *)pData;

    // Check channel is not the emergency channel
    if (pUpdate->channel == EMERGENCY_CHANNEL) {
        STATUS_LED_RED();
        printf(
            "-{E} Can't Subscribe to Emergency Channel!!\n"
        );
        printf("-FAIL\n\n");
        // host_print_error("Subscription Update: Cannot subscribe to emergency channel!!\n");
        return 1;
    }

    printf("-{I} Channel: %u\n", pUpdate->channel);
    printf("-{I} CTR Nonce Rand: ");
    crypto_print_hex(pUpdate->ctr_nonce_rand, CTR_NONCE_RAND_LEN);
    printf("-{I} Cypher Text: ");
    crypto_print_hex(pUpdate->cipher_text, 16);
    printf("-{I} MIC: ");
    crypto_print_hex(pUpdate->mic, 16);


    uint8_t micKey[16];
    uint8_t subscriptionKey[16];
    res = _derive_subscription_keys(
        pUpdate->channel, pUpdate->ctr_nonce_rand,
        micKey, subscriptionKey
    );
    if(res != 0){
        return res;
    }

    // // Find the first empty slot in the subscription array
    // for (int i = 0; i < MAX_CHANNEL_COUNT; i++) {
    //     if (decoder_status.subscribed_channels[i].id == update->channel || !decoder_status.subscribed_channels[i].active) {
    //         decoder_status.subscribed_channels[i].active = true;
    //         decoder_status.subscribed_channels[i].id = update->channel;
    //         decoder_status.subscribed_channels[i].start_timestamp = update->start_timestamp;
    //         decoder_status.subscribed_channels[i].end_timestamp = update->end_timestamp;
    //         break;
    //     }
    // }

    // // If we do not have any room for more subscriptions
    // if (i == MAX_CHANNEL_COUNT) {
    //     STATUS_LED_RED();
    //     host_print_error("Failed to update subscription - max subscriptions installed\n");
    //     return 1;
    // }

    // flash_simple_erase_page(FLASH_STATUS_ADDR);
    // flash_simple_write(FLASH_STATUS_ADDR, &decoder_status, sizeof(flash_entry_t));

    // Success message with an empty body
    // host_write_packet(SUBSCRIBE_MSG, NULL, 0);
    return 0;
}