#include "subscription.h"

#include <string.h>

#include "crypto.h"
#include "status_led.h"
#include "global_secrets.h"
#include "host_messaging.h"
#include "simple_flash.h"

/******************************** PRIVATE CONSTANTS ********************************/
#define SUBSCRIPTION_UPDATE_MSG_LEN 64

#define SUBSCRIPTION_KDF_DATA_LENGTH 32

#define CTR_NONCE_RAND_LEN 12

#define SUBSCRIPTION_MIC_KEY_LEN 16
#define SUBSCRIPTION_ENCRYPTION_KEY_LEN 16

#define SUBSCRIPTION_CIPHER_TEXT_LEN 32
#define SUBSCRIPTION_MIC_LEN 16

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
    uint8_t cipher_text[SUBSCRIPTION_CIPHER_TEXT_LEN];
    uint8_t mic[SUBSCRIPTION_MIC_LEN];
} subscription_update_packet_t;

/******************************** PRIVATE VARIABLES ********************************/
const uint32_t _decoder_id = DECODER_ID;

#define SUBSCRIPTION_MIC_KEY_TYPE 0xC7
#define SUBSCRIPTION_ENCRYPTION_KEY_TYPE 0x98

/******************************** PRIVATE FUNCTION DECLARATIONS ********************************/
static int _derive_subscription_keys(
    const channel_id_t channel, const uint8_t *pCtrNonceRand,
    uint8_t *pMicKey, uint8_t *pEncryptionKey
){  
    printf("[Subscription] @TASK Derive Keys:\n");
    int res;
    
    uint8_t pTmpMicKey[SUBSCRIPTION_MIC_KEY_LEN];
    uint8_t pTmpEncryptionKey[SUBSCRIPTION_ENCRYPTION_KEY_LEN];

    // Validate struct size is as expected 
    // - If not, is due to bad code and compiler screwing up the format
    if(sizeof(subscription_kdf_data_t) != SUBSCRIPTION_KDF_DATA_LENGTH){
        printf("-{E} Bad Subscription KDF Data Struct Length!!\n");
        printf("-FAIL\n");
        return 1;
    }

    subscription_kdf_data_t subscriptionKdfData;
    subscriptionKdfData.deviceId = _decoder_id;
    subscriptionKdfData.channel = channel;


    // Set channel key 
    // Byte offset: 1
    const uint8_t *pChannelKdfKey;
    res = secrets_get_channel_kdf_key(channel, &pChannelKdfKey);
    if(res != 0){
        printf("-{E} Failed to find Channel KDF key for Channel %u!!\n", channel);
        printf("-FAIL\n");
        return res;
    }
    memcpy(&subscriptionKdfData.channelKey, pChannelKdfKey, 25);

    // Get KDF key
    const uint8_t *pSubscriptionKdfKey;
    res = secrets_get_subscription_kdf_key(&pSubscriptionKdfKey);
    if(res != 0){
        printf("-{E} Failed to find Subscription KDF key for Channel %u!!\n", channel);
        printf("-FAIL\n");
        return res;
    }

    // Assemble CTR nonce
    // [0]: Decoder ID (4 Bytes, Big Endian)
    // [4]: Nonce Rand (12 Bytes)
    uint8_t ctrNonce[CRYPTO_AES_BLOCK_SIZE_BYTE];
    memcpy(ctrNonce+sizeof(uint32_t), pCtrNonceRand, CTR_NONCE_RAND_LEN);
    for(size_t i = 0; i < sizeof(uint32_t); i++){
        ctrNonce[i] = ((uint8_t*)&_decoder_id)[3-i];
    }

    uint8_t pCipherText[SUBSCRIPTION_KDF_DATA_LENGTH];

    printf("-{I} AES CTR Key: ");
    crypto_print_hex(pSubscriptionKdfKey, SUBSCRIPTION_KDF_KEY_LEN);

    // Perform encryption to calculate MIC key
    subscriptionKdfData.type = SUBSCRIPTION_MIC_KEY_TYPE;
    res = crypto_AES_CTR_encrypt(
        pSubscriptionKdfKey, MXC_AES_256BITS, ctrNonce,
        (uint8_t*)&subscriptionKdfData, pCipherText, SUBSCRIPTION_KDF_DATA_LENGTH
    );
    if(res != 0){
        printf("-{E} AES CTR Failed for MIC Key KDF!!\n");
        printf("-FAIL\n");
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
    for (size_t i = CTR_NONCE_RAND_LEN - 1; i >= 0; i--) {
        ctrNonce[4 + i]++;
        if (ctrNonce[4 + i] != 0){
            break; 
        }
    }

    // Perform encryption to calculate Encryption key
    subscriptionKdfData.type = SUBSCRIPTION_ENCRYPTION_KEY_TYPE;
    res = crypto_AES_CTR_encrypt(
        pSubscriptionKdfKey, MXC_AES_256BITS, ctrNonce,
        (uint8_t*)&subscriptionKdfData, pCipherText, SUBSCRIPTION_KDF_DATA_LENGTH
    );
    if(res != 0){
        printf("-{E} AES CTR Failed for Encryption Key KDF!!\n");
        printf("-FAIL\n");
        return res;
    }
    memcpy(pTmpEncryptionKey, pCipherText, SUBSCRIPTION_ENCRYPTION_KEY_LEN);


    printf("-{I} Encryption AES CTR Nonce: ");
    crypto_print_hex(ctrNonce, CRYPTO_AES_BLOCK_SIZE_BYTE);
    printf("-{I} Encryption KDF Input Data: ");
    crypto_print_hex((uint8_t*)&subscriptionKdfData, SUBSCRIPTION_KDF_DATA_LENGTH);
    printf("-{I} Encryption Key: ");
    crypto_print_hex(pTmpEncryptionKey, SUBSCRIPTION_ENCRYPTION_KEY_LEN);

    // Both keys have been successfully derived so copy to the key buffers 
    memcpy(pMicKey, pTmpMicKey, SUBSCRIPTION_MIC_KEY_LEN);
    memcpy(pEncryptionKey, pTmpEncryptionKey, SUBSCRIPTION_ENCRYPTION_KEY_LEN);

    printf("-COMPLETE\n");
    return 0;
}

static int _verify_mic(
    const subscription_update_packet_t *pSubscriptionPacket, 
    const uint8_t *pMicKey
){   
    printf("[Subscription] @TASK Verify MIC:\n");
    int res;

    // MIC is calculated on the whole packet minus the MIC
    const uint16_t micInputLength = sizeof(subscription_update_packet_t) - CRYPTO_CMAC_OUTPUT_SIZE;

    // Calculate expect MIC on subscription packet
    uint8_t calculatedMic[CRYPTO_CMAC_OUTPUT_SIZE];
    res = crypto_AES_CMAC(
        pMicKey, MXC_AES_128BITS, 
        (uint8_t*)pSubscriptionPacket, micInputLength,
        calculatedMic
    );
    if(res != 0){
        return res;
    }

    printf("-{I} Input Data: ");
    crypto_print_hex((uint8_t*)pSubscriptionPacket, micInputLength);
    printf("-{I} Calculated MIC: ");
    crypto_print_hex(calculatedMic, CRYPTO_CMAC_OUTPUT_SIZE);
    printf("-{I} Packet MIC: ");
    crypto_print_hex(pSubscriptionPacket->mic, CRYPTO_CMAC_OUTPUT_SIZE);

    // Compare MIC
    if (memcmp(calculatedMic, pSubscriptionPacket->mic, CRYPTO_CMAC_OUTPUT_SIZE) != 0){
        printf("-{E} Calculated MIC Does Not Match Packet MIC!!\n");
        printf("-FAIL\n");
        return 1;
    }

    printf("-{I} Calculated MIC Matches Packet MIC :)\n");
    printf("-COMPLETE\n");
    return 0;
}

static int _decrypt_data(
    const uint8_t *pCtrNonceRand, const uint8_t *pEncryptionKey, const uint8_t *pCipherText,
    timestamp_t *pTimeStampStart, timestamp_t *pTimeStampEnd
){
    printf("[Subscription] @TASK Decrypt Data:\n");
    int res;

    // Assemble CTR nonce
    // [0]: 0x00 (4 Bytes)
    // [4]: Nonce Rand (12 Bytes)
    uint8_t ctrNonce[CRYPTO_AES_BLOCK_SIZE_BYTE];
    memcpy(ctrNonce+sizeof(uint32_t), pCtrNonceRand, CTR_NONCE_RAND_LEN);
    for(size_t i = 0; i < sizeof(uint32_t); i++){
        ctrNonce[i] = 0x00;
    }

    printf("-{I} AES CTR Nonce: ");
    crypto_print_hex(ctrNonce, CRYPTO_AES_BLOCK_SIZE_BYTE);
    printf("-{I} AES CTR Key: ");
    crypto_print_hex(pEncryptionKey, SUBSCRIPTION_ENCRYPTION_KEY_LEN);
    
    // Decrypt the data
    uint8_t pDecryptedData[SUBSCRIPTION_CIPHER_TEXT_LEN];
    res = crypto_AES_CTR_encrypt(
        pEncryptionKey, MXC_AES_128BITS, ctrNonce,
        pCipherText, pDecryptedData, SUBSCRIPTION_CIPHER_TEXT_LEN
    );
    if(res != 0){
        printf("-{E} AES CTR Failed for Cipher Text Decryption!!\n");
        printf("-FAIL\n");
        return res;
    }
    
    // Check the decrypted cipher auth tag matches expected value
    const uint8_t *pCipherAuthTag = (pDecryptedData + sizeof(uint64_t));
    const uint8_t *pExpectedCipherAuthTag;
    res = secrets_get_subscription_cipher_auth_tag(&pExpectedCipherAuthTag);
    if(res != 0){
        printf("-{E} Failed to Get Subscription Cipher Auth Tag!!\n");
        printf("-FAIL\n");
        return res;
    }

    printf("-{I} Packet Subscription Cipher Auth Tag: ");
    crypto_print_hex(pCipherAuthTag, SUBSCRIPTION_CIPHER_AUTH_TAG_LEN);

    if (memcmp(pExpectedCipherAuthTag, pCipherAuthTag, SUBSCRIPTION_CIPHER_AUTH_TAG_LEN) != 0){
        printf("-{E} Decrypted Cipher Auth Tag Does not Match One in Global Secrets!!\n");
        printf("-FAIL\n");
        return 1;
    }
    printf("-{I} Expected Cipher Auth Tag Matches Packet Cipher Auth Tag :)\n");

    // Everything is good to get subscription info and store it
    *pTimeStampStart = *((uint64_t*)pDecryptedData);
    *pTimeStampEnd = *((uint64_t*)(pDecryptedData + sizeof(uint64_t) + SUBSCRIPTION_CIPHER_AUTH_TAG_LEN));

    printf("-{I} Time Stamp Start: %llu\n", *pTimeStampStart);
    printf("-{I} Time Stamp End: %llu\n", *pTimeStampEnd);
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
int subscription_update(const pkt_len_t pkt_len, const uint8_t *pData){
    int res;

    printf("[Subscription] @TASK Subscription Update:\n");

    // Check length is good
    if((pkt_len != SUBSCRIPTION_UPDATE_MSG_LEN) || (sizeof(subscription_update_packet_t) != SUBSCRIPTION_UPDATE_MSG_LEN)){
        STATUS_LED_RED();
        printf(
            "-{E} Bad Subscription Update Msg Length, Expected %u Bytes != Actual %u Bytes\n",
            SUBSCRIPTION_UPDATE_MSG_LEN, pkt_len
        );
        printf("-FAIL [Packet]\n\n");
        // host_print_error("Subscription Update: Bad subscription update size!!\n");
        return 1;
    }

    const subscription_update_packet_t *pUpdate = (const subscription_update_packet_t *)pData;

    // Check channel is not the emergency channel
    if (pUpdate->channel == EMERGENCY_CHANNEL) {
        STATUS_LED_RED();
        printf(
            "-{E} Can't Subscribe to Emergency Channel!!\n"
        );
        printf("-FAIL [Emergency Channel]\n\n");
        // host_print_error("Subscription Update: Cannot subscribe to emergency channel!!\n");
        return 1;
    }

    printf("-{I} Channel: %u\n", pUpdate->channel);
    printf("-{I} CTR Nonce Rand: ");
    crypto_print_hex(pUpdate->ctr_nonce_rand, CTR_NONCE_RAND_LEN);
    printf("-{I} Cypher Text: ");
    crypto_print_hex(pUpdate->cipher_text, SUBSCRIPTION_CIPHER_TEXT_LEN);
    printf("-{I} MIC: ");
    crypto_print_hex(pUpdate->mic, SUBSCRIPTION_MIC_LEN);

    // Derive MIC and encryption keys
    uint8_t pMicKey[SUBSCRIPTION_MIC_KEY_LEN];
    uint8_t pEncryptionKey[SUBSCRIPTION_ENCRYPTION_KEY_LEN];
    res = _derive_subscription_keys(
        pUpdate->channel, pUpdate->ctr_nonce_rand,
        pMicKey, pEncryptionKey
    );
    if(res != 0){
        printf("-FAIL [KDF]\n\n");
        return res;
    }

    // Check packet MIC matches MIC derived from the packet data
    res = _verify_mic(pUpdate, pMicKey);
    if(res != 0){
        printf("-FAIL [MIC]\n\n");
        return res;
    }

    // MIC is good so packet is unchanged
    // - Decrypt data and add it to subscription list
    uint64_t timeStampStart;
    uint64_t timeStampEnd;
    res = _decrypt_data(
        pUpdate->ctr_nonce_rand, pEncryptionKey, pUpdate->cipher_text,
        &timeStampStart, &timeStampEnd
    );
    if(res != 0){
        printf("-FAIL [Decrypt]\n\n");
        return res;
    }

    // Find:
    // - Existing subscription for specified channel
    // - If no existing subscription for channel, then first empty slot
    printf("-{I} Looking for existing subscription for channel %u or free slot\n", pUpdate->channel);
    uint8_t foundIdx = 0;
    uint8_t idx = 0;
    for (size_t i = 0; i < MAX_CHANNEL_COUNT; i++) {
        // Break instantly if existing subscription for channel is found
        // - Always update existing subscriptions
        if (decoder_status.subscribed_channels[i].id == pUpdate->channel) {
            idx = i;
            foundIdx = 1;
            printf("-{I} Found Existing Subscription :)\n");
            break;
        }

        // Found empty spot
        // - Need to keep looping though incase there is an existing subscription for specified channel further along
        if(!decoder_status.subscribed_channels[i].active && foundIdx == 0){
            idx = i;
            foundIdx = 1;
            printf("-{I} Found Empty Slot but Looking for Existing Subscription\n");
        }
    }

    // Check if no suitable idx was found
    // - No space left in subscriptions array :(
    if (foundIdx == 0) {
        STATUS_LED_RED();
        host_print_error("Failed to update subscription - max subscriptions installed\n");
        printf("-FAIL [Max Subscription]\n\n");
        return 1;
    }

    // Update subscription info
    decoder_status.subscribed_channels[idx].active = true;
    decoder_status.subscribed_channels[idx].id = pUpdate->channel;
    decoder_status.subscribed_channels[idx].start_timestamp = timeStampStart;
    decoder_status.subscribed_channels[idx].end_timestamp = timeStampEnd;

    flash_simple_erase_page(FLASH_STATUS_ADDR);
    flash_simple_write(FLASH_STATUS_ADDR, &decoder_status, sizeof(flash_entry_t));

    // Success message with an empty body
    // host_write_packet(SUBSCRIBE_MSG, NULL, 0);

    printf("-COMPLETE\n\n");
    return 0;
}