#include "subscription_manager.h"
#include "crypto.h"

#include "FreeRTOS.h"
#include "task.h"
#include "queue.h"
#include "string.h"

#include "crypto_manager.h"
#include "channel_manager.h"
#include "global_secrets.h"


//----- Private Constants -----//
#define SUBSCRIPTION_UPDATE_MSG_LEN 64

#define SUBSCRIPTION_KDF_DATA_LENGTH 32
#define SUBSCRIPTION_KDF_CHANNEL_KEY_LEN 25

#define SUBSCRIPTION_CIPHER_TEXT_LEN 32

#define SUBSCRIPTION_MIC_KEY_TYPE 0xC7
#define SUBSCRIPTION_ENCRYPTION_KEY_TYPE 0x98

#define CTR_NONCE_RAND_LEN 12

//----- Private Types -----//
typedef struct __attribute__((packed)) {
    uint8_t type;
    uint8_t channelKey[SUBSCRIPTION_KDF_CHANNEL_KEY_LEN];
    uint32_t deviceId;
    uint16_t channel;
  } subscription_kdf_data_t;
  
  typedef struct __attribute__((packed)) {
    channel_id_t channel;
    uint8_t ctr_nonce_rand[CTR_NONCE_RAND_LEN];
    uint8_t cipher_text[SUBSCRIPTION_CIPHER_TEXT_LEN];
    uint8_t mic[CRYPTO_MANAGER_MIC_LEN];
  } subscription_update_packet_t;

//----- Private Variables -----//


//----- Private Functions -----//
static int _assembleKdfData(
    const uint8_t type,
    const subscription_update_packet_t *pSubscriptionPacket,
    CryptoManager_KeyDerivationData *pKdfData
){  
    int res;
    
    // Validate KDF struct size is as expected 
    // - If not, is due to bad code and compiler screwing up the format
    if(sizeof(subscription_kdf_data_t) != SUBSCRIPTION_KDF_DATA_LENGTH){
        printf("-{E} Bad Subscription KDF Data Struct Length!!\n");
        printf("-FAIL\n");
        return 1;
    }

    subscription_kdf_data_t subscriptionKdfData;
    subscriptionKdfData.type = type;
    subscriptionKdfData.deviceId = cryptoManager_DecoderId();
    subscriptionKdfData.channel = pSubscriptionPacket->channel;

    // Set channel key 
    // Byte offset: 1
    const uint8_t *pChannelKdfKey;
    res = cryptoManager_GetChannelKdfKey(pSubscriptionPacket->channel, &pChannelKdfKey);
    if(res != 0){
        // printf("-{E} Failed to find Channel KDF key for Channel %u!!\n", channel);
        // printf("-FAIL\n");
        return res;
    }
    memcpy(&subscriptionKdfData.channelKey, pChannelKdfKey, SUBSCRIPTION_KDF_CHANNEL_KEY_LEN);

    // Assemble CTR nonce
    // [0]: Decoder ID (4 Bytes, Big Endian)
    // [4]: Nonce Rand (12 Bytes)
    uint32_t decoderId = cryptoManager_DecoderId();
    memcpy((pKdfData->pNonce)+sizeof(uint32_t), pSubscriptionPacket->ctr_nonce_rand, CTR_NONCE_RAND_LEN);
    for(size_t i = 0; i < sizeof(uint32_t); i++){
        pKdfData->pNonce[i] = ((uint8_t*)&decoderId)[3-i];
    }

    // Increment nonce by one for encryption KDF
    if (type == SUBSCRIPTION_ENCRYPTION_KEY_TYPE){
        for (size_t i = CTR_NONCE_RAND_LEN - 1; i >= 0; i--) {
            pKdfData->pNonce[4 + i]++;
            if (pKdfData->pNonce[4 + i] != 0){
                break; 
            }
        }
    }

    CRYPTO_CREATE_CLEANUP_BUFFER(pCipherText, SUBSCRIPTION_KDF_DATA_LENGTH);

    // Copy required data into given kdf data object
    memcpy(pKdfData->pData, &subscriptionKdfData, SUBSCRIPTION_KDF_DATA_LENGTH);

    return 0;
}

static int _checkMic(
    const subscription_update_packet_t *pSubscriptionPacket
){  
    int res;
    QueueHandle_t xRequestQueue = cryptoManager_RequestQueue();
    uint32_t ulNotificationValue;

    printf("[SubscriptionManager] @INFO Sending Signature Check Request\n");

    //-- Prepare the Signature Check Packet --//
    CryptoManager_SignatureCheck cryptoSigCheck;

    //-- Assemble KDF Data
    cryptoSigCheck.kdfData.keySource = SUBSCRIPTION_KDF_KEY;
    cryptoSigCheck.kdfData.length = sizeof(subscription_kdf_data_t);

    // Allocate stack buffer space for 
    // - KDF input data
    // - KDF AES nonce
    CRYPTO_CREATE_CLEANUP_BUFFER(tData, SUBSCRIPTION_KDF_DATA_LENGTH);
    cryptoSigCheck.kdfData.pData = tData;

    CRYPTO_CREATE_CLEANUP_BUFFER(pCtrNonce, CRYPTO_MANAGER_NONCE_LEN);
    cryptoSigCheck.kdfData.pNonce = pCtrNonce;

    // Assemble the KDF input data
    res = _assembleKdfData(
        SUBSCRIPTION_MIC_KEY_TYPE,
        pSubscriptionPacket, &cryptoSigCheck.kdfData
    );
    if(res != 0){
        return res;
    }
    
    //-- Assemble Signature Check Data
    // MIC is calculated on the whole packet minus the MIC
    cryptoSigCheck.pData = (uint8_t*)pSubscriptionPacket;
    cryptoSigCheck.length = sizeof(subscription_update_packet_t) - CRYPTO_MANAGER_MIC_LEN;
    cryptoSigCheck.pExpectedSignature = pSubscriptionPacket->mic;
    
    //-- Assemble Request
    CryptoManager_Request cryptoRequest;
    cryptoRequest.xRequestingTask = xTaskGetCurrentTaskHandle();
    cryptoRequest.requestType = CRYPTO_MANAGER_REQ_SIG_CHECK;
    cryptoRequest.requestLen = sizeof(cryptoSigCheck);
    cryptoRequest.pRequest = &cryptoSigCheck;

    //-- Send Request and Wait
    xQueueSend(xRequestQueue, &cryptoRequest, portMAX_DELAY);
    xTaskNotifyWait(0, 0xFFFFFFFF, &res, portMAX_DELAY);

    printf("[SubscriptionManager] @INFO Signature Check res = %d\n", res);

    return res;
}

static int _checkDecryptedAuthToken(
    const uint8_t *pAuthToken, uint16_t len
){
    int res;
    QueueHandle_t xRequestQueue = cryptoManager_RequestQueue();

    printf("[SubscriptionManager] @INFO Sending Check Decrypted Auth Token Request\n");

    //-- Prepare the Auth Token Check Packet --//
    CryptoManager_SubDecryptedAuthTokenCheck cryptoDecryptedAuthTokenCheck;

    cryptoDecryptedAuthTokenCheck.pPacketAuthToken = pAuthToken;
    cryptoDecryptedAuthTokenCheck.length = len;

    //-- Assemble Request
    CryptoManager_Request cryptoRequest;
    cryptoRequest.xRequestingTask = xTaskGetCurrentTaskHandle();
    cryptoRequest.requestType = CRYPTO_MANAGER_REQ_CHECK_SUB_DECRYPTED_AUTH_TOKEN;
    cryptoRequest.requestLen = sizeof(cryptoDecryptedAuthTokenCheck);
    cryptoRequest.pRequest = &cryptoDecryptedAuthTokenCheck;

    //-- Send Request and Wait
    xQueueSend(xRequestQueue, &cryptoRequest, portMAX_DELAY);
    xTaskNotifyWait(0, 0xFFFFFFFF, &res, portMAX_DELAY);

    printf("[SubscriptionManager] @INFO Signature Check res = %d\n", res);
    return res;
}

static int _decryptData(
    const subscription_update_packet_t *pSubscriptionPacket,
    uint8_t *pPlainText, size_t plainTextLen
){
    int res;
    QueueHandle_t xRequestQueue = cryptoManager_RequestQueue();

    printf("[SubscriptionManager] @INFO Sending Decryption Request\n");

    //-- Check Arguments --//
    if(plainTextLen != SUBSCRIPTION_CIPHER_TEXT_LEN){
        printf("-{E} Bad Plain Text Buffer Length!!\n");
        return 1;
    }

    //-- Prepare the Decryption Packet --//
    CryptoManager_DecryptData cryptoDecrypt;

    //-- Assemble KDF Data
    cryptoDecrypt.kdfData.keySource = SUBSCRIPTION_KDF_KEY;
    cryptoDecrypt.kdfData.length = sizeof(subscription_kdf_data_t);

    // Allocate stack buffer space for 
    // - KDF input data
    // - KDF AES nonce
    CRYPTO_CREATE_CLEANUP_BUFFER(tData, SUBSCRIPTION_KDF_DATA_LENGTH);
    cryptoDecrypt.kdfData.pData = tData;

    CRYPTO_CREATE_CLEANUP_BUFFER(pKdfCtrNonce, CRYPTO_MANAGER_NONCE_LEN);
    cryptoDecrypt.kdfData.pNonce = pKdfCtrNonce;

    // Assemble the KDF input data
    res = _assembleKdfData(
        SUBSCRIPTION_ENCRYPTION_KEY_TYPE,
        pSubscriptionPacket, &cryptoDecrypt.kdfData
    );
    if(res != 0){
        return res;
    }

    //-- Assemble Decryption Data
    // Assemble AES CTR nonce
    // [0]: 0x00 (4 Bytes)
    // [4]: Nonce Rand (12 Bytes)
    CRYPTO_CREATE_CLEANUP_BUFFER(pCtrNonce, CRYPTO_AES_BLOCK_SIZE_BYTE);
    memcpy(pCtrNonce+sizeof(uint32_t), pSubscriptionPacket->ctr_nonce_rand, CTR_NONCE_RAND_LEN);
    for(size_t i = 0; i < sizeof(uint32_t); i++){
        pCtrNonce[i] = 0x00;
    }
    cryptoDecrypt.pNonce = pCtrNonce;

    cryptoDecrypt.length = SUBSCRIPTION_CIPHER_TEXT_LEN;
    cryptoDecrypt.pCipherText = pSubscriptionPacket->cipher_text;

    cryptoDecrypt.pPlainText = pPlainText;

    //-- Assemble Request
    CryptoManager_Request cryptoRequest;
    cryptoRequest.xRequestingTask = xTaskGetCurrentTaskHandle();
    cryptoRequest.requestType = CRYPTO_MANAGER_REQ_DECRYPT;
    cryptoRequest.requestLen = sizeof(cryptoDecrypt);
    cryptoRequest.pRequest = &cryptoDecrypt;

    //-- Send Request and Wait
    xQueueSend(xRequestQueue, &cryptoRequest, portMAX_DELAY);
    xTaskNotifyWait(0, 0xFFFFFFFF, &res, portMAX_DELAY);

    printf("[SubscriptionManager] @INFO Decryption res = %d\n", res);
    return res;
}

static int _updateSubscription(
    const channel_id_t channel, 
    const timestamp_t timeStart, const timestamp_t timeEnd
){
    int res;
    QueueHandle_t xRequestQueue = channelManager_RequestQueue();

    //-- Prepare the Sub Update Packet --//
    ChannelManager_UpdateSubscription channelUpdateSub;

    channelUpdateSub.channel = channel;
    channelUpdateSub.timeStart = timeStart;
    channelUpdateSub.timeEnd = timeEnd;

    //-- Assemble Request
    ChannelManager_Request channelRequest;
    channelRequest.xRequestingTask = xTaskGetCurrentTaskHandle();
    channelRequest.requestType = CHANNEL_MANAGER_UPDATE_SUB;
    channelRequest.requestLen = sizeof(channelUpdateSub);
    channelRequest.pRequest = &channelUpdateSub;

    //-- Send Request and Wait
    xQueueSend(xRequestQueue, &channelRequest, portMAX_DELAY);
    xTaskNotifyWait(0, 0xFFFFFFFF, &res, portMAX_DELAY);

    printf("[SubscriptionManager] @INFO Update Subscription res = %d\n", res);

    return 0;
}

static int _addSubscription(const uint8_t *pData, const pkt_len_t pkt_len){
    int res;

    printf("\n[Subscription] @TASK Subscription Update:\n");

    // Check length is good
    if(((pkt_len % SUBSCRIPTION_UPDATE_MSG_LEN) != 0) || (sizeof(subscription_update_packet_t) != SUBSCRIPTION_UPDATE_MSG_LEN)){
        // STATUS_LED_RED();
        printf(
            "-{E} Bad Subscription Update Msg Length, Expected Multiple of %u Bytes != Actual %u Bytes\n",
            SUBSCRIPTION_UPDATE_MSG_LEN, pkt_len
        );
        printf("-FAIL [Packet]\n\n");
        // host_print_error("Subscription Update: Bad packet size\n");
        return 1;
    }

    size_t numPackets = pkt_len / SUBSCRIPTION_UPDATE_MSG_LEN;
    printf("-{I} %u Subscription Update Packets\n", numPackets);

    // Process all the subscription update packets
    for(size_t x = 0; x < numPackets; x++){
        const subscription_update_packet_t *pUpdate = (const subscription_update_packet_t *)(pData + x*sizeof(subscription_update_packet_t));

        // Check channel is not the emergency channel
        if (pUpdate->channel == EMERGENCY_CHANNEL) {
            // STATUS_LED_RED();
            printf(
                "-{E} Can't Subscribe to Emergency Channel!!\n"
            );
            printf("-FAIL [Emergency Channel]\n\n");
            // host_print_error("Subscription Update: Cannot subscribe to emergency channel!!\n");
            // host_print_error("Subscription Update: Can't subscribe to emergency\n");
            return 1;
        }

        // Channel is 4 bytes in the subscription update structure but max expected is 2 byte in python
        // - Verify that the channel fits in 2 bytes to prevent undefined behaviour later on
        if(pUpdate->channel > 0xFFFF){
            // STATUS_LED_RED();
            printf(
                "-{E} Channel Number Greater than 0xFFFF!!\n"
            );
            printf("-FAIL [Channel Num]\n\n");
            // host_print_error("Subscription Update: Channel number too big\n");
            return 1;
        }

        printf("-{I} Channel: %u\n", pUpdate->channel);
        printf("-{I} CTR Nonce Rand: ");
        crypto_print_hex(pUpdate->ctr_nonce_rand, 12);
        printf("-{I} Cypher Text: ");
        crypto_print_hex(pUpdate->cipher_text, SUBSCRIPTION_CIPHER_TEXT_LEN);
        printf("-{I} MIC: ");
        crypto_print_hex(pUpdate->mic, CRYPTO_MANAGER_MIC_LEN);

        // Check MIC
        res = _checkMic(pUpdate);
        if(res != 0){
            printf("-FAIL [MIC]\n\n");
            return res;
        }

        // MIC is good so packet is unchanged
        // - Decrypt data and add it to subscription list
        CRYPTO_CREATE_CLEANUP_BUFFER(pPlainText, SUBSCRIPTION_CIPHER_TEXT_LEN);
        res = _decryptData(pUpdate, pPlainText, SUBSCRIPTION_CIPHER_TEXT_LEN);
        if(res != 0){
            // STATUS_LED_RED();
            printf("-FAIL [Decrypt]\n\n");
            // host_print_error("Subscription Update: Decryption Failed\n");
            return res;
        }

        //-- Check Cipher Auth Tag
        const uint8_t *pDecryptedAuthTag = (pPlainText + sizeof(uint64_t));
        res = _checkDecryptedAuthToken(pDecryptedAuthTag, SUBSCRIPTION_CIPHER_AUTH_TAG_LEN);
        if(res != 0){
            // STATUS_LED_RED();
            printf("-FAIL [Cipher Auth Tag]\n\n");
            // host_print_error("Subscription Update: Cipher Auth Tag Failed\n");
            return res;

        }

        //-- Process Results and Update Subscription
        // MIC and Cipher auth tag have been verified :)
        uint64_t timeStampStart = *((uint64_t*)pPlainText);
        uint64_t timeStampEnd = *((uint64_t*)(pPlainText + sizeof(uint64_t) + SUBSCRIPTION_CIPHER_AUTH_TAG_LEN));

        printf("-{I} Time Stamp Start: %llu\n", timeStampStart);
        printf("-{I} Time Stamp End: %llu\n", timeStampEnd);

        res = _updateSubscription(pUpdate->channel, timeStampStart, timeStampEnd);
        if(res != 0){
            // STATUS_LED_RED();
            printf("-FAIL [Subscription Update]\n\n");
            // host_print_error("Subscription Update: Channel Update Failed\n");
            return res;
        }
    }

    printf("-COMPLETE\n");
    return 0;
}

//----- Public Functions -----//
void subscriptionManager_vMainTask(void *pvParameters){
    while (1){
        uint8_t subRequestPacket[] = {
            0x01, 0x00, 0x00, 0x00, 0xDA, 0xB8, 0x70, 0x45, 
            0x2C, 0xDF, 0xF3, 0x8C, 0xD5, 0x7E, 0xD0, 0x67, 
            0x51, 0x3B, 0x6A, 0x78, 0xD4, 0x14, 0x04, 0xD1, 
            0x7E, 0x60, 0xA5, 0x5B, 0xA5, 0x37, 0xBB, 0x8B, 
            0xFD, 0xC4, 0x5C, 0xF3, 0x20, 0x1F, 0x7E, 0x75, 
            0x51, 0x27, 0x8C, 0x1E, 0x2E, 0xA9, 0x8B, 0x7F, 
            0xC0, 0xE5, 0x16, 0x7A, 0xA0, 0x86, 0x58, 0x8E, 
            0xBE, 0x28, 0xBA, 0x8A, 0x46, 0x77, 0x97, 0x5A,
        };
        _addSubscription(subRequestPacket, sizeof(subRequestPacket));

        // vTaskDelay(pdMS_TO_TICKS(500));
        while(1);
    }
}