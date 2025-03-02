/**
 * @file subscription_manager.c
 * @author Simon Rosenzweig
 * @brief Channel Manager implementation
 * @date 2025
 *
 * @copyright Copyright (c) 2025 The MITRE Corporation
 */

#include "subscription_manager.h"

#include "FreeRTOS.h"
#include "task.h"
#include "queue.h"
#include "string.h"

#include "crypto_manager.h"
#include "channel_manager.h"
#include "global_secrets.h"

#include "host_messaging.h"
#include "crypto.h"

//----- Private Constants -----//
#define RTOS_QUEUE_LENGTH 16

#define CTR_NONCE_RAND_LEN 12

#define SUBSCRIPTION_UPDATE_MSG_LEN 64

#define SUBSCRIPTION_KDF_DATA_LENGTH 32
#define SUBSCRIPTION_KDF_CHANNEL_KEY_LEN 23

#define SUBSCRIPTION_CIPHER_TEXT_LEN 32


// Constants added to KDF input to ensure MIC and encryption key are different
#define SUBSCRIPTION_MIC_KEY_TYPE 0xC7
#define SUBSCRIPTION_ENCRYPTION_KEY_TYPE 0x98

//----- Private Types -----//

// Data used to derive the frame MIC and encryption secret key from
typedef struct __attribute__((packed)) {
    // Either "SUBSCRIPTION_MIC_KEY_TYPE" or "SUBSCRIPTION_ENCRYPTION_KEY_TYPE"
    uint8_t type;

    uint8_t channelKey[SUBSCRIPTION_KDF_CHANNEL_KEY_LEN];
    uint32_t deviceId;
    channel_id_t channel;
} subscription_kdf_data_t;
  
// Subscription update packet structure
typedef struct __attribute__((packed)) {
    channel_id_t channel;
    uint8_t ctrNonceRand[CTR_NONCE_RAND_LEN];
    uint8_t cipherText[SUBSCRIPTION_CIPHER_TEXT_LEN];
    uint8_t mic[CRYPTO_MANAGER_MIC_LEN];
} subscription_update_packet_t;

//----- Private Variables -----//

// Task request queue
static QueueHandle_t _xRequestQueue;

//----- Private Functions -----//

/** @brief Assemble KDF input data based on the given subscription packet
 * 
 * @param type key type to derive, either "SUBSCRIPTION_MIC_KEY_TYPE" or "SUBSCRIPTION_ENCRYPTION_KEY_TYPE"
 * @param pSubscriptionPacket Frame packet, some information used in KDF
 * @param pKdfData KDF input structure to fill out
 * 
 *  @return 0 on success, number on fail
 */
static int _assembleKdfData(
    const uint8_t type,
    const subscription_update_packet_t *pSubscriptionPacket,
    CryptoManager_KeyDerivationData *pKdfData
){  
    int res;
    
    // Validate KDF struct size is as expected 
    // - If not, is due to bad code and compiler screwing up the format
    if(sizeof(subscription_kdf_data_t) != SUBSCRIPTION_KDF_DATA_LENGTH){
        // printf("-{E} Bad Subscription KDF Data Struct Length!!\n");
        // printf("-FAIL\n");
        return 1;
    }

    subscription_kdf_data_t subscriptionKdfData;
    subscriptionKdfData.type = type;
    subscriptionKdfData.deviceId = cryptoManager_DecoderId();
    subscriptionKdfData.channel = pSubscriptionPacket->channel;

    // Set channel key 
    // Byte offset: 1
    const uint8_t *pChannelKdfKey;
    res = cryptoManager_GetChannelKdfInputKey(pSubscriptionPacket->channel, &pChannelKdfKey);
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
    memcpy((pKdfData->pNonce)+sizeof(uint32_t), pSubscriptionPacket->ctrNonceRand, CTR_NONCE_RAND_LEN);
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

    // Copy required data into given kdf data object
    memcpy(pKdfData->pData, &subscriptionKdfData, SUBSCRIPTION_KDF_DATA_LENGTH);
    return 0;
}

/** @brief Checks the MIC is valid on the given frame packet, 
 *         calls into Crypto Manager
 * 
 * @param pSubscriptionPacket Subscription update packet to calculate and 
 *                            check MIC on
 * 
 *  @return 0 if MIC valid, number on fail
 */
static int _checkMic(
    const subscription_update_packet_t *pSubscriptionPacket
){  
    int res;
    QueueHandle_t xRequestQueue = cryptoManager_RequestQueue();

    // printf("[SubscriptionManager] @INFO Sending Signature Check Request\n");

    //-- Prepare the Signature Check Packet --//
    CryptoManager_SignatureCheck cryptoSigCheck;

    //-- Assemble KDF Data
    cryptoSigCheck.kdfData.keySource = KEY_SOURCE_SUBSCRIPTION_KDF;
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
    xTaskNotifyWait(0, 0xFFFFFFFF, (uint32_t*)&res, portMAX_DELAY);

    // printf("[SubscriptionManager] @INFO Signature Check res = %d\n", res);

    return res;
}

/** @brief Checks the decrypted auth token is valid, 
 *         calls into Crypto Manager
 * 
 * @param pAuthToken Pointer to auth token
 * @param len Size of pAuthToken
 * 
 *  @return 0 if valid, number on fail
 */
static int _checkDecryptedAuthToken(
    const uint8_t *pAuthToken, uint16_t len
){
    int res;
    QueueHandle_t xRequestQueue = cryptoManager_RequestQueue();

    // printf("[SubscriptionManager] @INFO Sending Check Decrypted Auth Token Request\n");

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
    xTaskNotifyWait(0, 0xFFFFFFFF, (uint32_t*)&res, portMAX_DELAY);

    // printf("[SubscriptionManager] @INFO Signature Check res = %d\n", res);
    return res;
}

/** @brief Decrypts the cipher text in the subscription update packet, 
 *         calls into Crypto Manager
 * 
 * @param pSubscriptionPacket Pointer to subscription update packet
 * @param pPlainText Point to buffer to store plain text in
 * @param plainTextLen Size of pPlainText buffer
 * 
 *  @return 0 on success, number on fail
 */
static int _decryptData(
    const subscription_update_packet_t *pSubscriptionPacket,
    uint8_t *pPlainText, size_t plainTextLen
){
    int res;
    QueueHandle_t xRequestQueue = cryptoManager_RequestQueue();

    // printf("[SubscriptionManager] @INFO Sending Decryption Request\n");

    //-- Check Arguments --//
    if(plainTextLen != SUBSCRIPTION_CIPHER_TEXT_LEN){
        // printf("-{E} Bad Plain Text Buffer Length!!\n");
        return 1;
    }

    //-- Prepare the Decryption Packet --//
    CryptoManager_DecryptData cryptoDecrypt;

    //-- Assemble KDF Data
    cryptoDecrypt.kdfData.keySource = KEY_SOURCE_SUBSCRIPTION_KDF;
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
    memcpy(pCtrNonce+sizeof(uint32_t), pSubscriptionPacket->ctrNonceRand, CTR_NONCE_RAND_LEN);
    for(size_t i = 0; i < sizeof(uint32_t); i++){
        pCtrNonce[i] = 0x00;
    }
    cryptoDecrypt.pNonce = pCtrNonce;

    cryptoDecrypt.length = SUBSCRIPTION_CIPHER_TEXT_LEN;
    cryptoDecrypt.pCipherText = pSubscriptionPacket->cipherText;

    cryptoDecrypt.pPlainText = pPlainText;

    //-- Assemble Request
    CryptoManager_Request cryptoRequest;
    cryptoRequest.xRequestingTask = xTaskGetCurrentTaskHandle();
    cryptoRequest.requestType = CRYPTO_MANAGER_REQ_DECRYPT;
    cryptoRequest.requestLen = sizeof(cryptoDecrypt);
    cryptoRequest.pRequest = &cryptoDecrypt;

    //-- Send Request and Wait
    xQueueSend(xRequestQueue, &cryptoRequest, portMAX_DELAY);
    xTaskNotifyWait(0, 0xFFFFFFFF, (uint32_t*)&res, portMAX_DELAY);

    // printf("[SubscriptionManager] @INFO Decryption res = %d\n", res);
    return res;
}

/** @brief Updates the channel subscription, calls into Channel Manager
 * 
 * @param channel Channel to update subscription of
 * @param timeStart Subscription start timestamp
 * @param timeEnd Subscription end timestamp
 * 
 *  @return 0 on success, number on fail
 */
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
    xTaskNotifyWait(0, 0xFFFFFFFF, (uint32_t*)&res, portMAX_DELAY);

    // printf("[SubscriptionManager] @INFO Update Subscription res = %d\n", res);

    return 0;
}

/** @brief Process a subscription update packet and adds it if valid. Parameters are
 *         checked, then MIC, then cipher auth token
 * 
 * @param pSubUpdate Pointer to subscription update packet
 * 
 *  @return 0 on success, number on fail
 */
static int _addSubscription(SubscriptionManager_SubscriptionUpdate *pSubUpdate){
    int res;

    // printf("\n[Subscription] @TASK Subscription Update:\n");

    // Check length is good
    if(((pSubUpdate->pktLen % SUBSCRIPTION_UPDATE_MSG_LEN) != 0) || (sizeof(subscription_update_packet_t) != SUBSCRIPTION_UPDATE_MSG_LEN)){
        // printf(
        //     "-{E} Bad Subscription Update Msg Length, Expected Multiple of %u Bytes != Actual %u Bytes\n",
        //     SUBSCRIPTION_UPDATE_MSG_LEN, pSubUpdate->pktLen
        // );
        // printf("-FAIL [Packet]\n\n");
        // STATUS_LED_RED();
        // host_print_error("Subscription Update: Bad packet size\n");
        return 1;
    }

    size_t numPackets = pSubUpdate->pktLen / SUBSCRIPTION_UPDATE_MSG_LEN;
    // printf("-{I} %u Subscription Update Packets\n", numPackets);

    // Process all the subscription update packets
    for(size_t x = 0; x < numPackets; x++){
        const subscription_update_packet_t *pUpdate = (const subscription_update_packet_t *)(pSubUpdate->pBuff + x*sizeof(subscription_update_packet_t));

        // Check channel is not the emergency channel
        if (pUpdate->channel == EMERGENCY_CHANNEL) {
            // printf(
            //     "-{E} Can't Subscribe to Emergency Channel!!\n"
            // );
            // printf("-FAIL [Emergency Channel]\n\n");
            // STATUS_LED_RED();
            // host_print_error("Subscription Update: Cannot subscribe to emergency channel!!\n");
            return 1;
        }

        // printf("-{I} Channel: %u\n", pUpdate->channel);
        // printf("-{I} CTR Nonce Rand: ");
        // crypto_print_hex(pUpdate->ctrNonceRand, 12);
        // printf("-{I} Cypher Text: ");
        // crypto_print_hex(pUpdate->cipherText, SUBSCRIPTION_CIPHER_TEXT_LEN);
        // printf("-{I} MIC: ");
        // crypto_print_hex(pUpdate->mic, CRYPTO_MANAGER_MIC_LEN);

        // Check MIC
        res = _checkMic(pUpdate);
        if(res != 0){
            // printf("-FAIL [MIC]\n\n");
            // STATUS_LED_RED();
            // host_print_error("Subscription Update: Bad MIC\n");
            return res;
        }

        // MIC is good so packet is unchanged
        // - Decrypt data and add it to subscription list
        CRYPTO_CREATE_CLEANUP_BUFFER(pPlainText, SUBSCRIPTION_CIPHER_TEXT_LEN);
        res = _decryptData(pUpdate, pPlainText, SUBSCRIPTION_CIPHER_TEXT_LEN);
        if(res != 0){
            // printf("-FAIL [Decrypt]\n\n");
            // STATUS_LED_RED();
            // host_print_error("Subscription Update: Decryption Failed\n");
            return res;
        }

        //-- Check Cipher Auth Tag
        const uint8_t *pDecryptedAuthTag = (pPlainText + sizeof(uint64_t));
        res = _checkDecryptedAuthToken(pDecryptedAuthTag, SUBSCRIPTION_CIPHER_AUTH_TAG_LEN);
        if(res != 0){
            // printf("-FAIL [Cipher Auth Tag]\n\n");
            // STATUS_LED_RED();
            // host_print_error("Subscription Update: Cipher Auth Tag Check Failed\n");
            return res;

        }

        //-- Process Results and Update Subscription
        // MIC and Cipher auth tag have been verified :)
        uint64_t timeStampStart = *((uint64_t*)pPlainText);
        uint64_t timeStampEnd = *((uint64_t*)(pPlainText + sizeof(uint64_t) + SUBSCRIPTION_CIPHER_AUTH_TAG_LEN));

        // printf("-{I} Time Stamp Start: %llu\n", timeStampStart);
        // printf("-{I} Time Stamp End: %llu\n", timeStampEnd);

        res = _updateSubscription(pUpdate->channel, timeStampStart, timeStampEnd);
        if(res != 0){
            // printf("-FAIL [Subscription Update]\n\n");
            // host_print_error("Subscription Update: Channel Update Failed\n");
            // STATUS_LED_RED();
            // host_print_error("Subscription Update: Channel Update Failed\n");
            return res;
        }
    }
    
    // Success message with an empty body
    host_write_packet(SUBSCRIBE_MSG, NULL, 0);

    // printf("-COMPLETE\n");
    return 0;
}

/** @brief Processes requests from other tasks
 * 
 * @param pRequest Pointer to request structure
 * 
 * @return 0 if success, other numbers if failed
 */
static int _processRequest(SubscriptionManager_Request *pRequest){
    int res = 0;

    //-- Check Request Packet is Good
    if(pRequest->pRequest == 0){
        // printf("-{E} Bad Request Pointer!!\n"); 
        return 1;
    }

    if(pRequest->requestLen == 0){
        // printf("-{E} Bad Request Length!!\n"); 
        return 1;
    }

    //-- Execute Request
    switch (pRequest->requestType){
        case SUBSCRIPTION_MANAGER_SUB_UPDATE:
            // printf("-{I} Subscription Update Request\n");

            // Check request length is good
            if(pRequest->requestLen != sizeof(SubscriptionManager_SubscriptionUpdate)){
                // printf("-{E} Bad Request Length!!\n");
                return 0;
            }

            SubscriptionManager_SubscriptionUpdate *pSubUpdate = pRequest->pRequest;
            res = _addSubscription(pSubUpdate);
            break;
        default:
            // printf("-{E} Unknown Request Type!!\n");
            res = 1;
            break;
    }
    return res;
}


//----- Public Functions -----//

/** @brief Initializes the Subscription Manager ready for the main task to be run
 * 
 * @note Must be called before RTOS scheduler starts!!
 */
void subscriptionManager_Init(void){
    // Setup request queue
    _xRequestQueue = xQueueCreate(
        RTOS_QUEUE_LENGTH, sizeof(SubscriptionManager_Request)
    );
}

/** @brief Subscription Interface Manager main RTOS task
 * 
 * @param pvParameters FreeRTOS task parameters
 */
void subscriptionManager_vMainTask(void *pvParameters){
    SubscriptionManager_Request subscriptionRequest;

    while (1){
        if (xQueueReceive(_xRequestQueue, &subscriptionRequest, portMAX_DELAY) == pdPASS){
            // printf("[SubscriptionManager] @TASK Received Request\n");
            int res = _processRequest(&subscriptionRequest);
            // printf("-COMPLETE\n");

            // Signal the requesting task that request is complete
            xTaskNotify(subscriptionRequest.xRequestingTask, res, eSetValueWithOverwrite);
        }
    }
}

/** @brief Returns Subscription Manager request queue 
 * 
 * @param QueueHandle_t Request queue to send requests to Subscription Manager
 */
QueueHandle_t subscriptionManager_RequestQueue(void){
    return _xRequestQueue;
}