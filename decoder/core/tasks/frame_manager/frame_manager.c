/**
 * @file frame_manager.c
 * @author Simon Rosenzweig
 * @brief Frame Manager implementation
 * @date 2025
 *
 * @copyright Copyright (c) 2025 The MITRE Corporation
 */

#include "frame_manager.h"
#include "crypto.h"

#include "FreeRTOS.h"
#include "task.h"
#include "queue.h"
#include "string.h"

#include "crypto_manager.h"
#include "channel_manager.h"
#include "global_secrets.h"
#include "host_messaging.h"

//----- Private Constants -----//
#define RTOS_QUEUE_LENGTH 16

#define FRAME_KDF_DATA_LENGTH 32
#define FRAME_KDF_CHANNEL_KEY_LEN 18

// Upper 18 bytes of channel key are used in frame KDF
// - Calculate what index to start copying for the upper 18 bytes
#define FRAME_KDF_CHANNEL_KEY_OFFSET (CHANNEL_KDF_INPUT_KEY_LEN - FRAME_KDF_CHANNEL_KEY_LEN)

#define CTR_NONCE_RAND_LEN 12

// Frame Data Packet format
// [0]: Channel (4 Bytes)
// [4]: AES CTR nonce random bytes (12 Bytes)
// [16]: Time Stamp (8 Bytes)
// [17]: Frame Length (1 Byte)
// [25]: Cipher text (FrameLen + 1 Bytes)
// [25 + FrameLen]: MIC (16 bytes)
// 4 + 12 + 8 + 1 + FrameLen + 16 = 41 + FrameLen
#define FRAME_PACKET_BASE_LEN (4 + 12 + 8 + 1 + 16)
#define FRAME_PACKET_CIPHER_TEXT_OFFSET (4 + 12 + 8 + 1)

// Constants added to KDF input to ensure MIC and encryption key are different
#define FRAME_MIC_KEY_TYPE 0x9E
#define FRAME_ENCRYPTION_KEY_TYPE 0xD7

//----- Private Types -----//

// Data used to derive the frame MIC and encryption secret key from
typedef struct __attribute__((packed)) {
    // Either "FRAME_MIC_KEY_TYPE" or "FRAME_ENCRYPTION_KEY_TYPE"
    uint8_t type;
    
    uint8_t frameDataLen;
    uint8_t channelKey[FRAME_KDF_CHANNEL_KEY_LEN];
    uint64_t timeStamp;
    channel_id_t channel;
} frame_kdf_data_t;

// Header information of frame packet
typedef struct __attribute__((packed)) {
    channel_id_t channel;
    uint8_t ctrNonceRand[CTR_NONCE_RAND_LEN];
    uint64_t timeStamp;
    uint8_t frameLen;
} frame_packet_t;

// Structure to store channel timestamp information to enforce
// timestamp monotonicity
typedef struct {
    uint8_t active;
    channel_id_t channel;
    timestamp_t lastTimeStamp;
} channel_time_stamp_t;

//----- Private Variables -----//

// Task request queue
static QueueHandle_t _xRequestQueue;

// Stores channel timestamps to enforce timestamp monotonicity
channel_time_stamp_t _channelTimeStamps[MAX_CHANNEL_COUNT];

//----- Private Functions -----//

/** @brief Find index of given channel in the time stamp storage array
 * 
 * @param channel Channel to find index of
 * 
 *  @return -1 if channel not found, else array index
 */
static int _timestamp_FindChannel(const channel_id_t channel){
    for(size_t i = 0; i < MAX_CHANNEL_COUNT; i++){
        if(_channelTimeStamps[i].active && (_channelTimeStamps[i].channel == channel)){
            return i;
        }
    }
    return -1;
}

/** @brief Checks it the timestamp has increased for the given channel
 * 
 * @param channel Channel to check timestamp increased of
 * @param timestamp Timestamp to check increased
 * 
 *  @return 0 if timestamp is good, else 1 if not incremented
 */
static int _timestamp_CheckInc(const channel_id_t channel, const timestamp_t timestamp){
    int idx = _timestamp_FindChannel(channel);

    // Check if channel was found
    if(idx == -1){
        // Channel not seen before so is increment is good
        return 0;
    }

    if(timestamp > _channelTimeStamps[idx].lastTimeStamp){
        return 0;
    }

    return 1;
}

/** @brief Updates the time stamp check structure for the given channel
 * 
 * @param channel Channel to update last timestamp of
 * @param timestamp New timestamp for channel
 * 
 *  @return 0 on success, else 1
 */
static int _timestamp_Update(channel_id_t channel, timestamp_t timestamp){
    int idx = _timestamp_FindChannel(channel);

    // Check the channel was found
    if(idx >= 0){
        _channelTimeStamps[idx].lastTimeStamp = timestamp;
        return 0;
    }

    // Channel not found so add it
    for(size_t i = 0; i < MAX_CHANNEL_COUNT; i++){
        if(_channelTimeStamps[i].active == 0){
            _channelTimeStamps[i].active = 1;
            _channelTimeStamps[i].channel = channel;
            _channelTimeStamps[i].lastTimeStamp = timestamp;
            return 0;
        }
    }

    // No room to store the channel
    return 1;
}

/** @brief Calculates the expected frame packet length based on 
 *         the number of bytes in the frame
 * 
 * @param frameLen Frame length in bytes
 * 
 *  @return Expected packet length in bytes
 */
static size_t _expectedPacketLen(const uint8_t frameLen){
    return FRAME_PACKET_BASE_LEN + frameLen + 1;
}

/** @brief Returns a pointer to the cipher text in the given frame
 * 
 * @param pFramePacket Frame packet to get cipher text from
 * 
 *  @return Pointer to frame packet cipher text
 */
static const uint8_t* _getCipherText(const frame_packet_t *pFramePacket){
    return ((uint8_t*)pFramePacket + FRAME_PACKET_CIPHER_TEXT_OFFSET);
}

/** @brief Returns a pointer to the MIC in the given frame
 * 
 * @param pFramePacket Frame packet to get MIC from
 * 
 *  @return Pointer to frame packet MIC
 */
static const uint8_t* _getMIC(const frame_packet_t *pFramePacket, const pkt_len_t pktLen){
    return ((uint8_t*)pFramePacket + pktLen - CRYPTO_MANAGER_MIC_LEN);
}

/** @brief Calculated the expected cipher text length based on 
 *         the number of bytes in the frame
 * 
 * @param frameLen Number of bytes in the frame
 * 
 *  @return Total cipher text length
 */
static size_t _calcCipherTextLen(size_t frameLen){
    // Cipher text format is
    // [0]: Frame length
    // [1:1+frameLen]: Frame data
    return frameLen + 1;
}

/** @brief Assemble KDF input data based on the given frame packet, 
 *         calls into Crypto Manager
 * 
 * @param type key type to derive, either "FRAME_MIC_KEY_TYPE" or "FRAME_ENCRYPTION_KEY_TYPE"
 * @param pFramePacket Frame packet, some information used in KDF
 * @param pKdfData KDF input structure to fill out
 * 
 *  @return 0 on success, number on fail
 */
static int _assembleKdfData(
    const uint8_t type,
    const frame_packet_t *pFramePacket,
    CryptoManager_KeyDerivationData *pKdfData
){  
    int res;
    
    // Validate KDF struct size is as expected 
    // - If not, is due to bad code and compiler screwing up the format
    if(sizeof(frame_kdf_data_t) != FRAME_KDF_DATA_LENGTH){
        // printf("-{E} Bad Frame KDF Data Struct Length!!\n");
        // printf("-FAIL\n");
        return 1;
    }

    frame_kdf_data_t frameKdfData;
    frameKdfData.type = type;
    frameKdfData.frameDataLen = pFramePacket->frameLen;
    frameKdfData.timeStamp = pFramePacket->timeStamp;
    frameKdfData.channel = pFramePacket->channel;

    // Set channel key 
    // Byte offset: 2
    const uint8_t *pChannelKdfKey;
    res = cryptoManager_GetChannelKdfInputKey(pFramePacket->channel, &pChannelKdfKey);
    if(res != 0){
        // printf("-{E} Failed to find Channel KDF key for Channel %u!!\n", channel);
        // printf("-FAIL\n");
        return res;
    }
    memcpy(
        &frameKdfData.channelKey, 
        pChannelKdfKey + FRAME_KDF_CHANNEL_KEY_OFFSET, 
        FRAME_KDF_CHANNEL_KEY_LEN
    );

    // Assemble CTR nonce
    // [0]: Decoder ID (4 Bytes, Big Endian)
    // [4]: Nonce Rand (12 Bytes)
    memcpy((pKdfData->pNonce)+sizeof(uint32_t), pFramePacket->ctrNonceRand, CTR_NONCE_RAND_LEN);
    for(size_t i = 0; i < sizeof(uint32_t); i++){
        pKdfData->pNonce[i] = ((uint8_t*)&(pFramePacket->timeStamp))[i];
    }

    // Increment nonce by one for encryption KDF
    if (type == FRAME_ENCRYPTION_KEY_TYPE){
        for (size_t i = CTR_NONCE_RAND_LEN - 1; i >= 0; i--){
            pKdfData->pNonce[4 + i]++;
            if (pKdfData->pNonce[4 + i] != 0){
                break; 
            }
        }
    }

    // Copy required data into given kdf data object
    memcpy(pKdfData->pData, &frameKdfData, FRAME_KDF_DATA_LENGTH);

    return 0;
}

/** @brief Checks the MIC is valid on the given frame packet, 
 *         calls into Crypto Manager
 * 
 * @param pFramePacket Frame packet to check MIC of
 * @param pktLen Size of pFramePacket
 * 
 *  @return 0 if MIC valid, number on fail
 */
static int _checkMic(
    const frame_packet_t *pFramePacket,
    const pkt_len_t pktLen
){  
    int res;
    QueueHandle_t xRequestQueue = cryptoManager_RequestQueue();

    // printf("[FrameManager] @INFO Sending Signature Check Request\n");

    //-- Prepare the Signature Check Packet --//
    CryptoManager_SignatureCheck cryptoSigCheck;

    //-- Assemble KDF Data
    cryptoSigCheck.kdfData.keySource = KEY_SOURCE_FRAME_KDF;
    cryptoSigCheck.kdfData.length = sizeof(frame_kdf_data_t);

    // Allocate stack buffer space for 
    // - KDF input data
    // - KDF AES nonce
    CRYPTO_CREATE_CLEANUP_BUFFER(tData, FRAME_KDF_DATA_LENGTH);
    cryptoSigCheck.kdfData.pData = tData;

    CRYPTO_CREATE_CLEANUP_BUFFER(pCtrNonce, CRYPTO_MANAGER_NONCE_LEN);
    cryptoSigCheck.kdfData.pNonce = pCtrNonce;

    // Assemble the KDF input data
    res = _assembleKdfData(
        FRAME_MIC_KEY_TYPE,
        pFramePacket, &cryptoSigCheck.kdfData
    );
    if(res != 0){
        return res;
    }
    
    //-- Assemble Signature Check Data
    // MIC is calculated on the whole packet minus the MIC
    cryptoSigCheck.pData = (uint8_t*)pFramePacket;
    cryptoSigCheck.length = pktLen - CRYPTO_MANAGER_MIC_LEN;
    cryptoSigCheck.pExpectedSignature = _getMIC(pFramePacket, pktLen);
    
    //-- Assemble Request
    CryptoManager_Request cryptoRequest;
    cryptoRequest.xRequestingTask = xTaskGetCurrentTaskHandle();
    cryptoRequest.requestType = CRYPTO_MANAGER_REQ_SIG_CHECK;
    cryptoRequest.requestLen = sizeof(cryptoSigCheck);
    cryptoRequest.pRequest = &cryptoSigCheck;

    //-- Send Request and Wait
    xQueueSend(xRequestQueue, &cryptoRequest, portMAX_DELAY);
    xTaskNotifyWait(0, 0xFFFFFFFF, (uint32_t*)&res, portMAX_DELAY);

    // printf("[FrameManager] @INFO Signature Check res = %d\n", res);

    return res;
}

/** @brief Decrypt the given frame packet, 
 *         calls into Crypto Manager
 * 
 * @param pFramePacket Frame packet to decrypt
 * @param pktLen Size of pFramePacket
 * @param pPlainText Buffer to store decrypted frame data in
 * @param plainTextLen Size of pPlainText buffer
 * 
 *  @return 0 on success, number on fail
 */
static int _decryptData(
    const frame_packet_t *pFramePacket,
    const pkt_len_t pktLen,
    uint8_t *pPlainText, size_t plainTextLen
){
    int res;
    QueueHandle_t xRequestQueue = cryptoManager_RequestQueue();

    // printf("[FrameManager] @INFO Sending Decryption Request\n");
    
    //-- Check Arguments --//
    if(plainTextLen != _calcCipherTextLen(pFramePacket->frameLen)){
        // printf("-{E} Bad Plain Text Buffer Length!!\n");
        return 1;
    }

    //-- Prepare the Decryption Packet --//
    CryptoManager_DecryptData cryptoDecrypt;

    //-- Assemble KDF Data
    cryptoDecrypt.kdfData.keySource = KEY_SOURCE_FRAME_KDF;
    cryptoDecrypt.kdfData.length = sizeof(frame_kdf_data_t);

    // Allocate stack buffer space for 
    // - KDF input data
    // - KDF AES nonce
    CRYPTO_CREATE_CLEANUP_BUFFER(tData, FRAME_KDF_DATA_LENGTH);
    cryptoDecrypt.kdfData.pData = tData;

    CRYPTO_CREATE_CLEANUP_BUFFER(pKdfCtrNonce, CRYPTO_MANAGER_NONCE_LEN);
    cryptoDecrypt.kdfData.pNonce = pKdfCtrNonce;

    // Assemble the KDF input data
    res = _assembleKdfData(
        FRAME_ENCRYPTION_KEY_TYPE,
        pFramePacket, &cryptoDecrypt.kdfData
    );
    if(res != 0){
        return res;
    }

    //-- Assemble Decryption Data
    // Assemble AES CTR nonce
    // [0]: 0x00 (4 Bytes)
    // [4]: Nonce Rand (12 Bytes)
    CRYPTO_CREATE_CLEANUP_BUFFER(pCtrNonce, CRYPTO_AES_BLOCK_SIZE_BYTE);
    memcpy(pCtrNonce+sizeof(uint32_t), pFramePacket->ctrNonceRand, CTR_NONCE_RAND_LEN);
    for(size_t i = 0; i < sizeof(uint32_t); i++){
        pCtrNonce[i] = 0x00;
    }
    cryptoDecrypt.pNonce = pCtrNonce;

    cryptoDecrypt.length = _calcCipherTextLen(pFramePacket->frameLen);
    // printf("-{I} Cipher Text Length = %u\n", cryptoDecrypt.length);
    cryptoDecrypt.pCipherText = _getCipherText(pFramePacket);

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

    // printf("[FrameManager] @INFO Decryption res = %d\n", res);
    return res;
}

/** @brief Checks if the channel has a active subscription at the give 
 *         timestamp, calls into Channel Manager
 * 
 * @param channel Channel to check if subscription is active
 * @param time Time stamp to check if subscription is active at
 * 
 *  @return 0 if active, number on fail
 */
static int _checkActiveSub(
    const channel_id_t channel, const timestamp_t time
){
    int res;

    QueueHandle_t xRequestQueue = channelManager_RequestQueue();

    //-- Prepare the Sub Update Packet --//
    ChannelManager_CheckActiveSub checkActiveSub;

    checkActiveSub.channel = channel;
    checkActiveSub.time = time;

    //-- Assemble Request
    ChannelManager_Request channelRequest;
    channelRequest.xRequestingTask = xTaskGetCurrentTaskHandle();
    channelRequest.requestType = CHANNEL_MANAGER_CHECK_ACTIVE_SUB;
    channelRequest.requestLen = sizeof(checkActiveSub);
    channelRequest.pRequest = &checkActiveSub;

    //-- Send Request and Wait
    xQueueSend(xRequestQueue, &channelRequest, portMAX_DELAY);
    xTaskNotifyWait(0, 0xFFFFFFFF, (uint32_t*)&res, portMAX_DELAY);

    return res;
}

/** @brief Decodes the given frame. Active subscription is first checked, 
 *         then timestamp increased, then MIC then finally frame is decoded
 * 
 * @param pFrameDecode Structure holding the raw frame data
 * 
 *  @return 0 on success, number on fail
 */
static int _decodeFrame(
    const FrameManager_Decode *pFrameDecode
){
    int res;

    // printf("\n[FrameManager] @TASK Frame Decode:\n");

    const frame_packet_t *pFramePacket = (const frame_packet_t *)pFrameDecode->pBuff;

    // printf("[Frame] @TASK Decode Frame:\n");
    // printf("-{I} Packet Len: %u\n", pFrameDecode->pktLen);
    // printf("-{I} Channel: %lu\n", pFramePacket->channel);
    // printf("-{I} Time Stamp: %llu\n", pFramePacket->timeStamp);
    // printf("-{I} Frame Length: %u\n", pFramePacket->frameLen);

    // printf("-{I} CTR Nonce Rand: ");
    // crypto_print_hex(pFramePacket->ctrNonceRand, CTR_NONCE_RAND_LEN);
    // printf("-{I} Cypher Text: ");
    // crypto_print_hex(_getCipherText(pFramePacket), _calcCipherTextLen(pFramePacket->frameLen));
    // printf("-{I} MIC: ");
    // crypto_print_hex(_getMIC(pFramePacket, pFrameDecode->pktLen), CRYPTO_MANAGER_MIC_LEN);

    // Check length is good
    const size_t expectedPacketLen = _expectedPacketLen(pFramePacket->frameLen);
    if(expectedPacketLen != pFrameDecode->pktLen){
        // STATUS_LED_RED();
        // printf(
        //     "-{E} Bad Frame Msg Length, Expected %u Bytes != Actual %u Bytes\n",
        //     expectedPacketLen, pFrameDecode->pktLen
        // );
        // printf("-FAIL [Packet]\n\n");
        // host_print_error("FrameDecode -> Frame Bad Message Length\n");
        return 1;
    }

    // Check device is subscribed to the channel
    if(_checkActiveSub(pFramePacket->channel, pFramePacket->timeStamp) != 0){
        // STATUS_LED_RED();
        // printf(
        //     "-{E} Decoder does not have valid subscription for channel %u\n",
        //     pFramePacket->channel
        // );
        // printf("-FAIL [No Subscription]\n\n");
        // host_print_error("Frame No Subscription\n");
        return 1;
    }
    // printf(
    //     "-{I} Decoder has valid subscription for channel %u :)\n",
    //     pFramePacket->channel
    // );

    // Check timestamp increased
    if(_timestamp_CheckInc(pFramePacket->channel, pFramePacket->timeStamp) != 0){
        // STATUS_LED_RED();
        // printf("-{E} Frame Time Stamp Not Increased!!\n");
        // printf("-FAIL [Time Stamp]\n\n");

        // host_print_error("FrameDecode -> Frame Time Stamp Not Increased\n");
        return 1;
    }
    // printf("-{I} Frame Time Stamp Increased :)\n");

    // Check MIC
    res = _checkMic(pFramePacket, pFrameDecode->pktLen);
    if(res != 0){
        // printf("-FAIL [MIC]\n\n");
        // host_print_error("FrameDecode -> MIC\n");
        return res;
    }

    // Decrypt data
    CRYPTO_CREATE_CLEANUP_BUFFER(pDecryptedData, _calcCipherTextLen(pFramePacket->frameLen));
    res = _decryptData(
        pFramePacket, pFrameDecode->pktLen,
        pDecryptedData, sizeof(pDecryptedData)
    );
    if(res != 0){
        // printf("-FAIL [DECRYPT]\n\n");
        // host_print_error("FrameDecode -> Decryption\n");
        return res;
    }

    // Checked decrypted frame length matches the length in the packet header
    const uint8_t decryptedFrameLen = pDecryptedData[0];
    if (decryptedFrameLen != pFramePacket->frameLen){
        // printf(
        //     "-{E} Decrypted Frame Length Does Not Match Packet Header Frame Length (Frame %u != Decrypted %u)!!\n",
        //     pFramePacket->frameLen, decryptedFrameLen
        // );
        // printf("-FAIL\n");
        return 1;
    }

    // Packet has been successfully decoded and verified
    // - Update time stamp tracker
    res = _timestamp_Update(pFramePacket->channel, pFramePacket->timeStamp);
    if(res != 0){
        // printf("-{E} Frame Time Stamp Update Failed %d!!\n", res);
        // host_print_error("Time stamp update bad\n");
        return res;
    }

    // Copy over plain text
    const uint8_t *pFrameData = pDecryptedData+1;
    // if(plainTextLen != pFramePacket->frameLen){
    //     printf("-{E} Plain text buffer not big enough!!\n");
    //     printf("-FAIL\n");
    //     return 1;
    // }
    // memcpy(pPlainText, pFrameData, pFramePacket->frameLen);

    // printf("-COMPLETE\n\n");
    host_write_packet(DECODE_MSG, pFrameData, pFramePacket->frameLen);
    return 0;
}

/** @brief Processes requests from other tasks
 * 
 * @param pRequest Pointer to request structure
 * 
 * @return 0 if success, other numbers if failed
 */
static int _processRequest(FrameManager_Request *pRequest){
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
        case FRAME_MANAGER_DECODE:
            // printf("-{I} Frame Decode Request\n");

            // Check request length is good
            if(pRequest->requestLen != sizeof(FrameManager_Decode)){
                // printf("-{E} Bad Request Length!!\n");
                return 0;
            }

            FrameManager_Decode *pFrameDecode = pRequest->pRequest;
            res = _decodeFrame(pFrameDecode);
            break;
        default:
            // printf("-{E} Unknown Request Type!!\n");
            res = 1;
            break;
    }
    return res;
}

//----- Public Functions -----//

/** @brief Initializes the Frame Manager ready for the main task to be run
 * 
 * @note Must be called before RTOS scheduler starts!!
 */
void frameManager_Init(void){
    for(size_t i = 0; i < MAX_CHANNEL_COUNT; i++){
        _channelTimeStamps[i].active = 0;
    }

    // Setup request queue
    _xRequestQueue = xQueueCreate(
        RTOS_QUEUE_LENGTH, sizeof(FrameManager_Request)
    );
}

/** @brief Frame Manager main RTOS task
 * 
 * @param pvParameters FreeRTOS task parameters
 */
void frameManager_vMainTask(void *pvParameters){
    FrameManager_Request frameRequest;

    while (1){
        if (xQueueReceive(_xRequestQueue, &frameRequest, portMAX_DELAY) == pdPASS){
            // printf("[FrameManager] @TASK Received Request\n");
            int res = _processRequest(&frameRequest);
            // printf("-COMPLETE\n");

            // Signal the requesting task that request is complete
            xTaskNotify(frameRequest.xRequestingTask, res, eSetValueWithOverwrite);
        }
    }
}

/** @brief Returns Frame Manager request queue 
 * 
 * @param QueueHandle_t Request queue to send requests to Frame Manager
 */
QueueHandle_t frameManager_RequestQueue(void){
    return _xRequestQueue;
}