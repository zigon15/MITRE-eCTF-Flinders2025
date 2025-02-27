#include "frame_manager.h"
#include "crypto.h"

#include "FreeRTOS.h"
#include "task.h"
#include "queue.h"
#include "string.h"

#include "crypto_manager.h"
#include "global_secrets.h"

//----- Private Constants -----//
#define FRAME_KDF_DATA_LENGTH 32
#define FRAME_KDF_CHANNEL_KEY_LEN 20
#define FRAME_KDF_CHANNEL_KEY_OFFSET (CHANNEL_KDF_KEY_LEN - FRAME_KDF_CHANNEL_KEY_LEN)

#define CTR_NONCE_RAND_LEN 12

//  Frame Data Packet format
//  [0]: Channel (4 Bytes)
//  [4]: AES CTR nonce random bytes (12 Bytes)
//  [16]: Time Stamp (8 Bytes)
//  [17]: Frame Length (1 Byte)
//  [25]: Cipher text (FrameLen + 1 Bytes)
//  [25 + FrameLen]: MIC (16 bytes)
//  4 + 12 + 8 + 1 + FrameLen + 16 = 41 + FrameLen
#define FRAME_PACKET_BASE_LEN (4 + 12 + 8 + 1 + 16)
#define FRAME_PACKET_CIPHER_TEXT_OFFSET (4 + 12 + 8 + 1)

#define FRAME_MIC_KEY_TYPE 0x9E
#define FRAME_ENCRYPTION_KEY_TYPE 0xD7

//----- Private Types -----//
typedef struct __attribute__((packed)) {
    uint8_t type;
    uint8_t frameDataLen;
    uint8_t channelKey[FRAME_KDF_CHANNEL_KEY_LEN];
    uint64_t timeStamp;
    uint16_t channel;
} frame_kdf_data_t;

typedef struct __attribute__((packed)) {
    channel_id_t channel;
    uint8_t ctrNonceRand[CTR_NONCE_RAND_LEN];
    uint64_t timeStamp;
    uint8_t frameLen;
} frame_packet_t;

typedef struct {
    uint8_t active;
    channel_id_t channel;
    timestamp_t lastTimeStamp;
} channel_time_stamp_t;

//----- Private Variables -----//
channel_time_stamp_t _channelTimeStamps[MAX_CHANNEL_COUNT];

//----- Private Functions -----//
static int _timestamp_FindChannel(const channel_id_t channel){
    for(size_t i = 0; i < MAX_CHANNEL_COUNT; i++){
        if(_channelTimeStamps[i].active && (_channelTimeStamps[i].channel == channel)){
            return i;
        }
    }
    return -1;
}

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

    return -1;
}

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
    return -1;
}

static size_t _expectedPacketLen(const uint8_t frameLen){
    return FRAME_PACKET_BASE_LEN + frameLen + 1;
}

static const uint8_t* _getCipherText(const frame_packet_t *pFramePacket){
    return ((uint8_t*)pFramePacket + FRAME_PACKET_CIPHER_TEXT_OFFSET);
}

static const uint8_t* _getMIC(const frame_packet_t *pFramePacket, const pkt_len_t pktLen){
    return ((uint8_t*)pFramePacket + pktLen - CRYPTO_MANAGER_MIC_LEN);
}

static size_t _calcCipherTextLen(size_t frameLen){
    return frameLen + 1;
}

static int _assembleKdfData(
    const uint8_t type,
    const frame_packet_t *pFramePacket,
    CryptoManager_KeyDerivationData *pKdfData
){  
    int res;
    
    // Validate KDF struct size is as expected 
    // - If not, is due to bad code and compiler screwing up the format
    if(sizeof(frame_kdf_data_t) != FRAME_KDF_DATA_LENGTH){
        printf("-{E} Bad Frame KDF Data Struct Length!!\n");
        printf("-FAIL\n");
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
    res = cryptoManager_GetChannelKdfKey(pFramePacket->channel, &pChannelKdfKey);
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

static int _checkMic(
    const frame_packet_t *pFramePacket,
    const pkt_len_t pktLen
){  
    int res;
    QueueHandle_t xRequestQueue = cryptoManager_RequestQueue();

    printf("[FrameManager] @INFO Sending Signature Check Request\n");

    //-- Prepare the Signature Check Packet --//
    CryptoManager_SignatureCheck cryptoSigCheck;

    //-- Assemble KDF Data
    cryptoSigCheck.kdfData.keySource = FRAME_KDF_KEY;
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
    xTaskNotifyWait(0, 0xFFFFFFFF, &res, portMAX_DELAY);

    printf("[FrameManager] @INFO Signature Check res = %d\n", res);

    return res;
}

static int _decryptData(
    const frame_packet_t *pFramePacket,
    const pkt_len_t pktLen,
    uint8_t *pPlainText, size_t plainTextLen
){
    int res;
    QueueHandle_t xRequestQueue = cryptoManager_RequestQueue();

    printf("[FrameManager] @INFO Sending Decryption Request\n");
    
    //-- Check Arguments --//
    if(plainTextLen != _calcCipherTextLen(pFramePacket->frameLen)){
        printf("-{E} Bad Plain Text Buffer Length!!\n");
        return 1;
    }

    //-- Prepare the Decryption Packet --//
    CryptoManager_DecryptData cryptoDecrypt;

    //-- Assemble KDF Data
    cryptoDecrypt.kdfData.keySource = FRAME_KDF_KEY;
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
    printf("-{I} Cipher Text Length = %u\n", cryptoDecrypt.length);
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
    xTaskNotifyWait(0, 0xFFFFFFFF, &res, portMAX_DELAY);

    printf("[FrameManager] @INFO Decryption res = %d\n", res);
    return res;
}

static int _decodeFrame(
    const uint8_t *pData, const pkt_len_t pktLen,
    uint8_t *pPlainText, const size_t plainTextLen
){
    int res;

    printf("\n[FrameManager] @TASK Frame Decode:\n");

    const frame_packet_t *pFramePacket = (const frame_packet_t *)pData;

    printf("[Frame] @TASK Decode Frame:\n");
    printf("-{I} Packet Len: %u\n", pktLen);
    printf("-{I} Channel: %lu\n", pFramePacket->channel);
    printf("-{I} Time Stamp: %llu\n", pFramePacket->timeStamp);
    printf("-{I} Frame Length: %u\n", pFramePacket->frameLen);

    printf("-{I} CTR Nonce Rand: ");
    crypto_print_hex(pFramePacket->ctrNonceRand, CTR_NONCE_RAND_LEN);
    printf("-{I} Cypher Text: ");
    crypto_print_hex(_getCipherText(pData), _calcCipherTextLen(pFramePacket->frameLen));
    printf("-{I} MIC: ");
    crypto_print_hex(_getMIC(pFramePacket, pktLen), CRYPTO_MANAGER_MIC_LEN);

    // Check length is good
    const size_t expectedPacketLen = _expectedPacketLen(pFramePacket->frameLen);
    if(expectedPacketLen != pktLen){
        // STATUS_LED_RED();
        printf(
            "-{E} Bad Frame Msg Length, Expected %u Bytes != Actual %u Bytes\n",
            expectedPacketLen, pktLen
        );
        printf("-FAIL [Packet]\n\n");
        // host_print_error("Frame Bad Message Length\n");
        return 1;
    }

    // Channel is 4 bytes in the subscription update structure but max expected is 2 byte in python
    // - Verify that the channel fits in 2 bytes to prevent undefined behaviour later on
    if(pFramePacket->channel > 0xFFFF){
        // STATUS_LED_RED();
        printf(
            "-{E} Channel Number Greater than 0xFFFF!!\n"
        );
        printf("-FAIL [Channel Num]\n\n");
        // host_print_error("Frame Channel Number too Big\n");
        return 1;
    }

    // Check device is subscribed to the channel
    // TODO: !!ADD!!
    // if(subscription_is_subscribed(pFramePacket->channel, pFramePacket->time_stamp) == 0){
    //     STATUS_LED_RED();
    //     // printf(
    //     //     "-{E} Decoder does not have valid subscription for channel %u\n",
    //     //     pFramePacket->channel
    //     // );
    //     // printf("-FAIL [No Subscription]\n\n");

    //     host_print_error("Frame No Subscription\n");
    //     return 1;
    // }
    printf(
        "-{I} Decoder has valid subscription for channel %u :)\n",
        pFramePacket->channel
    );

    // Check timestamp is in subscription start -> end
    // TODO: !!ADD!!

    // Check timestamp increased
    if(_timestamp_CheckInc(pFramePacket->channel, pFramePacket->timeStamp) != 0){
        // STATUS_LED_RED();
        printf("-{E} Frame Time Stamp Not Increased!!\n");
        printf("-FAIL [Time Stamp]\n\n");

        // host_print_error("Frame Time Stamp Not Increased\n");
        return 1;
    }
    printf("-{I} Frame Time Stamp Increased :)\n");

    // Check MIC
    res = _checkMic(pFramePacket, pktLen);
    if(res != 0){
        printf("-FAIL [MIC]\n\n");
        return res;
    }

    // Decrypt data
    CRYPTO_CREATE_CLEANUP_BUFFER(pDecryptedData, _calcCipherTextLen(pFramePacket->frameLen));
    res = _decryptData(
        pFramePacket, pktLen,
        pDecryptedData, sizeof(pDecryptedData)
    );
    if(res != 0){
        printf("-FAIL [DECRYPT]\n\n");
        return res;
    }

    // Checked decrypted frame length matches the length in the packet header
    const uint8_t decryptedFrameLen = pDecryptedData[0];
    if (decryptedFrameLen != pFramePacket->frameLen){
        printf(
            "-{E} Decrypted Frame Length Does Not Match Packet Header Frame Length (Frame %u != Decrypted %u)!!\n",
            pFramePacket->frameLen, decryptedFrameLen
        );
        printf("-FAIL\n");
        return 1;
    }

    // Packet has been successfully decoded and verified
    // - Update time stamp tracker
    res = _timestamp_Update(pFramePacket->channel, pFramePacket->timeStamp);
    if(res != 0){
        printf("-{E} Frame Time Stamp Update Failed %d!!\n", res);
        // host_print_error("Time stamp update bad\n");
        return res;
    }

    // Copy over plain text
    const uint8_t *pFrameData = pPlainText+1;
    if(plainTextLen != pFramePacket->frameLen){
        printf("-{E} Plain text buffer not big enough!!\n");
        printf("-FAIL\n");
        return 1;
    }
    memcpy(pPlainText, pFrameData, pFramePacket->frameLen);

    printf("-COMPLETE\n\n");
    // host_write_packet(DECODE_MSG, pFrameData, pFramePacket->frame_len);
    return 0;
}

//----- Public Functions -----//
void frameManager_Init(void){
    for(size_t i = 0; i < MAX_CHANNEL_COUNT; i++){
        _channelTimeStamps[i].active = 0;
    }
}

void frameManager_vMainTask(void *pvParameters){
    while (1){
        uint8_t framePacket[] = {
            0x01, 0x00, 0x00, 0x00, 0x6C, 0x86, 0x21, 0x3D, 
            0x2B, 0xF3, 0x9B, 0xE2, 0xCE, 0x60, 0xE7, 0x86, 
            0x64, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
            0x0F, 0x3C, 0x2F, 0xBF, 0x28, 0x74, 0xB5, 0x2E, 
            0xBE, 0xCD, 0x4E, 0xB9, 0x37, 0xD5, 0x3D, 0xC4, 
            0x35, 0xA5, 0x62, 0xC4, 0xF0, 0xE6, 0x61, 0x86, 
            0x39, 0xC5, 0x25, 0x94, 0xF8, 0x1A, 0xD3, 0xA4, 
            0x38,
        };

        uint8_t frameLength = ((frame_packet_t*)framePacket)->frameLen;
        uint8_t pPlainText[_calcCipherTextLen(frameLength)];

        _decodeFrame(
            framePacket, sizeof(framePacket),
            pPlainText, frameLength
        );
        // _decodeFrame(framePacket, sizeof(framePacket));

        // vTaskDelay(pdMS_TO_TICKS(500));
        while(1);
    }
}