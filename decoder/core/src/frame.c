#include "frame.h"

#include <string.h>

#include "crypto.h"
#include "status_led.h"
#include "global_secrets.h"
#include "host_messaging.h"
#include "simple_flash.h"
#include "subscription.h"

/******************************** PRIVATE CONSTANTS ********************************/
#define FRAME_KDF_DATA_LENGTH 32
#define FRAME_KDF_CHANNEL_KEY_LEN 20
#define FRAME_KDF_CHANNEL_KEY_OFFSET (CHANNEL_KDF_KEY_LEN - FRAME_KDF_CHANNEL_KEY_LEN)

#define CTR_NONCE_RAND_LEN 12

#define FRAME_MIC_KEY_LEN 32
#define FRAME_ENCRYPTION_KEY_LEN 32

#define FRAME_MIC_LEN 16

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

/******************************** PRIVATE TYPES ********************************/
typedef struct __attribute__((packed)) {
    uint8_t type;
    uint8_t frameDataLen;
    uint8_t channelKey[FRAME_KDF_CHANNEL_KEY_LEN];
    uint64_t timeStamp;
    uint16_t channel;
} frame_kdf_data_t;

typedef struct __attribute__((packed)) {
    channel_id_t channel;
    uint8_t ctr_nonce_rand[CTR_NONCE_RAND_LEN];
    uint64_t time_stamp;
    uint8_t frame_len;
} frame_packet_t;

/******************************** PRIVATE VARIABLES ********************************/
typedef struct {
    uint8_t active;
    channel_id_t channel;
    timestamp_t last_time_stamp;
} channel_time_stamp_t;

channel_time_stamp_t _channelTimeStamps[MAX_CHANNEL_COUNT];

/******************************** PRIVATE FUNCTION DECLARATIONS ********************************/
int _timestamp_find_channel(const channel_id_t channel){
    for(size_t i = 0; i < MAX_CHANNEL_COUNT; i++){
        if(_channelTimeStamps[i].active && (_channelTimeStamps[i].channel == channel)){
            return i;
        }
    }
    return -1;
}

int _timestamp_check_inc(const channel_id_t channel, const timestamp_t timestamp){
    int idx = _timestamp_find_channel(channel);

    // Check if channel was found
    if(idx == -1){
        return 0;
    }

    if(timestamp > _channelTimeStamps[idx].last_time_stamp){
        return 0;
    }

    return -1;
}

int _timestamp_update(channel_id_t channel, timestamp_t timestamp){
    int idx = _timestamp_find_channel(channel);

    // Check the channel was found
    if(idx >= 0){
        _channelTimeStamps[idx].last_time_stamp = timestamp;
        return 0;
    }

    // Channel not found so add it
    for(size_t i = 0; i < MAX_CHANNEL_COUNT; i++){
        if(_channelTimeStamps[i].active == 0){
            _channelTimeStamps[i].active = 1;
            _channelTimeStamps[i].channel = channel;
            _channelTimeStamps[i].last_time_stamp = timestamp;
            return 0;
        }
    }

    // No room to store the channel
    return -1;
}

size_t _expected_packet_len(const uint8_t frameLen){
    return FRAME_PACKET_BASE_LEN + frameLen + 1;
}

const uint8_t* _get_cipher_text(const uint8_t *pFrame){
    return (pFrame + FRAME_PACKET_CIPHER_TEXT_OFFSET);
}

const uint8_t* _get_MIC(const uint8_t *pFrame, const pkt_len_t pktLen){
    return (pFrame + pktLen - FRAME_MIC_LEN);
}

size_t _calc_cipher_text_len(uint8_t frameLen){
    return frameLen + 1;
}

static int _derive_frame_keys(
    const channel_id_t channel, const uint8_t frameDataLen, const uint64_t timestamp,
    const uint8_t *pCtrNonceRand,
    uint8_t *pMicKey, uint8_t *pEncryptionKey
){  
    // printf("[Frame] @TASK Derive Keys:\n");
    int res;
    
    CRYPTO_CREATE_CLEANUP_BUFFER(pTmpMicKey, FRAME_MIC_KEY_LEN);
    CRYPTO_CREATE_CLEANUP_BUFFER(pTmpEncryptionKey, FRAME_ENCRYPTION_KEY_LEN);

    // Validate struct size is as expected 
    // - If not, is due to bad code and compiler screwing up the format
    if(sizeof(frame_kdf_data_t) != FRAME_KDF_DATA_LENGTH){
        // printf("-{E} Bad Frame KDF Data Struct Length!!\n");
        // printf("-FAIL\n");
        return 1;
    }

    //-- Assemble KDF Input Packet --//
    frame_kdf_data_t frameKdfData;
    frameKdfData.frameDataLen = frameDataLen;
    
    // Set channel key 
    // Byte offset: 2
    const uint8_t *pChannelKdfKey;
    res = secrets_get_channel_kdf_key(channel, &pChannelKdfKey);
    if(res != 0){
        // printf("-{E} Failed to find Channel KDF key for Channel %lu!!\n", channel);
        // printf("-FAIL\n");
        return res;
    }
    memcpy(
        &frameKdfData.channelKey, 
        pChannelKdfKey + FRAME_KDF_CHANNEL_KEY_OFFSET, 
        FRAME_KDF_CHANNEL_KEY_LEN
    );

    // Set timestamp
    // Byte offset: 22
    frameKdfData.timeStamp = timestamp;

    // Set channel
    // Byte offset: 30
    frameKdfData.channel = channel;

    //-- Prepare for AES CTR --//
    // Get KDF key
    const uint8_t *pFrameKdfKey;
    res = secrets_get_subscription_kdf_key(&pFrameKdfKey);
    if(res != 0){
        // printf("-{E} Failed to get Frame KDF!!\n");
        // printf("-FAIL\n");
        return res;
    }

    // Assemble CTR nonce
    // [0]: Time Stamp (Lower 4 Bytes, little Endian)
    // [4]: Nonce Rand (12 Bytes)
    CRYPTO_CREATE_CLEANUP_BUFFER(ctrNonce, CRYPTO_AES_BLOCK_SIZE_BYTE);
    memcpy(ctrNonce+sizeof(uint32_t), pCtrNonceRand, CTR_NONCE_RAND_LEN);
    for(size_t i = 0; i < sizeof(uint32_t); i++){
        ctrNonce[i] = ((uint8_t*)&timestamp)[i];
    }

    // printf("-{I} AES CTR Key: ");
    // crypto_print_hex(pFrameKdfKey, SUBSCRIPTION_KDF_KEY_LEN);

    //-- MIC KDF --//
    CRYPTO_CREATE_CLEANUP_BUFFER(pCipherText, FRAME_KDF_DATA_LENGTH);

    // Perform KDF to calculate MIC key
    frameKdfData.type = FRAME_MIC_KEY_TYPE;
    res = crypto_AES_CTR_encrypt(
        pFrameKdfKey, MXC_AES_256BITS, ctrNonce,
        (uint8_t*)&frameKdfData, pCipherText, FRAME_KDF_DATA_LENGTH
    );
    if(res != 0){
        // printf("-{E} AES CTR Failed for MIC Key KDF!!\n");
        // printf("-FAIL\n");
        return res;
    }
    memcpy(pTmpMicKey, pCipherText, FRAME_MIC_KEY_LEN);

    // printf("-{I} MIC AES CTR Nonce: ");
    // crypto_print_hex(ctrNonce, CRYPTO_AES_BLOCK_SIZE_BYTE);
    // printf("-{I} MIC KDF Input Data: ");
    // crypto_print_hex((uint8_t*)&frameKdfData, FRAME_KDF_DATA_LENGTH);
    // printf("-{I} MIC Key: ");
    // crypto_print_hex(pTmpMicKey, FRAME_MIC_KEY_LEN);

    //-- Encryption KDF --//
    // Increment nonce by one for encryption KDF
    for (size_t i = CTR_NONCE_RAND_LEN - 1; i >= 0; i--) {
        ctrNonce[4 + i]++;
        if (ctrNonce[4 + i] != 0){
            break; 
        }
    }

    // Perform KDF to calculate Encryption key
    frameKdfData.type = FRAME_ENCRYPTION_KEY_TYPE;
    res = crypto_AES_CTR_encrypt(
        pFrameKdfKey, MXC_AES_256BITS, ctrNonce,
        (uint8_t*)&frameKdfData, pCipherText, FRAME_KDF_DATA_LENGTH
    );
    if(res != 0){
        // printf("-{E} AES CTR Failed for Encryption Key KDF!!\n");
        // printf("-FAIL\n");
        return res;
    }
    memcpy(pTmpEncryptionKey, pCipherText, FRAME_ENCRYPTION_KEY_LEN);

    // printf("-{I} Encryption AES CTR Nonce: ");
    // crypto_print_hex(ctrNonce, CRYPTO_AES_BLOCK_SIZE_BYTE);
    // printf("-{I} Encryption KDF Input Data: ");
    // crypto_print_hex((uint8_t*)&frameKdfData, FRAME_KDF_DATA_LENGTH);
    // printf("-{I} Encryption Key: ");
    // crypto_print_hex(pTmpEncryptionKey, FRAME_ENCRYPTION_KEY_LEN);

    // Both keys have been successfully derived so copy to the key buffers 
    memcpy(pMicKey, pTmpMicKey, FRAME_MIC_KEY_LEN);
    memcpy(pEncryptionKey, pTmpEncryptionKey, FRAME_ENCRYPTION_KEY_LEN);

    // printf("-COMPLETE\n");
    return 0;
}

static int _verify_mic(
    const uint8_t *pFramePacket, const pkt_len_t pktLen, const uint8_t frameLen,
    const uint8_t *pMicKey
){   
    // printf("[Frame] @TASK Verify MIC:\n");
    int res;

    // MIC is calculated on the whole packet minus the MIC
    const uint16_t micInputLength = pktLen - CRYPTO_CMAC_OUTPUT_SIZE;

    // Calculate expect MIC on subscription packet
    CRYPTO_CREATE_CLEANUP_BUFFER(calculatedMic, CRYPTO_CMAC_OUTPUT_SIZE);
    res = crypto_AES_CMAC(
        pMicKey, MXC_AES_256BITS, 
        (uint8_t*)pFramePacket, micInputLength,
        calculatedMic
    );
    if(res != 0){
        return res;
    }

    const uint8_t *pPacketMic = _get_MIC(pFramePacket, pktLen);

    // printf("-{I} Input Data: ");
    // crypto_print_hex((uint8_t*)pFramePacket, micInputLength);
    // printf("-{I} Calculated MIC: ");
    // crypto_print_hex(calculatedMic, CRYPTO_CMAC_OUTPUT_SIZE);
    // printf("-{I} Packet MIC: ");
    // crypto_print_hex(pPacketMic, CRYPTO_CMAC_OUTPUT_SIZE);

    // Compare MIC
    if (memcmp(calculatedMic, pPacketMic, CRYPTO_CMAC_OUTPUT_SIZE) != 0){
        // printf("-{E} Calculated MIC Does Not Match Packet MIC!!\n");
        // printf("-FAIL\n");
        return 1;
    }

    // printf("-{I} Calculated MIC Matches Packet MIC :)\n");
    // printf("-COMPLETE\n");
    return 0;
}

static int _decrypt_data(
    const uint8_t pCtrNonceRand[CTR_NONCE_RAND_LEN], 
    const uint8_t pEncryptionKey[FRAME_ENCRYPTION_KEY_LEN], 
    const uint8_t *pCipherText,
    const uint8_t frameLen, 
    uint8_t *pFrameData
){
    // printf("[Frame] @TASK Decrypt Data:\n");
    int res;

    // Assemble CTR nonce
    // [0]: 0x00 (4 Bytes)
    // [4]: Nonce Rand (12 Bytes)
    CRYPTO_CREATE_CLEANUP_BUFFER(ctrNonce, CRYPTO_AES_BLOCK_SIZE_BYTE);
    memcpy(ctrNonce+sizeof(uint32_t), pCtrNonceRand, CTR_NONCE_RAND_LEN);
    for(size_t i = 0; i < sizeof(uint32_t); i++){
        ctrNonce[i] = 0x00;
    }

    // printf("-{I} AES CTR Nonce: ");
    // crypto_print_hex(ctrNonce, CRYPTO_AES_BLOCK_SIZE_BYTE);
    // printf("-{I} AES CTR Key: ");
    // crypto_print_hex(pEncryptionKey, FRAME_ENCRYPTION_KEY_LEN);
    
    // Decrypt the data
    uint16_t plainTextLen = frameLen + 1;
    CRYPTO_CREATE_CLEANUP_BUFFER(pDecryptedData, plainTextLen);
    res = crypto_AES_CTR_encrypt(
        pEncryptionKey, MXC_AES_256BITS, ctrNonce,
        pCipherText, pDecryptedData, plainTextLen
    );
    if(res != 0){
        // printf("-{E} AES CTR Failed for Cipher Text Decryption!!\n");
        // printf("-FAIL\n");
        return res;
    }
    // printf("-{I} AES CTR Decryption Complete :)\n");

    // Checked decrypted frame length matches the length in the packet header
    uint8_t decryptedFrameLen = pDecryptedData[0];
    if (decryptedFrameLen != frameLen){
        // printf(
        //     "-{E} Decrypted Frame Length Does Not Match Packet Header Frame Length (Frame %u != Decrypted %u)!!\n",
        //     frameLen, decryptedFrameLen
        // );
        // printf("-FAIL\n");
        return 1;
    }
    // printf(
    //     "-{I} Decrypted Frame Length Matches Packet Header Frame Length of %u Bytes\n",
    //     frameLen
    // );

    // All the checks are passed so copy over the data
    memcpy(pFrameData, pDecryptedData+1, frameLen);

    // printf("-{I} Decrypted Frame Data: \"");
    // for(size_t i = 0; i < frameLen; i++){
    //     printf("%c", pFrameData[i]);
    // }
    // printf("\" -> ");
    // crypto_print_hex(pFrameData, frameLen);
    
    // printf("-COMPLETE\n");
    return 0;
}

/******************************** PUBLIC FUNCTION DECLARATIONS ********************************/
void frame_init(void){
    for(size_t i = 0; i < MAX_CHANNEL_COUNT; i++){
        _channelTimeStamps[i].active = 0;
    }
}

/** @brief Decoded the given encrypted frame packet
 *
 *  @param pkt_len The length of the incoming packet
 *  @param pUpdate A pointer to a encrypted frame message
 *
 *  @note Take care to note that this system is little endian.
 *
 *  @return 0 upon success, 1 if error
*/
int frame_decode(const pkt_len_t pktLen, const uint8_t *pData){
    int res;

    const frame_packet_t *pFrame = (const frame_packet_t *)pData;

    // printf("[Frame] @TASK Decode Frame:\n");
    // printf("-{I} Packet Len: %u\n", pktLen);
    // printf("-{I} Channel: %lu\n", pFrame->channel);
    // printf("-{I} Time Stamp: %llu\n", pFrame->time_stamp);
    // printf("-{I} Frame Length: %u\n", pFrame->frame_len);

    // printf("-{I} CTR Nonce Rand: ");
    // crypto_print_hex(pFrame->ctr_nonce_rand, CTR_NONCE_RAND_LEN);
    // printf("-{I} Cypher Text: ");
    // crypto_print_hex(_get_cipher_text(pData), _calc_cipher_text_len(pFrame->frame_len));
    // printf("-{I} MIC: ");
    // crypto_print_hex(_get_MIC(pData, pktLen), FRAME_MIC_KEY_LEN);

    // Check length is good
    const size_t expectedPacketLen = _expected_packet_len(pFrame->frame_len);
    if(expectedPacketLen != pktLen){
        STATUS_LED_RED();
        // printf(
        //     "-{E} Bad Frame Msg Length, Expected %u Bytes != Actual %u Bytes\n",
        //     expectedPacketLen, pktLen
        // );
        // printf("-FAIL [Packet]\n\n");
        host_print_error("Frame Bad Message Length\n");
        return 1;
    }

    // Channel is 4 bytes in the subscription update structure but max expected is 2 byte in python
    // - Verify that the channel fits in 2 bytes to prevent undefined behaviour later on
    if(pFrame->channel > 0xFFFF){
        STATUS_LED_RED();
        // printf(
        //     "-{E} Channel Number Greater than 0xFFFF!!\n"
        // );
        // printf("-FAIL [Channel Num]\n\n");
        host_print_error("Frame Channel Number too Big\n");
        return 1;
    }

    // Check device is subscribed to the channel
    if(subscription_is_subscribed(pFrame->channel, pFrame->time_stamp) == 0){
        STATUS_LED_RED();
        // printf(
        //     "-{E} Decoder does not have valid subscription for channel %u\n",
        //     pFrame->channel
        // );
        // printf("-FAIL [No Subscription]\n\n");

        host_print_error("Frame No Subscription\n");
        return 1;
    }
    // printf(
    //     "-{I} Decoder has valid subscription for channel %u :)\n",
    //     pFrame->channel
    // );

    // Check timestamp increased
    if(_timestamp_check_inc(pFrame->channel, pFrame->time_stamp) != 0){
        STATUS_LED_RED();
        // printf(
        //     "-{E} Frame Time Stamp Not Increased (New %llu <= Last %llu)!!\n",
        //     pFrame->time_stamp,
        //     _lastTimeStamp
        // );
        // printf("-FAIL [Time Stamp]\n\n");

        host_print_error("Frame Time Stamp Not Increased\n");
        return 1;
    }
    // printf(
    //     "-{I} Frame Time Stamp Increased (New %llu > Last %llu) :)\n",
    //     pFrame->time_stamp,
    //     _lastTimeStamp
    // );

    // Check timestamp is in subscription start -> end


    // Derive MIC and encryption keys
    CRYPTO_CREATE_CLEANUP_BUFFER(pMicKey, FRAME_MIC_KEY_LEN);
    CRYPTO_CREATE_CLEANUP_BUFFER(pEncryptionKey, FRAME_ENCRYPTION_KEY_LEN);

    res = _derive_frame_keys(
        pFrame->channel, pFrame->frame_len, pFrame->time_stamp,
        pFrame->ctr_nonce_rand,
        pMicKey, pEncryptionKey
    );
    if(res != 0){
        // printf("-FAIL [KDF]\n\n");

        host_print_error("Frame KDF Failed\n");
        return res;
    }

    // Check packet MIC matches MIC derived from the packet data
    res = _verify_mic(pData, pktLen, pFrame->frame_len, pMicKey);
    if(res != 0){
        // printf("-FAIL [MIC]\n\n");
        host_print_error("Frame Bad MIC\n");
        return res;
    }

    // MIC is good so packet is unchanged
    // - Decrypt data
    CRYPTO_CREATE_CLEANUP_BUFFER(pFrameData, pFrame->frame_len);
    res = _decrypt_data(
        pFrame->ctr_nonce_rand, pEncryptionKey, _get_cipher_text(pData),
        pFrame->frame_len, pFrameData
    );
    if(res != 0){
        // printf("-FAIL [Decrypt]\n\n");
        host_print_error("Frame Bad Decryption\n");
        return res;
    }

    // Packet has been successfully decoded and verified
    // - Update time stamp tracker
    res = _timestamp_update(pFrame->channel, pFrame->time_stamp);
    if(res != 0){
        host_print_error("Time stamp update bad\n");
        return res;
    }

    // printf("-COMPLETE\n\n");
    host_write_packet(DECODE_MSG, pFrameData, pFrame->frame_len);
    return 0;
}