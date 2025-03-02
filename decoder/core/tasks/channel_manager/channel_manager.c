/**
 * @file channel_manager.c
 * @author Simon Rosenzweig
 * @brief Channel Manager implementation
 * @date 2025
 *
 * @copyright Copyright (c) 2025 The MITRE Corporation
 */

#include "channel_manager.h"

#include "string.h"

#include "FreeRTOS.h"
#include "task.h"
#include "queue.h"

#include "trng.h"

#include "crypto_manager.h"
#include "simple_flash.h"

//----- Private Constants -----//

#define RTOS_QUEUE_LENGTH 16

// Canary value used to detect if flash is valid or not
// - used in combination with a MIC!!
#define FLASH_FIRST_BOOT 0xDAD398CD

#define CHANNEL_KDF_INPUT_KEY_LEN_USED 26

#define CTR_NONCE_RAND_LEN 12

//----- Private Types -----//

// Channel information stored in flash
typedef struct __attribute__((packed)) {
    uint8_t active;
    channel_id_t id;
    timestamp_t timeStart;
    timestamp_t timeEnd;
} channel_status_t;

// Flash channel subscription info data storage structure
typedef struct __attribute__((packed)) {
    // If set to FLASH_FIRST_BOOT, device has booted before.
    uint32_t firstBootFlag; 

    uint8_t pCtrNonceRand[CTR_NONCE_RAND_LEN];
    uint16_t numActiveSubs;
    channel_status_t subscribedChannels[MAX_CHANNEL_COUNT];
    uint8_t mic[CRYPTO_MANAGER_MIC_LEN];
} flash_entry_t;

// Data used to derive the flash secret key from
typedef struct __attribute__((packed)) {
    uint16_t numActiveSubs;
    uint8_t flashKey[CHANNEL_KDF_INPUT_KEY_LEN_USED];
    uint32_t deviceId;
} flash_kdf_data_t;

//----- Private Variables -----//
static flash_entry_t _activeChannels;

// Task request queue
static QueueHandle_t _xRequestQueue;

// Whether flash data is good
static uint8_t _flashGood;

// Stores a random nonce generate on startup
uint8_t _ctrNonceRand[CTR_NONCE_RAND_LEN];

//----- Private Functions -----//
/** @brief Prints all the channels the decoder has a subscription for.
 *
*/
// static void _printActiveChannels(void){
//     printf("[ChannelManager] @INFO Active Channels:\n");
//     for (size_t i = 0; i < MAX_CHANNEL_COUNT; i++) {
//         if (_activeChannels.subscribedChannels[i].active) {
//             printf(
//                 "-{I} [%u] {Channel: %lu, Time Stamp Start: %llu, Time Stamp End: %llu}\n",
//                 i, _activeChannels.subscribedChannels[i].id, 
//                 _activeChannels.subscribedChannels[i].timeStart,
//                 _activeChannels.subscribedChannels[i].timeEnd
//             );
//         }
//     }
//     printf("-COMPLETE\n\n");
// }

/** @brief Calculates the number of active subscriptions
 * 
 *  @return Number of active subscriptions
 */
static int _numActiveSubs(void){
    int ret = 0;

    if(_flashGood == 0){
        return 0;
    }

    for(size_t i = 0; i < MAX_CHANNEL_COUNT; i++){
        if(_activeChannels.subscribedChannels[i].active){
            ret++;
        }
    }

    return ret;
}

/** @brief Write the _activeChannels structure to flash
 * 
 */
static int _updateFlash(void){
    // Disable all interrupts while writing to flash
    // - Only RAM code can run while writing to flash I think?!?!
    // - Else RTOS dies :(
    __disable_irq();
    flash_simple_erase_page(FLASH_STATUS_ADDR);
    flash_simple_write(FLASH_STATUS_ADDR, &_activeChannels, sizeof(flash_entry_t));

    // Re-enable all interrupts
    __enable_irq();

    return 0;
}


/** @brief Calculates the flash data (_activeChannels) MIC, 
 *         calls into Crypto Manager
 * 
 * @param pMic Point to buffer to store the calculated MIC in
 * 
 * @return 0 on success, other number on fail
 */
static int _calculateMic(uint8_t *pMic){
    int res;
    QueueHandle_t xRequestQueue = cryptoManager_RequestQueue();

    // printf("[ChannelManager] @INFO Sending Signature Sign Request\n");

    //-- Prepare the Signature Sign Packet --//
    CryptoManager_SignatureSign cryptoSigSign;

    //-- Assemble KDF Data
    flash_kdf_data_t flashKdfData;
    flashKdfData.numActiveSubs = _activeChannels.numActiveSubs;

    const uint8_t *pKdfInputKey;
    cryptoManager_GetFlashKdfInputKey(&pKdfInputKey);
    memcpy(flashKdfData.flashKey, pKdfInputKey, CHANNEL_KDF_INPUT_KEY_LEN_USED);

    flashKdfData.deviceId = cryptoManager_DecoderId();

    // Assemble CTR nonce
    // [0]: Decoder ID (4 Bytes, Big Endian)
    // [4]: Nonce Rand (12 Bytes)
    uint32_t decoderId = cryptoManager_DecoderId();
    CRYPTO_CREATE_CLEANUP_BUFFER(pCtrNonce, CRYPTO_MANAGER_NONCE_LEN);
    memcpy(pCtrNonce+sizeof(uint32_t), _activeChannels.pCtrNonceRand, CTR_NONCE_RAND_LEN);
    for(size_t i = 0; i < sizeof(uint32_t); i++){
        pCtrNonce[i] = ((uint8_t*)&decoderId)[3-i];
    }

    cryptoSigSign.kdfData.keySource = KEY_SOURCE_FLASH_KDF;
    cryptoSigSign.kdfData.length = sizeof(flash_kdf_data_t);
    cryptoSigSign.kdfData.pData = (uint8_t*)&flashKdfData;
    cryptoSigSign.kdfData.pNonce = pCtrNonce;

    //-- Assemble Signature Sign Data
    // MIC is calculated on the whole packet minus the MIC
    cryptoSigSign.pData = (uint8_t*)&_activeChannels;
    cryptoSigSign.length = sizeof(_activeChannels) - CRYPTO_MANAGER_MIC_LEN;
    cryptoSigSign.pSignature = pMic;
    
    //-- Assemble Request
    CryptoManager_Request cryptoRequest;
    cryptoRequest.xRequestingTask = xTaskGetCurrentTaskHandle();
    cryptoRequest.requestType = CRYPTO_MANAGER_REQ_SIG_SIGN;
    cryptoRequest.requestLen = sizeof(cryptoSigSign);
    cryptoRequest.pRequest = &cryptoSigSign;

    //-- Send Request and Wait
    xQueueSend(xRequestQueue, &cryptoRequest, portMAX_DELAY);
    xTaskNotifyWait(0, 0xFFFFFFFF, (uint32_t*)&res, portMAX_DELAY);

    // printf("[ChannelManager] @INFO Signature Sign res = %d\n", res);
    return res;
}

/** @brief Checks the flash data (_activeChannels) MIC, 
 *         calls into Crypto Manager
 * 
 * @return 0 if valid, other numbers if invalid
 */
static int _checkMicValid(void){
    int res;
    QueueHandle_t xRequestQueue = cryptoManager_RequestQueue();

    // printf("[ChannelManager] @INFO Sending Signature Check Request\n");

    //-- Prepare the Signature Sign Packet --//
    CryptoManager_SignatureCheck cryptoSigCheck;

    //-- Assemble KDF Data
    flash_kdf_data_t flashKdfData;
    flashKdfData.numActiveSubs = _activeChannels.numActiveSubs;

    const uint8_t *pKdfInputKey;
    cryptoManager_GetFlashKdfInputKey(&pKdfInputKey);
    memcpy(flashKdfData.flashKey, pKdfInputKey, CHANNEL_KDF_INPUT_KEY_LEN_USED);

    flashKdfData.deviceId = cryptoManager_DecoderId();

    // Assemble CTR nonce
    // [0]: Decoder ID (4 Bytes, Big Endian)
    // [4]: Nonce Rand (12 Bytes)
    uint32_t decoderId = cryptoManager_DecoderId();
    CRYPTO_CREATE_CLEANUP_BUFFER(pCtrNonce, CRYPTO_MANAGER_NONCE_LEN);
    memcpy(pCtrNonce+sizeof(uint32_t), _activeChannels.pCtrNonceRand, CTR_NONCE_RAND_LEN);
    for(size_t i = 0; i < sizeof(uint32_t); i++){
        pCtrNonce[i] = ((uint8_t*)&decoderId)[3-i];
    }

    cryptoSigCheck.kdfData.keySource = KEY_SOURCE_FLASH_KDF;
    cryptoSigCheck.kdfData.length = sizeof(flash_kdf_data_t);
    cryptoSigCheck.kdfData.pData = (uint8_t*)&flashKdfData;
    cryptoSigCheck.kdfData.pNonce = pCtrNonce;

    //-- Assemble Signature Sign Data
    // MIC is calculated on the whole packet minus the MIC
    cryptoSigCheck.pData = (uint8_t*)&_activeChannels;
    cryptoSigCheck.length = sizeof(_activeChannels) - CRYPTO_MANAGER_MIC_LEN;
    cryptoSigCheck.pExpectedSignature = _activeChannels.mic;
    
    //-- Assemble Request
    CryptoManager_Request cryptoRequest;
    cryptoRequest.xRequestingTask = xTaskGetCurrentTaskHandle();
    cryptoRequest.requestType = CRYPTO_MANAGER_REQ_SIG_CHECK;
    cryptoRequest.requestLen = sizeof(cryptoSigCheck);
    cryptoRequest.pRequest = &cryptoSigCheck;

    //-- Send Request and Wait
    xQueueSend(xRequestQueue, &cryptoRequest, portMAX_DELAY);
    xTaskNotifyWait(0, 0xFFFFFFFF, (uint32_t*)&res, portMAX_DELAY);

    // printf("[ChannelManager] @INFO Signature Check res = %d\n", res);
    return res;
}

/** @brief Initializes the flash data (_activeChannels) and updates flash
 * 
 * @return 0 if success, other numbers on fail
 */
static int _initializeFlash(void){
    int res;
    /* If this is the first boot of this decoder, mark all channels as unsubscribed.
    *  This data will be persistent across reboots of the decoder. Whenever the decoder
    *  processes a subscription update, this data will be updated.
    */
    // host_print_debug("Flash Manager: First boot -> Setting flash...\n");
    // printf("[ChannelManager] @INFO First Boot -> Setting Flash\n");

    _activeChannels.firstBootFlag = FLASH_FIRST_BOOT;
    for (int i = 0; i < MAX_CHANNEL_COUNT; i++){
        _activeChannels.subscribedChannels[i].timeStart = DEFAULT_CHANNEL_TIMESTAMP;
        _activeChannels.subscribedChannels[i].timeEnd = DEFAULT_CHANNEL_TIMESTAMP;
        _activeChannels.subscribedChannels[i].active = 0;
    }

    memcpy(_activeChannels.pCtrNonceRand, _ctrNonceRand, CTR_NONCE_RAND_LEN);
    _activeChannels.numActiveSubs = 0;

    // Calculate MIC
    res = _calculateMic(_activeChannels.mic);
    if(res != 0){
        return 1;
    }

    // Write data to flash
    _updateFlash();

    _flashGood = 1;
    return 0;
}

/** @brief Updates a channel subscription
 * 
 * @param pUpdateSub Pointer to structure with the new subscription information
 * 
 * @return 0 if success, other numbers on fail
 */
static int _updateSub(const ChannelManager_UpdateSubscription *pUpdateSub){
    int res;

    // Find:
    // - Existing subscription for specified channel
    // - If no existing subscription for channel, then first empty slot
    // printf("-{I} Looking for existing subscription for channel %u or free slot\n", pUpdateSub->channel);
    uint8_t foundIdx = 0;
    uint8_t idx = 0;
    for (size_t i = 0; i < MAX_CHANNEL_COUNT; i++) {
        // Break instantly if existing subscription for channel is found
        // - Always update existing subscriptions
        if (_activeChannels.subscribedChannels[i].id == pUpdateSub->channel) {
            idx = i;
            foundIdx = 1;
            // printf("-{I} Found Existing Subscription :)\n");
            break;
        }

        // Found empty spot
        // - Need to keep looping though incase there is an existing subscription for specified channel further along
        if(!_activeChannels.subscribedChannels[i].active && foundIdx == 0){
            idx = i;
            foundIdx = 1;
            // printf("-{I} Found Empty Slot but Looking for Existing Subscription\n");
        }
    }

    // Check if no suitable idx was found
    // - No space left in subscriptions array :(
    if (foundIdx == 0) {
        // STATUS_LED_RED();
        // printf("-FAIL [Max Subscription]\n\n");
        // host_print_error("Subscription Update: Max Subscriptions\n");
        return 1;
    }

    // Update subscription info
    _activeChannels.subscribedChannels[idx].active = true;
    _activeChannels.subscribedChannels[idx].id = pUpdateSub->channel;
    _activeChannels.subscribedChannels[idx].timeStart = pUpdateSub->timeStart;
    _activeChannels.subscribedChannels[idx].timeEnd = pUpdateSub->timeEnd;

    // printf(
    //     "-{I} Subscription Update Successful {Idx: %u, Channel: %u, Start: %llu, End: %llu}\n",
    //     idx, pUpdateSub->channel, pUpdateSub->timeStart, pUpdateSub->timeEnd
    // );

    // Increment flash nonce by one
    // - Big endian
    _activeChannels.numActiveSubs = _numActiveSubs();
    for (size_t i = CTR_NONCE_RAND_LEN - 1; i >= 0; i--){
        _activeChannels.pCtrNonceRand[i]++;
        if (_activeChannels.pCtrNonceRand[i] != 0){
            break; 
        }
    }
    res = _calculateMic(_activeChannels.mic);
    if(res != 0){
        return res;
    }

    _updateFlash();

    return 0;
}

/** @brief Checks if subscription for "channel" at "time" is active 
 * 
 * @param pCheckActiveSub Pointer to structure of the current channel information
 * 
 * @return 0 if subscription valid, other numbers if invalid
 */
static int _checkActiveSubscription(const ChannelManager_CheckActiveSub *pCheckActiveSub) {
    if(_flashGood == 0){
        return 1;
    }

    // Check if this is an emergency broadcast message
    if (pCheckActiveSub->channel == EMERGENCY_CHANNEL) {
        return 0;
    }

    // Check if the decoder has has a subscription
    for (size_t i = 0; i < MAX_CHANNEL_COUNT; i++) {
        // Check subscription is valid
        if (_activeChannels.subscribedChannels[i].id == pCheckActiveSub->channel && _activeChannels.subscribedChannels[i].active) {
            if(pCheckActiveSub->time >= _activeChannels.subscribedChannels[i].timeStart && pCheckActiveSub->time <= _activeChannels.subscribedChannels[i].timeEnd){
                return 0;
            }
        }
    }
    return 1;
}

/** @brief Gets all the active subscriptions
 * 
 * @param pCheckActiveSub Pointer to structure to store the subscription information in
 * 
 * @return 0 if success, other numbers if failed
 */
static int _getSubs(ChannelManager_GetSubscriptions *pGetSubs){
    if(_flashGood == 0){
        return 1;
    }

    int numChannels = 0;
    // Check if channel is active
    for (uint32_t i = 0; i < MAX_CHANNEL_COUNT; i++) {
        // Check if the subscription is active
        if (_activeChannels.subscribedChannels[i].active) {
            pGetSubs->channels[numChannels] =  _activeChannels.subscribedChannels[i].id;
            pGetSubs->timeStart[numChannels] = _activeChannels.subscribedChannels[i].timeStart;
            pGetSubs->timeEnd[numChannels] = _activeChannels.subscribedChannels[i].timeEnd;
            numChannels++;
        }
    }
    pGetSubs->numChannels = numChannels;
    return 0;
}

/** @brief Processes requests from other tasks
 * 
 * @param pRequest Pointer to request structure
 * 
 * @return 0 if success, other numbers if failed
 */
static int _processRequest(ChannelManager_Request *pRequest){
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
        case CHANNEL_MANAGER_CHECK_ACTIVE_SUB:
            // printf("-{I} Check Active Subscription Request\n");

            // Check request length is good
            if(pRequest->requestLen != sizeof(ChannelManager_CheckActiveSub)){
                // printf("-{E} Bad Request Length!!\n");
                return 0;
            }

            // Check for active subscriptions in given channel
            ChannelManager_CheckActiveSub *pCheckActiveSub = pRequest->pRequest;
            res = _checkActiveSubscription(pCheckActiveSub);
            break;

        case CHANNEL_MANAGER_GET_SUBS:
            // printf("-{I} Get Subscriptions Request\n");

            // Check request length is good
            if(pRequest->requestLen != sizeof(ChannelManager_GetSubscriptions)){
                // printf("-{E} Bad Request Length!!\n");
                return 0;
            }

            // List alls channels with subscriptions
            ChannelManager_GetSubscriptions *pGetSubs = pRequest->pRequest;
            res = _getSubs(pGetSubs);
            break;

        case CHANNEL_MANAGER_UPDATE_SUB:
            // printf("-{I} Update Subscription Request\n");

            // Check request length is good
            if(pRequest->requestLen != sizeof(ChannelManager_UpdateSubscription)){
                // printf("-{E} Bad Request Length!!\n");
                return 0;
            }

            // Update subscription
            ChannelManager_UpdateSubscription *pUpdateSub = pRequest->pRequest;
            res = _updateSub(pUpdateSub);
            break;

        default:
            // printf("-{E} Unknown Request Type!!\n");
            res = 1;
            break;
    }

    return res;
}

//----- Public Functions -----//

/** @brief Initializes the Channel Manager ready for the main task to be run
 * 
 * @note Must be called before RTOS scheduler starts!!
 */
void channelManager_Init(void){
    // Initialize the flash peripheral to enable access to persistent memory
    flash_simple_init();

    // Generate random nonce if needed later
    // - Don't want to access this TRNG in task as other tasks maybe using it!!
    MXC_TRNG_Random(_ctrNonceRand, CTR_NONCE_RAND_LEN);

    // Setup request queue
    _xRequestQueue = xQueueCreate(
        RTOS_QUEUE_LENGTH, sizeof(ChannelManager_Request)
    );
}

/** @brief Channel Manager main RTOS task
 * 
 * @param pvParameters FreeRTOS task parameters
 */
void channelManager_vMainTask(void *pvParameters){
    // Read starting flash values into our flash status struct
    flash_simple_read(FLASH_STATUS_ADDR, &_activeChannels, sizeof(flash_entry_t));

    int micNValid = _checkMicValid() == 0? 0: 1;

    // Reinitialize flash if:
    // - Flash first boot flag not set correctly
    // - MIC is wrong
    if ((_activeChannels.firstBootFlag != FLASH_FIRST_BOOT) || micNValid) {
        _initializeFlash();
    }else{
        _flashGood = 1;
    }

    ChannelManager_Request channelRequest;

    while (1){
        // Continually receive requests from other tasks and process them
        if (xQueueReceive(_xRequestQueue, &channelRequest, portMAX_DELAY) == pdPASS){
            // printf("[ChannelManager] @TASK Received Request\n");
            int res = _processRequest(&channelRequest);
            // printf("-COMPLETE\n");

            // Signal the requesting task that request is complete
            xTaskNotify(channelRequest.xRequestingTask, res, eSetValueWithOverwrite);
        }
    }
}

/** @brief Returns Channel Manager request queue 
 * 
 * @param QueueHandle_t Request queue to send requests to Channel Manager
 */
QueueHandle_t channelManager_RequestQueue(void){
    return _xRequestQueue;
}