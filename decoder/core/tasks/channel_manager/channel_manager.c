#include "channel_manager.h"

// #include "mxc_"

#include "FreeRTOS.h"
#include "task.h"
#include "queue.h"
#include "string.h"
#include "simple_flash.h"

//----- Private Constants -----//
#define RTOS_QUEUE_LENGTH 16

#define FLASH_FIRST_BOOT 0xDAD398CD

//----- Private Types -----//

//----- Private Variables -----//
static flash_entry_t _decoder_status;

// Task request queue
static QueueHandle_t _xRequestQueue;

//----- Private Functions -----//
/** @brief Prints all the channels the decoder has a subscription for.
 *
*/
// static void _printActiveChannels(void){
//     printf("[ChannelManager] @INFO Active Channels:\n");
//     for (size_t i = 0; i < MAX_CHANNEL_COUNT; i++) {
//         if (_decoder_status.subscribed_channels[i].active) {
//             printf(
//                 "-{I} [%u] {Channel: %lu, Time Stamp Start: %llu, Time Stamp End: %llu}\n",
//                 i, _decoder_status.subscribed_channels[i].id, 
//                 _decoder_status.subscribed_channels[i].start_timestamp,
//                 _decoder_status.subscribed_channels[i].end_timestamp
//             );
//         }
//     }
//     printf("-COMPLETE\n\n");
// }

static int _updateSub(const ChannelManager_UpdateSubscription *pUpdateSub){
    // Find:
    // - Existing subscription for specified channel
    // - If no existing subscription for channel, then first empty slot
    // printf("-{I} Looking for existing subscription for channel %u or free slot\n", pUpdateSub->channel);
    uint8_t foundIdx = 0;
    uint8_t idx = 0;
    for (size_t i = 0; i < MAX_CHANNEL_COUNT; i++) {
        // Break instantly if existing subscription for channel is found
        // - Always update existing subscriptions
        if (_decoder_status.subscribed_channels[i].id == pUpdateSub->channel) {
            idx = i;
            foundIdx = 1;
            // printf("-{I} Found Existing Subscription :)\n");
            break;
        }

        // Found empty spot
        // - Need to keep looping though incase there is an existing subscription for specified channel further along
        if(!_decoder_status.subscribed_channels[i].active && foundIdx == 0){
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
    _decoder_status.subscribed_channels[idx].active = true;
    _decoder_status.subscribed_channels[idx].id = pUpdateSub->channel;
    _decoder_status.subscribed_channels[idx].start_timestamp = pUpdateSub->timeStart;
    _decoder_status.subscribed_channels[idx].end_timestamp = pUpdateSub->timeEnd;

    // printf(
    //     "-{I} Subscription Update Successful {Idx: %u, Channel: %u, Start: %llu, End: %llu}\n",
    //     idx, pUpdateSub->channel, pUpdateSub->timeStart, pUpdateSub->timeEnd
    // );

    // Disable all interrupts while writing to flash
    // - Only RAM code can run while writing to flash I think?!?!
    // - Else RTOS dies :(
    __disable_irq();
    flash_simple_erase_page(FLASH_STATUS_ADDR);
    flash_simple_write(FLASH_STATUS_ADDR, &_decoder_status, sizeof(flash_entry_t));

    // Re-enable all interrupts
    __enable_irq();

    return 0;
}


static int _isSubscribed(const ChannelManager_CheckActiveSub *pCheckActiveSub) {
    // Check if this is an emergency broadcast message
    if (pCheckActiveSub->channel == EMERGENCY_CHANNEL) {
        return 1;
    }

    // Check if the decoder has has a subscription
    for (size_t i = 0; i < MAX_CHANNEL_COUNT; i++) {
        // Check subscription is valid
        if (_decoder_status.subscribed_channels[i].id == pCheckActiveSub->channel && _decoder_status.subscribed_channels[i].active) {
            if(pCheckActiveSub->time >= _decoder_status.subscribed_channels[i].start_timestamp && pCheckActiveSub->time <= _decoder_status.subscribed_channels[i].end_timestamp){
                return 1;
            }
        }
    }
    return 0;
}


static int _getSubs(ChannelManager_GetSubscription *pGetSubs){
    int numChannels = 0;
    // Check if channel is active
    for (uint32_t i = 0; i < MAX_CHANNEL_COUNT; i++) {
        // Check if the subscription is active
        if (_decoder_status.subscribed_channels[i].active) {
            pGetSubs->channels[numChannels] =  _decoder_status.subscribed_channels[i].id;
            pGetSubs->timeStart[numChannels] = _decoder_status.subscribed_channels[i].start_timestamp;
            pGetSubs->timeEnd[numChannels] = _decoder_status.subscribed_channels[i].end_timestamp;
            numChannels++;
        }
    }
    pGetSubs->numChannels = numChannels;
    return 0;
}

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
            res = _isSubscribed(pCheckActiveSub);
            break;

        case CHANNEL_MANAGER_GET_SUBSCRIPTION:
            // printf("-{I} Get Subscriptions Request\n");

            // Check request length is good
            if(pRequest->requestLen != sizeof(ChannelManager_GetSubscription)){
                // printf("-{E} Bad Request Length!!\n");
                return 0;
            }

            // List alls channels with subscriptions
            ChannelManager_GetSubscription *pGetSubs = pRequest->pRequest;
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
void channelManager_Init(void){
    // Initialize the flash peripheral to enable access to persistent memory
    flash_simple_init();

    // Read starting flash values into our flash status struct
    flash_simple_read(FLASH_STATUS_ADDR, &_decoder_status, sizeof(flash_entry_t));
    if (_decoder_status.first_boot != FLASH_FIRST_BOOT) {
        /* If this is the first boot of this decoder, mark all channels as unsubscribed.
        *  This data will be persistent across reboots of the decoder. Whenever the decoder
        *  processes a subscription update, this data will be updated.
        */
        // host_print_debug("First boot.  Setting flash...\n");
        // printf("[ChannelManager] @INFO First Boot -> Setting Flash\n");

        _decoder_status.first_boot = FLASH_FIRST_BOOT;

        channel_status_t subscription[MAX_CHANNEL_COUNT];

        for (int i = 0; i < MAX_CHANNEL_COUNT; i++){
            subscription[i].start_timestamp = DEFAULT_CHANNEL_TIMESTAMP;
            subscription[i].end_timestamp = DEFAULT_CHANNEL_TIMESTAMP;
            subscription[i].active = false;
        }

        // Write the starting channel subscriptions into flash.
        memcpy(_decoder_status.subscribed_channels, subscription, MAX_CHANNEL_COUNT*sizeof(channel_status_t));

        flash_simple_erase_page(FLASH_STATUS_ADDR);
        flash_simple_write(FLASH_STATUS_ADDR, &_decoder_status, sizeof(flash_entry_t));
    }


    // _printActiveChannels();
}

void channelManager_vMainTask(void *pvParameters){
    // Setup request queue
    _xRequestQueue = xQueueCreate(
        RTOS_QUEUE_LENGTH, sizeof(ChannelManager_Request)
    );

    ChannelManager_Request channelRequest;

    while (1){
        if (xQueueReceive(_xRequestQueue, &channelRequest, portMAX_DELAY) == pdPASS){
            // printf("[ChannelManager] @TASK Received Request\n");
            int res = _processRequest(&channelRequest);
            // printf("-COMPLETE\n");

            // Signal the requesting task that request is complete
            xTaskNotify(channelRequest.xRequestingTask, res, eSetValueWithOverwrite);
        }
    }
}

QueueHandle_t channelManager_RequestQueue(void){
    return _xRequestQueue;
}