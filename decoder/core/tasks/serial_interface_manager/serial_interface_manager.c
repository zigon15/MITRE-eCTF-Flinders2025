
/**
 * @file serial_interface.c
 * @author Simon Rosenzweig
 * @brief Serial Interface Manager implementation
 * @date 2025
 *
 * @copyright Copyright (c) 2025 The MITRE Corporation
 */

#include "serial_interface_manager.h"

#include "uart.h"
#include "board.h"

#include "FreeRTOS.h"
#include "task.h"
#include "queue.h"
#include "string.h"

#include "subscription_manager.h"
#include "frame_manager.h"
#include "channel_manager.h"

#include "simple_uart.h"
#include "host_messaging.h"
#include "status_led.h"

//----- Private Constants -----//

// Uart input and output buffers max size
#define INPUT_BUFFER_SIZE 512
#define OUTPUT_BUFFER_SIZE 512

//----- Private Types -----//

// Channel info structure used for listChannels() command response
typedef struct __attribute__((packed)) {
    channel_id_t channel;
    timestamp_t start;
    timestamp_t end;
} channel_info_t;

// List channel response structure 
 typedef struct __attribute__((packed)) {
    uint32_t n_channels;
    channel_info_t channel_info[MAX_CHANNEL_COUNT];
} list_response_t;


//----- Private Functions -----//

/** @brief Decode the given frame data by dispatching a decode frame request 
 *         to the frame manager
 * 
 * @param pBuff Pointer to frame packet
 * @param length Length of frame packet
 * 
 * @return 0 on success, other number on fail
 */
static int _decodeFrame(
    const uint8_t *pBuff, const size_t length
){
    int res;

    QueueHandle_t xRequestQueue = frameManager_RequestQueue();

    //-- Prepare the Frame Decode Packet --//
    FrameManager_Decode frameDecode;

    frameDecode.pBuff = pBuff;
    frameDecode.pktLen = length;

    //-- Assemble Request
    FrameManager_Request frameRequest;
    frameRequest.xRequestingTask = xTaskGetCurrentTaskHandle();
    frameRequest.requestType = FRAME_MANAGER_DECODE;
    frameRequest.requestLen = sizeof(frameDecode);
    frameRequest.pRequest = &frameDecode;

    //-- Send Request and Wait
    xQueueSend(xRequestQueue, &frameRequest, portMAX_DELAY);
    xTaskNotifyWait(0, 0xFFFFFFFF, (uint32_t*)&res, portMAX_DELAY);

    return res;
}

/** @brief Performs a subscription update by dispatching a subscription update 
 *         request to the subscription manager
 * 
 * @param pBuff Pointer to subscription update packet
 * @param length Length of subscription update packet
 * 
 * @return 0 on success, other number on fail
 */
static int _subscriptionUpdate(
   const uint8_t *pBuff, const size_t length
){  
    int res;

    QueueHandle_t xRequestQueue = subscriptionManager_RequestQueue();

    //-- Prepare the Sub Update Packet --//
    SubscriptionManager_SubscriptionUpdate subUpdate;

    subUpdate.pBuff = pBuff;
    subUpdate.pktLen = length;

    //-- Assemble Request
    SubscriptionManager_Request subscriptionRequest;
    subscriptionRequest.xRequestingTask = xTaskGetCurrentTaskHandle();
    subscriptionRequest.requestType = SUBSCRIPTION_MANAGER_SUB_UPDATE;
    subscriptionRequest.requestLen = sizeof(subUpdate);
    subscriptionRequest.pRequest = &subUpdate;

    //-- Send Request and Wait
    xQueueSend(xRequestQueue, &subscriptionRequest, portMAX_DELAY);
    xTaskNotifyWait(0, 0xFFFFFFFF, (uint32_t*)&res, portMAX_DELAY);

    return res;
}

/** @brief Performs a list channel command by dispatching a list channels
 *         request to the channel manager
 * 
 * @return 0 on success, other number on fail
 */
static int _listChannels(void){
    int res;

    QueueHandle_t xRequestQueue = channelManager_RequestQueue();

    //-- Prepare the Sub Update Packet --//
    ChannelManager_GetSubscriptions getSubs;

    //-- Assemble Request
    ChannelManager_Request channelRequest;
    channelRequest.xRequestingTask = xTaskGetCurrentTaskHandle();
    channelRequest.requestType = CHANNEL_MANAGER_GET_SUBS;
    channelRequest.requestLen = sizeof(getSubs);
    channelRequest.pRequest = &getSubs;

    //-- Send Request and Wait
    xQueueSend(xRequestQueue, &channelRequest, portMAX_DELAY);
    xTaskNotifyWait(0, 0xFFFFFFFF, (uint32_t*)&res, portMAX_DELAY);

    if(res != 0){
        return 1;
    }

    //-- Assemble and send channels to TV
    list_response_t resp;
    memset(&resp, 0, sizeof(list_response_t));
    pkt_len_t len;

    resp.n_channels = getSubs.numChannels;
    for(uint32_t i = 0; i < getSubs.numChannels; i++){
        resp.channel_info[i].channel = getSubs.channels[i];
        resp.channel_info[i].start = getSubs.timeStart[i];
        resp.channel_info[i].end = getSubs.timeEnd[i];
    }

    len = sizeof(resp.n_channels) + (sizeof(channel_info_t) * resp.n_channels);

    // Success message
    host_write_packet(LIST_MSG, &resp, len);

    return 0;
}

//----- Public Functions -----//

/** @brief Initializes the Serial Interface Manager ready for the main task to be run
 * 
 * @note Must be called before RTOS scheduler starts!!
 */
void serialInterfaceManager_Init(void){
    uart_init();
}

/** @brief Serial Interface Manager main RTOS task
 * 
 * @param pvParameters FreeRTOS task parameters
 */
void serialInterfaceManager_vMainTask(void *pvParameters){
    // State for managing message processing
    char uart_TxBuff[OUTPUT_BUFFER_SIZE] = {0};
    uint8_t uart_RxBuff[INPUT_BUFFER_SIZE];

    msg_type_t cmd;
    uint16_t pkt_len;

    host_print_debug("Decoder Booted!\n");

    int res;

    while (1){
        // host_print_debug("Ready\n");
        STATUS_LED_GREEN();

        res = host_read_packet(&cmd, uart_RxBuff, INPUT_BUFFER_SIZE, &pkt_len);
        if(res < 0){
            STATUS_LED_ERROR();
            host_print_error("Failed to receive cmd from host\n");
            continue;
        }

        // Handle the requested command
        switch(cmd){
            // Handle list command
            case LIST_MSG:
                STATUS_LED_CYAN();
                res = _listChannels();
                if(res != 0){
                    STATUS_LED_RED();
                    host_print_error("List Channels Failed\n");
                }
                break;

            // Handle decode command
            case DECODE_MSG:
                STATUS_LED_PURPLE();
                res = _decodeFrame(uart_RxBuff, pkt_len);
                if(res != 0){
                    STATUS_LED_RED();
                    host_print_error("Decode Failed\n");
                }
                break;

            // Handle subscribe command
            case SUBSCRIBE_MSG:
                STATUS_LED_YELLOW();
                res = _subscriptionUpdate(uart_RxBuff, pkt_len);
                if(res != 0){
                    STATUS_LED_RED();
                    host_print_error("Subscription Update Failed\n");
                }
                break;

            // Handle bad command
            default:
                STATUS_LED_ERROR();
                sprintf(uart_TxBuff, "Invalid Command: %c\n", cmd);
                host_print_error(uart_TxBuff);
                break;
        }
    }
}