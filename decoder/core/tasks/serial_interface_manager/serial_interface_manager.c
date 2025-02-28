
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
#define INPUT_BUFFER_SIZE 512
#define OUTPUT_BUFFER_SIZE 512

//----- Private Types -----//

//----- Private Variables -----//
TaskHandle_t _taskId;

//----- Private Functions -----//
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
void serialInterfaceManager_SetTaskId(TaskHandle_t taskId){
    _taskId = taskId;
}

void serialInterfaceManager_Init(void){
    uart_init();
}

void serialInterfaceManager_vMainTask(void *pvParameters){
    // State for managing message processing
    char uart_TxBuff[OUTPUT_BUFFER_SIZE] = {0};
    uint8_t uart_RxBuff[INPUT_BUFFER_SIZE];

    msg_type_t cmd;
    uint16_t pkt_len;

    host_print_debug("Decoder Booted!\n");

    int res;

    // uint8_t tmp[] = {
    //     0x01, 0x00, 0x00, 0x00, 0xBF, 0x5B, 0x9C, 0x11, 
    //     0x97, 0x69, 0xC5, 0xD4, 0xA0, 0xD7, 0xB2, 0xE9, 
    //     0x64, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
    //     0x0F, 0xEC, 0x9E, 0xA6, 0x9F, 0xB2, 0xF7, 0x87, 
    //     0x9A, 0x58, 0x7A, 0x56, 0x70, 0xC7, 0x24, 0x3B, 
    //     0x43, 0xF1, 0x09, 0x75, 0xED, 0x92, 0x9C, 0x4A, 
    //     0xB7, 0x50, 0x0F, 0x66, 0x8A, 0xC2, 0x04, 0x7E, 
    //     0xBA,
    // };
    // _decodeFrame(tmp, sizeof(tmp));

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
                    host_print_error("Decode Failed\n");
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