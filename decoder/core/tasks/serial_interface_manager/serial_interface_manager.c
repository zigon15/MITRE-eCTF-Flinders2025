
#include "serial_interface_manager.h"

#include "uart.h"
#include "board.h"

#include "FreeRTOS.h"
#include "task.h"
#include "queue.h"
#include "string.h"

#include "subscription_manager.h"
#include "frame_manager.h"

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

    // uint8_t pFrame[] = {
    //     0x01, 0x00, 0x00, 0x00, 0xF1, 0x02, 0x88, 0xFA, 
    //     0x89, 0x19, 0x81, 0xF2, 0xC1, 0x44, 0x3E, 0x3A, 
    //     0x64, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
    //     0x0F, 0x2A, 0x40, 0x32, 0x27, 0x35, 0x58, 0x0D, 
    //     0xCF, 0x14, 0x4E, 0x23, 0x3B, 0x3A, 0xA6, 0xF5, 
    //     0x46, 0xAA, 0xBE, 0x48, 0xD1, 0x5A, 0x92, 0x9A, 
    //     0x75, 0xBD, 0x35, 0x9C, 0x80, 0x1F, 0x90, 0xCB, 
    //     0xFB,
    // };

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

static int _listChannels(){

}

//----- Public Functions -----//
void serialInterfaceManager_SetTaskId(TaskHandle_t taskId){
    _taskId = taskId;
}

void serialInterfaceManager_Init(void){
    uart_init();
}

void serialInterfaceManager_vMainTask(void *pvParameters){
    //-- Setup UART --//
    // Enable UART0 interrupt
    // NVIC_ClearPendingIRQ(UART0_IRQn);
    // NVIC_DisableIRQ(UART0_IRQn);
    // NVIC_SetPriority(UART0_IRQn, 5);
    // NVIC_EnableIRQ(UART0_IRQn);

    int uartReadLen = 1;

    // State for managing message processing
    char output_buf[256] = {0};
    uint8_t uart_buf[INPUT_BUFFER_SIZE];

    msg_type_t cmd;
    int result;
    uint16_t pkt_len;

    host_print_debug("Decoder Booted!\n");

    int res;

    while (1){
        host_print_debug("Ready\n");

        STATUS_LED_GREEN();

        result = host_read_packet(&cmd, uart_buf, INPUT_BUFFER_SIZE, &pkt_len);

        if(result < 0){
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
                    host_print_error("Decode Failed\n");
                }
                break;

            // Handle decode command
            case DECODE_MSG:
                STATUS_LED_PURPLE();
                res = _decodeFrame(uart_buf, pkt_len);
                if(res != 0){
                    host_print_error("Decode Failed\n");
                }
                break;

            // Handle subscribe command
            case SUBSCRIBE_MSG:
                STATUS_LED_YELLOW();
                res = _subscriptionUpdate(uart_buf, pkt_len);
                if(res != 0){
                    host_print_error("Subscription Update Failed\n");
                }
                break;

            // Handle bad command
            default:
                STATUS_LED_ERROR();
                sprintf(output_buf, "Invalid Command: %c\n", cmd);
                host_print_error(output_buf);
                break;
        }

        // // Register async read request
        // if (MXC_UART_TransactionAsync(&async_read_req) != E_NO_ERROR) {
        //     printf("Error registering async request. Command line unavailable.\n");
        //     vTaskDelay(portMAX_DELAY);
        // }

        // // Hang here until ISR wakes us for a character
        // ulTaskNotifyTake(pdTRUE, portMAX_DELAY);
        

        // int res;
       
        // uint8_t pSubUpdate[] = {
        //     0x01, 0x00, 0x00, 0x00, 0x11, 0x4E, 0xBE, 0x11, 
        //     0xB8, 0xB2, 0xE7, 0x5E, 0x63, 0x8E, 0xDD, 0x10, 
        //     0xFA, 0xD1, 0x59, 0x39, 0xC0, 0x3D, 0x1E, 0x7B, 
        //     0x43, 0x44, 0x34, 0xC9, 0x4B, 0xC0, 0x8E, 0x89, 
        //     0x07, 0x0B, 0x25, 0x55, 0xC0, 0xD0, 0x7E, 0x2D, 
        //     0xAC, 0x3C, 0x2B, 0xDD, 0x69, 0x6F, 0x96, 0x0F, 
        //     0x91, 0xA0, 0x21, 0xB1, 0xE3, 0x39, 0x04, 0x59, 
        //     0x26, 0x3D, 0xD0, 0xEF, 0xE7, 0x8E, 0xDD, 0x8F, 
        // };
        // _subscriptionUpdate(pSubUpdate, sizeof(pSubUpdate));

        // uint8_t pFramePacket[] = {
        //     0x01, 0x00, 0x00, 0x00, 0x6C, 0x86, 0x21, 0x3D, 
        //     0x2B, 0xF3, 0x9B, 0xE2, 0xCE, 0x60, 0xE7, 0x86, 
        //     0x64, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
        //     0x0F, 0x3C, 0x2F, 0xBF, 0x28, 0x74, 0xB5, 0x2E, 
        //     0xBE, 0xCD, 0x4E, 0xB9, 0x37, 0xD5, 0x3D, 0xC4, 
        //     0x35, 0xA5, 0x62, 0xC4, 0xF0, 0xE6, 0x61, 0x86, 
        //     0x39, 0xC5, 0x25, 0x94, 0xF8, 0x1A, 0xD3, 0xA4, 
        //     0x38,
        // };
        // _decodeFrame(pFramePacket, sizeof(pFramePacket));

        // while(1);

    }
}