
#include "serial_interface_manager.h"

#include "uart.h"
#include "board.h"

#include "FreeRTOS.h"
#include "task.h"
#include "queue.h"
#include "string.h"

#include "subscription_manager.h"
#include "frame_manager.h"

//----- Private Constants -----//
#define INPUT_BUFFER_SIZE 512
#define OUTPUT_BUFFER_SIZE 512

//----- Private Types -----//
#define CMD_TYPE_LEN sizeof(char)
#define CMD_LEN_LEN sizeof(uint16_t)
#define MSG_MAGIC '%'     // '%' - 0x25
#define MAX_ALLOWED_LEN 65535

typedef enum {
    DECODE_MSG = 'D',     // 'D' - 0x44
    SUBSCRIBE_MSG = 'S',  // 'S' - 0x53
    LIST_MSG = 'L',       // 'L' - 0x4c
    ACK_MSG = 'A',        // 'A' - 0x41
    DEBUG_MSG = 'G',      // 'G' - 0x47
    ERROR_MSG = 'E',      // 'E' - 0x45
} msg_type_t;

// Tells the compiler not to pad the struct members
#pragma pack(push, 1) 

typedef struct {
    char magic;    // Should be MSG_MAGIC
    char cmd;      // msg_type_t
    uint16_t len;
} msg_header_t;

// Tells the compiler to resume padding struct members
#pragma pack(pop) 

enum MsgProgress{
    MSG_WAIT_MAGIC_BYTE,
    MSG_WAIT_HEADER,
    MSG_WRITE_ACK,
    MSG_WAIT_ACK,
    MSG_WAIT_DATA,
};

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

/** @brief vCmdLineTask_cb 
 * Callback on asynchronous reads to wake the waiting command
 *  processor task
 */
static void _newUartData_cb(mxc_uart_req_t *req, int error){
    BaseType_t xHigherPriorityTaskWoken;

    // Wake the task
    xHigherPriorityTaskWoken = pdFALSE;
    vTaskNotifyGiveFromISR(_taskId, &xHigherPriorityTaskWoken);
    portYIELD_FROM_ISR(xHigherPriorityTaskWoken);
}

//----- Public Functions -----//
void serialInterfaceManager_SetTaskId(TaskHandle_t taskId){
    _taskId = taskId;
}

void serialInterfaceManager_Init(void){

}

void serialInterfaceManager_vMainTask(void *pvParameters){
    //-- Setup UART --//
    // Enable UART0 interrupt
    NVIC_ClearPendingIRQ(UART0_IRQn);
    NVIC_DisableIRQ(UART0_IRQn);
    NVIC_SetPriority(UART0_IRQn, 5);
    NVIC_EnableIRQ(UART0_IRQn);
    
    // Async read will be used to wake process
    mxc_uart_req_t async_read_req;
    uint8_t rxData;

    async_read_req.uart = MXC_UART_GET_UART(CONSOLE_UART);
    async_read_req.rxData = &rxData;
    async_read_req.rxLen = 1;
    async_read_req.txData = NULL;
    async_read_req.txLen = 0;
    async_read_req.callback = _newUartData_cb;

    int uartReadLen = 1;

    // State for managing message processing
    int rxMsgProgress = MSG_WAIT_MAGIC_BYTE;
    msg_header_t msgHeader;
    uint8_t inputMsgData[INPUT_BUFFER_SIZE];

    int dataCounter = 0;

    while (1){
        // Register async read request
        if (MXC_UART_TransactionAsync(&async_read_req) != E_NO_ERROR) {
            printf("Error registering async request. Command line unavailable.\n");
            vTaskDelay(portMAX_DELAY);
        }
        // Hang here until ISR wakes us for a character
        ulTaskNotifyTake(pdTRUE, portMAX_DELAY);
        
         // Check that we have a valid character
         if (async_read_req.rxCnt > 0) {
            // Continually process characters
            // - Initial tmp is set my async process so always process the one character at least
            do {
                switch (rxMsgProgress){
                    // Wait for magic byte indicating message start
                    case MSG_WAIT_MAGIC_BYTE:
                        if(rxData == MSG_MAGIC){
                            memset(msgHeader, 0, sizeof(msgHeader));
                            dataCounter = 0;

                            rxMsgProgress = MSG_WAIT_HEADER;
                        }
                        break;

                    // Process header
                    case MSG_WAIT_HEADER:
                        (uint8_t*)(&msgHeader)[dataCounter] = rxData;
                        dataCounter++;

                        // Check if header received
                        if(dataCounter == sizeof(msgHeader)){
                            dataCounter = 0;
                            
                            // Figure out what to do next based on header command :)

                            // Ack message so no data
                            if (msgHeader.cmd == ACK_MSG) {
                                rxMsgProgress = MSG_WAIT_MAGIC_BYTE;
                                break;
                            }

                            // ACK the header
                            if (host_write_ack() < 0) { 
                                rxMsgProgress = MSG_WAIT_MAGIC_BYTE;
                                break;
                            }
                        }
                        break;

                    // Write ack
                    case MSG_WRITE_ACK:
                        if(){
                            // Check data fits in buffer
                            if (header.len > INPUT_BUFFER_SIZE) {
                                rxMsgProgress = MSG_WAIT_MAGIC_BYTE;
                                break;
                            }

                            // No data attached so wait for next command
                            if (header.len == 0) {
                                rxMsgProgress = MSG_WAIT_MAGIC_BYTE;
                                break;
                            }

                            // Next step is to read in data
                            rxMsgProgress = MSG_WAIT_DATA;
                        }
                        break;
                    // Process data attached to header
                    case MSG_WAIT_DATA:
                        inputMsgData[dataCounter] = rxData;
                        dataCounter++;

                        // Check if full data packet has been received
                        if(dataCounter == msgHeader.len){
                        }

                        break;
                    default:
                        break;
                }
                
                uartReadLen = 1;
                // If more characters are ready, continually process them
            } while (
                (MXC_UART_GetRXFIFOAvailable(MXC_UART_GET_UART(CONSOLE_UART)) > 0) &&
                (MXC_UART_Read(CONSOLE_UART, (uint8_t *)&rxData, &uartReadLen) == 0)
            );
        }

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