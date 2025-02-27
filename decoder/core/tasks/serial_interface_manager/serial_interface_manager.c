
#include "serial_interface_manager.h"

#include "FreeRTOS.h"
#include "task.h"
#include "queue.h"
#include "string.h"

#include "subscription_manager.h"
#include "frame_manager.h"

//----- Private Constants -----//


//----- Private Types -----//

//----- Private Variables -----//


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

//----- Public Functions -----//
void serialInterfaceManager_vMainTask(void *pvParameters){

    while (1){
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

        uint8_t pFramePacket[] = {
            0x01, 0x00, 0x00, 0x00, 0x6C, 0x86, 0x21, 0x3D, 
            0x2B, 0xF3, 0x9B, 0xE2, 0xCE, 0x60, 0xE7, 0x86, 
            0x64, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
            0x0F, 0x3C, 0x2F, 0xBF, 0x28, 0x74, 0xB5, 0x2E, 
            0xBE, 0xCD, 0x4E, 0xB9, 0x37, 0xD5, 0x3D, 0xC4, 
            0x35, 0xA5, 0x62, 0xC4, 0xF0, 0xE6, 0x61, 0x86, 
            0x39, 0xC5, 0x25, 0x94, 0xF8, 0x1A, 0xD3, 0xA4, 
            0x38,
        };
        _decodeFrame(pFramePacket, sizeof(pFramePacket));

        // while(1);

    }
}