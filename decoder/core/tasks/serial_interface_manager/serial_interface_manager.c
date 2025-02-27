
#include "serial_interface_manager.h"

#include "FreeRTOS.h"
#include "task.h"
#include "queue.h"
#include "string.h"

#include "subscription_manager.h"


//----- Private Constants -----//



//----- Private Types -----//

//----- Private Variables -----//


//----- Private Functions -----//


//----- Public Functions -----//
void serialInterfaceManager_vMainTask(void *pvParameters){

    while (1){
        int res;
        QueueHandle_t xRequestQueue = subscriptionManager_RequestQueue();

        uint8_t pSubUpdate[] = {
            0x01, 0x00, 0x00, 0x00, 0x11, 0x4E, 0xBE, 0x11, 
            0xB8, 0xB2, 0xE7, 0x5E, 0x63, 0x8E, 0xDD, 0x10, 
            0xFA, 0xD1, 0x59, 0x39, 0xC0, 0x3D, 0x1E, 0x7B, 
            0x43, 0x44, 0x34, 0xC9, 0x4B, 0xC0, 0x8E, 0x89, 
            0x07, 0x0B, 0x25, 0x55, 0xC0, 0xD0, 0x7E, 0x2D, 
            0xAC, 0x3C, 0x2B, 0xDD, 0x69, 0x6F, 0x96, 0x0F, 
            0x91, 0xA0, 0x21, 0xB1, 0xE3, 0x39, 0x04, 0x59, 
            0x26, 0x3D, 0xD0, 0xEF, 0xE7, 0x8E, 0xDD, 0x8F, 
        };

        //-- Prepare the Sub Update Packet --//
        SubscriptionManager_SubscriptionUpdate subUpdate;

        subUpdate.pBuff = pSubUpdate;
        subUpdate.pktLen = sizeof(pSubUpdate);

        //-- Assemble Request
        SubscriptionManager_Request subscriptionRequest;
        subscriptionRequest.xRequestingTask = xTaskGetCurrentTaskHandle();
        subscriptionRequest.requestType = SUBSCRIPTION_MANAGER_SUB_UPDATE;
        subscriptionRequest.requestLen = sizeof(subUpdate);
        subscriptionRequest.pRequest = &subUpdate;

        //-- Send Request and Wait
        xQueueSend(xRequestQueue, &subscriptionRequest, portMAX_DELAY);
        xTaskNotifyWait(0, 0xFFFFFFFF, &res, portMAX_DELAY);

        while(1);

    }
}