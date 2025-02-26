#include "subscription_manager.h"
#include "crypto.h"

#include "FreeRTOS.h"
#include "task.h"
#include "queue.h"
#include "string.h"

#include "crypto_manager.h"

//----- Private Constants -----//

//----- Private Variables -----//


//----- Private Functions -----//

//----- Public Functions -----//

void subscriptionManager_vEncryptionTask(void *pvParameters){
    // QueueHandle_t xEncryptionQueue = cryptoManager_SignatureCheckQueue();

    while (1){
        // CryptoManager_EncryptionRequest encryptionRequest;
        // xQueueSend(xEncryptionQueue, &encryptionRequest, portMAX_DELAY);

    }
}