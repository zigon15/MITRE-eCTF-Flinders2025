#include "crypto_manager.h"
#include "crypto.h"

#include "FreeRTOS.h"
#include "task.h"
#include "queue.h"
#include "string.h"

//----- Private Constants -----//
#define QUEUE_LENGTH 16

//----- Private Variables -----//
// Global encryption request queue (holds pointers or structures)
QueueHandle_t xEncryptionQueue;

// Holds signature checking
QueueHandle_t xSignatureCheckQueue;

//----- Private Functions -----//
uint8_t _deriveAes256Key(
    CryptoManager_KeyDerivationData *pKeyDerivationData,
    uint8_t *pKey
){
    return 0;
}

uint8_t _encryptData(CryptoManager_EncryptData *pEncrypt){
    return 0;
}

uint8_t _signatureCheck(CryptoManager_SignatureCheck *pSigCheck){
    int ret = 0;

    // Derive key
    uint8_t pKey[crypto_get_key_len(MXC_AES_256BITS)];
    ret = _deriveAes256Key(&(pSigCheck->kdfRequest), pKey);
    if(ret != 0){
        return ret;
    }

    // Calculate signature

    return 0;
}

//----- Public Functions -----//

void cryptoManager_vEncryptionTask(void *pvParameters){
    // Setup queues
    xEncryptionQueue = xQueueCreate(
        QUEUE_LENGTH, sizeof(CryptoManager_EncryptionRequest)
    );
    xSignatureCheckQueue = xQueueCreate(
        QUEUE_LENGTH, sizeof(CryptoManager_EncryptionRequest)
    );

    CryptoManager_EncryptionRequest encReq;
    CryptoManager_SignatureCheckRequest sigCheckReq;

    while (1){
        if (xQueueReceive(xEncryptionQueue, &encReq, portMAX_DELAY) == pdPASS){
            // ---------------------------------------------------------------------
            // TODO: Replace the following dummy operation with your AES encryption.
            // Example: aes_encrypt(req.pPlainData, req.pEncryptedData, req.length, aesKey);
            // ---------------------------------------------------------------------
            // memcpy(encReq.pEncryptedData, encReq.pPlainData, encReq.length);

            // Signal the requesting task that encryption is complete
            xTaskNotifyGive(encReq.xRequestingTask);
        }

        if (xQueueReceive(xSignatureCheckQueue, &sigCheckReq, portMAX_DELAY) == pdPASS){
            uint8_t sigGood = 0;

            // Check signature
            uint8_t ret = _signatureCheck(&(sigCheckReq.sigCheck));
            if(ret == 0){
                sigGood = 1;
            }

            // Signal the requesting task that signature check is complete
            xTaskNotify(sigCheckReq.xRequestingTask, (uint32_t)sigGood, eSetValueWithOverwrite);
        }
    }
}

QueueHandle_t cryptoManager_EncryptionQueue(void){
    return xEncryptionQueue;
}

QueueHandle_t cryptoManager_SignatureCheckQueue(void){
    return xSignatureCheckQueue;
}