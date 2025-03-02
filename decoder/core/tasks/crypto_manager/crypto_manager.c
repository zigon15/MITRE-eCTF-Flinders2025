#include "crypto_manager.h"

#include "FreeRTOS.h"
#include "task.h"
#include "queue.h"
#include "string.h"

#include "crypto.h"
#include "global_secrets.h"

//----- Private Constants -----//
#define RTOS_QUEUE_LENGTH 16

#define CTR_NONCE_RAND_LEN 12
#define CRYPTO_MANAGER_KEY_LEN 32

//----- Private Variables -----//
// Task request queue
static QueueHandle_t _xRequestQueue;

const uint32_t _decoder_id = DECODER_ID;

//----- Private Functions -----//
static int _deriveAes256Key(
    const CryptoManager_KeyDerivationData *pKeyDerivationData,
    uint8_t *pKey
){
    int res;

    // Get KDF key
    const uint8_t *pKdfKey;
    switch (pKeyDerivationData->keySource){
        case KEY_SOURCE_SUBSCRIPTION_KDF:
            // printf("-{I} Using Subscription KDF key\n");
            res = secrets_get_subscription_kdf_key(&pKdfKey);
            break;
        case KEY_SOURCE_FRAME_KDF:
            // printf("-{I} Using Frame KDF key\n");
            res = secrets_get_frame_kdf_key(&pKdfKey);
            break;
        case KEY_SOURCE_FLASH_KDF:
            // printf("-{I} Using Frame KDF key\n");
            res = secrets_get_flash_kdf_key(&pKdfKey);
            break;
        default:
            // printf("-{E} Bad KDF key source!!\n");
            // printf("-FAIL\n");
            res = 1;
            break;
    }
    if(res != 0){
        // printf("-{E} Failed to find KDF key!!\n");
        // printf("-FAIL\n");
        return res;
    }

    CRYPTO_CREATE_CLEANUP_BUFFER(pCipherText, pKeyDerivationData->length);

    // printf("-{I} KDF Key: ");
    // crypto_print_hex(pKdfKey, SUBSCRIPTION_KDF_KEY_LEN);
    // printf("-{I} KDF Nonce: ");
    // crypto_print_hex(pKeyDerivationData->pNonce, CRYPTO_MANAGER_NONCE_LEN);
    // printf("-{I} KDF Input: ");
    // crypto_print_hex(pKeyDerivationData->pData, pKeyDerivationData->length);

    // Perform encryption to calculate key
    res = crypto_AES_CTR_encrypt(
        pKdfKey, MXC_AES_256BITS, pKeyDerivationData->pNonce,
        (uint8_t*)pKeyDerivationData->pData, pCipherText, pKeyDerivationData->length
    );
    if(res != 0){
        // printf("-{E} AES CTR Failed for MIC Key KDF!!\n");
        // printf("-FAIL\n");
        return res;
    }

    // printf("-{I} Derived Key: ");
    // crypto_print_hex(pCipherText, CRYPTO_MANAGER_KEY_LEN);

    memcpy(pKey, pCipherText, CRYPTO_MANAGER_KEY_LEN);

    return 0;
}

static int _decryptData(const CryptoManager_DecryptData *pDecrypt){
    int res = 0;

    // Derive key
    uint8_t pDecryptionKey[crypto_get_key_len(MXC_AES_256BITS)];
    res = _deriveAes256Key(&(pDecrypt->kdfData), pDecryptionKey);
    if(res != 0){
        return res;
    }

    // printf("-{I} Decryption Key: ");
    // crypto_print_hex(pDecryptionKey, 32);
    // printf("-{I} Decryption Nonce: ");
    // crypto_print_hex(pDecrypt->pNonce, CRYPTO_MANAGER_NONCE_LEN);
    // printf("-{I} Decryption Cipher Text: ");
    // crypto_print_hex(pDecrypt->pCipherText, pDecrypt->length);

    // Decrypt the data
    res = crypto_AES_CTR_decrypt(
        pDecryptionKey, MXC_AES_256BITS, pDecrypt->pNonce,
        pDecrypt->pCipherText, pDecrypt->pPlainText, pDecrypt->length
    );
    if(res != 0){
        // printf("-{E} AES CTR Failed for Cipher Text Decryption!!\n");
        // printf("-FAIL\n");
        return res;
    }

    // printf("-{I} Decryption Plain Text: ");
    // crypto_print_hex(pDecrypt->pPlainText, pDecrypt->length);

    return 0;
}

static int _signatureCheck(CryptoManager_SignatureCheck *pSigCheck){
    int res = 0;

    // Derive key
    CRYPTO_CREATE_CLEANUP_BUFFER(pMicKey, CRYPTO_MANAGER_KEY_LEN);
    res = _deriveAes256Key(&(pSigCheck->kdfData), pMicKey);
    if(res != 0){
        return res;
    }

    // printf("-{I} MIC Key: ");
    // crypto_print_hex(pMicKey, CRYPTO_MANAGER_KEY_LEN);
    // printf("-{I} MIC Input: ");
    // crypto_print_hex(pSigCheck->pData, pSigCheck->length);

    // Calculate expect MIC on subscription packet
    CRYPTO_CREATE_CLEANUP_BUFFER(calculatedMic, CRYPTO_MANAGER_MIC_LEN);
    res = crypto_AES_CMAC(
        pMicKey, MXC_AES_256BITS, 
        pSigCheck->pData, pSigCheck->length,
        calculatedMic
    );
    if(res != 0){
        return res;
    }

    // printf("-{I} Calculated MIC: ");
    // crypto_print_hex(calculatedMic, CRYPTO_MANAGER_MIC_LEN);
    // printf("-{I} Packet MIC: ");
    // crypto_print_hex(pSigCheck->pExpectedSignature, CRYPTO_MANAGER_MIC_LEN);

    // Compare MIC
    if (memcmp(calculatedMic, pSigCheck->pExpectedSignature, CRYPTO_MANAGER_MIC_LEN) != 0){
        // printf("-{E} Calculated MIC Does Not Match Packet MIC!!\n");
        // printf("-FAIL\n");
        return 1;
    }
    // printf("-{I} MIC Good :)\n");
    return 0;
}

static int _signatureSign(CryptoManager_SignatureSign *pSigSign){
    int res = 0;

    // Derive key
    CRYPTO_CREATE_CLEANUP_BUFFER(pMicKey, CRYPTO_MANAGER_KEY_LEN);
    res = _deriveAes256Key(&(pSigSign->kdfData), pMicKey);
    if(res != 0){
        return res;
    }

    // printf("-{I} MIC Key: ");
    // crypto_print_hex(pMicKey, CRYPTO_MANAGER_KEY_LEN);
    // printf("-{I} MIC Input: ");
    // crypto_print_hex(pSigSign->pData, pSigSign->length);

    // Calculate expect MIC on subscription packet
    CRYPTO_CREATE_CLEANUP_BUFFER(pTmpMic, CRYPTO_MANAGER_MIC_LEN);
    res = crypto_AES_CMAC(
        pMicKey, MXC_AES_256BITS, 
        pSigSign->pData, pSigSign->length,
        pTmpMic
    );
    if(res != 0){
        return res;
    }

    // printf("-{I} Calculated MIC: ");
    // crypto_print_hex(pTmpMic, CRYPTO_MANAGER_MIC_LEN);

    memcpy(pSigSign->pSignature, pTmpMic, CRYPTO_MANAGER_MIC_LEN);
    return 0;
}

static int _subCipherAuthTagCheck(CryptoManager_SubDecryptedAuthTokenCheck *pCipherAuthTagCheck){
    int res = 0;

    // Check given packet length is good
    if(pCipherAuthTagCheck->length != SUBSCRIPTION_CIPHER_AUTH_TAG_LEN){
        // printf("-{E} Bad Cipher Auth Tag Length!!\n");
        return 1;
    }

    // Get auth tag from global secrets
    const uint8_t *pExpectedCipherAuthTag;
    res = secrets_get_subscription_cipher_auth_tag(&pExpectedCipherAuthTag);
    if(res != 0){
        // printf("-{E} Failed to Get Subscription Cipher Auth Tag!!\n");
        return res;
    }

    // printf("-{I} Global Secrets Cipher Auth Tag: ");
    // crypto_print_hex(pExpectedCipherAuthTag, SUBSCRIPTION_CIPHER_AUTH_TAG_LEN);

    // printf("-{I} Packet Subscription Cipher Auth Tag: ");
    // crypto_print_hex(pCipherAuthTagCheck->pPacketAuthToken, SUBSCRIPTION_CIPHER_AUTH_TAG_LEN);

    // Compare decrypted auth tag with one in global secrets
    if (memcmp(pExpectedCipherAuthTag, pCipherAuthTagCheck->pPacketAuthToken, SUBSCRIPTION_CIPHER_AUTH_TAG_LEN) != 0){
        // printf("-{E} Decrypted Cipher Auth Tag Does not Match One in Global Secrets!!\n");
        // printf("-FAIL\n");
        return 1;
    }
    // printf("-{I} Expected Cipher Auth Tag Matches Packet Cipher Auth Tag :)\n");
    return 0;
}

static int _processRequest(CryptoManager_Request *pRequest){
    int res;

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
        case CRYPTO_MANAGER_REQ_SIG_CHECK:
            // printf("-{I} Signature Check Request\n");

            // Check request length is good
            if(pRequest->requestLen != sizeof(CryptoManager_SignatureCheck)){
                // printf("-{E} Bad Request Length!!\n");
                return 0;
            }

            // Check signature
            CryptoManager_SignatureCheck *pSigCheck = pRequest->pRequest;
            res = _signatureCheck(pSigCheck);
            break;

        case CRYPTO_MANAGER_REQ_SIG_SIGN:            
            // printf("-{I} Signature Sign Request\n");
            // Check request length is good
            if(pRequest->requestLen != sizeof(CryptoManager_SignatureSign)){
                // printf("-{E} Bad Request Length!!\n");
                return 0;
            }

            // Check signature
            CryptoManager_SignatureSign *pSigSign = pRequest->pRequest;
            res = _signatureSign(pSigSign);
            break;

        case CRYPTO_MANAGER_REQ_DECRYPT:
            // printf("-{I} Decryption Request\n");

            // Check request length is good
            if(pRequest->requestLen != sizeof(CryptoManager_DecryptData)){
                // printf("-{E} Bad Request Length!!\n");
                return 0;
            }

            // Decrypt data
            CryptoManager_DecryptData *pDecrypt = pRequest->pRequest;
            res = _decryptData(pDecrypt);
            break;

        case CRYPTO_MANAGER_REQ_CHECK_SUB_DECRYPTED_AUTH_TOKEN:
            // printf("-{I} Check Decrypted Auth Token Request\n");

            // Check request length is good
            if(pRequest->requestLen != sizeof(CryptoManager_SubDecryptedAuthTokenCheck)){
                // printf("-{E} Bad Request Length!!\n");
                return 0;
            }

            // Check cipher auth tag
            CryptoManager_SubDecryptedAuthTokenCheck *pCipherAuthTag = pRequest->pRequest;
            res = _subCipherAuthTagCheck(pCipherAuthTag);
            break;

        default:
            // printf("-{E} Unknown Request Type!!\n");
            res = 1;
            break;
    }

    return res;
}

//----- Public Functions -----//
void cryptoManager_Init(void){
    secrets_init();

    // Setup request queue
    _xRequestQueue = xQueueCreate(
        RTOS_QUEUE_LENGTH, sizeof(CryptoManager_Request)
    );
}

void cryptoManager_vMainTask(void *pvParameters){
    secrets_init();

    CryptoManager_Request cryptoRequest;

    while (1){
        if (xQueueReceive(_xRequestQueue, &cryptoRequest, portMAX_DELAY) == pdPASS){
            // printf("[CryptoManager] @TASK Received Request\n");
            int res = _processRequest(&cryptoRequest);
            // printf("-COMPLETE\n");

            // Signal the requesting task that request is complete
            xTaskNotify(cryptoRequest.xRequestingTask, res, eSetValueWithOverwrite);
        }
        // vTaskDelay(pdMS_TO_TICKS(10));
        // taskYIELD();
    }
}

int cryptoManager_GetChannelKdfInputKey(const channel_id_t channel, const uint8_t **ppKey){
    return secrets_get_channel_kdf_key(channel, ppKey);
}

int cryptoManager_GetFlashKdfInputKey(const uint8_t **ppKey){
    return secrets_get_flash_kdf_input_key(ppKey);
}

QueueHandle_t cryptoManager_RequestQueue(void){
    return _xRequestQueue;
}

decoder_id_t cryptoManager_DecoderId(void){
    return _decoder_id;
}