/**
 * @file main.c
 * @author Simon Rosenzweig
 * @brief This source file sets up the FreeRTOS tasks. It also has some GCC security hooks.
 * @date 2025
 *
 * @copyright Copyright (c) 2025 The MITRE Corporation
 */

// C inclusions
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// FreeRTOS inclusions
#include "FreeRTOS.h"
#include "FreeRTOSConfig.h"
#include "portmacro.h"
#include "task.h"
#include "semphr.h"

// MAX78000 inclusions
#include <max78000.h>
#include "board.h"
#include "mxc_device.h"
#include "uart.h"
#include "lp.h"
#include "led.h"
#include "trng.h"
#include "tmr.h"
#include "wut.h"
#include "icc.h"
#include "mxc_delay.h"

// MITRE inclusions
#include "status_led.h"
#include "simple_uart.h"
#include "simple_flash.h"

// Include tasks
#include "crypto_manager.h"
#include "subscription_manager.h"
#include "serial_interface_manager.h"
#include "channel_manager.h"
#include "frame_manager.h"
#include "security_test.h"
#include "failsafe.h"

/* =================================================================
Configuration items 
================================================================= */
/* Explicitly disable tickless mode */
unsigned int disable_tickless = 1;

/* Stringification macros */
#define STRING(x) STRING_(x)
#define STRING_(x) #x

/* =================================================================
Task Setup 
================================================================= */
/* Task IDs */
TaskHandle_t crypto_manager_task_id;
TaskHandle_t subscription_manager_task_id;
TaskHandle_t serial_interface_manager_task_id;
TaskHandle_t channel_manager_task_id;
TaskHandle_t frame_manager_task_id;

/** @brief Called if stack smashing is detected
 *
*/
__attribute__((noreturn)) void __wrap___stack_chk_fail(void) {
    STATUS_LED_RED();
    printf("Stack Smashing Detected :(\n");
    printf("Reseting :(\n");

    // Wait for serial to flush then reset
    MXC_Delay(1000000);
    NVIC_SystemReset();
    while(1);
}

/** @brief Called by default fortify failure handler if buffer overflow is detected
 *
*/
__attribute__((noreturn)) void __wrap___chk_fail(void) {
    STATUS_LED_RED();
    printf("Buffer Overflow (I think?!?!) [https://github.dev/lattera/glibc/blob/master/debug/chk_fail.c]\n");
    printf("Reseting :(\n");

    // Wait for serial to flush then reset
    MXC_Delay(1000000);
    NVIC_SystemReset();
    while(1);
}

/** @brief Used to ensure there are context switches to check stack overflows
 * 
 * @param pvParameters FreeRTOS task parameters
 */
void contextSwitch_vMainTask(void *pvParameters){
    while (1){
        vTaskDelay(pdMS_TO_TICKS(1));
    }
}

/* =| main |==============================================
 * =====================================================*/
int main(void){
    int ret;

    Board_Init();
    LED_Init();
    
    // Enable instruction cache for better performance
    MXC_ICC_Enable(MXC_ICC0);

    // Initialize true random number generator for 
    // - delay timer
    // - channel manager
    MXC_TRNG_Init();

    printf("Creating tasks...\n");
    /* 
     * IMPORTANT: These tasks are for testing purposes only!
     */
    
    /* Stack Overflow Test Task - uncomment to test */
    // stackOverflowTask_Init();
    // ret = xTaskCreate(
    //     stackOverflowTask_vMainTask, "StackTest", STACK_OVERFLOW_TASK_STACK_SIZE,
    //     NULL, tskIDLE_PRIORITY+1, NULL
    // );
    // if (ret != pdPASS) {
    //     printf("xTaskCreate() failed to create Stack Test task.\n");
    //     while(1);
    // }
    
    ret = xTaskCreate(
        contextSwitch_vMainTask, "ContextSwitch", configMINIMAL_STACK_SIZE,
        NULL, tskIDLE_PRIORITY+5, NULL
    );
    if (ret != pdPASS) {
        printf("xTaskCreate() failed to create Context Switch task.\n");
        while(1);
    }

    /* eCTF Tasks */
    //-- Configure Tasks --// 
    
    // Crypto Manager task
    ret = xTaskCreate(
        cryptoManager_vMainTask, (const char *)"CryptoManager",
        CRYPTO_MANAGER_STACK_SIZE, NULL,
        tskIDLE_PRIORITY, &crypto_manager_task_id
    );
    if (ret != pdPASS){
        printf("@ERROR xTaskCreate() failed to create CryptoManager.\n");
        while(1);
    }

    // Subscription Manager task
    ret = xTaskCreate(
        subscriptionManager_vMainTask, (const char *)"SubscriptionManager",
        SUBSCRIPTION_MANAGER_STACK_SIZE, NULL,
        tskIDLE_PRIORITY, &subscription_manager_task_id
    );
    if (ret != pdPASS){
        printf("@ERROR xTaskCreate() failed to create SubscriptionManager: %d\n", ret);
        while(1);
    }

    // Serial Interface Manager task
    ret = xTaskCreate(
        serialInterfaceManager_vMainTask, (const char *)"SerialInterfaceManager",
        SERIAL_INTERFACE_MANAGER_STACK_SIZE, NULL,
        tskIDLE_PRIORITY+1, &serial_interface_manager_task_id
    );
    if (ret != pdPASS){
        printf("@ERROR xTaskCreate() failed to create SerialInterfaceManager: %d\n", ret);
        while(1);
    }

    // Channel Manager task
    ret = xTaskCreate(
        channelManager_vMainTask, (const char *)"ChannelManager",
        CHANNEL_MANAGER_STACK_SIZE, NULL,
        tskIDLE_PRIORITY, &channel_manager_task_id
    );
    if (ret != pdPASS){
        printf("@ERROR xTaskCreate() failed to create ChannelManager: %d\n", ret);
        while(1);
    }

    // Frame Manager task
    ret = xTaskCreate(
        frameManager_vMainTask, (const char *)"FrameManager",
        FRAME_MANAGER_STACK_SIZE, NULL,
        tskIDLE_PRIORITY, &frame_manager_task_id
    );
    if (ret != pdPASS){
        printf("@ERROR xTaskCreate() failed to create FrameManager: %d\n", ret);
        while(1);
    }

    /* Start scheduler */
    printf("Starting scheduler...\n\n");
    vTaskStartScheduler();

    /* This code is only reached if the scheduler failed to start */
    printf("FreeRTOS scheduler failed to start! Activating failsafe...\n");
    failsafe();
    
    return -1;
}