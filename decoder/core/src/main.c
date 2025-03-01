#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "FreeRTOS.h"
#include "FreeRTOSConfig.h"
#include "portmacro.h"
#include "task.h"
#include "semphr.h"
#include "mxc_device.h"
#include "wut.h"
#include "uart.h"
#include "lp.h"
#include "led.h"
#include "icc.h"
#include "board.h"
#include "mxc_delay.h"

// Include tasks
#include "crypto_manager.h"
#include "subscription_manager.h"
#include "serial_interface_manager.h"
#include "channel_manager.h"
#include "frame_manager.h"

#include "status_led.h"

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

int main(void){
    // Delay to prevent bricks
    volatile int i;
    for (i = 0; i < 0xFFFFF; i++) {}

    // Enable instruction cache for better performance
    MXC_ICC_Enable(MXC_ICC0);
    
    // Print banner (RTOS scheduler not running)
    // printf("\n-=- %s FreeRTOS (%s) Demo -=-\n", STRING(TARGET), tskKERNEL_VERSION_NUMBER);
    // printf("SystemCoreClock = %d\n", SystemCoreClock);

    //-- Configure Tasks --// 
    int ret;
    
    // Crypto manager task
    cryptoManager_Init();
    ret = xTaskCreate(
        cryptoManager_vMainTask, (const char *)"CryptoManager",
        CRYPTO_MANAGER_STACK_SIZE, NULL,
        tskIDLE_PRIORITY, &crypto_manager_task_id
    );
    if (ret != pdPASS){
        printf("@ERROR xTaskCreate() failed to create CryptoManager.\n");
        while(1);
    }

    // Subscription manager task
    subscriptionManager_Init();
    ret = xTaskCreate(
        subscriptionManager_vMainTask, (const char *)"SubscriptionManager",
        SUBSCRIPTION_MANAGER_STACK_SIZE, NULL,
        tskIDLE_PRIORITY, &subscription_manager_task_id
    );
    if (ret != pdPASS){
        printf("@ERROR xTaskCreate() failed to create SubscriptionManager: %d\n", ret);
        while(1);
    }

    // Serial interface manager task
    serialInterfaceManager_Init();
    ret = xTaskCreate(
        serialInterfaceManager_vMainTask, (const char *)"SerialInterfaceManager",
        SERIAL_INTERFACE_MANAGER_STACK_SIZE, NULL,
        tskIDLE_PRIORITY+1, &serial_interface_manager_task_id
    );
    if (ret != pdPASS){
        printf("@ERROR xTaskCreate() failed to create SerialInterfaceManager: %d\n", ret);
        while(1);
    }
    serialInterfaceManager_SetTaskId(serial_interface_manager_task_id);

    // Channel manager task
    channelManager_Init();
    ret = xTaskCreate(
        channelManager_vMainTask, (const char *)"ChannelManager",
        CHANNEL_MANAGER_STACK_SIZE, NULL,
        tskIDLE_PRIORITY, &channel_manager_task_id
    );
    if (ret != pdPASS){
        printf("@ERROR xTaskCreate() failed to create ChannelManager: %d\n", ret);
        while(1);
    }

    // Frame manager task
    frameManager_Init();
    ret = xTaskCreate(
        frameManager_vMainTask, (const char *)"FrameManager",
        FRAME_MANAGER_STACK_SIZE, NULL,
        tskIDLE_PRIORITY, &frame_manager_task_id
    );
    if (ret != pdPASS){
        printf("@ERROR xTaskCreate() failed to create FrameManager: %d\n", ret);
        while(1);
    }

    // Start scheduler
    // printf("Starting scheduler.\n");
    vTaskStartScheduler();

    // This code is only reached if the scheduler failed to start
    printf("ERROR: FreeRTOS did not start due to above error!\n");
    while (1) {
        __NOP();
    }

    return -1;
}
