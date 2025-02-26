/******************************************************************************
 *
 * Copyright (C) 2022-2023 Maxim Integrated Products, Inc. (now owned by 
 * Analog Devices, Inc.),
 * Copyright (C) 2023-2024 Analog Devices, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 ******************************************************************************/

/**
 * @file        main.c
 * @brief       FreeRTOS Example Application.
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "FreeRTOS.h"
#include "FreeRTOSConfig.h"
#include "portmacro.h"
#include "task.h"
#include "semphr.h"
#include "FreeRTOS_CLI.h"
#include "mxc_device.h"
#include "wut.h"
#include "uart.h"
#include "lp.h"
#include "led.h"
#include "board.h"

// Include tasks
#include "crypto_manager.h"
#include "subscription_manager.h"
#include "flash_manager.h"
#include "serial_interface_manager.h"

/* FreeRTOS+CLI */
void vRegisterCLICommands(void);

/* Task IDs */
TaskHandle_t cmd_task_id;
TaskHandle_t crypto_manager_task_id;
TaskHandle_t subscription_manager_task_id;

/* Stringification macros */
#define STRING(x) STRING_(x)
#define STRING_(x) #x

/* Console ISR selection */
#define UARTx_IRQHandler UART0_IRQHandler
#define UARTx_IRQn UART0_IRQn
mxc_uart_regs_t *ConsoleUART = MXC_UART_GET_UART(CONSOLE_UART);

/* Array sizes */
#define CMD_LINE_BUF_SIZE 80
#define OUTPUT_BUF_SIZE 512

/***** Functions *****/

void UARTx_IRQHandler(void){
    MXC_UART_AsyncHandler(ConsoleUART);
}

/* =| vCmdLineTask_cb |======================================
 *
 * Callback on asynchronous reads to wake the waiting command
 *  processor task
 *
 * ===========================================================
 */
void vCmdLineTask_cb(mxc_uart_req_t *req, int error){
    BaseType_t xHigherPriorityTaskWoken;

    /* Wake the task */
    xHigherPriorityTaskWoken = pdFALSE;
    vTaskNotifyGiveFromISR(cmd_task_id, &xHigherPriorityTaskWoken);
    portYIELD_FROM_ISR(xHigherPriorityTaskWoken);
}

/* =| vCmdLineTask |======================================
 *
 * The command line task provides a prompt on the serial
 *  interface and takes input from the user to evaluate
 *  via the FreeRTOS+CLI parser.
 *
 * NOTE: FreeRTOS+CLI is part of FreeRTOS+ and has
 *  different licensing requirements. Please see
 *  http://www.freertos.org/FreeRTOS-Plus for more information
 *
 * =======================================================
 */
void vCmdLineTask(void *pvParameters){
    unsigned char tmp;
    unsigned int index; /* Index into buffer */
    unsigned int x;
    int uartReadLen;
    char buffer[CMD_LINE_BUF_SIZE]; /* Buffer for input */
    char output[OUTPUT_BUF_SIZE]; /* Buffer for output */
    BaseType_t xMore;
    mxc_uart_req_t async_read_req;

    memset(buffer, 0, CMD_LINE_BUF_SIZE);
    index = 0;

    /* Register available CLI commands */
    vRegisterCLICommands();

    /* Enable UARTx interrupt */
    NVIC_ClearPendingIRQ(UARTx_IRQn);
    NVIC_DisableIRQ(UARTx_IRQn);
    NVIC_SetPriority(UARTx_IRQn, 5);
    NVIC_EnableIRQ(UARTx_IRQn);

    /* Async read will be used to wake process */
    async_read_req.uart = ConsoleUART;
    async_read_req.rxData = &tmp;
    async_read_req.rxLen = 1;
    async_read_req.txData = NULL;
    async_read_req.txLen = 0;
    async_read_req.callback = vCmdLineTask_cb;

    printf("\nEnter 'help' to view a list of available commands.\n");
    printf("cmd> ");
    fflush(stdout);
    while (1) {
        /* Register async read request */
        if (MXC_UART_TransactionAsync(&async_read_req) != E_NO_ERROR) {
            printf("Error registering async request. Command line unavailable.\n");
            vTaskDelay(portMAX_DELAY);
        }
        /* Hang here until ISR wakes us for a character */
        ulTaskNotifyTake(pdTRUE, portMAX_DELAY);
        /* Check that we have a valid character */
        if (async_read_req.rxCnt > 0) {
            /* Process character */
            do {
                if (tmp == 0x08) {
                    /* Backspace */
                    if (index > 0) {
                        index--;
                        printf("\x08 \x08");
                    }
                    fflush(stdout);
                } else if (tmp == 0x03) {
                    /* ^C abort */
                    index = 0;
                    printf("^C");
                    printf("\ncmd> ");
                    fflush(stdout);
                } else if ((tmp == '\r') || (tmp == '\n')) {
                    printf("\r\n");
                    /* Null terminate for safety */
                    buffer[index] = 0x00;
                    /* Evaluate */
                    do {
                        xMore = FreeRTOS_CLIProcessCommand(buffer, output, OUTPUT_BUF_SIZE);
                        /* If xMore == pdTRUE, then output buffer contains no null termination, so
             *  we know it is OUTPUT_BUF_SIZE. If pdFALSE, we can use strlen.
             */
                        for (x = 0; x < (xMore == pdTRUE ? OUTPUT_BUF_SIZE : strlen(output)); x++) {
                            putchar(*(output + x));
                        }
                    } while (xMore != pdFALSE);
                    /* New prompt */
                    index = 0;
                    printf("\ncmd> ");
                    fflush(stdout);
                } else if (index < CMD_LINE_BUF_SIZE) {
                    putchar(tmp);
                    buffer[index++] = tmp;
                    fflush(stdout);
                } else {
                    /* Throw away data and beep terminal */
                    putchar(0x07);
                    fflush(stdout);
                }
                uartReadLen = 1;
                /* If more characters are ready, process them here */
            } while ((MXC_UART_GetRXFIFOAvailable(MXC_UART_GET_UART(CONSOLE_UART)) > 0) &&
                     (MXC_UART_Read(ConsoleUART, (uint8_t *)&tmp, &uartReadLen) == 0));
        }
    }
}

int main(void){
    // Delay to prevent bricks
    volatile int i;
    for (i = 0; i < 0xFFFFFF; i++) {}

    // Print banner (RTOS scheduler not running)
    printf("\n-=- %s FreeRTOS (%s) Demo -=-\n", STRING(TARGET), tskKERNEL_VERSION_NUMBER);
    printf("SystemCoreClock = %d\n", SystemCoreClock);

    //-- Configure Tasks --// 
    int ret;

    // Command line task
    ret = xTaskCreate(
        vCmdLineTask, (const char *)"CmdLineTask",
        configMINIMAL_STACK_SIZE + CMD_LINE_BUF_SIZE + OUTPUT_BUF_SIZE, NULL,
        tskIDLE_PRIORITY + 2, &cmd_task_id
    );
    if (ret != pdPASS){
        printf("@ERROR xTaskCreate() failed to create CmdLineTask.\n");
        while(1);
    }
    
    // Crypto manager task
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
    ret = xTaskCreate(
        subscriptionManager_vMainTask, (const char *)"SubscriptionManager",
        SUBSCRIPTION_MANAGER_STACK_SIZE, NULL,
        tskIDLE_PRIORITY, &subscription_manager_task_id
    );
    if (ret != pdPASS){
        printf("@ERROR xTaskCreate() failed to create SubscriptionManager: %d\n", ret);
        while(1);
    }

    // Flash manager task
    ret = xTaskCreate(
        flashManager_vMainTask, (const char *)"FlashManager",
        FLASH_MANAGER_STACK_SIZE, NULL,
        tskIDLE_PRIORITY, &subscription_manager_task_id
    );
    if (ret != pdPASS){
        printf("@ERROR xTaskCreate() failed to create FlashManager: %d\n", ret);
        while(1);
    }

    // Serial interface manager task
    ret = xTaskCreate(
        serialInterfaceManager_vMainTask, (const char *)"SerialInterfaceManager",
        SERIAL_INTERFACE_MANAGER_STACK_SIZE, NULL,
        tskIDLE_PRIORITY, &subscription_manager_task_id
    );
    if (ret != pdPASS){
        printf("@ERROR xTaskCreate() failed to create SerialInterfaceManager: %d\n", ret);
        while(1);
    }

    // Start scheduler
    printf("Starting scheduler.\n");
    vTaskStartScheduler();

    // This code is only reached if the scheduler failed to start
    printf("ERROR: FreeRTOS did not start due to above error!\n");
    while (1) {
        __NOP();
    }

    return -1;
}
