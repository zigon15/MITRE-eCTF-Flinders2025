#include <stdio.h>
#include <stdint.h>
#include "FreeRTOS.h"
#include "task.h"
#include <max78000.h>
#include "board.h"
#include "mxc_device.h"
#include "mxc_delay.h"
#include "uart.h"
#include "lp.h"
#include "led.h"
#include "trng.h"
#include "tmr.h"
#include "failsafe.h"

// Include tasks
#include "crypto_manager.h"
#include "subscription_manager.h"
#include "serial_interface_manager.h"
#include "channel_manager.h"
#include "frame_manager.h"

/* Required for heap_4.c */
uint8_t ucHeap[configTOTAL_HEAP_SIZE];

/* Called if a call to pvPortMalloc() fails */
void vApplicationMallocFailedHook(void)
{
    /* Log the failure */
    char mallocMessage[127] = "Memory allocation failed! System attempting to reset. \n";
    system_reset(mallocMessage);
}

/* Called if stack overflow is detected during context switch */
void vApplicationStackOverflowHook(TaskHandle_t pxTask, char *pcTaskName)
{   
    /* Log the stack overflow */
    char stackMessage[127] = "Stack overflow! System attempting to reset.\n";
    system_reset(stackMessage);
}

/* Called when a daemon task is created */
void vApplicationDaemonTaskStartupHook(void) {
    // Measure boot delay
    mxc_tmr_cfg_t tmr_cfg;
    tmr_cfg.pres = TMR_PRES_1;
    tmr_cfg.mode = TMR_MODE_CONTINUOUS;
    tmr_cfg.cmp_cnt = 0xFFFFFFFF;  // Set to max value
    tmr_cfg.pol = 0;

    // Initialise timer
    MXC_TMR_Init(MXC_TMR0, &tmr_cfg, false);
    MXC_TMR_SetCount(MXC_TMR0, 0);
    MXC_TMR_Start(MXC_TMR0);

    // Security delay on boot
    uint8_t random_value;
    MXC_TRNG_Random(&random_value, sizeof(random_value));
    int base_delay = SystemCoreClock / 40;
    int random_factor = (random_value % 100);
    int delay_cycles = base_delay - (base_delay * random_factor / 1000);  // Calculate final delay (between 80% and 100% of base_delay)

    // Security delay on boot to prevent bruteforce attacks
    for (volatile int i = 0; i < delay_cycles; i++) {
        if (i % (delay_cycles / 10) == 0) {
            printf(".");
        }
    }

    // Stop the timer and get the count
    MXC_TMR_Stop(MXC_TMR0);
    uint32_t timer_count = MXC_TMR_GetCount(MXC_TMR0);

    // Calculate actual delay in milliseconds
    float actual_delay_ms = ((float)timer_count) / ((float)SystemCoreClock);

    // Create a buffer to hold the entire formatted string
    char task_list[1024];
    vTaskList(task_list);

    // Initialize all required tasks
    cryptoManager_Init();
    subscriptionManager_Init();
    serialInterfaceManager_Init();
    channelManager_Init();
    frameManager_Init();

    // Build the message in the buffer using snprintf
    printf(
             "\n\n*************************************************\n"
             "*            Boot Sequence Completed            *\n"
             "*            G'day from Team Flinders           *\n"
             "*          MAX78000 powered by FreeRTOS         *\n"
             "*                     %s                   *\n"
             "*************************************************\n"
             "Tick Rate = %d Hz\n\n"
             "Security delay: %f ms\n\n"
             "FreeRTOS Information:\n"
             "  Total Heap Size: %d bytes\n"
             "  Free Heap: %d bytes\n"
            //  "  Minimum Ever Free Heap: %d bytes\n"
             "  Number of Tasks: %d\n\n",
             tskKERNEL_VERSION_NUMBER,          // Version string
             configTICK_RATE_HZ,                // Tick rate
             actual_delay_ms,                   // Security delay
             configTOTAL_HEAP_SIZE,             // Total heap size
             xPortGetFreeHeapSize(),            // Free heap
            //  xPortGetMinimumEverFreeHeapSize(), // Min free heap
             uxTaskGetNumberOfTasks()           // Number of tasks
    );
    printf(
             "Task Name       State   Prio    Stack   Task#\n"
             "---------------------------------------------\n"
             "%s\n"
             "System initialisation complete!\n\n",
             task_list
    );

    // Indicate successful boot with a green LED
    LED_Init();
    LED_Off(LED_RED);
    LED_On(LED_GREEN);
}

/* Static memory for idle task */
static StaticTask_t xIdleTaskTCB;
static StackType_t uxIdleTaskStack[configMINIMAL_STACK_SIZE];

/* Provide memory for the idle task - required for static allocation */
void vApplicationGetIdleTaskMemory(StaticTask_t **ppxIdleTaskTCBBuffer,
                                   StackType_t **ppxIdleTaskStackBuffer,
                                   uint32_t *pulIdleTaskStackSize)
{
    *ppxIdleTaskTCBBuffer = &xIdleTaskTCB;
    *ppxIdleTaskStackBuffer = uxIdleTaskStack;
    *pulIdleTaskStackSize = configMINIMAL_STACK_SIZE;
}

/* Static memory for timer task */
static StaticTask_t xTimerTaskTCB;
static StackType_t uxTimerTaskStack[configTIMER_TASK_STACK_DEPTH];

/* Provide memory for the timer task - required for static allocation */
void vApplicationGetTimerTaskMemory(StaticTask_t **ppxTimerTaskTCBBuffer,
                                    StackType_t **ppxTimerTaskStackBuffer,
                                    uint32_t *pulTimerTaskStackSize)
{
    *ppxTimerTaskTCBBuffer = &xTimerTaskTCB;
    *ppxTimerTaskStackBuffer = uxTimerTaskStack;
    *pulTimerTaskStackSize = configTIMER_TASK_STACK_DEPTH;
}

/* Note: Idle and Tick hooks are disabled in FreeRTOSConfig.h 
   (configUSE_IDLE_HOOK=0, configUSE_TICK_HOOK=0) */
