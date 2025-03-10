/**
 * @file failsafe.h
 * @brief Failsafe functions for critical system errors
 */

#include <stdio.h>
#include "FreeRTOS.h"
#include "task.h"
#include "led.h"
#include "status_led.h"
#include "failsafe.h"
#include <wdt.h>

/**
 * @brief Enter a failsafe state when a critical error occurs
 * 
 * This function turns on the red LED as a visual indicator,
 * disables all interrupts, and enters an infinite loop,
 * effectively halting the system. The system will require
 * a manual reset to recover. Last resort to prevent tampering.
 */

void failsafe(void)
{
    /* Disable all interrupts at the processor level and stop scheduler */
    __disable_irq();
    taskDISABLE_INTERRUPTS();

    printf("System failsafe is now engaged. Please manually reboot the device.");

    /* Do nothing, uninterrupted, until heat death of universe */
    while (1) {
        __NOP();
    }

}

/**
 * @brief Reset the device when a critical error occurs
 * 
 * This function turns on the red LED as a visual indicator,
 * logs an error message, and then resets the device.
 * If reset fails, enter failsafe mode.
 * 
 * @param message The error message to print before rebooting
 */
void system_reset(const char *message)
{
    /* Visual indication - set red LED on */
    STATUS_LED_ERROR();

    /* Log the error message */
    if (message != NULL) {
        printf("[FATAL] %s\n", message);
        printf("System rebooting in 5 seconds...\n");
    }
    vTaskDelay(pdMS_TO_TICKS(5000));

    /* Try to reset gracefully */
    NVIC_SystemReset();
    
    /* If reset fails, enter failsafe mode */
    failsafe();
}