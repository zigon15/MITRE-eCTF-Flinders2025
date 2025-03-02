/**
 * @file serial_interface_manager.h
 * @author Simon Rosenzweig
 * @brief The Serial Interface Manager handles dispatching incoming serial
 *        commands to the correct task
 * 
 * @date 2025
 *
 * @copyright Copyright (c) 2025 The MITRE Corporation
 */

#ifndef SERIAL_INTERFACE_MANAGER_H
#define SERIAL_INTERFACE_MANAGER_H

#include "FreeRTOS.h"
#include "task.h"
#include "queue.h"

//----- Public Constants -----//

// FreeRTOS stack size for Serial Interface Manager
#define SERIAL_INTERFACE_MANAGER_STACK_SIZE 2048


//----- Public Functions -----//

/** @brief Initializes the Serial Interface Manager ready for the main task to be run
 * 
 * @note Must be called before RTOS scheduler starts!!
 */
void serialInterfaceManager_Init(void);

/** @brief Serial Interface Manager main RTOS task
 * 
 * @param pvParameters FreeRTOS task parameters
 */
void serialInterfaceManager_vMainTask(void *pvParameters);

#endif
