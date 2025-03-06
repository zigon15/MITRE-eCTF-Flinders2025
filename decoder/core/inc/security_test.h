/**
 * @file security_test.h
 * @brief Security tasks to demonstrate FreeRTOS failure hooks
 */

#ifndef TEST_TASKS_H
#define TEST_TASKS_H

#include "FreeRTOS.h"
#include "task.h"

// Task stack sizes
#define STACK_OVERFLOW_TASK_STACK_SIZE 128  // Small stack to cause overflow
#define MALLOC_FAIL_TASK_STACK_SIZE    512   // Regular stack size

// Function prototypes
void stackOverflowTask_Init(void);
void stackOverflowTask_vMainTask(void *pvParameters);

void mallocFailTask_Init(void);
void mallocFailTask_vMainTask(void *pvParameters);

#endif // SECURITY_TEST_H
