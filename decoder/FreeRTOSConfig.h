#ifndef FLINDERS_FREERTOSCONFIG_H_
#define FLINDERS_FREERTOSCONFIG_H_
 
#include <stdint.h>
#include <stdio.h>
#include "max78000.h"
 
// MSDK Debug flags
#if defined(FRTOS_DEBUG) && FRTOS_DEBUG == 1
  #warning "FreeRTOS Debug Build!!"
  
  // RTOS Assert & other debug configuration
  #define configASSERT(x)           \
      if ((x) == 0) {               \
          taskDISABLE_INTERRUPTS(); \
          for (;;) {printf("@ERROR ASSERT!!\n");} \
      }
  #define configRECORD_STACK_HIGH_ADDRESS 1
#endif
 
// Modes
#define configUSE_PREEMPTION                                        1
#define configUSE_PORT_OPTIMISED_TASK_SELECTION                     0
#define configUSE_TICKLESS_IDLE                                     0

// Clocks
#define configCPU_CLOCK_HZ                                          ((uint32_t)IPO_FREQ)
#define configRTC_TICK_RATE_HZ                                      (32768) //Set to realtime clock oscillator
#define configTICK_RATE_HZ                                          ((portTickType)1000) // Improves time resolution

// Diagnostics
#define configUSE_TRACE_FACILITY                                    1
#define configUSE_STATS_FORMATTING_FUNCTIONS                        1

// Scheduler
#define configMAX_PRIORITIES                                        5
#define configMINIMAL_STACK_SIZE                                    ((uint16_t)128)
#define configUSE_16_BIT_TICKS                                      0
#define configIDLE_SHOULD_YIELD                                     0
#define configUSE_MUTEXES                                           1 // Prevent priority inheritance attack
#define configUSE_RECURSIVE_MUTEXES                                 0
#define configUSE_COUNTING_SEMAPHORES                               0
#define configQUEUE_REGISTRY_SIZE                                   10
#define configUSE_QUEUE_SETS                                        0
#define configUSE_TIME_SLICING                                      1 // CHANGED!!
#define configUSE_NEWLIB_REENTRANT                                  0
#define configENABLE_BACKWARD_COMPATIBILITY                         1
#define configNUM_THREAD_LOCAL_STORAGE_POINTERS                     5
#define configUSE_MINI_LIST_ITEM                                    1
#define configSTACK_DEPTH_TYPE                                      uint16_t
#define configMESSAGE_BUFFER_LENGTH_TYPE                            size_t
#define configHEAP_CLEAR_MEMORY_ON_FREE                             1

// Notifications
#define configTASK_NOTIFICATION_ARRAY_ENTRIES                       1
#define configUSE_TASK_NOTIFICATIONS                                1

// Memory allocation
#define configSUPPORT_STATIC_ALLOCATION                             1
#define configSUPPORT_DYNAMIC_ALLOCATION                            1
#define configTOTAL_HEAP_SIZE                                       ((size_t)(64 * 1024))
#define configAPPLICATION_ALLOCATED_HEAP                            1
#define configSTACK_ALLOCATION_FROM_SEPARATE_HEAP                   0

// Hook functions 
#define configUSE_IDLE_HOOK                                 0
#define configUSE_TICK_HOOK                                 0
#define configCHECK_FOR_STACK_OVERFLOW                      2 // Method 3 for detection
#define configUSE_MALLOC_FAILED_HOOK                        1 // Use heap 4
#define configUSE_DAEMON_TASK_STARTUP_HOOK                  1 // Initialisation manager
#define configUSE_SB_COMPLETED_CALLBACK                     0

// Co-routines 
#define configUSE_CO_ROUTINES                               0
#define configMAX_CO_ROUTINE_PRIORITIES                     1 // Not used, but has to be defined.

// Timers
#define configUSE_TIMERS                                    1
#define configTIMER_TASK_PRIORITY                           3
#define configTIMER_QUEUE_LENGTH                            10
#define configTIMER_TASK_STACK_DEPTH                        (configMINIMAL_STACK_SIZE * 10)
 
/* Run time and task stats gathering related definitions. */
#define configUSE_TRACE_FACILITY 1
#define configUSE_STATS_FORMATTING_FUNCTIONS 1
 
// Optional functions - most linkers will remove unused functions anyway.
#define INCLUDE_vTaskPrioritySet                1
#define INCLUDE_uxTaskPriorityGet               1
#define INCLUDE_vTaskDelete                     0
#define INCLUDE_vTaskSuspend                    0
#define INCLUDE_vTaskDelayUntil                 1
#define INCLUDE_vTaskDelay                      1
#define INCLUDE_xTaskGetSchedulerState          1
#define INCLUDE_xTaskGetCurrentTaskHandle       1
#define INCLUDE_uxTaskGetStackHighWaterMark     0
#define INCLUDE_uxTaskGetStackHighWaterMark2    0
#define INCLUDE_xTaskGetIdleTaskHandle          0
#define INCLUDE_eTaskGetState                   0
#define INCLUDE_xTimerPendFunctionCall          0
#define INCLUDE_xTaskAbortDelay                 0
#define INCLUDE_xTaskGetHandle                  0
#define INCLUDE_xTaskResumeFromISR              1
 
/// Necessary MAX78000 definitions ///
 /* # of priority bits (configured in hardware) is provided by CMSIS */
 #define configPRIO_BITS __NVIC_PRIO_BITS
 
 /* Priority 7, or 255 as only the top three bits are implemented.  This is the lowest priority. */
 #define configKERNEL_INTERRUPT_PRIORITY ((unsigned char)7 << (8 - configPRIO_BITS))
 
 /* Priority 5, or 160 as only the top three bits are implemented. */
 #define configMAX_SYSCALL_INTERRUPT_PRIORITY ((unsigned char)5 << (8 - configPRIO_BITS))
 
 /* Alias the default handler names to match CMSIS weak symbols */
 #define vPortSVCHandler SVC_Handler
 #define xPortPendSVHandler PendSV_Handler
 #define xPortSysTickHandler SysTick_Handler
 
 #ifdef configUSE_TICKLESS_IDLE
 /* Provide routines for tickless idle pre- and post- processing */
 void vPreSleepProcessing(uint32_t *);
 void vPostSleepProcessing(uint32_t);
 #define configPRE_SLEEP_PROCESSING(idletime) vPreSleepProcessing(&idletime);
 #define configPOST_SLEEP_PROCESSING(idletime) vPostSleepProcessing(idletime);
 #endif
 
 /* FreeRTOS+CLI requires this size to be defined, but we do not use it */
 #define configCOMMAND_INT_MAX_OUTPUT_SIZE 1



 #endif /* FLINDERS_FREERTOS_CONFIG_H */
