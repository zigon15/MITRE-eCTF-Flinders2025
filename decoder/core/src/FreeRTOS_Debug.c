/******************************************************************************
 *
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
 * @file        FreeRTOS_Debug.c
 * @brief       FreeRTOS Debug utilities including RTOS Stats Timer 
 *              and template HardFault Handler
 */

#include "FreeRTOS.h"
#include "task.h"
#include "tmr.h"
#include "nvic_table.h"

// Only include the contents of this file if FRTOS_DEBUG == 1
#if defined(FRTOS_DEBUG) && (FRTOS_DEBUG == 1)

#warning "FreeRTOS Debug Build!!"

// void prvGetRegistersFromStack(uint32_t *pulFaultStackAddress)
// {
//     /* These are volatile to try and prevent the compiler/linker optimising them
//     away as the variables never actually get used.  If the debugger won't show the
//     values of the variables, make them global my moving their declaration outside
//     of this function. */
//     volatile uint32_t r0;
//     volatile uint32_t r1;
//     volatile uint32_t r2;
//     volatile uint32_t r3;
//     volatile uint32_t r12;
//     volatile uint32_t lr; /* Link register. */
//     volatile uint32_t pc; /* Program counter. */
//     volatile uint32_t psr; /* Program status register. */

//     r0 = pulFaultStackAddress[0];
//     r1 = pulFaultStackAddress[1];
//     r2 = pulFaultStackAddress[2];
//     r3 = pulFaultStackAddress[3];

//     r12 = pulFaultStackAddress[4];
//     lr = pulFaultStackAddress[5];
//     pc = pulFaultStackAddress[6];
//     psr = pulFaultStackAddress[7];

//     /* When the following line is hit, the variables contain the register values. */
//     for (;;) {}
// }

// void vApplicationStackOverflowHook(TaskHandle_t xTask, signed char *pcTaskName)
// {
//     for (;;) {}
// }

/* The prototype shows it is a naked function - in effect this is just an
assembly function. */
// void HardFault_Handler(void) __attribute__((naked, aligned(8)));

/* The fault handler implementation calls a function called
prvGetRegistersFromStack(). */
// void HardFault_Handler(void)
// {
//     __asm volatile(" tst lr, #4                                                \n"
//                    " ite eq                                                    \n"
//                    " mrseq r0, msp                                             \n"
//                    " mrsne r0, psp                                             \n"
//                    " ldr r1, [r0, #24]                                         \n"
//                    " ldr r2, handler2_address_const                            \n"
//                    " bx r2                                                     \n"
//                    " handler2_address_const: .word prvGetRegistersFromStack    \n");
// }
#endif
