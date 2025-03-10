/**
 * @file security_test.c
 * @brief Test tasks to demonstrate FreeRTOS failure hooks
 */

#include <stdio.h>
#include <string.h>

// FreeRTOS includes
#include "FreeRTOS.h"
#include "task.h"
#include "semphr.h"

// MAX78000 includes
#include "board.h"
#include "led.h"
#include "pb.h"

// Project includes
#include "security_test.h"

/**
 * @brief Initialize the stack overflow test task
 */
void stackOverflowTask_Init(void) {
    printf("[Stack Test] Task initialising...\n");
}

/**
 * @brief Test task that causes a stack overflow
 * @details This task intentionally causes a stack overflow by creating
 * a large local array and using infinite recursion
 */
void stackOverflowTask_vMainTask(void *pvParameters) {
    printf("[Stack Test] Task started. This will cause a stack overflow...\n");

    // Function to cause a stack overflow through recursion
    void recursiveFunction(int depth) {
        // Large local array to consume stack
        char largeArray[64];
        
        // Fill the array to prevent optimization
        memset(largeArray, 0xAA, sizeof(largeArray));
        
        // Print depth occasionally to show progress
        if (depth % 5 == 0) {
            printf("[Stack Test] Recursion depth: %d\n", depth);
        }
        
        // Recurse infinitely, consuming more stack each time
        recursiveFunction(depth + 1);
    }
    
    // Start the recursive function
    printf("[Stack Test] Starting infinite recursion...\n");
    recursiveFunction(1);

    // This point should never be reached
    printf("[Stack Test] Task ending (this should never be printed)\n");
}

/**
 * @brief Initialise the malloc failure test task
 */
void mallocFailTask_Init(void) {
    printf("[Stack Test] Task initialising...\n");
}

/**
 * @brief Test task that causes malloc failure
 * @details This task intentionally causes a malloc failure by
 * recursively filling the heap with chunks.
 */
void mallocFailTask_vMainTask(void *pvParameters) {
    printf("[Malloc Test] Task started. This will exhaust the heap...\n");
    
    // Use a more careful approach to exhaust the heap
    int allocCount = 0;
    size_t chunkSize = 512; // Smaller chunks
    size_t totalAllocated = 0;
    void *ptr = NULL;
    
    printf("[Malloc Test] Initial free heap: %d bytes\n", xPortGetFreeHeapSize());
    
    // Allocate just enough to leave a small amount of heap space
    size_t targetHeapSpace = 128; // Leave 128 bytes free
    size_t currentFreeHeap = xPortGetFreeHeapSize();
    
    while (currentFreeHeap > (targetHeapSpace + chunkSize)) {
        // Try to allocate a chunk of memory
        ptr = pvPortMalloc(chunkSize);
        
        if (ptr == NULL) {
            break; // Stop if allocation fails
        }
        
        // Fill the memory to ensure it's not optimized away (just first byte is enough)
        *((volatile uint8_t*)ptr) = 0xBB;
        
        allocCount++;
        totalAllocated += chunkSize;
        currentFreeHeap = xPortGetFreeHeapSize();
        
        // Print progress less frequently
        if (allocCount % 10 == 0) {
            printf("[Malloc Test] Allocated %d bytes, free heap: %d bytes\n", 
                   totalAllocated, currentFreeHeap);
        }
    }
    
    printf("[Malloc Test] Heap nearly exhausted after %d allocations\n", allocCount);
    printf("[Malloc Test] Final free heap: %d bytes\n", xPortGetFreeHeapSize());
    
    // Now deliberately trigger the malloc failed hook with a request larger than remaining heap
    printf("[Malloc Test] Triggering MallocFailedHook...\n");
    volatile void *finalPtr = pvPortMalloc(currentFreeHeap + 10);
    (void)finalPtr;
    
    // This point should never be reached
    printf("[Malloc Test] Task ending (this should never be printed)\n");
    
    // Loop forever - should never get here
    while (1) {
        __NOP();
    }
}
