/**
 * @file failsafe.h
 * @brief Header for failsafe functions
 */

#ifndef FAILSAFE_H
#define FAILSAFE_H

/**
 * @brief Enter a failsafe state when a critical error occurs
 * 
 * This function turns on the red LED as a visual indicator,
 * disables all interrupts, and enters an infinite loop,
 * effectively halting the system. The system will require
 * a manual reset to recover.
 */
void failsafe(void);

/**
 * @brief Reset the device when a critical error occurs
 * 
 * This function turns on the red LED as a visual indicator,
 * logs an error message, and then resets the device.
 * If reset fails, it will enter failsafe mode.
 * 
 * @param message The error message to print before rebooting
 */
void system_reset(const char *message);

#endif /* FAILSAFE_H */
