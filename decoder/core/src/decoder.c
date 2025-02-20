/**
 * @file    decoder.c
 * @author  Samuel Meyers, Simon Rosenzweig
 * @brief   Flinders eCTF Decoder Implementation
 * @date    2025
 *
 * This source file is part of an example system for MITRE's 2025 Embedded System CTF (eCTF).
 * This code is being provided only for educational purposes for the 2025 MITRE eCTF competition,
 * and may not meet MITRE standards for quality. Use this code at your own risk!
 *
 * @copyright Copyright (c) 2025 The MITRE Corporation
 */

/*********************** INCLUDES *************************/
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#include "decoder.h"
#include "mxc_device.h"
#include "status_led.h"
#include "board.h"
#include "mxc_delay.h"
#include "simple_flash.h"
#include "host_messaging.h"

#include "simple_uart.h"
#include "crypto.h"
#include "subscription.h"
#include "frame.h"


#include "crypto_test.h"

/**********************************************************
 *********************** CONSTANTS ************************
 **********************************************************/
// This is a canary value so we can confirm whether this decoder has booted before
#define FLASH_FIRST_BOOT 0xDEADBEEF

/**********************************************************
 *********** COMMUNICATION PACKET DEFINITIONS *************
 **********************************************************/

// Tells the compiler not to pad the struct members
// for more information on what struct padding does, see:
// https://www.gnu.org/software/c-intro-and-ref/manual/html_node/Structure-Layout.html
#pragma pack(push, 1) 

typedef struct {
    channel_id_t channel;
    timestamp_t start;
    timestamp_t end;
} channel_info_t;

typedef struct {
    uint32_t n_channels;
    channel_info_t channel_info[MAX_CHANNEL_COUNT];
} list_response_t;

// Tells the compiler to resume padding struct members
#pragma pack(pop)

/**********************************************************
 ************************ GLOBALS *************************
 **********************************************************/

// This is used to track decoder subscriptions
flash_entry_t decoder_status;

/**********************************************************
 ********************* CORE FUNCTIONS *********************
 **********************************************************/

/** @brief Called if stack smashing is detected
 *
*/
__attribute__((noreturn)) void __wrap___stack_chk_fail(void) {
    printf("Stack Smashing Detected :(\n");
    printf("Reseting :(\n");

    // Wait for serial to flush then reset
    MXC_Delay(1000000);
    NVIC_SystemReset();
    while(1);
}

// Override the default fortify failure handler
__attribute__((noreturn)) void __wrap___chk_fail() {
    printf("Buffer Overflow (I think?!?!) [https://github.dev/lattera/glibc/blob/master/debug/chk_fail.c]\n");
    printf("Reseting :(\n");

    // Wait for serial to flush then reset
    MXC_Delay(1000000);
    NVIC_SystemReset();
    while(1);
}

/** @brief Lists out the actively subscribed channels over UART.
 *
 *  @return 0 if successful.
*/
int list_channels(void) {
    list_response_t resp;
    pkt_len_t len;

    resp.n_channels = 0;

    for (uint32_t i = 0; i < MAX_CHANNEL_COUNT; i++) {
        if (decoder_status.subscribed_channels[i].active) {
            resp.channel_info[resp.n_channels].channel =  decoder_status.subscribed_channels[i].id;
            resp.channel_info[resp.n_channels].start = decoder_status.subscribed_channels[i].start_timestamp;
            resp.channel_info[resp.n_channels].end = decoder_status.subscribed_channels[i].end_timestamp;
            resp.n_channels++;
        }
    }

    len = sizeof(resp.n_channels) + (sizeof(channel_info_t) * resp.n_channels);

    // Success message
    host_write_packet(LIST_MSG, &resp, len);
    return 0;
}

/** @brief Initializes peripherals for system boot.
*/
void init(void) {
    int ret;

    // Initialize the flash peripheral to enable access to persistent memory
    flash_simple_init();

    // Read starting flash values into our flash status struct
    flash_simple_read(FLASH_STATUS_ADDR, &decoder_status, sizeof(flash_entry_t));
    if (decoder_status.first_boot != FLASH_FIRST_BOOT) {
        /* If this is the first boot of this decoder, mark all channels as unsubscribed.
        *  This data will be persistent across reboots of the decoder. Whenever the decoder
        *  processes a subscription update, this data will be updated.
        */
        host_print_debug("First boot.  Setting flash...\n");

        decoder_status.first_boot = FLASH_FIRST_BOOT;

        channel_status_t subscription[MAX_CHANNEL_COUNT];

        for (int i = 0; i < MAX_CHANNEL_COUNT; i++){
            subscription[i].start_timestamp = DEFAULT_CHANNEL_TIMESTAMP;
            subscription[i].end_timestamp = DEFAULT_CHANNEL_TIMESTAMP;
            subscription[i].active = false;
        }

        // Write the starting channel subscriptions into flash.
        memcpy(decoder_status.subscribed_channels, subscription, MAX_CHANNEL_COUNT*sizeof(channel_status_t));

        flash_simple_erase_page(FLASH_STATUS_ADDR);
        flash_simple_write(FLASH_STATUS_ADDR, &decoder_status, sizeof(flash_entry_t));
    }

    // Initialize the uart peripheral to enable serial I/O
    ret = uart_init();
    if (ret < 0) {
        STATUS_LED_ERROR();
        
        // If uart fails to initialize, do not continue to execute
        while (1);
    }

    // Initialize crypto to enable cryptographic operations
    ret = crypto_init();
    if(ret != 0){
        STATUS_LED_ERROR();

        // If crypto fails to initialize, do not continue to execute
        while(1);
    }

    ret = secrets_init();
    if(ret != 0){
        STATUS_LED_ERROR();

        // If globals secrets fails to initialize, do not continue to execute
        while(1);
    }
}

void test_crypto(void){
    // Run crypto tests
    if(crypto_test_AES_ECB() != 0){
        printf("@ERROR crypto_test_AES_ECB failed!!\n\n");
    }

    if(crypto_test_AES_CTR() != 0){
        printf("@ERROR crypto_test_AES_CTR failed!!\n\n");
    }

    if(crypto_test_CMAC() != 0){
        printf("@ERROR crypto_test_CMAC failed!!\n\n");
    }
}

void vulnerableFunction(const char *input) {
    char buffer[16];
    // This unsafe call will overflow 'buffer' if 'input' is too long.
    strcpy(buffer, input);
    printf("Buffer: %s\n", buffer);
}

/**********************************************************
 *********************** MAIN LOOP ************************
 **********************************************************/
int main(void) {
    // TODO: Check these buffers are the right length!!
    char output_buf[256] = {0};
    uint8_t uart_buf[256];
    msg_type_t cmd;
    int result;
    uint16_t pkt_len;

    // Initialize the device
    init();

    const char *longInput = "AAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    vulnerableFunction(longInput);

    // test_crypto();
    // while(1);
    
//     print_active_channels();
//     unsigned char subscription_update_buff[] = {
// 0x01, 0x00, 0x00, 0x00, 0x14, 0xC0, 0xEA, 0xAC, 
// 0x7F, 0x4E, 0x24, 0x3E, 0x2B, 0x98, 0xAC, 0xA8, 
// 0x7D, 0xC7, 0x78, 0xAB, 0x74, 0x2D, 0x1D, 0x68, 
// 0xF8, 0xC7, 0x10, 0xE3, 0x33, 0xF5, 0xF8, 0xFC, 
// 0x77, 0xC1, 0xE1, 0x11, 0x81, 0x2A, 0x56, 0xA1, 
// 0xA9, 0x3C, 0x68, 0xA5, 0x11, 0xCF, 0x4E, 0x8B, 
// 0x67, 0x71, 0xBF, 0x5F, 0x81, 0x28, 0xBA, 0x99, 
// 0xA4, 0xCA, 0xDE, 0x74, 0x4D, 0xEC, 0xF2, 0x35
//     };
//     subscription_update(sizeof(subscription_update_buff), subscription_update_buff);
//     print_active_channels();

    // unsigned char frame_buff[] = {
    //     0x01, 0x00, 0x00, 0x00, 0xE7, 0xB9, 0x02, 0xFD, 
    //     0x2C, 0x3B, 0x59, 0x0D, 0x54, 0xB2, 0x25, 0x47, 
    //     0x64, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
    //     0x0F, 0x43, 0xEB, 0x34, 0x87, 0xFF, 0xEF, 0x8E, 
    //     0xB4, 0xC8, 0xEE, 0x35, 0x88, 0xEC, 0xA4, 0xA8, 
    //     0xDC, 0x55, 0x43, 0xF7, 0x02, 0xD4, 0xFD, 0x98, 
    //     0xD2, 0x04, 0xCE, 0xAB, 0x13, 0xB6, 0x76, 0x1A, 
    //     0xF0
    // };
    // frame_decode(sizeof(frame_buff), frame_buff);
    // frame_decode(sizeof(frame_buff), frame_buff);

    // printf("@INFO Decoder ID: 0x%08X\n", DECODER_ID);

    host_print_debug("Decoder Booted!\n");

    // Process commands forever
    while (1) {
        host_print_debug("Ready\n");

        STATUS_LED_GREEN();

        result = host_read_packet(&cmd, uart_buf, &pkt_len);

        if (result < 0) {
            STATUS_LED_ERROR();
            host_print_error("Failed to receive cmd from host\n");
            continue;
        }

        // Handle the requested command
        switch (cmd) {

        // Handle list command
        case LIST_MSG:
            STATUS_LED_CYAN();
            list_channels();
            break;

        // Handle decode command
        case DECODE_MSG:
            STATUS_LED_PURPLE();
            frame_decode(pkt_len, uart_buf);
            break;

        // Handle subscribe command
        case SUBSCRIBE_MSG:
            STATUS_LED_YELLOW();
            subscription_update(pkt_len, uart_buf);
            break;

        // Handle bad command
        default:
            STATUS_LED_ERROR();
            sprintf(output_buf, "Invalid Command: %c\n", cmd);
            host_print_error(output_buf);
            break;
        }
    }
}
