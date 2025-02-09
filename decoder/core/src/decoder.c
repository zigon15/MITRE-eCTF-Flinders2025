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
    timestamp_t timestamp;
    uint8_t data[FRAME_SIZE];
} frame_packet_t;

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
 ******************* UTILITY FUNCTIONS ********************
 **********************************************************/

/** @brief Checks whether the decoder is subscribed to a given channel
 *
 *  @param channel The channel number to be checked.
 *  @return 1 if the the decoder is subscribed to the channel.  0 if not.
*/
int is_subscribed(channel_id_t channel) {
    // Check if this is an emergency broadcast message
    if (channel == EMERGENCY_CHANNEL) {
        return 1;
    }
    // Check if the decoder has has a subscription
    for (int i = 0; i < MAX_CHANNEL_COUNT; i++) {
        if (decoder_status.subscribed_channels[i].id == channel && decoder_status.subscribed_channels[i].active) {
            return 1;
        }
    }
    return 0;
}

/**********************************************************
 ********************* CORE FUNCTIONS *********************
 **********************************************************/

void print_active_channels(void){
    printf("@INFO Active Channels:\n");
    for (uint32_t i = 0; i < MAX_CHANNEL_COUNT; i++) {
        if (decoder_status.subscribed_channels[i].active) {
            printf(
                "-{I} [%u] {Channel: %u, Time Stamp Start: %llu, Time Stamp End: %llu}\n",
                i, decoder_status.subscribed_channels[i].id, 
                decoder_status.subscribed_channels[i].start_timestamp,
                decoder_status.subscribed_channels[i].end_timestamp
            );
        }
    }
    printf("-COMPLETE\n\n");
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

/** @brief Processes a packet containing frame data.
 *
 *  @param pkt_len A pointer to the incoming packet.
 *  @param new_frame A pointer to the incoming packet.
 *
 *  @return 0 if successful.  -1 if data is from unsubscribed channel.
*/
int decode(pkt_len_t pkt_len, frame_packet_t *new_frame) {
    char output_buf[128] = {0};
    uint16_t frame_size;
    channel_id_t channel;

    // Frame size is the size of the packet minus the size of non-frame elements
    frame_size = pkt_len - (sizeof(new_frame->channel) + sizeof(new_frame->timestamp));
    channel = new_frame->channel;

    // The reference design doesn't use the timestamp, but you may want to in your design
    // timestamp_t timestamp = new_frame->timestamp;

    // Check that we are subscribed to the channel...
    host_print_debug("Checking subscription\n");
    if (is_subscribed(channel)) {
        host_print_debug("Subscription Valid\n");
        /* The reference design doesn't need any extra work to decode, but your design likely will.
        *  Do any extra decoding here before returning the result to the host. */
        host_write_packet(DECODE_MSG, new_frame->data, frame_size);
        return 0;
    } else {
        STATUS_LED_RED();
        sprintf(
            output_buf,
            "Receiving unsubscribed channel data.  %u\n", channel);
        host_print_error(output_buf);
        return -1;
    }
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

/**********************************************************
 *********************** MAIN LOOP ************************
 **********************************************************/
int main(void) {
    char output_buf[128] = {0};
    uint8_t uart_buf[100];
    msg_type_t cmd;
    int result;
    uint16_t pkt_len;

    // Initialize the device
    init();

    // test_crypto();
    // while(1);
    
    print_active_channels();
    unsigned char subscription_update_buff[] = {
        0x01, 0x00, 0x00, 0x00, 0x06, 0xBD, 0x93, 0x1A, 
        0x05, 0x38, 0xFE, 0xD1, 0x7C, 0xC1, 0xDC, 0x04, 
        0x20, 0x11, 0x78, 0x43, 0x63, 0x26, 0xDD, 0x6F, 
        0x6E, 0x12, 0xAF, 0x64, 0xEC, 0x8C, 0x35, 0xED, 
        0xEC, 0xC4, 0x46, 0xCB, 0x5A, 0x37, 0xB5, 0x63, 
        0x54, 0x87, 0x0A, 0x51, 0xDF, 0x69, 0xE4, 0x0F, 
        0x93, 0xD9, 0x1F, 0x11, 0xA4, 0x54, 0xED, 0x93, 
        0x7D, 0x85, 0xAD, 0xFF, 0xBA, 0x65, 0x7E, 0x1F
    };
    subscription_update(sizeof(subscription_update_buff), subscription_update_buff);
    print_active_channels();

    printf("@INFO Decoder ID: 0x%08X\n", DECODER_ID);
    while(1);


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
            decode(pkt_len, (frame_packet_t *)uart_buf);
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
