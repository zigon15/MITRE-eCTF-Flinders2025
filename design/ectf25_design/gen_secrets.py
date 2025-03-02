"""
Author: Ben Janis, Simon Rosenzweig
Date: 2025

This source file is part of an example system for MITRE's 2025 Embedded System CTF
(eCTF). This code is being provided only for educational purposes for the 2025 MITRE
eCTF competition, and may not meet MITRE standards for quality. Use this code at your
own risk!

Copyright: Copyright (c) 2025 The MITRE Corporation
"""

import argparse
import base64
import json
from pathlib import Path
import random
import struct

from loguru import logger

# Length of each AES key in bits and bytes notation
AES_KEY_LEN_BIT = 256
AES_KEY_LEN_BYTE = AES_KEY_LEN_BIT//8

# Allowed channel number range (32b unsigned)
MIN_CHANNEL = 0
MAX_CHANNEL = 0xFFFFFFFF

# Maximum number of channels allowed in a single deployment (16b unsigned)
MAX_NUM_CHANNELS = 0xFFFF

SUBSCRIPTION_CYPHER_AUTH_TAG_LEN = 16

def gen_secrets(channels: list[int]) -> bytes:
    """Generate the contents secrets file

    This will be passed to the Encoder, ectf25_design.gen_subscription, and the build
    process of the decoder

    :param channels: List of channel numbers that will be valid in this deployment.
        Channel 0 is the emergency broadcast, which will always be valid and will
        NOT be included in this list. Each channel is a 32b number.

    :returns: Contents of the secrets file
    """

    # Emergency channel must always be in deployment
    if 0 not in channels:
        channels.append(0)

    # Validate that channels fit in required range
    for channel in channels:
        if channel < MIN_CHANNEL or channel > MAX_CHANNEL:
            print(f"Channel IDs must be in the range [{MIN_CHANNEL}, {MAX_CHANNEL}] -> ${channels}!!")
            print(f"-> Bad Channel: {channel}")
            raise Exception(f"Channel IDs must be in the range [{MIN_CHANNEL}, {MAX_CHANNEL}], Bad Channel: {channel}!!")

    # Validate that the number of channels fit in required range
    if len(channels) > MAX_NUM_CHANNELS:
        print(f"The number of channels must not exceed {MAX_NUM_CHANNELS}!!")
        raise Exception(f"The number of channels must not exceed {MAX_NUM_CHANNELS}!!")

    # Create the secrets object
    # You can change this to generate any secret material
    # The secrets file will never be shared with attackers

    # Generate subscription key for KDF and cypher authentication tag
    # - Random 256 bit number
    subscription_kdf_key = random.getrandbits(AES_KEY_LEN_BIT).to_bytes(
        AES_KEY_LEN_BYTE, byteorder="little"
    )
    subscription_cypher_auth_tag = random.getrandbits(SUBSCRIPTION_CYPHER_AUTH_TAG_LEN*8).to_bytes(
        SUBSCRIPTION_CYPHER_AUTH_TAG_LEN, byteorder="little"
    )

    # Generate frame key for KDF
    # - Random 256 bit number
    frame_kdf_key = random.getrandbits(AES_KEY_LEN_BIT).to_bytes(
        AES_KEY_LEN_BYTE, byteorder="little"
    )

    # Generate flash key for KDF and flash kdf input key
    # - Random 256 bit numbers
    flash_kdf_key = random.getrandbits(AES_KEY_LEN_BIT).to_bytes(
        AES_KEY_LEN_BYTE, byteorder="little"
    )
    flash_kdf_input_key = random.getrandbits(AES_KEY_LEN_BIT).to_bytes(
        AES_KEY_LEN_BYTE, byteorder="little"
    )

    # Generate channel secrets
    # - Random random 256 bit keys for each channel
    channel_keys = [random.getrandbits(AES_KEY_LEN_BIT).to_bytes(
        AES_KEY_LEN_BYTE, byteorder="little"
    ) for _ in range(len(channels))]

    # # Print secrets for debugging
    # logger.debug(f"Generated {len(channels)} Random Channel Keys for Channels {channels}")
    # channel_key_pairs = [
    #     f"{{Channel: {channel}, Key: 0x'{key.hex()}'}}" 
    #     for channel, key in zip(channels, channel_keys)
    # ]

    # logger.debug(
    #     f"Secrets: {{"
    #         f"Subscription KDF Key: 0x{subscription_kdf_key.hex()}, "
    #         f"Subscription Cypher Auth Tag: 0x{subscription_cypher_auth_tag.hex()}, "
    #         f"Frame KDF Key: 0x{frame_kdf_key.hex()}', "
    #         f"Flash KDF Key: 0x{flash_kdf_key.hex()}', "  
    #         f"Flash KDF Input Key: 0x{flash_kdf_input_key.hex()}', "  
    #         f"Channel Secrets: [{', '.join(channel_key_pairs)}]"
    #     f"}}"
    # )

    # Pack the data
    # [0]: Subscription KDF key (32 Bytes)
    # [32]: Subscription cypher authentication key (16 Bytes)
    # [48]: Frame KDF key (32 Bytes)
    # [80]: Flash KDF key (32 Bytes)
    # [112]: Flash KDF input key (32 Bytes)
    # [144]: Number of channels (2 Bytes)
    # [146]: Channel IDs (4 Bytes each)
    # [146 + 4*NumChannels]: Keys for each channel (32 Bytes each)
    secrets = struct.pack(
        f"<32s16s32s32s32sH{len(channels)}I{len(channels)*32}s",
        subscription_kdf_key,           # Subscription KDF key (32 Bytes)
        subscription_cypher_auth_tag,   # Subscription Cypher Auth Tag (16 Bytes)
        frame_kdf_key,                  # Frame KDF key (32 Bytes)
        flash_kdf_key,                  # Flash KDF key (32 Bytes)
        flash_kdf_input_key,            # Flash KDF input key (32 bytes)
        len(channels),                  # Number of channels (2 Bytes)
        *channels,                      # Channels (4 Bytes each)
        b"".join(channel_keys)          # Concatenate all channel keys (32 Bytes each)
    )

    # logger.debug(f"Secrets Len: {len(secrets)} Bytes")
    return secrets


def parse_args():
    """Define and parse the command line arguments

    NOTE: Your design must not change this function
    """
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--force",
        "-f",
        action="store_true",
        help="Force creation of secrets file, overwriting existing file",
    )
    parser.add_argument(
        "secrets_file",
        type=Path,
        help="Path to the secrets file to be created",
    )
    parser.add_argument(
        "channels",
        nargs="+",
        type=int,
        help="Supported channels. Channel 0 (broadcast) is always valid and will not"
        " be provided in this list",
    )
    return parser.parse_args()


def main():
    """Main function of gen_secrets

    You will likely not have to change this function
    """
    # Parse the command line arguments
    args = parse_args()

    secrets = gen_secrets(args.channels)

    # Open the file, erroring if the file exists unless the --force arg is provided
    with open(args.secrets_file, "wb" if args.force else "xb") as f:
        # Dump the secrets to the file
        f.write(secrets)


if __name__ == "__main__":
    main()
