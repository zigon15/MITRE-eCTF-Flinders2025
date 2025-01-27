"""
Author: Ben Janis
Date: 2025

This source file is part of an example system for MITRE's 2025 Embedded System CTF
(eCTF). This code is being provided only for educational purposes for the 2025 MITRE
eCTF competition, and may not meet MITRE standards for quality. Use this code at your
own risk!

Copyright: Copyright (c) 2025 The MITRE Corporation
"""

import argparse
import json
from pathlib import Path
import random
import struct

from loguru import logger


def gen_secrets(channels: list[int]) -> bytes:
    """Generate the contents secrets file

    This will be passed to the Encoder, ectf25_design.gen_subscription, and the build
    process of the decoder

    :param channels: List of channel numbers that will be valid in this deployment.
        Channel 0 is the emergency broadcast, which will always be valid and will
        NOT be included in this list

    :returns: Contents of the secrets file
    """

    # Validate that channels fit in unsigned 8-bit integer range
    if any(channel < 0 or channel > 255 for channel in channels):
        raise ValueError("Channel IDs must be in the range [0, 255]!!")

    # Validate that the number of channels fits in an unsigned 8-bit integer
    if len(channels) > 255:
        raise ValueError("The number of channels must not exceed 255!!")


    # Create the secrets object
    # You can change this to generate any secret material
    # The secrets file will never be shared with attackers

    # Generate secrets
    # - Random random 128 bit keys for each channel
    keys = [random.getrandbits(128).to_bytes(16, byteorder="little") for _ in range(len(channels))]
    logger.debug(f"Generated {len(channels)} Random Channel Keys")

    # Pack the data
    # [0]: Number of channels (8-bit)
    # [1 ... Num Channels]: Channels (8-bit each)
    # [1 + Num Channels ...]: Keys for each channel (16 bytes each)
    secrets = struct.pack(
        f"<B{len(channels)}B{len(channels) * 16}s",
        len(channels),  # Number of channels (8-bit)
        *channels,      # Channels (8-bit each)
        b"".join(keys)  # Concatenate all keys as raw bytes
    )
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

    # Print the generated secrets for your own debugging
    # Attackers will NOT have access to the output of this, but feel free to remove
    #
    # NOTE: Printing sensitive data is generally not good security practice
    logger.debug(f"Generated secrets: {secrets}")

    # Open the file, erroring if the file exists unless the --force arg is provided
    with open(args.secrets_file, "wb" if args.force else "xb") as f:
        # Dump the secrets to the file
        f.write(secrets)

    # For your own debugging. Feel free to remove
    logger.success(f"Wrote secrets to {str(args.secrets_file.absolute())}")


if __name__ == "__main__":
    main()
