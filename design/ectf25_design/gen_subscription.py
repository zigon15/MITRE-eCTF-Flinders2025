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
import base64
import os
from pathlib import Path
import struct
from cryptography.hazmat.primitives.cmac import CMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

from loguru import logger

# Length of each AES key in bits and bytes notation
AES_KEY_LEN_BIT = 256
AES_KEY_LEN_BYTE = AES_KEY_LEN_BIT//8

SUBSCRIPTION_KDF_KEY_LEN = 32
SUBSCRIPTION_CYPHER_AUTH_TAG_LEN = 16
FRAME_KDF_KEY_LEN = 32
CHANNEL_NUM_LEN = 2
CHANNEL_LEN = 2
CHANNEL_KEY_LEN = 32

AES_BLOCK_SIZE_BIT = 128
AES_BLOCK_SIZE_BYTE = 16

AES_CMAC_MIC_LEN = 16

SUBSCRIPTION_UPDATE_NONCE_RAND_LEN = 12
SUBSCRIPTION_UPDATE_CYPHER_TEX_LEN = 2*AES_BLOCK_SIZE_BYTE
SUBSCRIPTION_UPDATE_DATA_LEN = 64

# Different constant used for KDF of the MIC and encryption keys
SUBSCRIPTION_MIC_KEY_TYPE = 0xC7
SUBSCRIPTION_ENCRYPTION_KEY_TYPE = 0x98

def parse_secrets(
    raw_secrets: bytes,   
) -> list[dict[int, str]]: 
    """Parse the binary secrets file

    Returns a dictionary of the channels and channel keys for this deployment

    :param secrets: Contents of the secrets file generated by ectf25_design.gen_secrets
    """
    offset = 0

    # [0:31] bytes are subscription KDF key
    subscription_kdf_key = raw_secrets[offset:offset+SUBSCRIPTION_KDF_KEY_LEN] 
    offset += SUBSCRIPTION_KDF_KEY_LEN

    # [32:47]
    subscription_cypher_auth_tag = raw_secrets[offset:offset+SUBSCRIPTION_CYPHER_AUTH_TAG_LEN] 
    offset += SUBSCRIPTION_CYPHER_AUTH_TAG_LEN

    # [48:79] bytes are frame KDF key
    frame_kdf_key = raw_secrets[offset:offset+FRAME_KDF_KEY_LEN]
    offset += FRAME_KDF_KEY_LEN

    # [80:81] bytes are number of channels (16b) followed by channel IDs (16b each)
    num_channels = struct.unpack('<H', raw_secrets[offset:offset+CHANNEL_NUM_LEN])[0]
    offset += CHANNEL_NUM_LEN

    channels = [
        struct.unpack('<H', raw_secrets[offset + i*CHANNEL_LEN: offset + (i+1)*CHANNEL_LEN])[0]
        for i in range(num_channels)
    ]
    offset += num_channels*CHANNEL_LEN

    # Remaining bytes are the 256-bit channel keys
    channel_keys = [
        raw_secrets[offset + i*CHANNEL_KEY_LEN : offset + (i+1)*CHANNEL_KEY_LEN]
        for i in range(num_channels)
    ]

    # print(', '.join(f'0x{b:02X}' for b in subscription_kdf_key))

    # for channel_key, channel in zip(channel_keys, channels):
    #     print(channel)
    #     print(', '.join(f'0x{b:02X}' for b in channel_key))
    
    # Print secrets for debugging
    channel_key_pairs = [
        f"{{Channel: {channel}, Key: 0x{key.hex()}}}'" 
        for channel, key in zip(channels, channel_keys)
    ]
    logger.info(
        f"Secrets: {{"
            f"Subscription KDF Key: 0x{subscription_kdf_key.hex()}', "  
            f"Subscription Cypher Auth Tag: 0x{subscription_cypher_auth_tag.hex()}, "
            f"Frame KDF Key: {frame_kdf_key.hex()}', "  
            f"Channel Secrets: [{', '.join(channel_key_pairs)}]"
        f"}}"
    )

    return {
        "SubscriptionKdfKey": subscription_kdf_key,
        "SubscriptionCypherAuthTag": subscription_cypher_auth_tag,
        "FrameKdfKey": frame_kdf_key,
        "ChannelSecrets": [{"channel": channel, "key": key} for channel, key in zip(channels, channel_keys)]
    }

def get_key_by_channel(
    channel: int, decoded_secrets: bytes
) -> str:
    """Retrieve the key for a given channel from the secrets
    """

    channel_key_pairs = decoded_secrets["ChannelSecrets"]

    # Search for the dictionary with the matching channel and return its key
    for pair in channel_key_pairs:
        if pair['channel'] == channel:
            return pair['key']
    return None

# Derive the MIC and encryption keys used for the subscription update packet
# - Separate keys for MIC and encryption in case of leakage (Do not use same key twice!!)
# - Random nonce used internally to ensure we never get the same output twice!!
# - Base the KDF on as much context as possible so harder to derive
# References:
# - https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-108r1-upd1.pdf
# - https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-133r2.pdf#page=24.08
# - https://resources.lora-alliance.org/technical-specifications/ts001-1-0-4-lorawan-l2-1-0-4-specification
def subscription_derive_keys(
    device_id: int,
    channel: int, channel_key: bytes, subscription_kdf_key: bytes
) -> bytes:
    """
    AES Key Derivation Function for subscription update encryption
    """

    # Validate that the number of channels fit in required range
    if len(subscription_kdf_key) != AES_KEY_LEN_BYTE:
        logger.error(f"Bad subscription kdf key length, Expected {AES_KEY_LEN_BYTE} bytes!!")
        exit()

    # Nonce must have some randomness to ensure derived keys are never the same
    ctr_nonce_rand = os.urandom(12)
    nonce = device_id.to_bytes(4, byteorder='big') + ctr_nonce_rand
    

    # logger.info(f"KDF AES CTR Nonce Rand -> 0x{ctr_nonce_rand.hex()}")
    # logger.info(f"KDF AES CTR Nonce -> 0x{nonce.hex()}")
    logger.info(f"KDF AES CTR Key -> 0x{subscription_kdf_key.hex()}")

    cipher = Cipher(
        algorithms.AES(subscription_kdf_key), 
        modes.CTR(nonce=nonce),
        backend=default_backend()
    )

    # Input data to derive MIC key from
    # [0]: SUBSCRIPTION_MIC_KEY_TYPE (1 byte)
    # [1]: Channel Key (25 bytes)
    # [17]: Device ID (4 bytes)
    # [21]: Channel (2 bytes)
    # 1 + 25 + 4 + 2 = 32 bytes long
    input_bytes = SUBSCRIPTION_MIC_KEY_TYPE.to_bytes(1) + channel_key[0:25] + device_id.to_bytes(4, byteorder='little') +\
                  channel.to_bytes(2, byteorder='little')


    if len(input_bytes) != 2*AES_BLOCK_SIZE_BYTE:
        logger.error("Expected AES CTR Input for Subscription KDF to be one block length!!")
        exit()

    # Perform AES encryption
    encryptor = cipher.encryptor()
    mic_key = encryptor.update(input_bytes) + encryptor.finalize()
    mic_key = mic_key[0:16]

    logger.info(f"MIC AES CTR KDF Nonce -> 0x{nonce.hex()}")
    logger.info(f"MIC KDF Input Data -> 0x{input_bytes.hex()}")
    logger.info(f"MIC Key -> 0x{mic_key.hex()}")
    
    # Input data to derive encryption key from
    # [0]: SUBSCRIPTION_ENCRYPTION_KEY_TYPE (1 byte)
    # [1]: Channel Key (25 bytes)
    # [17]: Device ID (4 bytes)
    # [21]: Channel (2 bytes)
    # 1 + 25 + 4 + 2 = 32 bytes long
    input_bytes = SUBSCRIPTION_ENCRYPTION_KEY_TYPE.to_bytes(1) + channel_key[0:25] + device_id.to_bytes(4, byteorder='little') +\
                  channel.to_bytes(2, byteorder='little')
    
    # Perform AES encryption
    number = int.from_bytes(ctr_nonce_rand, byteorder='big')
    number += 1
    ctr_nonce_rand_p1 = number.to_bytes(12, byteorder='big')

    nonce = device_id.to_bytes(4, byteorder='big') + ctr_nonce_rand_p1
    cipher = Cipher(
        algorithms.AES(subscription_kdf_key), 
        modes.CTR(nonce=nonce),
        backend=default_backend()
    )
    encryptor = cipher.encryptor()
    encryption_key = encryptor.update(input_bytes) + encryptor.finalize()
    encryption_key = encryption_key[0:16]


    logger.info(f"Encryption AES CTR KDF Nonce -> 0x{nonce.hex()}")
    logger.info(f"Encryption KDF Input Data -> 0x{input_bytes.hex()}")
    logger.info(f"Encryption Key -> 0x{encryption_key.hex()}")

    # logger.debug(f"KDF -> Subscription MIC Key: {base64.b64encode(mic_key)}")
    # logger.debug(f"KDF -> Subscription Encryption Key: {base64.b64encode(encryption_key)}")

    return mic_key, encryption_key, ctr_nonce_rand

def subscription_encrypt_payload(
    encryption_key: bytes, ctr_nonce_rand: bytes, 
    subscription_cypher_auth_tag: bytes,
    start: int, end: int,
):  
    # CHECK: We can use the same nonce here as the key is different, maybe?!?!
    nonce = (b'\x00' * 4) + ctr_nonce_rand
    # print("Encryption Nonce (hex):", nonce.hex())
    
    cipher = Cipher(
        algorithms.AES(encryption_key), 
        modes.CTR(nonce=nonce),
        backend=default_backend()
    )

    # Input data to derive encryption key from
    # [0]: Time stamp start (8 bytes)
    # [8]: Magic authentication number (16 bytes)
    # [24]: Time stamp end (8 bytes)
    # 8 + 16 + 8 = 32 bytes long
    plain_text = start.to_bytes(8, byteorder='little') + subscription_cypher_auth_tag + end.to_bytes(8, byteorder='little')

    # Perform AES encryption
    encryptor = cipher.encryptor()
    cypher_text = encryptor.update(plain_text) + encryptor.finalize()

    logger.info(f"Encryption AES CTR Nonce -> 0x{nonce.hex()}")
    logger.info(f"Encryption Input Data -> 0x{plain_text.hex()}")
    logger.info(f"Encryption Cypher Text -> 0x{cypher_text.hex()}")
    
    return cypher_text

# Generate a valid subscription update packet for the specified device
# Aim: 
#  1) We do not want an attacker to be able to generate a valid subscription update message
#     - Do not leak global secrets so use key derivation
#     - Never use the same key twice -> separate keys for MIC and data encryption
#     - Each KDF should produce a different key -> use random nonce
#  2) We do not want an attacker to modify a valid subscription update message and it still be valid
#     - Trust nothing implicitly :( !!
#     - Use AES CMAC on the whole message XORed with as much context as possible
#     - AES CMAC should never be the same for two packets!!
def gen_subscription(
    secrets: bytes, device_id: int, start: int, end: int, channel: int
) -> bytes:
    """Generate the contents of a subscription.

    The output of this will be passed to the Decoder using ectf25.tv.subscribe

    :param secrets: Contents of the secrets file generated by ectf25_design.gen_secrets
    :param device_id: Device ID of the Decoder
    :param start: First timestamp the subscription is valid for
    :param end: Last timestamp the subscription is valid for
    :param channel: Channel to enable
    """

    # Please note that the secrets are READ ONLY at this stage!
    secrets = parse_secrets(secrets)

    # Load channel key
    channel_key = get_key_by_channel(channel, secrets)
    if channel_key == None:
        logger.error(f"Channel {channel} not found in deployment secrets!!")
        exit()

    # Derive subscription update key from all message parameters
    mic_key, encryption_key, ctr_nonce_rand = subscription_derive_keys(
        device_id=device_id,
        channel=channel, channel_key=channel_key,
        subscription_kdf_key=secrets["SubscriptionKdfKey"]
    )

    # Encrypt data
    # - Honestly, time start and end do not need to be encrypted 
    #   - MIC ensures they can not be modified and packet be valid
    # - Main aim is to make data used for MIC more random
    cipher_text = subscription_encrypt_payload(
        encryption_key=encryption_key, ctr_nonce_rand=ctr_nonce_rand, 
        subscription_cypher_auth_tag=secrets["SubscriptionCypherAuthTag"],
        start=start, end=end
    )

    if len(cipher_text) != SUBSCRIPTION_UPDATE_CYPHER_TEX_LEN:
        logger.error("Expected Subscription Cipher Text to be Two AES Block Length!!")
        exit()

    # Double check all the lengths are as expected
    assert(len(ctr_nonce_rand) == SUBSCRIPTION_UPDATE_NONCE_RAND_LEN)
    assert(len(cipher_text) == SUBSCRIPTION_UPDATE_CYPHER_TEX_LEN)

    # Packet format
    # [0]: Channel (4 Bytes)
    # [4]: AES CTR nonce random bytes (12 Bytes)
    # [16]: Cipher text (32 Bytes)
    # [38]: MIC (16 bytes) [Added later as MIC is calculated on whole packet]
    # 4 + 12 + 32 + 16 = 64
    subscription_update_msg = struct.pack(
        "<I12s32s", 
        channel,
        ctr_nonce_rand,
        cipher_text
    )

    # Calculate MIC using AES CMAC over whole packet using derived MIC key
    cmac = CMAC(algorithms.AES(mic_key), backend=default_backend())
    cmac.update(subscription_update_msg)
    mic = cmac.finalize()

    logger.info(f"AES CMAC Input -> 0x{subscription_update_msg.hex()}")
    logger.info(f"MIC -> 0x{mic.hex()}")

    assert(len(mic) == AES_CMAC_MIC_LEN)

    # Add on the MIC
    subscription_update_msg = subscription_update_msg + mic

    if len(subscription_update_msg) != SUBSCRIPTION_UPDATE_DATA_LEN:
        logger.error(f"Bad Subscription Update Length -> ({SUBSCRIPTION_UPDATE_DATA_LEN} != {len(subscription_update_msg)})!!")
        exit()


    logger.info(f"Subscription Update Message -> 0x{subscription_update_msg.hex()}")

    for i in range(len(subscription_update_msg)):
        if i % 8 == 0 and i != 0:
            print()
        
        print(f"0x{subscription_update_msg[i]:02X}, ", end="")
    print()

    # Subscription update will be sent to the decoder with ectf25.tv.subscribe
    return subscription_update_msg

def parse_args():
    """Define and parse the command line arguments

    NOTE: Your design must not change this function
    """
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--force",
        "-f",
        action="store_true",
        help="Force creation of subscription file, overwriting existing file",
    )
    parser.add_argument(
        "secrets_file",
        type=argparse.FileType("rb"),
        help="Path to the secrets file created by ectf25_design.gen_secrets",
    )
    parser.add_argument("subscription_file", type=Path, help="Subscription output")
    parser.add_argument(
        "device_id", type=lambda x: int(x, 0), help="Device ID of the update recipient."
    )
    parser.add_argument(
        "start", type=lambda x: int(x, 0), help="Subscription start timestamp"
    )
    parser.add_argument("end", type=int, help="Subscription end timestamp")
    parser.add_argument("channel", type=int, help="Channel to subscribe to")
    return parser.parse_args()


def main():
    """Main function of gen_subscription

    You will likely not have to change this function
    """
    # Parse the command line arguments
    args = parse_args()

    subscription = gen_subscription(
        args.secrets_file.read(), args.device_id, args.start, args.end, args.channel
    )

    # Print the generated subscription for your own debugging
    # Attackers will NOT have access to the output of this (although they may have
    # subscriptions in certain scenarios), but feel free to remove
    #
    # NOTE: Printing sensitive data is generally not good security practice
    logger.debug(f"Generated subscription: {subscription}")

    # Open the file, erroring if the file exists unless the --force arg is provided
    with open(args.subscription_file, "wb" if args.force else "xb") as f:
        f.write(subscription)

    # For your own debugging. Feel free to remove
    logger.success(f"Wrote subscription to {str(args.subscription_file.absolute())}")


if __name__ == "__main__":
    main()
