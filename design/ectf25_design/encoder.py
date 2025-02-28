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
import os
import struct
from cryptography.hazmat.primitives.cmac import CMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

from .global_secrets import *

# Length of each AES key in bits and bytes notation
AES_KEY_LEN_BIT = 256
AES_KEY_LEN_BYTE = AES_KEY_LEN_BIT//8

AES_BLOCK_SIZE_BIT = 128
AES_BLOCK_SIZE_BYTE = 16

AES_CMAC_MIC_LEN = 16


FRAME_NONCE_TIME_STAMP_LEN = 4
FRAME_NONCE_RAND_LEN = 12
FRAME_CYPHER_TEX_LEN = 2*AES_BLOCK_SIZE_BYTE
FRAME_PACKET_LEN = 64

FRAME_PLAIN_TEXT_MAX_LEN = 64

# Different constant used for KDF of the MIC and encryption keys
FRAME_MIC_KEY_TYPE = 0x9E
FRAME_ENCRYPTION_KEY_TYPE = 0xD7

class Encoder:
    def __init__(self, secrets: bytes):
        """
        You **may not** change the arguments or returns of this function!

        :param secrets: Contents of the secrets file generated by
            ectf25_design.gen_secrets
        """
        # TODO: parse your secrets data here and run any necessary pre-processing to
        #   improve the throughput of Encoder.encode

        # Load the json of the secrets file
        self.globalSecrets = GlobalSecrets(secrets)

    # Derive the MIC and encryption keys used for the frame data packet
    # - Separate keys for MIC and encryption in case of leakage (Do not use same key twice!!)
    # - Random nonce used internally to ensure we never get the same output twice!!
    # - Base the KDF on as much context as possible so harder to derive
    # References:
    # - https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-108r1-upd1.pdf
    # - https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-133r2.pdf#page=24.08
    # - https://resources.lora-alliance.org/technical-specifications/ts001-1-0-4-lorawan-l2-1-0-4-specification
    def derive_keys(
        self, 
        timestamp: int,
        channel: int, channel_key: bytes, 
        frame_data_len: int, frame_kdf_key: bytes
    ):
        """
        AES Key Derivation Function for frame encode MIC and encryption
        """
        
        if len(frame_kdf_key) != AES_KEY_LEN_BYTE:
            logger.error(f"Bad subscription kdf key length, Expected {AES_KEY_LEN_BYTE} bytes!!")
            raise Exception(f"Bad subscription kdf key length, Expected {AES_KEY_LEN_BYTE} bytes!!")

        # Validate that the number of channels fit in required range
        if channel > 0xFFFFFFFF:
            logger.error(f"Channel num greater than the max of 0xFFFFFFFF!!")
            raise Exception(f"Channel num greater than the max of 0xFFFFFFFF!!")

        # CTR Nonce must have some randomness to ensure derived keys are never the same
        ctr_nonce_rand = os.urandom(FRAME_NONCE_RAND_LEN)
        ctr_nonce = timestamp.to_bytes(8, byteorder='little')[:FRAME_NONCE_TIME_STAMP_LEN] + ctr_nonce_rand

        # logger.info(f"KDF AES CTR Key -> 0x{frame_kdf_key.hex()}")
        
        cipher = Cipher(
            algorithms.AES(frame_kdf_key), 
            modes.CTR(nonce=ctr_nonce),
            backend=default_backend()
        )
        
        # Input data to derive MIC key from
        # [0]: FRAME_MIC_KEY_TYPE (1 byte)
        # [1]: Frame Data Length (1 byte)
        # [2]: Channel Key (Last 18 bytes)
        # [20]: Time Stamp (8 bytes)
        # [28]: Channel (2 bytes)
        # 1 + 1 + 18 + 8 + 2 = 32 bytes long
        input_bytes = FRAME_MIC_KEY_TYPE.to_bytes(1) + frame_data_len.to_bytes(1) + channel_key[-18:] + timestamp.to_bytes(8, byteorder='little') +\
                      channel.to_bytes(4, byteorder='little')

        if len(input_bytes) != 2*AES_BLOCK_SIZE_BYTE:
            logger.error("Expected AES CTR Input for Frame Encode MIC KDF to be twe block lengths!!")
            raise Exception("Expected AES CTR Input for Frame Encode MIC KDF to be twe block lengths!!")

        # Perform AES encryption
        encryptor = cipher.encryptor()
        mic_key = encryptor.update(input_bytes) + encryptor.finalize()
        mic_key = mic_key

        # logger.info(f"MIC AES CTR KDF Nonce Rand -> 0x{ctr_nonce_rand.hex()}")
        # logger.info(f"MIC AES CTR KDF Nonce -> 0x{ctr_nonce.hex()}")
        # logger.info(f"MIC KDF Input Data -> 0x{input_bytes.hex()}")
        # logger.info(f"MIC Key -> 0x{mic_key.hex()}")

        # Input data to derive encryption key from
        # [0]: FRAME_ENCRYPTION_KEY_TYPE (1 byte)
        # [1]: Frame Data Length (1 byte)
        # [2]: Channel Key (Last 18 bytes)
        # [20]: Time Stamp (8 bytes)
        # [28]: Channel (4 bytes)
        # 1 + 18 + 8 + 4 = 32 bytes long
        input_bytes = FRAME_ENCRYPTION_KEY_TYPE.to_bytes(1) + frame_data_len.to_bytes(1) + channel_key[-18:] + timestamp.to_bytes(8, byteorder='little') +\
                      channel.to_bytes(4, byteorder='little')
        
        if len(input_bytes) != 2*AES_BLOCK_SIZE_BYTE:
            logger.error("Expected AES CTR Input for Frame Encode Encryption KDF to be two block length!!")
            raise Exception("Expected AES CTR Input for Frame Encode Encryption KDF to be twe block lengths!!")

        # Increment nonce as to not use the same nonce twice
        number = int.from_bytes(ctr_nonce_rand, byteorder='big')
        number += 1
        ctr_nonce_rand_p1 = number.to_bytes(FRAME_NONCE_RAND_LEN, byteorder='big')
        ctr_nonce = timestamp.to_bytes(8, byteorder='little')[:FRAME_NONCE_TIME_STAMP_LEN] + ctr_nonce_rand_p1

        # Perform AES encryption
        cipher = Cipher(
            algorithms.AES(frame_kdf_key), 
            modes.CTR(nonce=ctr_nonce),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        encryption_key = encryptor.update(input_bytes) + encryptor.finalize()
        encryption_key = encryption_key

        # logger.info(f"Encryption AES CTR KDF Nonce Rand -> 0x{ctr_nonce_rand.hex()}")
        # logger.info(f"Encryption AES CTR KDF Nonce -> 0x{ctr_nonce.hex()}")
        # logger.info(f"Encryption KDF Input Data -> 0x{input_bytes.hex()}")
        # logger.info(f"Encryption Key -> 0x{encryption_key.hex()}")

        return mic_key, encryption_key, ctr_nonce_rand
    
    def encrypt_payload(
        self,
        encryption_key: bytes, ctr_nonce_rand: bytes, 
        frame_data: bytes,
    ):  
        # CHECK: We can use the same nonce here as the key is different, maybe?!?!
        ctr_nonce = (b'\x00' * 4) + ctr_nonce_rand
        # print("Encryption Nonce (hex):", nonce.hex())
        
        cipher = Cipher(
            algorithms.AES(encryption_key), 
            modes.CTR(nonce=ctr_nonce),
            backend=default_backend()
        )
        
        # Input data to encrypt
        # [0]: Frame data length
        # [1]: Frame data
        plain_text = len(frame_data).to_bytes(1) + frame_data

        # Perform AES encryption
        encryptor = cipher.encryptor()
        cypher_text = encryptor.update(plain_text) + encryptor.finalize()

        # logger.info(f"Encryption AES CTR Nonce -> 0x{ctr_nonce.hex()}")
        # logger.info(f"Encryption Input Data -> 0x{plain_text.hex()}")
        # logger.info(f"Encryption Cypher Text -> 0x{cypher_text.hex()}")
        
        return cypher_text
    
    def encode(self, channel: int, frame: bytes, timestamp: int) -> bytes:
        """The frame encoder function

        This will be called for every frame that needs to be encoded before being
        transmitted by the satellite to all listening TVs

        You **may not** change the arguments or returns of this function!

        :param channel: 16b unsigned channel number. Channel 0 is the emergency
            broadcast that must be decodable by all channels.
        :param frame: Frame to encode. Max frame size is 64 bytes.
        :param timestamp: 64b timestamp to use for encoding. **NOTE**: This value may
            have no relation to the current timestamp, so you should not compare it
            against the current time. The timestamp is guaranteed to strictly
            monotonically increase (always go up) with subsequent calls to encode

        :returns: The encoded frame, which will be sent to the Decoder
        """
        # TODO: encode the satellite frames so that they meet functional and
        #  security requirements

        # Check frame length is good
        frame_len = len(frame)
        if frame_len > FRAME_PLAIN_TEXT_MAX_LEN:
            logger.error(f"Frame data with length {frame_len} bytes greater than maximum of {FRAME_PLAIN_TEXT_MAX_LEN} bytes!!")
            raise Exception(f"Frame data with length {frame_len} bytes greater than maximum of {FRAME_PLAIN_TEXT_MAX_LEN} bytes!!")

        if frame_len == 0:
            logger.error(f"Zero length frame data not allowed!!")
            raise Exception(f"Zero length frame data not allowed!!")

        # Load channel key
        channel_key = self.globalSecrets.channel_key(channel)
        if channel_key == None:
            logger.error(f"Channel {channel} not found in deployment secrets!!")
            raise Exception(f"Channel {channel} not found in deployment secrets!!")

        # Derive frame encode MIC and encrypt keys from various parameters
        mic_key, encryption_key, ctr_nonce_rand = self.derive_keys(
            channel=channel, channel_key=channel_key, timestamp=timestamp,
            frame_data_len=len(frame), frame_kdf_key=self.globalSecrets.frame_kdf_key()
        )

        # Encrypt frame data
        cipher_text = self.encrypt_payload(
            encryption_key=encryption_key, 
            ctr_nonce_rand=ctr_nonce_rand, 
            frame_data=frame
        )

        # Double check all the lengths are as expected
        assert(len(ctr_nonce_rand) == FRAME_NONCE_RAND_LEN)

        # Frame Data Packet format
        # [0]: Channel (4 Bytes)
        # [4]: AES CTR nonce random bytes (12 Bytes)
        # [16]: Time Stamp (8 Bytes)
        # [17]: Frame Length (1 Byte)
        # [25]: Cipher text
        # [25 + len(Cipher text)]: MIC (16 bytes) [Added later as MIC is calculated on whole packet]
        # 4 + 12 + 8 + 1 + len(Cipher text) + 16 = 41 + len(Cipher text)
        frame_data_msg = struct.pack(
            f"<I12s8ss{len(cipher_text)}s", 
            channel,
            ctr_nonce_rand,
            timestamp.to_bytes(8, byteorder="little"),
            frame_len.to_bytes(1),
            cipher_text
        )

        # Calculate MIC using AES CMAC over whole packet using derived MIC key
        cmac = CMAC(algorithms.AES(mic_key), backend=default_backend())
        cmac.update(frame_data_msg)
        mic = cmac.finalize()

        # logger.info(f"AES CMAC Input -> 0x{frame_data_msg.hex()}")
        # logger.info(f"MIC -> 0x{mic.hex()}")

        assert(len(mic) == AES_CMAC_MIC_LEN)

        # Add on the MIC
        frame_data_msg = frame_data_msg + mic
        
        # Print out frame data message for debugging
        # logger.info(f"Frame Data Message -> 0x{frame_data_msg.hex()}")

        # for i in range(len(frame_data_msg)):
        #     if i % 8 == 0 and i != 0:
        #         print()
            
        #     print(f"0x{frame_data_msg[i]:02X}, ", end="")
        # print()

        return frame_data_msg

def main():
    """A test main to one-shot encode a frame

    This function is only for your convenience and will not be used in the final design.

    After pip-installing, you should be able to call this with:
        python3 -m ectf25_design.encoder path/to/test.secrets 1 "frame to encode" 100
    """
    parser = argparse.ArgumentParser(prog="ectf25_design.encoder")
    parser.add_argument(
        "secrets_file", type=argparse.FileType("rb"), help="Path to the secrets file"
    )
    parser.add_argument("channel", type=int, help="Channel to encode for")
    parser.add_argument("frame", help="Contents of the frame")
    parser.add_argument("timestamp", type=int, help="64b timestamp to use")
    args = parser.parse_args()

    encoder = Encoder(args.secrets_file.read())
    print(repr(encoder.encode(args.channel, args.frame.encode(), args.timestamp)))


if __name__ == "__main__":
    main()
