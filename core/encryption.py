"""Provides cryptography for the ic2kp protocol.

Packet structure:

+--------------+---------+--------------------+----------+
| Content size | Content | AES block padding  | HMAC     |
+--------------+---------+--------------------+----------+
| 2 bytes      | ← bytes | up to 15 bytes     | 20 bytes |
+--------------+---------+--------------------+----------+
| AES 128 (CBC)                               | Raw      |
+--------------+---------+--------------------+----------+
"""

__all__ = ["decrypt"]

import math

from core.exceptions import *
from core.models import *
from core.utils import *


def get_aes_context(context, sender: str):
    if not sender in (SLAVE, MASTER):
        raise ValueError(f"Unknown sender '{sender}'.")
    if context.verbose > 1:
        ctx_no = 1 if sender == SLAVE else 2
        info("The packet will be decrypted with #%d AES context." % ctx_no)
    return context.aes_1 if sender == SLAVE else context.aes_2


def get_content_size(header: bytes, verbose: int) -> int:
    binary = header[:2]
    result = int.from_bytes(binary, "big") # endianness is not little
    if verbose > 1:
        info(
            "Packet header (and initial buffer):",
            dump(header, highlights = ((0, 2),)),
            sep = "\n"
        )
    if result < 0 or result > 4096:
        # Something unverifiable is wrong:
        #
        # 1) we do the decryption in a wrong order;
        # 2) someone sends malicious data (diff ic2kp version).
        raise ProtocolError((
            f"Invalid size packet ({result}) received. it is more likely "
            f"that the shared secret is wrong."
        ))
    return result


def get_initial_buffer(header: bytes) -> bytes:
    return header[2:] # 14 bytes after the content size in the same AES block


def decrypt(context, data: bytes, sender: str):
    """
    Dangerously decrypts data.

    It is recommended to use `core.models.Context.get_data` instead.

    The IV will be overwritten with this data, and if not in the order that the
    server was sent, then you will get a broken context due to AES CBC nature.

    You can pass more than one packet through the data parameter, but the sender
    must be the same. Useful for concatenated TCP packets.

    :param   context:  The decryption context.
    :type    context:  models.Context
    :param      data:  The binary data packets to decrypt.
    :type       data:  bytes
    :param    sender:  The required sender - MASTER or SLAVE ('filters.py').
    :type     sender:  str
    
    :returns:   Returns the decrypted data for the current batch of packets.
    :rtype:     Generator[bytes, None, None]
    """
    aes_ctx = get_aes_context(context, sender)
    
    header = aes_ctx.decrypt(data[:16])
    content_size = get_content_size(header, context.verbose)
    buffer = get_initial_buffer(header)

    packet_size = None
    if content_size <= 14:
        packet_size = 2 + 14 # content_size + buffer with padding
        buffer = buffer[:content_size] # remove padding
    else:
        # Computing the end of encrypted packet in the data.
        packet_size = math.ceil((2 + content_size) / 16) * 16
        remain_data = data[2 + 14 : packet_size] # without initial buffer
        buffer = buffer + aes_ctx.decrypt(remain_data)[: content_size - 14]
    hmac = data[packet_size : packet_size + 20]

    if len(hmac) != 0x14:
        raise ProtocolError(
            f"Packet signature ({hexdigest(hmac)}) of invalid size."
        )
    # TODO: The client will reject the packet if the hmac is invalid. The HMAC
    # check ensures that the decryption order is correct.

    if context.verbose > 1:
        info(
            "Packet:",
            f"size: {content_size};",
            f"HMAC: {hexdigest(hmac)}.",
            sep = "\n",
            style = "list"
        )
        info("Content:", dump(buffer), sep = "\n")

    yield buffer

    # TCP packets can be nested.
    next_packet = data[packet_size + 20:]
    if len(next_packet) > 0:
        if context.verbose > 1:
            info("The TCP packet contains a nested ic2kp packet.")
        for buffer in decrypt(context, next_packet, sender):
            yield buffer
