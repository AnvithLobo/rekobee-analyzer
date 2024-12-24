"""Provide steps for handshake (CHAP) analysis.
"""

__all__ = ["step_1", "step_2"]

from Crypto.Cipher import AES

from core.encryption import *
from core.exceptions import *
from core.models import *
from core.utils import *


def find_initial_index(capture):
    """
    Finds the index of the initial packet.
    
    :param      capture:  The capture.
    :type       capture:  pyshark.FileCapture

    :returns:   Returns the index if found; otherwise, a negative number.
    :rtype:     bytes
    """
    for index, packet in enumerate(capture):
        # skip packets without TCP layer
        if not hasattr(packet, "tcp"):
            continue
        if int(packet.tcp.len) == 40:
            return index
    return -1


def get_initial_index(capture, initial: int = None):
    if initial == None:
        initial = find_initial_index(capture)
        if initial < 0:
            raise ValueError("Initial packet not found.")
        success(f"Found the initial packet at {initial}.")
    elif int(capture[initial].tcp.len) != 40:
        raise ValueError((
            "The user-specified initial packet %d has an invalid payload "
            "length."
        ) % initial)
    return initial


def show_participants(packets_filter):
    info(
        "Participants:",
        f"CNC: {packets_filter.master_address}:{packets_filter.master_port}",
        f"Slave: {packets_filter.slave_address}:{packets_filter.slave_port}",
        sep = "\n",
        style = "list"
    )
    # TODO: frontend.show("participants", ...);
    # js/certain wasm function/etc receives JSON like {"participants": ...} and
    # update UI via 'factory'.


def show_encryption(key_1, key_2, iv_1, iv_2, verbose: int = 0):
    info(
        "Encryption (from the client's point of view):",
        f"AES(key={hexdigest(key_1)}, iv={hexdigest(iv_1)}) for sending;",
        f"AES(key={hexdigest(key_2)}, iv={hexdigest(iv_2)}) for receiving.",
        sep = "\n",
        style = "enum" if verbose > 1 else "list"
    )


def step_1(capture, secret: str, **kwargs) -> None:
    """
    Step 1: initial packet.

    The server sends a initial packet (40 bytes).
    """
    initial = kwargs.get("initial", None)
    verbose = kwargs.get("verbose", 0)

    initial = get_initial_index(capture, initial)

    # The server sends two hashes to the client:
    # 
    # - `sha1({timeval_1}{pid})`
    # - `sha1({timeval_2}{pid + 1})`
    # 
    # Where timeval is a linux-specific structure.
    packet = capture[initial]
    hashes = data(packet)
    salt_1 = hashes[:20]
    salt_2 = hashes[20:]

    # They are then used as salt and key in two aes contexts.
    #
    # 6 @ 00001d55  aes_init(&aes_ctx_1, encryption_secret, &aes_salt_2);
    # 7 @ 00001d67  aes_init(&aes_ctx_2, encryption_secret, &aes_salt_1);
    #
    # 15 @ 00001401  *(aes_ctx + 0x408) = *salt
    # 16 @ 0000141c  *(aes_ctx + 0x418) = ...
    #
    # The code base is shared, so the server uses it the same way, but the salts
    # are in direct order, and vice versa to the client. Note that we only need
    # decryption.
    key_1 = truncate_to_128(sha1(secret.encode() + salt_2))
    key_2 = truncate_to_128(sha1(secret.encode() + salt_1))
    iv_1 = truncate_to_128(salt_2) # 0xfb28 send_mutable_xor (part of aes_ctx_1)
    iv_2 = truncate_to_128(salt_1) # 0xe628 recv_mutable_xor (part of aes_ctx_2)
    # Probably AES CBC was made by hand on top of EBC.
    aes_1 = AES.new(key_1, AES.MODE_CBC, iv = iv_1)
    aes_2 = AES.new(key_2, AES.MODE_CBC, iv = iv_2)

    filter = PacketsFilter(packet)
    if verbose > 0:
        show_participants(filter)
    if verbose > 1:
        payload = dump(hashes, size = 20, highlights = ((0, 16), (20, 36)))
        info("Initial packet payload (salts highlighted):", payload, sep = "\n")
    if verbose > 0:
        show_encryption(key_1, key_2, iv_1, iv_2, verbose)

    return Context(
        aes_1 = aes_1,
        aes_2 = aes_2,
        capture = capture,
        current_packet = initial,
        packets_filter = filter,
        verbose = verbose
    )


def step_2(context, signature: str, **kwargs) -> None:
    """
    Step 2: bilateral challenge.

    The server sends a challenge - encrypted 16 bytes of magic signature, and if
    it matches the client's magic signature, then the client sends it back.
    """
    if isinstance(signature, str):
        signature = blob(signature)
    elif not isinstance(signature, bytes):
        raise TypeError("The signature is not bytes or hexadecimal string.")

    challenge_1 = context.get_data(MASTER)
    if challenge_1 != signature:
        # FIXME: Probably not. Correctness is determined by the version of the
        # client, but I just pulled it out to the argument. Otherwise, the
        # server may spam (?) the initial packets. I don't know. I don't have
        # the server. I only have a patched client. But I don't want to raise a
        # confusing ProtocolError.
        raise HandshakeError("The server sent an invalid magic signature.")
    success("The server is authenticated by the client.")

    challenge_2 = context.get_data(SLAVE)
    if challenge_1 != challenge_2:
        # The server will categorically refuse the connection.
        raise HandshakeError("The client sent an invalid magic signature.")
    success("The client is authenticated by the server.") # most likely
    