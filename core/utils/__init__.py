from .hashing import *
from .printing import *
from .encoding import *


def data(packet) -> bytes:
    """
    Gets the packet data as bytes.
    
    :param      packet:  The packet.
    :type       packet:  pyshark.packet.packet.Packet
    
    :returns:   Returns packet data.
    :rtype:     bytes
    """
    return blob(packet.DATA.data)


def truncate_to_128(sha1: bytes):
    """
    Truncates SHA1 (160 bit) to AES 128 (bit) how is it done by the executable.

    The executable implicitly truncates the hash via `(char*)int128_t`, which is
    before volatile int32_t and another large buffer.

    00001ce1  uint64_t client_init(int32_t connection, char* encryption_secret)

    2 @ 00001d21  int128_t aes_salt_1 = buffer
    3 @ 00001d2b  int32_t var_48_1 = buffer_after_16b  // volatile;
    7 @ 00001d67  aes_init(aes_ctx: &aes_ctx_2, secret: encryption_secret, salt: &aes_salt_1)

    00001385  void* aes_init(int32_t* aes_ctx, char* secret, char* salt)

    :param      sha1:  The SHA1 hash.
    :type       sha1:  bytes
    
    :returns:   Returns AES 128 key.
    :rtype:     bytes
    """
    return sha1[:16] # excellent
