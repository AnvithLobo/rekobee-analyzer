"""Provides converters to work with data representations.
"""

__all__ = ["blob", "hexdigest"]


def blob(string: str) -> bytes:
    """
    Converts HEX string to bytes, i.e. blob("000102) → b"\x00\x01\x02".

    :param      string:  The HEX string.
    :type       string:  str

    :returns:   Returns the binary equivalent.
    :rtype:     bytes
    """
    array = list(string)
    pairs = zip(array[0::2], array[1::2])
    hexes = map(lambda p: str().join(p), pairs)
    result = bytes.fromhex(" ".join(hexes))
    return result


def hexdigest(data) -> str:
    """
    The opposite of the blob function, i.e. hexdigest(b"\x01\x02") → "0102".
    """
    if isinstance(data, int):
        representation = str(hex(data)) # 0x1
        truncated = representation[2:] # 1
        justed = truncated.rjust(2, "0") # 01
        return justed
    elif isinstance(data, bytes):
        interim = map(hexdigest, data)
        result = str().join(interim)
        return result
    raise TypeError("The data is neither bytes nor int.")
