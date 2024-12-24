"""Provides hash functions.
"""

__all__ = ["sha1"]

import hashlib


def sha1(data: bytes) -> bytes:
    interim = hashlib.sha1(data)
    result = interim.digest()
    return result
