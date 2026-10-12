"""Authenticode hashing for UEFI PE applications."""

import lief


def authenticode_digest(data: bytes) -> bytes:
    """Calculate the SHA-384 measurement of one EFI executable."""
    with lief.logging.level_scope(lief.logging.LEVEL.OFF):
        binary = lief.PE.parse(data)
    if binary is None:
        raise ValueError("not a valid PE image")
    return binary.authentihash(lief.PE.ALGORITHMS.SHA_384)
