"""Predict the MOK measurements that shim extends into RTMR2.

On a fresh VM, shim builds its MOK allowlist and denylist from data embedded
in the shim executable. This module reproduces those lists and hashes them in
the same form shim measures during boot.
"""

import hashlib
import struct

import lief

# UEFI GUIDs in the mixed-endian byte order used in EFI_SIGNATURE_LIST.
EFI_CERT_X509_GUID = bytes.fromhex("a159c0a5e494a74a87b5ab155c2bf072")
EFI_CERT_SHA256_GUID = bytes.fromhex("2616c4c14c509240aca941f936934328")
SHIM_LOCK_GUID = bytes.fromhex("50ab5d6046e00043abb63dd810dd8b23")

MOK_LIST_TRUSTED_DIGEST = hashlib.sha384(b"\x01").digest()


def _signature_list(signature_type: bytes, signature: bytes) -> bytes:
    """Wrap one EFI signature in an EFI_SIGNATURE_LIST."""
    return (
        signature_type
        + struct.pack("<III", 28 + len(signature), 0, len(signature))
        + signature
    )


def _validate_signature_lists(payload: bytes) -> bytes:
    """Validate and return one or more serialized EFI signature lists."""
    position = 0
    while position + 28 <= len(payload):
        list_size, header_size, signature_size = struct.unpack_from(
            "<III", payload, position + 16
        )
        signature_bytes = list_size - 28 - header_size
        if (list_size < 28 or signature_size <= 16
                or signature_bytes <= 0
                or signature_bytes % signature_size):
            break
        position += list_size
    if position != len(payload):
        raise ValueError("shim contains malformed EFI signature-list data")
    return payload


def _authorized_mok_data(payload: bytes) -> bytes:
    """Convert shim's authorized data into MokList's serialized form."""
    # A shim build can embed either one raw certificate or a ready-made list.
    # Raw certificates must be wrapped in UEFI's standard list format before
    # shim measures the resulting MokList.
    if payload[:2] == b"\x30\x82":
        return _signature_list(EFI_CERT_X509_GUID, SHIM_LOCK_GUID + payload)
    return _validate_signature_lists(payload)


def _empty_mok_list_x() -> bytes:
    """Build shim's placeholder MokListX used without a vendor denylist."""
    # Shim represents an empty denylist with one all-zero SHA-256 entry.
    return _signature_list(
        EFI_CERT_SHA256_GUID,
        SHIM_LOCK_GUID + bytes(32),
    )


def _vendor_mok_data(shim: bytes) -> tuple[bytes, bytes]:
    """Extract shim's built-in MokList and MokListX data."""
    with lief.logging.level_scope(lief.logging.LEVEL.OFF):
        binary = lief.PE.parse(shim)
    if binary is None:
        raise ValueError("shim is not a valid PE image")

    for section in binary.sections:
        data = bytes(section.content)
        if len(data) < 16:
            continue

        fields = struct.unpack_from("<IIII", data)
        # Shim's vendor table describes the built-in allowlist and denylist.
        authorized_size, deauthorized_size = fields[:2]
        authorized_offset, deauthorized_offset = fields[2:]
        if (not authorized_size or authorized_offset != 16
                or authorized_offset + authorized_size > len(data)):
            continue

        authorized = data[
            authorized_offset:authorized_offset + authorized_size
        ]
        if deauthorized_size:
            if (deauthorized_offset < 16
                    or deauthorized_offset + deauthorized_size > len(data)):
                raise ValueError("shim contains invalid deauthorized certificate data")
            deauthorized = _validate_signature_lists(data[
                deauthorized_offset:deauthorized_offset + deauthorized_size
            ])
        else:
            deauthorized = _empty_mok_list_x()

        return _authorized_mok_data(authorized), deauthorized

    raise RuntimeError("could not find shim's vendor certificate table")


def mok_digests(shim: bytes) -> list[bytes]:
    """Return shim's MokList, MokListX, and MokListTrusted event digests."""
    mok_list, mok_list_x = _vendor_mok_data(shim)
    # These are individual event hashes. bootchain.py extends them into RTMR2.
    return [
        hashlib.sha384(mok_list).digest(),
        hashlib.sha384(mok_list_x).digest(),
        MOK_LIST_TRUSTED_DIGEST,
    ]
