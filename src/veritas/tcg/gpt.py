"""Build the GPT event data that UEFI measures into RTMR1 for a guest disk."""

import logging
import shutil
import struct
import subprocess
import zlib
from pathlib import Path

log = logging.getLogger(__name__)

SECTOR_SIZE = 512
HEADER_SIZE = 92
ENTRY_SIZE = 128
# Protective MBR + header + the standard 128-entry partition array.
GPT_REGION_SIZE = SECTOR_SIZE * 34
GPT_SIGNATURE = b"EFI PART"

# Offsets within EFI_PARTITION_TABLE_HEADER.
_HEADER_CRC = 16
_HEADER_SIZE = 12
_CURRENT_LBA = 24
_ALTERNATE_LBA = 32
_FIRST_USABLE_LBA = 40
_LAST_USABLE_LBA = 48
_ENTRY_LBA = 72
_NUM_ENTRIES = 80
_ENTRY_SIZE = 84
_ENTRY_ARRAY_CRC = 88


def read_disk_head(image: Path, size: int = GPT_REGION_SIZE) -> bytes:
    """Read the GPT area from either a raw or qcow2 guest disk image."""
    with image.open("rb") as handle:
        head = handle.read(size)
    if head[:4] != b"QFI\xfb":
        return head

    if not shutil.which("guestfish"):
        raise RuntimeError("guestfish is required; install libguestfs-tools")
    devices = subprocess.run(
        ["guestfish", "--ro", "-a", str(image), "run", ":", "list-devices"],
        capture_output=True, text=True,
    )
    if devices.returncode != 0:
        raise RuntimeError(
            f"guestfish could not open {image.name}: {devices.stderr.strip()}"
        )
    if not devices.stdout.strip():
        raise RuntimeError(f"guestfish found no block device in {image.name}")
    device = devices.stdout.strip().splitlines()[0]
    result = subprocess.run(
        ["guestfish", "--ro", "-a", str(image), "run", ":",
         "pread-device", device, str(size), "0"],
        capture_output=True,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"could not read the partition table from {image.name}: "
            f"{result.stderr.decode(errors='replace').strip()}"
        )
    return result.stdout


def gpt_event_data(disk_head: bytes) -> bytes:
    """Validate a GPT and encode the partition data that UEFI measures."""
    if len(disk_head) < SECTOR_SIZE + HEADER_SIZE:
        raise RuntimeError("guest image is too small to contain a GPT header")
    header = disk_head[SECTOR_SIZE:SECTOR_SIZE + HEADER_SIZE]
    if header[:8] != GPT_SIGNATURE:
        raise RuntimeError(
            "guest image has no GPT partition table; only GPT disks are "
            "measured into RTMR1"
        )
    header_size = struct.unpack_from("<I", header, _HEADER_SIZE)[0]
    if header_size != HEADER_SIZE:
        raise RuntimeError(f"unsupported GPT header size {header_size}")
    if struct.unpack_from("<Q", header, _CURRENT_LBA)[0] != 1:
        raise RuntimeError("primary GPT header is not at LBA 1")

    stored_header_crc = struct.unpack_from("<I", header, _HEADER_CRC)[0]
    crc_header = bytearray(header)
    struct.pack_into("<I", crc_header, _HEADER_CRC, 0)
    if zlib.crc32(crc_header) & 0xFFFFFFFF != stored_header_crc:
        raise RuntimeError("GPT header checksum is invalid")

    entry_lba = struct.unpack_from("<Q", header, _ENTRY_LBA)[0]
    count, entry_size = struct.unpack_from("<II", header, _NUM_ENTRIES)
    if entry_lba != 2 or count != 128 or entry_size != ENTRY_SIZE:
        raise RuntimeError("only the standard 128-entry GPT layout is supported")
    array_start = entry_lba * SECTOR_SIZE
    array_size = count * entry_size
    array = disk_head[array_start:array_start + array_size]
    if len(array) != array_size:
        raise RuntimeError("GPT partition entry array is truncated")
    stored_array_crc = struct.unpack_from("<I", header, _ENTRY_ARRAY_CRC)[0]
    if zlib.crc32(array) & 0xFFFFFFFF != stored_array_crc:
        raise RuntimeError("GPT partition entry checksum is invalid")
    used = [
        array[i * entry_size:(i + 1) * entry_size]
        for i in range(count)
        if array[i * entry_size:i * entry_size + 16] != bytes(16)
    ]
    first_usable = struct.unpack_from("<Q", header, _FIRST_USABLE_LBA)[0]
    last_usable = struct.unpack_from("<Q", header, _LAST_USABLE_LBA)[0]
    for entry in used:
        first, last = struct.unpack_from("<QQ", entry, 32)
        if first < first_usable or first > last or last > last_usable:
            raise RuntimeError("GPT contains an invalid partition range")
    return header + struct.pack("<Q", len(used)) + b"".join(used)


def resize_gpt_event(event: bytes, total_sectors: int) -> bytes:
    """Model a GPT that was expanded to a new disk size before boot."""
    header = bytearray(event[:HEADER_SIZE])
    count = struct.unpack_from("<Q", event, HEADER_SIZE)[0]
    entry_size = struct.unpack_from("<I", header, _ENTRY_SIZE)[0]
    entries = bytearray(event[HEADER_SIZE + 8:])
    if count == 0:
        raise RuntimeError("GPT has no partitions to resize")
    if total_sectors < 68 or total_sectors > 2**64 - 1:
        raise ValueError("deployed disk size is outside GPT limits")

    last_usable = total_sectors - 34
    partition = max(range(count), key=lambda index: struct.unpack_from(
        "<Q", entries, index * entry_size + 40)[0])
    first_lba = struct.unpack_from("<Q", entries, partition * entry_size + 32)[0]
    if first_lba >= last_usable:
        raise RuntimeError(
            f"disk of {total_sectors} sectors is too small for this image's "
            f"partition layout (last partition starts at LBA {first_lba})"
        )
    struct.pack_into("<Q", header, _ALTERNATE_LBA, total_sectors - 1)
    struct.pack_into("<Q", header, _LAST_USABLE_LBA, last_usable)
    struct.pack_into("<Q", entries, partition * entry_size + 40, last_usable)

    # The array CRC covers the full declared entry array, not just the
    # entries that are in use.
    declared = struct.unpack_from("<I", header, _NUM_ENTRIES)[0]
    padding = bytes((declared - count) * entry_size)
    struct.pack_into("<I", header, _ENTRY_ARRAY_CRC,
                     zlib.crc32(bytes(entries) + padding) & 0xFFFFFFFF)
    struct.pack_into("<I", header, _HEADER_CRC, 0)
    struct.pack_into("<I", header, _HEADER_CRC,
                     zlib.crc32(bytes(header)) & 0xFFFFFFFF)
    return bytes(header) + struct.pack("<Q", count) + bytes(entries)


def partition_table_event(image: Path, disk_size_bytes: int | None = None) -> bytes:
    """Return the GPT bytes that UEFI is expected to measure for this disk."""
    event = gpt_event_data(read_disk_head(image))
    if disk_size_bytes is None:
        return event
    if disk_size_bytes <= 0 or disk_size_bytes % SECTOR_SIZE:
        raise ValueError("disk size must be positive and divisible by 512")
    sectors = disk_size_bytes // SECTOR_SIZE
    image_sectors = struct.unpack_from("<Q", event, _LAST_USABLE_LBA)[0] + 34
    if sectors < image_sectors:
        raise ValueError("deployed disk cannot be smaller than the guest image")
    if sectors == image_sectors:
        return event
    log.info("Modelling a %.1f GiB volume (image's own table covers %.1f GiB)",
             disk_size_bytes / 1024 ** 3, image_sectors * SECTOR_SIZE / 1024 ** 3)
    return resize_gpt_event(event, sectors)
