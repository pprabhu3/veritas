"""Predict RTMR values for a UEFI disk boot."""

import hashlib
import shutil
import subprocess
import tempfile
from pathlib import Path

from veritas.tcg.gpt import partition_table_event
from veritas.tcg.pe import authenticode_digest
from veritas.tcg.shim import mok_digests

ESP = "/boot/efi/EFI"


def _guestfish(image: Path, *commands: str) -> subprocess.CompletedProcess:
    """Run guestfish commands that inspect the guest disk without changing it."""
    if not shutil.which("guestfish"):
        raise RuntimeError("guestfish is required; install libguestfs-tools")
    return subprocess.run(
        ["guestfish", "--ro", "-a", str(image), "-i", *commands],
        capture_output=True, text=True,
    )


def _bootloader_paths(image: Path) -> list[str]:
    """Find the EFI programs that a fresh KubeVirt VM is expected to start."""
    result = _guestfish(image, "find", ESP)
    if result.returncode != 0:
        raise RuntimeError(f"could not inspect {image.name}: {result.stderr.strip()}")

    entries = {line.strip().lstrip("/") for line in result.stdout.splitlines()}
    vendors = sorted({entry.split("/")[0] for entry in entries
                      if entry.endswith("/shimx64.efi")
                      and not entry.upper().startswith("BOOT/")})
    if len(vendors) != 1:
        raise RuntimeError("guest image must contain exactly one vendor shim")
    vendor = vendors[0]
    if f"{vendor}/grubx64.efi" not in entries:
        raise RuntimeError("guest image must contain a vendor shim and GRUB")

    return [
        f"{ESP}/BOOT/BOOTX64.EFI",
        f"{ESP}/BOOT/fbx64.efi",
        f"{ESP}/{vendor}/shimx64.efi",
        f"{ESP}/{vendor}/grubx64.efi",
    ]


def _download(image: Path, paths: list[str]) -> list[bytes]:
    """Read the selected EFI programs from the guest image into memory."""
    with tempfile.TemporaryDirectory() as tmpdir:
        destinations = [Path(tmpdir) / str(index) for index in range(len(paths))]
        commands = []
        for source, destination in zip(paths, destinations):
            commands.extend(["download", source, str(destination), ":"])
        result = _guestfish(image, *commands[:-1])
        if result.returncode != 0:
            raise RuntimeError(
                f"could not extract bootloaders from {image.name}: "
                f"{result.stderr.strip()}"
            )
        return [path.read_bytes() for path in destinations]


def _extend(digests: list[bytes]) -> bytes:
    """Replay a list of SHA-384 event digests into an RTMR value."""
    value = bytes(48)
    for digest in digests:
        if len(digest) != 48:
            raise ValueError("RTMR event digest must contain 48 bytes")
        value = hashlib.sha384(value + digest).digest()
    return value


def _measure_rtmr1(image: Path, disk_size: int | None,
                   programs: list[bytes]) -> bytes:
    """Replay the GPT and EFI application events into RTMR1."""
    digests = [
        hashlib.sha384(b"Calling EFI Application from Boot Option").digest(),
        hashlib.sha384(bytes(4)).digest(),
        hashlib.sha384(partition_table_event(image, disk_size)).digest(),
    ]
    digests.extend(authenticode_digest(data)
                   for data in programs)
    digests.extend([
        hashlib.sha384(b"Exit Boot Services Invocation").digest(),
        hashlib.sha384(b"Exit Boot Services Returned with Success").digest(),
    ])

    return _extend(digests)


def measure_rtmr1(image: Path, disk_size: int | None = None) -> bytes:
    """Predict RTMR1 by replaying the expected EFI boot measurements."""
    programs = _download(image, _bootloader_paths(image))
    return _measure_rtmr1(image, disk_size, programs)


def measure_rtmrs(image: Path, disk_size: int | None = None) -> tuple[bytes, bytes]:
    """Predict RTMR1 and shim's RTMR2 MOK measurements in one image scan."""
    programs = _download(image, _bootloader_paths(image))
    rtmr_1 = _measure_rtmr1(image, disk_size, programs)
    # A fresh vm boot runs shim twice: first as BOOTX64.EFI and then from
    # the distro directory. Each shim measures its MOK allowlist, denylist, and
    # trust flag, so all six event hashes are extended into RTMR2 in boot order.
    rtmr_2 = _extend(
        mok_digests(programs[0])
        + mok_digests(programs[2])
    )
    return rtmr_1, rtmr_2
