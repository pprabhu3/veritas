"""Predict RTMR1 for a UEFI disk boot."""

import hashlib
import shutil
import subprocess
import tempfile
from pathlib import Path

from veritas.tcg.gpt import partition_table_event
from veritas.tcg.pe import authenticode_digest

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


def measure_rtmr1(image: Path, disk_size: int | None = None) -> bytes:
    """Predict RTMR1 by replaying the expected EFI boot measurements."""
    digests = [
        hashlib.sha384(b"Calling EFI Application from Boot Option").digest(),
        hashlib.sha384(bytes(4)).digest(),
        hashlib.sha384(partition_table_event(image, disk_size)).digest(),
    ]
    digests.extend(authenticode_digest(data)
                   for data in _download(image, _bootloader_paths(image)))
    digests.extend([
        hashlib.sha384(b"Exit Boot Services Invocation").digest(),
        hashlib.sha384(b"Exit Boot Services Returned with Success").digest(),
    ])

    value = bytes(48)
    for digest in digests:
        value = hashlib.sha384(value + digest).digest()
    return value
