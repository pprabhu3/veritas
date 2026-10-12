"""Reference value extraction for confidential VMs."""

from pathlib import Path

from veritas.models import ReferenceValue
from veritas.platforms.base import PlatformExtractor
from veritas.tcg.bootchain import measure_rtmr1
from veritas.vendor.td_shim_tee_info_hash import compute_mrtd


class CvmExtractor(PlatformExtractor):
    """Extract reference values for confidential VM."""

    def __init__(self, tee: str, ovmf: str | None = None,
                 guest_image: str | None = None,
                 disk_size: int | None = None, **_kwargs):
        """Save and validate the files and disk size used for CVM measurements."""
        if tee != "tdx":
            raise ValueError("The CVM extractor currently supports only TDX")
        self.tee = tee
        self.ovmf = Path(ovmf).resolve() if ovmf else None
        self.guest_image = Path(guest_image).resolve() if guest_image else None
        self.disk_size = disk_size
        if disk_size is not None and self.guest_image is None:
            raise ValueError("disk_size requires a guest image")

    @property
    def platform(self) -> str:
        return "cvm"

    @property
    def evidence_type(self) -> str:
        return self.tee

    def reference_key_names(self) -> set[str]:
        return {"mr_td", "rtmr_1", "xfam"}

    def extract(self) -> list[ReferenceValue]:
        if not self.ovmf:
            raise RuntimeError("--ovmf is required for CVM extraction")
        if not self.ovmf.is_file():
            raise RuntimeError(f"OVMF firmware not found: {self.ovmf}")

        try:
            mr_td = compute_mrtd(str(self.ovmf))
        except (OSError, ValueError) as exc:
            raise RuntimeError(f"Failed to compute mr_td: {exc}") from exc

        values = [ReferenceValue(
            name="mr_td",
            values=[mr_td],
            category="executables",
            description="TD build-time measurement (OVMF/TDVF)",
            algorithm="sha384",
            source=f"TDVF descriptor from {self.ovmf.name}",
        )]

        if self.guest_image:
            if not self.guest_image.is_file():
                raise RuntimeError(f"Guest image not found: {self.guest_image}")
            try:
                rtmr_1 = measure_rtmr1(
                    self.guest_image,
                    disk_size=self.disk_size,
                )
            except (OSError, ValueError) as exc:
                raise RuntimeError(f"Failed to compute rtmr_1: {exc}") from exc
            values.append(ReferenceValue(
                name="rtmr_1",
                values=[rtmr_1.hex()],
                category="executables",
                description="Measured guest boot chain",
                algorithm="sha384",
                source=f"predicted boot chain of {self.guest_image.name}",
            ))

        return values

    def compute_initdata(self, initdata_paths: list[str]) -> ReferenceValue:
        raise RuntimeError("CVM initdata measurement is not implemented yet")
