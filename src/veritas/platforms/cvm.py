"""Reference value extraction for confidential VMs."""

from pathlib import Path

from veritas.models import ReferenceValue
from veritas.platforms.base import PlatformExtractor
from veritas.vendor.td_shim_tee_info_hash import compute_mrtd


class CvmExtractor(PlatformExtractor):
    """Extract reference values for confidential VM."""

    def __init__(self, tee: str, ovmf: str | None = None, **_kwargs):
        if tee != "tdx":
            raise ValueError("The CVM extractor currently supports only TDX")
        self.tee = tee
        self.ovmf = Path(ovmf).resolve() if ovmf else None

    @property
    def platform(self) -> str:
        return "cvm"

    @property
    def evidence_type(self) -> str:
        return self.tee

    def reference_key_names(self) -> set[str]:
        return {"mr_td", "xfam"}

    def extract(self) -> list[ReferenceValue]:
        if not self.ovmf:
            raise RuntimeError("--ovmf is required for CVM extraction")
        if not self.ovmf.is_file():
            raise RuntimeError(f"OVMF firmware not found: {self.ovmf}")

        try:
            mr_td = compute_mrtd(str(self.ovmf))
        except (OSError, ValueError) as exc:
            raise RuntimeError(f"Failed to compute mr_td: {exc}") from exc

        return [ReferenceValue(
            name="mr_td",
            values=[mr_td],
            category="executables",
            description="TD build-time measurement (OVMF/TDVF)",
            algorithm="sha384",
            source=f"TDVF descriptor from {self.ovmf.name}",
        )]

    def compute_initdata(self, initdata_paths: list[str]) -> ReferenceValue:
        raise RuntimeError("CVM initdata measurement is not implemented yet")
