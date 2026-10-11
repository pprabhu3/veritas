"""Reference value extraction for confidential VMs."""

from veritas.models import ReferenceValue
from veritas.platforms.base import PlatformExtractor


class CvmExtractor(PlatformExtractor):
    """Extract reference values for confidential VM."""

    def __init__(self, tee: str, **_kwargs):
        if tee != "tdx":
            raise ValueError("The CVM extractor currently supports only TDX")
        self.tee = tee

    @property
    def platform(self) -> str:
        return "cvm"

    @property
    def evidence_type(self) -> str:
        return self.tee

    def reference_key_names(self) -> set[str]:
        return {"mr_td", "rtmr_1", "rtmr_2", "init_data", "xfam"}

    def extract(self) -> list[ReferenceValue]:
        raise RuntimeError("CVM extraction is not implemented yet")

    def compute_initdata(self, initdata_paths: list[str]) -> ReferenceValue:
        raise RuntimeError("CVM initdata measurement is not implemented yet")
