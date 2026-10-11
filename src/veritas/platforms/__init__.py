"""Platform extractors registry."""

from veritas.platforms.azure import AzureExtractor
from veritas.platforms.baremetal import BaremetalExtractor
from veritas.platforms.cvm import CvmExtractor

EXTRACTORS = {
    "azure": AzureExtractor,
    "baremetal": BaremetalExtractor,
    "cvm": CvmExtractor,
}
