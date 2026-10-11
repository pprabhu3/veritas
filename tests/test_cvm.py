"""Unit tests for the KubeVirt CVM extractor."""

import pytest

from veritas.platforms import EXTRACTORS
from veritas.platforms.cvm import CvmExtractor


def test_cvm_extractor_is_registered():
    extractor = EXTRACTORS["cvm"]("tdx")

    with pytest.raises(RuntimeError, match="CVM extraction is not implemented yet"):
        extractor.extract()


def test_cvm_extractor_rejects_unsupported_tee():
    with pytest.raises(ValueError, match="only TDX"):
        CvmExtractor("snp")
