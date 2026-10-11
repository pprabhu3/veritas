"""Unit tests for the KubeVirt CVM extractor."""

import pytest

from veritas.platforms.cvm import CvmExtractor


def test_cvm_extractor_rejects_unsupported_tee():
    with pytest.raises(ValueError, match="only TDX"):
        CvmExtractor("snp")
