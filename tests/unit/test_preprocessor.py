"""
Unit tests for FlowPreprocessor normalization and serialization.
"""
import pytest
import numpy as np
import pandas as pd

from core.preprocessing.preprocessor import FlowPreprocessor
from core.preprocessing.schema import FEATURE_NAMES


def test_preprocessor_fit_transform():
    """Verify preprocessor fits and transforms tabular data."""
    df = pd.DataFrame([{
        name: float(idx + 1) for idx, name in enumerate(FEATURE_NAMES)
    }, {
        name: float((idx + 1) * 2) for idx, name in enumerate(FEATURE_NAMES)
    }])

    preprocessor = FlowPreprocessor()
    assert not preprocessor.is_fitted

    matrix = preprocessor.fit_transform(df)
    assert preprocessor.is_fitted
    assert matrix.shape == (2, len(FEATURE_NAMES))
    assert not np.isnan(matrix).any()


def test_preprocessor_serialization():
    """Verify roundtrip state serialization and deserialization."""
    df = pd.DataFrame([{name: float(i) for i, name in enumerate(FEATURE_NAMES)}])
    p1 = FlowPreprocessor()
    p1.fit(df)

    serialized = p1.to_dict()
    p2 = FlowPreprocessor.from_dict(serialized)

    assert p2.is_fitted
    assert p2.schema_version == p1.schema_version

    vec = {name: 10.0 for name in FEATURE_NAMES}
    out1 = p1.transform_single(vec)
    out2 = p2.transform_single(vec)
    np.testing.assert_array_almost_equal(out1, out2)
