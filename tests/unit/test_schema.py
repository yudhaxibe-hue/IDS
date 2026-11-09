"""
Unit tests for Canonical Feature Schema V1 and data validation.
"""
import pytest
import numpy as np
import pandas as pd

from core.preprocessing.schema import (
    CanonicalFeatureSchema,
    FEATURE_NAMES,
    CANONICAL_FEATURES,
    ATTACK_TAXONOMY
)


def test_schema_feature_count():
    """Verify exact count and ordering of canonical flow features."""
    assert len(FEATURE_NAMES) == 28
    assert len(CANONICAL_FEATURES) == 28
    assert FEATURE_NAMES[0] == "flow_duration"
    assert FEATURE_NAMES[-1] == "init_win_bytes_bwd"


def test_schema_validation_and_clean():
    """Verify handling of missing columns, NaNs, and infinities."""
    raw_df = pd.DataFrame([{
        "flow_duration": np.inf,
        "tot_fwd_pkts": np.nan,
        "unrelated_payload_column": "ATTACK_PAYLOAD"
    }])

    cleaned = CanonicalFeatureSchema.validate_and_clean(raw_df)

    # Must contain exactly the canonical columns
    assert list(cleaned.columns) == FEATURE_NAMES
    assert "unrelated_payload_column" not in cleaned.columns

    # Infinities must be clipped to feature bounds
    assert cleaned["flow_duration"].iloc[0] == 86400.0

    # NaNs filled with default values
    assert cleaned["tot_fwd_pkts"].iloc[0] == 1.0


def test_schema_vector_transformation():
    """Verify conversion of single flow dictionary to 2D numpy array."""
    flow = {
        "flow_duration": 1.25,
        "tot_fwd_pkts": 5,
        "tot_bwd_pkts": 4,
        "tot_fwd_bytes": 500,
        "tot_bwd_bytes": 1200
    }
    vec = CanonicalFeatureSchema.validate_vector(flow)
    assert isinstance(vec, np.ndarray)
    assert vec.shape == (1, 28)
    assert vec[0, 0] == 1.25
