"""
Unit tests for Concept Drift Detection (KS test) and Model Registry / Rollback.
"""
from pathlib import Path
import pytest
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier

from core.adaptation.drift_detector import DistributionDriftDetector, MONITORED_FEATURES
from core.adaptation.model_registry import ModelAdaptationRegistry
from datasets.manager.dataset_manager import generate_benchmark_dataset
from core.preprocessing.preprocessor import FlowPreprocessor


@pytest.fixture
def baseline_data():
    return generate_benchmark_dataset(num_samples=400, random_state=42)


def test_drift_detector_stationary(baseline_data):
    """Verify stationary traffic does not produce false drift alarms."""
    detector = DistributionDriftDetector(
        baseline_df=baseline_data,
        window_size=150,
        min_samples=40,
        p_value_threshold=0.01,
        ks_stat_threshold=0.20
    )

    # Feed identical distribution flows
    stationary_flows = generate_benchmark_dataset(num_samples=60, random_state=43).to_dict("records")
    for flow in stationary_flows:
        detector.add_observation(flow)

    report = detector.evaluate_drift()
    assert report.status == "STABLE"
    assert report.drifted_features_count == 0


def test_drift_detector_detects_shift(baseline_data):
    """Verify significant feature distribution shift triggers DRIFT_DETECTED."""
    detector = DistributionDriftDetector(
        baseline_df=baseline_data,
        window_size=150,
        min_samples=40,
        p_value_threshold=0.01,
        ks_stat_threshold=0.20
    )

    # Feed anomalous distribution: extreme packet rate, tiny packets, high SYN flags
    shifted_flows = []
    for _ in range(60):
        shifted_flows.append({
            "flow_duration": 0.005,
            "tot_fwd_pkts": 5000,
            "fwd_pkt_len_mean": 24.0,
            "flow_bytes_per_sec": 800000.0,
            "flow_pkts_per_sec": 200000.0,
            "flow_iat_mean": 0.00001,
            "syn_flag_cnt": 4500
        })

    for flow in shifted_flows:
        detector.add_observation(flow)

    report = detector.evaluate_drift()
    assert report.status == "DRIFT_DETECTED"
    assert report.drifted_features_count >= 2
    assert len(report.drifted_features) > 0


def test_model_registry_evaluation_and_rollback(tmp_path: Path):
    """Verify candidate evaluation sandbox, version promotion, and safe rollback."""
    test_db = tmp_path / "test_registry.db"
    registry = ModelAdaptationRegistry(db_path=test_db)

    # Setup baseline and validation data
    val_df = generate_benchmark_dataset(num_samples=300, random_state=99)
    preprocessor = FlowPreprocessor()
    X_val_scaled = preprocessor.fit_transform(val_df)
    y_val = val_df["label_category_id"].to_numpy()

    # Train a valid candidate model
    candidate_clf = RandomForestClassifier(n_estimators=30, random_state=42)
    candidate_clf.fit(X_val_scaled, y_val)
    candidate_artifact = {
        "classifier": candidate_clf,
        "preprocessor": preprocessor.to_dict()
    }

    # Evaluate candidate
    acceptable, metrics = registry.evaluate_candidate(
        candidate_artifact,
        val_df,
        min_f1_threshold=0.90,
        max_fpr_threshold=0.05
    )
    assert acceptable is True
    assert metrics["is_acceptable"] is True

    # Promote candidate to v1.1.0-adaptive
    promoted = registry.promote_candidate("v1.1.0-adaptive", candidate_artifact, metrics)
    assert promoted is True

    active = registry.get_active_version()
    assert active["version"] == "v1.1.0-adaptive"
    assert active["is_active"] == 1

    # Execute rollback
    restored_version = registry.rollback()
    assert restored_version == "v1.0.0-baseline"

    active_after_rollback = registry.get_active_version()
    assert active_after_rollback["version"] == "v1.0.0-baseline"
