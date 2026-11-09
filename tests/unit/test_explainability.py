"""
Unit tests for Explainable AI (SHAP TreeExplainer) and plain-language summaries.
"""
import pytest
from core.detection.detector import ThreatDetector
from core.explainability.explainer import IDSExplainer, ExplanationResult


@pytest.fixture
def detector_and_explainer():
    det = ThreatDetector()
    assert det.is_loaded
    expl = IDSExplainer(det.classifier)
    assert expl.is_initialized
    return det, expl


def test_explainer_on_dos_threat(detector_and_explainer):
    """Verify SHAP explanation on high-volume DoS event."""
    det, expl = detector_and_explainer
    dos_flow = {
        "flow_duration": 0.5,
        "tot_fwd_pkts": 800,
        "tot_bwd_pkts": 2,
        "tot_fwd_bytes": 48000,
        "tot_bwd_bytes": 80,
        "fwd_pkt_len_mean": 60.0,
        "bwd_pkt_len_mean": 40.0,
        "flow_bytes_per_sec": 96160.0,
        "flow_pkts_per_sec": 1604.0,
        "syn_flag_cnt": 500,
        "fin_flag_cnt": 0,
        "init_win_bytes_fwd": 1024,
        "init_win_bytes_bwd": 0
    }
    detection = det.predict_flow(dos_flow)
    assert detection.is_malicious is True

    result = expl.explain_prediction(detection, top_k=5)
    assert result.is_available is True
    assert result.predicted_category == "DoS / DDoS"
    assert len(result.top_features) == 5
    assert result.computation_time_ms > 0.0

    # Ensure plain-language summary describes the attack category honestly
    assert "DoS / DDoS" in result.summary
    assert "The most significant contributing factor" in result.summary

    # Ensure top feature has physical meaning
    top_feature = result.top_features[0]
    assert len(top_feature.display_name) > 0
    assert top_feature.attribution != 0.0


def test_explainer_on_normal_flow(detector_and_explainer):
    """Verify SHAP explanation on benign network flow."""
    det, expl = detector_and_explainer
    normal_flow = {
        "flow_duration": 3.0,
        "tot_fwd_pkts": 10,
        "tot_bwd_pkts": 12,
        "tot_fwd_bytes": 2000,
        "tot_bwd_bytes": 7000,
        "fwd_pkt_len_mean": 200.0,
        "bwd_pkt_len_mean": 583.0,
        "syn_flag_cnt": 1,
        "fin_flag_cnt": 1,
        "init_win_bytes_fwd": 65535,
        "init_win_bytes_bwd": 65535
    }
    detection = det.predict_flow(normal_flow)
    assert detection.is_malicious is False

    result = expl.explain_prediction(detection, top_k=5)
    assert result.is_available is True
    assert result.predicted_category == "Normal"
    assert "Normal network traffic" in result.summary
    assert len(result.top_features) == 5


def test_explainer_uninitialized_fallback():
    """Verify honest error reporting when explainer is not initialized."""
    uninit_expl = IDSExplainer()
    assert not uninit_expl.is_initialized

    # Fake detection object
    from unittest.mock import MagicMock
    mock_detection = MagicMock()
    mock_detection.attack_category = "DoS / DDoS"
    mock_detection.confidence_score = 0.95

    res = uninit_expl.explain_prediction(mock_detection)
    assert res.is_available is False
    assert "unavailable" in res.summary.lower()
    assert res.failure_reason == "Explainer uninitialized"
