"""
Unit tests for ThreatDetector classification, confidence calibration, and severity scoring.
"""
import pytest
from core.detection.detector import ThreatDetector


@pytest.fixture
def detector():
    det = ThreatDetector()
    assert det.is_loaded, "ThreatDetector must load the trained baseline model."
    return det


def test_detector_normal_flow(detector):
    """Verify normal benign flow classification."""
    normal_flow = {
        "flow_duration": 2.5,
        "tot_fwd_pkts": 12,
        "tot_bwd_pkts": 14,
        "tot_fwd_bytes": 2400,
        "tot_bwd_bytes": 8500,
        "fwd_pkt_len_mean": 200.0,
        "bwd_pkt_len_mean": 607.0,
        "flow_bytes_per_sec": 4360.0,
        "flow_pkts_per_sec": 10.4,
        "syn_flag_cnt": 1,
        "fin_flag_cnt": 1,
        "init_win_bytes_fwd": 65535,
        "init_win_bytes_bwd": 65535
    }
    result = detector.predict_flow(normal_flow)
    assert result.is_malicious is False
    assert result.attack_category == "Normal"
    assert result.confidence_score >= 0.50
    assert result.severity == "Informational"


def test_detector_dos_flow(detector):
    """Verify DoS / DDoS high-rate flow classification."""
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
    result = detector.predict_flow(dos_flow)
    assert result.is_malicious is True
    assert result.attack_category == "DoS / DDoS"
    assert result.confidence_score >= 0.70
    assert result.severity in ("High", "Critical")


def test_detector_portscan_flow(detector):
    """Verify Portscan single-packet flow classification."""
    scan_flow = {
        "flow_duration": 0.002,
        "tot_fwd_pkts": 1,
        "tot_bwd_pkts": 0,
        "tot_fwd_bytes": 44,
        "tot_bwd_bytes": 0,
        "fwd_pkt_len_mean": 44.0,
        "bwd_pkt_len_mean": 0.0,
        "syn_flag_cnt": 1,
        "fin_flag_cnt": 0,
        "init_win_bytes_fwd": 1024,
        "init_win_bytes_bwd": 0
    }
    result = detector.predict_flow(scan_flow)
    assert result.is_malicious is True
    assert result.attack_category == "Portscan"
    assert result.confidence_score >= 0.70
    assert result.severity in ("Medium", "Low")
