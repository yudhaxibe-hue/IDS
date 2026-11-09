"""
Unit tests for OfflineReplayEngine simulation stream.
"""
import pytest
import time
from monitoring.flow_processing.replay_engine import OfflineReplayEngine


def test_offline_replay_emission():
    """Verify replay engine streams flows with mode='demo' and cleans up."""
    received_flows = []
    engine = OfflineReplayEngine(
        flow_callback=lambda f: received_flows.append(f),
        flows_per_second=10.0
    )

    assert not engine.is_running
    engine.start()
    assert engine.is_running

    # Wait for a few flows to emit
    time.sleep(0.4)
    engine.stop()
    assert not engine.is_running

    assert len(received_flows) >= 2
    for flow in received_flows:
        assert flow["mode"] == "demo"
        assert "flow_duration" in flow
        assert "tot_fwd_pkts" in flow
        assert "src_ip" in flow
        assert "dst_ip" in flow
