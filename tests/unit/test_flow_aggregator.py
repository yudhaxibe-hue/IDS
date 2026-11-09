"""
Unit tests for BidirectionalFlowAggregator and feature calculation.
"""
import pytest
import time
from monitoring.flow_processing.aggregator import BidirectionalFlowAggregator


def test_flow_aggregation_bidirectional_exchange():
    """Verify forward and backward packet aggregation into single 5-tuple flow."""
    completed_flows = []
    agg = BidirectionalFlowAggregator(
        inactivity_timeout=5.0,
        active_timeout=60.0,
        on_flow_complete=lambda f: completed_flows.append(f)
    )

    t0 = 1000.0
    # Packet 1 (Forward: Client -> Server SYN)
    agg.process_packet(
        src_ip="192.168.1.10",
        dst_ip="93.184.216.34",
        src_port=54321,
        dst_port=80,
        protocol="TCP",
        pkt_len=64,
        timestamp=t0,
        tcp_flags={"SYN": True},
        tcp_window=65535
    )

    # Packet 2 (Backward: Server -> Client SYN+ACK)
    agg.process_packet(
        src_ip="93.184.216.34",
        dst_ip="192.168.1.10",
        src_port=80,
        dst_port=54321,
        protocol="TCP",
        pkt_len=64,
        timestamp=t0 + 0.05,
        tcp_flags={"SYN": True, "ACK": True},
        tcp_window=32768
    )

    # Packet 3 (Forward: Client -> Server ACK+Data)
    agg.process_packet(
        src_ip="192.168.1.10",
        dst_ip="93.184.216.34",
        src_port=54321,
        dst_port=80,
        protocol="TCP",
        pkt_len=512,
        timestamp=t0 + 0.10,
        tcp_flags={"ACK": True, "PSH": True}
    )

    # Packet 4 (Forward: Client -> Server FIN)
    agg.process_packet(
        src_ip="192.168.1.10",
        dst_ip="93.184.216.34",
        src_port=54321,
        dst_port=80,
        protocol="TCP",
        pkt_len=64,
        timestamp=t0 + 0.20,
        tcp_flags={"FIN": True, "ACK": True}
    )

    # Packet 5 (Backward: Server -> Client FIN - triggers flow termination)
    finished_flow = agg.process_packet(
        src_ip="93.184.216.34",
        dst_ip="192.168.1.10",
        src_port=80,
        dst_port=54321,
        protocol="TCP",
        pkt_len=64,
        timestamp=t0 + 0.25,
        tcp_flags={"FIN": True, "ACK": True}
    )

    assert finished_flow is not None
    assert finished_flow["src_ip"] == "192.168.1.10"
    assert finished_flow["dst_ip"] == "93.184.216.34"
    assert finished_flow["tot_fwd_pkts"] == 3
    assert finished_flow["tot_bwd_pkts"] == 2
    assert finished_flow["tot_fwd_bytes"] == 64 + 512 + 64
    assert finished_flow["tot_bwd_bytes"] == 64 + 64
    assert finished_flow["syn_flag_cnt"] == 2
    assert finished_flow["fin_flag_cnt"] == 2
    assert finished_flow["init_win_bytes_fwd"] == 65535
    assert finished_flow["init_win_bytes_bwd"] == 32768

    # Verify no raw payload was retained
    assert "payload" not in finished_flow
    assert "raw_data" not in finished_flow


def test_flow_inactivity_timeout():
    """Verify flow flushes automatically when inactivity timeout is reached."""
    agg = BidirectionalFlowAggregator(inactivity_timeout=2.0)
    t0 = 1000.0

    agg.process_packet("10.0.0.1", "10.0.0.2", 1234, 80, "TCP", 100, timestamp=t0)
    assert len(agg.active_flows) == 1

    # Before timeout
    expired = agg.check_timeouts(current_time=t0 + 1.0)
    assert len(expired) == 0
    assert len(agg.active_flows) == 1

    # After timeout
    expired = agg.check_timeouts(current_time=t0 + 2.5)
    assert len(expired) == 1
    assert len(agg.active_flows) == 0
    assert expired[0]["src_ip"] == "10.0.0.1"
