"""
Bidirectional Network Flow Aggregation Engine for Explainable Adaptive IDS.
Converts packet streams into completed bidirectional flow records adhering strictly
to Canonical Feature Schema V1 without inspecting or storing packet payloads.
"""
from dataclasses import dataclass, field
from datetime import datetime
import math
import time
from typing import Dict, Any, List, Optional, Tuple, Callable
import logging
import numpy as np

logger = logging.getLogger("IDS.FlowAggregator")


@dataclass
class FlowRecord:
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    start_time: float
    last_seen: float
    
    # Packet & Byte counters
    fwd_pkts: int = 0
    bwd_pkts: int = 0
    fwd_bytes: int = 0
    bwd_bytes: int = 0
    
    # Packet lengths
    fwd_lens: List[int] = field(default_factory=list)
    bwd_lens: List[int] = field(default_factory=list)
    
    # Timing
    packet_times: List[float] = field(default_factory=list)
    
    # TCP Flags
    fin_cnt: int = 0
    syn_cnt: int = 0
    rst_cnt: int = 0
    psh_cnt: int = 0
    ack_cnt: int = 0
    urg_cnt: int = 0
    
    # Window sizes
    init_win_fwd: int = 0
    init_win_bwd: int = 0


class BidirectionalFlowAggregator:
    """Aggregates observed network packets into bidirectional 5-tuple flow statistics."""

    def __init__(
        self,
        inactivity_timeout: float = 15.0,
        active_timeout: float = 120.0,
        max_active_flows: int = 5000,
        on_flow_complete: Optional[Callable[[Dict[str, Any]], None]] = None
    ):
        self.inactivity_timeout = inactivity_timeout
        self.active_timeout = active_timeout
        self.max_active_flows = max_active_flows
        self.on_flow_complete = on_flow_complete
        
        # Key: (ip_a, ip_b, port_a, port_b, proto)
        self.active_flows: Dict[Tuple, FlowRecord] = {}

    def _normalize_key(self, src_ip: str, dst_ip: str, src_port: int, dst_port: int, proto: str) -> Tuple:
        """Create canonical bidirectional 5-tuple key."""
        if (src_ip, src_port) <= (dst_ip, dst_port):
            return (src_ip, dst_ip, src_port, dst_port, proto)
        return (dst_ip, src_ip, dst_port, src_port, proto)

    def process_packet(
        self,
        src_ip: str,
        dst_ip: str,
        src_port: int,
        dst_port: int,
        protocol: str,
        pkt_len: int,
        timestamp: Optional[float] = None,
        tcp_flags: Optional[Dict[str, bool]] = None,
        tcp_window: int = 0
    ) -> Optional[Dict[str, Any]]:
        """
        Ingest a packet header and update flow state.
        Returns completed flow dictionary if this packet triggered flow termination.
        """
        now = timestamp if timestamp is not None else time.time()
        key = self._normalize_key(src_ip, dst_ip, src_port, dst_port, protocol)
        flags = tcp_flags or {}

        # Evict oldest flow if queue exceeds bounds
        if len(self.active_flows) >= self.max_active_flows and key not in self.active_flows:
            self._evict_oldest_flow(now)

        if key not in self.active_flows:
            # Initialize new forward-oriented flow
            flow = FlowRecord(
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                protocol=protocol,
                start_time=now,
                last_seen=now,
                init_win_fwd=tcp_window
            )
            self.active_flows[key] = flow
        else:
            flow = self.active_flows[key]

        # Determine packet direction
        is_forward = (src_ip == flow.src_ip and src_port == flow.src_port)

        if is_forward:
            flow.fwd_pkts += 1
            flow.fwd_bytes += pkt_len
            flow.fwd_lens.append(pkt_len)
        else:
            flow.bwd_pkts += 1
            flow.bwd_bytes += pkt_len
            flow.bwd_lens.append(pkt_len)
            if flow.init_win_bwd == 0 and tcp_window > 0:
                flow.init_win_bwd = tcp_window

        flow.packet_times.append(now)
        flow.last_seen = now

        # Update TCP flags
        if flags.get("FIN"): flow.fin_cnt += 1
        if flags.get("SYN"): flow.syn_cnt += 1
        if flags.get("RST"): flow.rst_cnt += 1
        if flags.get("PSH"): flow.psh_cnt += 1
        if flags.get("ACK"): flow.ack_cnt += 1
        if flags.get("URG"): flow.urg_cnt += 1

        # Check for immediate TCP connection teardown
        is_finished = flags.get("RST", False) or (flow.fin_cnt >= 2)
        is_expired = (now - flow.start_time >= self.active_timeout)

        if is_finished or is_expired:
            return self._finalize_flow(key)

        return None

    def check_timeouts(self, current_time: Optional[float] = None) -> List[Dict[str, Any]]:
        """Flush and return any flows exceeding inactivity or active timeouts."""
        now = current_time if current_time is not None else time.time()
        expired_keys: List[Tuple] = []

        for key, flow in self.active_flows.items():
            if (now - flow.last_seen >= self.inactivity_timeout) or (now - flow.start_time >= self.active_timeout):
                expired_keys.append(key)

        results: List[Dict[str, Any]] = []
        for key in expired_keys:
            res = self._finalize_flow(key)
            if res:
                results.append(res)
        return results

    def _finalize_flow(self, key: Tuple) -> Optional[Dict[str, Any]]:
        """Compile statistical flow features and delete from active table."""
        flow = self.active_flows.pop(key, None)
        if not flow:
            return None

        duration = max(0.0001, flow.last_seen - flow.start_time)
        fwd_lens = flow.fwd_lens or [0]
        bwd_lens = flow.bwd_lens or [0]

        # Calculate Inter-Arrival Times
        times = sorted(flow.packet_times)
        if len(times) > 1:
            iats = [times[i] - times[i-1] for i in range(1, len(times))]
            iat_mean = float(np.mean(iats))
            iat_std = float(np.std(iats))
            iat_max = float(np.max(iats))
            iat_min = float(np.min(iats))
        else:
            iat_mean = 0.0
            iat_std = 0.0
            iat_max = 0.0
            iat_min = 0.0

        # Assemble Canonical Feature Dictionary
        feature_dict: Dict[str, Any] = {
            "src_ip": flow.src_ip,
            "dst_ip": flow.dst_ip,
            "src_port": flow.src_port,
            "dst_port": flow.dst_port,
            "protocol": flow.protocol,
            "timestamp": datetime.fromtimestamp(flow.start_time).isoformat() + "Z",
            
            # Canonical features
            "flow_duration": duration,
            "tot_fwd_pkts": flow.fwd_pkts,
            "tot_bwd_pkts": flow.bwd_pkts,
            "tot_fwd_bytes": flow.fwd_bytes,
            "tot_bwd_bytes": flow.bwd_bytes,
            "fwd_pkt_len_max": float(max(fwd_lens)),
            "fwd_pkt_len_min": float(min(fwd_lens)),
            "fwd_pkt_len_mean": float(sum(fwd_lens) / max(1, len(fwd_lens))),
            "fwd_pkt_len_std": float(np.std(fwd_lens)) if len(fwd_lens) > 1 else 0.0,
            "bwd_pkt_len_max": float(max(bwd_lens)) if flow.bwd_pkts > 0 else 0.0,
            "bwd_pkt_len_min": float(min(bwd_lens)) if flow.bwd_pkts > 0 else 0.0,
            "bwd_pkt_len_mean": float(sum(bwd_lens) / max(1, len(bwd_lens))) if flow.bwd_pkts > 0 else 0.0,
            "bwd_pkt_len_std": float(np.std(bwd_lens)) if len(bwd_lens) > 1 else 0.0,
            "flow_bytes_per_sec": float((flow.fwd_bytes + flow.bwd_bytes) / duration),
            "flow_pkts_per_sec": float((flow.fwd_pkts + flow.bwd_pkts) / duration),
            "flow_iat_mean": iat_mean,
            "flow_iat_std": iat_std,
            "flow_iat_max": iat_max,
            "flow_iat_min": iat_min,
            "fin_flag_cnt": flow.fin_cnt,
            "syn_flag_cnt": flow.syn_cnt,
            "rst_flag_cnt": flow.rst_cnt,
            "psh_flag_cnt": flow.psh_cnt,
            "ack_flag_cnt": flow.ack_cnt,
            "urg_flag_cnt": flow.urg_cnt,
            "down_up_ratio": float(flow.bwd_pkts / max(1, flow.fwd_pkts)),
            "init_win_bytes_fwd": flow.init_win_fwd,
            "init_win_bytes_bwd": flow.init_win_bwd
        }

        if self.on_flow_complete:
            try:
                self.on_flow_complete(feature_dict)
            except Exception as exc:
                logger.error(f"Error in on_flow_complete callback: {exc}")

        return feature_dict

    def _evict_oldest_flow(self, current_time: float) -> None:
        """Evict oldest flow to maintain strict memory ceiling."""
        oldest_key = min(self.active_flows.keys(), key=lambda k: self.active_flows[k].last_seen)
        self._finalize_flow(oldest_key)
