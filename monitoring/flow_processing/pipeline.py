"""
Unified Monitoring and Ingestion Pipeline for Explainable Adaptive IDS.
Bridges Live Packet Capture or Offline Replay Simulation with
Flow Aggregation, Detection, XAI Explanation, Persistence, and Drift Monitoring.
"""
import logging
import platform
import queue
import threading
import time
from typing import Dict, Any, Optional

from app.lifecycle import app_state
from backend.database.db import insert_event
from monitoring.capture.base import BaseCaptureAdapter
from monitoring.macos.capture_macos import MacOSCaptureAdapter
from monitoring.windows.capture_windows import WindowsCaptureAdapter
from monitoring.flow_processing.aggregator import BidirectionalFlowAggregator
from monitoring.flow_processing.replay_engine import OfflineReplayEngine

logger = logging.getLogger("IDS.Pipeline")


class MonitoringPipeline:
    """Central coordinator for network monitoring and ingestion."""

    def __init__(self):
        self.mode = "idle"  # "idle", "live", "demo"
        self.interface: Optional[str] = None
        self._is_active = False
        
        # Adapters
        self.macos_adapter = MacOSCaptureAdapter()
        self.windows_adapter = WindowsCaptureAdapter()
        self.replay_engine: Optional[OfflineReplayEngine] = None
        
        # Flow Aggregator
        self.aggregator = BidirectionalFlowAggregator(
            inactivity_timeout=15.0,
            active_timeout=120.0,
            on_flow_complete=self._on_flow_completed
        )

        # Ingestion queue and worker thread
        self._flow_queue: queue.Queue = queue.Queue(maxsize=1000)
        self._worker_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._timeout_thread: Optional[threading.Thread] = None

    def start(self, mode: str = "demo", interface: Optional[str] = None) -> bool:
        """Start the ingestion pipeline in either 'live' or 'demo' mode."""
        if self._is_active:
            self.stop()

        self.mode = mode
        self.interface = interface or ("en0" if platform.system() == "Darwin" else "Ethernet")
        self._stop_event.clear()

        # Start background processing worker
        self._worker_thread = threading.Thread(target=self._process_queue_loop, daemon=True)
        self._worker_thread.start()

        if mode == "demo":
            logger.info("Initializing pipeline in Offline Replay / Demo Mode...")
            self.replay_engine = OfflineReplayEngine(
                flow_callback=self._enqueue_completed_flow,
                flows_per_second=2.5
            )
            success = self.replay_engine.start()
        else:
            logger.info(f"Initializing pipeline in Live Capture Mode on interface '{self.interface}'...")
            adapter = self._get_platform_adapter()
            success = adapter.start_capture(self.interface, self._on_raw_packet)

            # Start timeout checker thread for live packet flows
            self._timeout_thread = threading.Thread(target=self._timeout_monitor_loop, daemon=True)
            self._timeout_thread.start()

        if success:
            self._is_active = True
            app_state.set_monitoring(True, mode=mode, interface=self.interface)
            logger.info(f"Pipeline running successfully in {mode.upper()} mode.")
            return True
        else:
            self.stop()
            return False

    def stop(self) -> bool:
        """Stop all capture threads, replay engines, and ingestion workers."""
        logger.info("Stopping monitoring pipeline...")
        self._stop_event.set()

        if self.replay_engine and self.replay_engine.is_running:
            self.replay_engine.stop()
            self.replay_engine = None

        adapter = self._get_platform_adapter()
        if adapter.is_running:
            adapter.stop_capture()

        # Flush remaining timeouts
        self.aggregator.check_timeouts()

        self._is_active = False
        app_state.set_monitoring(False, mode="idle")
        logger.info("Pipeline stopped cleanly.")
        return True

    def _get_platform_adapter(self) -> BaseCaptureAdapter:
        """Return OS-appropriate packet capture adapter."""
        if platform.system() == "Darwin":
            return self.macos_adapter
        return self.windows_adapter

    def _on_raw_packet(self, packet: Any) -> None:
        """Scapy packet callback. Extracts headers and forwards to aggregator."""
        try:
            # Check for IP layer without storing payloads
            if not packet.haslayer("IP"):
                return

            ip_layer = packet.getlayer("IP")
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
            proto_num = ip_layer.proto
            pkt_len = len(packet)

            src_port = 0
            dst_port = 0
            tcp_flags = {}
            tcp_window = 0
            proto_str = "IP"

            if packet.haslayer("TCP"):
                proto_str = "TCP"
                tcp = packet.getlayer("TCP")
                src_port = tcp.sport
                dst_port = tcp.dport
                tcp_window = tcp.window
                flags_int = int(tcp.flags)
                tcp_flags = {
                    "FIN": bool(flags_int & 0x01),
                    "SYN": bool(flags_int & 0x02),
                    "RST": bool(flags_int & 0x04),
                    "PSH": bool(flags_int & 0x08),
                    "ACK": bool(flags_int & 0x10),
                    "URG": bool(flags_int & 0x20)
                }
            elif packet.haslayer("UDP"):
                proto_str = "UDP"
                udp = packet.getlayer("UDP")
                src_port = udp.sport
                dst_port = udp.dport

            completed = self.aggregator.process_packet(
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                protocol=proto_str,
                pkt_len=pkt_len,
                timestamp=float(packet.time),
                tcp_flags=tcp_flags,
                tcp_window=tcp_window
            )

            if completed:
                completed["mode"] = "live"
                self._enqueue_completed_flow(completed)

        except Exception as exc:
            logger.debug(f"Error parsing packet: {exc}")

    def _timeout_monitor_loop(self) -> None:
        """Periodic timeout checker flushing expired flows."""
        while not self._stop_event.is_set():
            time.sleep(1.0)
            completed_flows = self.aggregator.check_timeouts()
            for flow in completed_flows:
                flow["mode"] = "live"
                self._enqueue_completed_flow(flow)

    def _on_flow_completed(self, flow: Dict[str, Any]) -> None:
        """Callback from aggregator when a flow expires or is terminated."""
        self._enqueue_completed_flow(flow)

    def _enqueue_completed_flow(self, flow: Dict[str, Any]) -> None:
        """Enqueue completed flow record for inference and persistence."""
        try:
            self._flow_queue.put_nowait(flow)
        except queue.Full:
            # Drop oldest flow to prevent buffer bloat
            try:
                self._flow_queue.get_nowait()
                self._flow_queue.put_nowait(flow)
            except Exception:
                pass

    def _process_queue_loop(self) -> None:
        """Worker loop scoring flows and saving events."""
        while not self._stop_event.is_set():
            try:
                flow = self._flow_queue.get(timeout=0.25)
            except queue.Empty:
                continue

            try:
                self._score_and_persist_flow(flow)
            except Exception as exc:
                logger.error(f"Error processing completed flow: {exc}")
            finally:
                self._flow_queue.task_done()

    def _score_and_persist_flow(self, flow: Dict[str, Any]) -> None:
        """Score flow against detector, compute XAI for alerts, and persist to SQLite."""
        detector = app_state.detector
        explainer = app_state.explainer
        drift_detector = app_state.drift_detector

        # Feed feature vector into drift detector sliding window
        if drift_detector:
            drift_detector.add_observation(flow)

        if not detector or not detector.is_loaded:
            return

        # Inference
        detection = detector.predict_flow(flow)
        is_alert = detection.is_malicious

        # Compute XAI explanation
        explanation_dict = {}
        if explainer and explainer.is_initialized:
            explanation = explainer.explain_prediction(detection, top_k=5)
            explanation_dict = explanation.to_dict()

        # Update telemetry
        app_state.increment_counters(is_alert=is_alert)

        # Insert into SQLite
        event_record = {
            "timestamp": flow.get("timestamp"),
            "src_ip": flow.get("src_ip", "0.0.0.0"),
            "dst_ip": flow.get("dst_ip", "0.0.0.0"),
            "src_port": flow.get("src_port", 0),
            "dst_port": flow.get("dst_port", 0),
            "protocol": flow.get("protocol", "TCP"),
            "flow_duration": flow.get("flow_duration", 0.0),
            "packet_count": flow.get("tot_fwd_pkts", 0) + flow.get("tot_bwd_pkts", 0),
            "byte_count": flow.get("tot_fwd_bytes", 0) + flow.get("tot_bwd_bytes", 0),
            "is_malicious": is_alert,
            "attack_category": detection.attack_category,
            "confidence_score": detection.confidence_score,
            "severity": detection.severity,
            "explanation": explanation_dict,
            "features": flow,
            "mode": flow.get("mode", "demo")
        }
        insert_event(event_record)


# Singleton pipeline instance
pipeline = MonitoringPipeline()
