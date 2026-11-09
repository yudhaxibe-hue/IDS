"""
Offline Replay / Demo Stream Engine for Explainable Adaptive IDS.
Streams pre-recorded benchmark flow records at realistic intervals without
requiring packet capture permissions or network socket access.
All emitted flows are strictly tagged with mode='demo'.
"""
from datetime import datetime
import logging
import random
import threading
import time
from typing import Dict, Any, Callable, Optional
import pandas as pd

from datasets.manager.dataset_manager import ensure_benchmark_sample

logger = logging.getLogger("IDS.ReplayEngine")


class OfflineReplayEngine:
    """Streams reproducible flow observations from verified benchmark dataset."""

    def __init__(
        self,
        flow_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
        flows_per_second: float = 2.0
    ):
        self.flow_callback = flow_callback
        self.flows_per_second = flows_per_second
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._is_running = False

    def start(self) -> bool:
        """Start streaming replay flows in background daemon thread."""
        if self._is_running:
            return True

        self._stop_event.clear()
        self._thread = threading.Thread(target=self._run_loop, daemon=True)
        self._thread.start()
        self._is_running = True
        logger.info("Offline Replay / Demo streaming engine started.")
        return True

    def stop(self) -> bool:
        """Stop streaming thread cleanly."""
        if not self._is_running:
            return True

        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=2.0)
            self._thread = None
        self._is_running = False
        logger.info("Offline Replay streaming engine stopped.")
        return True

    def _run_loop(self) -> None:
        """Background loop reading and emitting benchmark flows."""
        data_path = ensure_benchmark_sample()
        df = pd.read_csv(data_path)
        records = df.to_dict("records")
        idx = 0
        total_records = len(records)
        interval = 1.0 / max(0.1, self.flows_per_second)

        while not self._stop_event.is_set():
            raw_rec = records[idx % total_records]
            idx += 1

            # Prepare flow dictionary with live metadata
            now_iso = datetime.utcnow().isoformat() + "Z"
            
            # Synthetic 5-tuple metadata
            label_id = int(raw_rec.get("label_category_id", 0))
            if label_id == 0:
                src_ip = f"192.168.1.{random.randint(10, 80)}"
                dst_ip = f"142.250.{random.randint(1, 250)}.{random.randint(1, 250)}"
                src_port = random.randint(49152, 65535)
                dst_port = random.choice([443, 80, 53])
            elif label_id == 1:
                # DoS / DDoS attack
                src_ip = f"10.0.0.{random.randint(100, 250)}"
                dst_ip = "192.168.1.1"
                src_port = random.randint(1024, 65535)
                dst_port = 80
            elif label_id == 2:
                # Portscan attack
                src_ip = "10.0.0.99"
                dst_ip = "192.168.1.1"
                src_port = 54321
                dst_port = random.randint(20, 1024)
            elif label_id == 3:
                # Brute Force attack
                src_ip = "172.16.0.45"
                dst_ip = "192.168.1.20"
                src_port = random.randint(40000, 50000)
                dst_port = 22
            else:
                # Web Attack
                src_ip = "198.51.100.14"
                dst_ip = "192.168.1.80"
                src_port = random.randint(30000, 40000)
                dst_port = 8080

            flow_data = {
                "timestamp": now_iso,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": src_port,
                "dst_port": dst_port,
                "protocol": "TCP",
                "mode": "demo",
                **{k: v for k, v in raw_rec.items() if not k.startswith("label_")}
            }

            if self.flow_callback:
                try:
                    self.flow_callback(flow_data)
                except Exception as exc:
                    logger.error(f"Error in replay flow callback: {exc}")

            time.sleep(interval)

    @property
    def is_running(self) -> bool:
        return self._is_running
