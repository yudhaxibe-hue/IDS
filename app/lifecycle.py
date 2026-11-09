"""
Application lifecycle manager for Explainable-Adaptive-IDS.
Coordinates startup initialization, state management, and graceful shutdown.
"""
import sys
import logging
import threading
from typing import Dict, Any, Optional

from backend.database.db import initialize_database
from core.detection.detector import ThreatDetector, DEFAULT_MODEL_PATH
from core.explainability.explainer import IDSExplainer

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] [%(levelname)s] [%(name)s]: %(message)s"
)
logger = logging.getLogger("IDS.Lifecycle")


class ApplicationState:
    """Thread-safe global state for application runtime."""
    def __init__(self):
        self._lock = threading.Lock()
        self.is_running = True
        self.monitoring_active = False
        self.monitoring_mode = "idle"  # "idle", "live", "demo"
        self.selected_interface: Optional[str] = None
        self.model_loaded = False
        self.active_model_version = "v1.0.0-baseline"
        self.processed_flows_count = 0
        self.alert_count = 0
        self.drift_status = "STABLE"
        self.detector: Optional[ThreatDetector] = None
        self.explainer: Optional[IDSExplainer] = None

    def set_monitoring(self, active: bool, mode: str = "idle", interface: Optional[str] = None) -> None:
        with self._lock:
            self.monitoring_active = active
            self.monitoring_mode = mode
            if interface:
                self.selected_interface = interface

    def increment_counters(self, is_alert: bool = False) -> None:
        with self._lock:
            self.processed_flows_count += 1
            if is_alert:
                self.alert_count += 1

    def get_summary(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "is_running": self.is_running,
                "monitoring_active": self.monitoring_active,
                "monitoring_mode": self.monitoring_mode,
                "selected_interface": self.selected_interface,
                "model_loaded": self.model_loaded,
                "active_model_version": self.active_model_version,
                "processed_flows_count": self.processed_flows_count,
                "alert_count": self.alert_count,
                "drift_status": self.drift_status
            }


# Singleton application state instance
app_state = ApplicationState()


def on_startup() -> None:
    """Execute startup routines: database initialization and model loading."""
    logger.info("Initializing IDS Application Lifecycle...")
    try:
        initialize_database()
        logger.info("Local SQLite database initialized successfully.")
    except Exception as exc:
        logger.error(f"Failed to initialize database: {exc}")
        raise exc

    # Load baseline threat detection model & XAI explainer
    try:
        detector = ThreatDetector()
        if detector.is_loaded:
            app_state.detector = detector
            app_state.model_loaded = True
            app_state.active_model_version = detector.model_version
            logger.info(f"ThreatDetector loaded model artifact {detector.model_version}")

            # Initialize SHAP TreeExplainer
            explainer = IDSExplainer(detector.classifier)
            if explainer.is_initialized:
                app_state.explainer = explainer
                logger.info("IDSExplainer initialized with SHAP TreeExplainer.")
            else:
                logger.warning("IDSExplainer failed to initialize.")
        else:
            logger.warning("ThreatDetector baseline model artifact not found. Detection offline.")
    except Exception as exc:
        logger.error(f"Error loading ThreatDetector model: {exc}")


def on_shutdown() -> None:
    """Execute graceful shutdown routines: stop monitoring, release capture resources."""
    logger.info("Executing clean shutdown of IDS Application...")
    app_state.is_running = False
    app_state.set_monitoring(False, "idle")
    logger.info("All capture threads and database connections released.")
