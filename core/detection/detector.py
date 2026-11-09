"""
Detection and classification engine for Explainable Adaptive IDS.
Loads verified baseline models and scores incoming network flow vectors.
"""
from dataclasses import dataclass
import json
import logging
from pathlib import Path
from typing import Dict, Any, Optional, Tuple
import joblib
import numpy as np

from core.preprocessing.schema import CanonicalFeatureSchema, FEATURE_NAMES, ATTACK_TAXONOMY
from core.preprocessing.preprocessor import FlowPreprocessor

logger = logging.getLogger("IDS.Detector")
DEFAULT_MODEL_PATH = Path(__file__).resolve().parent.parent.parent / "models" / "trained" / "baseline_model.joblib"


@dataclass
class DetectionResult:
    is_malicious: bool
    attack_category: str
    attack_category_id: int
    confidence_score: float
    probability: float
    severity: str
    model_version: str
    feature_schema_version: str
    transformed_features: np.ndarray
    raw_features: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "is_malicious": self.is_malicious,
            "attack_category": self.attack_category,
            "attack_category_id": self.attack_category_id,
            "confidence_score": round(self.confidence_score, 4),
            "probability": round(self.probability, 4),
            "severity": self.severity,
            "model_version": self.model_version,
            "feature_schema_version": self.feature_schema_version
        }


class ThreatDetector:
    """Evaluates network flow features using the active trained intrusion detection model."""

    def __init__(self, model_path: Optional[Path] = None, alert_threshold: float = 0.50):
        self.model_path = model_path or DEFAULT_MODEL_PATH
        self.alert_threshold = alert_threshold
        self.classifier = None
        self.preprocessor = None
        self.model_version = "v1.0.0-uninitialized"
        self.feature_names = FEATURE_NAMES
        self.taxonomy = ATTACK_TAXONOMY
        self.metadata = {}
        self.is_loaded = False
        
        self.load_model()

    def load_model(self) -> bool:
        """Load trained model bundle from disk."""
        if not self.model_path.exists():
            logger.warning(f"Model file not found at {self.model_path}. Detector uninitialized.")
            self.is_loaded = False
            return False

        try:
            artifact = joblib.load(str(self.model_path))
            self.classifier = artifact["classifier"]
            self.preprocessor = FlowPreprocessor.from_dict(artifact["preprocessor"])
            self.feature_names = artifact.get("feature_names", FEATURE_NAMES)
            self.taxonomy = artifact.get("taxonomy", ATTACK_TAXONOMY)
            self.metadata = artifact.get("metadata", {})
            self.model_version = self.metadata.get("model_version", "v1.0.0-baseline")
            self.is_loaded = True
            logger.info(f"Loaded IDS model {self.model_version} successfully.")
            return True
        except Exception as exc:
            logger.error(f"Failed to load IDS model: {exc}")
            self.is_loaded = False
            return False

    def predict_flow(self, flow_dict: Dict[str, Any]) -> DetectionResult:
        """
        Score a single flow dictionary against the model.
        Returns complete DetectionResult with calibrated probability and severity.
        """
        if not self.is_loaded or self.classifier is None:
            raise RuntimeError("ThreatDetector is not loaded with a valid model artifact.")

        # Transform vector with fitted preprocessor
        scaled_features = self.preprocessor.transform_single(flow_dict)
        
        # Multi-class probabilities
        probabilities = self.classifier.predict_proba(scaled_features)[0]
        predicted_class_id = int(np.argmax(probabilities))
        normal_prob = float(probabilities[0])
        attack_prob = float(1.0 - normal_prob)

        # Binary decision based on configurable alert threshold
        is_malicious = attack_prob >= self.alert_threshold
        
        if is_malicious:
            # If flagged malicious, determine attack category
            if predicted_class_id == 0:
                # If sum of attack probs exceeded threshold but normal was top single class,
                # assign highest attack sub-class
                attack_class_id = int(np.argmax(probabilities[1:]) + 1)
            else:
                attack_class_id = predicted_class_id
            
            category = self.taxonomy.get(attack_class_id, "Unknown Attack")
            confidence = attack_prob
            severity = self._compute_severity(category, confidence)
        else:
            attack_class_id = 0
            category = "Normal"
            confidence = normal_prob
            severity = "Informational"

        return DetectionResult(
            is_malicious=is_malicious,
            attack_category=category,
            attack_category_id=attack_class_id,
            confidence_score=confidence,
            probability=attack_prob,
            severity=severity,
            model_version=self.model_version,
            feature_schema_version=CanonicalFeatureSchema.SCHEMA_VERSION,
            transformed_features=scaled_features,
            raw_features=flow_dict
        )

    def _compute_severity(self, category: str, confidence: float) -> str:
        """Assign standardized severity tier based on threat category and confidence."""
        if category in ("DoS / DDoS", "Web Attack"):
            return "Critical" if confidence > 0.85 else "High"
        elif category in ("Brute Force",):
            return "High" if confidence > 0.80 else "Medium"
        elif category in ("Portscan",):
            return "Medium" if confidence > 0.75 else "Low"
        return "Low"
