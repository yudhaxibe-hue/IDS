"""
Explainable AI (XAI) engine for Explainable Adaptive IDS.
Leverages SHAP (SHapley Additive exPlanations) TreeExplainer to produce
grounded feature attributions and deterministic plain-language summaries.
"""
from dataclasses import dataclass, field
import logging
from typing import Dict, Any, List, Optional
import numpy as np
import shap

from core.preprocessing.schema import FEATURE_MAP, FEATURE_NAMES, ATTACK_TAXONOMY
from core.detection.detector import DetectionResult

logger = logging.getLogger("IDS.Explainer")


@dataclass
class FeatureAttribution:
    name: str
    display_name: str
    value: Any
    unit: str
    attribution: float  # SHAP value
    direction: str      # "malicious" or "normal"
    description: str


@dataclass
class ExplanationResult:
    is_available: bool
    predicted_category: str
    confidence_score: float
    top_features: List[FeatureAttribution]
    summary: str
    failure_reason: Optional[str] = None
    computation_time_ms: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "is_available": self.is_available,
            "predicted_category": self.predicted_category,
            "confidence_score": round(self.confidence_score, 4),
            "top_features": [
                {
                    "name": f.display_name,
                    "raw_key": f.name,
                    "value": f.value,
                    "unit": f.unit,
                    "attribution": round(f.attribution, 4),
                    "direction": f.direction,
                    "description": f.description
                } for f in self.top_features
            ],
            "summary": self.summary,
            "failure_reason": self.failure_reason,
            "computation_time_ms": round(self.computation_time_ms, 2)
        }


class IDSExplainer:
    """Manages TreeExplainer instances and plain-language explanation generation."""

    def __init__(self, classifier: Any = None):
        self.classifier = classifier
        self.explainer: Optional[shap.TreeExplainer] = None
        self.is_initialized = False

        if classifier is not None:
            self.initialize(classifier)

    def initialize(self, classifier: Any) -> bool:
        """Initialize SHAP TreeExplainer for the provided tree classifier."""
        try:
            self.classifier = classifier
            self.explainer = shap.TreeExplainer(classifier)
            self.is_initialized = True
            logger.info("SHAP TreeExplainer successfully initialized.")
            return True
        except Exception as exc:
            logger.error(f"Failed to initialize SHAP TreeExplainer: {exc}")
            self.is_initialized = False
            return False

    def explain_prediction(
        self,
        detection: DetectionResult,
        top_k: int = 5
    ) -> ExplanationResult:
        """
        Compute SHAP values for a single flow event and translate into plain-language explanation.
        """
        import time
        start_time = time.time()

        if not self.is_initialized or self.explainer is None:
            return ExplanationResult(
                is_available=False,
                predicted_category=detection.attack_category,
                confidence_score=detection.confidence_score,
                top_features=[],
                summary="Explanation unavailable: XAI engine is not initialized.",
                failure_reason="Explainer uninitialized",
                computation_time_ms=0.0
            )

        try:
            # Scaled features 2D array [1, num_features]
            X = detection.transformed_features
            shap_values = self.explainer.shap_values(X)

            # Handle SHAP multi-class output structure (list of ndarrays or 3D ndarray)
            target_class_idx = detection.attack_category_id

            if isinstance(shap_values, list):
                # List of ndarrays: one per class
                if target_class_idx < len(shap_values):
                    class_shap = shap_values[target_class_idx][0]
                else:
                    class_shap = shap_values[0][0]
            elif isinstance(shap_values, np.ndarray):
                if shap_values.ndim == 3:
                    # Shape: [num_samples, num_features, num_classes]
                    class_shap = shap_values[0, :, target_class_idx]
                elif shap_values.ndim == 2:
                    class_shap = shap_values[0]
                else:
                    class_shap = shap_values.flatten()
            else:
                raise ValueError("Unexpected SHAP output structure.")

            # Rank features by absolute attribution magnitude
            abs_shap = np.abs(class_shap)
            ranked_indices = np.argsort(abs_shap)[::-1][:top_k]

            attributions: List[FeatureAttribution] = []
            for idx in ranked_indices:
                feat_name = FEATURE_NAMES[idx]
                feat_def = FEATURE_MAP.get(feat_name)
                attribution_val = float(class_shap[idx])
                raw_val = detection.raw_features.get(feat_name, 0.0)

                # Direction: positive pushes towards predicted class
                direction = "malicious" if (attribution_val > 0 and detection.is_malicious) else "normal"

                attributions.append(FeatureAttribution(
                    name=feat_name,
                    display_name=feat_def.display_name if feat_def else feat_name,
                    value=round(float(raw_val), 2) if isinstance(raw_val, (int, float)) else raw_val,
                    unit=feat_def.unit if feat_def else "",
                    attribution=attribution_val,
                    direction=direction,
                    description=feat_def.description if feat_def else ""
                ))

            # Generate deterministic plain-language narrative
            summary = self._generate_plain_language_summary(detection, attributions)
            elapsed_ms = (time.time() - start_time) * 1000.0

            return ExplanationResult(
                is_available=True,
                predicted_category=detection.attack_category,
                confidence_score=detection.confidence_score,
                top_features=attributions,
                summary=summary,
                computation_time_ms=elapsed_ms
            )

        except Exception as exc:
            logger.error(f"Error computing SHAP explanation: {exc}")
            return ExplanationResult(
                is_available=False,
                predicted_category=detection.attack_category,
                confidence_score=detection.confidence_score,
                top_features=[],
                summary=f"Explanation computation encountered an error: {str(exc)}",
                failure_reason=str(exc),
                computation_time_ms=(time.time() - start_time) * 1000.0
            )

    def _generate_plain_language_summary(
        self,
        detection: DetectionResult,
        top_features: List[FeatureAttribution]
    ) -> str:
        """Create structured, non-technical plain-language explanation without causal claims."""
        if not top_features:
            return f"Flow classified as {detection.attack_category} with {(detection.confidence_score * 100):.1f}% confidence."

        f1 = top_features[0]
        f2 = top_features[1] if len(top_features) > 1 else None

        if detection.is_malicious:
            summary = (
                f"Suspicious activity flagged: Flow exhibits indicators of {detection.attack_category} "
                f"with {(detection.confidence_score * 100):.1f}% model confidence. "
                f"The most significant contributing factor was {f1.display_name} recorded at {f1.value} {f1.unit}, "
                f"which strongly pushed the prediction toward malicious activity."
            )
            if f2:
                summary += f" Secondary support came from {f2.display_name} ({f2.value} {f2.unit})."
        else:
            summary = (
                f"Flow verified as Normal network traffic ({(detection.confidence_score * 100):.1f}% confidence). "
                f"Key benign indicators include balanced {f1.display_name} ({f1.value} {f1.unit})"
            )
            if f2:
                summary += f" and normal {f2.display_name} ({f2.value} {f2.unit})."

        return summary
