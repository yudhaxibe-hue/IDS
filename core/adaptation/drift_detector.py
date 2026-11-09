"""
Concept Drift Monitoring Subsystem for Explainable Adaptive IDS.
Implements two-sample Kolmogorov-Smirnov (KS) testing and distribution monitoring
over sliding windows of streaming flow features.
"""
from dataclasses import dataclass, field
from datetime import datetime
import logging
from typing import Dict, Any, List, Optional
import numpy as np
import pandas as pd
from scipy.stats import ks_2samp

from core.preprocessing.schema import CANONICAL_FEATURES, FEATURE_NAMES

logger = logging.getLogger("IDS.DriftDetector")

# Monitored primary features sensitive to workload and attack shifts
MONITORED_FEATURES = [
    "flow_duration",
    "tot_fwd_pkts",
    "fwd_pkt_len_mean",
    "flow_bytes_per_sec",
    "flow_pkts_per_sec",
    "flow_iat_mean",
    "syn_flag_cnt"
]


@dataclass
class FeatureDriftResult:
    feature_name: str
    display_name: str
    ks_statistic: float
    p_value: float
    is_drifted: bool
    baseline_mean: float
    current_mean: float
    interpretation: str


@dataclass
class DriftReport:
    timestamp: str
    status: str  # "STABLE", "WARNING", "DRIFT_DETECTED"
    sample_size: int
    min_required_samples: int
    features_evaluated: int
    drifted_features_count: int
    drifted_features: List[FeatureDriftResult]
    summary: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "status": self.status,
            "sample_size": self.sample_size,
            "min_required_samples": self.min_required_samples,
            "features_evaluated": self.features_evaluated,
            "drifted_features_count": self.drifted_features_count,
            "drifted_features": [
                {
                    "feature_name": f.feature_name,
                    "display_name": f.display_name,
                    "ks_statistic": round(f.ks_statistic, 4),
                    "p_value": round(f.p_value, 5),
                    "is_drifted": f.is_drifted,
                    "baseline_mean": round(f.baseline_mean, 2),
                    "current_mean": round(f.current_mean, 2),
                    "interpretation": f.interpretation
                } for f in self.drifted_features
            ],
            "summary": self.summary
        }


class DistributionDriftDetector:
    """Monitors sliding windows of incoming network flows against baseline training distributions."""

    def __init__(
        self,
        baseline_df: Optional[pd.DataFrame] = None,
        window_size: int = 300,
        min_samples: int = 50,
        p_value_threshold: float = 0.01,
        ks_stat_threshold: float = 0.20,
        min_drifted_features_to_alert: int = 2
    ):
        self.window_size = window_size
        self.min_samples = min_samples
        self.p_value_threshold = p_value_threshold
        self.ks_stat_threshold = ks_stat_threshold
        self.min_drifted_features = min_drifted_features_to_alert
        
        self.baseline_data: Dict[str, np.ndarray] = {}
        self.current_window: List[Dict[str, Any]] = []

        if baseline_df is not None:
            self.set_baseline(baseline_df)

    def set_baseline(self, df: pd.DataFrame) -> None:
        """Establish baseline statistical distribution from approved training/validation dataset."""
        self.baseline_data.clear()
        for col in MONITORED_FEATURES:
            if col in df.columns:
                values = pd.to_numeric(df[col], errors="coerce").dropna().to_numpy(dtype=np.float64)
                if len(values) > 0:
                    self.baseline_data[col] = values
        logger.info(f"Baseline established across {len(self.baseline_data)} monitored features.")

    def add_observation(self, flow: Dict[str, Any]) -> None:
        """Add a completed flow observation to the sliding distribution window."""
        self.current_window.append(flow)
        if len(self.current_window) > self.window_size:
            self.current_window.pop(0)

    def evaluate_drift(self) -> DriftReport:
        """Perform two-sample Kolmogorov-Smirnov test across monitored features."""
        current_len = len(self.current_window)
        now_iso = datetime.utcnow().isoformat() + "Z"

        if current_len < self.min_samples:
            return DriftReport(
                timestamp=now_iso,
                status="STABLE",
                sample_size=current_len,
                min_required_samples=self.min_samples,
                features_evaluated=len(self.baseline_data),
                drifted_features_count=0,
                drifted_features=[],
                summary=f"Collecting flow observations ({current_len}/{self.min_samples} required for statistical testing)."
            )

        if not self.baseline_data:
            return DriftReport(
                timestamp=now_iso,
                status="STABLE",
                sample_size=current_len,
                min_required_samples=self.min_samples,
                features_evaluated=0,
                drifted_features_count=0,
                drifted_features=[],
                summary="Baseline distribution uninitialized."
            )

        window_df = pd.DataFrame(self.current_window)
        feature_results: List[FeatureDriftResult] = []
        drifted_count = 0

        for feat_name, baseline_series in self.baseline_data.items():
            if feat_name not in window_df.columns:
                continue

            current_series = pd.to_numeric(window_df[feat_name], errors="coerce").dropna().to_numpy(dtype=np.float64)
            if len(current_series) < self.min_samples:
                continue

            ks_stat, p_val = ks_2samp(baseline_series, current_series)
            
            # Drift flagged if p-value is significant AND statistic exceeds magnitude threshold
            is_drifted = (p_val < self.p_value_threshold) and (ks_stat > self.ks_stat_threshold)
            if is_drifted:
                drifted_count += 1

            base_mean = float(np.mean(baseline_series))
            curr_mean = float(np.mean(current_series))

            if is_drifted:
                change_dir = "higher" if curr_mean > base_mean else "lower"
                interpretation = (
                    f"Statistically significant distribution shift (KS={ks_stat:.3f}, p={p_val:.4f}). "
                    f"Current mean ({curr_mean:.2f}) is noticeably {change_dir} than baseline ({base_mean:.2f})."
                )
            else:
                interpretation = "Feature distribution aligns with baseline training window."

            feature_results.append(FeatureDriftResult(
                feature_name=feat_name,
                display_name=feat_name.replace("_", " ").title(),
                ks_statistic=float(ks_stat),
                p_value=float(p_val),
                is_drifted=is_drifted,
                baseline_mean=base_mean,
                current_mean=curr_mean,
                interpretation=interpretation
            ))

        # Overall Status
        if drifted_count >= self.min_drifted_features:
            status = "DRIFT_DETECTED"
            summary = (
                f"Significant concept drift detected: {drifted_count} features exhibit statistical divergence "
                f"from baseline. Investigate traffic patterns or assess a candidate model."
            )
        elif drifted_count > 0:
            status = "WARNING"
            summary = f"Moderate distribution variation observed in {drifted_count} feature(s). Monitoring continues."
        else:
            status = "STABLE"
            summary = "Streaming network traffic characteristics align closely with approved baseline distribution."

        return DriftReport(
            timestamp=now_iso,
            status=status,
            sample_size=current_len,
            min_required_samples=self.min_samples,
            features_evaluated=len(feature_results),
            drifted_features_count=drifted_count,
            drifted_features=feature_results,
            summary=summary
        )
