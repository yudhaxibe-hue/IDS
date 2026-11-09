"""
Canonical Feature Schema (V1) for Explainable Adaptive IDS.
Guarantees identical feature definitions, types, bounds, and ordering
across dataset training, evaluation, live flow capture, and inference.
"""
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
import numpy as np
import pandas as pd


@dataclass(frozen=True)
class FeatureDefinition:
    name: str
    display_name: str
    dtype: str
    description: str
    unit: str
    min_val: float
    max_val: float
    default_val: float = 0.0


# 28 Canonical Flow Features computable from bidirectional packet headers and timing
CANONICAL_FEATURES: List[FeatureDefinition] = [
    FeatureDefinition("flow_duration", "Flow Duration", "float64", "Total duration of bidirectional flow", "seconds", 0.0, 86400.0, 0.0),
    FeatureDefinition("tot_fwd_pkts", "Forward Packets", "int64", "Total packets transmitted in forward direction", "packets", 0.0, 1e7, 1.0),
    FeatureDefinition("tot_bwd_pkts", "Backward Packets", "int64", "Total packets transmitted in backward direction", "packets", 0.0, 1e7, 0.0),
    FeatureDefinition("tot_fwd_bytes", "Forward Bytes", "int64", "Total bytes transmitted in forward direction", "bytes", 0.0, 1e10, 0.0),
    FeatureDefinition("tot_bwd_bytes", "Backward Bytes", "int64", "Total bytes transmitted in backward direction", "bytes", 0.0, 1e10, 0.0),
    FeatureDefinition("fwd_pkt_len_max", "Max Forward Packet Length", "float64", "Maximum size of forward packet", "bytes", 0.0, 65535.0, 0.0),
    FeatureDefinition("fwd_pkt_len_min", "Min Forward Packet Length", "float64", "Minimum size of forward packet", "bytes", 0.0, 65535.0, 0.0),
    FeatureDefinition("fwd_pkt_len_mean", "Mean Forward Packet Length", "float64", "Average size of forward packets", "bytes", 0.0, 65535.0, 0.0),
    FeatureDefinition("fwd_pkt_len_std", "Std Forward Packet Length", "float64", "Standard deviation of forward packet lengths", "bytes", 0.0, 65535.0, 0.0),
    FeatureDefinition("bwd_pkt_len_max", "Max Backward Packet Length", "float64", "Maximum size of backward packet", "bytes", 0.0, 65535.0, 0.0),
    FeatureDefinition("bwd_pkt_len_min", "Min Backward Packet Length", "float64", "Minimum size of backward packet", "bytes", 0.0, 65535.0, 0.0),
    FeatureDefinition("bwd_pkt_len_mean", "Mean Backward Packet Length", "float64", "Average size of backward packets", "bytes", 0.0, 65535.0, 0.0),
    FeatureDefinition("bwd_pkt_len_std", "Std Backward Packet Length", "float64", "Standard deviation of backward packet lengths", "bytes", 0.0, 65535.0, 0.0),
    FeatureDefinition("flow_bytes_per_sec", "Flow Byte Rate", "float64", "Total bytes transferred per second", "bytes/s", 0.0, 1e9, 0.0),
    FeatureDefinition("flow_pkts_per_sec", "Flow Packet Rate", "float64", "Total packets transferred per second", "packets/s", 0.0, 1e8, 0.0),
    FeatureDefinition("flow_iat_mean", "Mean Inter-Arrival Time", "float64", "Mean time between observed packets in flow", "seconds", 0.0, 3600.0, 0.0),
    FeatureDefinition("flow_iat_std", "Std Inter-Arrival Time", "float64", "Standard deviation of packet inter-arrival times", "seconds", 0.0, 3600.0, 0.0),
    FeatureDefinition("flow_iat_max", "Max Inter-Arrival Time", "float64", "Maximum observed time between packets", "seconds", 0.0, 86400.0, 0.0),
    FeatureDefinition("flow_iat_min", "Min Inter-Arrival Time", "float64", "Minimum observed time between packets", "seconds", 0.0, 3600.0, 0.0),
    FeatureDefinition("fin_flag_cnt", "FIN Flag Count", "int64", "Number of packets with FIN flag set", "count", 0.0, 1e5, 0.0),
    FeatureDefinition("syn_flag_cnt", "SYN Flag Count", "int64", "Number of packets with SYN flag set", "count", 0.0, 1e5, 0.0),
    FeatureDefinition("rst_flag_cnt", "RST Flag Count", "int64", "Number of packets with RST flag set", "count", 0.0, 1e5, 0.0),
    FeatureDefinition("psh_flag_cnt", "PSH Flag Count", "int64", "Number of packets with PSH flag set", "count", 0.0, 1e5, 0.0),
    FeatureDefinition("ack_flag_cnt", "ACK Flag Count", "int64", "Number of packets with ACK flag set", "count", 0.0, 1e5, 0.0),
    FeatureDefinition("urg_flag_cnt", "URG Flag Count", "int64", "Number of packets with URG flag set", "count", 0.0, 1e5, 0.0),
    FeatureDefinition("down_up_ratio", "Download/Upload Ratio", "float64", "Ratio of backward packets to forward packets", "ratio", 0.0, 1e4, 0.0),
    FeatureDefinition("init_win_bytes_fwd", "Init TCP Window Fwd", "int64", "Initial TCP window size in forward direction", "bytes", 0.0, 65535.0, 0.0),
    FeatureDefinition("init_win_bytes_bwd", "Init TCP Window Bwd", "int64", "Initial TCP window size in backward direction", "bytes", 0.0, 65535.0, 0.0),
]

# Ordered list of feature names
FEATURE_NAMES: List[str] = [f.name for f in CANONICAL_FEATURES]
FEATURE_MAP: Dict[str, FeatureDefinition] = {f.name: f for f in CANONICAL_FEATURES}

# Taxonomy of verified attack categories
ATTACK_TAXONOMY: Dict[int, str] = {
    0: "Normal",
    1: "DoS / DDoS",
    2: "Portscan",
    3: "Brute Force",
    4: "Web Attack"
}

LABEL_TO_ID: Dict[str, int] = {v: k for k, v in ATTACK_TAXONOMY.items()}


class CanonicalFeatureSchema:
    """Validator and transformer ensuring tabular records match canonical specifications."""
    
    SCHEMA_VERSION = "1.0.0"

    @classmethod
    def get_feature_names(cls) -> List[str]:
        return list(FEATURE_NAMES)

    @classmethod
    def validate_and_clean(cls, df: pd.DataFrame) -> pd.DataFrame:
        """
        Validate incoming DataFrame, ensuring all canonical features are present,
        handling NaNs, infinite values, and data type coercion.
        """
        cleaned = pd.DataFrame(index=df.index)

        for feat in CANONICAL_FEATURES:
            col_name = feat.name
            if col_name in df.columns:
                series = pd.to_numeric(df[col_name], errors="coerce")
            else:
                series = pd.Series(feat.default_val, index=df.index)

            # Replace positive/negative infinities with bounds
            series = series.replace([np.inf], feat.max_val)
            series = series.replace([-np.inf], feat.min_val)
            
            # Fill remaining NaNs with default
            series = series.fillna(feat.default_val)
            
            # Clip within physical feature boundaries
            series = series.clip(lower=feat.min_val, upper=feat.max_val)
            
            cleaned[col_name] = series.astype(feat.dtype)

        return cleaned[FEATURE_NAMES]

    @classmethod
    def validate_vector(cls, vector: Dict[str, Any]) -> np.ndarray:
        """Validate a single flow dictionary and return 2D numpy array [1, num_features]."""
        df = pd.DataFrame([vector])
        cleaned_df = cls.validate_and_clean(df)
        return cleaned_df.to_numpy(dtype=np.float64)
