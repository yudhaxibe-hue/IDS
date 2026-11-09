"""
Feature preprocessing pipeline for Explainable Adaptive IDS.
Implements robust normalization, missing value handling, and isolation
guaranteeing zero data leakage between training and evaluation splits.
"""
from typing import Dict, Any, Optional
import numpy as np
import pandas as pd
from sklearn.preprocessing import RobustScaler

from core.preprocessing.schema import CanonicalFeatureSchema, FEATURE_NAMES


class FlowPreprocessor:
    """Preprocesses tabular network flow features according to Canonical Schema V1."""
    
    def __init__(self):
        self.scaler = RobustScaler(unit_variance=True)
        self.is_fitted = False
        self.schema_version = CanonicalFeatureSchema.SCHEMA_VERSION

    def fit(self, df: pd.DataFrame) -> "FlowPreprocessor":
        """Fit feature scaler strictly on the training partition."""
        cleaned_df = CanonicalFeatureSchema.validate_and_clean(df)
        self.scaler.fit(cleaned_df.to_numpy(dtype=np.float64))
        self.is_fitted = True
        return self

    def transform(self, df: pd.DataFrame) -> np.ndarray:
        """Transform tabular flow data into scaled numerical feature matrix."""
        cleaned_df = CanonicalFeatureSchema.validate_and_clean(df)
        features_matrix = cleaned_df.to_numpy(dtype=np.float64)
        if self.is_fitted:
            return self.scaler.transform(features_matrix)
        return features_matrix

    def fit_transform(self, df: pd.DataFrame) -> np.ndarray:
        """Fit on training partition and return transformed matrix."""
        return self.fit(df).transform(df)

    def transform_single(self, vector: Dict[str, Any]) -> np.ndarray:
        """Transform a single incoming flow vector dictionary for live inference."""
        raw_array = CanonicalFeatureSchema.validate_vector(vector)
        if self.is_fitted:
            return self.scaler.transform(raw_array)
        return raw_array

    def to_dict(self) -> Dict[str, Any]:
        """Serialize preprocessor state for model packaging."""
        return {
            "schema_version": self.schema_version,
            "is_fitted": self.is_fitted,
            "feature_names": FEATURE_NAMES,
            "scaler": self.scaler
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "FlowPreprocessor":
        """Reconstruct preprocessor from serialized state."""
        instance = cls()
        instance.schema_version = data.get("schema_version", CanonicalFeatureSchema.SCHEMA_VERSION)
        instance.is_fitted = data.get("is_fitted", False)
        instance.scaler = data.get("scaler", RobustScaler(unit_variance=True))
        return instance
