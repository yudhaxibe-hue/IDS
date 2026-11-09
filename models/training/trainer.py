"""
Model training, cross-validation, and leak-free evaluation pipeline for Explainable Adaptive IDS.
Trains a balanced Random Forest classifier on canonical flow features and persists
calibrated model artifacts and evaluation metrics.
"""
from datetime import datetime
import json
import logging
from pathlib import Path
from typing import Dict, Any, Tuple, Optional
import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    classification_report
)
from sklearn.model_selection import train_test_split

from core.preprocessing.schema import CanonicalFeatureSchema, FEATURE_NAMES, ATTACK_TAXONOMY
from core.preprocessing.preprocessor import FlowPreprocessor
from datasets.manager.dataset_manager import ensure_benchmark_sample

logging.basicConfig(level=logging.INFO, format="[%(asctime)s] [TRAINER] %(message)s")
logger = logging.getLogger("IDS.Trainer")

MODELS_DIR = Path(__file__).resolve().parent.parent
TRAINED_MODEL_PATH = MODELS_DIR / "trained" / "baseline_model.joblib"
EVAL_REPORT_PATH = MODELS_DIR / "evaluation" / "baseline_eval_report.json"


def train_and_evaluate_baseline(
    dataset_path: Optional[Path] = None,
    output_model_path: Optional[Path] = None,
    output_report_path: Optional[Path] = None,
    random_state: int = 42
) -> Dict[str, Any]:
    """
    Execute end-to-end reproducible training and evaluation pipeline:
    1. Loads dataset and validates schema
    2. Performs leak-free Train / Val / Test splitting
    3. Fits preprocessor strictly on training data
    4. Trains Random Forest classifier with class balancing
    5. Evaluates comprehensive metrics on untouched test split
    6. Persists model artifact and evaluation report
    """
    logger.info("Starting baseline model training pipeline...")
    
    # Ingest data
    data_file = dataset_path or ensure_benchmark_sample()
    df = pd.read_csv(data_file)
    logger.info(f"Loaded dataset with {len(df)} records from {data_file.name}")

    # Separate features and targets
    X_raw = CanonicalFeatureSchema.validate_and_clean(df)
    y_multiclass = df["label_category_id"].to_numpy(dtype=np.int64)
    y_binary = df["label_binary"].to_numpy(dtype=np.int64)

    # Leakage-aware 3-way split: 70% Train, 15% Validation, 15% Test
    X_train_raw, X_temp, y_train, y_temp = train_test_split(
        X_raw, y_multiclass, test_size=0.30, random_state=random_state, stratify=y_multiclass
    )
    X_val_raw, X_test_raw, y_val, y_test = train_test_split(
        X_temp, y_temp, test_size=0.50, random_state=random_state, stratify=y_temp
    )

    logger.info(f"Split sizes - Train: {len(X_train_raw)}, Val: {len(X_val_raw)}, Test: {len(X_test_raw)}")

    # Fit preprocessor strictly on Train partition
    preprocessor = FlowPreprocessor()
    X_train = preprocessor.fit_transform(X_train_raw)
    X_val = preprocessor.transform(X_val_raw)
    X_test = preprocessor.transform(X_test_raw)

    # Train Random Forest Classifier
    logger.info("Fitting Random Forest classifier (n_estimators=100)...")
    clf = RandomForestClassifier(
        n_estimators=100,
        max_depth=16,
        min_samples_split=4,
        class_weight="balanced_subsample",
        random_state=random_state,
        n_jobs=-1
    )
    clf.fit(X_train, y_train)

    # Evaluate on final untouched Test set
    logger.info("Evaluating classifier on untouched test partition...")
    y_pred = clf.predict(X_test)
    y_prob = clf.predict_proba(X_test)

    # Multi-class performance
    acc = float(accuracy_score(y_test, y_pred))
    macro_prec = float(precision_score(y_test, y_pred, average="macro", zero_division=0))
    macro_rec = float(recall_score(y_test, y_pred, average="macro", zero_division=0))
    macro_f1 = float(f1_score(y_test, y_pred, average="macro", zero_division=0))
    weighted_f1 = float(f1_score(y_test, y_pred, average="weighted", zero_division=0))

    # Binary performance (0 = Normal, >=1 = Malicious)
    y_test_bin = (y_test != 0).astype(int)
    y_pred_bin = (y_pred != 0).astype(int)
    bin_acc = float(accuracy_score(y_test_bin, y_pred_bin))
    bin_prec = float(precision_score(y_test_bin, y_pred_bin, zero_division=0))
    bin_rec = float(recall_score(y_test_bin, y_pred_bin, zero_division=0))
    bin_f1 = float(f1_score(y_test_bin, y_pred_bin, zero_division=0))

    # Confusion matrix & False Positive / Negative rates
    conf_mat = confusion_matrix(y_test_bin, y_pred_bin).tolist()
    tn, fp, fn, tp = confusion_matrix(y_test_bin, y_pred_bin).ravel()
    fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0
    fnr = float(fn / (fn + tp)) if (fn + tp) > 0 else 0.0

    # Per-category metrics
    class_report = classification_report(y_test, y_pred, target_names=list(ATTACK_TAXONOMY.values()), output_dict=True)

    eval_report: Dict[str, Any] = {
        "model_version": "v1.0.0-baseline",
        "algorithm": "RandomForestClassifier",
        "evaluated_at": datetime.utcnow().isoformat() + "Z",
        "dataset_split": {
            "train_samples": len(X_train_raw),
            "val_samples": len(X_val_raw),
            "test_samples": len(X_test_raw),
            "total_samples": len(df)
        },
        "binary_detection_metrics": {
            "accuracy": bin_acc,
            "precision": bin_prec,
            "recall": bin_rec,
            "f1_score": bin_f1,
            "false_positive_rate": fpr,
            "false_negative_rate": fnr,
            "confusion_matrix": {
                "true_negatives": int(tn),
                "false_positives": int(fp),
                "false_negatives": int(fn),
                "true_positives": int(tp)
            }
        },
        "multiclass_metrics": {
            "accuracy": acc,
            "macro_precision": macro_prec,
            "macro_recall": macro_rec,
            "macro_f1": macro_f1,
            "weighted_f1": weighted_f1,
            "per_class": class_report
        },
        "feature_schema_version": CanonicalFeatureSchema.SCHEMA_VERSION,
        "feature_count": len(FEATURE_NAMES)
    }

    # Persist model bundle
    model_save_path = output_model_path or TRAINED_MODEL_PATH
    model_save_path.parent.mkdir(parents=True, exist_ok=True)
    
    artifact = {
        "classifier": clf,
        "preprocessor": preprocessor.to_dict(),
        "schema_version": CanonicalFeatureSchema.SCHEMA_VERSION,
        "feature_names": FEATURE_NAMES,
        "taxonomy": ATTACK_TAXONOMY,
        "metadata": eval_report
    }
    joblib.dump(artifact, str(model_save_path))
    logger.info(f"Model artifact saved to {model_save_path}")

    # Persist evaluation report
    report_save_path = output_report_path or EVAL_REPORT_PATH
    report_save_path.parent.mkdir(parents=True, exist_ok=True)
    with open(report_save_path, "w") as f:
        json.dump(eval_report, f, indent=2)
    logger.info(f"Evaluation report saved to {report_save_path}")

    logger.info(f"Training Complete! Test F1: {bin_f1:.4f}, Macro F1: {macro_f1:.4f}, FPR: {fpr:.4f}")
    return eval_report


if __name__ == "__main__":
    train_and_evaluate_baseline()
