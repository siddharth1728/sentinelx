"""
train.py - Baseline Random Forest Model Training and Persistence for SENTINELX.

Why this module exists:
Random Forest is a premier baseline algorithm for tabular network intrusion detection because:
1. It is an ensemble of decision trees, making it resilient to noisy network telemetry.
2. It handles non-linear feature interactions (e.g. high byte count + unusual port = anomaly).
3. It natively supports probability calibration and feature importance extraction.
4. It is less prone to overfitting than single trees when properly configured.

This module encapsulates model instantiation, fitting on preprocessed training data,
and atomic model serialization into `ml/models/`.
"""

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, Optional
import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier

from ..features.feature_pipeline import FeaturePipeline


class ModelTrainer:
    """
    ModelTrainer manages training the baseline Random Forest classifier
    and serializing the resulting model artifacts and configuration.
    """

    def __init__(
        self,
        n_estimators: int = 100,
        max_depth: Optional[int] = 15,
        min_samples_split: int = 5,
        min_samples_leaf: int = 2,
        class_weight: str = "balanced",
        random_state: int = 42,
        n_jobs: int = 1,
    ):
        """
        Initialize ModelTrainer with defensive hyperparameters.

        Args:
            n_estimators: Number of trees in the forest.
            max_depth: Maximum tree depth to control overfitting.
            min_samples_split: Minimum samples required to split an internal node.
            min_samples_leaf: Minimum samples required to be at a leaf node.
            class_weight: 'balanced' adjusts weights inversely proportional to class frequencies.
            random_state: Seed for reproducibility.
            n_jobs: Number of CPU cores to use (-1 = all).
        """
        self.params = {
            "n_estimators": n_estimators,
            "max_depth": max_depth,
            "min_samples_split": min_samples_split,
            "min_samples_leaf": min_samples_leaf,
            "class_weight": class_weight,
            "random_state": random_state,
            "n_jobs": n_jobs,
        }
        self.model: Optional[RandomForestClassifier] = None
        self.training_metadata: Dict[str, Any] = {}

    def train(
        self,
        X_train: np.ndarray,
        y_train: np.ndarray,
        feature_pipeline: Optional[FeaturePipeline] = None,
        class_names: Optional[list] = None,
    ) -> RandomForestClassifier:
        """
        Train the Random Forest model on preprocessed training features and labels.

        Args:
            X_train: Transformed feature matrix (n_samples, n_features).
            y_train: Target label array (n_samples,).
            feature_pipeline: The fitted FeaturePipeline instance (stored with artifacts).
            class_names: List of human-readable class names (e.g. ['Normal', 'Attack']).

        Returns:
            Fitted RandomForestClassifier.
        """
        if len(X_train) == 0 or len(y_train) == 0:
            raise ValueError("[SENTINELX ERROR] Cannot train model on empty dataset.")

        if len(X_train) != len(y_train):
            raise ValueError(
                f"[SENTINELX ERROR] Feature sample count ({len(X_train)}) does not match label count ({len(y_train)})."
            )

        self.model = RandomForestClassifier(**self.params)
        self.model.fit(X_train, y_train)

        # Record training run metadata
        self.training_metadata = {
            "model_type": "RandomForestClassifier",
            "hyperparameters": {k: v for k, v in self.params.items() if k != "n_jobs"},
            "trained_at_utc": datetime.now(timezone.utc).isoformat(),
            "train_samples": int(len(X_train)),
            "feature_count": int(X_train.shape[1]),
            "classes": [str(c) for c in self.model.classes_],
            "class_names": class_names or ["Class_" + str(c) for c in self.model.classes_],
            "is_production_ready": False,  # Explicitly marking Phase 1 as development baseline
            "disclaimer": "SENTINELX Phase 1 development baseline model. Not validated for production deployment.",
        }

        return self.model

    def save_model(
        self,
        output_dir: str = "ml/models",
        model_filename: str = "sentinelx_rf_model.joblib",
        feature_pipeline: Optional[FeaturePipeline] = None,
        pipeline_filename: str = "preprocessor.joblib",
        metadata_filename: str = "model_metadata.json",
    ) -> Dict[str, str]:
        """
        Serialize model and accompanying pipeline artifacts to disk.

        Args:
            output_dir: Directory to save model files.
            model_filename: Filename for the Scikit-learn model artifact.
            feature_pipeline: Optional fitted FeaturePipeline to persist.
            pipeline_filename: Filename for preprocessor artifact.
            metadata_filename: Filename for training metadata JSON.

        Returns:
            Dict with saved artifact paths.
        """
        if self.model is None:
            raise RuntimeError("[SENTINELX ERROR] Cannot save untrained model. Call train() first.")

        save_path = Path(output_dir)
        save_path.mkdir(parents=True, exist_ok=True)

        model_file = save_path / model_filename
        joblib.dump(self.model, model_file)

        saved_files = {"model_path": str(model_file)}

        if feature_pipeline is not None:
            pipeline_file = save_path / pipeline_filename
            joblib.dump(feature_pipeline, pipeline_file)
            saved_files["preprocessor_path"] = str(pipeline_file)

            if hasattr(feature_pipeline, "get_metadata"):
                self.training_metadata["feature_pipeline_metadata"] = feature_pipeline.get_metadata()

        metadata_file = save_path / metadata_filename
        with open(metadata_file, "w", encoding="utf-8") as f:
            json.dump(self.training_metadata, f, indent=2)
        saved_files["metadata_path"] = str(metadata_file)

        return saved_files
