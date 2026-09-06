"""
predictor.py - Production-Ready Modular Inference Engine for SENTINELX.

Why this module exists:
In Phase 2 of SENTINELX, the platform will introduce a FastAPI backend and streaming
network log parsers. The inference engine must therefore:
1. Decouple ML model internals from HTTP endpoints.
2. Load serialized models, preprocessor pipelines, and metadata atomically.
3. Validate incoming telemetry packets/flows before feeding them into transformers.
4. Output structured prediction responses containing class labels, binary flags,
   confidence/probability vectors, and timestamps.
"""

import json
import time
from pathlib import Path
from typing import Dict, Any, List, Union, Optional
import joblib
import numpy as np
import pandas as pd


class SentinelXPredictor:
    """
    SentinelXPredictor manages artifact loading and real-time/batch inference
    on new network flow telemetry.
    """

    def __init__(
        self,
        model_dir: str = "ml/models",
        model_filename: str = "sentinelx_rf_model.joblib",
        preprocessor_filename: str = "preprocessor.joblib",
        metadata_filename: str = "model_metadata.json",
    ):
        """
        Initialize SentinelXPredictor and load artifacts.

        Args:
            model_dir: Path to directory containing saved model files.
            model_filename: Name of the joblib model file.
            preprocessor_filename: Name of the joblib preprocessor pipeline file.
            metadata_filename: Name of the JSON metadata file.
        """
        self.model_dir = Path(model_dir)
        self.model_file = self.model_dir / model_filename
        self.preprocessor_file = self.model_dir / preprocessor_filename
        self.metadata_file = self.model_dir / metadata_filename

        self.model = None
        self.preprocessor = None
        self.metadata: Dict[str, Any] = {}
        self.class_names: List[str] = ["Normal", "Attack"]

        self._load_artifacts()

    def _load_artifacts(self) -> None:
        """
        Safely load serialized model, preprocessor, and metadata from disk.

        Raises:
            FileNotFoundError: If essential model files are absent.
            RuntimeError: If artifacts fail to deserialize.
        """
        if not self.model_file.exists():
            raise FileNotFoundError(
                f"[SENTINELX ERROR] Model artifact not found at {self.model_file.resolve()}. "
                "Please run training first."
            )

        if not self.preprocessor_file.exists():
            raise FileNotFoundError(
                f"[SENTINELX ERROR] Preprocessor artifact not found at {self.preprocessor_file.resolve()}. "
                "Please run training/preprocessing first."
            )

        try:
            self.model = joblib.load(self.model_file)
        except Exception as exc:
            raise RuntimeError(
                f"[SENTINELX ERROR] Failed to load model artifact: {exc}"
            ) from exc

        try:
            self.preprocessor = joblib.load(self.preprocessor_file)
        except Exception as exc:
            raise RuntimeError(
                f"[SENTINELX ERROR] Failed to load preprocessor artifact: {exc}"
            ) from exc

        if self.metadata_file.exists():
            try:
                with open(self.metadata_file, "r", encoding="utf-8") as f:
                    self.metadata = json.load(f)
                    self.class_names = self.metadata.get("class_names", self.class_names)
            except Exception:
                pass

    def predict_single(self, flow_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Run inference on a single network flow record (e.g. from an API payload).

        Args:
            flow_data: Key-value dictionary representing one network connection record.

        Returns:
            Dict containing prediction, is_intrusion flag, confidence, and class probabilities.
        """
        df = pd.DataFrame([flow_data])
        batch_result = self.predict_batch(df)
        return batch_result[0]

    def predict_batch(self, df: pd.DataFrame) -> List[Dict[str, Any]]:
        """
        Run inference on a batch of network flow records.

        Args:
            df: Pandas DataFrame containing raw network features.

        Returns:
            List of prediction dictionaries.
        """
        if self.model is None or self.preprocessor is None:
            raise RuntimeError("[SENTINELX ERROR] Predictor is not properly initialized.")

        if df.empty:
            return []

        start_time = time.perf_counter()

        # Transform raw features using persisted FeaturePipeline
        try:
            X_transformed = self.preprocessor.transform(df)
        except Exception as exc:
            raise ValueError(
                f"[SENTINELX ERROR] Feature transformation failed: {exc}"
            ) from exc

        # Generate predictions and probabilities
        preds = self.model.predict(X_transformed)
        probas = (
            self.model.predict_proba(X_transformed)
            if hasattr(self.model, "predict_proba")
            else None
        )

        elapsed_ms = (time.perf_counter() - start_time) * 1000.0
        per_sample_ms = elapsed_ms / len(df)

        results = []
        for idx, pred_class_idx in enumerate(preds):
            pred_idx = int(pred_class_idx)
            class_label = (
                self.class_names[pred_idx]
                if pred_idx < len(self.class_names)
                else f"Class_{pred_idx}"
            )
            is_intrusion = bool(pred_idx != 0 and "normal" not in class_label.lower())

            prob_dict = {}
            confidence = 1.0
            if probas is not None:
                prob_row = probas[idx]
                confidence = float(np.max(prob_row))
                for c_idx, c_name in enumerate(self.class_names):
                    if c_idx < len(prob_row):
                        prob_dict[c_name] = float(prob_row[c_idx])

            record_res = {
                "sample_index": idx,
                "predicted_class_id": pred_idx,
                "predicted_label": class_label,
                "is_intrusion": is_intrusion,
                "confidence": confidence,
                "probabilities": prob_dict,
                "inference_time_ms": round(per_sample_ms, 3),
            }
            results.append(record_res)

        return results
