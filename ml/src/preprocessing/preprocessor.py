"""
preprocessor.py - End-to-End Data Preprocessing and Partitioning for SENTINELX.

Why this module exists:
To train an effective defensive ML model without data leakage, we must:
1. Strictly separate feature columns from ground-truth security labels.
2. Fit feature encoders and scalers strictly on training data (never test data).
3. Apply stratified sampling so that rare attack classes are proportionally represented.
4. Save preprocessed datasets into `ml/data/processed/` for auditability and reproducibility.
"""

import os
from pathlib import Path
from typing import Tuple, List, Optional, Dict, Any
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder

from ..features.feature_pipeline import FeaturePipeline
from .data_loader import DataLoader


class NetworkDataPreprocessor:
    """
    NetworkDataPreprocessor manages end-to-end dataset cleaning,
    feature separation, stratified train/test splitting, encoding, and artifact export.
    """

    def __init__(
        self,
        label_column: str = "label",
        binary_classification: bool = True,
        normal_label_value: str = "normal",
        test_size: float = 0.2,
        random_state: int = 42,
    ):
        """
        Initialize NetworkDataPreprocessor.

        Args:
            label_column: Name of target column (e.g. 'label' or 'attack_type').
            binary_classification: If True, maps labels to 0 (Normal) and 1 (Intrusion/Attack).
            normal_label_value: The string value representing benign/normal traffic.
            test_size: Fraction of dataset allocated for testing (default: 0.2 = 20%).
            random_state: Random seed for reproducible splitting.
        """
        self.label_column = label_column
        self.binary_classification = binary_classification
        self.normal_label_value = normal_label_value.lower()
        self.test_size = test_size
        self.random_state = random_state

        self.feature_pipeline: Optional[FeaturePipeline] = None
        self.label_encoder: Optional[LabelEncoder] = None
        self.numerical_cols: List[str] = []
        self.categorical_cols: List[str] = []
        self.class_names: List[str] = []

    def prepare_dataset(
        self,
        df: pd.DataFrame,
        numerical_cols: Optional[List[str]] = None,
        categorical_cols: Optional[List[str]] = None,
    ) -> Tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray]:
        """
        Orchestrate dataset partitioning and transformation.

        Args:
            df: Raw DataFrame containing features and label column.
            numerical_cols: Explicit list of numerical column names. If None, inferred automatically.
            categorical_cols: Explicit list of categorical column names. If None, inferred automatically.

        Returns:
            Tuple of (X_train_transformed, X_test_transformed, y_train, y_test).
        """
        if self.label_column not in df.columns:
            raise ValueError(
                f"[SENTINELX ERROR] Label column '{self.label_column}' not found in dataset columns: {list(df.columns)}"
            )

        # 1. Clean invalid / missing rows
        cleaned_df, _ = DataLoader.clean_invalid_rows(df, drop_na=True)

        # 2. Separate features (X) and label (y)
        X_df = cleaned_df.drop(columns=[self.label_column])
        y_raw = cleaned_df[self.label_column].astype(str)

        # 3. Infer or set column types
        if numerical_cols is None:
            self.numerical_cols = list(X_df.select_dtypes(include=[np.number]).columns)
        else:
            self.numerical_cols = numerical_cols

        if categorical_cols is None:
            self.categorical_cols = list(X_df.select_dtypes(include=["object", "category"]).columns)
        else:
            self.categorical_cols = categorical_cols

        # 4. Process labels
        y_processed = self._process_labels(y_raw)

        # 5. Perform Stratified Train-Test Split to ensure attack representation
        X_train_df, X_test_df, y_train, y_test = train_test_split(
            X_df,
            y_processed,
            test_size=self.test_size,
            random_state=self.random_state,
            stratify=y_processed,
        )

        # 6. Fit feature pipeline on X_train ONLY, then transform X_train and X_test
        self.feature_pipeline = FeaturePipeline(
            numerical_cols=self.numerical_cols,
            categorical_cols=self.categorical_cols,
        )
        X_train_transformed = self.feature_pipeline.fit_transform(X_train_df)
        X_test_transformed = self.feature_pipeline.transform(X_test_df)

        return X_train_transformed, X_test_transformed, y_train, y_test

    def _process_labels(self, y_raw: pd.Series) -> np.ndarray:
        """
        Convert raw string labels into numeric class indices.

        Args:
            y_raw: Series of raw string labels.

        Returns:
            np.ndarray: Integer encoded array of labels.
        """
        if self.binary_classification:
            # 0 = Benign/Normal, 1 = Intrusion/Attack
            y_binary = y_raw.str.lower().apply(
                lambda val: 0 if self.normal_label_value in val else 1
            ).values
            self.class_names = ["Normal", "Attack"]
            return y_binary
        else:
            self.label_encoder = LabelEncoder()
            y_encoded = self.label_encoder.fit_transform(y_raw)
            self.class_names = list(self.label_encoder.classes_)
            return y_encoded

    def save_processed_data(
        self,
        X_train: np.ndarray,
        X_test: np.ndarray,
        y_train: np.ndarray,
        y_test: np.ndarray,
        output_dir: str = "ml/data/processed",
    ) -> Dict[str, str]:
        """
        Save preprocessed matrices to disk for auditability and experiment tracking.

        Args:
            X_train: Transformed training features.
            X_test: Transformed testing features.
            y_train: Training labels.
            y_test: Testing labels.
            output_dir: Destination folder.

        Returns:
            Dict containing paths of saved files.
        """
        out_path = Path(output_dir)
        out_path.mkdir(parents=True, exist_ok=True)

        train_feat_path = out_path / "X_train.npy"
        test_feat_path = out_path / "X_test.npy"
        train_lbl_path = out_path / "y_train.npy"
        test_lbl_path = out_path / "y_test.npy"

        np.save(train_feat_path, X_train)
        np.save(test_feat_path, X_test)
        np.save(train_lbl_path, y_train)
        np.save(test_lbl_path, y_test)

        return {
            "X_train": str(train_feat_path),
            "X_test": str(test_feat_path),
            "y_train": str(train_lbl_path),
            "y_test": str(test_lbl_path),
        }
