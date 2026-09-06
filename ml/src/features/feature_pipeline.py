"""
feature_pipeline.py - Feature Transformation and Scaling Pipeline for SENTINELX.

Why this module exists:
Raw network packets and connection logs combine numerical measurements (e.g. byte counts,
duration, connection frequencies) with categorical protocols/flags (e.g. TCP, UDP, SF, REJ).
This module builds a reusable Scikit-Learn ColumnTransformer that standardizes numerical
metrics and encodes categorical signals into a normalized numeric vector format.
Critically, it handles unseen categories gracefully (handle_unknown='ignore') to prevent
inference crashes in production or live monitoring.
"""

from typing import List, Optional, Dict, Any
import numpy as np
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.preprocessing import StandardScaler, OneHotEncoder
from sklearn.impute import SimpleImputer
from sklearn.pipeline import Pipeline


class FeaturePipeline:
    """
    FeaturePipeline constructs, fits, and manages feature transformers
    for network intrusion detection datasets.
    """

    def __init__(
        self,
        numerical_cols: Optional[List[str]] = None,
        categorical_cols: Optional[List[str]] = None,
    ):
        """
        Initialize FeaturePipeline.

        Args:
            numerical_cols: List of column names representing continuous/numerical features.
            categorical_cols: List of column names representing categorical attributes.
        """
        self.numerical_cols = numerical_cols or []
        self.categorical_cols = categorical_cols or []
        self.transformer: Optional[ColumnTransformer] = None
        self.feature_names_out: List[str] = []

    def build_transformer(self) -> ColumnTransformer:
        """
        Construct a ColumnTransformer with imputation and standard scaling for numerical features,
        and one-hot encoding for categorical features.

        Returns:
            ColumnTransformer: Scikit-learn transformer ready for fitting.
        """
        # Numerical pipeline: impute missing values with median, then standardize
        num_pipeline = Pipeline([
            ("imputer", SimpleImputer(strategy="median")),
            ("scaler", StandardScaler()),
        ])

        # Categorical pipeline: impute missing values with 'missing', then OneHotEncode
        cat_pipeline = Pipeline([
            ("imputer", SimpleImputer(strategy="constant", fill_value="missing")),
            ("onehot", OneHotEncoder(handle_unknown="ignore", sparse_output=False)),
        ])

        transformers = []
        if self.numerical_cols:
            transformers.append(("num", num_pipeline, self.numerical_cols))
        if self.categorical_cols:
            transformers.append(("cat", cat_pipeline, self.categorical_cols))

        self.transformer = ColumnTransformer(
            transformers=transformers,
            remainder="drop"  # Drop any unselected/unknown column
        )
        return self.transformer

    def fit(self, X: pd.DataFrame) -> "FeaturePipeline":
        """
        Fit the transformer on the training feature DataFrame.

        Args:
            X: Input training features DataFrame.

        Returns:
            self: Fitted FeaturePipeline instance.
        """
        self._validate_input_columns(X)
        if self.transformer is None:
            self.build_transformer()

        self.transformer.fit(X)
        self._extract_feature_names()
        return self

    def transform(self, X: pd.DataFrame) -> np.ndarray:
        """
        Transform input features into scaled/encoded numpy array.

        Args:
            X: Input features DataFrame.

        Returns:
            np.ndarray: Transformed numeric matrix.
        """
        if self.transformer is None:
            raise RuntimeError(
                "[SENTINELX ERROR] FeaturePipeline transformer has not been fitted or loaded."
            )
        self._validate_input_columns(X)
        return self.transformer.transform(X)

    def fit_transform(self, X: pd.DataFrame) -> np.ndarray:
        """
        Fit and transform features in a single step.

        Args:
            X: Input training features DataFrame.

        Returns:
            np.ndarray: Transformed numeric matrix.
        """
        return self.fit(X).transform(X)

    def _validate_input_columns(self, X: pd.DataFrame) -> None:
        """
        Validate that required columns exist in input DataFrame.

        Args:
            X: Input DataFrame.

        Raises:
            ValueError: If expected numerical or categorical columns are missing.
        """
        expected_cols = set(self.numerical_cols + self.categorical_cols)
        missing_cols = expected_cols - set(X.columns)
        if missing_cols:
            raise ValueError(
                f"[SENTINELX ERROR] Input DataFrame is missing required feature columns: {sorted(list(missing_cols))}"
            )

    def _extract_feature_names(self) -> None:
        """Cache transformed feature names after fitting."""
        try:
            if hasattr(self.transformer, "get_feature_names_out"):
                self.feature_names_out = list(self.transformer.get_feature_names_out())
        except Exception:
            self.feature_names_out = []

    def get_metadata(self) -> Dict[str, Any]:
        """
        Return metadata describing the pipeline structure.

        Returns:
            Dict containing numerical_cols, categorical_cols, and output feature counts.
        """
        return {
            "numerical_cols": self.numerical_cols,
            "categorical_cols": self.categorical_cols,
            "num_transformed_features": len(self.feature_names_out),
            "transformed_feature_names": self.feature_names_out,
        }
