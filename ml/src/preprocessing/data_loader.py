"""
data_loader.py - Secure and Robust Dataset Ingestion for SENTINELX.

Why this module exists:
In network intrusion detection, raw security logs and packet flow captures
frequently contain malformed records, missing values, or corrupted timestamps.
This module provides a safe, reproducible entry point for loading network telemetry
datasets, inspecting schemas, and removing corrupt rows before downstream processing.
"""

import os
from pathlib import Path
from typing import Optional, Tuple, Dict, Any
import pandas as pd


class DataLoader:
    """
    DataLoader handles reading raw network flow datasets from disk,
    performing initial integrity checks, logging structural information,
    and returning verified DataFrames.
    """

    def __init__(self, data_path: Optional[str] = None):
        """
        Initialize DataLoader.
        
        Args:
            data_path: Optional default path to the dataset CSV file.
        """
        self.data_path = Path(data_path) if data_path else None

    def load_csv(self, file_path: Optional[str] = None) -> pd.DataFrame:
        """
        Load a CSV file with defensive error handling for missing files and malformed lines.

        Args:
            file_path: Optional override path for the CSV file.

        Returns:
            pd.DataFrame: Loaded raw dataset.

        Raises:
            FileNotFoundError: If the specified file does not exist.
            ValueError: If the file is empty, not a CSV, or cannot be parsed.
        """
        target_path = Path(file_path) if file_path else self.data_path

        if target_path is None:
            raise ValueError("No file path provided to DataLoader.")

        if not target_path.exists():
            raise FileNotFoundError(
                f"[SENTINELX ERROR] Dataset not found at: {target_path.resolve()}"
            )

        if not target_path.is_file():
            raise ValueError(f"[SENTINELX ERROR] Path is not a file: {target_path.resolve()}")

        if target_path.suffix.lower() not in [".csv", ".txt"]:
            raise ValueError(
                f"[SENTINELX ERROR] Unsupported file format '{target_path.suffix}'. Expected .csv or .txt"
            )

        try:
            # Using on_bad_lines='warn' to gracefully skip corrupt lines in raw telemetry
            df = pd.read_csv(target_path, on_bad_lines="warn")
        except Exception as exc:
            raise ValueError(
                f"[SENTINELX ERROR] Failed to parse dataset CSV at {target_path}: {exc}"
            ) from exc

        if df.empty:
            raise ValueError(f"[SENTINELX ERROR] Loaded dataset is empty: {target_path}")

        return df

    @staticmethod
    def inspect_dataset(df: pd.DataFrame) -> Dict[str, Any]:
        """
        Inspect dataset shape, column names, missing value counts, and data types.

        Args:
            df: The pandas DataFrame to inspect.

        Returns:
            Dict containing metadata: shape, columns, missing_values, dtypes, duplicates.
        """
        missing_counts = df.isnull().sum().to_dict()
        total_missing = sum(missing_counts.values())
        duplicate_count = int(df.duplicated().sum())

        inspection = {
            "total_rows": len(df),
            "total_columns": len(df.columns),
            "columns": list(df.columns),
            "dtypes": {col: str(dtype) for col, dtype in df.dtypes.items()},
            "missing_values_per_column": {k: v for k, v in missing_counts.items() if v > 0},
            "total_missing_cells": total_missing,
            "duplicate_rows": duplicate_count,
        }
        return inspection

    @staticmethod
    def clean_invalid_rows(
        df: pd.DataFrame,
        drop_duplicates: bool = False,
        drop_na: bool = True
    ) -> Tuple[pd.DataFrame, Dict[str, int]]:
        """
        Remove invalid or missing rows from the DataFrame while tracking drop metrics.

        Args:
            df: Input DataFrame.
            drop_duplicates: Whether to drop identical flow rows. (In network traffic,
                             identical flows can be valid retransmissions/floods, so default is False).
            drop_na: Whether to drop rows with missing values (NaN/null).

        Returns:
            Tuple of (cleaned_df, drop_stats_dict).
        """
        initial_count = len(df)
        cleaned_df = df.copy()

        na_dropped = 0
        dup_dropped = 0

        if drop_na:
            before_na = len(cleaned_df)
            cleaned_df = cleaned_df.dropna()
            na_dropped = before_na - len(cleaned_df)

        if drop_duplicates:
            before_dup = len(cleaned_df)
            cleaned_df = cleaned_df.drop_duplicates()
            dup_dropped = before_dup - len(cleaned_df)

        stats = {
            "initial_rows": initial_count,
            "final_rows": len(cleaned_df),
            "na_rows_removed": na_dropped,
            "duplicates_removed": dup_dropped,
            "total_removed": initial_count - len(cleaned_df),
        }

        return cleaned_df, stats
