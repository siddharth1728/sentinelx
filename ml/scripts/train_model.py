"""
train_model.py - Standalone Training Pipeline CLI for SENTINELX.

Why this script exists:
Enables ML engineers and cybersecurity analysts to run model training
reproducibly from the command line, persisting fitted feature transformers,
trained Random Forest models, and metadata into `ml/models/`.
"""

import argparse
import sys
from pathlib import Path

# Add project root to sys.path so modules can be imported directly
project_root = Path(__file__).resolve().parent.parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from ml.src.preprocessing.data_loader import DataLoader
from ml.src.preprocessing.preprocessor import NetworkDataPreprocessor
from ml.src.training.train import ModelTrainer


def run_training(
    data_path: str = "ml/data/raw/network_traffic.csv",
    output_model_dir: str = "ml/models",
    output_data_dir: str = "ml/data/processed",
    n_estimators: int = 100,
    max_depth: int = 15,
    random_state: int = 42,
):
    """
    Execute full dataset ingestion, preprocessing, and model training.
    """
    print(f"\n{'='*60}")
    print("  SENTINELX: Phase 1 ML Model Training")
    print(f"{'='*60}\n")

    # Step 1: Load raw data
    print(f"[1/4] Loading raw dataset from: {data_path}")
    loader = DataLoader(data_path)
    df = loader.load_csv()
    inspection = loader.inspect_dataset(df)
    print(f"      Rows: {inspection['total_rows']:,} | Columns: {inspection['total_columns']}")
    print(f"      Missing Values: {inspection['total_missing_cells']} | Duplicates: {inspection['duplicate_rows']}")

    # Step 2: Preprocess & Partition Data
    print("\n[2/4] Partitioning & transforming features (Stratified 80/20 Train-Test Split)...")
    preprocessor = NetworkDataPreprocessor(
        label_column="label",
        binary_classification=True,
        normal_label_value="normal",
        test_size=0.2,
        random_state=random_state,
    )
    X_train, X_test, y_train, y_test = preprocessor.prepare_dataset(df)
    print(f"      Training samples : {len(X_train):,} (Features: {X_train.shape[1]})")
    print(f"      Testing samples  : {len(X_test):,}  (Features: {X_test.shape[1]})")

    # Save processed matrices for reproducibility
    saved_data = preprocessor.save_processed_data(
        X_train, X_test, y_train, y_test, output_dir=output_data_dir
    )
    print(f"      Saved preprocessed data to: {output_data_dir}")

    # Step 3: Train Baseline Random Forest
    print("\n[3/4] Training baseline Random Forest Classifier...")
    trainer = ModelTrainer(
        n_estimators=n_estimators,
        max_depth=max_depth,
        class_weight="balanced",
        random_state=random_state,
    )
    model = trainer.train(
        X_train=X_train,
        y_train=y_train,
        feature_pipeline=preprocessor.feature_pipeline,
        class_names=preprocessor.class_names,
    )
    print("      Model training complete.")

    # Step 4: Save Artifacts
    print(f"\n[4/4] Serializing model and preprocessor to: {output_model_dir}")
    saved_artifacts = trainer.save_model(
        output_dir=output_model_dir,
        feature_pipeline=preprocessor.feature_pipeline,
    )
    for k, v in saved_artifacts.items():
        print(f"      - {k}: {v}")

    print(f"\n{'='*60}")
    print("  Training finished successfully.")
    print(f"{'='*60}\n")
    return model, preprocessor.feature_pipeline, (X_test, y_test)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Train SENTINELX Random Forest IDS model.")
    parser.add_argument("--data", type=str, default="ml/data/raw/network_traffic.csv", help="Path to raw CSV dataset")
    parser.add_argument("--model-dir", type=str, default="ml/models", help="Output directory for model artifacts")
    parser.add_argument("--trees", type=int, default=100, help="Number of trees (n_estimators)")
    parser.add_argument("--depth", type=int, default=15, help="Maximum tree depth")
    args = parser.parse_args()

    run_training(
        data_path=args.data,
        output_model_dir=args.model_dir,
        n_estimators=args.trees,
        max_depth=args.depth,
    )
