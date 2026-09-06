"""
run_pipeline.py - End-to-End ML Pipeline Orchestrator for SENTINELX.

Why this script exists:
Provides a unified, single-command orchestration script that executes the complete
Phase 1 ML workflow:
  1. Data Ingestion / Generation
  2. Inspection & Data Quality Cleaning
  3. Feature Transformation & Stratified Train/Test Splitting
  4. Baseline Random Forest Model Training
  5. Performance Evaluation & Confusion Matrix Analysis
  6. Model Artifact Persistence
  7. Inference Sanity Testing
"""

import argparse
import sys
from pathlib import Path

# Add project root to sys.path
project_root = Path(__file__).resolve().parent.parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from ml.scripts.generate_sample_data import generate_network_dataset
from ml.scripts.train_model import run_training
from ml.scripts.evaluate_model import run_evaluation
from ml.scripts.predict_sample import run_prediction_demo


def main():
    parser = argparse.ArgumentParser(description="Run the full SENTINELX Phase 1 ML Pipeline.")
    parser.add_argument("--data-path", type=str, default="ml/data/raw/network_traffic.csv", help="Path to raw CSV dataset")
    parser.add_argument("--force-generate", action="store_true", help="Force re-generation of synthetic network dataset")
    parser.add_argument("--samples", type=int, default=5000, help="Number of samples if generating dataset")
    parser.add_argument("--trees", type=int, default=100, help="Number of trees in Random Forest")
    parser.add_argument("--depth", type=int, default=15, help="Max depth of Random Forest")
    args = parser.parse_args()

    raw_path = Path(args.data_path)

    print("\n" + "#" * 70)
    print("  SENTINELX: END-TO-END DEFENSIVE ML PIPELINE RUNNER")
    print("#" * 70 + "\n")

    # Step 1: Ensure raw dataset exists
    if not raw_path.exists() or args.force_generate:
        print(f"[PIPELINE STEP 1] Generating controlled network flow dataset ({args.samples:,} samples)...")
        generate_network_dataset(n_samples=args.samples, output_path=str(raw_path))
    else:
        print(f"[PIPELINE STEP 1] Using existing dataset at: {raw_path}")

    # Step 2: Training (Ingestion, Preprocessing, Splitting, Fitting, Saving)
    print("\n[PIPELINE STEP 2] Executing Training Pipeline...")
    run_training(
        data_path=str(raw_path),
        output_model_dir="ml/models",
        output_data_dir="ml/data/processed",
        n_estimators=args.trees,
        max_depth=args.depth,
    )

    # Step 3: Evaluation (Metrics, Confusion Matrix, JSON Report, Plot)
    print("\n[PIPELINE STEP 3] Executing Model Evaluation...")
    run_evaluation(
        model_path="ml/models/sentinelx_rf_model.joblib",
        test_features_path="ml/data/processed/X_test.npy",
        test_labels_path="ml/data/processed/y_test.npy",
        output_dir="ml/models",
    )

    # Step 4: Inference Demonstration
    print("\n[PIPELINE STEP 4] Executing Inference Sanity Check...")
    run_prediction_demo()

    print("\n" + "#" * 70)
    print("  SENTINELX Phase 1 Pipeline Completed Successfully!")
    print("#" * 70 + "\n")


if __name__ == "__main__":
    main()
