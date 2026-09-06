"""
evaluate_model.py - Standalone Model Evaluation CLI for SENTINELX.

Why this script exists:
Enables cybersecurity engineers to inspect performance metrics, review confusion
matrices, detect False Positive / False Negative trade-offs, and verify model behavior
on held-out test telemetry.
"""

import argparse
import sys
from pathlib import Path
import joblib
import numpy as np

# Add project root to sys.path
project_root = Path(__file__).resolve().parent.parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from ml.src.evaluation.evaluate import ModelEvaluator


def run_evaluation(
    model_path: str = "ml/models/sentinelx_rf_model.joblib",
    test_features_path: str = "ml/data/processed/X_test.npy",
    test_labels_path: str = "ml/data/processed/y_test.npy",
    output_dir: str = "ml/models",
):
    """
    Execute comprehensive model evaluation on test data.
    """
    print(f"\n{'='*60}")
    print("  SENTINELX: Phase 1 Model Evaluation & Cybersecurity Metrics")
    print(f"{'='*60}\n")

    # Step 1: Verify file existence
    m_file = Path(model_path)
    x_file = Path(test_features_path)
    y_file = Path(test_labels_path)

    if not m_file.exists():
        raise FileNotFoundError(f"[SENTINELX ERROR] Model file not found: {m_file.resolve()}")
    if not x_file.exists() or not y_file.exists():
        raise FileNotFoundError(
            f"[SENTINELX ERROR] Test data files not found in {x_file.parent.resolve()}. "
            "Run training or preprocessing first."
        )

    # Step 2: Load Model and Test Data
    print(f"[1/3] Loading model: {m_file}")
    model = joblib.load(m_file)
    X_test = np.load(x_file)
    y_test = np.load(y_file)
    print(f"      Loaded {len(X_test):,} test instances with {X_test.shape[1]} features.")

    # Step 3: Run Predictions
    print("\n[2/3] Generating test set predictions & probabilities...")
    y_pred = model.predict(X_test)
    y_proba = model.predict_proba(X_test) if hasattr(model, "predict_proba") else None

    # Step 4: Compute Metrics & Generate Plots
    print("\n[3/3] Calculating cybersecurity-specific metrics...")
    evaluator = ModelEvaluator(class_names=["Normal", "Attack"])
    metrics = evaluator.evaluate(y_true=y_test, y_pred=y_pred, y_proba=y_proba)

    # Save outputs
    cm_img_path = str(Path(output_dir) / "confusion_matrix.png")
    json_metrics_path = str(Path(output_dir) / "evaluation_metrics.json")
    evaluator.plot_confusion_matrix(np.array(metrics["confusion_matrix"]), output_path=cm_img_path)
    evaluator.save_metrics(metrics, output_path=json_metrics_path)

    # Print Formatted Report
    summary = metrics["summary_metrics"]
    breakdown = metrics.get("binary_breakdown", {})

    print("\n" + "-" * 50)
    print("  KEY PERFORMANCE METRICS:")
    print("-" * 50)
    print(f"  • Accuracy        : {summary['accuracy'] * 100:.2f}%")
    print(f"  • Precision       : {summary['precision'] * 100:.2f}% (Minimizes False Alarms)")
    print(f"  • Recall          : {summary['recall'] * 100:.2f}% (Catches Actual Intrusions)")
    print(f"  • F1 Score        : {summary['f1_score'] * 100:.2f}% (Harmonic Mean)")
    print("-" * 50)

    if breakdown:
        print("\n  CONFUSION MATRIX BREAKDOWN (CYBERSECURITY PERSPECTIVE):")
        print(f"  [TN] Normal Allowed (True Negatives)   : {breakdown.get('true_negatives_normal_allowed', 0):>5}")
        print(f"  [TP] Attacks Caught (True Positives)   : {breakdown.get('true_positives_attack_detected', 0):>5}")
        print(f"  [FP] Benign Flagged (False Positives)  : {breakdown.get('false_positives_benign_flagged', 0):>5}  <-- Causes Analyst Alert Fatigue")
        print(f"  [FN] Attacks Missed (False Negatives)  : {breakdown.get('false_negatives_attack_missed', 0):>5}  <-- Severe Security Breach Risk")
        print(f"  • False Positive Rate (FPR)            : {breakdown.get('false_positive_rate', 0.0) * 100:.2f}%")
        print(f"  • False Negative Rate (FNR)            : {breakdown.get('false_negative_rate', 0.0) * 100:.2f}%")

    print("\n  DETAILED CLASSIFICATION REPORT:")
    print(metrics["classification_report_text"])

    print(f"  Saved confusion matrix plot to : {cm_img_path}")
    print(f"  Saved detailed JSON metrics to : {json_metrics_path}")
    print(f"\n{'='*60}\n")
    return metrics


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Evaluate SENTINELX IDS model.")
    parser.add_argument("--model", type=str, default="ml/models/sentinelx_rf_model.joblib")
    parser.add_argument("--x-test", type=str, default="ml/data/processed/X_test.npy")
    parser.add_argument("--y-test", type=str, default="ml/data/processed/y_test.npy")
    parser.add_argument("--output-dir", type=str, default="ml/models")
    args = parser.parse_args()

    run_evaluation(
        model_path=args.model,
        test_features_path=args.x_test,
        test_labels_path=args.y_test,
        output_dir=args.output_dir,
    )
