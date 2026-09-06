"""
evaluate.py - Performance Evaluation & Defensive Metric Analysis for SENTINELX.

Why this module exists:
In network intrusion detection, standard accuracy is dangerously misleading because normal
traffic typically outnumbers malicious traffic 99-to-1 (the class imbalance problem).
A naive model predicting everything as 'Normal' achieves 99% accuracy but fails completely
at cybersecurity defense.

This module computes cybersecurity-critical evaluation metrics:
- Precision: Minimizes False Positives (avoids SOC analyst alert fatigue).
- Recall: Minimizes False Negatives (avoids undetected breach/compromise).
- F1 Score: Harmonic balance between Precision and Recall.
- Confusion Matrix: Explicit accounting of TP, FP, TN, and FN.
"""

import json
from pathlib import Path
from typing import Dict, Any, List, Optional
import matplotlib.pyplot as plt
import numpy as np
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    classification_report,
)


class ModelEvaluator:
    """
    ModelEvaluator calculates classification metrics, extracts confusion matrix breakdowns,
    generates visual diagnostic plots, and saves audit-ready evaluation summaries.
    """

    def __init__(self, class_names: Optional[List[str]] = None):
        """
        Initialize ModelEvaluator.

        Args:
            class_names: Names of classes, e.g. ['Normal', 'Attack'].
        """
        self.class_names = class_names or ["Normal", "Attack"]

    def evaluate(
        self,
        y_true: np.ndarray,
        y_pred: np.ndarray,
        y_proba: Optional[np.ndarray] = None,
    ) -> Dict[str, Any]:
        """
        Compute full suite of classification metrics.

        Args:
            y_true: Ground truth target labels.
            y_pred: Predicted class labels.
            y_proba: Optional prediction probabilities.

        Returns:
            Dict containing accuracy, precision, recall, f1, confusion matrix, and breakdown.
        """
        acc = float(accuracy_score(y_true, y_pred))
        
        # Determine average strategy for multi-class vs binary
        is_binary = len(np.unique(y_true)) <= 2 and len(self.class_names) <= 2
        avg_mode = "binary" if is_binary else "weighted"

        prec = float(precision_score(y_true, y_pred, average=avg_mode, zero_division=0))
        rec = float(recall_score(y_true, y_pred, average=avg_mode, zero_division=0))
        f1 = float(f1_score(y_true, y_pred, average=avg_mode, zero_division=0))

        macro_prec = float(precision_score(y_true, y_pred, average="macro", zero_division=0))
        macro_rec = float(recall_score(y_true, y_pred, average="macro", zero_division=0))
        macro_f1 = float(f1_score(y_true, y_pred, average="macro", zero_division=0))

        cm = confusion_matrix(y_true, y_pred)
        report_dict = classification_report(
            y_true,
            y_pred,
            target_names=self.class_names,
            output_dict=True,
            zero_division=0,
        )
        report_text = classification_report(
            y_true,
            y_pred,
            target_names=self.class_names,
            zero_division=0,
        )

        # Binary breakdown (Normal=0, Attack=1)
        matrix_breakdown = {}
        if is_binary and cm.shape == (2, 2):
            tn, fp, fn, tp = cm.ravel()
            matrix_breakdown = {
                "true_negatives_normal_allowed": int(tn),
                "false_positives_benign_flagged": int(fp),
                "false_negatives_attack_missed": int(fn),
                "true_positives_attack_detected": int(tp),
                "false_positive_rate": float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0,
                "false_negative_rate": float(fn / (fn + tp)) if (fn + tp) > 0 else 0.0,
            }

        results = {
            "summary_metrics": {
                "accuracy": acc,
                "precision": prec,
                "recall": rec,
                "f1_score": f1,
                "macro_precision": macro_prec,
                "macro_recall": macro_rec,
                "macro_f1_score": macro_f1,
            },
            "confusion_matrix": cm.tolist(),
            "binary_breakdown": matrix_breakdown,
            "classification_report": report_dict,
            "classification_report_text": report_text,
            "sample_counts": {
                "total_evaluated_samples": len(y_true),
                "true_class_distribution": {
                    self.class_names[i] if i < len(self.class_names) else str(i): int(count)
                    for i, count in enumerate(np.bincount(y_true))
                },
            },
        }
        return results

    def plot_confusion_matrix(
        self,
        cm: np.ndarray,
        output_path: str = "ml/models/confusion_matrix.png",
        title: str = "SENTINELX Intrusion Detection Confusion Matrix",
    ) -> str:
        """
        Plot and save confusion matrix heatmap as PNG.

        Args:
            cm: Confusion matrix array.
            output_path: File path to save the generated image.
            title: Plot title.

        Returns:
            str: Path to the saved image file.
        """
        out_file = Path(output_path)
        out_file.parent.mkdir(parents=True, exist_ok=True)

        fig, ax = plt.subplots(figsize=(6, 5))
        cax = ax.matshow(cm, cmap=plt.cm.Blues, alpha=0.85)

        for i in range(cm.shape[0]):
            for j in range(cm.shape[1]):
                ax.text(
                    x=j,
                    y=i,
                    s=f"{cm[i, j]:,}",
                    va="center",
                    ha="center",
                    size="large",
                    weight="bold",
                    color="white" if cm[i, j] > (cm.max() / 2) else "black",
                )

        fig.colorbar(cax)
        ticks = np.arange(len(self.class_names))
        ax.set_xticks(ticks)
        ax.set_yticks(ticks)
        ax.set_xticklabels(self.class_names)
        ax.set_yticklabels(self.class_names)
        ax.tick_params(axis="x", bottom=True, top=False, labelbottom=True, labeltop=False)

        plt.xlabel("Predicted Class", fontsize=11, fontweight="bold")
        plt.ylabel("True Class (Ground Truth)", fontsize=11, fontweight="bold")
        plt.title(title, fontsize=12, fontweight="bold", pad=15)
        plt.tight_layout()

        plt.savefig(out_file, dpi=300)
        plt.close(fig)

        return str(out_file)

    def save_metrics(
        self,
        metrics: Dict[str, Any],
        output_path: str = "ml/models/evaluation_metrics.json",
    ) -> str:
        """
        Save computed metrics to JSON for documentation and reporting.

        Args:
            metrics: Metrics dictionary computed by evaluate().
            output_path: Destination JSON filepath.

        Returns:
            str: Path to saved file.
        """
        out_file = Path(output_path)
        out_file.parent.mkdir(parents=True, exist_ok=True)

        with open(out_file, "w", encoding="utf-8") as f:
            json.dump(metrics, f, indent=2)

        return str(out_file)
