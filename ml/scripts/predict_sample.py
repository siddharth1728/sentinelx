"""
predict_sample.py - Live Inference Demonstration for SENTINELX.

Why this script exists:
Demonstrates how Phase 2 (FastAPI backend), security automation scripts,
or SOC analysts can pass raw network connection dictionaries into the
SentinelXPredictor service and obtain instant intrusion classifications,
confidence scores, and probability vectors.
"""

import json
import sys
from pathlib import Path

# Add project root to sys.path
project_root = Path(__file__).resolve().parent.parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from ml.src.inference.predictor import SentinelXPredictor


def run_prediction_demo():
    print(f"\n{'='*65}")
    print("  SENTINELX: Real-Time Network Flow Inference Test")
    print(f"{'='*65}\n")

    print("[1/2] Initializing SentinelXPredictor service...")
    predictor = SentinelXPredictor(model_dir="ml/models")
    print("      Model and Preprocessor loaded successfully.")

    # Define test flow records representing different network scenarios
    sample_flows = [
        {
            "scenario": "Benign HTTPS Web Traffic",
            "data": {
                "duration": 1.25,
                "protocol_type": "tcp",
                "service": "https",
                "flag": "SF",
                "src_bytes": 1420,
                "dst_bytes": 8940,
                "count": 4,
                "srv_count": 4,
                "same_srv_rate": 1.0,
                "diff_srv_rate": 0.0,
                "dst_host_count": 15,
                "dst_host_srv_count": 15,
                "dst_host_same_srv_rate": 1.0,
                "dst_host_diff_srv_rate": 0.0,
            },
        },
        {
            "scenario": "High-Volume SYN Flood (DoS Attack)",
            "data": {
                "duration": 0.0,
                "protocol_type": "tcp",
                "service": "http",
                "flag": "S0",
                "src_bytes": 0,
                "dst_bytes": 0,
                "count": 480,
                "srv_count": 480,
                "same_srv_rate": 1.0,
                "diff_srv_rate": 0.0,
                "dst_host_count": 255,
                "dst_host_srv_count": 12,
                "dst_host_same_srv_rate": 0.05,
                "dst_host_diff_srv_rate": 0.85,
            },
        },
        {
            "scenario": "Host & Port Scanning (Reconnaissance Probe)",
            "data": {
                "duration": 0.02,
                "protocol_type": "tcp",
                "service": "private",
                "flag": "REJ",
                "src_bytes": 0,
                "dst_bytes": 0,
                "count": 120,
                "srv_count": 2,
                "same_srv_rate": 0.02,
                "diff_srv_rate": 0.98,
                "dst_host_count": 255,
                "dst_host_srv_count": 3,
                "dst_host_same_srv_rate": 0.01,
                "dst_host_diff_srv_rate": 0.95,
            },
        },
        {
            "scenario": "SSH Password Brute Force Attempt",
            "data": {
                "duration": 1.80,
                "protocol_type": "tcp",
                "service": "ssh",
                "flag": "SF",
                "src_bytes": 380,
                "dst_bytes": 240,
                "count": 65,
                "srv_count": 60,
                "same_srv_rate": 0.95,
                "diff_srv_rate": 0.05,
                "dst_host_count": 180,
                "dst_host_srv_count": 55,
                "dst_host_same_srv_rate": 0.85,
                "dst_host_diff_srv_rate": 0.05,
            },
        },
    ]

    print("\n[2/2] Running inference on incoming sample network flows:\n")

    for i, test_case in enumerate(sample_flows, 1):
        scenario_name = test_case["scenario"]
        payload = test_case["data"]

        result = predictor.predict_single(payload)

        status_tag = "[ALERT: INTRUSION DETECTED]" if result["is_intrusion"] else "[PASS: BENIGN TRAFFIC]"
        print(f"--- Flow #{i}: {scenario_name} ---")
        print(f"  Result       : {status_tag}")
        print(f"  Class Label  : {result['predicted_label']} (ID: {result['predicted_class_id']})")
        print(f"  Confidence   : {result['confidence'] * 100:.2f}%")
        print(f"  Probabilities: {json.dumps(result['probabilities'])}")
        print(f"  Latency      : {result['inference_time_ms']} ms\n")

    print(f"{'='*65}")
    print("  Prediction demonstration completed.")
    print(f"{'='*65}\n")


if __name__ == "__main__":
    run_prediction_demo()
