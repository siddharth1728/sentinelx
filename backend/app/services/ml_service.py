"""
ml_service.py - Machine Learning Inference Service for SENTINELX.

Why this module exists:
Encapsulates ML prediction business logic, transforms Pydantic network flow schemas
into dictionary payloads for the predictor, applies post-prediction threat taxonomy rules,
and returns structured DetectionResult objects.
"""

from typing import List, Dict, Any
from ..schemas.network_flow import NetworkFlowInput
from ..schemas.detection import DetectionResult
from ..ml.model_loader import get_ml_predictor
from ..utils.logger import get_logger

logger = get_logger("ml_service")


class MLService:
    """
    MLService coordinates model inference, feature preprocessing,
    and threat categorization.
    """

    @staticmethod
    def infer_threat_type(flow: NetworkFlowInput, is_intrusion: bool) -> str:
        """
        Classify the specific attack taxonomy based on flow indicators.

        Args:
            flow: The validated NetworkFlowInput object.
            is_intrusion: Boolean flag from the ML classifier.

        Returns:
            str: Threat classification category.
        """
        if not is_intrusion:
            return "Benign Traffic"

        # Heuristic taxonomy refinement based on telemetry patterns
        if flow.flag in ["S0", "RSTOS0"] and (flow.count > 100 or flow.dst_bytes == 0):
            return "DoS SYN Flood"
        elif flow.diff_srv_rate > 0.60 or flow.dst_host_diff_srv_rate > 0.60:
            return "Reconnaissance Port Scan"
        elif flow.service in ["ssh", "ftp"] and flow.count > 30 and flow.srv_count > 20:
            return "Brute Force Authentication"
        else:
            return "Network Anomaly / Malicious Flow"

    def predict_flow(self, flow: NetworkFlowInput) -> DetectionResult:
        """
        Execute ML inference on a single network flow record.

        Args:
            flow: Validated network flow input.

        Returns:
            DetectionResult: Classification results, confidence, and latency.
        """
        predictor = get_ml_predictor()
        flow_dict = flow.model_dump()

        raw_result = predictor.predict_single(flow_dict)
        is_intrusion = raw_result["is_intrusion"]

        return DetectionResult(
            is_intrusion=is_intrusion,
            predicted_label=raw_result["predicted_label"],
            predicted_class_id=raw_result["predicted_class_id"],
            confidence=raw_result["confidence"],
            probabilities=raw_result["probabilities"],
            inference_time_ms=raw_result["inference_time_ms"],
        )

    def predict_flows_batch(self, flows: List[NetworkFlowInput]) -> List[DetectionResult]:
        """
        Execute ML inference on a batch of network flow records.

        Args:
            flows: List of validated network flow inputs.

        Returns:
            List[DetectionResult]: Batch of prediction results.
        """
        import pandas as pd

        if not flows:
            return []

        predictor = get_ml_predictor()
        flow_dicts = [f.model_dump() for f in flows]
        df = pd.DataFrame(flow_dicts)

        raw_results = predictor.predict_batch(df)
        detection_results = []

        for r in raw_results:
            detection_results.append(
                DetectionResult(
                    is_intrusion=r["is_intrusion"],
                    predicted_label=r["predicted_label"],
                    predicted_class_id=r["predicted_class_id"],
                    confidence=r["confidence"],
                    probabilities=r["probabilities"],
                    inference_time_ms=r["inference_time_ms"],
                )
            )

        return detection_results


# Default instance
ml_service = MLService()
