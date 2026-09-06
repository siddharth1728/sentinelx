"""
Inference module for SENTINELX.
Provides modular, decoupled prediction services suitable for Phase 2 FastAPI integration.
"""

from .predictor import SentinelXPredictor

__all__ = ["SentinelXPredictor"]
