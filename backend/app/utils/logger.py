"""
logger.py - Structured Application Logging for SENTINELX Backend.

Why this module exists:
Security operations require transparent audit trails and diagnostic observability.
This module configures consistent, formatted logging across all routes,
services, database sessions, and ML inference invocations.
"""

import logging
import sys
from typing import Optional


def setup_logging(log_level: str = "INFO") -> None:
    """
    Configure global logging format and handler.

    Args:
        log_level: Desired log level string ('DEBUG', 'INFO', 'WARNING', 'ERROR').
    """
    numeric_level = getattr(logging, log_level.upper(), logging.INFO)
    
    log_format = "%(asctime)s | %(levelname)-8s | [%(name)s] %(message)s"
    date_format = "%Y-%m-%d %H:%M:%S"

    logging.basicConfig(
        level=numeric_level,
        format=log_format,
        datefmt=date_format,
        handlers=[
            logging.StreamHandler(sys.stdout)
        ],
        force=True
    )


def get_logger(name: Optional[str] = None) -> logging.Logger:
    """
    Get a namespaced logger instance.

    Args:
        name: Module or component name.

    Returns:
        logging.Logger: Configured logger.
    """
    logger_name = f"sentinelx.{name}" if name else "sentinelx"
    return logging.getLogger(logger_name)
