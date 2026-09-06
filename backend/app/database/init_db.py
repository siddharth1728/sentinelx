"""
init_db.py - Database Schema Initialization and Health Check.

Why this module exists:
Ensures all database tables and indexes are created upon application startup
without requiring manual DDL execution. Also provides connection validation.
"""

from sqlalchemy import text
from ..models.base import Base
from .session import engine
from ..utils.logger import get_logger

logger = get_logger("init_db")


def init_db() -> None:
    """
    Initialize database schema (create all tables if they do not exist).
    """
    logger.info("Initializing database schema...")
    try:
        Base.metadata.create_all(bind=engine)
        logger.info("Database schema initialized successfully.")
    except Exception as exc:
        logger.error(f"Failed to initialize database tables: {exc}", exc_info=True)
        raise


def check_db_health() -> bool:
    """
    Ping the database engine to verify connectivity.

    Returns:
        bool: True if query executes successfully, False otherwise.
    """
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        return True
    except Exception as exc:
        logger.warning(f"Database health check failed: {exc}")
        return False
