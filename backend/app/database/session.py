"""
session.py - SQLAlchemy Database Connection & Session Management.

Why this module exists:
Manages engine creation, connection pooling, and request-scoped session lifecycle.
Provides the `get_db` FastAPI dependency with automatic commit/rollback/close guarantees.
"""

from typing import Generator
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session

from ..config import settings
from ..utils.logger import get_logger

logger = get_logger("database")

# Handle SQLite vs PostgreSQL connection configurations
connect_args = {}
if settings.DATABASE_URL.startswith("sqlite"):
    connect_args = {"check_same_thread": False}

# Create SQLAlchemy engine with connection pooling
engine = create_engine(
    settings.DATABASE_URL,
    echo=settings.DEBUG,
    connect_args=connect_args,
    pool_pre_ping=True,  # Automatically verify connections before checkout
)

# Request-scoped session factory
SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine,
    expire_on_commit=False,
)


def get_db() -> Generator[Session, None, None]:
    """
    FastAPI dependency yielding an active database session per request.
    Ensures safe cleanup and rollback on unhandled exceptions.
    """
    db = SessionLocal()
    try:
        yield db
    except Exception as exc:
        db.rollback()
        logger.error(f"Database transaction error: {exc}", exc_info=True)
        raise
    finally:
        db.close()
