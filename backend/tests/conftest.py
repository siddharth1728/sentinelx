"""
conftest.py - Pytest Test Configuration and Fixtures.

Why this module exists:
Sets up an isolated in-memory SQLite test database for all API tests,
overrides FastAPI database session dependencies, and provides a pre-configured
TestClient instance.
"""

import sys
from pathlib import Path
from typing import Generator
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.pool import StaticPool

# Ensure backend root is in sys.path
backend_root = Path(__file__).resolve().parent.parent
if str(backend_root) not in sys.path:
    sys.path.insert(0, str(backend_root))

from app.database.session import get_db
from app.models.base import Base
from app.main import app

# In-memory SQLite engine for fast, isolated test runs
SQLALCHEMY_DATABASE_URL = "sqlite:///:memory:"

test_engine = create_engine(
    SQLALCHEMY_DATABASE_URL,
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)


@pytest.fixture(scope="session", autouse=True)
def setup_test_database():
    """Create all tables before test session and drop them afterward."""
    Base.metadata.create_all(bind=test_engine)
    yield
    Base.metadata.drop_all(bind=test_engine)


@pytest.fixture()
def db_session() -> Generator[Session, None, None]:
    """Provide a fresh transactional session for each test."""
    connection = test_engine.connect()
    transaction = connection.begin()
    session = TestingSessionLocal(bind=connection)

    yield session

    session.close()
    transaction.rollback()
    connection.close()


@pytest.fixture()
def client(db_session: Session) -> Generator[TestClient, None, None]:
    """Provide a TestClient with overridden database dependency."""
    def override_get_db():
        try:
            yield db_session
        finally:
            pass

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


@pytest.fixture()
def sample_benign_flow() -> dict:
    """Sample benign network flow payload."""
    return {
        "source_ip": "192.168.1.50",
        "destination_ip": "10.0.0.1",
        "source_port": 54321,
        "destination_port": 443,
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
    }


@pytest.fixture()
def sample_syn_flood_flow() -> dict:
    """Sample malicious SYN flood flow payload."""
    return {
        "source_ip": "203.0.113.19",
        "destination_ip": "10.0.0.80",
        "source_port": 49152,
        "destination_port": 80,
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
    }
