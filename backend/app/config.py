"""
config.py - Centralized Configuration Management for SENTINELX Backend.

Why this module exists:
Follows 12-factor application design principles by decoupling environment
configurations, secrets, database credentials, and model paths from codebase logic.
All values are validated at startup through Pydantic BaseSettings.
"""

from pathlib import Path
from typing import List, Union
from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """
    Application settings loaded from environment variables and .env file.
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # Core Application
    APP_NAME: str = "SENTINELX Security Analytics Platform"
    APP_VERSION: str = "1.0.0"
    APP_ENV: str = "development"
    API_V1_PREFIX: str = "/api/v1"
    DEBUG: bool = False
    LOG_LEVEL: str = "INFO"

    # Server Binding
    HOST: str = "0.0.0.0"
    PORT: int = 8000

    # PostgreSQL / SQLAlchemy Connection URL
    # Defaults to SQLite local database if PostgreSQL URL is not provided in env
    DATABASE_URL: str = "sqlite:///./sentinelx.db"

    # Security & Incident Response Parameters
    INTRUSION_CONFIDENCE_THRESHOLD: float = 0.70
    ENABLE_AUTO_ALERT_CREATION: bool = True

    # Machine Learning Model Artifacts
    MODEL_DIR: str = str((Path(__file__).resolve().parent.parent.parent / "ml" / "models").resolve())
    MODEL_FILE: str = "sentinelx_rf_model.joblib"
    PREPROCESSOR_FILE: str = "preprocessor.joblib"
    METADATA_FILE: str = "model_metadata.json"

    # CORS Origins (List of strings or comma-separated string)
    ALLOWED_ORIGINS: Union[List[str], str] = [
        "http://localhost:3000",
        "http://localhost:5173",
        "http://127.0.0.1:3000",
        "http://127.0.0.1:5173",
    ]

    @field_validator("ALLOWED_ORIGINS", mode="before")
    @classmethod
    def assemble_cors_origins(cls, v: Union[str, List[str]]) -> List[str]:
        if isinstance(v, str):
            return [i.strip() for i in v.split(",") if i.strip()]
        elif isinstance(v, list):
            return v
        return []


# Global cached settings instance
settings = Settings()
