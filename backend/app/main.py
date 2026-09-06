"""
main.py - FastAPI Application Entry Point for SENTINELX Backend.

Why this module exists:
Serves as the root orchestrator for the backend service:
- Initializes database tables upon startup.
- Pre-loads and warms up the ML detection engine.
- Configures CORS for secure communication with frontend clients.
- Registers structured exception handlers for consistent API error responses.
- Generates interactive OpenAPI & Swagger UI documentation (/docs, /redoc).
"""

from contextlib import asynccontextmanager
from typing import AsyncGenerator
from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError

from .config import settings
from .database.init_db import init_db
from .ml.model_loader import get_ml_predictor
from .api.routes import api_router
from .utils.logger import setup_logging, get_logger

# Initialize logging configuration
setup_logging(settings.LOG_LEVEL)
logger = get_logger("main")


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """
    Application startup and shutdown lifecycle manager.
    """
    logger.info(f"Starting {settings.APP_NAME} v{settings.APP_VERSION} ({settings.APP_ENV})...")

    # 1. Initialize Database Schema
    try:
        init_db()
        logger.info("Database schema verification completed.")
    except Exception as exc:
        logger.error(f"Critical error during database initialization: {exc}", exc_info=True)

    # 2. Pre-load ML Model and Feature Transformers
    try:
        predictor = get_ml_predictor()
        logger.info(f"ML Detection Engine initialized successfully with {len(predictor.class_names)} classes.")
    except Exception as exc:
        logger.warning(f"ML Model pre-loading deferred or failed: {exc}")

    yield

    logger.info(f"Shutting down {settings.APP_NAME}...")


# Create FastAPI application instance with OpenAPI metadata
app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description="""
# SENTINELX Security Analytics & Intrusion Detection API

SENTINELX is an enterprise-grade defensive cybersecurity platform providing real-time
machine-learning intrusion detection, automated alert generation, incident case management,
and security analytics.

### Key Features:
* **ML Intrusion Detection**: Real-time vector inference for tabular network flow telemetry.
* **Security Event Persistence**: Storage of network events and model audit logs in PostgreSQL.
* **Alert Triage**: Automated rule-based and ML-driven alert generation with status lifecycles.
* **Incident Management**: Incident case correlation and mitigation tracking for SOC teams.
* **SOC Telemetry & Statistics**: Aggregated KPIs and threat taxonomy distributions.
    """,
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
    lifespan=lifespan,
)

# Configure Cross-Origin Resource Sharing (CORS)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS if isinstance(settings.ALLOWED_ORIGINS, list) else ["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global Exception Handlers
@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    """Format Pydantic validation errors cleanly."""
    logger.warning(f"Input validation error at {request.url.path}: {exc.errors()}")
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
        content={
            "status": "error",
            "error_type": "ValidationError",
            "message": "Invalid input format or out-of-bounds telemetry values.",
            "details": exc.errors(),
        },
    )


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """Catch-all unhandled exception handler to avoid leaking internal trace details."""
    logger.error(f"Unhandled internal server error at {request.url.path}: {exc}", exc_info=True)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "status": "error",
            "error_type": "InternalServerError",
            "message": "An unexpected error occurred while processing the security request.",
        },
    )


# Register API Routes
app.include_router(api_router, prefix=settings.API_V1_PREFIX)


@app.get("/", tags=["System & Diagnostics"], summary="Root Welcome Endpoint")
def read_root():
    """Welcome endpoint providing service metadata and documentation links."""
    return {
        "service": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "environment": settings.APP_ENV,
        "status": "OPERATIONAL",
        "docs_url": "/docs",
        "redoc_url": "/redoc",
        "health_check": f"{settings.API_V1_PREFIX}/health",
    }
