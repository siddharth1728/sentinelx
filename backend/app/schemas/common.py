"""
common.py - Common Pydantic Response and Pagination Schemas.
"""

from typing import Generic, TypeVar, List, Optional
from pydantic import BaseModel, ConfigDict

T = TypeVar("T")


class BaseResponse(BaseModel):
    """Standard success response wrapper."""
    model_config = ConfigDict(from_attributes=True)
    status: str = "success"
    message: Optional[str] = None


class PaginatedResponse(BaseModel, Generic[T]):
    """Standard paginated list container."""
    model_config = ConfigDict(from_attributes=True)
    total: int
    page: int
    page_size: int
    items: List[T]


class HealthResponse(BaseModel):
    """System health check payload."""
    status: str
    app_name: str
    version: str
    environment: str
    database_connected: bool
    ml_model_loaded: bool
    model_version: Optional[str] = None
