"""Pydantic models for the HTTP API."""

from __future__ import annotations

from pydantic import BaseModel, Field


class ProviderConfig(BaseModel):
    """Provider configuration sent per-request from the Odosian web app."""

    base_url: str
    api_key: str
    model: str
    max_tokens: int | None = None
    temperature: float | None = None


class AnalyzeRequest(BaseModel):
    """Request body for /api/v1/analyze."""

    provider: ProviderConfig
    user_id: str
    rule_text: str = ""
    rule_id: str | None = None
    query: str = ""
    language: str = ""


class EnhanceRequest(BaseModel):
    """Request body for /api/v1/enhance."""

    provider: ProviderConfig
    user_id: str
    rule_text: str = ""
    rule_id: str | None = None


class GenerateRequest(BaseModel):
    """Request body for /api/v1/generate."""

    provider: ProviderConfig
    user_id: str
    requirement: str = ""


class HealthResponse(BaseModel):
    """Response body for /health."""

    status: str = "ok"
    pipeline_ready: bool = False


class StructuredIssue(BaseModel):
    """One validation issue with full context."""

    code: str
    severity: str
    category: str
    path: str
    message: str


class ErrorResponse(BaseModel):
    """Standard error response."""

    error: str
    category: str = ""
    issues: list[str] = Field(default_factory=list)
    structured_issues: list[StructuredIssue] = Field(default_factory=list)
