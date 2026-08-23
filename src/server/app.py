"""FastAPI application wrapping the Odosian AI Engine pipeline.

The pipeline builds once at startup (4.4s to index the 19MB knowledge base).
Provider configuration arrives per-request from the Odosian web app and is
never stored — each request carries the baseUrl, apiKey, and model the admin
configured in the Settings GUI.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import time
from collections import OrderedDict
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from pathlib import Path
from queue import Queue
from typing import Any, Final

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, StreamingResponse

from src.application.pipeline import Pipeline, StageCallback
from src.application.provider_factory import provider_from_request
from src.application.requests import EngineRequest
from src.config.config_loader import load_configuration
from src.config.secrets import Secret
from src.config.settings import EngineConfig
from src.core.exceptions import (
    InvalidReasoningRequestError,
    PromptRenderingError,
    ReasoningValidationError,
    ResponseSchemaError,
)
from src.core.types import ReasoningOperation
from src.context.exceptions import (
    ContextBudgetExceededError,
    ContextValidationError,
    SecretLeakError,
)
from src.llm.exceptions import (
    LLMAuthenticationError,
    LLMConnectionError,
    LLMError,
    LLMModelUnavailableError,
    LLMRateLimitError,
    LLMServiceUnavailableError,
    LLMTimeoutError,
)
from src.llm.provider import LLMProvider
from src.validation.exceptions import ValidationEngineError

from .schemas import (
    AnalyzeRequest as AnalyzeBody,
    EnhanceRequest as EnhanceBody,
    ErrorResponse,
    GenerateRequest as GenerateBody,
    HealthResponse,
    ProviderConfig,
)

logger = logging.getLogger(__name__)

_MAX_PROVIDER_CACHE: Final[int] = 10


class _ProviderCache:
    """LRU cache for provider instances, keyed by (base_url, model)."""

    def __init__(self, max_size: int = _MAX_PROVIDER_CACHE) -> None:
        self._cache: OrderedDict[tuple[str, str, str], LLMProvider] = OrderedDict()
        self._max_size = max_size
        self._api_keys: dict[tuple[str, str, str], str] = {}

    def get_or_create(self, config: ProviderConfig) -> LLMProvider:
        key = (config.base_url, config.model, config.api_key[:8])
        existing_key = self._api_keys.get(key)
        if key in self._cache and existing_key == config.api_key:
            self._cache.move_to_end(key)
            return self._cache[key]
        provider = provider_from_request(
            api_key=config.api_key,
            base_url=config.base_url,
            model=config.model,
        )
        self._cache[key] = provider
        self._api_keys[key] = config.api_key
        if len(self._cache) > self._max_size:
            evicted = self._cache.popitem(last=False)
            self._api_keys.pop(evicted[0], None)
        return provider


class _AppState:
    """Mutable state attached to the FastAPI app."""

    def __init__(self) -> None:
        self.pipeline: Pipeline | None = None
        self.config: EngineConfig | None = None
        self.provider_cache = _ProviderCache()
        self.ready = False
        self.startup_time: float = 0.0


_state = _AppState()


def _find_root_dir() -> Path:
    """Locate the engine root directory."""
    env_root = os.environ.get("ODOSIAN_ENGINE_ROOT")
    if env_root:
        return Path(env_root)
    here = Path(__file__).resolve()
    for parent in (here.parent.parent.parent, here.parent.parent):
        if (parent / "configs").is_dir():
            return parent
    return Path.cwd()


@asynccontextmanager
async def lifespan(app: FastAPI):
    root_dir = _find_root_dir()
    logger.info("engine root: %s", root_dir)

    dotenv_path = root_dir / ".env"
    config_data = load_configuration(
        root_dir,
        dotenv_path=dotenv_path if dotenv_path.exists() else None,
    )
    _state.config = EngineConfig.from_mapping(config_data, root_dir)

    dummy_secret = Secret("LLM_API_KEY", "server-managed")
    from src.application.provider_factory import provider_from_config
    try:
        default_provider = provider_from_config(
            _state.config, {"LLM_API_KEY": dummy_secret}
        )
    except Exception:
        from src.llm.gemini_provider import GeminiProvider
        default_provider = GeminiProvider(api_key=dummy_secret)

    logger.info("building pipeline (indexing knowledge base)...")
    start = time.perf_counter()
    _state.pipeline = Pipeline.create(_state.config, default_provider)
    elapsed = time.perf_counter() - start
    logger.info("pipeline ready in %.1fs", elapsed)

    _state.ready = True
    _state.startup_time = time.time()
    yield
    _state.ready = False


app = FastAPI(
    title="Odosian AI Engine",
    version="1.0.0",
    lifespan=lifespan,
)


@app.get("/health")
async def health() -> HealthResponse:
    return HealthResponse(
        status="ok",
        pipeline_ready=_state.ready,
    )


def _build_pipeline_and_request(
    operation: ReasoningOperation,
    provider_config: ProviderConfig,
    **request_kwargs: Any,
) -> tuple[Pipeline, EngineRequest]:
    """Prepare a per-request pipeline and validated engine request."""
    if _state.pipeline is None or _state.config is None:
        raise RuntimeError("Pipeline not initialized")

    provider = _state.provider_cache.get_or_create(provider_config)

    config = _state.config
    overrides: dict[str, Any] = {"provider": provider.name, "name": provider_config.model}
    if provider_config.max_tokens is not None:
        overrides["max_output_tokens"] = provider_config.max_tokens
    if provider_config.temperature is not None:
        overrides["temperature"] = provider_config.temperature

    config = EngineConfig(
        engine=config.engine,
        paths=config.paths,
        model=config.model.with_overrides(**overrides),
        logging=config.logging,
        security=config.security,
    )

    pipeline = _state.pipeline.with_provider(provider, config)
    engine_request = EngineRequest(operation=operation, **request_kwargs)
    return pipeline, engine_request


def _run_pipeline(
    operation: ReasoningOperation,
    provider_config: ProviderConfig,
    **request_kwargs: Any,
) -> dict[str, Any]:
    """Run the pipeline with a per-request provider (non-streaming)."""
    pipeline, engine_request = _build_pipeline_and_request(
        operation, provider_config, **request_kwargs
    )
    return pipeline.run(engine_request)


def _wants_sse(request: Request) -> bool:
    """Return True if the client requested SSE streaming."""
    accept = request.headers.get("accept", "")
    return "text/event-stream" in accept


async def _run_pipeline_sse(
    operation: ReasoningOperation,
    provider_config: ProviderConfig,
    **request_kwargs: Any,
) -> AsyncGenerator[str, None]:
    """Run the pipeline and yield SSE events for each stage."""
    stage_queue: Queue[dict[str, Any]] = Queue()

    def on_stage(name: str, index: int, total: int, label: str) -> None:
        stage_queue.put({"stage": name, "index": index, "total": total, "label": label})

    try:
        pipeline, engine_request = _build_pipeline_and_request(
            operation, provider_config, **request_kwargs
        )
        loop = asyncio.get_running_loop()
        result_future = loop.run_in_executor(
            None, lambda: pipeline.run(engine_request, on_stage=on_stage)
        )

        while not result_future.done():
            while not stage_queue.empty():
                event = stage_queue.get_nowait()
                yield f"event: stage\ndata: {json.dumps(event)}\n\n"
            await asyncio.sleep(0.05)

        result = result_future.result()

        while not stage_queue.empty():
            event = stage_queue.get_nowait()
            yield f"event: stage\ndata: {json.dumps(event)}\n\n"

        yield f"event: result\ndata: {json.dumps(result)}\n\n"

    except Exception as e:
        error_resp = _error_response(e)
        error_body = json.loads(error_resp.body.decode())
        error_body["status"] = error_resp.status_code
        yield f"event: error\ndata: {json.dumps(error_body)}\n\n"


@app.post("/api/v1/analyze", response_model=None)
async def analyze(body: AnalyzeBody, request: Request) -> StreamingResponse | JSONResponse:
    kwargs = dict(
        user_id=body.user_id,
        rule_text=body.rule_text,
        rule_id=body.rule_id,
        query=body.query,
        language=body.language,
    )
    if _wants_sse(request):
        return StreamingResponse(
            _run_pipeline_sse(ReasoningOperation.ANALYZE, body.provider, **kwargs),
            media_type="text/event-stream",
        )
    try:
        result = _run_pipeline(ReasoningOperation.ANALYZE, body.provider, **kwargs)
        return JSONResponse(content=result)
    except Exception as e:
        return _error_response(e)


@app.post("/api/v1/enhance", response_model=None)
async def enhance(body: EnhanceBody, request: Request) -> StreamingResponse | JSONResponse:
    kwargs = dict(
        user_id=body.user_id,
        rule_text=body.rule_text,
        rule_id=body.rule_id,
    )
    if _wants_sse(request):
        return StreamingResponse(
            _run_pipeline_sse(ReasoningOperation.ENHANCE, body.provider, **kwargs),
            media_type="text/event-stream",
        )
    try:
        result = _run_pipeline(ReasoningOperation.ENHANCE, body.provider, **kwargs)
        return JSONResponse(content=result)
    except Exception as e:
        return _error_response(e)


@app.post("/api/v1/generate", response_model=None)
async def generate(body: GenerateBody, request: Request) -> StreamingResponse | JSONResponse:
    kwargs = dict(
        user_id=body.user_id,
        requirement=body.requirement,
    )
    if _wants_sse(request):
        return StreamingResponse(
            _run_pipeline_sse(ReasoningOperation.GENERATE, body.provider, **kwargs),
            media_type="text/event-stream",
        )
    try:
        result = _run_pipeline(ReasoningOperation.GENERATE, body.provider, **kwargs)
        return JSONResponse(content=result)
    except Exception as e:
        return _error_response(e)


def _error_response(error: Exception) -> JSONResponse:
    """Map engine exceptions to HTTP responses."""
    if isinstance(error, ValidationEngineError):
        category = error.category.value if error.category else "validation"
        return JSONResponse(
            status_code=422,
            content=ErrorResponse(
                error=str(error),
                category=category,
                issues=list(error.issues),
            ).model_dump(),
        )

    if isinstance(error, InvalidReasoningRequestError):
        return JSONResponse(
            status_code=400,
            content=ErrorResponse(error=str(error), category="invalid_request").model_dump(),
        )

    if isinstance(error, (ResponseSchemaError, ReasoningValidationError)):
        issues = list(error.issues) if hasattr(error, "issues") else []
        return JSONResponse(
            status_code=422,
            content=ErrorResponse(
                error=str(error),
                category="reasoning_validation",
                issues=issues,
            ).model_dump(),
        )

    if isinstance(error, PromptRenderingError):
        return JSONResponse(
            status_code=500,
            content=ErrorResponse(error=str(error), category="prompt_error").model_dump(),
        )

    if isinstance(error, LLMAuthenticationError):
        return JSONResponse(
            status_code=401,
            content=ErrorResponse(error=str(error), category="auth").model_dump(),
        )

    if isinstance(error, LLMRateLimitError):
        return JSONResponse(
            status_code=429,
            content=ErrorResponse(error=str(error), category="rate_limit").model_dump(),
        )

    if isinstance(error, LLMTimeoutError):
        return JSONResponse(
            status_code=504,
            content=ErrorResponse(error=str(error), category="timeout").model_dump(),
        )

    if isinstance(error, (LLMServiceUnavailableError, LLMConnectionError, LLMModelUnavailableError)):
        return JSONResponse(
            status_code=503,
            content=ErrorResponse(error=str(error), category="provider_unavailable").model_dump(),
        )

    if isinstance(error, LLMError):
        return JSONResponse(
            status_code=502,
            content=ErrorResponse(error=str(error), category="provider_error").model_dump(),
        )

    if isinstance(error, (ContextBudgetExceededError, SecretLeakError)):
        return JSONResponse(
            status_code=500,
            content=ErrorResponse(error=str(error), category="context_error").model_dump(),
        )

    if isinstance(error, ContextValidationError):
        return JSONResponse(
            status_code=500,
            content=ErrorResponse(
                error=str(error),
                category="context_validation",
                issues=list(error.messages),
            ).model_dump(),
        )

    logger.exception("unhandled error in pipeline")
    return JSONResponse(
        status_code=500,
        content=ErrorResponse(error="Internal engine error", category="internal").model_dump(),
    )
