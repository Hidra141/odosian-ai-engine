"""Application layer.

Orchestration of the whole engine: a caller's request in, the operation's
contract document out.

Every stage below this one was already finished and already tested, and none of
them called the next. This layer is the wiring, and it is the only module that
knows the order::

    EngineRequest -> Stage-08 -> Stage-09 -> Stage-10 -> Stage-13 -> Stage-14
                  -> Stage-15 -> Stage-16 -> Stage-17 -> contract document

It reasons about nothing. Every decision the document reports was made by a
stage beneath it; what this layer decides is only what runs, in what order, and
what the application itself owns — which request this was, who asked, when, and
how long it took.

Typical use::

    loaded = load_configuration(root_dir)
    provider = provider_from_config(loaded.config, loaded.secrets)
    pipeline = Pipeline.create(loaded.config, provider)
    document = pipeline.run(
        EngineRequest(ReasoningOperation.ANALYZE, user_id=user, rule_text=rule)
    )

Build the pipeline once. Assembling it reads and indexes every dataset, and a
pipeline per request would do that per request.

Nothing beneath this package imports it, and nothing here is imported by a lower
stage. The dependency runs one way, which is what keeps the layer removable.
"""

from __future__ import annotations

from .pipeline import Pipeline
from .provider_factory import API_KEY_SECRET, provider_from_config
from .requests import RULE_OPERATIONS, EngineRequest
from .retrieval import (
    DEFAULT_SETTINGS,
    RetrievalService,
    requirement_query,
    rule_query,
)
from .runtime import RuntimeFactory, as_timestamp, new_uuid, utc_now

__all__ = [
    "API_KEY_SECRET",
    "DEFAULT_SETTINGS",
    "RULE_OPERATIONS",
    "EngineRequest",
    "Pipeline",
    "RetrievalService",
    "RuntimeFactory",
    "as_timestamp",
    "new_uuid",
    "provider_from_config",
    "requirement_query",
    "rule_query",
    "utc_now",
]
