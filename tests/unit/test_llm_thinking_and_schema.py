"""Stage-07 thinking level and structured-output schema.

The provider-neutral controls added after a live diagnosis showed that an
unbounded reasoning budget can consume the whole output allowance and truncate
the reply.

Two properties are load-bearing and are asserted rather than assumed: the
neutral request never carries a provider type, and the Gemini adapter is the
only place that names one. No test here calls a provider.
"""

from __future__ import annotations

import pytest

from src.config.coercion import as_optional_enum
from src.config.exceptions import InvalidConfigValueError
from src.config.settings import ModelSettings
from src.config.types import ThinkingLevel
from src.config.yaml_loader import load_yaml_file
from src.core.output_format import json_schema_for
from src.core.types import ReasoningOperation
from src.llm.gemini_provider import GeminiProvider
from src.llm.request import GenerationParameters, LLMRequest
from src.llm.response import LLMResponse, TokenUsage
from src.llm.types import FinishReason, ResponseFormat
from tests.fixtures.stage15 import PROMPTS_DIR

MODEL_CONFIG = PROMPTS_DIR.parent / "configs" / "model.yaml"

SCHEMA = {
    "type": "object",
    "properties": {"status": {"type": "string"}},
    "required": ["status"],
}


def settings(**overrides: object) -> ModelSettings:
    base = {
        "provider": "gemini",
        "name": "gemini-3.5-flash",
        "temperature": 0.2,
        "top_p": 0.95,
        "max_output_tokens": 8192,
        "timeout_seconds": 60,
        "max_retries": 3,
        "retry_backoff_seconds": 1.0,
        "thinking_level": ThinkingLevel.MINIMAL,
    }
    base.update(overrides)
    return ModelSettings(**base)  # type: ignore[arg-type]


def request_of(**overrides: object) -> LLMRequest:
    base = {
        "system": "system text",
        "instruction": "instruction text",
        "parameters": GenerationParameters.from_settings(settings()),
        "response_format": ResponseFormat.JSON,
        "operation": "analyze",
    }
    base.update(overrides)
    return LLMRequest(**base)  # type: ignore[arg-type]


def config_of(request: LLMRequest) -> object:
    """Return the SDK configuration the adapter builds, without calling out."""
    provider = GeminiProvider.__new__(GeminiProvider)
    return provider._build_config(request)  # noqa: SLF001 - the translation is the subject


# A — configuration


def test_the_shipped_configuration_resolves_thinking_level_minimal():
    model = ModelSettings.from_mapping(load_yaml_file(MODEL_CONFIG))
    assert model.thinking_level is ThinkingLevel.MINIMAL


def test_thinking_level_is_optional_and_defaults_to_unset():
    minimal = {"model": {"provider": "x", "name": "y"}}
    assert ModelSettings.from_mapping(minimal).thinking_level is None
    assert settings(thinking_level=None).thinking_level is None


@pytest.mark.parametrize("value", ["minimal", "LOW", " Medium ", "high"])
def test_valid_thinking_levels_are_accepted_case_insensitively(value):
    assert as_optional_enum({"thinking_level": value}, "thinking_level", ThinkingLevel) is not None


# B — invalid level


@pytest.mark.parametrize("value", ["maximal", "none", "", "1", "very high"])
def test_an_invalid_thinking_level_is_rejected(value):
    with pytest.raises(InvalidConfigValueError) as error:
        ModelSettings.from_mapping(
            {"model": {"provider": "gemini", "name": "m", "thinking_level": value}}
        )
    assert "thinking_level" in str(error.value)


def test_a_non_string_thinking_level_is_rejected():
    with pytest.raises(InvalidConfigValueError):
        ModelSettings.from_mapping(
            {"model": {"provider": "gemini", "name": "m", "thinking_level": 3}}
        )


# C — the neutral request carries a generic schema


def test_the_request_carries_a_plain_json_schema():
    request = request_of(response_json_schema=SCHEMA)
    assert request.response_json_schema == SCHEMA
    assert request.has_schema
    assert isinstance(request.response_json_schema, dict)


def test_a_request_without_a_schema_still_builds():
    request = request_of()
    assert request.response_json_schema is None
    assert not request.has_schema


def test_the_schema_stays_out_of_the_request_repr():
    assert "status" not in repr(request_of(response_json_schema=SCHEMA))


def test_stage_15_supplies_the_operation_schema_as_plain_json():
    for operation in ReasoningOperation:
        schema = json_schema_for(operation)
        assert schema["type"] == "object"
        assert "operation" in schema["required"]
        assert schema["properties"]["operation"]["enum"] == [operation.value]
        assert isinstance(schema, dict)


# D — the adapter maps the level


@pytest.mark.parametrize(
    ("level", "expected"),
    [
        (ThinkingLevel.MINIMAL, "MINIMAL"),
        (ThinkingLevel.LOW, "LOW"),
        (ThinkingLevel.MEDIUM, "MEDIUM"),
        (ThinkingLevel.HIGH, "HIGH"),
    ],
)
def test_the_adapter_maps_every_thinking_level(level, expected):
    parameters = GenerationParameters.from_settings(settings(thinking_level=level))
    config = config_of(request_of(parameters=parameters))
    assert config.thinking_config is not None
    assert config.thinking_config.thinking_level.value == expected


def test_an_unset_level_sends_no_thinking_configuration():
    parameters = GenerationParameters.from_settings(settings(thinking_level=None))
    assert config_of(request_of(parameters=parameters)).thinking_config is None


def test_the_adapter_never_sends_a_thinking_budget():
    config = config_of(request_of())
    assert config.thinking_config.thinking_budget is None


# E, F — structured output


def test_the_adapter_sets_the_response_schema_it_was_given():
    config = config_of(request_of(response_json_schema=SCHEMA))
    assert config.response_json_schema == SCHEMA
    assert config.response_schema is None


def test_the_response_mime_type_stays_json():
    assert config_of(request_of()).response_mime_type == "application/json"
    with_schema = config_of(request_of(response_json_schema=SCHEMA))
    assert with_schema.response_mime_type == "application/json"


def test_a_text_request_carries_no_schema():
    config = config_of(
        request_of(response_format=ResponseFormat.TEXT, response_json_schema=SCHEMA)
    )
    assert config.response_mime_type == "text/plain"
    assert config.response_json_schema is None


# G — everything else unchanged


def test_the_existing_generation_parameters_are_unchanged():
    config = config_of(request_of(response_json_schema=SCHEMA))
    assert config.temperature == 0.2
    assert config.top_p == 0.95
    assert config.max_output_tokens == 8192
    assert config.http_options.timeout == 60_000
    assert config.system_instruction == "system text"


def test_a_request_with_no_system_part_still_omits_it():
    assert config_of(request_of(system="")).system_instruction is None


# H, I — telemetry


def test_token_usage_captures_thoughts_when_the_provider_reports_them():
    from src.llm.gemini_provider import _extract_usage  # noqa: PLC0415

    class Metadata:
        prompt_token_count = 100
        candidates_token_count = 200
        total_token_count = 700
        thoughts_token_count = 400

    class Raw:
        usage_metadata = Metadata()

    usage = _extract_usage(Raw())
    assert usage.thoughts_tokens == 400
    assert usage.output_tokens == 600
    assert (usage.prompt_tokens, usage.completion_tokens, usage.total_tokens) == (100, 200, 700)


def test_token_usage_stays_compatible_when_thoughts_are_absent():
    from src.llm.gemini_provider import _extract_usage  # noqa: PLC0415

    class Metadata:
        prompt_token_count = 10
        candidates_token_count = 20
        total_token_count = 30

    class Raw:
        usage_metadata = Metadata()

    usage = _extract_usage(Raw())
    assert usage.thoughts_tokens == 0
    assert usage.output_tokens == 20
    assert TokenUsage(1, 2, 3) == TokenUsage(1, 2, 3, 0)
    assert TokenUsage.unknown().thoughts_tokens == 0


def test_thoughts_tokens_are_loggable_and_carry_no_content():
    response = LLMResponse(
        text="{}",
        provider="gemini",
        model="gemini-3.5-flash",
        finish_reason=FinishReason.STOP,
        usage=TokenUsage(10, 20, 60, 30),
        duration_seconds=1.0,
    )
    fields = response.log_fields()
    assert fields["thoughts_tokens"] == "30"
    assert "{}" not in "".join(fields.values())
