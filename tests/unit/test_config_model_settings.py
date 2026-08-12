"""Shipped model configuration.

Guards the output budget against a silent reduction.

``max_output_tokens`` bounds the model's reasoning tokens as well as its answer.
A live ``gemini-3.5-flash`` analyze call spent 4432 tokens thinking and 911
answering, so at 4096 the reply was three characters long and failed to parse.
The value is therefore a correctness setting, not a cost knob, and it is
asserted here rather than left to review.

The file is read directly rather than through ``load_configuration`` so the test
needs no API key.
"""

from __future__ import annotations

from pathlib import Path

from src.config.settings import ModelSettings
from src.config.types import ThinkingLevel
from src.config.yaml_loader import load_yaml_file

MODEL_CONFIG = Path(__file__).resolve().parents[2] / "configs" / "model.yaml"


def settings() -> ModelSettings:
    return ModelSettings.from_mapping(load_yaml_file(MODEL_CONFIG))


def test_the_output_budget_leaves_room_for_an_answer():
    assert settings().max_output_tokens == 8192


def test_reasoning_is_held_to_the_level_the_live_diagnosis_settled_on():
    assert settings().thinking_level is ThinkingLevel.MINIMAL


def test_the_rest_of_the_model_configuration_is_unchanged():
    model = settings()
    assert model.provider == "gemini"
    assert model.name == "gemini-3.5-flash"
    assert model.temperature == 0.2
    assert model.top_p == 0.95
    assert model.timeout_seconds == 60
    assert model.max_retries == 3
    assert model.retry_backoff_seconds == 1.0
