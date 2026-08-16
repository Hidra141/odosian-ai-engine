"""Provider construction.

The one place a configured provider name becomes an object.

Stage-15 takes a provider already built and never learns which one it holds;
that is what keeps the reasoning layer provider-agnostic. Something still has to
read ``model.provider``, find the credential it needs and construct the thing.
It is here, in a module the pipeline does not import, so that a test injecting a
fake provider never touches a credential or an SDK.

The credential is a :class:`~src.config.secrets.Secret` throughout. It is read
by name from the resolved secrets, passed as an object, and revealed once inside
the provider. No value passes through this module.

Both refusals reuse Stage-05's own errors. A provider name the engine does not
implement is an unusable configuration value; a declared secret that did not
resolve is a missing secret. Neither is a new kind of failure.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Final

from src.config.exceptions import InvalidConfigValueError, MissingSecretError
from src.config.secrets import Secret
from src.config.settings import EngineConfig
from src.llm.gemini_provider import PROVIDER_NAME, GeminiProvider
from src.llm.provider import LLMProvider

API_KEY_SECRET: Final[str] = "LLM_API_KEY"
"""The logical name ``configs/security.yaml`` declares for the model credential."""


def provider_from_config(config: EngineConfig, secrets: Mapping[str, Secret]) -> LLMProvider:
    """Return the provider the configuration names, built from the resolved secrets."""
    if config.model.provider != PROVIDER_NAME:
        raise InvalidConfigValueError(
            "model.provider",
            config.model.provider,
            f"a supported provider name, currently only {PROVIDER_NAME!r}",
        )
    secret = secrets.get(API_KEY_SECRET)
    if secret is None:
        raise MissingSecretError(API_KEY_SECRET)
    return GeminiProvider(api_key=secret)
