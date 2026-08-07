# LLM Contract v1.0

**Project:** ODOSIAN AI Engine

**Status:** Approved

**Version:** 1.0

---

# 1. Purpose

This document defines the contract between the Prompt Management layer and the Large Language Model (LLM) layer.

Its purpose is to standardize how prompts are submitted to the model, how responses are received, how failures are handled, and how structured output is enforced.

The LLM layer is an execution layer.

It is not responsible for prompt generation, context construction, or business logic.

---

# 2. Scope

This contract applies to every supported LLM provider.

The MVP implementation uses:

- Google Gemini 2.5 Flash

Future providers may include:

- OpenAI
- Anthropic
- Local Models

Every provider must implement this same contract.

---

# 3. Responsibilities

The LLM layer is responsible for:

- Receiving a fully prepared prompt
- Sending the request to the provider
- Receiving the model response
- Returning the raw response
- Returning structured metadata
- Handling retries
- Handling provider failures
- Handling timeouts

The LLM layer is NOT responsible for:

- Prompt authoring
- Prompt validation
- Context building
- Knowledge retrieval
- Rule parsing
- Entity extraction
- AI reasoning decisions
- Output formatting

---

# 4. Input Contract

The LLM layer receives a fully rendered prompt.

Input object:

```

RenderedPrompt

```

The prompt is already complete.

No additional prompt construction is allowed inside the LLM layer.

---

# 5. Request Parameters

The LLM layer must support configurable runtime parameters.

Minimum supported parameters:

- Model
- Temperature
- Max Output Tokens
- Top P
- Top K
- Timeout

Values are loaded from the Configuration System.

No values may be hardcoded.

---

# 6. Provider Interface

Every provider must expose the same public interface.

Required operations:

- Generate Response

Future optional operations:

- Streaming
- Batch Requests

The rest of the AI Engine must never depend on provider-specific SDKs.

---

# 7. Response Contract

Every provider returns a common response object.

Minimum fields:

- Raw Text
- Finish Reason
- Token Usage
- Provider Name
- Model Name
- Request Duration

Provider-specific metadata may be preserved but must not leak into the engine.

---

# 8. JSON Mode

The AI Engine expects structured output.

The LLM layer must always request JSON responses whenever supported by the provider.

If the provider cannot guarantee JSON:

- Return raw text.
- Allow later validation to detect invalid output.

The LLM layer does not repair invalid JSON.

---

# 9. Retry Policy

Retry only for transient failures.

Examples:

- Temporary network errors
- Rate limiting
- Internal provider errors

Do NOT retry:

- Invalid prompt
- Invalid configuration
- Invalid authentication
- Invalid API key

Retry policy:

- Maximum Attempts: Configurable
- Backoff Strategy: Exponential
- Retry Delay: Configurable

---

# 10. Timeout Policy

Every request must use a configurable timeout.

Expired requests must raise a Timeout exception.

Timeout duration is configured through the Configuration System.

---

# 11. Error Handling

The LLM layer must expose typed exceptions.

Examples:

- ProviderError
- TimeoutError
- AuthenticationError
- RateLimitError
- InvalidResponseError
- ModelUnavailableError

Provider-specific exceptions must never escape outside the LLM package.

---

# 12. Logging

The LLM layer logs:

- Provider
- Model
- Request Duration
- Token Usage
- Finish Reason

The following must NEVER be logged:

- API Keys
- Secrets
- User Prompts
- Runtime Context

Sensitive data must always remain protected.

---

# 13. Security

API keys are loaded only through the Configuration System.

The LLM layer never stores credentials.

The LLM layer never modifies configuration values.

---

# 14. Deterministic Behavior

When deterministic mode is enabled:

- Temperature should be minimized.
- Runtime parameters should remain fixed.

This is intended for repeatable evaluations.

---

# 15. Future Extensions

Future versions may support:

- Multiple Providers
- Provider Failover
- Streaming
- Local Models
- Parallel Requests
- Model Selection Policies

These capabilities are outside the MVP scope.

---

# 16. Design Principles

The LLM layer follows these principles.

- Provider Independence
- Configuration Driven
- Stateless Execution
- Strong Typing
- Explicit Error Handling
- No Business Logic
- No Prompt Logic
- No Knowledge Logic

---

# 17. Sequence

```

Prompt Management
│
▼
RenderedPrompt
│
▼
LLM Layer
│
▼
Provider Adapter
│
▼
Gemini
│
▼
Raw Response
│
▼
LLM Response Object

```

---

# 18. Definition of Done

The LLM layer is considered complete when:

- A rendered prompt can be sent to Gemini.
- A structured response object is returned.
- Retries work correctly.
- Timeouts are enforced.
- Typed exceptions are exposed.
- No provider-specific SDK leaks outside the package.
- The layer remains independent from Prompt Management and Validation.

---

# End of Document