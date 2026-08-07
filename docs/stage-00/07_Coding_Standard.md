# 07_Coding_Standard.md

Version: 1.0
Status: Draft

---

# Purpose

This document defines the official coding standards for the ODOSIAN AI Engine.

The objectives are:

- Maintain consistency
- Improve readability
- Simplify maintenance
- Reduce technical debt
- Encourage modular architecture
- Support long-term scalability

---

# General Principles

The project follows these principles:

- Readability over cleverness
- Explicit over implicit
- Simplicity over complexity
- Composition over inheritance
- Configuration over hardcoding
- Interfaces over implementation
- Testability by design

---

# Project Structure

Source code must follow the repository structure.

No module may bypass another module's responsibility.

Business logic must never exist outside `src/`.

---

# Naming Conventions

## Files

Use snake_case.

Examples:

```
rule_parser.py
entity_mapper.py
knowledge_loader.py
```

---

## Classes

Use PascalCase.

Examples:

```python
RuleParser
KnowledgeRepository
EntityMapper
```

---

## Functions

Use snake_case.

Examples:

```python
parse_rule()
extract_entities()
build_context()
```

---

## Variables

Use descriptive snake_case.

Good:

```python
mapped_entities
graph_context
knowledge_package
```

Avoid:

```python
x
tmp
data1
```

---

## Constants

Use UPPER_SNAKE_CASE.

```python
MAX_CONTEXT_SIZE
DEFAULT_TIMEOUT
SUPPORTED_PROVIDERS
```

---

# Module Design

Each module should have a single responsibility.

Modules communicate only through public interfaces.

Internal implementation details must remain private.

---

# Functions

Functions should:

- Perform one task
- Be easy to understand
- Have descriptive names
- Avoid side effects where possible

Avoid long functions.

Split complex logic into smaller reusable units.

---

# Classes

Classes should:

- Represent one concept
- Encapsulate related behavior
- Avoid excessive inheritance
- Favor dependency injection

---

# Type Hints

All public functions should include type hints.

Example:

```python
def parse_rule(rule: str) -> ParsedRule:
    ...
```

---

# Documentation

Every public class and function should include a docstring.

Example:

```python
def extract_entities(rule: ParsedRule) -> EntityCollection:
    """
    Extract cybersecurity entities from a parsed rule.
    """
```

---

# Error Handling

Never silently ignore exceptions.

Catch only expected exceptions.

Raise project-specific exceptions when appropriate.

Example:

```python
raise RuleParsingError(...)
```

---

# Logging

Use structured logging.

Avoid print() in production code.

Every significant failure should be logged.

Sensitive information must never be logged.

---

# Configuration

Configuration values must never be hardcoded.

Use configuration files or environment variables.

---

# Dependency Management

Prefer standard library when suitable.

Add external dependencies only when justified.

Every dependency should have a clear purpose.

---

# Code Formatting

Use:

- Black
- Ruff
- isort

The entire project must use the same formatting tools.

---

# Testing

Every new feature should include appropriate tests.

Test categories include:

- Unit Tests
- Integration Tests
- Evaluation Tests

Critical logic should not be merged without tests.

---

# Security

Never commit:

- API keys
- Secrets
- Tokens
- Passwords
- Credentials

Validate all external inputs.

Never trust user-provided data.

---

# Performance

Optimize only after correctness.

Avoid premature optimization.

Measure before optimizing.

---

# AI-Specific Rules

LLM calls must be isolated inside the `llm` module.

Prompt loading must occur through the prompt management layer.

Knowledge resources must remain read-only.

Business logic must never depend directly on raw JSONL files.

The Validation Engine must verify every AI response before it is returned.

---

# Code Review Requirements

Before merging code:

- Code builds successfully
- Tests pass
- Formatting passes
- Linting passes
- Documentation updated
- No debug code remains
- No unused imports
- No commented-out production code

---

# Design Philosophy

Good code should be:

- Predictable
- Testable
- Maintainable
- Modular
- Explainable

Every line of code should have a clear reason to exist.

---

End of Document