# 06_Prompt_Standard.md

Version: 1.0
Status: Draft

---

# Purpose

This document defines the official prompt engineering standards for the ODOSIAN AI Engine.

Prompts are treated as first-class project assets.

They are versioned, reviewed, tested, and maintained independently from application code.

The goal is to ensure consistency, maintainability, reproducibility, and provider independence.

---

# Prompt Philosophy

Prompts are not source code.

Prompts are not configuration.

Prompts are knowledge assets.

Every prompt must be:

- Modular
- Reusable
- Version controlled
- Testable
- Human readable
- Provider independent

---

# Prompt Storage

All prompts must be stored inside the project.

```
prompts/
├── analyze/
├── enhance/
├── generate/
├── shared/
└── templates/
```

Prompts must never be hardcoded inside Python files.

Incorrect:

```python
prompt = """
Analyze this rule...
"""
```

Correct:

```python
prompt = PromptLoader.load("analyze/rule_analysis.md")
```

---

# Prompt Structure

Every prompt should follow the same structure.

## 1. Role

Define the AI role.

Example:

"You are a cybersecurity analyst specializing in Elastic SIEM detection engineering."

---

## 2. Objective

Explain exactly what the model must accomplish.

---

## 3. Context

Provide all required information.

Examples:

- Detection rule
- Retrieved knowledge
- Graph context
- Related techniques

---

## 4. Constraints

Examples:

- Do not hallucinate.
- Use only provided context.
- Do not invent ATT&CK IDs.
- Preserve JSON structure.

---

## 5. Output Format

Explicitly define the required response format.

Prefer structured JSON whenever possible.

---

# Prompt Categories

The project may contain prompts for:

## Analysis

Analyze rules.

---

## Enhancement

Improve existing rules.

---

## Generation

Generate new outputs.

---

## Validation

Validate AI responses.

---

## Shared

Reusable prompt fragments.

---

# Prompt Versioning

Every prompt should contain metadata.

Example:

```
Prompt Name:
Version:
Author:
Last Updated:
Purpose:
Compatible Providers:
```

---

# Prompt Naming

Use descriptive names.

Examples:

```
rule_analysis.md

rule_summary.md

rule_validation.md

graph_context.md
```

Avoid:

```
prompt1.md

new.md

test.md
```

---

# Prompt Design Principles

Every prompt should:

- Be deterministic where possible.
- Avoid ambiguity.
- Define clear responsibilities.
- Request structured outputs.
- Minimize hallucinations.
- Avoid unnecessary verbosity.

---

# Variables

Dynamic values must use placeholders.

Example:

```
{{RULE}}

{{ENTITIES}}

{{GRAPH_CONTEXT}}

{{KNOWLEDGE}}

{{OUTPUT_SCHEMA}}
```

Application code is responsible for replacing placeholders before sending the prompt to the LLM.

---

# Provider Independence

Prompts should avoid provider-specific features unless absolutely necessary.

The same prompt should work with:

- Gemini
- OpenAI
- Local Models

Whenever possible.

---

# Prompt Testing

Every important prompt should be tested.

Testing should verify:

- Placeholder replacement
- JSON validity
- Response consistency
- Required fields
- Prompt loading

---

# Prompt Review Checklist

Before approving a prompt:

- Clear objective
- Clear role
- Proper context
- Defined constraints
- Explicit output format
- No hardcoded runtime values
- No provider-specific assumptions

---

# Project Rules

Prompts must never contain:

- Secrets
- API keys
- Hardcoded credentials
- Internal tokens

Prompts should avoid:

- Excessive examples
- Unnecessary repetition
- Hidden assumptions

---

# Future Expansion

The prompt system should support:

- Prompt versioning
- Prompt inheritance
- Shared prompt fragments
- Prompt templates
- A/B prompt evaluation
- Multi-provider optimization

---

End of Document