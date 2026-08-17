# Prompt Specification v1.0

**Project:** ODOSIAN AI Engine

**Status:** Approved

**Version:** 1.0

---

# 1. Purpose

This document defines the official Prompt Architecture used by the ODOSIAN AI Engine.

Its purpose is to standardize how prompts are designed, assembled, validated, and maintained across all AI operations.

This specification is the single source of truth for every prompt used by the engine.

Prompt text is considered project resources, not application code.

---

# 2. Design Principles

The Prompt System follows these principles.

## Principle 1

Prompt is Configuration, not Code.

Prompt text must never be hardcoded inside Python modules.

---

## Principle 2

One Prompt Architecture.

All operations follow the same prompt architecture.

Only their instruction layer changes.

---

## Principle 3

Runtime Context is the only source of dynamic information.

Prompts never fetch data by themselves.

---

## Principle 4

Prompt Management is independent from the LLM.

The Prompt layer prepares prompts.

The LLM layer executes prompts.

---

## Principle 5

All AI responses must follow the Output Contract.

---

# 3. Prompt Architecture

The AI Engine builds prompts using layered composition.

```
Shared Prompts
        │
        ▼
Operation Prompt
        │
        ▼
Runtime Context
        │
        ▼
Prompt Builder
        │
        ▼
Final Prompt
        │
        ▼
LLM
```

The Prompt Builder is responsible for assembling the final prompt.

---

# 4. Shared Prompt Components

Shared prompts are reusable across every operation.

Directory:

```
prompts/shared/
```

Files:

```
system.md
output.md
safety.md
glossary.md
```

## system.md

Defines:

- AI identity
- Reasoning behavior
- General instructions
- Response style

---

## output.md

Defines:

- Output format
- JSON schema
- Field naming
- Formatting rules

---

## safety.md

Defines:

- No hallucination
- Use supplied context only
- Report uncertainty
- Never invent evidence

---

## glossary.md

Defines shared terminology used throughout the project.

---

# 5. Operation Prompt Components

Every operation contains only operation-specific instructions.

Directory structure:

```
prompts/

analyze/
    instruction.md

enhance/
    instruction.md

generate/
    instruction.md
```

Operation prompts never redefine:

- AI identity
- Output format
- Safety rules

They only describe the requested task.

---

# 6. Runtime Variables

Prompt Builder injects runtime data using placeholders.

Official placeholders:

```
{{RULE}}

{{CONTEXT}}

{{ENTITIES}}

{{MITRE}}

{{SIGMA}}

{{ELASTIC}}

{{ATOMIC}}

{{LOLBAS}}

{{SIMILAR_RULES}}

{{OUTPUT_FORMAT}}
```

Additional placeholders may be introduced in future versions without breaking existing prompts.

---

# 7. Prompt Assembly

The final prompt is assembled in the following order.

```
system.md

+

output.md

+

safety.md

+

glossary.md

+

instruction.md

+

Runtime Context

↓

Final Prompt
```

Prompt Builder is responsible for this process.

---

# 8. Output Contract

All operations must produce structured JSON.

Markdown responses are not allowed.

Free-text responses are not allowed.

General output structure:

```json
{
  "operation": "",
  "summary": "",
  "findings": [],
  "recommendations": [],
  "confidence": 0.0,
  "metadata": {}
}
```

Operation-specific fields may extend this structure while preserving compatibility.

---

# 9. Placeholder Rules

All placeholders follow the same format.

```
{{VARIABLE_NAME}}
```

Rules:

- Uppercase only
- Digits allowed
- Underscore allowed
- No nested placeholders
- No undefined placeholders

Prompt validation must fail if required placeholders are missing.

---

# 10. Prompt Profiles (Future)

Future versions may support multiple Prompt Profiles.

Example:

```
prompts/

profiles/

default/

enterprise/

soc/

research/
```

Profiles may override shared prompts without modifying operation prompts.

This functionality is outside the MVP scope.

---

# 11. Versioning

Prompt Specification follows semantic versioning.

```
v1.0

↓

v1.1

↓

v2.0
```

Breaking architectural changes require a new major version.

---

# 12. Responsibilities

Prompt Management is responsible for:

- Loading prompts
- Resolving templates
- Rendering placeholders
- Validating prompt integrity
- Building the final prompt

Prompt Management is NOT responsible for:

- Calling the LLM
- Building runtime context
- Parsing rules
- Knowledge retrieval
- Graph traversal
- AI reasoning

These responsibilities belong to other modules.

---

# 13. Scope

This specification applies to all prompt resources used by the ODOSIAN AI Engine.

Any new prompt must conform to this specification.

No prompt may bypass the Prompt Builder.

No prompt may contain hardcoded runtime information.

---

# End of Document