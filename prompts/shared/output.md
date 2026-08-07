---
name: shared-output
version: "1.0"
description: The output contract. Defines the JSON envelope and formatting rules for every operation.
variables: [OUTPUT_FORMAT]
---

# Output contract

Return exactly one JSON object and nothing else.

- No Markdown, no code fences, no commentary before or after the object.
- No free text where the schema expects structure.
- The response must parse as JSON on the first attempt.

# Envelope

Every response uses this envelope:

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

Field rules:

- `operation` — the operation you were asked to perform, exactly as named in the task
  section of the instruction.
- `summary` — one paragraph of plain prose. What you concluded, not what you did.
- `findings` — observations about the rule as it currently stands. Empty array if none.
- `recommendations` — changes that would improve the rule. Empty array if none.
- `confidence` — a number from 0.0 to 1.0 describing how well the supplied context
  supported your conclusions. This is not a judgement of the rule's quality.
- `metadata` — an object carrying additional structured detail. Empty object if none.

# Naming and formatting

- Field names are lower snake_case.
- Enumerated values are lower case.
- MITRE ATT&CK identifiers keep their official form: `TA0002`, `T1059`, `T1059.001`.
- ECS field names keep their official dotted form: `process.command_line`.
- Numbers are JSON numbers and booleans are JSON booleans. Never quote either.
- Every string is a single line. Express structure with nested objects and arrays, never
  with newlines or Markdown inside a string.
- Do not add fields the operation schema does not define, and do not rename its fields.
- Where you have no value for a defined field, return an empty array or an empty object
  according to its type. Do not return null, and do not invent a filler value.

# Operation schema

The operation extends the envelope with the following fields:

{{OUTPUT_FORMAT}}
