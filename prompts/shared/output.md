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
- MITRE ATT&CK identifiers keep the official form they were supplied in — a tactic as
  `<TACTIC_ID>`, a technique as `<TECHNIQUE_ID>`, a sub-technique with its dotted suffix.
  Copy the identifier you were given; never assemble one to fit the shape of a placeholder.
- ECS field names keep their official dotted form, exactly as supplied.
- Numbers are JSON numbers and booleans are JSON booleans. Never quote either.
- Every string is a single line. Express structure with nested objects and arrays, never
  with newlines or Markdown inside a string.
- Do not add fields the operation schema does not define, and do not rename its fields.
- Where you have no value for a defined field, return an empty array or an empty object
  according to its type. Do not return null, and do not invent a filler value.

# Assessments and labels

Some operations ask for a judgement — a score, a risk level, a list of strengths, of
evasion routes, of tags, or an ATT&CK mapping. These are claims like any other and the
grounding rules apply to them in full.

- A judgement scores the rule, not your certainty about it. Thin context lowers
  `confidence`; it does not make a weak rule look strong or a strong rule look weak.
- A list is grounded item by item. An empty array is a real answer where the supplied
  material establishes nothing, and is always better than a plausible invention.
- ATT&CK names are copied from the supplied material that carries them, never recalled.
  Where the material gives an identifier without a name, return the identifier and leave
  the name an empty string. A correct identifier does not license a remembered name.
- A mapping's own confidence describes how well the material establishes that one
  mapping. It is not the envelope's `confidence` and not a restatement of it.
- A code fragment may use only fields and values the supplied material confirms. It must
  introduce no identifier that appears nowhere in what you were given.
- An identifier the context reports as unresolved or ambiguous stays that way in every
  field of your answer, including these. Do not let a score, a tag or a mapping quietly
  settle what the uncertainty list says is unsettled.

# Operation schema

The operation extends the envelope with the following fields:

{{OUTPUT_FORMAT}}
