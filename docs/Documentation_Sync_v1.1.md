# Documentation Sync v1.1

**Project:** ODOSIAN AI Engine

**Status:** Deferred — not yet applied

**Version:** 1.1 (pending)

---

# 1. Purpose

This document records documentation updates that have been agreed but deliberately **not
yet applied**. It exists so that decisions taken during implementation are not lost while
the frozen stages remain untouched.

Nothing in this document changes any implementation. Each item is applied to its target
document during the post-MVP documentation synchronisation.

---

# 2. Rules

- These changes are **documentation-only**.
- They must **NOT** modify any frozen implementation.
- No item here authorises a code change, a configuration change, or a structural change.
- Items are applied together during the documentation sync, not individually.

---

# 3. Deferred Items

## Item 1 — `top_k` becomes an OPTIONAL provider-specific parameter

**Target:** LLM Contract v1.0, section 5 (Request Parameters)

`top_k` is currently listed among the minimum supported request parameters. It is
reclassified as an optional, provider-specific parameter.

**Reason:** `top_k` is not supported uniformly across providers, and the frozen
Configuration System does not expose a field for it. Treating it as required would force a
change to a frozen stage.

**Effect on implementation:** none. The LLM layer supports the parameters the frozen
`ModelSettings` exposes.

---

## Item 2 — Official MVP model is Gemini 3.5 Flash

**Target:** LLM Contract v1.0, section 2 (Scope)

The contract names Gemini 2.5 Flash. The official MVP model is **Gemini 3.5 Flash**, as
already recorded in the project roadmap and in `configs/model.yaml`.

**Reason:** the contract and the frozen configuration disagreed. The configuration and the
roadmap are correct.

**Effect on implementation:** none. The model name is configuration-driven and is never
hardcoded in the LLM layer.

---

## Item 3 — Deterministic Mode moves to Future Extensions

**Target:** LLM Contract v1.0, section 14 (Deterministic Behavior) → section 15 (Future
Extensions)

Deterministic Mode is moved out of the MVP contract and recorded as a future extension.

**Reason:** the frozen Configuration System exposes no field to enable it, and it is not
required for the MVP.

**Effect on implementation:** none. No deterministic-mode switch is implemented in
Stage-07.

---

## Item 4 — `TimeoutError` is renamed to `LLMTimeoutError`

**Target:** LLM Contract v1.0, section 11 (Error Handling)

The typed exception listed as `TimeoutError` is renamed **`LLMTimeoutError`**.

**Reason:** `TimeoutError` is a Python builtin. Shadowing it inside the LLM package would
be ambiguous at every call site that also handles builtin timeouts.

**Effect on implementation:** the Stage-07 exception is named `LLMTimeoutError`. This is
the name the contract will carry after the sync.

---

## Item 5 — Documentation-only scope

**Target:** this document

Items 1 to 4 are documentation-only. They must **NOT** modify any frozen implementation.

Frozen at the time of writing:

- Stage-04 Repository Structure
- Stage-05 Configuration System
- Stage-06 Prompt Management
- Prompt Templates (Prompt Specification v1.0)

---

# 4. Previously Recorded Divergences

The following structural divergences were identified earlier and remain deferred to the
same synchronisation. They are listed here so the sync has a single entry point.

| Document says | Repository has |
| --- | --- |
| `src/application/` | `src/core/` |
| `src/rag/` | `src/graphrag/` |
| *(no entry)* | `src/mapping/` |
| *(no entry)* | `src/prompts/` alongside root `prompts/` |
| 4 operations including Quick Feedback | 3 operations |

**Target:** 03_Project_Structure.md, 04_Module_Responsibilities.md

---

# 5. Open Questions

Recorded, not yet decided. These are not authorised changes.

1. **Generate operation input placeholder.** Prompt Specification v1.0 section 6 defines no
   placeholder for a natural-language detection requirement. The `generate` templates
   currently carry it in `{{RULE}}`. A dedicated placeholder would be clearer.
2. **`{{OUTPUT_FORMAT}}` payloads.** The per-operation JSON schemas injected into
   `{{OUTPUT_FORMAT}}` are not yet authored anywhere.

---

# End of Document
