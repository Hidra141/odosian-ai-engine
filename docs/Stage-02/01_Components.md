# 01_Components.md

Version: 1.0
Status: Draft

---

# Purpose

This document defines the internal components of the ODOSIAN AI Engine.

A component is an independent functional unit that performs a single business responsibility within the AI Engine. Components collaborate through well-defined interfaces and data contracts.

---

# Design Principles

Every component must:

- Have one responsibility.
- Own its business logic.
- Communicate only through contracts.
- Be replaceable.
- Be independently testable.
- Hide internal implementation details.

---

# Component Overview

```
                 Pipeline Orchestrator
                         │
 ────────────────────────┼────────────────────────
                         │
        ┌─────────────────────────────────┐
        │                                 │
   Rule Parser                    Entity Extraction
        │                                 │
        └──────────────► Entity Mapping ◄──┘
                         │
        ┌────────────────┴────────────────┐
        │                                 │
 Knowledge Base                 Knowledge Graph
        │                                 │
        └──────────────► GraphRAG ◄────────┘
                         │
                  Context Builder
                         │
                    LLM Provider
                         │
                 Validation Engine
                         │
                     Formatter
```

---

# Components

## Pipeline Orchestrator

### Responsibility

Coordinates the execution of the complete AI workflow.

### Owns

- Workflow state
- Execution order
- Error propagation
- Retry decisions

### Depends On

All processing components.

---

## Rule Parser

### Responsibility

Convert detection rules into a normalized internal representation.

### Input

DetectionRule

### Output

RuleParsingResult

---

## Entity Extraction

### Responsibility

Extract cybersecurity entities from parsed rules.

### Output

EntityExtractionResult

---

## Entity Mapping

### Responsibility

Resolve aliases and map entities to canonical identifiers.

### Output

EntityMappingResult

---

## Knowledge Base

### Responsibility

Retrieve structured cybersecurity knowledge.

### Sources

- MITRE ATT&CK
- CAPEC
- CWE
- CVE
- Custom datasets

---

## Knowledge Graph

### Responsibility

Provide semantic relationships between entities.

---

## GraphRAG

### Responsibility

Rank and retrieve the most relevant contextual evidence.

---

## Context Builder

### Responsibility

Assemble all available evidence into the final context for the language model.

---

## LLM Provider

### Responsibility

Generate reasoning using the prepared context.

Supported providers may include:

- OpenAI
- Anthropic
- Local models

---

## Validation Engine

### Responsibility

Validate AI output before exposing it to clients.

Validation may include:

- Structure validation
- Schema validation
- Hallucination detection
- Consistency checks

---

## Formatter

### Responsibility

Produce the official response returned by the AI Engine.

---

# Component Dependencies

```
Pipeline Orchestrator
        │
        ▼
Rule Parser
        │
        ▼
Entity Extraction
        │
        ▼
Entity Mapping
        │
        ├────────► Knowledge Base
        │
        └────────► Knowledge Graph
                    │
                    ▼
                 GraphRAG
                    │
                    ▼
             Context Builder
                    │
                    ▼
               LLM Provider
                    │
                    ▼
            Validation Engine
                    │
                    ▼
                Formatter
```

---

# Dependency Rules

- Components communicate only through interfaces.
- Components exchange Data Contracts only.
- Components never access each other's internal state.
- Components remain implementation-independent.
- Circular dependencies are forbidden.

---

# Component Lifecycle

Every component follows the same lifecycle:

1. Receive Contract
2. Validate Input
3. Execute Business Logic
4. Produce Output Contract
5. Report Execution Status

---

# Extensibility

New components should:

- Implement an existing interface whenever possible.
- Register with the Pipeline Orchestrator.
- Avoid modifying existing components.

---

End of Document