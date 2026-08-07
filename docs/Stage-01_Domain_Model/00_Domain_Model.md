# 00_Domain_Model.md

Version: 1.0
Status: Draft

---

# Purpose

This document defines the core business domain of the ODOSIAN AI Engine.

It identifies the primary domain entities, their responsibilities, and the relationships between them.

The Domain Model serves as the conceptual foundation for all application models, interfaces, and workflows.

---

# Design Principles

The domain model should:

- Represent business concepts rather than implementation details.
- Remain independent of frameworks and libraries.
- Avoid provider-specific assumptions.
- Be stable over time.
- Support future extensibility.

---

# Core Domain Overview

The AI Engine processes detection rules by extracting cybersecurity entities, enriching them with structured knowledge, generating contextual reasoning using an LLM, validating the generated output, and returning a structured response.

The domain consists of the following major concepts:

```
Detection Rule
      │
      ▼
Parsed Rule
      │
      ▼
Entities
      │
      ▼
Mapped Entities
      │
      ▼
Knowledge Records
      │
      ▼
Knowledge Graph
      │
      ▼
Retrieved Context
      │
      ▼
LLM Context
      │
      ▼
AI Response
      │
      ▼
Validated Response
      │
      ▼
Final Response
```

---

# Domain Entities

## DetectionRule

Represents the original rule submitted to the AI Engine.

Responsibilities:

- Preserve original content.
- Represent user input.
- Remain immutable.

---

## ParsedRule

Represents the structured interpretation of a detection rule.

Responsibilities:

- Store parsed metadata.
- Store normalized fields.
- Provide structured access.

Produced by:

Rule Parser.

---

## Entity

Represents a cybersecurity concept extracted from a rule.

Examples:

- ATT&CK Technique
- CVE
- Process
- Registry Key
- File Path
- Command
- User
- Domain
- IP Address

---

## MappedEntity

Represents the canonical version of an extracted entity.

Responsibilities:

- Alias resolution.
- Version normalization.
- Canonical identification.

---

## KnowledgeRecord

Represents a single factual record stored in the Knowledge Base.

Responsibilities:

- Preserve factual knowledge.
- Provide structured information.
- Remain immutable.

---

## KnowledgePackage

Represents the collection of retrieved knowledge records relevant to a request.

---

## GraphNode

Represents an entity inside the Knowledge Graph.

---

## GraphEdge

Represents a semantic relationship between two graph nodes.

---

## GraphContext

Represents the expanded relationship context produced by graph traversal.

---

## RetrievedContext

Represents the filtered context selected by GraphRAG.

---

## LLMContext

Represents the complete information package delivered to the LLM.

Contains:

- Parsed rule
- Entities
- Knowledge
- Graph information
- Instructions

---

## AIResponse

Represents the raw response returned by the LLM.

---

## ValidatedResponse

Represents an AI response that has passed validation.

---

## FinalResponse

Represents the official output returned by the AI Engine.

---

# Domain Relationships

```
DetectionRule
      │
      ▼
ParsedRule
      │
      ▼
Entity
      │
      ▼
MappedEntity
      │
      ▼
KnowledgeRecord
      │
      ▼
KnowledgePackage
      │
      ▼
GraphContext
      │
      ▼
RetrievedContext
      │
      ▼
LLMContext
      │
      ▼
AIResponse
      │
      ▼
ValidatedResponse
      │
      ▼
FinalResponse
```

---

# Domain Boundaries

The Domain Model does not define:

- Database schemas
- JSON serialization
- API endpoints
- Python classes
- Framework-specific implementations

These concerns are addressed in later stages.

---

# Domain Invariants

The following rules must always hold:

- DetectionRule is immutable.
- ParsedRule is derived only from DetectionRule.
- MappedEntity always references a canonical entity.
- KnowledgeRecord is immutable.
- KnowledgePackage contains only normalized records.
- LLMContext contains only validated contextual information.
- FinalResponse must originate from a ValidatedResponse.

---

# Future Extensions

The domain model supports future additions, including:

- Multiple rule formats.
- Multiple knowledge providers.
- Multiple graph implementations.
- Hybrid retrieval strategies.
- Multi-step reasoning.
- Agent orchestration.

---

End of Document