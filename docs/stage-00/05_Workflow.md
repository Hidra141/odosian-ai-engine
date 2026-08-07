# 05_Workflow.md

Version: 1.0
Status: Draft

---

# Purpose

This document defines the complete execution workflow of the ODOSIAN AI Engine.

It describes how data flows through the system, how modules interact, and how information is progressively transformed into a validated AI response.

The workflow is deterministic up to the LLM inference stage and deterministic again after validation.

---

# High-Level Workflow

```
User Request
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
      ▼
Knowledge Base
      │
      ▼
Knowledge Graph
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
Response Formatter
      │
      ▼
Final Response
```

---

# Execution Steps

## Step 1 — Receive Request

### Input

Detection rule.

### Output

Raw request.

---

## Step 2 — Parse Rule

Responsible Module

Rule Parser

### Responsibilities

- Parse rule syntax.
- Validate required fields.
- Extract structured attributes.

### Output

ParsedRule

---

## Step 3 — Extract Entities

Responsible Module

Entity Extraction

### Responsibilities

Extract cybersecurity entities.

Examples:

- ATT&CK IDs
- CVEs
- Processes
- Commands
- Registry Keys
- Domains
- IP Addresses
- Services

### Output

ExtractedEntities

---

## Step 4 — Map Entities

Responsible Module

Entity Mapping

### Responsibilities

Convert extracted entities into canonical identifiers.

Examples:

- ATT&CK alias resolution
- Version mapping
- Canonical IDs
- Dataset normalization

### Output

MappedEntities

---

## Step 5 — Retrieve Knowledge

Responsible Module

Knowledge Base

### Responsibilities

Retrieve structured knowledge from datasets.

Possible sources include:

- MITRE ATT&CK
- Sigma
- Elastic
- LOLBAS
- Atomic Red Team
- Custom datasets

### Output

KnowledgePackage

---

## Step 6 — Expand Relationships

Responsible Module

Knowledge Graph

### Responsibilities

Expand entity relationships.

Examples:

- Related techniques
- Parent tactics
- Software
- Threat groups
- Campaigns

### Output

GraphContext

---

## Step 7 — Graph Retrieval

Responsible Module

GraphRAG

### Responsibilities

Retrieve graph-aware context.

Operations include:

- Neighbor expansion
- Ranking
- Context filtering
- Evidence selection

### Output

RetrievedContext

---

## Step 8 — Build Context

Responsible Module

Context Builder

### Responsibilities

Combine all available information into one structured context.

Sources:

- Parsed rule
- Entities
- Knowledge Base
- Knowledge Graph
- GraphRAG

### Output

LLMContext

---

## Step 9 — AI Inference

Responsible Module

LLM Provider

### Responsibilities

- Load prompt
- Inject context
- Generate reasoning
- Produce structured output

### Output

AIResponse

---

## Step 10 — Validate Response

Responsible Module

Validation Engine

### Responsibilities

Validate:

- JSON schema
- Required fields
- Confidence
- Hallucination indicators
- Structural correctness

### Output

ValidatedResponse

---

## Step 11 — Format Output

Responsible Module

Formatter

### Responsibilities

Convert the validated response into the official API output.

### Output

FinalResponse

---

# Error Handling

Each module is responsible for validating its own inputs.

A module must never assume that previous modules succeeded.

Failures should be propagated using standardized exceptions.

The workflow must terminate immediately on unrecoverable errors.

---

# Design Principles

The workflow follows these principles:

- Sequential execution
- Clear module boundaries
- Immutable intermediate data
- Deterministic preprocessing
- Explainable transformations
- Provider independence
- Fail-fast architecture

---

# Future Extensions

The workflow supports future additions such as:

- Multiple Knowledge Bases
- Multiple Knowledge Graphs
- Multiple LLM Providers
- Hybrid Retrieval
- Agent-based reasoning
- Parallel retrieval strategies
- Caching layers
- Distributed execution

---

End of Document