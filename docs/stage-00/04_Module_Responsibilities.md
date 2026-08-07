# 04_Module_Responsibilities.md

Version: 1.0
Status: Draft

---

# Purpose

This document defines the responsibilities, boundaries, and interactions of every module within the ODOSIAN AI Engine.

Each module has a single primary responsibility and should not perform work assigned to another module.

This separation improves maintainability, testing, scalability, and future extensibility.

---

# AI Engine Pipeline

```

Request
↓
Rule Parser
↓
Entity Extraction
↓
Entity Mapping
↓
Knowledge Base
↓
Knowledge Graph
↓
GraphRAG
↓
Context Builder
↓
LLM
↓
Validation
↓
Formatter
↓
Response

```

---

# Module Responsibilities

## 1. Rule Parser

### Responsibility

Parse detection rules into a structured internal representation.

### Input

- Detection Rule

### Output

- ParsedRule

### Must Do

- Parse syntax
- Extract fields
- Validate required attributes

### Must NOT Do

- Call the LLM
- Search the Knowledge Base
- Perform entity mapping

---

## 2. Entity Extraction

### Responsibility

Extract cybersecurity entities from parsed rules.

### Examples

- ATT&CK Techniques
- ATT&CK Tactics
- CVEs
- File paths
- Registry Keys
- Domains
- IP Addresses
- Processes
- Commands
- Services

### Input

ParsedRule

### Output

ExtractedEntities

### Must NOT Do

- Resolve aliases
- Query datasets
- Infer missing entities

---

## 3. Entity Mapping

### Responsibility

Resolve extracted entities into canonical representations.

### Responsibilities include

- Alias resolution
- ATT&CK version mapping
- Source normalization
- Canonical ID resolution

### Input

ExtractedEntities

### Output

MappedEntities

### Must NOT Do

- Generate explanations
- Query the LLM

---

## 4. Knowledge Base

### Responsibility

Retrieve structured cybersecurity knowledge.

### Responsibilities include

- Load JSONL resources
- Search datasets
- Retrieve matching records
- Normalize records
- Return structured knowledge

### Must NOT Do

- Build prompts
- Generate text
- Rank LLM responses

---

## 5. Knowledge Graph

### Responsibility

Represent relationships between cybersecurity entities.

### Responsibilities include

- Store relationships
- Traverse connections
- Expand related entities

### Must NOT Do

- Parse rules
- Build prompts
- Generate responses

---

## 6. GraphRAG

### Responsibility

Retrieve graph-aware contextual knowledge.

### Responsibilities include

- Query graph
- Rank connected nodes
- Collect relevant evidence
- Reduce retrieval noise

### Must NOT Do

- Generate final answers
- Modify graph data

---

## 7. Context Builder

### Responsibility

Assemble all retrieved information into a single structured context.

### Context Sources

- Parsed Rule
- Entities
- Knowledge Base
- Knowledge Graph
- GraphRAG

### Output

LLM Context Package

### Must NOT Do

- Generate explanations
- Validate responses

---

## 8. LLM Provider

### Responsibility

Generate AI reasoning using the prepared context.

### Responsibilities

- Load prompts
- Send requests
- Receive responses
- Handle provider communication

### Supported Providers

- Gemini
- OpenAI
- Local Models

### Must NOT Do

- Build graph
- Query JSONL
- Parse rules

---

## 9. Validation Engine

### Responsibility

Validate AI-generated responses.

### Responsibilities

- JSON validation
- Required fields
- Confidence checks
- Hallucination detection
- Schema validation

### Must NOT Do

- Modify prompts
- Query datasets

---

## 10. Formatter

### Responsibility

Convert validated output into the official API response format.

### Responsibilities

- JSON formatting
- Output normalization
- Version tagging

### Must NOT Do

- AI reasoning
- Knowledge retrieval

---

# Communication Rules

Modules communicate only through well-defined interfaces.

A module must never directly access another module's internal implementation.

All communication should occur through contracts or interfaces.

---

# Dependency Rules

Allowed dependency direction:

Parser
↓

Entity Extraction
↓

Entity Mapping
↓

Knowledge Base
↓

Knowledge Graph
↓

GraphRAG
↓

Context Builder
↓

LLM
↓

Validation
↓

Formatter

Backward dependencies are not allowed.

---

# Design Principles

Each module follows:

- Single Responsibility Principle
- Loose Coupling
- High Cohesion
- Dependency Inversion
- Interface-Based Design

---

End of Document