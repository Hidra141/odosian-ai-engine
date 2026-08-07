# ODOSIAN AI Engine Architecture

Version: 1.0
Status: Draft

---

# Overview

The ODOSIAN AI Engine follows a layered architecture to ensure modularity,
maintainability, scalability, and testability.

Each layer has a single responsibility and communicates only with adjacent layers.

---

# High-Level Architecture

                 API / Backend
                       │
                       ▼
              Application Layer
                       │
                       ▼
                AI Engine Layer
     ┌─────────────────────────────────────┐
     │                                     │
     │ Rule Parser                         │
     │ Entity Extraction                   │
     │ Entity Mapping                      │
     │ Knowledge Base                      │
     │ Knowledge Graph                     │
     │ GraphRAG                            │
     │ Context Builder                     │
     │ LLM Provider                        │
     │ Response Formatter                  │
     │                                     │
     └─────────────────────────────────────┘
                       │
                       ▼
              Validation Layer
                       │
                       ▼
                 JSON Response

---

# Layers

## 1. Application Layer

Responsibilities

- Receive requests
- Validate request schema
- Invoke AI Engine
- Return response

Never performs AI reasoning.

---

## 2. AI Engine Layer

Core business logic.

Contains:

- Rule Parser
- Entity Extraction
- Entity Mapping
- Knowledge Base
- Knowledge Graph
- GraphRAG
- Context Builder
- LLM Provider
- Response Formatter

---

## 3. Validation Layer

Responsibilities

- Validate AI output
- Validate JSON schema
- Check confidence
- Detect hallucination indicators
- Produce final validated response

---

# Module Responsibilities

Rule Parser
→ Parse Elastic Detection Rules.

Entity Extraction
→ Extract techniques, fields, products, data sources, actors, commands, etc.

Entity Mapping
→ Map extracted entities to standardized knowledge.

Knowledge Base
→ Retrieve cybersecurity knowledge.

Knowledge Graph
→ Represent relationships between entities.

GraphRAG
→ Retrieve the most relevant graph context.

Context Builder
→ Build the final prompt context.

LLM Provider
→ Execute inference.

Response Formatter
→ Convert inference into structured JSON.

Validation
→ Validate the generated response.

---

# Architecture Principles

- Layered Architecture
- Loose Coupling
- High Cohesion
- Dependency Injection
- Provider Independence
- Config First
- Prompt as Code
- Validation First

---

# Communication Rules

Allowed

Application
↓

AI Engine

↓

Validation

↓

Application

Not Allowed

Rule Parser
↓

Knowledge Graph مباشرة

أو

LLM
↓

Knowledge Base مباشرة

كل Module يتواصل فقط عبر الواجهات (Interfaces).

---

# Future Expansion

The architecture supports:

- Multiple LLM Providers
- Multiple Knowledge Sources
- Additional Graph Databases
- Local AI Models
- Cloud AI Models
- Multi-language Support