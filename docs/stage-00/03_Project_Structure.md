# 03_Project_Structure.md

Version: 1.0
Status: Draft

---

# Purpose

This document defines the official repository structure for the ODOSIAN AI Engine.

The project structure is designed to provide:

- Clear separation of responsibilities
- High maintainability
- Scalability
- Modular development
- Independent testing
- Future extensibility

The repository separates source code, knowledge resources, prompts, configuration, documentation, and testing into dedicated locations.

---

# Repository Structure

```text
odosian-ai-engine/
│
├── docs/
│   ├── stage-00/
│   ├── stage-01/
│   ├── architecture/
│   ├── decisions/
│   └── api/
│
├── src/
│   ├── application/
│   ├── config/
│   ├── parser/
│   ├── entities/
│   │
│   ├── knowledge/
│   │   ├── loader/
│   │   ├── repository/
│   │   ├── normalizer/
│   │   ├── resolver/
│   │   ├── models/
│   │   └── interfaces/
│   │
│   ├── graph/
│   ├── rag/
│   ├── context/
│   ├── llm/
│   ├── validation/
│   ├── formatter/
│   ├── models/
│   ├── interfaces/
│   ├── utils/
│   └── exceptions/
│
├── resources/
│   ├── knowledge/
│   │   ├── mitre.jsonl
│   │   ├── sigma.jsonl
│   │   ├── elastic.jsonl
│   │   ├── lolbas.jsonl
│   │   ├── atomic.jsonl
│   │   └── custom.jsonl
│   │
│   ├── mappings/
│   │   ├── mitre_aliases.json
│   │   ├── field_aliases.json
│   │   └── source_aliases.json
│   │
│   └── schemas/
│
├── prompts/
│   ├── analyze/
│   ├── enhance/
│   ├── generate/
│   ├── shared/
│   └── templates/
│
├── configs/
│   ├── providers/
│   ├── models/
│   ├── logging/
│   └── settings/
│
├── tests/
│   ├── unit/
│   ├── integration/
│   ├── evaluation/
│   ├── performance/
│   └── fixtures/
│
├── scripts/
│
├── examples/
│
├── .env.example
├── .gitignore
├── pyproject.toml
├── README.md
└── LICENSE
```

---

# Folder Responsibilities

## docs/

Contains all project documentation.

Examples:

- Architecture
- Design decisions
- Development stages
- API documentation

No production code should exist here.

---

## src/

Contains all production source code.

Every executable component of the AI Engine belongs here.

---

## src/application/

Application entry points and orchestration.

Responsible for coordinating the overall AI Engine workflow.

---

## src/config/

Internal configuration loading and configuration management.

---

## src/parser/

Rule parsing logic.

Responsible for parsing detection rules into structured representations.

---

## src/entities/

Entity extraction and entity identification.

Examples include:

- Techniques
- Tactics
- Commands
- Processes
- File paths
- Registry keys
- Network indicators

---

## src/knowledge/

Implements the Knowledge Base logic.

This module does not store the knowledge itself.

It provides the software layer that loads, validates, normalizes, and retrieves knowledge records.

Submodules:

### loader/

Reads knowledge resources from JSONL files.

### repository/

Provides a unified interface for querying knowledge.

### normalizer/

Normalizes field names, values, and internal representations.

### resolver/

Resolves aliases, version differences, and canonical identifiers.

### models/

Knowledge-specific data models.

### interfaces/

Contracts used by knowledge providers.

---

## src/graph/

Knowledge Graph construction and querying.

Responsible for graph generation and graph traversal.

---

## src/rag/

GraphRAG implementation.

Responsible for graph-aware retrieval.

---

## src/context/

Builds the final context supplied to the LLM.

---

## src/llm/

LLM provider abstraction.

Supports multiple providers such as:

- Gemini
- OpenAI
- Local models

---

## src/validation/

Validates AI outputs before returning results.

---

## src/formatter/

Converts validated results into the official output schema.

---

## src/models/

Shared domain models.

---

## src/interfaces/

Shared interfaces and abstract contracts.

---

## src/utils/

Reusable utility functions.

---

## src/exceptions/

Custom project exceptions.

---

## resources/

Contains non-code resources required by the project.

Resources are immutable inputs to the system.

---

## resources/knowledge/

Stores the cybersecurity knowledge datasets.

Examples:

- MITRE ATT&CK
- Sigma
- Elastic
- LOLBAS
- Atomic Red Team
- Custom datasets

These files are treated as read-only.

---

## resources/mappings/

Contains mapping files used to resolve differences between datasets.

Examples include:

- ATT&CK version aliases
- Field mappings
- Source mappings

---

## resources/schemas/

Stores JSON schemas and validation schemas.

---

## prompts/

Contains every LLM prompt used by the AI Engine.

Prompts are treated as project assets rather than embedded source code.

---

## configs/

Project configuration files.

Examples:

- Provider configuration
- Model configuration
- Logging
- Runtime settings

Configuration should never be hardcoded.

---

## tests/

Contains automated testing.

Includes:

- Unit tests
- Integration tests
- Evaluation tests
- Performance tests

---

## scripts/

Development and maintenance scripts.

Examples:

- Dataset updates
- Index generation
- Graph rebuilding
- Maintenance utilities

---

## examples/

Example inputs and expected outputs.

Useful for documentation, testing, and demonstrations.

---

# Project Rules

The following rules apply throughout the repository.

## Source Code

Production code belongs only inside `src/`.

---

## Knowledge Resources

Knowledge datasets are stored only inside `resources/knowledge/`.

They must never contain executable code.

---

## Prompt Management

Prompts belong only inside the `prompts/` directory.

Prompt text must never be hardcoded inside application logic.

---

## Configuration

Configuration values must be externalized.

Hardcoded runtime configuration is prohibited.

---

## Documentation

Documentation belongs only inside `docs/`.

---

## Testing

Tests belong only inside `tests/`.

Production code must never depend on test data.

---

## Resources

Knowledge resources are treated as immutable source material.

Normalization and transformation occur during runtime rather than modifying the original datasets.

---

# Design Principles

The project follows these architectural principles:

- Separation of concerns
- Single responsibility
- Config over hardcoding
- Prompt as code
- Immutable knowledge resources
- Modular architecture
- Provider independence
- Scalable repository organization

---

# Future Expansion

The structure is designed to support future additions including:

- Multiple LLM providers
- Additional cybersecurity datasets
- Multiple vector databases
- Multiple graph databases
- Offline execution
- Cloud deployment
- Distributed processing
- Multi-language knowledge sources
- Plugin-based extensions

---

End of Document