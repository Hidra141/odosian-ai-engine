# ODOSIAN AI Engine

An AI-powered cybersecurity reasoning engine. It parses Elastic detection rules, extracts and maps
cybersecurity entities, enriches them from a knowledge base and knowledge graph, assembles a
contextual evidence package, and drives a language model to analyze, enhance, or generate rules.

The engine exposes three operations: **analyze**, **enhance**, and **generate**. It is the
reasoning component only — the web application, user management, Elastic Stack, and deployment
infrastructure are outside its scope.

## Architecture Overview

Processing runs as a linear pipeline. Each stage has one responsibility, receives a data contract,
and produces a data contract. Modules communicate only through the abstractions in
`src/interfaces/`; no module imports another module's implementation, which keeps the dependency
graph acyclic.

```
Request → Rule Parser → Entity Extraction → Entity Mapping → Knowledge Base
        → Knowledge Graph → GraphRAG → Context Builder → Prompt Management
        → LLM Provider → Validation Engine → Formatter → Response
```

| Package | Responsibility |
| --- | --- |
| `core` | Internal engine: engine, pipeline, workflows, and operation dispatch. |
| `config` | Centralised loading of YAML configuration and credentials. |
| `parser` | Parses KQL, EQL, ES\|QL, Lucene, and Sigma rules into a structured representation. |
| `entities` | Extracts entities: processes, files, registry keys, ports, IPs, commands, ECS fields. |
| `mapping` | Resolves entities to canonical identifiers against MITRE ATT&CK, ECS, and the ontology. |
| `knowledge` | Loads, normalises, resolves, and queries the knowledge datasets. |
| `graph` | Knowledge graph construction and traversal over Neo4j. |
| `graphrag` | Graph-aware retrieval, hybrid search, and ranking of contextual evidence. |
| `context` | Assembles the final context package for the language model. |
| `prompts` | Loads, versions, and renders the prompt assets stored under `prompts/`. |
| `llm` | Provider-agnostic abstraction over language model backends. |
| `validation` | Validates AI output: syntax, ECS compliance, MITRE coverage, schema. |
| `formatter` | Converts validated results into the official JSON output schema. |
| `models` | Shared domain models exchanged between modules. |
| `interfaces` | Shared abstract contracts. Imports `models` and nothing else. |
| `exceptions` | Custom project exceptions. |
| `utils` | Reusable utility functions. |

Prompts, configuration, and knowledge datasets are project assets rather than source code, and live
outside `src/` in `prompts/`, `configs/`, and `resources/`.

## Folder Structure

```
odosian-ai-engine/
├── configs/                    # YAML configuration
│   ├── logging/
│   ├── models/
│   ├── providers/
│   └── settings/
├── docs/
│   ├── api/
│   ├── architecture/
│   ├── decisions/
│   └── stage-*/
├── examples/                   # Example inputs and expected outputs
├── prompts/                    # Prompt assets (Markdown)
│   ├── analyze/
│   ├── enhance/
│   ├── generate/
│   ├── shared/
│   └── templates/
├── resources/                  # Immutable, read-only inputs
│   ├── knowledge/
│   │   ├── mitre/
│   │   ├── sigma/
│   │   ├── elastic/
│   │   ├── lolbas/
│   │   └── atomic/
│   ├── mappings/
│   └── schemas/
├── scripts/                    # Dataset updates, index and graph rebuilds
├── src/
│   ├── core/
│   ├── config/
│   ├── parser/
│   ├── entities/
│   ├── mapping/
│   ├── knowledge/
│   │   ├── loader/
│   │   ├── repository/
│   │   ├── normalizer/
│   │   ├── resolver/
│   │   ├── models/
│   │   └── interfaces/
│   ├── graph/
│   ├── graphrag/
│   ├── context/
│   ├── prompts/
│   ├── llm/
│   ├── validation/
│   ├── formatter/
│   ├── models/
│   ├── interfaces/
│   ├── exceptions/
│   └── utils/
├── tests/
│   ├── unit/
│   ├── integration/
│   ├── evaluation/
│   ├── performance/
│   └── fixtures/
├── .env.example
├── .gitignore
├── LICENSE
├── README.md
├── pyproject.toml
└── requirements.txt
```

## Development Prerequisites

- Python 3.12 or newer
- An API key for the configured language model provider

```bash
python -m venv .venv
```

```bash
pip install -e ".[dev]"
```

```bash
cp .env.example .env
```

Code style: PEP 8, full type hints, `ruff` for linting, `mypy --strict` for type checking, and
`pytest` for the test suite.
