# AI Engine Architecture

**Version:** 1.0 · **Status:** Draft · **Stage:** 00 — Foundations

> [!NOTE]
> A design-stage document. For the architecture as built — including the HTTP service and the
> eight-stage pipeline — see the [project README](../../README.md).

---

## Overview

The ODOSIAN AI Engine follows a layered architecture to ensure modularity, maintainability,
scalability, and testability.

Each layer has a single responsibility and communicates only with adjacent layers.

---

## High-level architecture

```mermaid
flowchart TB
    API["<b>API / Backend</b>"] --> APP["<b>Application Layer</b><br/><i>receives, validates, dispatches</i>"]

    APP --> ENGINE

    subgraph ENGINE["AI Engine Layer — the reasoning core"]
        direction TB
        subgraph ROW1["read the rule"]
            direction LR
            E1["Rule Parser"] --> E2["Entity Extraction"] --> E3["Entity Mapping"]
        end
        subgraph ROW2["gather the knowledge"]
            direction LR
            E4["Knowledge Base"] --> E5["Knowledge Graph"] --> E6["GraphRAG"]
        end
        subgraph ROW3["ask the model"]
            direction LR
            E7["Context Builder"] --> E8["LLM Provider"] --> E9["Response Formatter"]
        end
        ROW1 --> ROW2 --> ROW3
    end

    ENGINE --> VAL["<b>Validation Layer</b><br/><i>the last word on what may be returned</i>"]
    VAL --> OUT(["JSON Response"])

    classDef edge fill:#e6fcf5,stroke:#0ca678,color:#052e26
    classDef layer fill:#fff4e6,stroke:#f08c00,color:#3a2a0b
    classDef comp fill:#e8f0fe,stroke:#4c6ef5,color:#0b1a3a
    class API,OUT edge
    class APP,VAL layer
    class E1,E2,E3,E4,E5,E6,E7,E8,E9 comp
```

---

## Layers

### 1 · Application layer

Receives requests, validates the request schema, invokes the AI engine, and returns the response.

**It never performs AI reasoning.**

### 2 · AI engine layer

The core business logic — the nine components in the diagram above.

### 3 · Validation layer

Validates the AI output: the JSON schema, the confidence, and any hallucination indicators. It
produces the final validated response, and it is what stands between a generated answer and a
caller acting on it.

---

## Module responsibilities

| Module | Responsibility |
| --- | --- |
| Rule Parser | Parse Elastic detection rules. |
| Entity Extraction | Extract techniques, fields, products, data sources, actors, commands, and the rest. |
| Entity Mapping | Map extracted entities to standardised knowledge. |
| Knowledge Base | Retrieve cybersecurity knowledge. |
| Knowledge Graph | Represent relationships between entities. |
| GraphRAG | Retrieve the most relevant graph context. |
| Context Builder | Build the final prompt context. |
| LLM Provider | Execute inference. |
| Response Formatter | Convert inference into structured JSON. |
| Validation | Validate the generated response. |

---

## Architecture principles

| Principle | |
| --- | --- |
| Layered architecture | Each layer talks only to its neighbours. |
| Loose coupling | Modules depend on interfaces, never on each other's implementations. |
| High cohesion | One responsibility per module. |
| Dependency injection | Collaborators are supplied, not constructed in place. |
| Provider independence | No layer learns which language model backend is behind it. |
| Config first | Behaviour is configured, not hard-coded. |
| Prompt as code | Prompts are versioned assets, reviewed like code. |
| Validation first | Nothing is returned that has not been validated. |

---

## Communication rules

```mermaid
flowchart LR
    subgraph OK["✔ Allowed"]
        direction LR
        A1["Application"] --> A2["AI Engine"] --> A3["Validation"] --> A4["Application"]
    end

    subgraph NO["✘ Not allowed"]
        direction LR
        B1["Rule Parser"] -. direct .-x B2["Knowledge Graph"]
        B3["LLM"] -. direct .-x B4["Knowledge Base"]
    end

    classDef ok fill:#e6fcf5,stroke:#0ca678,color:#052e26
    classDef no fill:#ffe3e3,stroke:#e03131,color:#3a0b0b
    class A1,A2,A3,A4 ok
    class B1,B2,B3,B4 no
```

كل Module يتواصل فقط عبر الواجهات (Interfaces) — لا يستدعي أي مديول تنفيذَ مديول آخر مباشرة.

*Every module communicates only through the interfaces. No module calls another module's
implementation directly.*

---

## Future expansion

The architecture supports:

- Multiple LLM providers
- Multiple knowledge sources
- Additional graph databases
- Local AI models
- Cloud AI models
