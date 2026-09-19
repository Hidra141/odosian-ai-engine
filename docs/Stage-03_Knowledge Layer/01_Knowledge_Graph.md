# Knowledge Graph

**Version:** 1.0 · **Status:** Draft · **Stage:** 03 — Knowledge Layer

> [!NOTE]
> A design-stage document. In the shipped engine the graph is built in-process from the
> JSONL corpus and queried through hybrid retrieval — see the
> [project README](../../README.md).

---

## Purpose

This document defines the architecture of the Knowledge Graph used by the ODOSIAN AI Engine.

The Knowledge Graph transforms isolated cybersecurity records into a connected semantic network that enables contextual reasoning, relationship discovery, GraphRAG retrieval, and explainable AI responses.

The Knowledge Graph is not a replacement for the Knowledge Base.

Instead, it is an additional semantic layer built from the Knowledge Base.

---

## Scope

This document defines:

- Knowledge Graph architecture
- Node model
- Edge model
- Graph construction
- Graph lifecycle
- Relationship management
- Graph boundaries

This document does NOT define:

- Graph database technology
- Graph query language
- Graph implementation
- Graph storage engine

---

## Design Principles

The Knowledge Graph should be:

- Source-aware
- Explainable
- Traceable
- Immutable during runtime
- Provider-independent
- Extensible

Every relationship must be explainable.

---

## Knowledge Graph Overview

```mermaid
flowchart TB
    KB["Knowledge Base"] --> LO["Knowledge Loader"] --> NO["Normalizer"] --> RE["Resolver"]
    RE --> GB["Graph Builder"] --> KG["<b>Knowledge Graph</b>"] --> RAG["GraphRAG"]
    classDef n fill:#e8f0fe,stroke:#4c6ef5,color:#0b1a3a
    classDef hi fill:#f3f0ff,stroke:#7048e8,color:#1d0b3a
    class KB,LO,NO,RE,GB,RAG n
    class KG hi
```

---

## Purpose of the Graph

The Knowledge Base answers:

> What information exists?

The Knowledge Graph answers:

> How is this information related?

Example:

```mermaid
flowchart LR
    A["Sigma Rule"] --> B["Technique T1059"] --> C["PowerShell"]
    C --> D["LOLBAS Entry"] --> E["Elastic Rule"] --> F["Atomic Test"]
    classDef n fill:#f3f0ff,stroke:#7048e8,color:#1d0b3a
    class A,B,C,D,E,F n
```

The graph enables navigation between related concepts.

---

## Node Types

The graph consists of semantic nodes.

Current node categories include:

- Technique
- Tactic
- Sigma Rule
- Elastic Rule
- Atomic Test
- LOLBAS Entry
- Software
- Threat Group
- Campaign
- Mitigation
- Data Source

Additional node types may be introduced in future versions.

---

## Edge Types

Edges represent semantic relationships.

Examples include:

- uses
- detects
- references
- belongs_to
- mitigates
- tests
- related_to
- parent_of
- child_of

Edges represent knowledge relationships, not execution flow.

---

## Node Identity

Every node must have:

- Stable identifier
- Canonical identifier
- Source reference
- Source type

Original identifiers must always remain recoverable.

---

## Edge Identity

Every edge should define:

- Source node
- Target node
- Relationship type
- Relationship origin

Relationships should preserve provenance.

---

## Graph Construction

Graph construction consists of multiple stages.

```mermaid
flowchart TB
    R["Raw Records"] --> N["Normalize"] --> A["Resolve Aliases"]
    A --> CN["Create Nodes"] --> CE["Create Edges"] --> V{"Validate Graph"}
    V -- "valid" --> P["Publish Graph"]
    V -- "invalid" --> X["not published"]
    classDef n fill:#e8f0fe,stroke:#4c6ef5,color:#0b1a3a
    classDef g fill:#fff4e6,stroke:#f08c00,color:#3a2a0b
    classDef f fill:#ffe3e3,stroke:#e03131,color:#3a0b0b
    class R,N,A,CN,CE,P n
    class V g
    class X f
```

The graph is built offline.

Runtime requests must never rebuild the graph.

---

## Relationship Sources

Relationships may originate from:

- MITRE ATT&CK
- Sigma references
- Elastic mappings
- LOLBAS references
- Atomic mappings

Relationships should never be invented by the graph builder.

---

## Missing Relationships

The Knowledge Graph must distinguish between four states that are **not** equivalent:

| State | Means |
| --- | --- |
| **Known** | The relationship is recorded by a source. |
| **Unknown** | No source states it either way. *Unknown does not imply false.* |
| **Missing** | A source that should state it does not. *Missing does not imply absence.* |
| **Inferred** | Derived rather than recorded, and marked as such. |

---

## Version Handling

Different knowledge sources may reference different ATT&CK versions.

The graph should normalize identifiers before creating edges.

Canonical identifiers should be used internally.

Original identifiers should remain available for traceability.

---

## Graph Validation

Before publication, the graph should verify:

- Duplicate nodes
- Duplicate edges
- Invalid identifiers
- Broken references
- Cyclic validation rules (where applicable)

Invalid graph structures must not be published.

---

## Graph Lifecycle

```mermaid
flowchart LR
    U["Knowledge Update"] --> B["Graph Build"] --> V["Graph Validation"]
    V --> P["Graph Publication"] --> Q["Runtime Queries"]
    classDef off fill:#f3f0ff,stroke:#7048e8,color:#1d0b3a
    classDef on fill:#e6fcf5,stroke:#0ca678,color:#052e26
    class U,B,V,P off
    class Q on
```

Graph construction and runtime querying are separate processes.

---

## Runtime Responsibilities

During runtime, the graph should provide:

- Neighbor discovery
- Relationship traversal
- Context expansion
- Evidence collection

The graph should not perform AI reasoning.

---

## Explainability

Every retrieved relationship should remain explainable.

Example:

```mermaid
flowchart LR
    T["Technique T1059"] -- "referenced by" --> S["Sigma Rule"]
    S -- "referenced by" --> E["Elastic Rule"]
    E -- "referenced by" --> A["Atomic Test"]
    classDef n fill:#e8f0fe,stroke:#4c6ef5,color:#0b1a3a
    class T,S,E,A n
```

The graph must preserve the chain of evidence.

---

## Graph Independence

The Knowledge Graph must remain independent from:

- LLM provider
- Prompt templates
- Validation logic
- Response formatting

Its responsibility ends with semantic relationship retrieval.

---

## Future Expansion

The architecture supports future additions including:

- Organization-specific knowledge
- Threat Intelligence feeds
- Vulnerability relationships
- Malware relationships
- Asset relationships
- Detection coverage analysis

New relationship types should extend the graph without modifying existing node definitions.

---

## Knowledge Graph Boundary

The graph answers:

> "What is connected?"

It does NOT answer:

> "What should the AI conclude?"

Reasoning belongs to later stages:

```mermaid
flowchart LR
    KG["Knowledge Graph<br/><i>what is connected</i>"] --> RAG["GraphRAG<br/><i>what is relevant</i>"]
    RAG --> CB["Context Builder<br/><i>what the model sees</i>"] --> LLM["LLM<br/><i>what to conclude</i>"]
    classDef n fill:#e8f0fe,stroke:#4c6ef5,color:#0b1a3a
    class KG,RAG,CB,LLM n
```

---

End of Document