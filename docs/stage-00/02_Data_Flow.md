# Data Flow

Version: 1.0
Status: Draft

---

# Purpose

This document defines how data moves through the ODOSIAN AI Engine from the moment a request is received until the final validated response is returned.

---

# Data Flow Overview

Request
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
Response Formatter
    │
    ▼
Validation Engine
    │
    ▼
JSON Response

---

# Step 1 — Request

Input:

- Rule Text
- Operation Type
  - Analyze
  - Enhance
  - Generate

Output:

Raw Request Object

---

# Step 2 — Rule Parser

Responsibilities

- Parse the rule
- Detect syntax errors
- Normalize the rule
- Build a structured object

Output

Structured Rule Object

---

# Step 3 — Entity Extraction

Responsibilities

Extract cybersecurity entities such as:

- MITRE Techniques
- Fields
- Products
- Data Sources
- Commands
- File Paths
- Registry Keys
- Processes
- IP Addresses
- Domains

Output

Extracted Entity List

---

# Step 4 — Entity Mapping

Responsibilities

Map extracted entities to standardized identifiers.

Example:

"powershell"

↓

LOLBAS

↓

MITRE

↓

Elastic ECS

Output

Mapped Entities

---

# Step 5 — Knowledge Base

Responsibilities

Retrieve documentation and reference knowledge related to mapped entities.

Sources may include:

- MITRE ATT&CK
- Sigma
- Elastic
- Atomic Red Team
- LOLBAS
- Internal Knowledge

Output

Knowledge Documents

---

# Step 6 — Knowledge Graph

Responsibilities

Load relationships between entities.

Example

PowerShell

↓

Technique

↓

Detection

↓

Data Source

↓

Relevant Rule

Output

Knowledge Subgraph

---

# Step 7 — GraphRAG

Responsibilities

Retrieve only the most relevant graph context.

Output

Relevant Context

---

# Step 8 — Context Builder

Responsibilities

Merge:

- Parsed Rule
- Extracted Entities
- Mapped Entities
- Knowledge Documents
- Graph Context
- User Operation

Output

Final Prompt Context

---

# Step 9 — LLM Provider

Responsibilities

Execute inference using the configured LLM.

Input

Prompt Context

Output

Raw AI Response

---

# Step 10 — Response Formatter

Responsibilities

Convert raw AI output into the project's JSON schema.

Output

Structured Response

---

# Step 11 — Validation Engine

Responsibilities

Validate:

- JSON Schema
- Required Fields
- Confidence
- Consistency
- Unsupported Claims

Output

Validated Response

---

# Final Output

The AI Engine returns:

- Validated JSON
- Confidence Score
- Reasoning
- Suggestions (when applicable)