# 02_Model_Specifications.md

Version: 1.0
Status: Draft

---

# Purpose

This document defines the detailed specifications of every Core Model used in the ODOSIAN AI Engine.

Unlike the Core Models document, which describes business concepts, this document specifies the internal structure of each model, including fields, constraints, and validation expectations.

These specifications serve as the blueprint for future implementations such as Python dataclasses, Pydantic models, or API schemas.

---

# Scope

This document defines:

- Model fields
- Field types
- Required fields
- Optional fields
- Validation constraints
- Default values
- Examples

This document does not define implementation code.

---

# Design Principles

Every model specification should:

- Be implementation-independent
- Be serialization-friendly
- Be versionable
- Be immutable whenever practical
- Be self-describing

---

# Model Specification Template

Every model should define:

- Description
- Producer
- Consumers
- Fields
- Constraints
- Example

---

# DetectionRule

## Description

Represents the original rule submitted to the AI Engine.

### Producer

Client

### Consumers

- Rule Parser

### Fields

| Field | Type | Required | Description |
|--------|------|----------|-------------|
| id | String | Optional | Unique identifier |
| source | String | Required | Rule source (Sigma, Elastic, etc.) |
| content | String | Required | Original rule content |
| metadata | Object | Optional | Additional metadata |

---

# ParsedRule

## Description

Structured representation of the detection rule.

### Producer

Rule Parser

### Consumers

- Entity Extraction
- Context Builder

### Fields

| Field | Type | Required | Description |
|--------|------|----------|-------------|
| id | String | Required | Internal identifier |
| title | String | Optional | Rule title |
| description | String | Optional | Rule description |
| rule_type | String | Required | Rule format |
| normalized_content | Object | Required | Parsed representation |

---

# Entity

### Fields

| Field | Type | Required | Description |
|--------|------|----------|-------------|
| id | String | Required | Internal entity identifier |
| type | String | Required | Entity type |
| value | String | Required | Extracted value |
| confidence | Float | Optional | Extraction confidence |

---

# MappedEntity

### Fields

| Field | Type | Required | Description |
|--------|------|----------|-------------|
| entity | Entity | Required | Original entity |
| canonical_id | String | Required | Canonical identifier |
| aliases | List<String> | Optional | Known aliases |
| source | String | Required | Mapping source |

---

# KnowledgeRecord

### Fields

| Field | Type | Required | Description |
|--------|------|----------|-------------|
| id | String | Required | Record identifier |
| source | String | Required | Knowledge source |
| content | Object | Required | Structured knowledge |
| metadata | Object | Optional | Additional metadata |

---

# KnowledgePackage

### Fields

| Field | Type | Required | Description |
|--------|------|----------|-------------|
| records | List<KnowledgeRecord> | Required | Retrieved records |
| retrieval_time | Integer | Optional | Retrieval duration |
| source_count | Integer | Optional | Number of sources |

---

# GraphNode

### Fields

| Field | Type | Required | Description |
|--------|------|----------|-------------|
| id | String | Required | Node identifier |
| label | String | Required | Display label |
| type | String | Required | Node category |

---

# GraphEdge

### Fields

| Field | Type | Required | Description |
|--------|------|----------|-------------|
| source | String | Required | Source node |
| target | String | Required | Target node |
| relation | String | Required | Relationship type |

---

# GraphContext

### Fields

| Field | Type | Required | Description |
|--------|------|----------|-------------|
| nodes | List<GraphNode> | Required | Retrieved nodes |
| edges | List<GraphEdge> | Required | Retrieved edges |

---

# RetrievedContext

### Fields

| Field | Type | Required | Description |
|--------|------|----------|-------------|
| evidence | List<Object> | Required | Ranked evidence |
| score | Float | Optional | Overall relevance |

---

# LLMContext

### Fields

| Field | Type | Required | Description |
|--------|------|----------|-------------|
| parsed_rule | ParsedRule | Required | Parsed rule |
| entities | List<MappedEntity> | Required | Canonical entities |
| knowledge | KnowledgePackage | Required | Retrieved knowledge |
| graph | GraphContext | Optional | Graph information |

---

# AIResponse

### Fields

| Field | Type | Required | Description |
|--------|------|----------|-------------|
| content | Object | Required | Raw model output |
| provider | String | Required | LLM provider |
| model | String | Required | Model name |

---

# ValidatedResponse

### Fields

| Field | Type | Required | Description |
|--------|------|----------|-------------|
| response | AIResponse | Required | Validated response |
| validation_status | String | Required | Validation result |
| confidence | Float | Optional | Confidence score |

---

# FinalResponse

### Fields

| Field | Type | Required | Description |
|--------|------|----------|-------------|
| data | Object | Required | Final payload |
| version | String | Required | Response version |
| timestamp | DateTime | Required | Generation timestamp |

---

# Model Evolution

Changes to model specifications must:

- Preserve backward compatibility whenever possible.
- Be documented.
- Be reviewed before approval.

---

End of Document