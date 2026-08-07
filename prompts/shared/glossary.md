---
name: shared-glossary
version: "1.0"
description: Shared terminology. Fixes the meaning of terms used across prompts and outputs.
variables: []
---

# Glossary

These terms carry the meanings below throughout the task. Use them consistently in your
output, and do not substitute synonyms.

## Detection

- **Rule** — a detection definition evaluated by Elastic Security, comprising a query and
  its metadata.
- **Query** — the search expression a rule evaluates.
- **Query language** — one of KQL, EQL, ES|QL or Lucene.
- **Rule type** — one of query, threshold, eql, new_terms or esql.
- **Severity** — one of critical, high, medium or low.
- **Risk score** — an integer from 0 to 100 accompanying severity.
- **Investigation guide** — the triage guidance an analyst follows when the rule fires.

## Evaluation

- **Finding** — an observation about the rule as it currently stands.
- **Recommendation** — a proposed change to the rule.
- **False positive** — benign activity that satisfies the rule.
- **False negative** — target activity the rule fails to match.
- **Noise** — matches that are technically correct but too voluminous to action.
- **Evasion** — a change in attacker behaviour that avoids the rule while still achieving
  the attack.
- **Coverage** — the portion of a technique's observable behaviour a rule detects.
- **Brittleness** — dependence on an incidental detail, such as a literal path or a
  specific argument order, that an attacker can vary at no cost.

## Knowledge sources

- **MITRE ATT&CK** — the tactic, technique and sub-technique taxonomy. Tactics carry `TA`
  identifiers, techniques carry `T` identifiers.
- **Sigma** — the vendor-neutral detection rule format.
- **Elastic** — Elastic's prebuilt detection rules.
- **ECS** — the Elastic Common Schema, defining canonical dotted field names.
- **LOLBAS** — living-off-the-land binaries, scripts and libraries abused by attackers.
- **Atomic Red Team** — executable tests mapped to ATT&CK techniques.
- **Similar rules** — existing rules retrieved as comparable to the one under review.

## Engine

- **Context** — the evidence package assembled for this task by the engine. It is fixed
  for the duration of the task.
- **Entity** — a cybersecurity object extracted from a rule, such as a process, file
  path, registry key, port, command or ECS field.
