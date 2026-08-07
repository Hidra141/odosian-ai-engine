---
name: analyze-instruction
version: "1.0"
description: Task instructions for the analyze operation.
variables: [RULE, CONTEXT, ENTITIES, MITRE, SIGMA, ELASTIC, ATOMIC, LOLBAS, SIMILAR_RULES]
---

# Task

Operation: `analyze`

Assess the detection rule below against the supplied context. Report what is wrong with
it, what it misses, and how it can be evaded.

Do not rewrite the rule. Producing a corrected query is the enhance operation. Here you
may describe what a change would need to achieve, but you do not author it.

# What to assess

Work through each dimension below. Report only where the supplied context lets you say
something specific — an empty dimension is a legitimate result, a padded one is not.

1. **Logic** — does the query express the behaviour its title and description claim? Name
   any condition that widens or narrows it beyond that claim.
2. **Fields** — is every referenced field a valid ECS field present in the supplied
   context? Flag fields that are misspelled, deprecated, or absent from the schema.
3. **False positives** — what benign activity satisfies this query? Be concrete about the
   software or administrative process responsible.
4. **False negatives** — which variants of the target behaviour does the query miss?
5. **Evasion** — what is the smallest change to attacker behaviour that defeats this rule
   while preserving the attack? Ground each evasion in the supplied LOLBAS or Atomic Red
   Team material, and say which supplied item supports it.
6. **Brittleness** — does the rule depend on incidental detail, such as a literal path,
   a casing, or an argument order, that an attacker varies at no cost?
7. **MITRE coverage** — does the claimed mapping match what the query actually detects?
   Report claimed techniques the query does not cover, and covered behaviour the mapping
   omits. Use only identifiers present in the supplied MITRE material.
8. **Noise** — will this fire at a volume an analyst can work? Identify the condition
   driving the volume.
9. **Documentation** — is the investigation guidance sufficient to triage a hit without
   consulting the rule's author?

Where the supplied similar rules already solve a problem you identify, say which rule and
what it does differently.

# Inputs

## Rule under analysis

{{RULE}}

## Context

{{CONTEXT}}

## Extracted entities

{{ENTITIES}}

## MITRE ATT&CK

{{MITRE}}

## Sigma

{{SIGMA}}

## Elastic

{{ELASTIC}}

## Atomic Red Team

{{ATOMIC}}

## LOLBAS

{{LOLBAS}}

## Similar rules

{{SIMILAR_RULES}}
