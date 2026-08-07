---
name: generate-instruction
version: "1.0"
description: Task instructions for the generate operation. RULE carries the detection requirement.
variables: [RULE, CONTEXT, ENTITIES, MITRE, SIGMA, ELASTIC, ATOMIC, LOLBAS, SIMILAR_RULES]
---

# Task

Operation: `generate`

Write a complete detection rule satisfying the requirement below.

For this operation the requirement section carries a description of what is to be
detected, stated in natural language, rather than an existing rule.

# How to write it

1. **Establish the target behaviour.** Determine what observable activity the requirement
   describes. Where the requirement is ambiguous, resolve it toward the reading the
   supplied context supports, and record the ambiguity in your findings.
2. **Choose the data source.** Detect on fields the supplied ECS material confirms exist.
   A rule referencing a field absent from the supplied context is not a usable rule.
3. **Choose the query language and rule type.** Pick the pair that expresses the behaviour
   most directly. Prefer eql where the requirement describes a sequence or a
   parent-child relationship, and a plain query where it describes a single event.
4. **Write the query.** Condition on the behaviour rather than on one way of spelling it.
   Anticipate the trivial variations the supplied LOLBAS and Atomic Red Team material
   demonstrate.
5. **Set the metadata.** Severity and risk score must reflect the consequence of the
   detected behaviour, not the confidence of the detection. Map to MITRE ATT&CK using
   only identifiers present in the supplied material.
6. **Document it.** Write an investigation guide a first responder can follow unaided, and
   state the false positives you expect a deployment to encounter.

# Constraints

- Produce one rule. Where the requirement describes several distinct behaviours, cover the
  primary one and record the others as recommendations.
- Do not invent field names, log sources, or identifiers absent from the supplied context.
  If the requirement cannot be detected with the supplied material, say so plainly in the
  summary, lower `confidence`, and produce the closest rule the material does support.
- Where a supplied similar rule already covers the requirement, say so and explain how
  yours differs. Do not reproduce it.

# Inputs

## Detection requirement

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
