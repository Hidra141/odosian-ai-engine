---
name: enhance-instruction
version: "1.0"
description: Task instructions for the enhance operation.
variables: [RULE, CONTEXT, ENTITIES, MITRE, SIGMA, ELASTIC, ATOMIC, LOLBAS, SIMILAR_RULES]
---

# Task

Operation: `enhance`

Produce an improved version of the detection rule below, and account for every change you
make.

The improved rule must detect the same behaviour as the original. Narrowing the rule until
it stops matching, or widening it until it matches everything, is not an improvement.

# How to improve it

Apply changes in this order of priority, and stop where the supplied context stops
supporting you:

1. **Correctness** — fix conditions that do not express the intended behaviour, and
   replace field names that are invalid or absent from the supplied ECS material.
2. **Evasion resistance** — remove dependence on incidental detail an attacker can vary
   at no cost. Prefer conditions on the behaviour itself over conditions on one way of
   spelling it.
3. **False positive reduction** — exclude benign activity, but only activity the supplied
   context identifies as benign. Do not add an exclusion you cannot justify from the
   context, and never exclude on a field an attacker controls.
4. **Coverage** — extend to variants of the technique the supplied Atomic Red Team or
   LOLBAS material shows, where doing so does not compromise points 2 and 3.
5. **Documentation** — improve the investigation guidance so a first responder can triage
   a hit unaided.

# Constraints

- Keep the original rule_type and query language unless the original language cannot
  express a required correction. rule_type and language are not independent: eql only
  pairs with eql, esql only with esql, and every other rule_type only with kql or lucene.
  If you change the language, change rule_type to match in the same edit — a rule_type
  and language that do not agree is a rule that will not load, not a valid combination
  to leave for later. Say why in the accounting for that change.
- Every change must trace to a specific problem in the original rule. A change you cannot
  justify is a change you do not make.
- Preserve the rule's metadata unless a change requires updating it. Where severity, risk
  score or MITRE mapping no longer matches the improved query, correct it and account for
  that correction as its own change.
- Where a problem is real but the supplied context does not support a fix, leave the rule
  alone and record the problem as a recommendation instead.
- A `machine_learning` rule_type's query is a placeholder standing in for an ML job
  reference, not a filter expression describing the detection. Do not rewrite it as
  though it were one. Improve what can genuinely be improved — metadata, severity,
  investigation guidance — and leave the query and rule_type as they are.

# Inputs

## Rule to enhance

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
