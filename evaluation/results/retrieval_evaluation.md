# ODOSIAN Retrieval Evaluation

Benchmark `odosian-retrieval-1.0` — 36 cases, 2605 graded judgments, K = [1, 3, 5, 10].

Retrieval is evaluated at record granularity: ranked chunks are collapsed to their parent records, keeping rank order, before any metric is computed.

## 1. Which retrieval mode performed best?

| Mode | P@1 | P@3 | P@5 | P@10 | R@10 | MRR | NDCG@1 | NDCG@5 | NDCG@10 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| BM25 / text | 0.543 | 0.324 | 0.263 | 0.223 | 0.259 | 0.634 | 0.502 | 0.483 | 0.465 |
| Graph | 0.571 | 0.476 | 0.429 | 0.386 | 0.244 | 0.600 | 0.571 | 0.585 | 0.571 |
| Hybrid | 0.800 | 0.486 | 0.417 | 0.340 | 0.297 | 0.820 | 0.776 | 0.687 | 0.649 |

Best by NDCG@10: **Hybrid** (0.649).

## 2-3. How much did Hybrid improve, and what did Graph contribute?

- **Hybrid vs BM25**: NDCG@10 +0.1831, MRR +0.1856, P@1 +0.2571
- **Hybrid vs Graph**: NDCG@10 +0.0772, MRR +0.2198, P@1 +0.2286
- **Graph vs BM25**: NDCG@10 +0.1059, MRR -0.0342, P@1 +0.0286

## 4. Which ranking component mattered most?

| Variant | NDCG@10 | Δ vs full | MRR | P@1 |
| --- | ---: | ---: | ---: | ---: |
| full | 0.6486 | +0.0000 | 0.8198 | 0.8000 |
| no_graph | 0.6486 | +0.0000 | 0.8198 | 0.8000 |
| no_exact_identifier | 0.6756 | +0.0270 | 0.8198 | 0.8000 |
| no_entity_match | 0.6486 | +0.0000 | 0.8198 | 0.8000 |
| no_source_weight | 0.7233 | +0.0748 | 0.8491 | 0.7714 |

No component removal reduced NDCG@10. On this benchmark the ranking components are not separable by these cases.

## 5. Which queries failed?

7 of 35 scored cases missed at rank 1:

- `name-002` — MRR 0.333, NDCG@10 0.478
- `cmd-001` — MRR 0.023, NDCG@10 0.000
- `cmd-003` — MRR 0.111, NDCG@10 0.083
- `lolbas-001` — MRR 0.062, NDCG@10 0.000
- `lolbas-002` — MRR 0.143, NDCG@10 0.420
- `lolbas-003` — MRR 0.009, NDCG@10 0.000
- `unresolved-002` — MRR 0.011, NDCG@10 0.000

1 case(s) were skipped for metrics because the corpus grounds no relevant record for them:

- `tactic-001` — corpus grounds no relevant record for this case

## 6. Were unresolved and ambiguous cases handled safely?

16 of 16 security expectations held.

| Check | Identifier | Result | Detail |
| --- | --- | --- | --- |
| unresolved_seed_reported | `T1562` | pass | seed status=unresolved |
| no_fabricated_technique_node | `T1562` | pass | no Technique node carries this identifier |
| no_fabricated_graph_evidence | `T1562` | pass | 0 items carried graph evidence |
| text_evidence_still_available | `T1562` | pass | 10 items returned via text |
| unresolved_seed_reported | `T1562.001` | pass | seed status=unresolved |
| no_fabricated_technique_node | `T1562.001` | pass | no Technique node carries this identifier |
| no_fabricated_graph_evidence | `T1562.001` | pass | 0 items carried graph evidence |
| text_evidence_still_available | `T1562.001` | pass | 10 items returned via text |
| missing_tactic_unresolved | `TA0011` | pass | seed status=unresolved |
| no_tactic_nodes_fabricated | `TA0011` | pass | 0 Tactic nodes in graph |
| no_belongs_to_edges_fabricated | `TA0011` | pass | 0 BELONGS_TO edges in graph |
| ambiguity_reported | `M1013` | pass | seed status=ambiguous |
| all_candidates_preserved | `M1013` | pass | candidates=['mitre:Mitigation:enterprise:M1013', 'mitre:Mitigation:mobile:M1013'] |
| no_domain_collapsed | `M1013` | pass | domains=['enterprise', 'mobile'] |
| no_arbitrary_selection | `M1013` | pass | 0 graph candidates from an ambiguous seed |
| no_fabricated_uses_field_edges | `USES_FIELD` | pass | 0 USES_FIELD edges; corpus states none |

## 7. Corpus limitations affecting these results

- **Ground-truth bias.** For technique cases the grade-2 set is *records whose metadata cites the technique* — the same linkage the Stage-12 graph is built from. Graph and hybrid retrieval therefore hold a structural advantage on those categories. ECS, LOLBAS and technique-name cases are grounded on identity instead and are available to lexical retrieval alone.
- **Recall is bounded by design.** Popular techniques have hundreds of citing records, so Recall@10 cannot exceed roughly 0.04 for them. Precision and NDCG are the informative measures here.
- **ATT&CK version skew.** `T1562` and `T1562.001` are cited by rules but absent from the MITRE snapshot, so they can never resolve to a node.
- **No tactic objects.** The snapshot contains none, so `TA0011` grounds nothing and its case is skipped for metrics by design.
- **`M1013` is duplicated** across the enterprise and mobile domains and must stay ambiguous.
- **No `USES_FIELD` edges exist**, so ECS cases are answerable by text only.

## Performance

- Index build: 6.46 s (once per run)
- Total run: 13.58 s over 108 queries
- Latency: mean 17.6 ms, median 10.6 ms, p95 45.9 ms

## Corpus integrity

| Dataset | SHA-256 |
| --- | --- |
| ecs | `946afcf66eba0279611723e07a119fdf6ddbeaa250b9cb3857caaa792e9e3cfc` |
| elastic | `b5dbfe5fa93958cfbb0e4e4699a653b95e7474a0dda9ae4697c09e387878abba` |
| lolbas | `6feea579ce4db6ccd610a74d8bb069a53f2fdcecdcc51bb78f64bc4687421f4f` |
| mitre | `7e87c0d1241408274ed483613f6d836f93f0b5025031ffc7ae9aaf6afca128dd` |
| sigma | `4b22114d0286449830467802c3315fe84b4d5904d57cad1d6f52d17d362f6303` |

Digests are taken before and after the run and compared; a change aborts the run.

