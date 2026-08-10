"""Evaluation.

Deterministic evaluation of retrieval and ranking quality.

This layer measures Stage-13. It is **not** part of the production retrieval
path and never runs as a side effect of retrieval: a caller invokes
:class:`EvaluationRunner` explicitly.

Everything is deterministic. The benchmark is a fixed, ordered set of security
queries whose anchors were verified against the corpus; ground truth is derived
from explicit dataset metadata rather than asserted by hand or scored by a
model; and no sampling or randomness exists anywhere. Two runs on one corpus
produce identical rankings, metrics and findings.

No language model is involved in judging relevance. That is deliberate — an LLM
judge would make the measurement non-reproducible and would be evaluating the
thing this stage is meant to hold fixed.

Typical use::

    runner = EvaluationRunner(corpus_root)
    report = runner.run()
    ReportWriter().write_json(report, json_path)
"""

from __future__ import annotations

from .ablation import AblationHarness, variant_weights
from .benchmark import BENCHMARK_CASES, BENCHMARK_VERSION, cases_by_id
from .exceptions import BenchmarkGroundingError, CorpusModifiedError, EvaluationError
from .ground_truth import GroundTruthBuilder, GroundTruthSet
from .metrics import (
    dcg_at_k,
    dedupe,
    ideal_dcg_at_k,
    ndcg_at_k,
    precision_at_k,
    recall_at_k,
    reciprocal_rank,
)
from .models import (
    AblationReport,
    BenchmarkReport,
    CaseOutcome,
    EvaluationCase,
    GroundTruth,
    Judgment,
    LatencyStatistics,
    MetricScores,
    ModeReport,
    SecurityFinding,
    mean_scores,
)
from .report import ReportWriter, default_result_paths
from .runner import K_VALUES, MODE_ORDER, RETRIEVAL_DEPTH, EvaluationRunner
from .security_checks import SecurityEvaluator
from .types import AblationVariant, CaseCategory, GroundTruthRule, Relevance

__all__ = [
    "BENCHMARK_CASES",
    "BENCHMARK_VERSION",
    "K_VALUES",
    "MODE_ORDER",
    "RETRIEVAL_DEPTH",
    "AblationHarness",
    "AblationReport",
    "AblationVariant",
    "BenchmarkGroundingError",
    "BenchmarkReport",
    "CaseCategory",
    "CaseOutcome",
    "CorpusModifiedError",
    "EvaluationCase",
    "EvaluationError",
    "EvaluationRunner",
    "GroundTruth",
    "GroundTruthBuilder",
    "GroundTruthRule",
    "GroundTruthSet",
    "Judgment",
    "LatencyStatistics",
    "MetricScores",
    "ModeReport",
    "Relevance",
    "ReportWriter",
    "SecurityEvaluator",
    "SecurityFinding",
    "cases_by_id",
    "dcg_at_k",
    "dedupe",
    "default_result_paths",
    "ideal_dcg_at_k",
    "mean_scores",
    "ndcg_at_k",
    "precision_at_k",
    "recall_at_k",
    "reciprocal_rank",
]
