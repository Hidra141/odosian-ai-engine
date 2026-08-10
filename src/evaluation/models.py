"""Evaluation models.

Cases, judgments, per-case outcomes and the assembled report.

Evaluation is at *record* granularity. Retrieval returns chunks, and a long
record can produce many of them, so a ranked chunk list is collapsed to its
parent records — preserving order, keeping the first appearance — before any
metric is computed. Without that, one 132-chunk Sigma rule could fill the whole
top-10 and precision would measure chunking rather than retrieval.
"""

from __future__ import annotations

from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from types import MappingProxyType

from src.knowledge.models.types import KnowledgeSource

from .types import AblationVariant, CaseCategory, GroundTruthRule


@dataclass(frozen=True, slots=True)
class EvaluationCase:
    """One benchmark question, and how its ground truth is derived."""

    case_id: str
    query_text: str
    category: CaseCategory
    rule: GroundTruthRule
    anchors: tuple[str, ...] = ()
    entity_ids: tuple[str, ...] = ()
    canonical_fields: tuple[str, ...] = ()
    expected_sources: tuple[KnowledgeSource, ...] = ()
    notes: str = ""

    @property
    def is_security_case(self) -> bool:
        """Return whether this case exists to test a corpus limitation."""
        return self.category in (
            CaseCategory.UNRESOLVED_REFERENCE,
            CaseCategory.MISSING_TACTIC,
            CaseCategory.AMBIGUOUS_REFERENCE,
        )


@dataclass(frozen=True, slots=True)
class Judgment:
    """One graded relevance judgment, with the field that justifies it."""

    record_id: str
    grade: int
    source: KnowledgeSource
    justification: str

    def __str__(self) -> str:
        """Return the judgment rendered for a report line."""
        return f"{self.record_id}={self.grade} ({self.justification})"


@dataclass(frozen=True, slots=True)
class GroundTruth:
    """Every judgment for one case."""

    case_id: str
    judgments: tuple[Judgment, ...] = ()

    def __len__(self) -> int:
        """Return how many records were judged."""
        return len(self.judgments)

    @property
    def is_empty(self) -> bool:
        """Return whether the corpus grounds nothing for this case."""
        return not self.judgments

    @property
    def grades(self) -> Mapping[str, int]:
        """Return record id to grade."""
        return MappingProxyType({item.record_id: item.grade for item in self.judgments})

    @property
    def relevant_ids(self) -> frozenset[str]:
        """Return the records graded at least partially relevant."""
        return frozenset(item.record_id for item in self.judgments if item.grade > 0)


@dataclass(frozen=True, slots=True)
class MetricScores:
    """The metric values for one case or one aggregate, by cutoff."""

    precision: Mapping[int, float] = field(default_factory=dict)
    recall: Mapping[int, float] = field(default_factory=dict)
    ndcg: Mapping[int, float] = field(default_factory=dict)
    mrr: float = 0.0

    def as_mapping(self) -> Mapping[str, object]:
        """Return the scores in a JSON-friendly shape."""
        return {
            "precision": {str(k): round(v, 6) for k, v in sorted(self.precision.items())},
            "recall": {str(k): round(v, 6) for k, v in sorted(self.recall.items())},
            "ndcg": {str(k): round(v, 6) for k, v in sorted(self.ndcg.items())},
            "mrr": round(self.mrr, 6),
        }


@dataclass(frozen=True, slots=True)
class CaseOutcome:
    """What one mode produced for one case."""

    case_id: str
    mode: str
    ranked_records: tuple[str, ...] = ()
    scores: MetricScores = field(default_factory=MetricScores)
    retrieved_chunks: int = 0
    latency_ms: float = 0.0
    skipped: bool = False
    skip_reason: str = ""
    unresolved_seeds: tuple[str, ...] = ()
    ambiguous_seeds: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class ModeReport:
    """Aggregate metrics for one retrieval mode."""

    mode: str
    aggregate: MetricScores = field(default_factory=MetricScores)
    cases_scored: int = 0
    cases_skipped: int = 0
    outcomes: tuple[CaseOutcome, ...] = ()

    def by_category(self, cases: Mapping[str, EvaluationCase]) -> Mapping[str, MetricScores]:
        """Return the aggregate per case category, for bias inspection."""
        grouped: dict[str, list[CaseOutcome]] = {}
        for outcome in self.outcomes:
            case = cases.get(outcome.case_id)
            if case is None or outcome.skipped:
                continue
            grouped.setdefault(case.category.value, []).append(outcome)
        return MappingProxyType(
            {key: _mean_scores([item.scores for item in value]) for key, value in grouped.items()}
        )


@dataclass(frozen=True, slots=True)
class AblationReport:
    """Aggregate metrics for one ranking variant."""

    variant: AblationVariant
    aggregate: MetricScores = field(default_factory=MetricScores)
    cases_scored: int = 0


@dataclass(frozen=True, slots=True)
class SecurityFinding:
    """The outcome of one security-specific expectation."""

    check: str
    identifier: str
    passed: bool
    detail: str = ""

    def __str__(self) -> str:
        """Return the finding rendered for a report line."""
        return f"[{'ok' if self.passed else 'FAIL'}] {self.check}({self.identifier}): {self.detail}"


@dataclass(frozen=True, slots=True)
class LatencyStatistics:
    """Timing observed during a run."""

    index_build_seconds: float = 0.0
    total_seconds: float = 0.0
    queries: int = 0
    mean_ms: float = 0.0
    median_ms: float = 0.0
    p95_ms: float = 0.0


@dataclass(frozen=True, slots=True)
class BenchmarkReport:
    """Everything one evaluation run produced."""

    benchmark_version: str
    corpus_digests: Mapping[str, str] = field(default_factory=dict)
    cases: int = 0
    judgments: int = 0
    k_values: tuple[int, ...] = ()
    modes: tuple[ModeReport, ...] = ()
    ablations: tuple[AblationReport, ...] = ()
    security: tuple[SecurityFinding, ...] = ()
    latency: LatencyStatistics = field(default_factory=LatencyStatistics)
    skipped: tuple[tuple[str, str], ...] = ()

    def mode(self, name: str) -> ModeReport | None:
        """Return one mode's report by name."""
        for item in self.modes:
            if item.mode == name:
                return item
        return None

    def __iter__(self) -> Iterator[ModeReport]:
        """Iterate the mode reports."""
        return iter(self.modes)


def _mean_scores(scores: Sequence[MetricScores]) -> MetricScores:
    """Return the arithmetic mean of several metric score sets."""
    if not scores:
        return MetricScores()
    cutoffs = sorted({k for item in scores for k in item.precision})
    return MetricScores(
        precision={k: _mean([item.precision.get(k, 0.0) for item in scores]) for k in cutoffs},
        recall={k: _mean([item.recall.get(k, 0.0) for item in scores]) for k in cutoffs},
        ndcg={k: _mean([item.ndcg.get(k, 0.0) for item in scores]) for k in cutoffs},
        mrr=_mean([item.mrr for item in scores]),
    )


def _mean(values: Sequence[float]) -> float:
    """Return the arithmetic mean, or zero for an empty sequence."""
    return sum(values) / len(values) if values else 0.0


mean_scores = _mean_scores
