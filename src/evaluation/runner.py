"""Evaluation runner.

Builds the index once, runs every case through every mode, and assembles the
report.

Nothing here is random and nothing is sampled. Cases run in benchmark order,
modes in a fixed order, and the retrieval depth is constant, so two runs on one
corpus produce byte-identical results.

Retrieval returns chunks; metrics are computed over the *records* those chunks
belong to, deduplicated in rank order. Depth is set well above the largest
cutoff so that collapsing chunks to records still leaves enough distinct records
to fill a top-10.

This layer never runs as part of production retrieval. It is invoked explicitly.
"""

from __future__ import annotations

import hashlib
import statistics
import time
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Final, final

from src.graph.graph_builder import GraphBuilder
from src.graph.models import KnowledgeGraph
from src.graphrag.config import GraphRagSettings
from src.graphrag.models import RetrievalQuery, RetrievalResult
from src.graphrag.retriever import GraphRagRetriever
from src.graphrag.types import RetrievalMode
from src.knowledge.models.types import KnowledgeSource
from src.knowledge.repository.jsonl_repository import JsonlKnowledgeRepository

from .ablation import AblationHarness
from .benchmark import BENCHMARK_CASES, BENCHMARK_VERSION, cases_by_id
from .exceptions import CorpusModifiedError
from .ground_truth import GroundTruthBuilder, GroundTruthSet
from .metrics import ndcg_at_k, precision_at_k, recall_at_k, reciprocal_rank
from .models import (
    AblationReport,
    BenchmarkReport,
    CaseOutcome,
    EvaluationCase,
    GroundTruth,
    LatencyStatistics,
    MetricScores,
    ModeReport,
    mean_scores,
)
from .security_checks import SecurityEvaluator
from .types import AblationVariant

K_VALUES: Final[tuple[int, ...]] = (1, 3, 5, 10)
RETRIEVAL_DEPTH: Final[int] = 120
"""Chunks fetched per query.

Collapsing chunks to records loses positions, so depth must exceed the largest
cutoff by a wide margin. 120 leaves room for a record contributing many chunks
without starving the top-10.
"""

MODE_ORDER: Final[tuple[RetrievalMode, ...]] = (
    RetrievalMode.TEXT,
    RetrievalMode.GRAPH,
    RetrievalMode.HYBRID,
)


@dataclass(frozen=True, slots=True)
class RunInputs:
    """Everything a run needs, built once."""

    repository: JsonlKnowledgeRepository
    graph: KnowledgeGraph
    retriever: GraphRagRetriever
    settings: GraphRagSettings
    index_build_seconds: float


@final
class EvaluationRunner:
    """Runs the benchmark against Stage-13 retrieval."""

    __slots__ = ("_corpus_root", "_settings", "_latencies")

    def __init__(self, corpus_root: Path, settings: GraphRagSettings | None = None) -> None:
        """Hold the corpus location; nothing is read until :meth:`run`."""
        self._corpus_root = corpus_root
        self._settings = settings if settings is not None else GraphRagSettings()
        self._latencies: list[float] = []

    def prepare(self) -> RunInputs:
        """Build the repository, the graph and the retrieval index once."""
        started = time.perf_counter()
        repository = JsonlKnowledgeRepository.from_root(self._corpus_root)
        graph = GraphBuilder.over(repository).build()
        retriever = GraphRagRetriever(repository, graph, self._settings)
        retriever.build_index()
        return RunInputs(
            repository=repository,
            graph=graph,
            retriever=retriever,
            settings=self._settings,
            index_build_seconds=time.perf_counter() - started,
        )

    def run(self) -> BenchmarkReport:
        """Run the whole benchmark and return the report."""
        digests_before = self._digests()
        started = time.perf_counter()
        self._latencies = []

        inputs = self.prepare()
        truths = self._ground_truth(inputs.repository)
        modes = tuple(self._run_mode(inputs, truths, mode) for mode in MODE_ORDER)
        ablations = self._run_ablations(inputs, truths)
        security = SecurityEvaluator(inputs.retriever, inputs.graph).evaluate()

        total = time.perf_counter() - started
        digests_after = self._digests()
        for name, before in digests_before.items():
            after = digests_after[name]
            if before != after:
                raise CorpusModifiedError(self._dataset_path(name), before, after)

        skipped = tuple(
            (outcome.case_id, outcome.skip_reason)
            for report in modes
            for outcome in report.outcomes
            if outcome.skipped and report.mode == RetrievalMode.HYBRID.value
        )
        return BenchmarkReport(
            benchmark_version=BENCHMARK_VERSION,
            corpus_digests=digests_before,
            cases=len(BENCHMARK_CASES),
            judgments=truths.total_judgments,
            k_values=K_VALUES,
            modes=modes,
            ablations=ablations,
            security=security,
            latency=self._latency(inputs.index_build_seconds, total),
            skipped=skipped,
        )

    def _ground_truth(self, repository: JsonlKnowledgeRepository) -> GroundTruthSet:
        """Derive every case's judgments from the corpus."""
        builder = GroundTruthBuilder(repository)
        return GroundTruthSet(tuple(builder.build(case) for case in BENCHMARK_CASES))

    def _run_mode(
        self,
        inputs: RunInputs,
        truths: GroundTruthSet,
        mode: RetrievalMode,
    ) -> ModeReport:
        """Run every case in one retrieval mode."""
        outcomes: list[CaseOutcome] = []
        for case in BENCHMARK_CASES:
            truth = truths.of(case.case_id)
            outcomes.append(self._run_case(inputs, case, truth, mode))
        scored = [item for item in outcomes if not item.skipped]
        return ModeReport(
            mode=mode.value,
            aggregate=mean_scores([item.scores for item in scored]),
            cases_scored=len(scored),
            cases_skipped=len(outcomes) - len(scored),
            outcomes=tuple(outcomes),
        )

    def _run_case(
        self,
        inputs: RunInputs,
        case: EvaluationCase,
        truth: GroundTruth | None,
        mode: RetrievalMode,
    ) -> CaseOutcome:
        """Run one case in one mode and score it."""
        query = self._query(case, mode)
        started = time.perf_counter()
        result = inputs.retriever.retrieve(query)
        latency_ms = (time.perf_counter() - started) * 1000.0
        self._latencies.append(latency_ms)

        ranked = self._records(result)
        unresolved = tuple(item.value for item in result.unresolved_seeds)
        ambiguous = tuple(item.value for item in result.ambiguous_seeds)

        if truth is None or truth.is_empty:
            return CaseOutcome(
                case_id=case.case_id,
                mode=mode.value,
                ranked_records=ranked[:10],
                retrieved_chunks=len(result),
                latency_ms=latency_ms,
                skipped=True,
                skip_reason="corpus grounds no relevant record for this case",
                unresolved_seeds=unresolved,
                ambiguous_seeds=ambiguous,
            )
        return CaseOutcome(
            case_id=case.case_id,
            mode=mode.value,
            ranked_records=ranked[:10],
            scores=self._score(ranked, truth),
            retrieved_chunks=len(result),
            latency_ms=latency_ms,
            unresolved_seeds=unresolved,
            ambiguous_seeds=ambiguous,
        )

    def _query(self, case: EvaluationCase, mode: RetrievalMode) -> RetrievalQuery:
        """Build the retrieval query for a case in one mode."""
        return RetrievalQuery(
            text=case.query_text,
            entity_ids=case.entity_ids,
            canonical_fields=case.canonical_fields,
            max_results=RETRIEVAL_DEPTH,
            mode=mode,
        )

    def _records(self, result: RetrievalResult) -> tuple[str, ...]:
        """Collapse a ranked chunk list to its records, keeping rank order."""
        seen: list[str] = []
        for item in result.items:
            record_id = item.chunk.parent_record_id
            if record_id not in seen:
                seen.append(record_id)
        return tuple(seen)

    def _score(self, ranked: Sequence[str], truth: GroundTruth) -> MetricScores:
        """Compute every metric for one ranked record list."""
        relevant = truth.relevant_ids
        grades = truth.grades
        return MetricScores(
            precision={k: precision_at_k(ranked, relevant, k) for k in K_VALUES},
            recall={k: recall_at_k(ranked, relevant, k) for k in K_VALUES},
            ndcg={k: ndcg_at_k(ranked, grades, k) for k in K_VALUES},
            mrr=reciprocal_rank(ranked, relevant),
        )

    def _run_ablations(
        self,
        inputs: RunInputs,
        truths: GroundTruthSet,
    ) -> tuple[AblationReport, ...]:
        """Re-rank every case under each variant and aggregate."""
        harness = AblationHarness(
            index=inputs.retriever.index,
            graph=inputs.graph,
            base_settings=inputs.settings,
        )
        reports: list[AblationReport] = []
        for variant in AblationVariant:
            retriever = harness.retriever_for(variant)
            scores: list[MetricScores] = []
            for case in BENCHMARK_CASES:
                truth = truths.of(case.case_id)
                if truth is None or truth.is_empty:
                    continue
                result = retriever.retrieve(self._query(case, RetrievalMode.HYBRID))
                scores.append(self._score(self._records(result), truth))
            reports.append(
                AblationReport(
                    variant=variant,
                    aggregate=mean_scores(scores),
                    cases_scored=len(scores),
                )
            )
        return tuple(reports)

    def _latency(self, build_seconds: float, total_seconds: float) -> LatencyStatistics:
        """Summarise the query latencies observed."""
        if not self._latencies:
            return LatencyStatistics(
                index_build_seconds=round(build_seconds, 3),
                total_seconds=round(total_seconds, 3),
            )
        ordered = sorted(self._latencies)
        index = min(len(ordered) - 1, int(len(ordered) * 0.95))
        return LatencyStatistics(
            index_build_seconds=round(build_seconds, 3),
            total_seconds=round(total_seconds, 3),
            queries=len(ordered),
            mean_ms=round(statistics.fmean(ordered), 3),
            median_ms=round(statistics.median(ordered), 3),
            p95_ms=round(ordered[index], 3),
        )

    def _dataset_path(self, source_name: str) -> Path:
        """Return the dataset path of a source."""
        return self._corpus_root / source_name / f"{source_name}.jsonl"

    def _digests(self) -> dict[str, str]:
        """Return the SHA-256 of every dataset, read only."""
        digests: dict[str, str] = {}
        for source in KnowledgeSource:
            path = self._dataset_path(source.value)
            if not path.is_file():
                continue
            hasher = hashlib.sha256()
            with path.open("rb") as handle:
                for block in iter(lambda: handle.read(1 << 20), b""):
                    hasher.update(block)
            digests[source.value] = hasher.hexdigest()
        return digests


def case_index() -> dict[str, EvaluationCase]:
    """Return the benchmark keyed by case id."""
    return cases_by_id()
