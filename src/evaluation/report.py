"""Reporting.

Writes the machine-readable result and the human-readable summary.

The JSON is the record of a run; the Markdown answers the questions the run was
commissioned to answer. Neither claims an improvement the numbers do not show —
the comparison section states the measured deltas and says plainly when they are
small or when a result is shaped by how ground truth was derived.

A timestamp is written into the JSON for provenance but is deliberately excluded
from the reproducibility payload, so two runs can be compared byte for byte.
"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, final

from .benchmark import BENCHMARK_CASES
from .models import BenchmarkReport, ModeReport
from .types import AblationVariant

_MODE_LABELS = {"text": "BM25 / text", "graph": "Graph", "hybrid": "Hybrid"}


@final
class ReportWriter:
    """Serialises a benchmark report."""

    __slots__ = ()

    def to_payload(self, report: BenchmarkReport, *, include_timestamp: bool = True) -> dict[str, Any]:
        """Return the report as a JSON-ready mapping.

        With ``include_timestamp`` false the payload is stable across runs and
        can be compared directly for determinism.
        """
        payload: dict[str, Any] = {
            "benchmark_version": report.benchmark_version,
            "corpus_digests": dict(sorted(report.corpus_digests.items())),
            "cases": report.cases,
            "judgments": report.judgments,
            "k_values": list(report.k_values),
            "modes": {item.mode: self._mode(item) for item in report.modes},
            "ablations": {
                item.variant.value: {
                    "aggregate": item.aggregate.as_mapping(),
                    "cases_scored": item.cases_scored,
                }
                for item in report.ablations
            },
            "security": [
                {
                    "check": item.check,
                    "identifier": item.identifier,
                    "passed": item.passed,
                    "detail": item.detail,
                }
                for item in report.security
            ],
            "latency": {
                "index_build_seconds": report.latency.index_build_seconds,
                "total_seconds": report.latency.total_seconds,
                "queries": report.latency.queries,
                "mean_ms": report.latency.mean_ms,
                "median_ms": report.latency.median_ms,
                "p95_ms": report.latency.p95_ms,
            },
            "skipped": [{"case_id": c, "reason": r} for c, r in report.skipped],
        }
        if include_timestamp:
            payload["generated_at"] = datetime.now(timezone.utc).isoformat()
        return payload

    def reproducible_payload(self, report: BenchmarkReport) -> dict[str, Any]:
        """Return the payload without timing or timestamps, for comparison.

        Latency varies between runs on any machine; excluding it isolates the
        parts that must be identical — rankings, metrics and findings.
        """
        payload = self.to_payload(report, include_timestamp=False)
        payload.pop("latency", None)
        return payload

    def write_json(self, report: BenchmarkReport, path: Path) -> None:
        """Write the machine-readable result."""
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(self.to_payload(report), indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

    def write_markdown(self, report: BenchmarkReport, path: Path) -> None:
        """Write the human-readable summary."""
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(self.to_markdown(report), encoding="utf-8")

    def _mode(self, report: ModeReport) -> dict[str, Any]:
        """Return one mode's section of the payload."""
        return {
            "aggregate": report.aggregate.as_mapping(),
            "cases_scored": report.cases_scored,
            "cases_skipped": report.cases_skipped,
            "per_case": [
                {
                    "case_id": item.case_id,
                    "skipped": item.skipped,
                    "skip_reason": item.skip_reason,
                    "retrieved_chunks": item.retrieved_chunks,
                    "top_records": list(item.ranked_records[:5]),
                    "scores": item.scores.as_mapping(),
                    "unresolved_seeds": list(item.unresolved_seeds),
                    "ambiguous_seeds": list(item.ambiguous_seeds),
                }
                for item in report.outcomes
            ],
        }

    def to_markdown(self, report: BenchmarkReport) -> str:
        """Return the human-readable report."""
        lines: list[str] = []
        add = lines.append
        add("# ODOSIAN Retrieval Evaluation")
        add("")
        add(f"Benchmark `{report.benchmark_version}` — {report.cases} cases, "
            f"{report.judgments} graded judgments, K = {list(report.k_values)}.")
        add("")
        add("Retrieval is evaluated at record granularity: ranked chunks are collapsed to "
            "their parent records, keeping rank order, before any metric is computed.")
        add("")

        add("## 1. Which retrieval mode performed best?")
        add("")
        add("| Mode | P@1 | P@3 | P@5 | P@10 | R@10 | MRR | NDCG@1 | NDCG@5 | NDCG@10 |")
        add("| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |")
        for mode in report.modes:
            a = mode.aggregate
            add(
                f"| {_MODE_LABELS.get(mode.mode, mode.mode)} "
                f"| {a.precision.get(1, 0):.3f} | {a.precision.get(3, 0):.3f} "
                f"| {a.precision.get(5, 0):.3f} | {a.precision.get(10, 0):.3f} "
                f"| {a.recall.get(10, 0):.3f} | {a.mrr:.3f} "
                f"| {a.ndcg.get(1, 0):.3f} | {a.ndcg.get(5, 0):.3f} | {a.ndcg.get(10, 0):.3f} |"
            )
        add("")
        best = max(report.modes, key=lambda item: item.aggregate.ndcg.get(10, 0.0))
        add(f"Best by NDCG@10: **{_MODE_LABELS.get(best.mode, best.mode)}** "
            f"({best.aggregate.ndcg.get(10, 0):.3f}).")
        add("")

        add("## 2-3. How much did Hybrid improve, and what did Graph contribute?")
        add("")
        text = report.mode("text")
        graph = report.mode("graph")
        hybrid = report.mode("hybrid")
        if text and hybrid:
            add(self._delta_line("Hybrid vs BM25", hybrid, text))
        if graph and hybrid:
            add(self._delta_line("Hybrid vs Graph", hybrid, graph))
        if text and graph:
            add(self._delta_line("Graph vs BM25", graph, text))
        add("")

        add("## 4. Which ranking component mattered most?")
        add("")
        add("| Variant | NDCG@10 | Δ vs full | MRR | P@1 |")
        add("| --- | ---: | ---: | ---: | ---: |")
        full = next(
            (item for item in report.ablations if item.variant is AblationVariant.FULL), None
        )
        baseline = full.aggregate.ndcg.get(10, 0.0) if full else 0.0
        for item in report.ablations:
            value = item.aggregate.ndcg.get(10, 0.0)
            delta = value - baseline
            add(
                f"| {item.variant.value} | {value:.4f} | {delta:+.4f} "
                f"| {item.aggregate.mrr:.4f} | {item.aggregate.precision.get(1, 0):.4f} |"
            )
        add("")
        drops = [
            (item.variant.value, baseline - item.aggregate.ndcg.get(10, 0.0))
            for item in report.ablations
            if item.variant is not AblationVariant.FULL
        ]
        drops.sort(key=lambda item: -item[1])
        if drops:
            name, amount = drops[0]
            if amount <= 0.0:
                add("No component removal reduced NDCG@10. On this benchmark the ranking "
                    "components are not separable by these cases.")
            else:
                add(f"Largest degradation: **{name}** (−{amount:.4f} NDCG@10).")
        add("")

        add("## 5. Which queries failed?")
        add("")
        if hybrid:
            failures = [
                item
                for item in hybrid.outcomes
                if not item.skipped and item.scores.precision.get(1, 0.0) == 0.0
            ]
            if not failures:
                add("No case returned an irrelevant record at rank 1 in hybrid mode.")
            else:
                add(f"{len(failures)} of {hybrid.cases_scored} scored cases missed at rank 1:")
                add("")
                for item in failures:
                    add(f"- `{item.case_id}` — MRR {item.scores.mrr:.3f}, "
                        f"NDCG@10 {item.scores.ndcg.get(10, 0):.3f}")
        add("")
        if report.skipped:
            add(f"{len(report.skipped)} case(s) were skipped for metrics because the corpus "
                "grounds no relevant record for them:")
            add("")
            for case_id, reason in report.skipped:
                add(f"- `{case_id}` — {reason}")
        add("")

        add("## 6. Were unresolved and ambiguous cases handled safely?")
        add("")
        passed = sum(1 for item in report.security if item.passed)
        add(f"{passed} of {len(report.security)} security expectations held.")
        add("")
        add("| Check | Identifier | Result | Detail |")
        add("| --- | --- | --- | --- |")
        for item in report.security:
            add(f"| {item.check} | `{item.identifier}` | "
                f"{'pass' if item.passed else '**FAIL**'} | {item.detail} |")
        add("")

        add("## 7. Corpus limitations affecting these results")
        add("")
        add("- **Ground-truth bias.** For technique cases the grade-2 set is *records whose "
            "metadata cites the technique* — the same linkage the Stage-12 graph is built "
            "from. Graph and hybrid retrieval therefore hold a structural advantage on those "
            "categories. ECS, LOLBAS and technique-name cases are grounded on identity "
            "instead and are available to lexical retrieval alone.")
        add("- **Recall is bounded by design.** Popular techniques have hundreds of citing "
            "records, so Recall@10 cannot exceed roughly 0.04 for them. Precision and NDCG "
            "are the informative measures here.")
        add("- **ATT&CK version skew.** `T1562` and `T1562.001` are cited by rules but absent "
            "from the MITRE snapshot, so they can never resolve to a node.")
        add("- **No tactic objects.** The snapshot contains none, so `TA0011` grounds nothing "
            "and its case is skipped for metrics by design.")
        add("- **`M1013` is duplicated** across the enterprise and mobile domains and must "
            "stay ambiguous.")
        add("- **No `USES_FIELD` edges exist**, so ECS cases are answerable by text only.")
        add("")

        add("## Performance")
        add("")
        add(f"- Index build: {report.latency.index_build_seconds:.2f} s (once per run)")
        add(f"- Total run: {report.latency.total_seconds:.2f} s over "
            f"{report.latency.queries} queries")
        add(f"- Latency: mean {report.latency.mean_ms:.1f} ms, "
            f"median {report.latency.median_ms:.1f} ms, p95 {report.latency.p95_ms:.1f} ms")
        add("")
        add("## Corpus integrity")
        add("")
        add("| Dataset | SHA-256 |")
        add("| --- | --- |")
        for name, digest in sorted(report.corpus_digests.items()):
            add(f"| {name} | `{digest}` |")
        add("")
        add("Digests are taken before and after the run and compared; a change aborts the run.")
        add("")
        return "\n".join(lines) + "\n"

    def _delta_line(self, label: str, left: ModeReport, right: ModeReport) -> str:
        """Return one comparison line with measured deltas."""
        parts = []
        for name, getter in (
            ("NDCG@10", lambda m: m.aggregate.ndcg.get(10, 0.0)),
            ("MRR", lambda m: m.aggregate.mrr),
            ("P@1", lambda m: m.aggregate.precision.get(1, 0.0)),
        ):
            delta = getter(left) - getter(right)
            parts.append(f"{name} {delta:+.4f}")
        return f"- **{label}**: " + ", ".join(parts)


def default_result_paths(root: Path) -> tuple[Path, Path]:
    """Return the JSON and Markdown result paths beneath a project root."""
    directory = root / "evaluation" / "results"
    return directory / "retrieval_evaluation.json", directory / "retrieval_evaluation.md"


def case_notes() -> Mapping[str, str]:
    """Return each case's note, for report annotation."""
    return {case.case_id: case.notes for case in BENCHMARK_CASES if case.notes}


def summarise_failures(outcomes: Sequence[Any]) -> tuple[str, ...]:
    """Return the ids of outcomes that found nothing relevant at rank 1."""
    return tuple(
        item.case_id
        for item in outcomes
        if not item.skipped and item.scores.precision.get(1, 0.0) == 0.0
    )
