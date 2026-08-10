"""Ground truth derivation.

Builds graded judgments for a case by reading the corpus, never by asking a
model and never by hand-asserting a record id.

Each rule reads one explicit metadata field, so every judgment carries the
justification that produced it and the whole set can be re-derived identically
on any machine. Iteration follows file order, so the judgment sequence is stable.

**A known bias, stated rather than hidden.** For technique cases the grade-2 set
is "records whose metadata cites this technique" — the same linkage the Stage-12
graph is built from. Graph and hybrid retrieval therefore have a structural
advantage on those cases, because ground truth and graph edges are drawn from
one field. The benchmark counters this with ECS and LOLBAS cases, whose ground
truth is identity-based and available to lexical retrieval alone, and results are
reported per category so the effect stays visible.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from typing import final

from src.knowledge.models.records import KnowledgeRecord
from src.knowledge.models.types import KnowledgeSource
from src.knowledge.repository.jsonl_repository import JsonlKnowledgeRepository

from .exceptions import BenchmarkGroundingError
from .models import EvaluationCase, GroundTruth, Judgment
from .types import GroundTruthRule, Relevance


@final
class GroundTruthBuilder:
    """Derives judgments for benchmark cases from the corpus."""

    __slots__ = ("_repository", "_mitre_by_id", "_citations", "_ecs_by_field", "_lolbas_by_binary")

    def __init__(self, repository: JsonlKnowledgeRepository) -> None:
        """Index the corpus once for every rule the benchmark uses."""
        self._repository = repository
        self._mitre_by_id: dict[str, list[KnowledgeRecord]] = {}
        self._citations: dict[str, list[tuple[KnowledgeRecord, str]]] = {}
        self._ecs_by_field: dict[str, KnowledgeRecord] = {}
        self._lolbas_by_binary: dict[str, list[KnowledgeRecord]] = {}
        self._index()

    def build(self, case: EvaluationCase) -> GroundTruth:
        """Return the judgments a case's rule derives from the corpus."""
        rule = case.rule
        if rule is GroundTruthRule.NONE_EXPECTED:
            return GroundTruth(case_id=case.case_id)
        if rule is GroundTruthRule.ATTACK_TECHNIQUE:
            return self._attack(case)
        if rule is GroundTruthRule.TECHNIQUE_NAME:
            return self._by_name(case)
        if rule is GroundTruthRule.ECS_FIELD:
            return self._ecs(case)
        if rule is GroundTruthRule.LOLBAS_BINARY:
            return self._lolbas(case)
        if rule is GroundTruthRule.CITING_RECORDS_ONLY:
            return self._citing_only(case)
        if rule is GroundTruthRule.ALL_CANDIDATES:
            return self._all_candidates(case)
        raise BenchmarkGroundingError(case.case_id, f"unknown rule {rule.value!r}")

    def _index(self) -> None:
        """Build the lookup tables every rule reads."""
        for record in self._repository.iterate_source(KnowledgeSource.MITRE):
            key = record.metadata_str("techniqueId") or record.metadata_str("id")
            if key:
                self._mitre_by_id.setdefault(key.upper(), []).append(record)

        for record in self._repository.iterate_source(KnowledgeSource.SIGMA):
            for value in record.metadata_value("mitreTechniques") or ():
                if isinstance(value, str):
                    self._cite(value, record, "sigma.mitreTechniques")
        for record in self._repository.iterate_source(KnowledgeSource.ELASTIC):
            for entry in record.metadata_value("mitre") or ():
                if isinstance(entry, dict) and isinstance(entry.get("techniqueId"), str):
                    self._cite(entry["techniqueId"], record, "elastic.mitre.techniqueId")
        for record in self._repository.iterate_source(KnowledgeSource.LOLBAS):
            value = record.metadata_str("mitreTechnique")
            if value:
                self._cite(value, record, "lolbas.mitreTechnique")
            binary = record.metadata_str("binary")
            if binary:
                self._lolbas_by_binary.setdefault(binary.lower(), []).append(record)

        for record in self._repository.iterate_source(KnowledgeSource.ECS):
            field_name = record.metadata_str("fieldName")
            if field_name:
                self._ecs_by_field[field_name.lower()] = record

    def _cite(self, identifier: str, record: KnowledgeRecord, field: str) -> None:
        """Record that one record cites an identifier."""
        self._citations.setdefault(identifier.strip().upper(), []).append((record, field))

    def _attack(self, case: EvaluationCase) -> GroundTruth:
        """Grade the MITRE record for an identifier, then everything citing it."""
        judgments: list[Judgment] = []
        seen: set[str] = set()
        for anchor in case.anchors:
            key = anchor.strip().upper()
            defined = self._mitre_by_id.get(key, [])
            if not defined:
                raise BenchmarkGroundingError(case.case_id, f"MITRE defines no {anchor!r}")
            for record in defined:
                judgments.extend(
                    self._judge(record, Relevance.HIGHLY_RELEVANT, f"mitre defines {key}", seen)
                )
            for record, field in self._citations.get(key, []):
                judgments.extend(
                    self._judge(record, Relevance.RELEVANT, f"cites {key} via {field}", seen)
                )
            parent = key.split(".")[0] if "." in key else ""
            for record in self._mitre_by_id.get(parent, []):
                judgments.extend(
                    self._judge(record, Relevance.PARTIAL, f"parent technique of {key}", seen)
                )
        return GroundTruth(case_id=case.case_id, judgments=tuple(judgments))

    def _by_name(self, case: EvaluationCase) -> GroundTruth:
        """Grade every MITRE record whose name matches exactly."""
        judgments: list[Judgment] = []
        seen: set[str] = set()
        wanted = {item.strip().lower() for item in case.anchors}
        matched: list[KnowledgeRecord] = []
        for records in self._mitre_by_id.values():
            for record in records:
                name = record.metadata_str("techniqueName") or record.metadata_str("name")
                if name and name.strip().lower() in wanted:
                    matched.append(record)
        if not matched:
            raise BenchmarkGroundingError(case.case_id, f"no MITRE record named {case.anchors}")
        matched.sort(key=lambda item: item.id)
        for record in matched:
            judgments.extend(
                self._judge(record, Relevance.HIGHLY_RELEVANT, "mitre name match", seen)
            )
            key = (record.metadata_str("techniqueId") or record.metadata_str("id") or "").upper()
            for citing, field in self._citations.get(key, []):
                judgments.extend(
                    self._judge(citing, Relevance.PARTIAL, f"cites {key} via {field}", seen)
                )
        return GroundTruth(case_id=case.case_id, judgments=tuple(judgments))

    def _ecs(self, case: EvaluationCase) -> GroundTruth:
        """Grade the ECS record defining a field."""
        judgments: list[Judgment] = []
        seen: set[str] = set()
        for anchor in case.anchors:
            record = self._ecs_by_field.get(anchor.strip().lower())
            if record is None:
                raise BenchmarkGroundingError(case.case_id, f"ECS defines no field {anchor!r}")
            judgments.extend(
                self._judge(record, Relevance.HIGHLY_RELEVANT, "ecs defines field", seen)
            )
        return GroundTruth(case_id=case.case_id, judgments=tuple(judgments))

    def _lolbas(self, case: EvaluationCase) -> GroundTruth:
        """Grade every LOLBAS record for a binary."""
        judgments: list[Judgment] = []
        seen: set[str] = set()
        for anchor in case.anchors:
            records = self._lolbas_by_binary.get(anchor.strip().lower(), [])
            if not records:
                raise BenchmarkGroundingError(case.case_id, f"LOLBAS has no binary {anchor!r}")
            for record in records:
                judgments.extend(
                    self._judge(record, Relevance.HIGHLY_RELEVANT, "lolbas binary match", seen)
                )
        return GroundTruth(case_id=case.case_id, judgments=tuple(judgments))

    def _citing_only(self, case: EvaluationCase) -> GroundTruth:
        """Grade the records citing an identifier the corpus does not define.

        Used where ATT&CK version skew leaves a technique undefined. The citing
        rules are real evidence and remain retrievable; no record is invented to
        stand in for the missing definition.
        """
        judgments: list[Judgment] = []
        seen: set[str] = set()
        for anchor in case.anchors:
            key = anchor.strip().upper()
            if self._mitre_by_id.get(key):
                raise BenchmarkGroundingError(
                    case.case_id, f"{anchor!r} is defined; case assumes it is not"
                )
            for record, field in self._citations.get(key, []):
                judgments.extend(
                    self._judge(record, Relevance.RELEVANT, f"cites undefined {key} via {field}", seen)
                )
        return GroundTruth(case_id=case.case_id, judgments=tuple(judgments))

    def _all_candidates(self, case: EvaluationCase) -> GroundTruth:
        """Grade every record carrying an identifier equally.

        Used for ambiguity. Both candidates are highly relevant and neither is
        preferred, so a retriever that returns either is correct and one that
        silently picks one is not rewarded for it.
        """
        judgments: list[Judgment] = []
        seen: set[str] = set()
        for anchor in case.anchors:
            key = anchor.strip().upper()
            records = self._mitre_by_id.get(key, [])
            if len(records) < 2:
                raise BenchmarkGroundingError(
                    case.case_id, f"{anchor!r} is not ambiguous ({len(records)} records)"
                )
            for record in records:
                domain = record.metadata_str("domain") or "?"
                judgments.extend(
                    self._judge(
                        record, Relevance.HIGHLY_RELEVANT, f"candidate in {domain} domain", seen
                    )
                )
        return GroundTruth(case_id=case.case_id, judgments=tuple(judgments))

    def _judge(
        self,
        record: KnowledgeRecord,
        grade: Relevance,
        justification: str,
        seen: set[str],
    ) -> Iterator[Judgment]:
        """Yield a judgment unless the record already has one.

        The first, highest-grade justification wins, so a record that is both
        the definition and a citation is graded as the definition.
        """
        if record.id in seen:
            return
        seen.add(record.id)
        yield Judgment(
            record_id=record.id,
            grade=int(grade),
            source=record.source,
            justification=justification,
        )


@dataclass(frozen=True, slots=True)
class GroundTruthSet:
    """Every case's ground truth, built once."""

    truths: tuple[GroundTruth, ...] = ()

    @property
    def total_judgments(self) -> int:
        """Return how many judgments the benchmark holds."""
        return sum(len(item) for item in self.truths)

    def of(self, case_id: str) -> GroundTruth | None:
        """Return one case's ground truth."""
        for item in self.truths:
            if item.case_id == case_id:
                return item
        return None
