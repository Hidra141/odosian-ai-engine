"""Evidence conversion.

Turns the objects the upstream stages produced into context items, carrying
their provenance forward intact.

Nothing is resolved, re-ranked or re-interpreted here. A retrieval item's score
is copied, not recomputed; a graph path is copied, not rebuilt; an identifier
that Stage-13 reported unresolved becomes an item that *says* it is unresolved,
never one that quietly reads as established.

Credential-looking substrings are redacted as text is copied. That is the one
transformation this module performs, and it is announced: every redaction raises
a warning naming the item it touched.
"""

from __future__ import annotations

import re
from collections.abc import Iterator, Sequence
from dataclasses import dataclass
from typing import Final, final

from src.entities.models import ExtractedEntities
from src.graphrag.models import RetrievalItem, RetrievalResult
from src.graphrag.types import RetrievalMethod
from src.mapping.models import MappedEntities
from src.mapping.types import MappingStatus

from .models import ContextItem, ContextWarning, GraphTrace, ItemProvenance, RuleContext
from .types import (
    EvidenceKind,
    EvidencePriority,
    EvidenceStatus,
    SectionName,
    WarningCode,
)

_REDACTION: Final[str] = "[REDACTED]"

_CREDENTIAL_PATTERNS: Final[tuple[tuple[str, re.Pattern[str]], ...]] = (
    (
        "assignment",
        re.compile(
            r"(?i)\b(api[_-]?key|apikey|secret|password|passwd|token|bearer|authorization)"
            r"\s*[:=]\s*[\"']?([A-Za-z0-9._\-/+]{8,})[\"']?"
        ),
    ),
    ("aws_access_key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("private_key_block", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
)


def redact(text: str) -> tuple[str, tuple[str, ...]]:
    """Return the text with credential-looking values masked.

    Returns the masked text and the names of the patterns that fired, so the
    caller can warn about exactly what was touched. Only high-confidence
    credential shapes are matched; ordinary prose is left alone.
    """
    found: list[str] = []
    result = text
    for name, pattern in _CREDENTIAL_PATTERNS:
        if pattern.search(result):
            found.append(name)
            result = pattern.sub(
                lambda match: _mask(match),
                result,
            )
    return result, tuple(found)


def _mask(match: re.Match[str]) -> str:
    """Return a match with its secret portion replaced."""
    if match.re.groups >= 2:
        return f"{match.group(1)}={_REDACTION}"
    return _REDACTION


@dataclass(frozen=True, slots=True)
class EvidenceBatch:
    """Items produced from one input, with any warnings they raised."""

    items: tuple[ContextItem, ...] = ()
    warnings: tuple[ContextWarning, ...] = ()


@final
class EvidenceExtractor:
    """Converts upstream objects into context items."""

    __slots__ = ()

    def from_rule(self, rule: RuleContext) -> EvidenceBatch:
        """Return the items describing the rule under consideration."""
        if rule.is_empty:
            return EvidenceBatch()
        items: list[ContextItem] = []
        warnings: list[ContextWarning] = []
        blocks = (
            (EvidenceKind.RULE_TEXT, self._rule_header(rule)),
            (EvidenceKind.RULE_DETECTION, self._rule_detection(rule)),
        )
        for index, (kind, text) in enumerate(block for block in blocks if block[1].strip()):
            item_id = f"{SectionName.RULE.value}:{index:04d}"
            safe, fired = redact(text)
            if fired:
                warnings.append(
                    ContextWarning(
                        code=WarningCode.CREDENTIAL_REDACTED,
                        detail=f"redacted {', '.join(fired)} in rule text",
                        item_id=item_id,
                        section=SectionName.RULE,
                    )
                )
            items.append(
                ContextItem(
                    item_id=item_id,
                    section=SectionName.RULE,
                    kind=kind,
                    text=safe,
                    evidence_status=EvidenceStatus.NOT_APPLICABLE,
                    priority=EvidencePriority.EXACT_IDENTIFIER,
                    provenance=ItemProvenance(origin="caller:rule"),
                )
            )
        return EvidenceBatch(tuple(items), tuple(warnings))

    def from_entities(self, entities: ExtractedEntities | None) -> EvidenceBatch:
        """Return one item per extracted entity, in extraction order."""
        if entities is None or not len(entities):
            return EvidenceBatch()
        items = [
            ContextItem(
                item_id=f"{SectionName.ENTITIES.value}:{index:04d}",
                section=SectionName.ENTITIES,
                kind=EvidenceKind.EXTRACTED_ENTITY,
                text=(
                    f"{entity.entity_type.value}={entity.value!r} "
                    f"field={entity.source_field or '-'} at {entity.location}"
                ),
                relevance_score=entity.confidence,
                evidence_status=EvidenceStatus.NOT_APPLICABLE,
                priority=EvidencePriority.ENTITY_MATCH,
                provenance=ItemProvenance(origin=f"stage09:{entity.extractor}"),
                metadata={
                    "entity_type": entity.entity_type.value,
                    "source_field": entity.source_field,
                    "location": entity.location,
                },
            )
            for index, entity in enumerate(entities)
        ]
        return EvidenceBatch(tuple(items))

    def from_mappings(self, mappings: MappedEntities | None) -> EvidenceBatch:
        """Return one item per mapped entity, preserving unresolved status."""
        if mappings is None or not len(mappings):
            return EvidenceBatch()
        items: list[ContextItem] = []
        warnings: list[ContextWarning] = []
        for index, mapped in enumerate(mappings):
            item_id = f"{SectionName.MAPPINGS.value}:{index:04d}"
            status = self._mapping_status(mapped.status)
            canonical = mapped.canonical_id or mapped.canonical_value or "-"
            text = (
                f"{mapped.canonical_type.value}: {canonical} "
                f"(original={mapped.original.value!r}, status={mapped.status.value}, "
                f"method={mapped.method.value})"
            )
            if mapped.note:
                text = f"{text} note={mapped.note}"
            if status is EvidenceStatus.UNRESOLVED:
                warnings.append(
                    ContextWarning(
                        code=WarningCode.UNRESOLVED_REFERENCE,
                        detail=(
                            f"{mapped.original.value!r} has no canonical form "
                            f"({mapped.note or 'no reason recorded'})"
                        ),
                        item_id=item_id,
                        section=SectionName.MAPPINGS,
                    )
                )
            items.append(
                ContextItem(
                    item_id=item_id,
                    section=SectionName.MAPPINGS,
                    kind=EvidenceKind.MAPPED_ENTITY,
                    text=text,
                    relevance_score=mapped.confidence,
                    evidence_status=status,
                    priority=EvidencePriority.ENTITY_MATCH,
                    provenance=ItemProvenance(origin=f"stage10:{mapped.mapper}"),
                    metadata={
                        "canonical_type": mapped.canonical_type.value,
                        "mapping_status": mapped.status.value,
                        "mapping_method": mapped.method.value,
                    },
                )
            )
        return EvidenceBatch(tuple(items), tuple(warnings))

    def from_retrieval(self, result: RetrievalResult | None) -> EvidenceBatch:
        """Return one item per retrieved chunk, carrying its provenance forward."""
        if result is None:
            return EvidenceBatch()
        if not result.items:
            return EvidenceBatch(
                warnings=(
                    ContextWarning(
                        code=WarningCode.EMPTY_RETRIEVAL,
                        detail="retrieval returned no items; context carries no retrieved evidence",
                    ),
                )
            )
        items: list[ContextItem] = []
        warnings: list[ContextWarning] = []
        for rank, retrieved in enumerate(result.items):
            section = self._section_for(retrieved)
            item_id = f"{section.value}:{rank:04d}"
            safe, fired = redact(retrieved.chunk.text)
            if fired:
                warnings.append(
                    ContextWarning(
                        code=WarningCode.CREDENTIAL_REDACTED,
                        detail=f"redacted {', '.join(fired)} in retrieved chunk",
                        item_id=item_id,
                        section=section,
                    )
                )
            items.append(
                ContextItem(
                    item_id=item_id,
                    section=section,
                    kind=(
                        EvidenceKind.RETRIEVED_GRAPH
                        if section is SectionName.GRAPH
                        else EvidenceKind.RETRIEVED_TEXT
                    ),
                    text=safe,
                    source=retrieved.chunk.source,
                    source_id=retrieved.chunk.source_id,
                    relevance_score=retrieved.score.total,
                    evidence_status=EvidenceStatus.RESOLVED,
                    priority=self._priority(retrieved),
                    retrieval_rank=rank,
                    provenance=self._provenance(retrieved),
                    metadata={
                        "chunk_section": retrieved.chunk.section.value,
                        "score_exact_identifier": f"{retrieved.score.exact_identifier:.3f}",
                        "score_graph": f"{retrieved.score.graph:.3f}",
                        "score_lexical": f"{retrieved.score.lexical:.3f}",
                    },
                )
            )
        return EvidenceBatch(tuple(items), tuple(warnings))

    def from_seeds(self, result: RetrievalResult | None) -> EvidenceBatch:
        """Return one item per query identifier, including those that failed.

        This is where the corpus's honesty reaches the context. An identifier
        the graph could not resolve appears as an unresolved item, and one that
        matched several nodes appears with every candidate listed.

        A deprecated identifier followed to ATT&CK's successor appears as a
        *redirected* item naming both. It is neither of the two failures — a
        record was reached — and it is not the success either, because the rule
        never wrote the identifier that reached it. Reporting it as resolved
        would tell the model the rule cited a technique it did not cite.
        """
        if result is None or not result.seeds:
            return EvidenceBatch()
        items: list[ContextItem] = []
        warnings: list[ContextWarning] = []
        for index, seed in enumerate(result.seeds):
            item_id = f"{SectionName.KNOWLEDGE.value}:{index:04d}"
            status = self._seed_status(seed.status)
            candidates = ", ".join(seed.node_ids) if seed.node_ids else "none"
            via = f" -> {seed.resolved_value}" if seed.resolved_value else ""
            text = (
                f"identifier {seed.value}{via}: {seed.status} "
                f"(candidates: {candidates})"
                + (f" — {seed.note}" if seed.note else "")
            )
            if status is EvidenceStatus.REDIRECTED:
                warnings.append(
                    ContextWarning(
                        code=WarningCode.REDIRECTED_REFERENCE,
                        detail=(
                            f"{seed.value} is deprecated; ATT&CK revoked it in favour of "
                            f"{seed.resolved_value}, which the corpus holds"
                        ),
                        item_id=item_id,
                        section=SectionName.KNOWLEDGE,
                    )
                )
            elif status is EvidenceStatus.UNRESOLVED:
                warnings.append(
                    ContextWarning(
                        code=WarningCode.UNRESOLVED_REFERENCE,
                        detail=f"{seed.value} matched no knowledge record",
                        item_id=item_id,
                        section=SectionName.KNOWLEDGE,
                    )
                )
            elif status is EvidenceStatus.AMBIGUOUS:
                warnings.append(
                    ContextWarning(
                        code=WarningCode.AMBIGUOUS_REFERENCE,
                        detail=(
                            f"{seed.value} matched {len(seed.node_ids)} records; "
                            "no candidate was selected"
                        ),
                        item_id=item_id,
                        section=SectionName.KNOWLEDGE,
                    )
                )
            items.append(
                ContextItem(
                    item_id=item_id,
                    section=SectionName.KNOWLEDGE,
                    kind=EvidenceKind.SEED_RESOLUTION,
                    text=text,
                    evidence_status=status,
                    priority=EvidencePriority.EXACT_IDENTIFIER,
                    provenance=ItemProvenance(
                        origin="stage13:seed",
                        matched_entities=(seed.value,),
                    ),
                    metadata={
                        "identifier": seed.value,
                        "status": seed.status,
                        "candidate_count": str(len(seed.node_ids)),
                        "candidates": ",".join(seed.node_ids),
                        "resolved_identifier": seed.resolved_value or "",
                    },
                )
            )
        return EvidenceBatch(tuple(items), tuple(warnings))

    def from_references(self, rule: RuleContext) -> EvidenceBatch:
        """Return one item per reference the rule itself states.

        Only the caller's own references. Nothing is harvested from retrieved
        text, because a URL appearing in a knowledge record is that record's
        citation, not this rule's.
        """
        items = [
            ContextItem(
                item_id=f"{SectionName.REFERENCES.value}:{index:04d}",
                section=SectionName.REFERENCES,
                kind=EvidenceKind.REFERENCE,
                text=reference,
                evidence_status=EvidenceStatus.NOT_APPLICABLE,
                priority=EvidencePriority.LEXICAL,
                provenance=ItemProvenance(origin="caller:rule.references"),
            )
            for index, reference in enumerate(rule.references)
        ]
        return EvidenceBatch(tuple(items))

    def _section_for(self, retrieved: RetrievalItem) -> SectionName:
        """Return the section a retrieved item belongs in.

        Graph involvement decides: an item traversal reached belongs with the
        graph evidence even when lexical search also found it, because its
        distinguishing feature is the path that justifies it.
        """
        if RetrievalMethod.GRAPH in retrieved.methods:
            return SectionName.GRAPH
        return SectionName.RETRIEVAL

    def _priority(self, retrieved: RetrievalItem) -> EvidencePriority:
        """Return the ordering class implied by an item's own score components."""
        if retrieved.score.exact_identifier > 0.0:
            return EvidencePriority.EXACT_IDENTIFIER
        if retrieved.score.graph > 0.0:
            return EvidencePriority.GRAPH
        if retrieved.score.entity_match > 0.0:
            return EvidencePriority.ENTITY_MATCH
        return EvidencePriority.LEXICAL

    def _provenance(self, retrieved: RetrievalItem) -> ItemProvenance:
        """Carry a retrieval item's provenance across without loss."""
        provenance = retrieved.provenance
        paths = tuple(
            tuple(
                GraphTrace(
                    start_id=step.start_id,
                    relationship_type=step.relationship_type,
                    end_id=step.end_id,
                    direction=step.direction,
                    hops=index + 1,
                )
                for index, step in enumerate(path)
            )
            for path in provenance.graph_paths
        )
        hops = min(
            (
                evidence.hops
                for evidence in provenance.evidence
                if evidence.method is RetrievalMethod.GRAPH
            ),
            default=None,
        )
        return ItemProvenance(
            source=provenance.source,
            source_id=provenance.source_id,
            parent_record_id=provenance.parent_record_id,
            chunk_id=provenance.chunk_id,
            dataset_location=provenance.location,
            retrieval_methods=tuple(method.value for method in provenance.methods),
            matched_terms=provenance.matched_terms,
            matched_entities=provenance.matched_entities,
            graph_paths=paths,
            hops=hops,
            origin="stage13:retrieval",
        )

    def _mapping_status(self, status: MappingStatus) -> EvidenceStatus:
        """Translate a Stage-10 mapping status into an evidence status."""
        if status is MappingStatus.UNRESOLVED:
            return EvidenceStatus.UNRESOLVED
        return EvidenceStatus.RESOLVED

    def _seed_status(self, status: str) -> EvidenceStatus:
        """Translate a Stage-13 seed status into an evidence status."""
        token = status.strip().lower()
        if token == "resolved":
            return EvidenceStatus.RESOLVED
        if token == "ambiguous":
            return EvidenceStatus.AMBIGUOUS
        if token == "redirected":
            return EvidenceStatus.REDIRECTED
        return EvidenceStatus.UNRESOLVED

    def _rule_header(self, rule: RuleContext) -> str:
        """Return the rule's descriptive block."""
        lines = [line for line in (
            f"Title: {rule.title}" if rule.title else "",
            f"Identifier: {rule.identifier}" if rule.identifier else "",
            f"Format: {rule.rule_format}" if rule.rule_format else "",
            f"Language: {rule.language}" if rule.language else "",
            f"Log source: {rule.log_source}" if rule.log_source else "",
            f"Tags: {', '.join(rule.tags)}" if rule.tags else "",
            f"False positives: {'; '.join(rule.false_positives)}" if rule.false_positives else "",
        ) if line]
        return "\n".join(lines)

    def _rule_detection(self, rule: RuleContext) -> str:
        """Return the rule's detection block."""
        lines = [line for line in (
            f"Query:\n{rule.query}" if rule.query else "",
            f"Condition: {rule.condition}" if rule.condition else "",
        ) if line]
        if not lines and rule.raw_text:
            return rule.raw_text
        return "\n".join(lines)


def iter_batches(batches: Sequence[EvidenceBatch]) -> Iterator[ContextItem]:
    """Yield the items of several batches in order."""
    for batch in batches:
        yield from batch.items
