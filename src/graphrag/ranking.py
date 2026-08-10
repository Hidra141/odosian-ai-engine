"""Ranking.

Scores a candidate against a query, transparently.

The total is a weighted sum of seven components, each normalised to ``[0, 1]``,
with weights that sum to one. Nothing is hidden and nothing is probabilistic:
the same candidate and query always produce the same number, and every number
can be read back as the reason the item is where it is.

    total = 0.30 * exact_identifier
          + 0.20 * entity_match
          + 0.20 * graph
          + 0.15 * lexical
          + 0.07 * source
          + 0.05 * distance
          + 0.03 * section

* **exact_identifier** — the query named an identifier and the chunk carries it.
  Weighted highest because it is a fact rather than a similarity.
* **entity_match** — the chunk's record was reached through an entity the query
  named, whether or not the text repeats it.
* **graph** — the candidate was found by traversal at all.
* **lexical** — BM25, squashed into ``[0, 1]``. A hint, never proof, so it is
  weighted below the two agreement components.
* **source** — the dataset's authority for this query. ECS rises only when the
  query names a field.
* **distance** — decay by hop count, so a seed outranks its neighbour.
* **section** — detection logic outranks a reference list.

Ties break on chunk id, so the order is stable across runs.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Final, final

from .config import GraphRagSettings
from .models import Candidate, RetrievalQuery, RetrievalScore
from .types import MatchKind, RetrievalMethod

_LEXICAL_SATURATION: Final[float] = 12.0
"""BM25 score at which the lexical component is treated as full.

BM25 is unbounded, so it is squashed with ``s / (s + c)``. The constant is the
score at which the component reaches one half; it is a scale choice, documented
here rather than tuned invisibly.
"""

_HOP_DECAY: Final[float] = 0.6
"""Multiplier applied per hop, so a seed scores 1.0, one hop 0.6, two hops 0.36."""


@final
@dataclass(frozen=True, slots=True)
class DeterministicRanker:
    """Scores candidates with documented, reproducible weights."""

    settings: GraphRagSettings

    def score(self, candidate: Candidate, query: RetrievalQuery) -> RetrievalScore:
        """Return the score of one candidate, with every component."""
        weights = self.settings.weights
        names_field = bool(query.canonical_fields)

        exact = self._exact_identifier(candidate)
        entity = self._entity_match(candidate, query)
        graph = self._graph(candidate)
        lexical = self._lexical(candidate)
        distance = self._distance(candidate)
        source = self.settings.source_weight(candidate.chunk.source, query_names_field=names_field)
        section = self.settings.section_weight(candidate.chunk.section)

        total = (
            weights.exact_identifier * exact
            + weights.entity_match * entity
            + weights.graph * graph
            + weights.lexical * lexical
            + weights.source * source
            + weights.distance * distance
            + weights.section * section
        )
        return RetrievalScore(
            total=round(total, 6),
            exact_identifier=exact,
            entity_match=entity,
            lexical=round(lexical, 6),
            graph=graph,
            distance=round(distance, 6),
            source=source,
            section=section,
        )

    def rank(
        self,
        candidates: Sequence[Candidate],
        query: RetrievalQuery,
    ) -> tuple[tuple[Candidate, RetrievalScore], ...]:
        """Return the candidates in rank order, best first."""
        scored = [(candidate, self.score(candidate, query)) for candidate in candidates]
        scored.sort(key=lambda item: (-item[1].total, item[0].chunk.chunk_id))
        return tuple(scored)

    def _exact_identifier(self, candidate: Candidate) -> float:
        """Return 1.0 when a query identifier appears literally in the chunk."""
        for evidence in candidate.evidence:
            if evidence.match_kind is MatchKind.EXACT_IDENTIFIER and evidence.matched_entities:
                return 1.0
        return 0.0

    def _entity_match(self, candidate: Candidate, query: RetrievalQuery) -> float:
        """Return 1.0 when the candidate carries an entity the query named."""
        wanted = {item.strip().lower() for item in query.all_identifiers if item.strip()}
        if not wanted:
            return 0.0
        for evidence in candidate.evidence:
            for entity in evidence.matched_entities:
                if entity.strip().lower() in wanted:
                    return 1.0
        return 0.0

    def _graph(self, candidate: Candidate) -> float:
        """Return 1.0 when traversal found this candidate."""
        return 1.0 if any(
            evidence.method is RetrievalMethod.GRAPH for evidence in candidate.evidence
        ) else 0.0

    def _lexical(self, candidate: Candidate) -> float:
        """Return the squashed best BM25 score among the text evidence."""
        best = max(
            (
                evidence.raw_score
                for evidence in candidate.evidence
                if evidence.method is RetrievalMethod.TEXT
            ),
            default=0.0,
        )
        if best <= 0.0:
            return 0.0
        return best / (best + _LEXICAL_SATURATION)

    def _distance(self, candidate: Candidate) -> float:
        """Return the hop decay of the closest graph evidence."""
        hops = [
            evidence.hops
            for evidence in candidate.evidence
            if evidence.method is RetrievalMethod.GRAPH
        ]
        if not hops:
            return 0.0
        return _HOP_DECAY ** min(hops)
