"""Text retrieval.

Answers a query from the lexical index and attaches the evidence for each hit.

The query sent to the index is the caller's text together with any identifiers
and field names they named, because an identifier is the strongest lexical
signal available: a chunk containing ``T1059.001`` is about T1059.001 whatever
its prose says.

The field names are taken in the vocabulary the *rule* wrote, not the one the
corpus documents. This route matches strings against an index, so the only
spelling that can find anything is the spelling the indexed records use, and a
rule format's own names are what its records hold. A query naming no separate
lexical vocabulary falls back to the canonical names, which is what every
caller asked with before the two were told apart.

Every hit records which terms matched and which of the query's identifiers
appear in the chunk, so ranking never has to re-derive it and a reader can see
why the chunk is here.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import final

from .exceptions import IndexNotBuiltError
from .filters import query_predicate
from .models import Candidate, RetrievalQuery
from .provenance import RetrievalEvidence
from .text_index import TextIndex, tokenize
from .types import MatchKind, RetrievalMethod


@final
@dataclass(frozen=True, slots=True)
class LexicalTextRetriever:
    """Retrieves chunks by lexical relevance."""

    index: TextIndex

    def retrieve(self, query: RetrievalQuery, limit: int) -> tuple[Candidate, ...]:
        """Return text candidates, best first."""
        if not self.index.is_built:
            raise IndexNotBuiltError("text index")
        text = self._query_text(query)
        if not text.strip():
            return ()

        identifiers = tuple(item.strip().lower() for item in self._askable(query) if item.strip())
        candidates: list[Candidate] = []
        for chunk_id, score, matched in self.index.search(text, limit, query_predicate(query)):
            chunk = self.index.chunk(chunk_id)
            if chunk is None:
                continue
            present = self._identifiers_in(chunk.text, identifiers)
            candidates.append(
                Candidate(
                    chunk=chunk,
                    evidence=(
                        RetrievalEvidence(
                            method=RetrievalMethod.TEXT,
                            match_kind=(
                                MatchKind.EXACT_IDENTIFIER if present else MatchKind.LEXICAL
                            ),
                            detail=f"bm25={score:.4f}",
                            matched_terms=matched,
                            matched_entities=present,
                            raw_score=score,
                        ),
                    ),
                )
            )
        return tuple(candidates)

    def _query_text(self, query: RetrievalQuery) -> str:
        """Return the text sent to the index for a query."""
        parts = [query.text, *self._askable(query)]
        return " ".join(part for part in parts if part and part.strip())

    def _askable(self, query: RetrievalQuery) -> tuple[str, ...]:
        """Return what this route may ask the index with, in query order.

        The identifiers and the field names in the rule's own vocabulary. One
        function rather than two expressions because the query text and the
        identifier-presence check must ask with the same terms: a term that can
        win a chunk on BM25 but is then not looked for in it would make the
        evidence disagree with the score it produced.
        """
        return (*query.entity_ids, *query.lexical_vocabulary)

    def _identifiers_in(self, text: str, identifiers: tuple[str, ...]) -> tuple[str, ...]:
        """Return which of the query's identifiers appear in a chunk."""
        if not identifiers:
            return ()
        tokens = set(tokenize(text))
        return tuple(item for item in identifiers if item in tokens)
