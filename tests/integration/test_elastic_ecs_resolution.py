"""An Elastic rule's fields, against the real ECS corpus.

The unit tests establish that a query's fields survive extraction and reach
Stage-13's seeding. They stop there, because the seed is only half the claim:
a canonical field is worth carrying only if a node answers to it.

This closes that half against the corpus as committed. It builds the real
graph, looks up the fields a real corpus rule references, and checks that the
identifiers Stage-13 would seed with are identifiers Stage-12 actually holds.

Nothing here writes, and no provider is called. A checkout without the datasets
is skipped rather than failed, as the other integration modules do: the corpus
is an input to the repository, not an artefact of it.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from src.application.retrieval import rule_query
from src.context.context_builder import rule_context_from_parsed
from src.entities.extractor import EntityExtractor
from src.graph.graph_builder import GraphBuilder
from src.graphrag.graph_retriever import GraphView
from src.knowledge.loader.layout import CorpusLayout
from src.knowledge.repository.jsonl_repository import JsonlKnowledgeRepository
from src.mapping.entity_mapper import EntityMapper
from src.parser.models import Detection, ParsedRule, RuleMetadata
from src.parser.types import RuleFormat, RuleLanguage
from tests.fixtures import stage15 as fixtures

ROOT = Path(__file__).resolve().parents[2]
KNOWLEDGE_DIR = ROOT / "resources" / "knowledge"

IODINE_RECORD = "elastic-rules:041d4d41-9589-43e2-ba13-5680af75ebc2"
"""``Deprecated - Potential DNS Tunneling via Iodine``, read from the corpus.

Read rather than quoted, so the test is exercising the rule the repository
actually ships. A corpus that stopped carrying it fails here loudly instead of
passing against a copy that has drifted.
"""

_QUERY_BLOCK = re.compile(r"\nQuery:\n(.*?)(?:\n\n[A-Z][A-Za-z ]*:|\Z)", re.S)


@pytest.fixture(scope="module")
def view() -> GraphView:
    """Build the real knowledge graph once and return its adjacency view."""
    missing = CorpusLayout(root=KNOWLEDGE_DIR).missing_sources()
    if missing:
        pytest.skip(f"corpus incomplete: {', '.join(item.value for item in missing)}")
    repository = JsonlKnowledgeRepository.from_root(KNOWLEDGE_DIR)
    return GraphView.of(GraphBuilder.over(repository).build())


@pytest.fixture(scope="module")
def iodine_query() -> str:
    """Return the query of the Iodine rule, as the corpus states it."""
    path = KNOWLEDGE_DIR / "elastic" / "elastic.jsonl"
    if not path.is_file():
        pytest.skip("elastic dataset is not present")
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        record = json.loads(line)
        if record["id"] == IODINE_RECORD:
            found = _QUERY_BLOCK.search(record["text"])
            if found is None:
                pytest.skip(f"{IODINE_RECORD} states no query block")
            return found.group(1).strip()
    pytest.skip(f"{IODINE_RECORD} is not in the corpus")
    raise AssertionError("unreachable")


def query_rule(query: str) -> ParsedRule:
    """Return a parsed Elastic rule stating one query."""
    return ParsedRule(
        rule_format=RuleFormat.ELASTIC,
        metadata=RuleMetadata(title="probe"),
        detection=Detection(query=query, language=RuleLanguage.KUERY),
        source_text=query,
    )


def seeds(parsed: ParsedRule):
    """Return what a parsed rule asks the corpus."""
    mappings = EntityMapper().map(EntityExtractor().extract(parsed))
    return rule_query(rule_context_from_parsed(parsed), mappings, top_k=10)


def nodes_for(view: GraphView, identifier: str) -> list[str]:
    """Return the node ids one identifier resolves to."""
    return view.by_identifier.get(identifier.strip().lower(), [])


# --------------------------------------------------------------------- TEST 8


def test_the_ecs_corpus_holds_the_fields_a_query_names(view: GraphView):
    for field in ("process.name", "process.command_line"):
        assert nodes_for(view, field) == [f"ecs:ECSField:{field}"]


def test_every_field_of_the_fixture_query_resolves(view: GraphView):
    for field in seeds(query_rule(fixtures.RULE_QUERY)).canonical_fields:
        assert len(nodes_for(view, field)) == 1


# --------------------------------------------------------------------- TEST 9


def test_a_query_rule_seeds_retrieval_with_a_resolvable_field(view: GraphView):
    found = seeds(query_rule(fixtures.RULE_QUERY))
    assert found.canonical_fields == ("process.name", "process.command_line")
    assert [nodes_for(view, field) for field in found.canonical_fields] == [
        ["ecs:ECSField:process.name"],
        ["ecs:ECSField:process.command_line"],
    ]


def test_the_iodine_rule_reaches_an_ecs_node(view: GraphView, iodine_query: str):
    found = seeds(query_rule(iodine_query))
    assert "process.name" in found.canonical_fields
    assert nodes_for(view, "process.name") == ["ecs:ECSField:process.name"]


def test_the_iodine_rule_asked_the_corpus_nothing_before_this_correction(
    view: GraphView,
    iodine_query: str,
):
    """The regression this phase exists to prevent.

    Before the query reader, ``canonical_fields`` was empty for every Elastic
    rule, so the graph route contributed nothing at all. An empty tuple here
    would mean the correction had been undone.
    """
    assert seeds(query_rule(iodine_query)).canonical_fields != ()
