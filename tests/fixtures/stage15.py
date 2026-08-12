"""Stage-15 test fixtures.

A deterministic context package, a fake provider, and valid responses built
against that package.

The package is assembled with the real Stage-14 builder from real Stage-13
objects, so the item ids, the section order and the uncertainty ledger are the
ones the pipeline actually produces rather than ones invented for the test. The
seeds reproduce the corpus's known gaps: T1562 and TA0011 resolve to nothing,
and M1013 matches both an enterprise and a mobile record.

No test in this suite touches the knowledge datasets, and none calls a provider.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from src.config.settings import ModelSettings
from src.context.context_builder import ContextBuilder
from src.context.models import ContextPackage, RuleContext
from src.context.types import ContextOperation
from src.core.engine import ReasoningEngine
from src.core.types import ReasoningOperation
from src.core.uncertainty import uncertain_identifiers
from src.graphrag.models import (
    Chunk,
    RetrievalItem,
    RetrievalQuery,
    RetrievalResult,
    RetrievalScore,
)
from src.graphrag.provenance import ChunkProvenance, RetrievalProvenance, SeedReport
from src.graphrag.types import RetrievalMethod, RetrievalMode, SectionType
from src.knowledge.models.types import KnowledgeSource
from src.llm.exceptions import LLMError
from src.llm.request import LLMRequest
from src.llm.response import LLMResponse, TokenUsage
from src.llm.types import FinishReason

RULE_TEXT = """title: Suspicious PowerShell Encoded Command
id: 8a1f2c34-0000-4c11-9f00-2b7a5c9e1234
status: experimental
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    process.name: powershell.exe
    process.command_line|contains: '-enc'
  condition: selection
falsepositives:
  - Administrative scripts
level: medium
"""

RULE_QUERY = 'process.name:"powershell.exe" and process.command_line:*-enc*'


def rule_context(raw_text: str = RULE_TEXT) -> RuleContext:
    """Return the rule the fixtures reason about."""
    return RuleContext(
        title="Suspicious PowerShell Encoded Command",
        identifier="8a1f2c34-0000-4c11-9f00-2b7a5c9e1234",
        rule_format="sigma",
        language="sigma",
        query=RULE_QUERY,
        condition="selection",
        log_source="category=process_creation, product=windows",
        tags=("attack.execution", "attack.t1059.001"),
        references=("https://attack.mitre.org/techniques/T1059/001/",),
        false_positives=("Administrative scripts",),
        raw_text=raw_text,
    )


def _chunk(
    index: int,
    source: KnowledgeSource,
    source_id: str,
    section: SectionType,
    text: str,
) -> Chunk:
    """Return one chunk with complete provenance."""
    return Chunk(
        chunk_id=f"{source.value}:{source_id}:{index:02d}",
        parent_record_id=f"{source.value}:{source_id}",
        source=source,
        source_id=source_id,
        section=section,
        text=text,
        provenance=ChunkProvenance(
            source=source,
            source_id=source_id,
            parent_record_id=f"{source.value}:{source_id}",
            dataset=f"resources/knowledge/{source.value}/{source.value}.jsonl",
            line_number=index + 1,
            section=section,
            section_label=section.value,
            char_start=0,
            char_end=len(text),
        ),
    )


def _item(chunk: Chunk, score: float, *, exact: float = 0.0) -> RetrievalItem:
    """Return one retrieved item carrying its chunk's provenance."""
    return RetrievalItem(
        chunk=chunk,
        score=RetrievalScore(total=score, exact_identifier=exact, lexical=score),
        provenance=RetrievalProvenance(
            source=chunk.source,
            source_id=chunk.source_id,
            parent_record_id=chunk.parent_record_id,
            chunk_id=chunk.chunk_id,
            section=chunk.section,
            location=(
                f"resources/knowledge/{chunk.source.value}/{chunk.source.value}.jsonl"
                f"#L{chunk.provenance.line_number if chunk.provenance else 0}"
            ),
            methods=(RetrievalMethod.TEXT,),
        ),
    )


def retrieval_result() -> RetrievalResult:
    """Return a retrieval result carrying the corpus's known gaps."""
    chunks = (
        _chunk(
            0,
            KnowledgeSource.MITRE,
            "T1059.001",
            SectionType.DESCRIPTION,
            "T1059.001 PowerShell: adversaries abuse PowerShell for execution, often with "
            "encoded commands passed through process.command_line.",
        ),
        _chunk(
            1,
            KnowledgeSource.LOLBAS,
            "Powershell.exe",
            SectionType.COMMAND,
            "Powershell.exe -enc <base64> executes an encoded command; -e and -encodedcommand "
            "are accepted abbreviations.",
        ),
        _chunk(
            2,
            KnowledgeSource.ELASTIC,
            "elastic-encoded-powershell",
            SectionType.QUERY,
            "Encoded PowerShell Command: process.name:\"powershell.exe\" and "
            "process.args:(\"-enc\" or \"-encodedcommand\" or \"-e\")",
        ),
        _chunk(
            3,
            KnowledgeSource.SIGMA,
            "sigma-encoded-powershell",
            SectionType.DETECTION,
            "Encoded PowerShell Command Line: detects powershell.exe invoked with an encoded "
            "command argument.",
        ),
        _chunk(
            4,
            KnowledgeSource.ECS,
            "process.command_line",
            SectionType.FIELD,
            "process.command_line is the full command line that started the process, as a "
            "keyword field with a text multi-field.",
        ),
    )
    scores = (0.91, 0.84, 0.77, 0.71, 0.64)
    items = tuple(
        _item(chunk, score, exact=0.9 if index == 0 else 0.0)
        for index, (chunk, score) in enumerate(zip(chunks, scores, strict=True))
    )
    return RetrievalResult(
        query=RetrievalQuery(
            text="powershell encoded command",
            entity_ids=("T1059.001", "T1562", "TA0011", "M1013"),
            mode=RetrievalMode.HYBRID,
        ),
        mode=RetrievalMode.HYBRID,
        items=items,
        total_candidates=42,
        seeds=(
            SeedReport(value="T1059.001", status="resolved", node_ids=("technique:T1059.001",)),
            SeedReport(value="T1562", status="unresolved", note="no record carries T1562"),
            SeedReport(value="TA0011", status="unresolved", note="no tactic records in snapshot"),
            SeedReport(
                value="M1013",
                status="ambiguous",
                node_ids=("enterprise:M1013", "mobile:M1013"),
                note="two mitigation records answer to M1013",
            ),
        ),
    )


def context_package(
    operation: ContextOperation = ContextOperation.ANALYZE,
    *,
    rule: RuleContext | None = None,
    retrieval: RetrievalResult | None = None,
) -> ContextPackage:
    """Return the fixture context package for one operation."""
    return ContextBuilder().build(
        operation,
        rule=rule if rule is not None else rule_context(),
        retrieval=retrieval if retrieval is not None else retrieval_result(),
    )


def item_id_of(package: ContextPackage, source: KnowledgeSource) -> str:
    """Return the id of the first retrieved item from one source."""
    for item in package.items:
        if item.source is source:
            return item.item_id
    raise LookupError(f"package carries no item from {source.value}")


def uncertainties_of(package: ContextPackage) -> list[dict[str, Any]]:
    """Return the uncertainty array a valid response must carry for a package."""
    return [
        {
            "identifier": entry.identifier,
            "status": entry.status.value,
            "candidates": list(entry.candidates),
            "treatment": "carried forward without being resolved",
        }
        for entry in uncertain_identifiers(package)
    ]


def _evidence(package: ContextPackage) -> list[dict[str, Any]]:
    """Return one citation of the supplied MITRE item."""
    return [
        {
            "item_id": item_id_of(package, KnowledgeSource.MITRE),
            "source": "mitre",
            "identifier": "T1059.001",
            "detail": "the supplied technique record describes encoded PowerShell execution",
        }
    ]


def _envelope(package: ContextPackage, operation: ReasoningOperation) -> dict[str, Any]:
    """Return a valid envelope for one operation."""
    return {
        "operation": operation.value,
        "summary": "The rule matches encoded PowerShell invocations but depends on one spelling "
        "of the encoding flag.",
        "findings": [
            {
                "finding_id": "F1",
                "category": "brittleness",
                "severity": "high",
                "statement": "The query matches only the literal '-enc' spelling of the "
                "encoding flag.",
                "explanation": "The supplied LOLBAS material lists -e and -encodedcommand as "
                "accepted abbreviations, neither of which the query matches.",
                "support": "supported",
                "evidence": _evidence(package),
                "confidence": 0.8,
            }
        ],
        "recommendations": [
            {
                "recommendation_id": "R1",
                "category": "brittleness",
                "priority": "high",
                "action": "Match every accepted abbreviation of the encoding flag.",
                "rationale": "The supplied material shows three spellings an attacker may use "
                "at no cost.",
                "addresses": ["F1"],
                "support": "supported",
            }
        ],
        "confidence": 0.72,
        "metadata": {"reviewed_dimensions": "logic,brittleness,evasion"},
        "uncertainties": uncertainties_of(package),
    }


def _rule_object() -> dict[str, Any]:
    """Return a valid produced rule."""
    return {
        "title": "Encoded PowerShell Command Line",
        "description": "Detects powershell.exe started with an encoded command argument.",
        "rule_type": "query",
        "language": "kql",
        "query": 'process.name:"powershell.exe" and process.command_line:('
        '*-enc* or *-encodedcommand* or *-e *)',
        "severity": "medium",
        "risk_score": 47,
        "index_patterns": ["logs-endpoint.events.process-*"],
        "false_positives": ["Administrative scripts that pass encoded commands"],
        "investigation_guide": "Decode the base64 argument and review the parent process.",
        "mitre": [{"tactic_id": "", "technique_id": "T1059.001"}],
    }


def analyze_response(package: ContextPackage) -> dict[str, Any]:
    """Return a valid analyze response for a package."""
    return _envelope(package, ReasoningOperation.ANALYZE)


def enhance_response(package: ContextPackage) -> dict[str, Any]:
    """Return a valid enhance response for a package."""
    body = _envelope(package, ReasoningOperation.ENHANCE)
    body["original_rule"] = {
        "identifier": "8a1f2c34-0000-4c11-9f00-2b7a5c9e1234",
        "title": "Suspicious PowerShell Encoded Command",
        "language": "sigma",
        "query": RULE_QUERY,
    }
    body["enhanced_rule"] = _rule_object()
    body["changes"] = [
        {
            "change_id": "C1",
            "category": "evasion_resistance",
            "before": "process.command_line:*-enc*",
            "after": "process.command_line:(*-enc* or *-encodedcommand* or *-e *)",
            "rationale": "The original matched one spelling of a flag with three accepted forms.",
            "addresses": ["F1"],
            "evidence": _evidence(package),
            "support": "supported",
        }
    ]
    return body


def generate_response(package: ContextPackage) -> dict[str, Any]:
    """Return a valid generate response for a package."""
    body = _envelope(package, ReasoningOperation.GENERATE)
    body["generated_rule"] = _rule_object()
    body["rationale"] = [
        {
            "aspect": "target_behaviour",
            "statement": "Detect encoded command execution through powershell.exe.",
            "rationale": "The requirement names encoded PowerShell, which the supplied "
            "technique record describes.",
            "evidence": _evidence(package),
        }
    ]
    body["mappings"] = [
        {
            "tactic_id": "",
            "technique_id": "T1059.001",
            "support": "supported",
            "evidence": _evidence(package),
        }
    ]
    return body


def body_of(payload: dict[str, Any]) -> str:
    """Return a response payload serialised as a provider would return it."""
    return json.dumps(payload)


def response_of(text: str, *, finish_reason: FinishReason = FinishReason.STOP) -> LLMResponse:
    """Return a provider response carrying a body."""
    return LLMResponse(
        text=text,
        provider="fake",
        model="fake-model",
        finish_reason=finish_reason,
        usage=TokenUsage(prompt_tokens=100, completion_tokens=200, total_tokens=300),
        duration_seconds=0.0,
    )


@dataclass
class FakeProvider:
    """A provider that returns queued bodies, or raises queued failures.

    Satisfies the Stage-07 ``LLMProvider`` protocol by shape. It performs no I/O,
    so every test in this suite runs without a network or a credential.
    """

    bodies: list[str] = field(default_factory=list)
    failures: list[LLMError | None] = field(default_factory=list)
    requests: list[LLMRequest] = field(default_factory=list)
    finish_reason: FinishReason = FinishReason.STOP

    @property
    def name(self) -> str:
        """Return this provider's identifier."""
        return "fake"

    def generate(self, request: LLMRequest) -> LLMResponse:
        """Return the next queued body, after raising any queued failure."""
        self.requests.append(request)
        if self.failures:
            failure = self.failures.pop(0)
            if failure is not None:
                raise failure
        body = self.bodies.pop(0) if self.bodies else "{}"
        return response_of(body, finish_reason=self.finish_reason)

    @property
    def calls(self) -> int:
        """Return how many times the provider was called."""
        return len(self.requests)

    @property
    def last_request(self) -> LLMRequest:
        """Return the request of the most recent call."""
        return self.requests[-1]


def provider_returning(payloads: Sequence[dict[str, Any]] | Sequence[str]) -> FakeProvider:
    """Return a provider queued to answer with the given payloads."""
    bodies = [item if isinstance(item, str) else body_of(item) for item in payloads]
    return FakeProvider(bodies=bodies)


PROMPTS_DIR = Path(__file__).resolve().parents[2] / "prompts"
"""The project's real prompt tree. The tests render the shipped templates."""


def model_settings() -> ModelSettings:
    """Return deterministic model settings for the fake provider."""
    return ModelSettings(
        provider="fake",
        name="fake-model",
        temperature=0.0,
        top_p=1.0,
        max_output_tokens=4096,
        timeout_seconds=30,
        max_retries=2,
        retry_backoff_seconds=0.0,
    )


def engine_of(provider: FakeProvider) -> ReasoningEngine:
    """Return an engine wired to a fake provider, with waiting disabled."""
    return ReasoningEngine.of(
        provider=provider,
        settings=model_settings(),
        prompts_dir=PROMPTS_DIR,
        sleep=lambda _: None,
    )
