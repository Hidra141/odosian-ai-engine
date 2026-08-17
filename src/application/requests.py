"""The engine request.

What a caller asks for, before any stage has run.

Every request type the lower layers define already begins at a built context
package: Stage-15's :class:`~src.core.models.AnalyzeRequest` and its siblings
take one as their first field. That is the right shape for the reasoning layer
and the wrong shape for a caller, who holds a rule and a question rather than an
evidence package. This is the missing half — the input the pipeline accepts and
turns into the other.

Analyze takes its subject in one of two forms. A caller with a saved rule sends
the rule; a caller who pasted a query into a box sends the query and says what
language it is written in. Both are the same operation over the same pipeline,
and exactly one of them may be supplied — a request carrying both states two
subjects and names neither.

Enhance takes only a rule. Generate takes only a requirement. Neither accepts a
raw query, because neither contract has anywhere to put one.

Validation rejects; it never fills a gap in. A request naming an operation
without the material that operation needs is refused, and so is one carrying
material the operation has no field for. Silently discarding what a caller
supplied is the same fault as silently inventing what they did not, and a
generate request carrying a rule id is exactly that: the generate contract has
no ``ruleId``, so the value could only be dropped. A language supplied beside a
structured rule is the same case: the rule states its own, so the one passed
alongside it could only be ignored.

The refusal is Stage-15's :class:`~src.core.exceptions.InvalidReasoningRequestError`
rather than a new type. The fault it reports is the same one — a request that
cannot be executed as stated — and a second name for it would only make callers
catch two things where one will do.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final, final

from src.core.exceptions import InvalidReasoningRequestError
from src.core.types import ReasoningOperation
from src.parser.types import RuleLanguage

RULE_OPERATIONS: Final[frozenset[ReasoningOperation]] = frozenset(
    {ReasoningOperation.ANALYZE, ReasoningOperation.ENHANCE}
)
"""The operations that reason about a rule the caller already has.

Generate is the exception: it is asked about a requirement no rule yet
satisfies, which is why it takes different material and refuses a rule.
"""

QUERY_OPERATIONS: Final[frozenset[ReasoningOperation]] = frozenset(
    {ReasoningOperation.ANALYZE}
)
"""The operations that also accept a bare query in place of a rule.

Only analyze. Enhance rewrites a rule and reports the original beside the
rewrite, so it needs the rule itself; generate is asked about a requirement and
has no subject to read.
"""

QUERY_LANGUAGES: Final[frozenset[RuleLanguage]] = frozenset(
    {
        RuleLanguage.KUERY,
        RuleLanguage.EQL,
        RuleLanguage.LUCENE,
        RuleLanguage.ESQL,
    }
)
"""The languages a bare query may be written in.

Stage-08's vocabulary, narrowed to the four the query-language contract states.
``sigma`` is excluded deliberately: it names a rule document format rather than
a query language, and a bare Sigma query is not a thing a caller can hold.

The tokens themselves are not listed here. :meth:`RuleLanguage.from_value`
already accepts every spelling the contract uses — ``kuery`` and ``kql`` both
reach :attr:`RuleLanguage.KUERY`, ``esql`` and ``es|ql`` both reach
:attr:`RuleLanguage.ESQL` — so no second table is written down.
"""


@final
@dataclass(frozen=True, slots=True)
class EngineRequest:
    """One request to run an operation from raw input to a contract document."""

    operation: ReasoningOperation
    user_id: str
    rule_text: str = ""
    requirement: str = ""
    rule_id: str | None = None
    query: str = ""
    language: str = ""

    @property
    def is_rule_operation(self) -> bool:
        """Return whether this operation reasons about a supplied subject."""
        return self.operation in RULE_OPERATIONS

    @property
    def is_raw_query(self) -> bool:
        """Return whether this request states its subject as a bare query."""
        return bool(self.query.strip())

    @property
    def rule_language(self) -> RuleLanguage:
        """Return the stated language in Stage-08's vocabulary.

        :attr:`RuleLanguage.UNKNOWN` for anything unrecognised, which
        :meth:`validate` refuses rather than passing on.
        """
        return RuleLanguage.from_value(self.language)

    def validate(self) -> None:
        """Raise when the request cannot be executed as stated."""
        if not self.user_id.strip():
            self._refuse("needs a user id, and the request supplies none")
        if self.is_rule_operation:
            self._validate_rule_operation()
        else:
            self._validate_requirement_operation()

    def _validate_rule_operation(self) -> None:
        """Raise when an analyze or enhance request is not usable."""
        if self.requirement.strip():
            self._refuse(
                "reasons about a rule rather than a requirement, and the request supplies a "
                "requirement that could only be discarded"
            )
        if self.is_raw_query:
            self._validate_raw_query()
            return
        if not self.rule_text.strip():
            subject = (
                "a rule or a raw query"
                if self.operation in QUERY_OPERATIONS
                else "a rule"
            )
            self._refuse(f"needs {subject}, and the request supplies neither")
        if self.language.strip():
            self._refuse(
                "reads the language from the rule it was given, and the request supplies a "
                "language beside it that could only be discarded"
            )

    def _validate_raw_query(self) -> None:
        """Raise when a request stating a bare query is not usable."""
        if self.operation not in QUERY_OPERATIONS:
            self._refuse(
                "rewrites a rule and reports the original beside it, so it needs the rule "
                "rather than a bare query"
            )
        if self.rule_text.strip():
            self._refuse(
                "takes one subject, and the request supplies both a rule and a raw query"
            )
        if not self.language.strip():
            self._refuse(
                "cannot read a bare query without being told its language, and the request "
                "supplies none"
            )
        if self.rule_language not in QUERY_LANGUAGES:
            supported = ", ".join(sorted(item.value for item in QUERY_LANGUAGES))
            self._refuse(
                f"was given language {self.language!r}, which is not one of {supported}"
            )

    def _validate_requirement_operation(self) -> None:
        """Raise when a generate request is not usable."""
        if not self.requirement.strip():
            self._refuse("needs a detection requirement, and the request supplies none")
        if self.rule_text.strip():
            self._refuse(
                "writes a rule rather than reading one, and the request supplies a rule "
                "that could only be discarded"
            )
        if self.is_raw_query:
            self._refuse(
                "writes a rule rather than reading one, and the request supplies a raw "
                "query that could only be discarded"
            )
        if self.language.strip():
            self._refuse(
                "chooses the language of the rule it writes, and the request supplies one "
                "that could only be discarded"
            )
        if self.rule_id is not None:
            self._refuse(
                "writes a rule that does not exist yet and its contract carries no rule id, "
                "so the supplied rule id could only be discarded"
            )

    def _refuse(self, reason: str) -> None:
        """Raise the refusal, naming the operation it applies to."""
        raise InvalidReasoningRequestError(f"operation {self.operation.value!r} {reason}")
