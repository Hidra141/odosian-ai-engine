"""Prompt validation.

Checks a template, and a template against the variables offered for it, before
anything is rendered.

Issues carry a severity. Only errors block a build; warnings describe template
hygiene, such as a declared variable the body never uses. All issues from one
check are collected before reporting, so a single run reports every problem.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass

from .exceptions import PromptValidationError
from .placeholders import find_malformed
from .prompt_models import PromptTemplate
from .types import IssueSeverity, VariableMapping


@dataclass(frozen=True, slots=True)
class PromptIssue:
    """A single problem found in a template or in its variables."""

    severity: IssueSeverity
    template: str
    message: str

    def __str__(self) -> str:
        """Return the issue rendered as ``severity template: message``."""
        return f"{self.severity.value} {self.template}: {self.message}"


@dataclass(frozen=True, slots=True)
class PromptValidationResult:
    """Outcome of validating a template."""

    issues: tuple[PromptIssue, ...] = ()

    @property
    def errors(self) -> tuple[PromptIssue, ...]:
        """Return only the blocking issues."""
        return tuple(issue for issue in self.issues if issue.severity is IssueSeverity.ERROR)

    @property
    def warnings(self) -> tuple[PromptIssue, ...]:
        """Return only the non-blocking issues."""
        return tuple(issue for issue in self.issues if issue.severity is IssueSeverity.WARNING)

    @property
    def is_valid(self) -> bool:
        """Return whether the template is free of blocking issues."""
        return not self.errors

    def raise_if_invalid(self) -> None:
        """Raise :class:`PromptValidationError` when any error was found."""
        errors = self.errors
        if errors:
            raise PromptValidationError([str(issue) for issue in errors])


@dataclass(frozen=True, slots=True)
class PromptValidator:
    """Validate templates and the variables offered for them."""

    def validate_template(self, template: PromptTemplate) -> PromptValidationResult:
        """Check a template on its own, without any variables."""
        return PromptValidationResult(tuple(self._template_issues(template)))

    def validate(
        self,
        template: PromptTemplate,
        variables: VariableMapping,
    ) -> PromptValidationResult:
        """Check a template together with the variables offered for it."""
        issues = [*self._template_issues(template), *self._variable_issues(template, variables)]
        return PromptValidationResult(tuple(issues))

    def _template_issues(self, template: PromptTemplate) -> Iterator[PromptIssue]:
        """Yield issues that depend only on the template itself."""
        name = template.metadata.name
        if template.is_empty:
            yield PromptIssue(IssueSeverity.ERROR, name, "template body is empty")
        for fragment in find_malformed(template.body):
            yield PromptIssue(
                IssueSeverity.ERROR,
                name,
                f"malformed placeholder: {fragment}",
            )
        if not template.metadata.declares_variables:
            return
        declared = set(template.metadata.declared_variables)
        for placeholder in template.placeholders:
            if placeholder not in declared:
                yield PromptIssue(
                    IssueSeverity.ERROR,
                    name,
                    f"placeholder {placeholder} is not declared in front matter",
                )
        for variable in template.metadata.declared_variables:
            if variable not in template.placeholders:
                yield PromptIssue(
                    IssueSeverity.WARNING,
                    name,
                    f"declared variable {variable} is never used in the body",
                )

    def _variable_issues(
        self,
        template: PromptTemplate,
        variables: VariableMapping,
    ) -> Iterator[PromptIssue]:
        """Yield issues about the variables offered for a template."""
        name = template.metadata.name
        for placeholder in template.placeholders:
            if placeholder not in variables:
                yield PromptIssue(
                    IssueSeverity.ERROR,
                    name,
                    f"no value supplied for {placeholder}",
                )
