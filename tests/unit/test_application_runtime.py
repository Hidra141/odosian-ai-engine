"""Stage-18 runtime envelope.

Three of the envelope's fields vary between otherwise identical runs, which is
why they are injected rather than read from the machine. These tests supply a
fixed clock, a fixed identifier and a fake timer, and check that the values
reaching the envelope are exactly the ones supplied — the property that makes
every other Stage-18 test able to assert on a whole document.

The timestamp is checked against the shape the contract demonstrates rather
than against Python's default, which writes microseconds and a numeric offset.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta, timezone

import pytest

from src.application.requests import EngineRequest
from src.application.runtime import RuntimeFactory, as_timestamp, new_uuid, utc_now
from src.core.types import ReasoningOperation

USER = "8a9ffc32-8495-4a25-a616-362d90f35dcc"
RULE_ID = "1bdc1065-5bd4-4dd6-a6df-c111d643ff90"
MOMENT = datetime(2026, 7, 24, 9, 12, 3, 456_789, tzinfo=UTC)

CONTRACT_TIMESTAMP = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$")

REQUEST = EngineRequest(
    operation=ReasoningOperation.ANALYZE,
    user_id=USER,
    rule_text='process.name:"powershell.exe"',
    rule_id=RULE_ID,
)


class FakeTimer:
    """A timer returning the queued readings, in order."""

    def __init__(self, *readings: float) -> None:
        self.readings = list(readings)
        self.last = 0.0

    def __call__(self) -> float:
        if self.readings:
            self.last = self.readings.pop(0)
        return self.last


def factory(*, timer=None, moment=MOMENT, identifier="fixed-id") -> RuntimeFactory:
    """Return a factory with every source of variation pinned."""
    return RuntimeFactory(
        now=lambda: moment,
        new_id=lambda: identifier,
        timer=timer if timer is not None else FakeTimer(0.0, 0.0),
    )


def test_the_injected_identifier_reaches_the_envelope():
    envelope = factory(identifier="80ea7075-5585-4f0f-914a-f643b4c8c3f2").create(
        REQUEST, started=0.0, input_query=""
    )
    assert envelope.id == "80ea7075-5585-4f0f-914a-f643b4c8c3f2"


def test_two_runs_of_the_real_generator_differ():
    assert new_uuid() != new_uuid()


def test_the_real_generator_produces_a_uuid_shaped_value():
    assert re.fullmatch(r"[0-9a-f-]{36}", new_uuid())


def test_the_injected_clock_reaches_the_envelope():
    envelope = factory().create(REQUEST, started=0.0, input_query="")
    assert envelope.created_at == "2026-07-24T09:12:03.456Z"


def test_the_timestamp_matches_the_shape_the_contract_demonstrates():
    assert CONTRACT_TIMESTAMP.fullmatch(as_timestamp(MOMENT))
    assert CONTRACT_TIMESTAMP.fullmatch(as_timestamp(utc_now()))


def test_the_timestamp_never_carries_a_numeric_offset():
    rendered = as_timestamp(MOMENT)
    assert rendered.endswith("Z")
    assert "+00:00" not in rendered


def test_milliseconds_are_truncated_rather_than_rounded_up():
    """456789 microseconds is 456 milliseconds, not 457."""
    assert as_timestamp(MOMENT).endswith(".456Z")


def test_a_whole_second_still_states_three_millisecond_digits():
    exact = datetime(2026, 7, 24, 9, 12, 3, 0, tzinfo=UTC)
    assert as_timestamp(exact) == "2026-07-24T09:12:03.000Z"


def test_a_non_utc_clock_is_converted_rather_than_relabelled():
    """A local reading behind a Z would state the wrong instant."""
    tokyo = MOMENT.astimezone(timezone(timedelta(hours=9)))
    assert as_timestamp(tokyo) == as_timestamp(MOMENT)


def test_the_real_clock_is_timezone_aware_and_utc():
    assert utc_now().tzinfo is UTC


@pytest.mark.parametrize(
    ("start", "end", "expected"),
    [(0.0, 0.0, 0), (0.0, 1.0, 1000), (10.0, 18.12, 8120), (2.5, 2.5004, 0)],
)
def test_latency_is_whole_milliseconds_between_the_two_readings(start, end, expected):
    built = factory(timer=FakeTimer(start, end))
    started = built.start()
    assert built.create(REQUEST, started=started, input_query="").latency_ms == expected


def test_a_backwards_clock_never_reports_a_negative_duration():
    built = factory(timer=FakeTimer(50.0, 10.0))
    started = built.start()
    assert built.create(REQUEST, started=started, input_query="").latency_ms == 0


def test_the_request_supplies_the_account_and_the_rule():
    envelope = factory().create(REQUEST, started=0.0, input_query="q")
    assert (envelope.user_id, envelope.rule_id, envelope.input_query) == (USER, RULE_ID, "q")


def test_an_absent_rule_id_stays_none_rather_than_becoming_a_blank():
    ad_hoc = EngineRequest(ReasoningOperation.ANALYZE, user_id=USER, rule_text="x")
    assert factory().create(ad_hoc, started=0.0, input_query="").rule_id is None


def test_nothing_is_saved_unless_the_caller_says_so():
    envelope = factory().create(REQUEST, started=0.0, input_query="")
    assert (envelope.saved_rule_id, envelope.saved_rule_title) == (None, None)
    assert not envelope.saved


def test_the_defaults_are_the_real_sources():
    built = RuntimeFactory()
    assert (built.now, built.new_id, built.timer) == (utc_now, new_uuid, built.timer)
    assert callable(built.timer)


def test_the_default_callables_are_not_bound_to_the_instance():
    """A function stored on a dataclass must stay a plain function."""
    assert RuntimeFactory().now() is not None
    assert isinstance(RuntimeFactory().new_id(), str)
