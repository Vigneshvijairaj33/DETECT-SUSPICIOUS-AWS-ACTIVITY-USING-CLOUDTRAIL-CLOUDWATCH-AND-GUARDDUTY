"""
test_normalizer.py
==================
Unit tests for src/normalize_events.py

Run with:  pytest tests/test_normalizer.py -v
"""

import sys
from pathlib import Path
from datetime import datetime, timezone

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest
from src.normalize_events import (
    classify_severity,
    is_off_hours,
    parse_timestamp,
    normalize_event,
    normalize_events,
    deduplicate,
    HIGH_SEVERITY_EVENTS,
    MEDIUM_SEVERITY_EVENTS,
)


# ─────────────────────────────────────────────────────────────────────────── #
# Helpers
# ─────────────────────────────────────────────────────────────────────────── #

def make_event(**overrides) -> dict:
    """Build a minimal parsed event dict."""
    base = {
        "eventId":       "evt-norm-001",
        "eventTime":     "2026-10-12T09:00:00Z",
        "eventSource":   "ec2.amazonaws.com",
        "eventName":     "DescribeInstances",
        "eventType":     "AwsApiCall",
        "awsRegion":     "us-east-1",
        "principalType": "IAMUser",
        "userName":      "alice",
        "principalArn":  "arn:aws:iam::123456789012:user/alice",
        "accountId":     "123456789012",
        "sourceIPAddress": "203.0.113.1",
        "userAgent":     "aws-cli/2.15.0",
        "errorCode":     "",
        "errorMessage":  "",
        "readOnly":      True,
        "requestParameters": None,
        "responseElements":  None,
    }
    base.update(overrides)
    return base


# ─────────────────────────────────────────────────────────────────────────── #
# classify_severity tests
# ─────────────────────────────────────────────────────────────────────────── #

class TestClassifySeverity:

    def test_high_severity_events(self):
        for event_name in HIGH_SEVERITY_EVENTS:
            assert classify_severity(event_name, "") == "high", (
                f"{event_name} should be high severity"
            )

    def test_medium_severity_events(self):
        for event_name in MEDIUM_SEVERITY_EVENTS:
            result = classify_severity(event_name, "")
            # Some medium events might also be in HIGH — that's fine
            assert result in ("high", "medium"), (
                f"{event_name} should be at least medium"
            )

    def test_info_for_read_only(self):
        assert classify_severity("DescribeInstances", "") == "info"
        assert classify_severity("ListBuckets", "") == "info"
        assert classify_severity("GetCallerIdentity", "") == "info"

    def test_error_code_raises_to_medium(self):
        # A normally-info event becomes medium when it has an error
        result = classify_severity("DescribeInstances", "AccessDenied")
        assert result == "medium"

    def test_high_overrides_error_code(self):
        # High severity regardless of error code
        result = classify_severity("StopLogging", "AccessDenied")
        assert result == "high"

    def test_empty_error_code_stays_info(self):
        assert classify_severity("ListUsers", "") == "info"


# ─────────────────────────────────────────────────────────────────────────── #
# is_off_hours tests
# ─────────────────────────────────────────────────────────────────────────── #

class TestIsOffHours:

    def test_midnight_is_off_hours(self):
        assert is_off_hours(0) is True

    def test_3am_is_off_hours(self):
        assert is_off_hours(3) is True

    def test_6am_is_boundary(self):
        # 06:00 is the start of "on" hours — not off-hours
        assert is_off_hours(6) is False

    def test_noon_is_on_hours(self):
        assert is_off_hours(12) is False

    def test_9pm_is_on_hours(self):
        assert is_off_hours(21) is False

    def test_10pm_is_off_hours(self):
        assert is_off_hours(22) is True

    def test_11pm_is_off_hours(self):
        assert is_off_hours(23) is True


# ─────────────────────────────────────────────────────────────────────────── #
# parse_timestamp tests
# ─────────────────────────────────────────────────────────────────────────── #

class TestParseTimestamp:

    def test_parses_z_suffix(self):
        dt = parse_timestamp("2026-10-12T08:00:00Z")
        assert dt is not None
        assert dt.year  == 2026
        assert dt.month == 10
        assert dt.day   == 12
        assert dt.hour  == 8
        assert dt.tzinfo == timezone.utc

    def test_parses_plus_zero_offset(self):
        dt = parse_timestamp("2026-10-12T08:00:00+00:00")
        assert dt is not None
        assert dt.tzinfo is not None

    def test_returns_none_for_empty_string(self):
        assert parse_timestamp("") is None

    def test_returns_none_for_invalid_string(self):
        assert parse_timestamp("not-a-date") is None

    def test_result_is_utc(self):
        dt = parse_timestamp("2026-10-12T15:30:00Z")
        assert dt.tzinfo == timezone.utc
        assert dt.hour   == 15


# ─────────────────────────────────────────────────────────────────────────── #
# normalize_event tests
# ─────────────────────────────────────────────────────────────────────────── #

class TestNormalizeEvent:

    def test_adds_timestamp_fields(self):
        e = make_event(eventTime="2026-10-12T09:00:00Z")
        n = normalize_event(e)
        assert "eventTimestamp" in n
        assert "eventHour"      in n
        assert "eventDayOfWeek" in n
        assert "isOffHours"     in n

    def test_hour_extracted_correctly(self):
        e = make_event(eventTime="2026-10-12T15:30:00Z")
        n = normalize_event(e)
        assert n["eventHour"] == 15

    def test_off_hours_flagged_at_3am(self):
        e = make_event(eventTime="2026-10-12T03:00:00Z")
        n = normalize_event(e)
        assert n["isOffHours"] is True

    def test_not_off_hours_at_noon(self):
        e = make_event(eventTime="2026-10-12T12:00:00Z")
        n = normalize_event(e)
        assert n["isOffHours"] is False

    def test_severity_assigned(self):
        e = make_event(eventName="StopLogging")
        n = normalize_event(e)
        assert n["severity"] == "high"

    def test_root_activity_flagged(self):
        e = make_event(userName="root")
        n = normalize_event(e)
        assert n["isRootActivity"] is True

    def test_is_suspicious_for_root(self):
        e = make_event(userName="root")
        n = normalize_event(e)
        assert n["isSuspicious"] is True

    def test_is_suspicious_for_high_severity(self):
        e = make_event(eventName="StopLogging")
        n = normalize_event(e)
        assert n["isSuspicious"] is True

    def test_normal_event_not_suspicious(self):
        e = make_event(
            eventName="DescribeInstances",
            userName="alice",
            errorCode="",
            eventTime="2026-10-12T10:00:00Z",
        )
        n = normalize_event(e)
        assert n["isSuspicious"] is False

    def test_failed_event_flagged(self):
        e = make_event(errorCode="AccessDenied")
        n = normalize_event(e)
        assert n["isFailed"] is True

    def test_handles_missing_timestamp(self):
        e = make_event(eventTime="")
        n = normalize_event(e)
        assert n["eventTimestamp"] is None
        assert n["eventHour"] == -1


# ─────────────────────────────────────────────────────────────────────────── #
# deduplicate tests
# ─────────────────────────────────────────────────────────────────────────── #

class TestDeduplicate:

    def test_removes_exact_duplicates(self):
        events = [
            make_event(eventId="evt-001"),
            make_event(eventId="evt-001"),  # duplicate
            make_event(eventId="evt-002"),
        ]
        result = deduplicate(events)
        assert len(result) == 2

    def test_preserves_all_unique(self):
        events = [
            make_event(eventId="evt-001"),
            make_event(eventId="evt-002"),
            make_event(eventId="evt-003"),
        ]
        result = deduplicate(events)
        assert len(result) == 3

    def test_handles_events_without_id(self):
        events = [
            {"eventName": "TestEvent"},  # no eventId
            {"eventName": "TestEvent"},  # no eventId — NOT deduped (no key to compare)
        ]
        result = deduplicate(events)
        assert len(result) == 2  # both kept (no ID to deduplicate on)


# ─────────────────────────────────────────────────────────────────────────── #
# Integration: full pipeline through normalizer
# ─────────────────────────────────────────────────────────────────────────── #

class TestNormalizeEventsIntegration:

    def test_normalizes_sample_data(self):
        from src.collect_events import load_sample_events
        from src.parse_events   import parse_events

        raw    = load_sample_events()
        parsed = parse_events(raw)
        result = normalize_events(parsed)

        assert len(result) == len(parsed)
        for e in result:
            assert "severity"    in e
            assert "isSuspicious" in e
            assert "isOffHours"  in e

    def test_finds_suspicious_events_in_sample(self):
        from src.collect_events import load_sample_events
        from src.parse_events   import parse_events

        raw    = load_sample_events()
        parsed = parse_events(raw)
        result = normalize_events(parsed)

        suspicious = [e for e in result if e["isSuspicious"]]
        # Sample data includes root login, StopLogging, etc.
        assert len(suspicious) > 0, (
            "Sample data should contain at least one suspicious event"
        )
