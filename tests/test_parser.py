"""
test_parser.py
==============
Unit tests for src/parse_events.py

Run with:  pytest tests/test_parser.py -v
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest
from src.parse_events import parse_event, parse_events, extract_username, redact_sensitive


# ─────────────────────────────────────────────────────────────────────────── #
# Fixtures
# ─────────────────────────────────────────────────────────────────────────── #

def iam_user_event() -> dict:
    return {
        "eventVersion": "1.09",
        "userIdentity": {
            "type": "IAMUser",
            "principalId": "AIDATEST001",
            "arn": "arn:aws:iam::123456789012:user/testuser",
            "accountId": "123456789012",
            "userName": "testuser",
        },
        "eventTime": "2026-10-12T08:00:00Z",
        "eventSource": "ec2.amazonaws.com",
        "eventName": "DescribeInstances",
        "awsRegion": "us-east-1",
        "sourceIPAddress": "203.0.113.1",
        "userAgent": "aws-cli/2.15.0",
        "requestParameters": None,
        "responseElements": None,
        "errorCode": None,
        "errorMessage": None,
        "requestID": "req-test-001",
        "eventID": "evt-test-001",
        "eventType": "AwsApiCall",
        "readOnly": True,
    }


def root_event() -> dict:
    return {
        "eventVersion": "1.09",
        "userIdentity": {
            "type": "Root",
            "principalId": "123456789012",
            "arn": "arn:aws:iam::123456789012:root",
            "accountId": "123456789012",
        },
        "eventTime": "2026-10-12T02:00:00Z",
        "eventSource": "signin.amazonaws.com",
        "eventName": "ConsoleLogin",
        "awsRegion": "us-east-1",
        "sourceIPAddress": "198.51.100.1",
        "userAgent": "Mozilla/5.0",
        "requestParameters": None,
        "responseElements": {"ConsoleLogin": "Success"},
        "errorCode": None,
        "errorMessage": None,
        "requestID": "req-test-002",
        "eventID": "evt-test-002",
        "eventType": "AwsConsoleSignIn",
        "readOnly": False,
    }


def failed_login_event() -> dict:
    return {
        "eventVersion": "1.09",
        "userIdentity": {
            "type": "IAMUser",
            "principalId": "AIDATEST002",
            "arn": "arn:aws:iam::123456789012:user/baduser",
            "accountId": "123456789012",
            "userName": "baduser",
        },
        "eventTime": "2026-10-12T09:00:00Z",
        "eventSource": "signin.amazonaws.com",
        "eventName": "ConsoleLogin",
        "awsRegion": "us-east-1",
        "sourceIPAddress": "192.0.2.50",
        "userAgent": "Mozilla/5.0",
        "requestParameters": None,
        "responseElements": {"ConsoleLogin": "Failure"},
        "errorCode": "Failed authentication",
        "errorMessage": "Failed authentication",
        "requestID": "req-test-003",
        "eventID": "evt-test-003",
        "eventType": "AwsConsoleSignIn",
        "readOnly": False,
    }


# ─────────────────────────────────────────────────────────────────────────── #
# extract_username tests
# ─────────────────────────────────────────────────────────────────────────── #

class TestExtractUsername:

    def test_iam_user(self):
        identity = {"type": "IAMUser", "userName": "alice"}
        assert extract_username(identity) == "alice"

    def test_root(self):
        identity = {"type": "Root", "principalId": "123456789012"}
        assert extract_username(identity) == "root"

    def test_assumed_role_with_session(self):
        identity = {
            "type": "AssumedRole",
            "sessionContext": {
                "sessionIssuer": {
                    "userName": "my-role"
                }
            },
        }
        assert extract_username(identity) == "my-role"

    def test_aws_service(self):
        identity = {"type": "AWSService", "invokedBy": "lambda.amazonaws.com"}
        assert extract_username(identity) == "lambda.amazonaws.com"

    def test_empty_identity(self):
        assert extract_username({}) == "unknown"

    def test_none_identity(self):
        assert extract_username(None) == "unknown"


# ─────────────────────────────────────────────────────────────────────────── #
# redact_sensitive tests
# ─────────────────────────────────────────────────────────────────────────── #

class TestRedactSensitive:

    def test_redacts_access_key_in_string(self):
        result = redact_sensitive("Key: AKIAIOSFODNN7EXAMPLE")
        assert "AKIA" not in result
        assert "[REDACTED]" in result

    def test_redacts_access_key_in_dict(self):
        data = {"accessKeyId": "AKIAIOSFODNN7EXAMPLE", "other": "safe"}
        result = redact_sensitive(data)
        assert "AKIA" not in str(result)

    def test_redacts_access_key_in_nested_list(self):
        data = [{"key": "AKIAIOSFODNN7EXAMPLE"}]
        result = redact_sensitive(data)
        assert "AKIA" not in str(result)

    def test_non_string_passthrough(self):
        assert redact_sensitive(42) == 42
        assert redact_sensitive(None) is None
        assert redact_sensitive(True) is True

    def test_safe_string_unchanged(self):
        assert redact_sensitive("hello world") == "hello world"


# ─────────────────────────────────────────────────────────────────────────── #
# parse_event tests
# ─────────────────────────────────────────────────────────────────────────── #

class TestParseEvent:

    def test_parses_iam_user_event(self):
        result = parse_event(iam_user_event())
        assert result is not None
        assert result["eventName"]  == "DescribeInstances"
        assert result["userName"]   == "testuser"
        assert result["eventSource"] == "ec2.amazonaws.com"
        assert result["awsRegion"]  == "us-east-1"
        assert result["errorCode"]  == ""

    def test_parses_root_event(self):
        result = parse_event(root_event())
        assert result is not None
        assert result["userName"] == "root"
        assert result["principalType"] == "Root"

    def test_parses_failed_login(self):
        result = parse_event(failed_login_event())
        assert result is not None
        assert result["errorCode"] == "Failed authentication"

    def test_returns_none_for_non_dict(self):
        assert parse_event("not a dict") is None
        assert parse_event(None) is None
        assert parse_event(42) is None

    def test_handles_missing_fields_gracefully(self):
        # Minimal event — most fields missing
        minimal = {"eventID": "min-001", "eventName": "TestEvent"}
        result = parse_event(minimal)
        assert result is not None
        assert result["eventName"] == "TestEvent"
        assert result["userName"] == "unknown"
        assert result["errorCode"] == ""

    def test_eventid_preserved(self):
        result = parse_event(iam_user_event())
        assert result["eventId"] == "evt-test-001"


# ─────────────────────────────────────────────────────────────────────────── #
# parse_events (batch) tests
# ─────────────────────────────────────────────────────────────────────────── #

class TestParseEvents:

    def test_parses_multiple_events(self):
        raw = [iam_user_event(), root_event(), failed_login_event()]
        results = parse_events(raw)
        assert len(results) == 3

    def test_skips_non_dict_entries(self):
        raw = [iam_user_event(), "invalid", None, 42, root_event()]
        results = parse_events(raw)
        # Should return only the two valid dict events
        assert len(results) == 2

    def test_empty_list(self):
        assert parse_events([]) == []

    def test_all_invalid(self):
        assert parse_events(["bad", None, 123]) == []


# ─────────────────────────────────────────────────────────────────────────── #
# Integration: sample data file
# ─────────────────────────────────────────────────────────────────────────── #

class TestSampleDataIntegration:

    def test_sample_data_parses_without_errors(self):
        from src.collect_events import load_sample_events
        raw = load_sample_events()
        assert len(raw) > 0, "Sample data should contain at least one event"
        results = parse_events(raw)
        assert len(results) == len(raw), (
            "All synthetic sample events should parse without errors"
        )

    def test_sample_data_has_expected_fields(self):
        from src.collect_events import load_sample_events
        raw = load_sample_events()
        results = parse_events(raw)
        for r in results:
            assert "eventId"   in r
            assert "eventName" in r
            assert "userName"  in r
            assert "eventTime" in r
