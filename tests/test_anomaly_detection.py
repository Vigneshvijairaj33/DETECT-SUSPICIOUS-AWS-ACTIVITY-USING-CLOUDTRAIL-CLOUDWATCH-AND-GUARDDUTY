"""
test_anomaly_detection.py
=========================
Unit tests for src/detect_anomalies.py

Run with:  pytest tests/test_anomaly_detection.py -v
"""

import sys
from pathlib import Path
from datetime import datetime, timezone, timedelta

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest
from src.detect_anomalies import (
    detect_anomalies,
    check_root_activity,
    check_cloudtrail_disabled,
    check_security_group_open,
    check_iam_policy_change,
    check_access_key_created,
    check_s3_policy_change,
    check_off_hours_high_severity,
    check_brute_force,
)


# ─────────────────────────────────────────────────────────────────────────── #
# Helpers
# ─────────────────────────────────────────────────────────────────────────── #

def make_norm_event(**overrides) -> dict:
    """Build a minimal normalised event dict."""
    base = {
        "eventId":        "evt-det-001",
        "eventTime":      "2026-10-12T09:00:00Z",
        "eventTimestamp": datetime(2026, 10, 12, 9, 0, 0, tzinfo=timezone.utc),
        "eventSource":    "ec2.amazonaws.com",
        "eventName":      "DescribeInstances",
        "eventType":      "AwsApiCall",
        "awsRegion":      "us-east-1",
        "userName":       "alice",
        "principalType":  "IAMUser",
        "sourceIPAddress": "203.0.113.1",
        "errorCode":      "",
        "severity":       "info",
        "isSuspicious":   False,
        "isFailed":       False,
        "isRootActivity": False,
        "isOffHours":     False,
        "eventHour":      9,
        "requestParameters": None,
        "responseElements":  None,
    }
    base.update(overrides)
    return base


# ─────────────────────────────────────────────────────────────────────────── #
# Individual rule tests
# ─────────────────────────────────────────────────────────────────────────── #

class TestCheckRootActivity:

    def test_detects_root(self):
        e = make_norm_event(userName="root", isRootActivity=True)
        findings = check_root_activity(e)
        assert len(findings) == 1
        assert findings[0]["ruleId"] == "R01"

    def test_no_finding_for_normal_user(self):
        e = make_norm_event(userName="alice", isRootActivity=False)
        findings = check_root_activity(e)
        assert findings == []


class TestCheckCloudTrailDisabled:

    def test_detects_stop_logging(self):
        e = make_norm_event(eventName="StopLogging")
        findings = check_cloudtrail_disabled(e)
        assert len(findings) == 1
        assert findings[0]["ruleId"] == "R03"

    def test_detects_delete_trail(self):
        e = make_norm_event(eventName="DeleteTrail")
        findings = check_cloudtrail_disabled(e)
        assert len(findings) == 1

    def test_detects_update_trail(self):
        e = make_norm_event(eventName="UpdateTrail")
        findings = check_cloudtrail_disabled(e)
        assert len(findings) == 1

    def test_no_finding_for_describe(self):
        e = make_norm_event(eventName="DescribeTrails")
        findings = check_cloudtrail_disabled(e)
        assert findings == []


class TestCheckSecurityGroupOpen:

    def test_detects_open_ingress_cidr(self):
        e = make_norm_event(
            eventName="AuthorizeSecurityGroupIngress",
            requestParameters={"ipPermissions": {"items": [{"cidrIp": "0.0.0.0/0"}]}},
        )
        findings = check_security_group_open(e)
        assert len(findings) == 1
        assert findings[0]["ruleId"] == "R04"

    def test_detects_ipv6_open(self):
        e = make_norm_event(
            eventName="AuthorizeSecurityGroupIngress",
            requestParameters={"ipPermissions": {"items": [{"cidrIpv6": "::/0"}]}},
        )
        findings = check_security_group_open(e)
        assert len(findings) == 1

    def test_no_finding_for_specific_cidr(self):
        e = make_norm_event(
            eventName="AuthorizeSecurityGroupIngress",
            requestParameters={"ipPermissions": {"items": [{"cidrIp": "10.0.0.0/8"}]}},
        )
        findings = check_security_group_open(e)
        assert findings == []

    def test_no_finding_for_non_sg_event(self):
        e = make_norm_event(eventName="DescribeInstances")
        findings = check_security_group_open(e)
        assert findings == []


class TestCheckIAMPolicyChange:

    def test_detects_attach_user_policy(self):
        e = make_norm_event(
            eventName="AttachUserPolicy",
            requestParameters={"policyArn": "arn:aws:iam::aws:policy/AdministratorAccess"},
        )
        findings = check_iam_policy_change(e)
        assert len(findings) == 1
        assert findings[0]["ruleId"] == "R05"

    def test_detects_put_user_policy(self):
        e = make_norm_event(eventName="PutUserPolicy")
        findings = check_iam_policy_change(e)
        assert len(findings) == 1

    def test_no_finding_for_read_only_iam(self):
        e = make_norm_event(eventName="ListUsers")
        findings = check_iam_policy_change(e)
        assert findings == []


class TestCheckAccessKeyCreated:

    def test_detects_create_access_key(self):
        e = make_norm_event(
            eventName="CreateAccessKey",
            requestParameters={"userName": "service-account"},
        )
        findings = check_access_key_created(e)
        assert len(findings) == 1
        assert findings[0]["ruleId"] == "R07"
        assert "service-account" in findings[0]["detail"]

    def test_no_finding_for_other_events(self):
        e = make_norm_event(eventName="ListAccessKeys")
        findings = check_access_key_created(e)
        assert findings == []


class TestCheckS3PolicyChange:

    def test_detects_put_bucket_policy(self):
        e = make_norm_event(
            eventName="PutBucketPolicy",
            requestParameters={"bucketName": "my-data-bucket"},
        )
        findings = check_s3_policy_change(e)
        assert len(findings) == 1
        assert findings[0]["ruleId"] == "R08"
        assert "my-data-bucket" in findings[0]["detail"]

    def test_detects_delete_bucket_policy(self):
        e = make_norm_event(eventName="DeleteBucketPolicy")
        findings = check_s3_policy_change(e)
        assert len(findings) == 1

    def test_no_finding_for_list_buckets(self):
        e = make_norm_event(eventName="ListBuckets")
        findings = check_s3_policy_change(e)
        assert findings == []


class TestCheckOffHoursHighSeverity:

    def test_flags_high_severity_at_3am(self):
        e = make_norm_event(
            eventName="StopLogging",
            severity="high",
            isOffHours=True,
            eventHour=3,
        )
        findings = check_off_hours_high_severity(e)
        assert len(findings) == 1
        assert findings[0]["ruleId"] == "R06"

    def test_no_flag_for_high_during_business_hours(self):
        e = make_norm_event(
            eventName="StopLogging",
            severity="high",
            isOffHours=False,
            eventHour=10,
        )
        findings = check_off_hours_high_severity(e)
        assert findings == []

    def test_no_flag_for_info_at_off_hours(self):
        e = make_norm_event(
            eventName="DescribeInstances",
            severity="info",
            isOffHours=True,
        )
        findings = check_off_hours_high_severity(e)
        assert findings == []


# ─────────────────────────────────────────────────────────────────────────── #
# Brute-force detection tests
# ─────────────────────────────────────────────────────────────────────────── #

class TestCheckBruteForce:

    def _make_login_failure(self, username: str, offset_seconds: int) -> dict:
        base_time = datetime(2026, 10, 12, 8, 0, 0, tzinfo=timezone.utc)
        ts = base_time + timedelta(seconds=offset_seconds)
        return make_norm_event(
            eventName="ConsoleLogin",
            userName=username,
            isFailed=True,
            errorCode="Failed authentication",
            eventTimestamp=ts,
            eventTime=ts.isoformat(),
        )

    def test_detects_three_failures_within_5_minutes(self):
        events = [
            self._make_login_failure("bob", 0),
            self._make_login_failure("bob", 60),
            self._make_login_failure("bob", 120),
        ]
        findings = check_brute_force(events)
        assert len(findings) == 1
        assert findings[0]["ruleId"] == "R02"
        assert findings[0]["userName"] == "bob"

    def test_no_detection_for_two_failures(self):
        events = [
            self._make_login_failure("bob", 0),
            self._make_login_failure("bob", 60),
        ]
        findings = check_brute_force(events)
        assert findings == []

    def test_no_detection_when_spread_over_10_minutes(self):
        events = [
            self._make_login_failure("bob", 0),
            self._make_login_failure("bob", 300),
            self._make_login_failure("bob", 700),
        ]
        findings = check_brute_force(events)
        assert findings == []

    def test_detects_per_user_independently(self):
        events = [
            self._make_login_failure("alice", 0),
            self._make_login_failure("alice", 30),
            self._make_login_failure("alice", 60),
            self._make_login_failure("bob",   0),
            self._make_login_failure("bob",   30),
            self._make_login_failure("bob",   60),
        ]
        findings = check_brute_force(events)
        users = {f["userName"] for f in findings}
        assert "alice" in users
        assert "bob"   in users

    def test_no_detection_for_successful_logins(self):
        events = [
            make_norm_event(
                eventName="ConsoleLogin",
                userName="alice",
                isFailed=False,
                eventTimestamp=datetime(2026, 10, 12, 8, i, 0, tzinfo=timezone.utc),
            )
            for i in range(5)
        ]
        findings = check_brute_force(events)
        assert findings == []


# ─────────────────────────────────────────────────────────────────────────── #
# Full pipeline integration
# ─────────────────────────────────────────────────────────────────────────── #

class TestDetectAnomaliesIntegration:

    def test_runs_against_sample_data(self):
        from src.collect_events   import load_sample_events
        from src.parse_events     import parse_events
        from src.normalize_events import normalize_events

        raw      = load_sample_events()
        parsed   = parse_events(raw)
        norm     = normalize_events(parsed)
        findings = detect_anomalies(norm)

        # Sample data contains: root login, StopLogging, IAM policy attach, etc.
        assert len(findings) > 0, (
            "Sample data should trigger at least one rule finding"
        )

    def test_finding_has_required_fields(self):
        from src.collect_events   import load_sample_events
        from src.parse_events     import parse_events
        from src.normalize_events import normalize_events

        raw      = load_sample_events()
        parsed   = parse_events(raw)
        norm     = normalize_events(parsed)
        findings = detect_anomalies(norm)

        required_fields = {
            "findingType", "ruleId", "ruleName", "detail",
            "severity", "eventName", "userName",
        }
        for f in findings:
            for field in required_fields:
                assert field in f, f"Finding missing field '{field}': {f}"

    def test_r01_triggered_for_root_in_sample(self):
        from src.collect_events   import load_sample_events
        from src.parse_events     import parse_events
        from src.normalize_events import normalize_events

        raw      = load_sample_events()
        parsed   = parse_events(raw)
        norm     = normalize_events(parsed)
        findings = detect_anomalies(norm)

        r01_findings = [f for f in findings if f["ruleId"] == "R01"]
        assert len(r01_findings) >= 1, "R01 should trigger on root ConsoleLogin in sample"

    def test_r02_triggered_for_brute_force_in_sample(self):
        from src.collect_events   import load_sample_events
        from src.parse_events     import parse_events
        from src.normalize_events import normalize_events

        raw      = load_sample_events()
        parsed   = parse_events(raw)
        norm     = normalize_events(parsed)
        findings = detect_anomalies(norm)

        r02_findings = [f for f in findings if f["ruleId"] == "R02"]
        assert len(r02_findings) >= 1, (
            "R02 should trigger: sample has 3 login failures in < 5 minutes for 'bob'"
        )
