"""
detect_anomalies.py
====================
Phase 7 / 8 — Rule-based anomaly detection (ML layer added in Phase 8).

Rule-based detection runs first (no ML dependency).
The optional ML layer (Isolation Forest) is loaded when available.

Rules implemented:
  R01 — Root account used
  R02 — Console login failure (≥ 3 in 5 minutes = possible brute-force)
  R03 — CloudTrail logging stopped or deleted
  R04 — Security group opened to 0.0.0.0/0
  R05 — IAM policy attached with admin or wildcard action
  R06 — API activity at off-hours (22:00–06:00 UTC)
  R07 — New access key created
  R08 — S3 bucket policy made public

Full ML implementation: Phase 8.
Stub created in: Phase 1 (project scaffold).
"""

import logging
from collections import defaultdict
from datetime import datetime, timezone, timedelta
from typing import Any

log = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────── #
# Rule definitions
# ─────────────────────────────────────────────────────────────────────────── #

RULES = {
    "R01": "Root account activity detected",
    "R02": "Possible console brute-force: ≥3 login failures within 5 minutes",
    "R03": "CloudTrail logging stopped or deleted",
    "R04": "Security group rule opened to 0.0.0.0/0 (all traffic)",
    "R05": "IAM policy attached — review for privilege escalation",
    "R06": "High-severity API call during off-hours",
    "R07": "New AWS access key created",
    "R08": "S3 bucket policy or ACL modified",
}


def _finding(event: dict, rule_id: str, detail: str = "") -> dict:
    """Build a structured finding dict."""
    return {
        "findingType": "RuleBased",
        "ruleId":      rule_id,
        "ruleName":    RULES.get(rule_id, rule_id),
        "detail":      detail,
        "severity":    event.get("severity", "medium"),
        "eventId":     event.get("eventId", ""),
        "eventTime":   event.get("eventTime", ""),
        "eventName":   event.get("eventName", ""),
        "userName":    event.get("userName", ""),
        "sourceIP":    event.get("sourceIPAddress", ""),
        "awsRegion":   event.get("awsRegion", ""),
    }


# ─────────────────────────────────────────────────────────────────────────── #
# Individual rule checks
# ─────────────────────────────────────────────────────────────────────────── #

def check_root_activity(event: dict) -> list[dict]:
    if event.get("isRootActivity"):
        return [_finding(event, "R01",
                         f"Root used for {event.get('eventName')}")]
    return []


def check_cloudtrail_disabled(event: dict) -> list[dict]:
    dangerous = {"StopLogging", "DeleteTrail", "UpdateTrail", "PutEventSelectors"}
    if event.get("eventName") in dangerous:
        return [_finding(event, "R03",
                         f"CloudTrail modified: {event.get('eventName')}")]
    return []


def check_security_group_open(event: dict) -> list[dict]:
    sg_events = {"AuthorizeSecurityGroupIngress", "AuthorizeSecurityGroupEgress"}
    if event.get("eventName") not in sg_events:
        return []

    params = event.get("requestParameters") or {}
    params_str = str(params)
    if "0.0.0.0/0" in params_str or "::/0" in params_str:
        return [_finding(event, "R04",
                         "SG rule allows traffic from 0.0.0.0/0 or ::/0")]
    return []


def check_iam_policy_change(event: dict) -> list[dict]:
    iam_events = {
        "AttachUserPolicy", "DetachUserPolicy",
        "PutUserPolicy",    "AttachRolePolicy",
        "DetachRolePolicy", "PutRolePolicy",
    }
    if event.get("eventName") in iam_events:
        params = event.get("requestParameters") or {}
        return [_finding(event, "R05",
                         f"IAM change: {event.get('eventName')} | "
                         f"params: {str(params)[:100]}")]
    return []


def check_off_hours_high_severity(event: dict) -> list[dict]:
    if event.get("isOffHours") and event.get("severity") == "high":
        return [_finding(event, "R06",
                         f"High-severity event at off-hours: "
                         f"hour={event.get('eventHour')} UTC")]
    return []


def check_access_key_created(event: dict) -> list[dict]:
    if event.get("eventName") == "CreateAccessKey":
        params = event.get("requestParameters") or {}
        target = params.get("userName", "unknown") if isinstance(params, dict) else "unknown"
        return [_finding(event, "R07",
                         f"Access key created for user: {target}")]
    return []


def check_s3_policy_change(event: dict) -> list[dict]:
    s3_events = {"PutBucketPolicy", "DeleteBucketPolicy", "PutBucketAcl"}
    if event.get("eventName") in s3_events:
        params = event.get("requestParameters") or {}
        bucket = (params.get("bucketName", "unknown")
                  if isinstance(params, dict) else "unknown")
        return [_finding(event, "R08",
                         f"S3 policy/ACL changed on bucket: {bucket}")]
    return []


# ─────────────────────────────────────────────────────────────────────────── #
# Brute-force detection (stateful — requires full event list)
# ─────────────────────────────────────────────────────────────────────────── #

def check_brute_force(events: list[dict]) -> list[dict]:
    """
    Detect ≥3 console login failures for the same user within 5 minutes.
    This rule needs the full event list to find temporal clusters.
    """
    findings = []
    failures: dict[str, list[datetime]] = defaultdict(list)

    for e in events:
        if e.get("eventName") != "ConsoleLogin":
            continue
        if not e.get("isFailed"):
            continue

        user = e.get("userName", "unknown")
        ts   = e.get("eventTimestamp")
        if ts is None:
            continue

        failures[user].append(ts)

    for user, timestamps in failures.items():
        timestamps.sort()
        for i, start in enumerate(timestamps):
            window_end = start + timedelta(minutes=5)
            count = sum(1 for t in timestamps[i:] if t <= window_end)
            if count >= 3:
                findings.append({
                    "findingType": "RuleBased",
                    "ruleId":      "R02",
                    "ruleName":    RULES["R02"],
                    "detail":      f"User '{user}' had {count} login failures "
                                   f"starting at {start.isoformat()}",
                    "severity":    "high",
                    "eventId":     "",
                    "eventTime":   start.isoformat(),
                    "eventName":   "ConsoleLogin",
                    "userName":    user,
                    "sourceIP":    "",
                    "awsRegion":   "",
                })
                break  # one finding per user per check

    return findings


# ─────────────────────────────────────────────────────────────────────────── #
# Main detection function
# ─────────────────────────────────────────────────────────────────────────── #

def detect_anomalies(events: list[dict]) -> list[dict]:
    """
    Run all rules against a list of normalised events.

    Args:
        events: Output from normalize_events.normalize_events().

    Returns:
        List of finding dicts. Empty list = no anomalies detected.
    """
    findings: list[dict] = []

    # Per-event rules
    per_event_rules = [
        check_root_activity,
        check_cloudtrail_disabled,
        check_security_group_open,
        check_iam_policy_change,
        check_off_hours_high_severity,
        check_access_key_created,
        check_s3_policy_change,
    ]

    for event in events:
        for rule_fn in per_event_rules:
            findings.extend(rule_fn(event))

    # Stateful rules (need full list)
    findings.extend(check_brute_force(events))

    log.info("Anomaly detection complete: %d finding(s) from %d event(s).",
             len(findings), len(events))

    # Summary by rule
    from collections import Counter
    rule_counts = Counter(f["ruleId"] for f in findings)
    for rule_id, count in sorted(rule_counts.items()):
        log.info("  %s — %s: %d finding(s)", rule_id, RULES.get(rule_id, "?"), count)

    return findings


if __name__ == "__main__":
    import sys
    sys.path.insert(0, str(__import__("pathlib").Path(__file__).resolve().parent.parent))
    from src.collect_events   import load_sample_events
    from src.parse_events     import parse_events
    from src.normalize_events import normalize_events

    logging.basicConfig(level=logging.INFO)
    raw      = load_sample_events()
    parsed   = parse_events(raw)
    norm     = normalize_events(parsed)
    findings = detect_anomalies(norm)

    print(f"\nFindings ({len(findings)}):\n")
    for f in findings:
        print(
            f"  [{f['ruleId']}] [{f['severity'].upper():6s}] "
            f"{f['eventTime'][:19]:20s} | "
            f"{f['eventName']:35s} | "
            f"user={f['userName']}"
        )
        if f["detail"]:
            print(f"           Detail: {f['detail']}")
