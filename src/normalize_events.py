"""
normalize_events.py
===================
Phase 7 — Normalise parsed CloudTrail events for analysis.

Transformations:
  - Parse ISO 8601 timestamps to UTC datetime objects
  - Add derived time fields (hour, day_of_week, is_off_hours)
  - Classify event severity (info / medium / high)
  - Flag known suspicious event types
  - Deduplicate by eventId

Full implementation: Phase 7.
Stub created in: Phase 1 (project scaffold).
"""

import logging
from datetime import datetime, timezone
from typing import Any

log = logging.getLogger(__name__)

# ── Suspicious event classification ─────────────────────────────────────── #

# HIGH severity — always flag for investigation
HIGH_SEVERITY_EVENTS = {
    "StopLogging",               # CloudTrail disabled
    "DeleteTrail",               # CloudTrail trail deleted
    "UpdateTrail",               # CloudTrail trail modified
    "PutEventSelectors",         # CloudTrail filtering changed
    "AttachUserPolicy",          # IAM policy attached
    "DetachUserPolicy",          # IAM policy detached
    "PutUserPolicy",             # Inline IAM policy added
    "CreateAccessKey",           # New access key created
    "DeleteAccessKey",           # Access key deleted
    "AuthorizeSecurityGroupIngress",   # Inbound rule added to SG
    "AuthorizeSecurityGroupEgress",    # Outbound rule added to SG
    "CreateVpc",                 # VPC creation
    "DeleteVpc",                 # VPC deletion
    "PutBucketPolicy",           # S3 bucket policy changed
    "DeleteBucketPolicy",        # S3 bucket policy removed
    "PutBucketAcl",              # S3 bucket ACL changed
}

# MEDIUM severity — worth investigating in context
MEDIUM_SEVERITY_EVENTS = {
    "ConsoleLogin",              # Could indicate brute-force if repeated failures
    "CreateUser",                # New IAM user created
    "DeleteUser",                # IAM user deleted
    "TerminateInstances",        # EC2 instance terminated
    "RunInstances",              # EC2 instance launched
    "CreateRole",                # IAM role created
    "DeleteRole",                # IAM role deleted
    "GetSecretValue",            # Secrets Manager access
    "DescribeSecret",            # Secrets Manager discovery
    "ListSecrets",               # Secrets Manager enumeration
    "CreateBucket",              # S3 bucket created
    "DeleteBucket",              # S3 bucket deleted
    "ModifyDBInstance",          # RDS instance modified
    "DeleteDBInstance",          # RDS instance deleted
}

# Off-hours threshold: 22:00 – 06:00 UTC
OFF_HOURS_START = 22
OFF_HOURS_END   = 6


def classify_severity(event_name: str, error_code: str) -> str:
    """Return 'high', 'medium', or 'info' for an event."""
    if event_name in HIGH_SEVERITY_EVENTS:
        return "high"
    if event_name in MEDIUM_SEVERITY_EVENTS:
        return "medium"
    if error_code and error_code not in ("", "None"):
        return "medium"   # any error is worth a look
    return "info"


def is_off_hours(hour_utc: int) -> bool:
    """Return True if the hour (UTC) falls outside normal business hours."""
    return hour_utc >= OFF_HOURS_START or hour_utc < OFF_HOURS_END


def parse_timestamp(ts_str: str) -> datetime | None:
    """Parse an ISO 8601 timestamp string to a UTC-aware datetime."""
    if not ts_str:
        return None
    try:
        # Handle both 'Z' suffix and '+00:00'
        ts_str = ts_str.replace("Z", "+00:00")
        dt = datetime.fromisoformat(ts_str)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except ValueError as e:
        log.warning("Could not parse timestamp '%s': %s", ts_str, e)
        return None


def normalize_event(event: dict) -> dict:
    """
    Add derived fields to a parsed event dict.

    Args:
        event: A parsed event from parse_events.parse_event().

    Returns:
        The same dict with additional normalised fields.
    """
    normalised = dict(event)  # shallow copy

    # ── Timestamp ────────────────────────────────────────────────────────── #
    dt = parse_timestamp(event.get("eventTime", ""))
    if dt:
        normalised["eventTimestamp"] = dt
        normalised["eventHour"]      = dt.hour
        normalised["eventDayOfWeek"] = dt.strftime("%A")   # e.g., "Monday"
        normalised["isOffHours"]     = is_off_hours(dt.hour)
    else:
        normalised["eventTimestamp"] = None
        normalised["eventHour"]      = -1
        normalised["eventDayOfWeek"] = "Unknown"
        normalised["isOffHours"]     = False

    # ── Severity ─────────────────────────────────────────────────────────── #
    normalised["severity"] = classify_severity(
        event.get("eventName", ""),
        event.get("errorCode", ""),
    )

    # ── Suspicious flags ─────────────────────────────────────────────────── #
    normalised["isSuspicious"] = (
        normalised["severity"] in ("high", "medium")
        or normalised["isOffHours"]
        or bool(event.get("errorCode"))
        or event.get("userName") == "root"
    )

    # ── Failed API call ──────────────────────────────────────────────────── #
    normalised["isFailed"] = bool(event.get("errorCode"))

    # ── Root activity ────────────────────────────────────────────────────── #
    normalised["isRootActivity"] = event.get("userName") == "root"

    return normalised


def deduplicate(events: list[dict]) -> list[dict]:
    """Remove duplicate events by eventId."""
    seen = set()
    unique = []
    for e in events:
        eid = e.get("eventId")
        if eid and eid in seen:
            log.debug("Duplicate event skipped: %s", eid)
            continue
        if eid:
            seen.add(eid)
        unique.append(e)
    duplicates_removed = len(events) - len(unique)
    if duplicates_removed:
        log.info("Removed %d duplicate event(s).", duplicates_removed)
    return unique


def normalize_events(events: list[dict]) -> list[dict]:
    """
    Normalise a list of parsed CloudTrail events.

    Args:
        events: Output from parse_events.parse_events().

    Returns:
        Normalised, deduplicated list of event dicts.
    """
    normalised = [normalize_event(e) for e in events]
    normalised = deduplicate(normalised)

    high   = sum(1 for e in normalised if e["severity"] == "high")
    medium = sum(1 for e in normalised if e["severity"] == "medium")
    susp   = sum(1 for e in normalised if e["isSuspicious"])
    log.info(
        "Normalised %d events — high: %d, medium: %d, suspicious: %d",
        len(normalised), high, medium, susp
    )
    return normalised


if __name__ == "__main__":
    import sys
    sys.path.insert(0, str(__import__("pathlib").Path(__file__).resolve().parent.parent))
    from src.collect_events import load_sample_events
    from src.parse_events   import parse_events

    logging.basicConfig(level=logging.INFO)
    raw    = load_sample_events()
    parsed = parse_events(raw)
    norm   = normalize_events(parsed)

    print(f"\nNormalised {len(norm)} events:\n")
    for e in norm:
        print(
            f"  [{e['severity'].upper():6s}] "
            f"{e['eventTime'][:19]:20s} | "
            f"{e['eventName']:35s} | "
            f"user={e['userName']:10s} | "
            f"offhours={e['isOffHours']} | "
            f"suspicious={e['isSuspicious']}"
        )
