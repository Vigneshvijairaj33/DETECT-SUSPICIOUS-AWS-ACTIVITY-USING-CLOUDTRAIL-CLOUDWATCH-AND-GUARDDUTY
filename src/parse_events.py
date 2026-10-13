"""
parse_events.py
===============
Phase 7 — Parse raw CloudTrail event JSON into structured records.

Handles:
  - Malformed JSON gracefully
  - Missing or null fields
  - Nested userIdentity structures (IAMUser, Root, AssumedRole, etc.)
  - Redaction of sensitive values (access key IDs in responseElements)

Full implementation: Phase 7.
Stub created in: Phase 1 (project scaffold).
"""

import json
import logging
import re
from typing import Any

log = logging.getLogger(__name__)

# Fields to redact from parsed output
REDACT_PATTERNS = [
    re.compile(r"AKIA[A-Z0-9]{16}"),   # AWS Access Key IDs
    re.compile(r"(?i)secret"),           # anything labelled 'secret'
]

REDACTED_MARKER = "[REDACTED]"


def extract_username(user_identity: dict) -> str:
    """
    Extract a human-readable principal name from a userIdentity block.

    CloudTrail userIdentity has several possible types:
      IAMUser       → userName field
      Root          → 'root'
      AssumedRole   → sessionContext.sessionIssuer.userName or arn
      AWSService    → invokedBy
      FederatedUser → principalId
    """
    if not user_identity:
        return "unknown"

    id_type = user_identity.get("type", "")

    if id_type == "IAMUser":
        return user_identity.get("userName", "unknown-iam-user")
    elif id_type == "Root":
        return "root"
    elif id_type == "AssumedRole":
        session = user_identity.get("sessionContext", {})
        issuer  = session.get("sessionIssuer", {})
        return issuer.get("userName") or user_identity.get("arn", "assumed-role")
    elif id_type == "AWSService":
        return user_identity.get("invokedBy", "aws-service")
    elif id_type == "FederatedUser":
        return user_identity.get("principalId", "federated-user")
    else:
        return user_identity.get("arn") or user_identity.get("principalId") or "unknown"


def redact_sensitive(value: Any) -> Any:
    """
    Recursively redact known sensitive patterns from a parsed structure.
    Operates on strings, dicts, and lists.
    """
    if isinstance(value, str):
        for pattern in REDACT_PATTERNS:
            value = pattern.sub(REDACTED_MARKER, value)
        return value
    elif isinstance(value, dict):
        return {k: redact_sensitive(v) for k, v in value.items()}
    elif isinstance(value, list):
        return [redact_sensitive(item) for item in value]
    return value


def parse_event(raw: dict) -> dict | None:
    """
    Parse a single raw CloudTrail event into a flat, normalised record.

    Returns None if the event cannot be parsed (logged as a warning).
    """
    if not isinstance(raw, dict):
        log.warning("Skipping non-dict event: %s", type(raw))
        return None

    try:
        user_identity = raw.get("userIdentity") or {}

        parsed = {
            # Core identity
            "eventId":        raw.get("eventID", ""),
            "eventTime":      raw.get("eventTime", ""),
            "eventSource":    raw.get("eventSource", ""),
            "eventName":      raw.get("eventName", ""),
            "eventType":      raw.get("eventType", ""),
            "awsRegion":      raw.get("awsRegion", ""),
            # Principal
            "principalType":  user_identity.get("type", ""),
            "userName":       extract_username(user_identity),
            "principalArn":   user_identity.get("arn", ""),
            "accountId":      user_identity.get("accountId", ""),
            # Network
            "sourceIPAddress": raw.get("sourceIPAddress", ""),
            "userAgent":       raw.get("userAgent", ""),
            # Outcome
            "errorCode":    raw.get("errorCode") or "",
            "errorMessage": raw.get("errorMessage") or "",
            "readOnly":     raw.get("readOnly", None),
            # Raw parameters (redacted)
            "requestParameters": redact_sensitive(raw.get("requestParameters")),
            "responseElements":  redact_sensitive(raw.get("responseElements")),
        }
        return parsed

    except Exception as e:
        log.warning("Failed to parse event %s: %s", raw.get("eventID", "?"), e)
        return None


def parse_events(raw_events: list[dict]) -> list[dict]:
    """
    Parse a list of raw CloudTrail events.

    Args:
        raw_events: List of raw event dicts (from collect_events).

    Returns:
        List of parsed event dicts (failed events are excluded with a warning).
    """
    parsed = []
    skipped = 0

    for raw in raw_events:
        result = parse_event(raw)
        if result is not None:
            parsed.append(result)
        else:
            skipped += 1

    log.info("Parsed %d events (%d skipped).", len(parsed), skipped)
    return parsed


if __name__ == "__main__":
    import sys
    sys.path.insert(0, str(__import__("pathlib").Path(__file__).resolve().parent.parent))
    from src.collect_events import load_sample_events

    logging.basicConfig(level=logging.INFO)
    raw = load_sample_events()
    events = parse_events(raw)

    print(f"\nParsed {len(events)} events:\n")
    for e in events:
        print(
            f"  {e['eventTime'][:19]:20s} | "
            f"{e['eventName']:35s} | "
            f"user={e['userName']:10s} | "
            f"ip={e['sourceIPAddress']:15s} | "
            f"error={e['errorCode'] or '—'}"
        )
