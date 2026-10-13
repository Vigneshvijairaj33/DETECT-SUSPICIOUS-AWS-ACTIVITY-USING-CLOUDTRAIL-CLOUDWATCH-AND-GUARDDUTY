"""
collect_events.py
=================
Phase 7 — Collect CloudTrail events from AWS or local sample data.

This module is the entry point for the data pipeline. It reads events
from either:
  a) AWS CloudTrail API (paginated, rate-limited)
  b) A local JSON file (for development/testing without AWS credentials)

Full implementation: Phase 7.
Stub created in: Phase 1 (project scaffold).
"""

import json
import logging
import os
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Iterator

log = logging.getLogger(__name__)

# Default lookback window (hours)
DEFAULT_LOOKBACK_HOURS = 24
# Max events per API page
MAX_RESULTS_PER_PAGE = 50


def load_sample_events(path: str | None = None) -> list[dict]:
    """
    Load synthetic CloudTrail events from a local JSON file.
    Used for development, CI, and demos without AWS credentials.

    Args:
        path: Path to the JSON file. Defaults to sample_data/sample_cloudtrail_events.json

    Returns:
        List of CloudTrail event records.
    """
    if path is None:
        root = Path(__file__).resolve().parent.parent
        path = root / "sample_data" / "sample_cloudtrail_events.json"

    log.info("Loading sample events from: %s", path)
    with open(path) as f:
        data = json.load(f)

    records = data.get("Records", [])
    log.info("Loaded %d sample events.", len(records))
    return records


def collect_from_cloudtrail_api(
    region: str,
    lookback_hours: int = DEFAULT_LOOKBACK_HOURS,
) -> Iterator[dict]:
    """
    Collect CloudTrail events via the LookupEvents API.

    NOTE: LookupEvents returns the last 90 days of management events.
          It only returns events recorded AFTER the trail was enabled.
          For long-term storage, read directly from S3.

    Args:
        region: AWS region name.
        lookback_hours: How many hours back to look.

    Yields:
        Individual CloudTrail event dictionaries.

    Full implementation: Phase 7.
    """
    # Phase 7 implementation placeholder
    log.info(
        "collect_from_cloudtrail_api: Phase 7 implementation. "
        "Use load_sample_events() for now."
    )
    raise NotImplementedError("Full implementation in Phase 7.")


def collect_events(
    source: str = "local",
    region: str = "us-east-1",
    lookback_hours: int = DEFAULT_LOOKBACK_HOURS,
    sample_path: str | None = None,
) -> list[dict]:
    """
    Main collection entry point.

    Args:
        source: 'local' for sample data, 'aws' for live CloudTrail API.
        region: AWS region (used when source='aws').
        lookback_hours: Lookback window (used when source='aws').
        sample_path: Custom path to local sample data.

    Returns:
        List of CloudTrail event records.
    """
    if source == "local":
        return load_sample_events(sample_path)
    elif source == "aws":
        return list(collect_from_cloudtrail_api(region, lookback_hours))
    else:
        raise ValueError(f"Unknown source '{source}'. Use 'local' or 'aws'.")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    events = collect_events(source="local")
    print(f"Collected {len(events)} events.")
    for e in events[:3]:
        print(f"  {e.get('eventTime')} | {e.get('eventName')} | "
              f"{e.get('userIdentity', {}).get('userName', 'unknown')}")
