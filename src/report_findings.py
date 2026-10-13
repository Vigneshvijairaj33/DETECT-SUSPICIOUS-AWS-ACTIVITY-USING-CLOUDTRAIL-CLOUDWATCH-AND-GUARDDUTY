"""
report_findings.py
==================
Phase 7 — Generate a security report from processed events and findings.

Outputs:
  - output/processed_events.csv   (normalised events for analysis)
  - output/security_report.json   (summary + findings)
  - Console summary printed to stdout

Full implementation: Phase 7.
Stub created in: Phase 1 (project scaffold).
"""

import csv
import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path

log = logging.getLogger(__name__)


def save_events_csv(events: list[dict], output_path: Path) -> None:
    """Save normalised events to a CSV file."""
    if not events:
        log.warning("No events to save.")
        return

    output_path.parent.mkdir(parents=True, exist_ok=True)

    # Columns to include in the CSV (omit large nested dicts)
    columns = [
        "eventId", "eventTime", "eventSource", "eventName", "eventType",
        "awsRegion", "principalType", "userName", "principalArn",
        "sourceIPAddress", "userAgent", "errorCode", "errorMessage",
        "readOnly", "severity", "isSuspicious", "isFailed",
        "isRootActivity", "isOffHours", "eventHour", "eventDayOfWeek",
    ]

    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=columns, extrasaction="ignore")
        writer.writeheader()
        for e in events:
            # Convert datetime objects to strings for CSV
            row = {
                k: (v.isoformat() if isinstance(v, datetime) else v)
                for k, v in e.items()
                if k in columns
            }
            writer.writerow(row)

    log.info("Saved %d events to: %s", len(events), output_path)


def build_report(events: list[dict], findings: list[dict]) -> dict:
    """Build a structured security report dictionary."""
    now = datetime.now(timezone.utc).isoformat()

    # ── Event statistics ─────────────────────────────────────────────────── #
    total = len(events)
    failed_events  = [e for e in events if e.get("isFailed")]
    root_events    = [e for e in events if e.get("isRootActivity")]
    offhours_events = [e for e in events if e.get("isOffHours")]
    suspicious     = [e for e in events if e.get("isSuspicious")]

    # Top event names
    from collections import Counter
    event_name_counts = Counter(e.get("eventName", "") for e in events)
    top_events = event_name_counts.most_common(10)

    # Activity by user
    user_counts = Counter(e.get("userName", "unknown") for e in events)
    top_users = user_counts.most_common(10)

    # Activity by source IP
    ip_counts = Counter(e.get("sourceIPAddress", "") for e in events)
    top_ips = ip_counts.most_common(10)

    # Severity breakdown
    severity_counts = Counter(e.get("severity", "info") for e in events)

    # Finding severity breakdown
    finding_severity_counts = Counter(f.get("severity", "info") for f in findings)
    finding_rule_counts     = Counter(f.get("ruleId", "") for f in findings)

    report = {
        "reportGeneratedAt": now,
        "summary": {
            "totalEvents":       total,
            "failedApiCalls":    len(failed_events),
            "rootActivityCount": len(root_events),
            "offHoursEvents":    len(offhours_events),
            "suspiciousEvents":  len(suspicious),
            "totalFindings":     len(findings),
        },
        "severityBreakdown": dict(severity_counts),
        "findingSeverityBreakdown": dict(finding_severity_counts),
        "findingsByRule": dict(finding_rule_counts),
        "topEventNames": [{"event": e, "count": c} for e, c in top_events],
        "topUsers":      [{"user": u, "count": c} for u, c in top_users],
        "topSourceIPs":  [{"ip": i,   "count": c} for i, c in top_ips],
        "findings": findings,
    }
    return report


def save_report_json(report: dict, output_path: Path) -> None:
    """Save the security report to a JSON file."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, default=str)
    log.info("Security report saved to: %s", output_path)


def print_console_summary(report: dict) -> None:
    """Print a human-readable summary to the console."""
    s = report["summary"]
    print("\n" + "=" * 60)
    print("  AWS Security Monitoring — Event Report")
    print("=" * 60)
    print(f"  Generated:          {report['reportGeneratedAt']}")
    print(f"  Total events:       {s['totalEvents']}")
    print(f"  Failed API calls:   {s['failedApiCalls']}")
    print(f"  Root activity:      {s['rootActivityCount']}")
    print(f"  Off-hours events:   {s['offHoursEvents']}")
    print(f"  Suspicious events:  {s['suspiciousEvents']}")
    print(f"  Total findings:     {s['totalFindings']}")

    print("\n  Severity breakdown:")
    for sev, count in sorted(report["severityBreakdown"].items()):
        print(f"    {sev.upper():8s}: {count}")

    print("\n  Top event names:")
    for item in report["topEventNames"][:5]:
        print(f"    {item['count']:4d}x  {item['event']}")

    print("\n  Top users by API calls:")
    for item in report["topUsers"][:5]:
        print(f"    {item['count']:4d}x  {item['user']}")

    if report["findings"]:
        print(f"\n  Findings ({len(report['findings'])}):")
        for f in report["findings"]:
            print(
                f"    [{f.get('ruleId','?')}] [{f.get('severity','?').upper():6s}] "
                f"{f.get('eventTime','')[:19]} | "
                f"{f.get('eventName',''):30s} | "
                f"user={f.get('userName','')}"
            )
    else:
        print("\n  No rule-based findings detected.")

    print("=" * 60 + "\n")


def generate_report(
    events: list[dict],
    findings: list[dict],
    output_dir: Path | None = None,
) -> dict:
    """
    Main entry point: build and save the report.

    Args:
        events:     Normalised events from normalize_events().
        findings:   Findings from detect_anomalies().
        output_dir: Directory for output files. Defaults to project_root/output/.

    Returns:
        The report dict.
    """
    if output_dir is None:
        root = Path(__file__).resolve().parent.parent
        output_dir = root / "output"

    report = build_report(events, findings)
    save_events_csv(events, output_dir / "processed_events.csv")
    save_report_json(report, output_dir / "security_report.json")
    print_console_summary(report)
    return report


if __name__ == "__main__":
    import sys
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from src.collect_events   import load_sample_events
    from src.parse_events     import parse_events
    from src.normalize_events import normalize_events
    from src.detect_anomalies import detect_anomalies

    logging.basicConfig(level=logging.INFO)
    raw      = load_sample_events()
    parsed   = parse_events(raw)
    norm     = normalize_events(parsed)
    findings = detect_anomalies(norm)
    generate_report(norm, findings)
