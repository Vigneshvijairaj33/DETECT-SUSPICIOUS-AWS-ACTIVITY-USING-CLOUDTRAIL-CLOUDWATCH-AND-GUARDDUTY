"""
generate_sample_activity.py
============================
Phase 3 — Generate safe, authorized test API activity using Boto3.

PURPOSE
-------
This script makes ONLY read-only AWS API calls so that CloudTrail has
events to record. It does NOT:
  - create or delete resources
  - escalate privileges
  - expose data publicly
  - perform any destructive action

All calls are equivalent to what a developer would run to inspect the
state of their account. They are completely safe to run repeatedly.

USAGE
-----
    python scripts/generate_sample_activity.py
    python scripts/generate_sample_activity.py --region us-east-1
    python scripts/generate_sample_activity.py --dry-run   # print what would run
    python scripts/generate_sample_activity.py --local     # use sample_data only (no AWS)

REQUIREMENTS
------------
  - AWS credentials configured (aws configure or environment variables)
  - Minimum IAM permissions: see docs/setup_guide.md Section 3
  - pip install boto3 python-dotenv
"""

import json
import time
import argparse
import logging
import os
from datetime import datetime, timezone
from pathlib import Path

# Load .env if present (never required — just convenient)
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

# --------------------------------------------------------------------------- #
# Logging
# --------------------------------------------------------------------------- #
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
log = logging.getLogger(__name__)


# --------------------------------------------------------------------------- #
# Import boto3 safely
# --------------------------------------------------------------------------- #
try:
    import boto3
    from botocore.exceptions import ClientError, NoCredentialsError, EndpointResolutionError
    BOTO3_AVAILABLE = True
except ImportError:
    BOTO3_AVAILABLE = False
    log.warning("boto3 is not installed. Run: pip install boto3")


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #

def get_boto3_client(service: str, region: str):
    """Return a boto3 client, respecting AWS_PROFILE env var."""
    profile = os.environ.get("AWS_PROFILE", "default")
    session = boto3.Session(profile_name=profile, region_name=region)
    return session.client(service)


def safe_call(description: str, fn, dry_run: bool = False):
    """
    Execute a callable, log the result, and never raise.
    Returns (success: bool, result: dict | None).
    """
    if dry_run:
        log.info("[DRY RUN] Would execute: %s", description)
        return True, None

    log.info("Calling: %s", description)
    try:
        result = fn()
        log.info("  ✓ Success")
        return True, result
    except ClientError as e:
        code = e.response["Error"]["Code"]
        msg  = e.response["Error"]["Message"]
        log.warning("  ✗ ClientError [%s]: %s", code, msg)
        return False, None
    except NoCredentialsError:
        log.error("  ✗ No AWS credentials found. Run: aws configure")
        return False, None
    except Exception as e:
        log.warning("  ✗ Unexpected error: %s", e)
        return False, None


# --------------------------------------------------------------------------- #
# Read-only API calls — safe test activity
# --------------------------------------------------------------------------- #

def run_safe_api_calls(region: str, dry_run: bool) -> list[dict]:
    """
    Execute a set of harmless, read-only API calls.
    Each call generates one CloudTrail management event.
    Returns a list of result summaries.
    """
    if not BOTO3_AVAILABLE:
        log.error("boto3 is required. Run: pip install boto3")
        return []

    results = []
    timestamp = datetime.now(timezone.utc).isoformat()

    # ── STS ─────────────────────────────────────────────────────────────── #
    sts = get_boto3_client("sts", region)

    ok, data = safe_call(
        "STS GetCallerIdentity",
        lambda: sts.get_caller_identity(),
        dry_run=dry_run,
    )
    results.append({
        "call": "sts:GetCallerIdentity",
        "success": ok,
        "timestamp": timestamp,
        "note": "Identifies the current IAM principal",
    })
    if ok and data and not dry_run:
        log.info("  Account: %s | ARN: %s", data.get("Account"), data.get("Arn"))
    time.sleep(0.3)

    # ── EC2 ─────────────────────────────────────────────────────────────── #
    ec2 = get_boto3_client("ec2", region)

    ok, data = safe_call(
        "EC2 DescribeInstances",
        lambda: ec2.describe_instances(MaxResults=5),
        dry_run=dry_run,
    )
    count = 0
    if ok and data:
        count = sum(len(r["Instances"]) for r in data.get("Reservations", []))
    results.append({
        "call": "ec2:DescribeInstances",
        "success": ok,
        "timestamp": timestamp,
        "note": f"Found {count} instance(s) (max 5 returned)",
    })
    time.sleep(0.3)

    ok, data = safe_call(
        "EC2 DescribeSecurityGroups",
        lambda: ec2.describe_security_groups(MaxResults=5),
        dry_run=dry_run,
    )
    sg_count = len(data.get("SecurityGroups", [])) if ok and data else 0
    results.append({
        "call": "ec2:DescribeSecurityGroups",
        "success": ok,
        "timestamp": timestamp,
        "note": f"Found {sg_count} security group(s) (max 5 returned)",
    })
    time.sleep(0.3)

    ok, _ = safe_call(
        "EC2 DescribeRegions",
        lambda: ec2.describe_regions(),
        dry_run=dry_run,
    )
    results.append({
        "call": "ec2:DescribeRegions",
        "success": ok,
        "timestamp": timestamp,
        "note": "Lists available AWS regions",
    })
    time.sleep(0.3)

    # ── S3 ──────────────────────────────────────────────────────────────── #
    s3 = get_boto3_client("s3", region)

    ok, data = safe_call(
        "S3 ListBuckets",
        lambda: s3.list_buckets(),
        dry_run=dry_run,
    )
    bucket_count = len(data.get("Buckets", [])) if ok and data else 0
    results.append({
        "call": "s3:ListBuckets",
        "success": ok,
        "timestamp": timestamp,
        "note": f"Found {bucket_count} S3 bucket(s)",
    })
    time.sleep(0.3)

    # ── IAM (read-only) ──────────────────────────────────────────────────── #
    iam = get_boto3_client("iam", region)

    ok, data = safe_call(
        "IAM ListUsers (first page only)",
        lambda: iam.list_users(MaxItems=5),
        dry_run=dry_run,
    )
    user_count = len(data.get("Users", [])) if ok and data else 0
    results.append({
        "call": "iam:ListUsers",
        "success": ok,
        "timestamp": timestamp,
        "note": f"Found {user_count} IAM user(s) (max 5 returned)",
    })
    time.sleep(0.3)

    ok, _ = safe_call(
        "IAM GetAccountPasswordPolicy",
        lambda: iam.get_account_password_policy(),
        dry_run=dry_run,
    )
    results.append({
        "call": "iam:GetAccountPasswordPolicy",
        "success": ok,
        "timestamp": timestamp,
        "note": "Checks password policy — common security audit call",
    })
    time.sleep(0.3)

    # ── CloudTrail (read-only) ───────────────────────────────────────────── #
    ct = get_boto3_client("cloudtrail", region)

    ok, data = safe_call(
        "CloudTrail DescribeTrails",
        lambda: ct.describe_trails(),
        dry_run=dry_run,
    )
    trail_count = len(data.get("trailList", [])) if ok and data else 0
    results.append({
        "call": "cloudtrail:DescribeTrails",
        "success": ok,
        "timestamp": timestamp,
        "note": f"Found {trail_count} CloudTrail trail(s)",
    })
    time.sleep(0.3)

    # ── GuardDuty (read-only) ────────────────────────────────────────────── #
    gd = get_boto3_client("guardduty", region)

    ok, data = safe_call(
        "GuardDuty ListDetectors",
        lambda: gd.list_detectors(),
        dry_run=dry_run,
    )
    detector_ids = data.get("DetectorIds", []) if ok and data else []
    results.append({
        "call": "guardduty:ListDetectors",
        "success": ok,
        "timestamp": timestamp,
        "note": f"Found {len(detector_ids)} detector(s): {detector_ids}",
    })
    time.sleep(0.3)

    return results


# --------------------------------------------------------------------------- #
# Local-only mode — no AWS needed
# --------------------------------------------------------------------------- #

def run_local_demo() -> list[dict]:
    """
    Load and display the synthetic sample events without any AWS call.
    Useful in environments with no AWS access.
    """
    data_path = (
        Path(__file__).resolve().parent.parent
        / "sample_data"
        / "sample_cloudtrail_events.json"
    )

    if not data_path.exists():
        log.error("Sample data file not found: %s", data_path)
        return []

    with open(data_path) as f:
        data = json.load(f)

    records = data.get("Records", [])
    log.info("Loaded %d synthetic CloudTrail events from sample_data/", len(records))

    summary = []
    for record in records:
        summary.append({
            "eventTime":  record.get("eventTime"),
            "eventName":  record.get("eventName"),
            "eventSource": record.get("eventSource"),
            "user":        record.get("userIdentity", {}).get("userName", "unknown"),
            "sourceIP":    record.get("sourceIPAddress"),
            "errorCode":   record.get("errorCode"),
        })
        log.info(
            "  [%s] %-40s user=%-10s ip=%s error=%s",
            record.get("eventTime", ""),
            record.get("eventName", ""),
            record.get("userIdentity", {}).get("userName", "unknown"),
            record.get("sourceIPAddress", ""),
            record.get("errorCode") or "—",
        )

    return summary


# --------------------------------------------------------------------------- #
# Save results
# --------------------------------------------------------------------------- #

def save_results(results: list[dict], output_dir: Path) -> Path:
    """Save the activity summary to a JSON file in output/."""
    output_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out_path = output_dir / f"activity_summary_{ts}.json"
    with open(out_path, "w") as f:
        json.dump(results, f, indent=2, default=str)
    log.info("Results saved to: %s", out_path)
    return out_path


# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate safe read-only AWS API activity for CloudTrail testing."
    )
    parser.add_argument(
        "--region",
        default=os.environ.get("AWS_DEFAULT_REGION", "us-east-1"),
        help="AWS region to use (default: us-east-1 or $AWS_DEFAULT_REGION)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print what would be called without making real AWS API calls.",
    )
    parser.add_argument(
        "--local",
        action="store_true",
        help="Use local sample_data only — no AWS credentials required.",
    )
    args = parser.parse_args()

    root = Path(__file__).resolve().parent.parent
    output_dir = root / "output"

    log.info("=" * 60)
    log.info("  AWS Suspicious Activity Detector")
    log.info("  Phase 3: Sample Activity Generator")
    log.info("=" * 60)

    if args.local:
        log.info("Running in LOCAL mode — no AWS API calls will be made.")
        results = run_local_demo()
        mode = "local"
    else:
        log.info("Region: %s | Dry-run: %s", args.region, args.dry_run)
        log.info(
            "NOTE: These are read-only calls. They are safe, authorized, "
            "and will appear in CloudTrail as expected management events."
        )
        results = run_safe_api_calls(args.region, dry_run=args.dry_run)
        mode = "dry_run" if args.dry_run else "live"

    # Summary
    if results:
        successful = sum(1 for r in results if r.get("success", True))
        log.info("-" * 60)
        log.info("Activity summary: %d / %d calls succeeded", successful, len(results))

        if not args.dry_run:
            save_results(results, output_dir)

        log.info("")
        log.info("Next steps:")
        if mode == "live":
            log.info("  1. Open CloudTrail Event History in the AWS Console")
            log.info("     and filter by the event names above.")
            log.info("  2. Events may take 5–15 minutes to appear.")
            log.info("  3. If CloudWatch delivery is configured, check the")
            log.info("     log group for matching entries.")
        elif mode == "dry_run":
            log.info("  Re-run without --dry-run to execute live calls.")
        else:
            log.info("  Run the pipeline:  python src/parse_events.py")
    else:
        log.warning("No results were collected.")


if __name__ == "__main__":
    main()
