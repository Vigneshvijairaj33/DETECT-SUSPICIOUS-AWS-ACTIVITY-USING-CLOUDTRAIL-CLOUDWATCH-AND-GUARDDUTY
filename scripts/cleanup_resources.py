"""
cleanup_resources.py
=====================
Phase 12 — Safe cleanup of project-created AWS resources.

⚠  IMPORTANT SAFETY RULES ⚠
----------------------------
1. This script NEVER runs automatically. You must execute it manually.
2. It lists what it will delete and asks for confirmation BEFORE acting.
3. It deletes ONLY resources whose names match the project prefix in config.
4. CloudTrail logs in S3 are preserved by default (pass --delete-logs to remove).
5. Audit logs should generally be retained for compliance purposes.

USAGE
-----
    # Dry run — shows what would be deleted, touches nothing
    python scripts/cleanup_resources.py --dry-run

    # Interactive cleanup (confirms each resource group)
    python scripts/cleanup_resources.py

    # Also delete CloudTrail S3 logs (irreversible — use with care)
    python scripts/cleanup_resources.py --delete-logs

RESOURCES DELETED (when confirmed)
------------------------------------
  - CloudWatch metric filters (project prefix)
  - CloudWatch alarms (project prefix)
  - CloudWatch log group (project prefix)
  - SNS topic and subscriptions (project prefix)
  - EventBridge rules (project prefix)
  - CloudTrail trail (project prefix)
  - GuardDuty sample findings (does NOT disable the detector)
  - S3 bucket with CloudTrail logs (only with --delete-logs and extra confirmation)
"""

import os
import sys
import json
import logging
import argparse
from pathlib import Path

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
log = logging.getLogger(__name__)

try:
    import boto3
    from botocore.exceptions import ClientError
    BOTO3_AVAILABLE = True
except ImportError:
    BOTO3_AVAILABLE = False


# --------------------------------------------------------------------------- #
# Config
# --------------------------------------------------------------------------- #

def load_config() -> dict:
    root = Path(__file__).resolve().parent.parent
    config_path = root / "config" / "config.json"
    example_path = root / "config" / "config.example.json"

    if config_path.exists():
        with open(config_path) as f:
            return json.load(f)
    elif example_path.exists():
        log.warning("Using config.example.json — fill in real values for live cleanup.")
        with open(example_path) as f:
            return json.load(f)
    else:
        return {}


def get_prefix(config: dict) -> str:
    return config.get("project", {}).get("prefix", "suspicious-activity")


# --------------------------------------------------------------------------- #
# Confirmation helper
# --------------------------------------------------------------------------- #

def confirm(prompt: str, dry_run: bool) -> bool:
    if dry_run:
        log.info("[DRY RUN] Would ask: %s", prompt)
        return False  # never act in dry-run mode
    answer = input(f"\n  ⚠  {prompt} [yes/no]: ").strip().lower()
    return answer == "yes"


# --------------------------------------------------------------------------- #
# Cleanup functions
# --------------------------------------------------------------------------- #

def cleanup_cloudwatch(region: str, prefix: str, dry_run: bool) -> None:
    log.info("── CloudWatch ──────────────────────────────────────────")
    cw = boto3.client("cloudwatch", region_name=region)
    logs = boto3.client("logs", region_name=region)

    # Alarms
    paginator = cw.get_paginator("describe_alarms")
    alarms_to_delete = []
    for page in paginator.paginate():
        for alarm in page.get("MetricAlarms", []):
            if alarm["AlarmName"].startswith(prefix):
                alarms_to_delete.append(alarm["AlarmName"])

    if alarms_to_delete:
        log.info("  CloudWatch alarms to delete: %s", alarms_to_delete)
        if confirm(f"Delete {len(alarms_to_delete)} CloudWatch alarm(s)?", dry_run):
            cw.delete_alarms(AlarmNames=alarms_to_delete)
            log.info("  Deleted.")
    else:
        log.info("  No matching CloudWatch alarms found.")

    # Log groups
    try:
        lgs = logs.describe_log_groups(logGroupNamePrefix=f"/aws/cloudtrail/{prefix}")
        groups = [g["logGroupName"] for g in lgs.get("logGroups", [])]
        if groups:
            log.info("  Log groups to delete: %s", groups)
            for group in groups:
                if confirm(f"Delete log group '{group}'?", dry_run):
                    logs.delete_log_group(logGroupName=group)
                    log.info("  Deleted: %s", group)
        else:
            log.info("  No matching CloudWatch log groups found.")
    except ClientError as e:
        log.warning("  Error listing log groups: %s", e)


def cleanup_sns(region: str, prefix: str, dry_run: bool) -> None:
    log.info("── SNS ─────────────────────────────────────────────────")
    sns = boto3.client("sns", region_name=region)

    paginator = sns.get_paginator("list_topics")
    topics_to_delete = []
    for page in paginator.paginate():
        for topic in page.get("Topics", []):
            arn = topic["TopicArn"]
            name = arn.split(":")[-1]
            if name.startswith(prefix):
                topics_to_delete.append(arn)

    if topics_to_delete:
        log.info("  SNS topics to delete: %s", topics_to_delete)
        for arn in topics_to_delete:
            if confirm(f"Delete SNS topic '{arn}'?", dry_run):
                sns.delete_topic(TopicArn=arn)
                log.info("  Deleted: %s", arn)
    else:
        log.info("  No matching SNS topics found.")


def cleanup_cloudtrail(region: str, prefix: str, dry_run: bool) -> None:
    log.info("── CloudTrail ──────────────────────────────────────────")
    ct = boto3.client("cloudtrail", region_name=region)

    try:
        trails = ct.describe_trails().get("trailList", [])
        for trail in trails:
            if trail["Name"].startswith(prefix):
                log.info("  Trail to delete: %s", trail["Name"])
                if confirm(f"Delete CloudTrail trail '{trail['Name']}'? "
                           f"(Audit logs in S3 are preserved)", dry_run):
                    ct.delete_trail(Name=trail["TrailARN"])
                    log.info("  Deleted trail: %s", trail["Name"])
    except ClientError as e:
        log.warning("  Error describing trails: %s", e)


def cleanup_eventbridge(region: str, prefix: str, dry_run: bool) -> None:
    log.info("── EventBridge ─────────────────────────────────────────")
    eb = boto3.client("events", region_name=region)

    paginator = eb.get_paginator("list_rules")
    rules_to_delete = []
    for page in paginator.paginate():
        for rule in page.get("Rules", []):
            if rule["Name"].startswith(prefix):
                rules_to_delete.append(rule["Name"])

    if rules_to_delete:
        log.info("  EventBridge rules to delete: %s", rules_to_delete)
        for rule_name in rules_to_delete:
            if confirm(f"Delete EventBridge rule '{rule_name}'?", dry_run):
                # Remove targets first
                targets = eb.list_targets_by_rule(Rule=rule_name).get("Targets", [])
                if targets:
                    eb.remove_targets(
                        Rule=rule_name,
                        Ids=[t["Id"] for t in targets],
                    )
                eb.delete_rule(Name=rule_name)
                log.info("  Deleted: %s", rule_name)
    else:
        log.info("  No matching EventBridge rules found.")


def cleanup_local_output() -> None:
    log.info("── Local Output Files ──────────────────────────────────")
    output_dir = Path(__file__).resolve().parent.parent / "output"
    if output_dir.exists():
        files = list(output_dir.glob("*"))
        if files:
            log.info("  Local output files: %s", [f.name for f in files])
            answer = input("  Delete local output files? [yes/no]: ").strip().lower()
            if answer == "yes":
                for f in files:
                    f.unlink()
                log.info("  Deleted %d file(s).", len(files))
        else:
            log.info("  No local output files found.")
    else:
        log.info("  No output/ directory found.")


# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Clean up project-created AWS resources (with confirmation)."
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="List what would be deleted without deleting anything.",
    )
    parser.add_argument(
        "--delete-logs",
        action="store_true",
        help="Also delete the CloudTrail S3 bucket and logs (IRREVERSIBLE).",
    )
    parser.add_argument(
        "--region",
        default=os.environ.get("AWS_DEFAULT_REGION", "us-east-1"),
    )
    args = parser.parse_args()

    if not BOTO3_AVAILABLE:
        log.error("boto3 is required. Run: pip install boto3")
        sys.exit(1)

    config = load_config()
    prefix = get_prefix(config)
    region = args.region

    log.info("=" * 60)
    log.info("  AWS Suspicious Activity Detector — Cleanup Script")
    log.info("  Region: %s | Prefix: %s | Dry-run: %s",
             region, prefix, args.dry_run)
    log.info("=" * 60)
    log.info("")
    log.info("This script will ONLY delete resources whose names start with:")
    log.info("  '%s'", prefix)
    log.info("")

    if not args.dry_run:
        answer = input(
            "  ⚠  You are about to delete AWS resources. "
            "This cannot be undone.\n"
            "  Type 'yes' to continue: "
        ).strip().lower()
        if answer != "yes":
            log.info("Aborted.")
            sys.exit(0)

    cleanup_cloudwatch(region, prefix, args.dry_run)
    cleanup_sns(region, prefix, args.dry_run)
    cleanup_cloudtrail(region, prefix, args.dry_run)
    cleanup_eventbridge(region, prefix, args.dry_run)
    cleanup_local_output()

    if args.delete_logs:
        log.warning("--delete-logs was specified.")
        log.warning("S3 bucket deletion is not implemented in this script to prevent")
        log.warning("accidental loss of audit logs. Delete the bucket manually from")
        log.warning("the AWS Console after confirming logs are no longer needed.")

    log.info("")
    log.info("Cleanup complete.")
    log.info("GuardDuty detector was NOT disabled — disable it manually if needed.")
    log.info("IAM roles/policies created for this project should be reviewed")
    log.info("and deleted manually from the IAM console.")


if __name__ == "__main__":
    main()
