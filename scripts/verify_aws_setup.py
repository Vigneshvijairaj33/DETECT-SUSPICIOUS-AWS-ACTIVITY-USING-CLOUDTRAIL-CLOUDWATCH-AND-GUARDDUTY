"""
verify_aws_setup.py
===================
Phase 1 — Environment verification script.

Checks every local prerequisite BEFORE touching any AWS resource.
Safe to run with no AWS credentials configured (it will warn you gracefully).

Usage:
    python scripts/verify_aws_setup.py
    python scripts/verify_aws_setup.py --skip-aws   # local checks only
"""

import sys
import os
import json
import subprocess
import argparse
from pathlib import Path

# --------------------------------------------------------------------------- #
# Colour helpers (work on all terminals; fall back to plain text)
# --------------------------------------------------------------------------- #
try:
    from colorama import init, Fore, Style
    init(autoreset=True)
    GREEN  = Fore.GREEN
    RED    = Fore.RED
    YELLOW = Fore.YELLOW
    CYAN   = Fore.CYAN
    RESET  = Style.RESET_ALL
except ImportError:
    GREEN = RED = YELLOW = CYAN = RESET = ""

PASS  = f"{GREEN}[PASS]{RESET}"
FAIL  = f"{RED}[FAIL]{RESET}"
WARN  = f"{YELLOW}[WARN]{RESET}"
INFO  = f"{CYAN}[INFO]{RESET}"


# --------------------------------------------------------------------------- #
# Helper utilities
# --------------------------------------------------------------------------- #

def section(title: str) -> None:
    """Print a visible section header."""
    print(f"\n{'=' * 60}")
    print(f"  {title}")
    print(f"{'=' * 60}")


def run(cmd: list[str]) -> tuple[int, str, str]:
    """Run a subprocess and return (returncode, stdout, stderr)."""
    result = subprocess.run(
        cmd, capture_output=True, text=True, timeout=15
    )
    return result.returncode, result.stdout.strip(), result.stderr.strip()


# --------------------------------------------------------------------------- #
# Check 1 — Python version
# --------------------------------------------------------------------------- #

def check_python_version() -> bool:
    major, minor = sys.version_info[:2]
    required = (3, 9)
    ok = (major, minor) >= required
    status = PASS if ok else FAIL
    print(f"  {status} Python version: {major}.{minor} "
          f"(required >= {required[0]}.{required[1]})")
    if not ok:
        print(f"       Install Python {required[0]}.{required[1]}+ "
              f"from https://www.python.org/downloads/")
    return ok


# --------------------------------------------------------------------------- #
# Check 2 — Required Python packages
# --------------------------------------------------------------------------- #

def check_python_packages() -> bool:
    packages = {
        "boto3":         "AWS SDK — core dependency",
        "botocore":      "Low-level AWS SDK (ships with boto3)",
        "dotenv":        "python-dotenv — loads .env files (import name: dotenv)",
        "pandas":        "Data processing pipeline",
        "numpy":         "Numerical operations for ML",
        "sklearn":       "scikit-learn — anomaly detection (import name: sklearn)",
        "streamlit":     "Local security dashboard",
        "pytest":        "Unit-test runner",
        "moto":          "AWS service mocking for tests",
    }
    all_ok = True
    for module, description in packages.items():
        try:
            __import__(module)
            print(f"  {PASS} {module:15s} — {description}")
        except ImportError:
            print(f"  {FAIL} {module:15s} — {description}")
            print(f"         Run:  pip install -r requirements.txt")
            all_ok = False
    return all_ok


# --------------------------------------------------------------------------- #
# Check 3 — AWS CLI
# --------------------------------------------------------------------------- #

def check_aws_cli() -> bool:
    code, out, err = run(["aws", "--version"])
    if code == 0:
        print(f"  {PASS} AWS CLI installed: {out}")
        return True
    else:
        print(f"  {FAIL} AWS CLI not found.")
        print("         Download: https://docs.aws.amazon.com/cli/latest/"
              "userguide/getting-started-install.html")
        return False


# --------------------------------------------------------------------------- #
# Check 4 — AWS credentials configured
# --------------------------------------------------------------------------- #

def check_aws_credentials() -> bool:
    """
    Check that credentials exist in the environment or credential file.
    Does NOT print key or secret values.
    """
    key   = os.environ.get("AWS_ACCESS_KEY_ID", "")
    token = os.environ.get("AWS_SESSION_TOKEN", "")
    profile = os.environ.get("AWS_PROFILE", "default")

    # Check credential file
    cred_file = Path.home() / ".aws" / "credentials"
    config_file = Path.home() / ".aws" / "config"

    if key:
        print(f"  {PASS} AWS credentials found in environment variables "
              f"(key ID ends …{key[-4:]})")
    elif cred_file.exists():
        print(f"  {PASS} AWS credentials file found: {cred_file}")
    else:
        print(f"  {WARN} No AWS credentials detected.")
        print(f"         Run:  aws configure --profile {profile}")
        print(f"         or set environment variables "
              f"AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY")
        return False

    if config_file.exists():
        print(f"  {PASS} AWS config file found: {config_file}")
    else:
        print(f"  {WARN} AWS config file not found at {config_file}. "
              f"Default region may not be set.")
    return True


# --------------------------------------------------------------------------- #
# Check 5 — Active AWS identity (requires valid credentials)
# --------------------------------------------------------------------------- #

def check_aws_identity() -> bool:
    """Call STS GetCallerIdentity — the cheapest safe AWS API call."""
    code, out, err = run(["aws", "sts", "get-caller-identity", "--output", "json"])
    if code != 0:
        print(f"  {FAIL} Could not verify AWS identity.")
        print(f"         Error: {err[:200]}")
        print(f"         Make sure credentials are valid and region is set.")
        return False

    try:
        identity = json.loads(out)
        account = identity.get("Account", "UNKNOWN")
        arn     = identity.get("Arn", "UNKNOWN")
        user_id = identity.get("UserId", "UNKNOWN")

        # Mask middle digits of account ID for display
        masked = account[:3] + "****" + account[-3:] if len(account) == 12 else account

        print(f"  {PASS} AWS identity verified:")
        print(f"         Account : {masked}")
        print(f"         ARN     : {arn}")
        print(f"         UserID  : {user_id}")

        # Warn if operating as root
        if ":root" in arn:
            print(f"  {WARN} You are authenticated as the ROOT user.")
            print(f"         Best practice: use an IAM user or role instead.")
        return True
    except json.JSONDecodeError:
        print(f"  {FAIL} Unexpected response from STS: {out[:200]}")
        return False


# --------------------------------------------------------------------------- #
# Check 6 — Active AWS region
# --------------------------------------------------------------------------- #

def check_aws_region() -> bool:
    region = os.environ.get("AWS_DEFAULT_REGION") or os.environ.get("AWS_REGION")
    if not region:
        code, out, err = run(["aws", "configure", "get", "region"])
        region = out if code == 0 else None

    if region:
        print(f"  {PASS} AWS region configured: {region}")
        return True
    else:
        print(f"  {WARN} No AWS region configured.")
        print(f"         Set it:  aws configure set region us-east-1")
        print(f"         or add   AWS_DEFAULT_REGION=us-east-1  to your .env file")
        return False


# --------------------------------------------------------------------------- #
# Check 7 — Project directory structure
# --------------------------------------------------------------------------- #

def check_project_structure() -> bool:
    root = Path(__file__).resolve().parent.parent  # project root

    required = [
        "requirements.txt",
        ".gitignore",
        ".env.example",
        "config/config.example.json",
        "scripts/verify_aws_setup.py",
        "sample_data/sample_cloudtrail_events.json",
        "src",
        "ml",
        "dashboard",
        "tests",
        "docs",
    ]

    all_ok = True
    for item in required:
        path = root / item
        if path.exists():
            print(f"  {PASS} {item}")
        else:
            print(f"  {FAIL} Missing: {item}")
            all_ok = False
    return all_ok


# --------------------------------------------------------------------------- #
# Check 8 — .env file (should exist but NOT be committed)
# --------------------------------------------------------------------------- #

def check_env_file() -> bool:
    root = Path(__file__).resolve().parent.parent
    env_path   = root / ".env"
    example    = root / ".env.example"
    gitignore  = root / ".gitignore"

    if not env_path.exists():
        print(f"  {WARN} .env file not found.")
        print(f"         Copy .env.example → .env and fill in your values.")
        ok = False
    else:
        print(f"  {PASS} .env file exists.")
        ok = True

    # Verify .env is git-ignored
    if gitignore.exists():
        content = gitignore.read_text()
        if ".env" in content:
            print(f"  {PASS} .env is listed in .gitignore — credentials protected.")
        else:
            print(f"  {FAIL} .env is NOT in .gitignore — add it immediately!")
            ok = False
    return ok


# --------------------------------------------------------------------------- #
# Check 9 — Sample data file validity
# --------------------------------------------------------------------------- #

def check_sample_data() -> bool:
    root      = Path(__file__).resolve().parent.parent
    data_path = root / "sample_data" / "sample_cloudtrail_events.json"

    if not data_path.exists():
        print(f"  {FAIL} Sample data file not found: {data_path}")
        return False

    try:
        with open(data_path) as f:
            data = json.load(f)
        records = data.get("Records", [])
        print(f"  {PASS} Sample data file is valid JSON "
              f"({len(records)} synthetic events).")
        return True
    except json.JSONDecodeError as e:
        print(f"  {FAIL} Sample data file contains invalid JSON: {e}")
        return False


# --------------------------------------------------------------------------- #
# Summary
# --------------------------------------------------------------------------- #

def print_summary(results: dict[str, bool]) -> None:
    section("SUMMARY")
    passed = sum(1 for v in results.values() if v)
    total  = len(results)

    for check, ok in results.items():
        icon = PASS if ok else FAIL
        print(f"  {icon} {check}")

    print(f"\n  Result: {passed}/{total} checks passed.")

    if passed == total:
        print(f"\n  {GREEN}All checks passed. Environment is ready for Phase 1.{RESET}")
    else:
        failed = [k for k, v in results.items() if not v]
        print(f"\n  {RED}Fix the failing checks before proceeding:{RESET}")
        for f in failed:
            print(f"    - {f}")

    print()


# --------------------------------------------------------------------------- #
# Entry point
# --------------------------------------------------------------------------- #

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Verify the local environment for the AWS Security Monitoring project."
    )
    parser.add_argument(
        "--skip-aws",
        action="store_true",
        help="Skip checks that require live AWS credentials.",
    )
    args = parser.parse_args()

    print("\n" + "=" * 60)
    print("  AWS Suspicious Activity Detector — Environment Check")
    print("  Phase 1: Prerequisites Verification")
    print("=" * 60)

    results: dict[str, bool] = {}

    # ── Local checks ────────────────────────────────────────────────────── #
    section("1. Python Version")
    results["Python >= 3.9"] = check_python_version()

    section("2. Python Packages")
    results["Python packages installed"] = check_python_packages()

    section("3. AWS CLI")
    results["AWS CLI installed"] = check_aws_cli()

    section("4. Project Structure")
    results["Project directories present"] = check_project_structure()

    section("5. Environment File (.env)")
    results[".env configured and git-ignored"] = check_env_file()

    section("6. Sample Data File")
    results["Sample CloudTrail data valid"] = check_sample_data()

    # ── AWS checks (skip if --skip-aws) ─────────────────────────────────── #
    if not args.skip_aws:
        section("7. AWS Credentials")
        creds_ok = check_aws_credentials()
        results["AWS credentials configured"] = creds_ok

        section("8. AWS Region")
        results["AWS region configured"] = check_aws_region()

        if creds_ok:
            section("9. AWS Identity (STS GetCallerIdentity)")
            results["AWS identity verified"] = check_aws_identity()
        else:
            print(f"\n  {WARN} Skipping identity check — no credentials found.")
            results["AWS identity verified"] = False
    else:
        print(f"\n  {INFO} Skipping AWS connectivity checks (--skip-aws flag set).")

    print_summary(results)


if __name__ == "__main__":
    main()
