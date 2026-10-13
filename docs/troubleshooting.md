# Troubleshooting Guide

## Local Environment Issues

### Python version too old
**Symptom:** `SyntaxError` on type hints like `str | None`
**Fix:** Install Python 3.10+ from https://www.python.org/downloads/

### pip install fails
**Symptom:** `ERROR: Could not find a version that satisfies the requirement`
**Fix:**
```bash
python -m pip install --upgrade pip
pip install -r requirements.txt
```

### AWS CLI not found
**Symptom:** `verify_aws_setup.py` reports FAIL for AWS CLI
**Fix:** Install from https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html
Then restart your terminal.

---

## AWS Credential Issues

### NoCredentialsError
**Symptom:** `botocore.exceptions.NoCredentialsError: Unable to locate credentials`
**Fix:**
```bash
aws configure --profile default
# Enter your Access Key ID, Secret Access Key, region, and output format
```

### Wrong profile active
**Symptom:** Commands run against wrong account
**Fix:**
```bash
# Check which profile is active
aws sts get-caller-identity

# Use a specific profile
export AWS_PROFILE=my-profile         # macOS/Linux
set AWS_PROFILE=my-profile            # Windows CMD
$env:AWS_PROFILE="my-profile"         # PowerShell
```

### ExpiredTokenException
**Symptom:** `An error occurred (ExpiredTokenException)`
**Fix:** Refresh your temporary credentials (if using SSO or assume-role).

---

## CloudTrail Issues (Phase 2 — not yet active)

### Events not appearing in Event History
- Events take 5–15 minutes to appear.
- Event History only shows management events; data events need explicit configuration.
- Check that the trail is enabled: `aws cloudtrail get-trail-status --name <trail-name>`

### CloudWatch Logs not receiving events
- Verify the IAM role attached to the trail has `logs:CreateLogGroup`,
  `logs:CreateLogStream`, `logs:PutLogEvents`.
- Check the CloudTrail console → Trail → CloudWatch Logs section.

---

## GuardDuty Issues (Phase 5 — not yet active)

### No findings appearing
- GuardDuty requires real threat signals; synthetic read-only calls do not
  generate findings.
- Use the "Generate sample findings" feature in the GuardDuty console to
  create test findings.

### Detector not found
- Confirm GuardDuty is enabled in the correct region.
- `aws guardduty list-detectors --region <region>`

---

## Pipeline Issues

### `FileNotFoundError` for sample data
Run all commands from the project root directory:
```bash
cd aws-suspicious-activity-detector
python src/report_findings.py
```

### Empty findings list
The pipeline produced no findings. This means:
1. No events in the input matched any rule — check your input data.
2. The input file is empty or malformed — run `pytest tests/test_parser.py`.

### ML model file not found
Run training before evaluation:
```bash
python ml/train_model.py
python ml/evaluate_model.py
```
