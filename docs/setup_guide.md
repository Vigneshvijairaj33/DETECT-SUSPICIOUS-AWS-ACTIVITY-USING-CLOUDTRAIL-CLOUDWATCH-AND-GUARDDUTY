# Setup Guide

## Phase 1 — Local Environment

### 1. Prerequisites

| Tool | Minimum Version | Download |
|------|----------------|---------|
| Python | 3.9 | https://www.python.org/downloads/ |
| AWS CLI v2 | 2.x | https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html |
| pip | latest | Ships with Python |
| Git | any | https://git-scm.com/ |

### 2. Clone and Install

```bash
# Clone the project
git clone <your-repo-url>
cd aws-suspicious-activity-detector

# Create a virtual environment (strongly recommended)
python -m venv .venv

# Activate (Windows CMD)
.venv\Scripts\activate.bat

# Activate (Windows PowerShell)
.venv\Scripts\Activate.ps1

# Activate (macOS / Linux)
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### 3. Configure Environment

```bash
# Copy the example file
copy .env.example .env       # Windows
cp .env.example .env         # macOS / Linux

# Edit .env with your values:
#   AWS_DEFAULT_REGION=us-east-1
#   AWS_PROFILE=default
#   ALERT_EMAIL=your@email.com
```

### 4. Configure AWS CLI

```bash
# Create or update a named profile
aws configure --profile default

# You will be prompted for:
#   AWS Access Key ID     (from IAM console — NOT root)
#   AWS Secret Access Key (from IAM console — NOT root)
#   Default region name   (e.g. us-east-1)
#   Default output format (json)
```

> **Security note:** Never create access keys for the root account.
> Create an IAM user with the minimum required permissions listed below.

### 5. Verify Setup

```bash
# Local checks only (no AWS credentials required)
python scripts/verify_aws_setup.py --skip-aws

# Full check including live AWS identity verification
python scripts/verify_aws_setup.py
```

### 6. Minimum IAM Policy for Phase 1

Create an IAM policy with this JSON and attach it to your IAM user:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "Phase1VerifyIdentity",
      "Effect": "Allow",
      "Action": [
        "sts:GetCallerIdentity"
      ],
      "Resource": "*"
    },
    {
      "Sid": "Phase1ReadOnlyActivity",
      "Effect": "Allow",
      "Action": [
        "ec2:DescribeInstances",
        "ec2:DescribeSecurityGroups",
        "ec2:DescribeRegions",
        "s3:ListAllMyBuckets",
        "iam:ListUsers",
        "iam:GetAccountPasswordPolicy",
        "cloudtrail:DescribeTrails",
        "guardduty:ListDetectors"
      ],
      "Resource": "*"
    }
  ]
}
```

> Additional permissions for later phases (CloudTrail, CloudWatch, GuardDuty,
> EventBridge, SNS) will be documented at the start of each phase.
> **Do not create AWS resources until you have reviewed Phase 2.**

### 7. Run the Local Pipeline (no AWS required)

```bash
# Run the full local pipeline against synthetic sample data
python src/report_findings.py

# Run unit tests
pytest tests/ -v

# Generate local sample activity summary
python scripts/generate_sample_activity.py --local
```

---

## Cost Considerations (Phase 1 — Local Only)

Phase 1 creates NO AWS resources. The only potential cost is:

- **STS GetCallerIdentity** — Free (always).
- **Read-only EC2/S3/IAM calls** — Free tier or near-zero.

Costs for later phases will be listed before any resource is created.
