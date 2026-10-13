# Testing Guide

## Phase 1 Local Tests (No AWS Credentials Required)

### Run All Unit Tests

```bash
pytest tests/ -v
```

Expected output:

```
tests/test_parser.py::TestExtractUsername::test_iam_user            PASSED
tests/test_parser.py::TestExtractUsername::test_root                PASSED
tests/test_parser.py::TestParseEvent::test_parses_iam_user_event   PASSED
tests/test_parser.py::TestSampleDataIntegration::test_sample_data_parses_without_errors  PASSED
tests/test_normalizer.py::TestClassifySeverity::test_high_severity_events  PASSED
tests/test_normalizer.py::TestNormalizeEventsIntegration::test_finds_suspicious_events_in_sample  PASSED
tests/test_anomaly_detection.py::TestDetectAnomaliesIntegration::test_runs_against_sample_data  PASSED
... (all PASSED)
```

### Run with Coverage Report

```bash
pytest tests/ -v --cov=src --cov-report=term-missing
```

### Run Individual Test Files

```bash
pytest tests/test_parser.py -v
pytest tests/test_normalizer.py -v
pytest tests/test_anomaly_detection.py -v
```

---

## Verification Checklist — Phase 1

| # | Check | How to verify | Expected |
|---|-------|--------------|---------|
| 1 | Python ≥ 3.9 installed | `python --version` | `Python 3.9.x` or higher |
| 2 | pip packages installed | `pip list` | boto3, pandas, scikit-learn, streamlit listed |
| 3 | AWS CLI installed | `aws --version` | `aws-cli/2.x.x` |
| 4 | Project structure present | `verify_aws_setup.py --skip-aws` | All PASS |
| 5 | Sample data file valid | `pytest tests/test_parser.py::TestSampleDataIntegration -v` | PASSED |
| 6 | Parser works | `pytest tests/test_parser.py -v` | All PASSED |
| 7 | Normalizer works | `pytest tests/test_normalizer.py -v` | All PASSED |
| 8 | Anomaly detection works | `pytest tests/test_anomaly_detection.py -v` | All PASSED |
| 9 | Pipeline runs end-to-end | `python src/report_findings.py` | Report printed, CSV and JSON saved |
| 10 | No credentials in git | `git status` | .env not staged |

---

## What the Sample Data Tests Verify

The synthetic dataset in `sample_data/sample_cloudtrail_events.json` contains:

| Event | Expected Trigger |
|-------|-----------------|
| Root ConsoleLogin | R01 — Root activity |
| 3× Bob login failures < 5 min | R02 — Brute-force |
| StopLogging at 02:30 UTC | R03 + R06 — CloudTrail disabled + off-hours |
| AuthorizeSecurityGroupIngress 0.0.0.0/0 | R04 — Open SG rule |
| AttachUserPolicy AdministratorAccess | R05 — IAM privilege change |
| CreateAccessKey at 04:00 UTC | R07 + R06 — New key + off-hours |
| PutBucketPolicy at 03:15 UTC | R08 — S3 policy change |

---

## Troubleshooting

**Tests fail with `ModuleNotFoundError: No module named 'src'`**
Make sure you are running pytest from the project root, not from inside `src/`:
```bash
cd aws-suspicious-activity-detector
pytest tests/ -v
```

**`ImportError: No module named 'boto3'`**
Run: `pip install -r requirements.txt`

**`FileNotFoundError: sample_cloudtrail_events.json`**
Ensure you are running from the project root directory.
