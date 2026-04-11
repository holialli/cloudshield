# CloudShield

CloudShield is a modular Python CSPM tool for AWS posture checks and targeted remediation.

## What It Scans

- IAM: root MFA status, access key age over 90 days, and wildcard IAM policies.
- S3: public buckets and missing S3 Public Access Block.
- EC2: security groups that expose ports 22 or 3389 to `0.0.0.0/0`.

Each finding is mapped to a CIS AWS Foundations Benchmark control.

## Requirements

- Python 3.10+
- AWS credentials available through an instance profile or local AWS profile chain
- Optional role assumption using `AWS_ROLE_ARN`

## Install

```bash
pip install -r requirements.txt
```

## Configuration

Use environment variables or a `.env` file:

```env
AWS_REGION=us-east-1
AWS_ROLE_ARN=arn:aws:iam::123456789012:role/SecurityAuditRole
AWS_EXTERNAL_ID=optional-external-id
CLOUDSHIELD_REPORT_PATH=cloudshield_report.pdf
```

If `AWS_ROLE_ARN` is set, CloudShield assumes that role through STS after creating a base `boto3.Session`.

## Run

```bash
python main.py
```

The tool runs the scanners in parallel, remediates high severity S3 findings by enabling bucket-level Public Access Block, and writes a PDF report.

## GitHub Actions Integration

CloudShield fits into a compliance workflow by running on a schedule or on pull requests. Store AWS credentials in GitHub Secrets or use OIDC with a role that has read-only security audit permissions and the S3 remediation permissions you want to allow.

Example workflow:

```yaml
name: CloudShield Compliance

on:
  schedule:
    - cron: '0 8 * * *'
  pull_request:

jobs:
  scan:
    runs-on: ubuntu-latest
    permissions:
      id-token: write
      contents: read
    steps:
      - name: Checkout
        uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'

      - name: Install dependencies
        run: pip install -r requirements.txt

      - name: Run CloudShield
        env:
          AWS_REGION: us-east-1
          AWS_ROLE_ARN: ${{ secrets.CLOUDSHIELD_ROLE_ARN }}
        run: python main.py

      - name: Upload report
        uses: actions/upload-artifact@v4
        with:
          name: cloudshield-report
          path: cloudshield_report.pdf
```

## Notes

- CloudShield uses Boto3 for all AWS interactions.
- The PDF report includes a Security Risk Score from 0 to 100.
- Remediation is intentionally limited to high severity S3 findings.
